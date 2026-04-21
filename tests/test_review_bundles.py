from __future__ import annotations

import json
import os
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from knives_out.models import AttackResult, AttackResults
from knives_out.review_bundles import (
    BASELINE_RESULTS_PATH,
    CURRENT_RESULTS_PATH,
    MANIFEST_PATH,
    ReviewBundle,
    ReviewBundleManifest,
    load_review_bundle,
    render_review_bundle,
    write_review_bundle_artifacts,
)


def _results(*, base_url: str = "https://example.com") -> AttackResults:
    return AttackResults(
        source="bundle-test",
        base_url=base_url,
        executed_at="2026-04-15T04:00:00Z",
        results=[
            AttackResult(
                attack_id="atk_api",
                operation_id="getSecret",
                kind="missing_auth",
                name="Missing auth",
                protocol="openapi",
                method="GET",
                path="/secrets",
                url=f"{base_url}/secrets",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
            )
        ],
    )


def _manifest(**updates: object) -> dict[str, object]:
    manifest: dict[str, object] = {
        "bundle_kind": "review",
        "bundle_version": 1,
        "name": "Bundle",
        "created_at": "2026-04-15T04:00:00Z",
        "base_url": "https://example.com",
        "executed_at": "2026-04-15T04:00:00Z",
        "result_count": 1,
        "includes_baseline": False,
        "includes_suppressions": False,
        "includes_artifacts": False,
        "min_severity": "high",
        "min_confidence": "medium",
    }
    manifest.update(updates)
    return manifest


def _zip_bytes(entries: dict[str, bytes | str]) -> bytes:
    raw = BytesIO()
    with ZipFile(raw, "w", compression=ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return raw.getvalue()


def _bundle_with_manifest(manifest: dict[str, object], **entries: bytes | str) -> bytes:
    return _zip_bytes(
        {
            MANIFEST_PATH: json.dumps(manifest),
            CURRENT_RESULTS_PATH: _results().model_dump_json(exclude_none=True),
            **entries,
        }
    )


def test_review_bundle_rejects_empty_raw_and_missing_artifact_directory(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="empty"):
        load_review_bundle(b"")

    with pytest.raises(ValueError, match="does not exist or is not a directory"):
        render_review_bundle(_results(), artifact_dir=tmp_path / "missing")


def test_review_bundle_validates_manifest_contract() -> None:
    with pytest.raises(ValueError, match="Unsupported bundle kind"):
        load_review_bundle(_bundle_with_manifest(_manifest(bundle_kind="snapshot")))

    with pytest.raises(ValueError, match="Unsupported review bundle version"):
        load_review_bundle(_bundle_with_manifest(_manifest(bundle_version=2)))


@pytest.mark.parametrize(
    ("manifest", "entries", "match"),
    [
        (_manifest(), {CURRENT_RESULTS_PATH: "{}"}, "current results are invalid"),
        (_manifest(includes_baseline=True), {}, "expects baseline/results.json"),
        (
            _manifest(),
            {BASELINE_RESULTS_PATH: "{}"},
            "baseline results are invalid",
        ),
        (_manifest(includes_suppressions=True), {}, "expects review/suppressions.yml"),
        (_manifest(includes_artifacts=True), {}, "expects bundled artifacts"),
    ],
)
def test_review_bundle_validates_expected_payloads(
    manifest: dict[str, object],
    entries: dict[str, bytes | str],
    match: str,
) -> None:
    with pytest.raises(ValueError, match=match):
        load_review_bundle(_bundle_with_manifest(manifest, **entries))


def test_review_bundle_loader_skips_directory_entries() -> None:
    raw = BytesIO()
    with ZipFile(raw, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("artifacts/", "")
        archive.writestr(MANIFEST_PATH, json.dumps(_manifest()))
        archive.writestr(CURRENT_RESULTS_PATH, _results().model_dump_json(exclude_none=True))

    loaded = load_review_bundle(raw.getvalue())

    assert loaded.artifacts == {}


def test_review_bundle_artifact_writer_rejects_symlink_escape(tmp_path: Path) -> None:
    escape_target = tmp_path / "outside"
    artifact_root = tmp_path / "artifacts"
    escape_target.mkdir()
    artifact_root.mkdir()
    try:
        os.symlink(escape_target, artifact_root / "link")
    except OSError as exc:
        pytest.skip(f"symlinks are unavailable: {exc}")

    bundle = ReviewBundle(
        manifest=ReviewBundleManifest(
            name="Bundle",
            base_url="https://example.com",
            executed_at=_results().executed_at,
            result_count=1,
            includes_artifacts=True,
        ),
        current_results=_results(),
        baseline_results=None,
        suppressions_yaml=None,
        artifacts={"link/outside.txt": b"escape"},
    )

    with pytest.raises(ValueError, match="unsafe artifact path"):
        write_review_bundle_artifacts(bundle, artifact_root)
