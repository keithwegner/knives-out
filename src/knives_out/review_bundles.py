from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path, PurePosixPath
from zipfile import ZIP_DEFLATED, BadZipFile, ZipFile

from pydantic import BaseModel, Field, ValidationError

from knives_out.models import AttackResults

REVIEW_BUNDLE_KIND = "review"
REVIEW_BUNDLE_VERSION = 1
MANIFEST_PATH = "manifest.json"
CURRENT_RESULTS_PATH = "current/results.json"
BASELINE_RESULTS_PATH = "baseline/results.json"
SUPPRESSIONS_PATH = "review/suppressions.yml"
ARTIFACTS_PREFIX = "artifacts/"


class ReviewBundleManifest(BaseModel):
    bundle_kind: str = REVIEW_BUNDLE_KIND
    bundle_version: int = REVIEW_BUNDLE_VERSION
    name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    base_url: str
    executed_at: datetime
    result_count: int
    includes_baseline: bool = False
    includes_suppressions: bool = False
    includes_artifacts: bool = False
    min_severity: str = "high"
    min_confidence: str = "medium"


@dataclass(frozen=True)
class ReviewBundle:
    manifest: ReviewBundleManifest
    current_results: AttackResults
    baseline_results: AttackResults | None
    suppressions_yaml: str | None
    artifacts: dict[str, bytes]


class ReviewBundleInspection(BaseModel):
    manifest: ReviewBundleManifest
    current_result_count: int
    baseline_result_count: int | None = None
    suppressions_bytes: int | None = None
    artifact_count: int = 0
    artifact_names: list[str] = Field(default_factory=list)


def _default_name(name: str | None) -> str:
    return name.strip() if name and name.strip() else "Imported review"


def _safe_member_name(name: str) -> str:
    if not name:
        raise ValueError("Review bundle contains an empty member path.")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"Review bundle contains unsafe path {name!r}.")
    return path.as_posix()


def _validate_manifest(manifest: ReviewBundleManifest) -> None:
    if manifest.bundle_kind != REVIEW_BUNDLE_KIND:
        raise ValueError(f"Unsupported bundle kind {manifest.bundle_kind!r}.")
    if manifest.bundle_version != REVIEW_BUNDLE_VERSION:
        raise ValueError(
            f"Unsupported review bundle version {manifest.bundle_version}; "
            f"expected {REVIEW_BUNDLE_VERSION}."
        )


def _is_zip_bytes(raw: bytes) -> bool:
    try:
        with ZipFile(BytesIO(raw)):
            return True
    except BadZipFile:
        return False


def render_review_bundle(
    current_results: AttackResults,
    *,
    name: str | None = None,
    baseline: AttackResults | None = None,
    suppressions_yaml: str | None = None,
    artifact_dir: Path | None = None,
    min_severity: str = "high",
    min_confidence: str = "medium",
) -> bytes:
    if artifact_dir is not None and (not artifact_dir.exists() or not artifact_dir.is_dir()):
        raise ValueError(
            f"Artifact directory '{artifact_dir}' does not exist or is not a directory."
        )

    artifact_names: list[str] = []
    if artifact_dir is not None:
        artifact_names = [
            path.relative_to(artifact_dir).as_posix()
            for path in sorted(artifact_dir.rglob("*"))
            if path.is_file()
        ]

    manifest = ReviewBundleManifest(
        name=_default_name(name),
        base_url=current_results.base_url,
        executed_at=current_results.executed_at,
        result_count=len(current_results.results),
        includes_baseline=baseline is not None,
        includes_suppressions=bool(suppressions_yaml),
        includes_artifacts=bool(artifact_names),
        min_severity=min_severity,
        min_confidence=min_confidence,
    )

    stream = BytesIO()
    with ZipFile(stream, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr(MANIFEST_PATH, manifest.model_dump_json(indent=2, exclude_none=True))
        archive.writestr(
            CURRENT_RESULTS_PATH,
            current_results.model_dump_json(indent=2, exclude_none=True),
        )
        if baseline is not None:
            archive.writestr(
                BASELINE_RESULTS_PATH,
                baseline.model_dump_json(indent=2, exclude_none=True),
            )
        if suppressions_yaml:
            archive.writestr(SUPPRESSIONS_PATH, suppressions_yaml)
        if artifact_dir is not None:
            for artifact_name in artifact_names:
                archive.writestr(
                    f"{ARTIFACTS_PREFIX}{artifact_name}",
                    (artifact_dir / artifact_name).read_bytes(),
                )
    return stream.getvalue()


def load_review_bundle(raw: bytes) -> ReviewBundle:
    if not raw:
        raise ValueError("Review bundle is empty.")
    if not _is_zip_bytes(raw):
        raise ValueError("Review bundle must be a zip archive.")

    members: dict[str, bytes] = {}
    try:
        with ZipFile(BytesIO(raw)) as archive:
            for member in archive.infolist():
                if member.is_dir():
                    continue
                safe_name = _safe_member_name(member.filename)
                members[safe_name] = archive.read(member)
    except BadZipFile as exc:
        raise ValueError("Review bundle must be a zip archive.") from exc

    manifest_bytes = members.get(MANIFEST_PATH)
    if manifest_bytes is None:
        raise ValueError("Review bundle is missing manifest.json.")
    try:
        manifest = ReviewBundleManifest.model_validate_json(manifest_bytes)
    except ValidationError as exc:
        raise ValueError(f"Review bundle manifest is invalid: {exc}") from exc
    _validate_manifest(manifest)

    current_bytes = members.get(CURRENT_RESULTS_PATH)
    if current_bytes is None:
        raise ValueError("Review bundle is missing current/results.json.")
    try:
        current_results = AttackResults.model_validate_json(current_bytes)
    except ValidationError as exc:
        raise ValueError(f"Review bundle current results are invalid: {exc}") from exc

    baseline_bytes = members.get(BASELINE_RESULTS_PATH)
    if manifest.includes_baseline and baseline_bytes is None:
        raise ValueError("Review bundle manifest expects baseline/results.json.")
    baseline_results = None
    if baseline_bytes is not None:
        try:
            baseline_results = AttackResults.model_validate_json(baseline_bytes)
        except ValidationError as exc:
            raise ValueError(f"Review bundle baseline results are invalid: {exc}") from exc

    suppressions_bytes = members.get(SUPPRESSIONS_PATH)
    if manifest.includes_suppressions and suppressions_bytes is None:
        raise ValueError("Review bundle manifest expects review/suppressions.yml.")
    suppressions_yaml = (
        suppressions_bytes.decode("utf-8") if suppressions_bytes is not None else None
    )

    artifacts = {
        name.removeprefix(ARTIFACTS_PREFIX): content
        for name, content in members.items()
        if name.startswith(ARTIFACTS_PREFIX)
    }
    if manifest.includes_artifacts and not artifacts:
        raise ValueError("Review bundle manifest expects bundled artifacts.")

    return ReviewBundle(
        manifest=manifest,
        current_results=current_results,
        baseline_results=baseline_results,
        suppressions_yaml=suppressions_yaml,
        artifacts=artifacts,
    )


def inspect_review_bundle(raw: bytes) -> ReviewBundleInspection:
    bundle = load_review_bundle(raw)
    return ReviewBundleInspection(
        manifest=bundle.manifest,
        current_result_count=len(bundle.current_results.results),
        baseline_result_count=(
            len(bundle.baseline_results.results) if bundle.baseline_results is not None else None
        ),
        suppressions_bytes=(
            len(bundle.suppressions_yaml.encode("utf-8"))
            if bundle.suppressions_yaml is not None
            else None
        ),
        artifact_count=len(bundle.artifacts),
        artifact_names=sorted(bundle.artifacts),
    )


def write_review_bundle_artifacts(bundle: ReviewBundle, artifact_root: Path) -> None:
    root = artifact_root.resolve()
    for relative_name, content in bundle.artifacts.items():
        safe_name = _safe_member_name(relative_name)
        target = (artifact_root / safe_name).resolve()
        if root not in target.parents and target != root:
            raise ValueError(f"Review bundle contains unsafe artifact path {relative_name!r}.")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
