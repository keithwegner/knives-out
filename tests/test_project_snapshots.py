from __future__ import annotations

import json
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from knives_out.project_snapshots import load_project_snapshot

CREATED_AT = "2026-04-13T12:00:00Z"


def _zip_bytes(entries: dict[str, bytes | str]) -> bytes:
    raw = BytesIO()
    with ZipFile(raw, "w", compression=ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return raw.getvalue()


def _manifest(**overrides: object) -> str:
    payload = {
        "snapshot_kind": "project_snapshot",
        "snapshot_version": 1,
        "name": "Snapshot demo",
        "created_at": CREATED_AT,
        "project_id": "project-1",
        "source_mode": "openapi",
        "job_count": 0,
        "result_count": 0,
        "artifact_count": 0,
    }
    payload.update(overrides)
    return json.dumps(payload)


def _project(**overrides: object) -> str:
    payload = {
        "id": "project-1",
        "name": "Snapshot demo",
        "source_mode": "openapi",
        "active_step": "source",
        "created_at": CREATED_AT,
        "updated_at": CREATED_AT,
    }
    payload.update(overrides)
    return json.dumps(payload)


def _job(**overrides: object) -> str:
    payload = {
        "id": "job-1",
        "status": "completed",
        "created_at": CREATED_AT,
        "base_url": "https://api.example",
        "attack_count": 1,
        "project_id": "project-1",
    }
    payload.update(overrides)
    return json.dumps(payload)


def _results(**overrides: object) -> str:
    payload = {
        "source": "demo.yaml",
        "base_url": "https://api.example",
        "executed_at": CREATED_AT,
        "results": [],
    }
    payload.update(overrides)
    return json.dumps(payload)


def test_project_snapshot_loader_rejects_unsupported_kind() -> None:
    raw = _zip_bytes(
        {
            "manifest.json": json.dumps(
                {
                    "snapshot_kind": "review",
                    "snapshot_version": 1,
                    "name": "Wrong kind",
                    "created_at": "2026-04-13T12:00:00Z",
                    "project_id": "project-1",
                    "source_mode": "openapi",
                    "job_count": 0,
                    "result_count": 0,
                    "artifact_count": 0,
                }
            ),
            "project/project.json": "{}",
        }
    )

    with pytest.raises(ValueError, match="Unsupported project snapshot kind"):
        load_project_snapshot(raw)


def test_project_snapshot_loader_rejects_unsupported_version() -> None:
    raw = _zip_bytes(
        {
            "manifest.json": _manifest(snapshot_version=2),
            "project/project.json": _project(),
        }
    )

    with pytest.raises(ValueError, match="Unsupported project snapshot version"):
        load_project_snapshot(raw)


def test_project_snapshot_loader_rejects_empty_uploads() -> None:
    with pytest.raises(ValueError, match="Project snapshot is empty"):
        load_project_snapshot(b"")


def test_project_snapshot_loader_rejects_non_zip_uploads() -> None:
    with pytest.raises(ValueError, match="must be a zip archive"):
        load_project_snapshot(b"not a zip")


def test_project_snapshot_loader_rejects_missing_manifest() -> None:
    raw = _zip_bytes({"project/project.json": _project()})

    with pytest.raises(ValueError, match="missing manifest.json"):
        load_project_snapshot(raw)


def test_project_snapshot_loader_rejects_invalid_manifest_json() -> None:
    raw = _zip_bytes(
        {
            "manifest.json": "{}",
            "project/project.json": _project(),
        }
    )

    with pytest.raises(ValueError, match="manifest is invalid"):
        load_project_snapshot(raw)


def test_project_snapshot_loader_rejects_unsafe_member_paths() -> None:
    raw = _zip_bytes({"../escape.txt": "nope"})

    with pytest.raises(ValueError, match="unsafe path"):
        load_project_snapshot(raw)


def test_project_snapshot_loader_rejects_mismatched_project_id() -> None:
    raw = _zip_bytes(
        {
            "manifest.json": _manifest(project_id="project-1"),
            "project/project.json": _project(id="project-2"),
        }
    )

    with pytest.raises(ValueError, match="project_id does not match"):
        load_project_snapshot(raw)


def test_project_snapshot_loader_rejects_unknown_result_jobs() -> None:
    raw = _zip_bytes(
        {
            "manifest.json": _manifest(result_count=1),
            "project/project.json": _project(),
            "jobs/missing/result.json": _results(),
        }
    )

    with pytest.raises(ValueError, match="results for an unknown job"):
        load_project_snapshot(raw)


def test_project_snapshot_loader_rejects_unknown_artifact_jobs() -> None:
    raw = _zip_bytes(
        {
            "manifest.json": _manifest(artifact_count=1),
            "project/project.json": _project(),
            "jobs/missing/artifacts/request.json": "{}",
        }
    )

    with pytest.raises(ValueError, match="artifacts for an unknown job"):
        load_project_snapshot(raw)


def test_project_snapshot_loader_rejects_unsupported_job_members() -> None:
    raw = _zip_bytes(
        {
            "manifest.json": _manifest(),
            "project/project.json": _project(),
            "jobs/job-1/notes.txt": "unsupported",
        }
    )

    with pytest.raises(ValueError, match="unsupported job member"):
        load_project_snapshot(raw)


def test_project_snapshot_loader_rejects_job_path_id_mismatch() -> None:
    raw = _zip_bytes(
        {
            "manifest.json": _manifest(job_count=1),
            "project/project.json": _project(),
            "jobs/job-path/job.json": _job(id="job-record"),
        }
    )

    with pytest.raises(ValueError, match="job path does not match"):
        load_project_snapshot(raw)


def test_project_snapshot_loader_rejects_jobs_from_other_projects() -> None:
    raw = _zip_bytes(
        {
            "manifest.json": _manifest(job_count=1),
            "project/project.json": _project(),
            "jobs/job-1/job.json": _job(project_id="project-2"),
        }
    )

    with pytest.raises(ValueError, match="job does not belong"):
        load_project_snapshot(raw)


def test_project_snapshot_loader_rejects_manifest_count_mismatches() -> None:
    raw = _zip_bytes(
        {
            "manifest.json": _manifest(job_count=2, result_count=1, artifact_count=1),
            "project/project.json": _project(),
            "jobs/job-1/job.json": _job(),
            "jobs/job-1/result.json": _results(),
            "jobs/job-1/artifacts/request.json": "{}",
        }
    )

    with pytest.raises(ValueError, match=r"expects 2 job record"):
        load_project_snapshot(raw)
