from __future__ import annotations

import json
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from knives_out.project_snapshots import load_project_snapshot


def _zip_bytes(entries: dict[str, bytes | str]) -> bytes:
    raw = BytesIO()
    with ZipFile(raw, "w", compression=ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return raw.getvalue()


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


def test_project_snapshot_loader_rejects_unsafe_member_paths() -> None:
    raw = _zip_bytes({"../escape.txt": "nope"})

    with pytest.raises(ValueError, match="unsafe path"):
        load_project_snapshot(raw)
