from __future__ import annotations

import shutil
from pathlib import Path
from time import monotonic, sleep
from uuid import uuid4

from pydantic import ValidationError

from knives_out.api_models import ProjectRecord


class ProjectNotFoundError(FileNotFoundError):
    pass


class ProjectStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.projects_dir = root / "projects"
        self.projects_dir.mkdir(parents=True, exist_ok=True)

    def project_dir(self, project_id: str) -> Path:
        return self.projects_dir / project_id

    def record_path(self, project_id: str) -> Path:
        return self.project_dir(project_id) / "project.json"

    def _write_json_atomic(self, path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_name(f"{path.name}.{uuid4().hex}.tmp")
        temp_path.write_text(content, encoding="utf-8")
        temp_path.replace(path)

    def _load_json_with_retries(
        self,
        path: Path,
        model,
        *,
        timeout_seconds: float = 0.2,
        retry_delay_seconds: float = 0.01,
    ):
        last_error: ValidationError | OSError | None = None
        deadline = monotonic() + timeout_seconds

        while True:
            try:
                raw = path.read_text(encoding="utf-8")
                return model.model_validate_json(raw)
            except (OSError, ValidationError) as exc:
                last_error = exc
                if monotonic() >= deadline:
                    raise
                sleep(retry_delay_seconds)
        if last_error is not None:
            raise last_error
        raise RuntimeError(f"Unable to load JSON from {path}.")

    def _write_record(self, record: ProjectRecord) -> None:
        self._write_json_atomic(
            self.record_path(record.id),
            record.model_dump_json(indent=2, exclude_none=True),
        )

    def create_project(self, record: ProjectRecord) -> ProjectRecord:
        self.project_dir(record.id).mkdir(parents=True, exist_ok=True)
        self._write_record(record)
        return record

    def load_project(self, project_id: str) -> ProjectRecord:
        path = self.record_path(project_id)
        if not path.exists():
            raise ProjectNotFoundError(project_id)
        return self._load_json_with_retries(path, ProjectRecord)

    def update_project(self, record: ProjectRecord) -> ProjectRecord:
        self._write_record(record)
        return record

    def list_projects(self) -> list[ProjectRecord]:
        records: list[ProjectRecord] = []
        for record_path in sorted(self.projects_dir.glob("*/project.json")):
            records.append(self._load_json_with_retries(record_path, ProjectRecord))
        records.sort(key=lambda record: record.updated_at, reverse=True)
        return records

    def delete_project(self, project_id: str) -> None:
        project_dir = self.project_dir(project_id)
        if not project_dir.exists():
            raise ProjectNotFoundError(project_id)
        shutil.rmtree(project_dir)
