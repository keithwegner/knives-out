from __future__ import annotations

from pathlib import Path
from time import monotonic, sleep
from uuid import uuid4

from pydantic import ValidationError

from knives_out.api_models import (
    ApiJobStatus,
    ArtifactListResponse,
    JobListResponse,
    JobRecord,
    JobStatusResponse,
)
from knives_out.models import AttackResults


class JobNotFoundError(FileNotFoundError):
    pass


class JobStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.jobs_dir = root / "jobs"
        self.jobs_dir.mkdir(parents=True, exist_ok=True)

    def create_job(self, record: JobRecord) -> JobRecord:
        job_dir = self.job_dir(record.id)
        job_dir.mkdir(parents=True, exist_ok=True)
        self._write_record(record)
        self.artifact_dir(record.id).mkdir(parents=True, exist_ok=True)
        return record

    def job_dir(self, job_id: str) -> Path:
        return self.jobs_dir / job_id

    def artifact_dir(self, job_id: str) -> Path:
        return self.job_dir(job_id) / "artifacts"

    def record_path(self, job_id: str) -> Path:
        return self.job_dir(job_id) / "job.json"

    def result_path(self, job_id: str) -> Path:
        return self.job_dir(job_id) / "result.json"

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

    def _write_record(self, record: JobRecord) -> None:
        self._write_json_atomic(
            self.record_path(record.id),
            record.model_dump_json(indent=2, exclude_none=True),
        )

    def load_job(self, job_id: str) -> JobRecord:
        path = self.record_path(job_id)
        if not path.exists():
            raise JobNotFoundError(job_id)
        return self._load_json_with_retries(path, JobRecord)

    def update_job(self, record: JobRecord) -> JobRecord:
        self._write_record(record)
        return record

    def write_result(self, job_id: str, results: AttackResults) -> None:
        self._write_json_atomic(
            self.result_path(job_id),
            results.model_dump_json(indent=2, exclude_none=True),
        )

    def load_result(self, job_id: str) -> AttackResults:
        path = self.result_path(job_id)
        if not path.exists():
            raise JobNotFoundError(job_id)
        return self._load_json_with_retries(path, AttackResults)

    def result_exists(self, job_id: str) -> bool:
        return self.result_path(job_id).exists()

    def list_artifacts(self, job_id: str) -> list[str]:
        artifact_dir = self.artifact_dir(job_id)
        if not artifact_dir.exists():
            return []
        return sorted(
            path.relative_to(artifact_dir).as_posix()
            for path in artifact_dir.rglob("*")
            if path.is_file()
        )

    def artifact_list_response(self, job_id: str) -> ArtifactListResponse:
        return ArtifactListResponse(job_id=job_id, artifacts=self.list_artifacts(job_id))

    def artifact_path_for_name(self, job_id: str, name: str) -> Path:
        candidate = (self.artifact_dir(job_id) / name).resolve()
        artifact_root = self.artifact_dir(job_id).resolve()
        if artifact_root not in candidate.parents and candidate != artifact_root:
            raise FileNotFoundError(name)
        if not candidate.exists() or not candidate.is_file():
            raise FileNotFoundError(name)
        return candidate

    def _status_response(self, record: JobRecord) -> JobStatusResponse:
        return JobStatusResponse(
            id=record.id,
            kind=record.kind,
            status=record.status,
            created_at=record.created_at,
            started_at=record.started_at,
            completed_at=record.completed_at,
            base_url=record.base_url,
            attack_count=record.attack_count,
            result_count=record.result_count,
            flagged_count=record.flagged_count,
            auth_failure_count=record.auth_failure_count,
            error=record.error,
            result_available=self.result_exists(record.id),
            artifact_names=self.list_artifacts(record.id),
        )

    def list_jobs(
        self,
        *,
        status: ApiJobStatus | None = None,
        limit: int = 20,
    ) -> list[JobRecord]:
        records: list[JobRecord] = []
        for job_dir in self.jobs_dir.iterdir():
            if not job_dir.is_dir():
                continue
            if not self.record_path(job_dir.name).exists():
                continue
            record = self.load_job(job_dir.name)
            if status is not None and record.status != status:
                continue
            records.append(record)

        records.sort(key=lambda record: record.created_at, reverse=True)
        return records[:limit]

    def job_list_response(
        self,
        *,
        status: ApiJobStatus | None = None,
        limit: int = 20,
    ) -> JobListResponse:
        return JobListResponse(
            jobs=[
                self._status_response(record)
                for record in self.list_jobs(status=status, limit=limit)
            ]
        )

    def job_status_response(self, job_id: str) -> JobStatusResponse:
        record = self.load_job(job_id)
        return self._status_response(record)
