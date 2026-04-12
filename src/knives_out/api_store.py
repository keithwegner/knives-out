from __future__ import annotations

from pathlib import Path

from knives_out.api_models import ArtifactListResponse, JobRecord, JobStatusResponse
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

    def _write_record(self, record: JobRecord) -> None:
        self.record_path(record.id).write_text(
            record.model_dump_json(indent=2, exclude_none=True),
            encoding="utf-8",
        )

    def load_job(self, job_id: str) -> JobRecord:
        path = self.record_path(job_id)
        if not path.exists():
            raise JobNotFoundError(job_id)
        return JobRecord.model_validate_json(path.read_text(encoding="utf-8"))

    def update_job(self, record: JobRecord) -> JobRecord:
        self._write_record(record)
        return record

    def write_result(self, job_id: str, results: AttackResults) -> None:
        self.result_path(job_id).write_text(
            results.model_dump_json(indent=2, exclude_none=True),
            encoding="utf-8",
        )

    def load_result(self, job_id: str) -> AttackResults:
        path = self.result_path(job_id)
        if not path.exists():
            raise JobNotFoundError(job_id)
        return AttackResults.model_validate_json(path.read_text(encoding="utf-8"))

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

    def job_status_response(self, job_id: str) -> JobStatusResponse:
        record = self.load_job(job_id)
        return JobStatusResponse(
            id=record.id,
            kind=record.kind,
            status=record.status,
            created_at=record.created_at,
            started_at=record.started_at,
            completed_at=record.completed_at,
            base_url=record.base_url,
            attack_count=record.attack_count,
            error=record.error,
            result_available=self.result_exists(job_id),
            artifact_names=self.list_artifacts(job_id),
        )
