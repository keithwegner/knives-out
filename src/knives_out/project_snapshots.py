from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from io import BytesIO
from pathlib import PurePosixPath
from uuid import uuid4
from zipfile import ZIP_DEFLATED, BadZipFile, ZipFile

from pydantic import BaseModel, Field, ValidationError

from knives_out.api_models import JobRecord, ProjectRecord
from knives_out.api_store import JobStore
from knives_out.models import AttackResults
from knives_out.project_store import ProjectStore

PROJECT_SNAPSHOT_KIND = "project_snapshot"
PROJECT_SNAPSHOT_VERSION = 1
MANIFEST_PATH = "manifest.json"
PROJECT_PATH = "project/project.json"
JOBS_PREFIX = "jobs"
JOB_RECORD_NAME = "job.json"
JOB_RESULT_NAME = "result.json"
JOB_ARTIFACTS_SEGMENT = "artifacts"


class ProjectSnapshotManifest(BaseModel):
    snapshot_kind: str = PROJECT_SNAPSHOT_KIND
    snapshot_version: int = PROJECT_SNAPSHOT_VERSION
    name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    project_id: str
    source_mode: str
    job_count: int = 0
    result_count: int = 0
    artifact_count: int = 0


@dataclass(frozen=True)
class ProjectSnapshotJob:
    record: JobRecord
    result: AttackResults | None
    artifacts: dict[str, bytes]


@dataclass(frozen=True)
class ProjectSnapshot:
    manifest: ProjectSnapshotManifest
    project: ProjectRecord
    jobs: list[ProjectSnapshotJob]


def _safe_member_name(name: str) -> str:
    if not name:
        raise ValueError("Project snapshot contains an empty member path.")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"Project snapshot contains unsafe path {name!r}.")
    return path.as_posix()


def _validate_manifest(manifest: ProjectSnapshotManifest) -> None:
    if manifest.snapshot_kind != PROJECT_SNAPSHOT_KIND:
        raise ValueError(f"Unsupported project snapshot kind {manifest.snapshot_kind!r}.")
    if manifest.snapshot_version != PROJECT_SNAPSHOT_VERSION:
        raise ValueError(
            f"Unsupported project snapshot version {manifest.snapshot_version}; "
            f"expected {PROJECT_SNAPSHOT_VERSION}."
        )


def _job_member_parts(name: str) -> tuple[str, ...]:
    return PurePosixPath(name).parts


def _job_record_path(job_id: str) -> str:
    return f"{JOBS_PREFIX}/{job_id}/{JOB_RECORD_NAME}"


def _job_result_path(job_id: str) -> str:
    return f"{JOBS_PREFIX}/{job_id}/{JOB_RESULT_NAME}"


def _job_artifact_path(job_id: str, artifact_name: str) -> str:
    return f"{JOBS_PREFIX}/{job_id}/{JOB_ARTIFACTS_SEGMENT}/{_safe_member_name(artifact_name)}"


def render_project_snapshot(
    project_store: ProjectStore,
    job_store: JobStore,
    project_id: str,
) -> bytes:
    project = project_store.load_project(project_id)
    jobs = [record for record in job_store.list_job_records() if record.project_id == project.id]
    result_count = sum(1 for record in jobs if job_store.result_exists(record.id))
    artifact_count = sum(len(job_store.list_artifacts(record.id)) for record in jobs)
    manifest = ProjectSnapshotManifest(
        name=project.name,
        project_id=project.id,
        source_mode=project.source_mode.value,
        job_count=len(jobs),
        result_count=result_count,
        artifact_count=artifact_count,
    )

    stream = BytesIO()
    with ZipFile(stream, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr(MANIFEST_PATH, manifest.model_dump_json(indent=2, exclude_none=True))
        archive.writestr(PROJECT_PATH, project.model_dump_json(indent=2, exclude_none=True))
        for record in jobs:
            archive.writestr(
                _job_record_path(record.id),
                record.model_dump_json(indent=2, exclude_none=True),
            )
            if job_store.result_exists(record.id):
                archive.writestr(
                    _job_result_path(record.id),
                    job_store.load_result(record.id).model_dump_json(
                        indent=2,
                        exclude_none=True,
                    ),
                )
            for artifact_name in job_store.list_artifacts(record.id):
                archive.writestr(
                    _job_artifact_path(record.id, artifact_name),
                    job_store.artifact_path_for_name(record.id, artifact_name).read_bytes(),
                )
    return stream.getvalue()


def _load_members(raw: bytes) -> dict[str, bytes]:
    if not raw:
        raise ValueError("Project snapshot is empty.")
    try:
        with ZipFile(BytesIO(raw)) as archive:
            return {
                _safe_member_name(member.filename): archive.read(member)
                for member in archive.infolist()
                if not member.is_dir()
            }
    except BadZipFile as exc:
        raise ValueError("Project snapshot must be a zip archive.") from exc


def _load_json_model(members: dict[str, bytes], path: str, model, label: str):
    raw = members.get(path)
    if raw is None:
        raise ValueError(f"Project snapshot is missing {path}.")
    try:
        return model.model_validate_json(raw)
    except ValidationError as exc:
        raise ValueError(f"Project snapshot {label} is invalid: {exc}") from exc


def _group_job_payloads(
    members: dict[str, bytes],
) -> tuple[dict[str, bytes], dict[str, bytes], dict[str, dict[str, bytes]]]:
    job_records: dict[str, bytes] = {}
    job_results: dict[str, bytes] = {}
    artifacts: dict[str, dict[str, bytes]] = defaultdict(dict)

    for name, content in members.items():
        parts = _job_member_parts(name)
        if len(parts) < 3 or parts[0] != JOBS_PREFIX:
            continue
        job_id = parts[1]
        if len(parts) == 3 and parts[2] == JOB_RECORD_NAME:
            job_records[job_id] = content
            continue
        if len(parts) == 3 and parts[2] == JOB_RESULT_NAME:
            job_results[job_id] = content
            continue
        if len(parts) >= 4 and parts[2] == JOB_ARTIFACTS_SEGMENT:
            artifact_name = _safe_member_name(PurePosixPath(*parts[3:]).as_posix())
            artifacts[job_id][artifact_name] = content
            continue
        raise ValueError(f"Project snapshot contains unsupported job member {name!r}.")

    return job_records, job_results, dict(artifacts)


def load_project_snapshot(raw: bytes) -> ProjectSnapshot:
    members = _load_members(raw)
    manifest = _load_json_model(
        members,
        MANIFEST_PATH,
        ProjectSnapshotManifest,
        "manifest",
    )
    _validate_manifest(manifest)
    project = _load_json_model(members, PROJECT_PATH, ProjectRecord, "project record")
    if project.id != manifest.project_id:
        raise ValueError("Project snapshot manifest project_id does not match project record.")

    job_record_payloads, result_payloads, artifact_payloads = _group_job_payloads(members)
    unknown_result_jobs = sorted(set(result_payloads) - set(job_record_payloads))
    if unknown_result_jobs:
        raise ValueError("Project snapshot contains results for an unknown job.")
    unknown_artifact_jobs = sorted(set(artifact_payloads) - set(job_record_payloads))
    if unknown_artifact_jobs:
        raise ValueError("Project snapshot contains artifacts for an unknown job.")

    jobs: list[ProjectSnapshotJob] = []
    for job_id, payload in sorted(job_record_payloads.items()):
        try:
            record = JobRecord.model_validate_json(payload)
        except ValidationError as exc:
            raise ValueError(f"Project snapshot job {job_id} is invalid: {exc}") from exc
        if record.id != job_id:
            raise ValueError("Project snapshot job path does not match job record id.")
        if record.project_id != project.id:
            raise ValueError("Project snapshot job does not belong to the bundled project.")

        result = None
        result_payload = result_payloads.get(job_id)
        if result_payload is not None:
            try:
                result = AttackResults.model_validate_json(result_payload)
            except ValidationError as exc:
                raise ValueError(f"Project snapshot job {job_id} result is invalid: {exc}") from exc
        jobs.append(
            ProjectSnapshotJob(
                record=record,
                result=result,
                artifacts=artifact_payloads.get(job_id, {}),
            )
        )

    result_count = sum(1 for job in jobs if job.result is not None)
    artifact_count = sum(len(job.artifacts) for job in jobs)
    if len(jobs) != manifest.job_count:
        raise ValueError(f"Project snapshot manifest expects {manifest.job_count} job record(s).")
    if result_count != manifest.result_count:
        raise ValueError(f"Project snapshot manifest expects {manifest.result_count} result(s).")
    if artifact_count != manifest.artifact_count:
        raise ValueError(
            f"Project snapshot manifest expects {manifest.artifact_count} artifact(s)."
        )

    return ProjectSnapshot(manifest=manifest, project=project, jobs=jobs)


def _write_snapshot_artifacts(
    job_store: JobStore,
    *,
    job_id: str,
    artifacts: dict[str, bytes],
) -> None:
    root = job_store.artifact_dir(job_id).resolve()
    for artifact_name, content in artifacts.items():
        safe_name = _safe_member_name(artifact_name)
        target = (job_store.artifact_dir(job_id) / safe_name).resolve()
        if root not in target.parents and target != root:
            raise ValueError(f"Project snapshot contains unsafe artifact path {artifact_name!r}.")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)


def import_project_snapshot(
    project_store: ProjectStore,
    job_store: JobStore,
    snapshot: ProjectSnapshot,
    *,
    name: str | None = None,
) -> ProjectRecord:
    now = datetime.now(UTC)
    project_id = uuid4().hex
    job_id_map = {job.record.id: uuid4().hex for job in snapshot.jobs}
    imported_name = name.strip() if name and name.strip() else snapshot.project.name

    artifacts = snapshot.project.artifacts.model_copy(
        deep=True,
        update={
            "last_run_job_id": job_id_map.get(snapshot.project.artifacts.last_run_job_id)
            if snapshot.project.artifacts.last_run_job_id is not None
            else None,
        },
    )
    review_draft = snapshot.project.review_draft.model_copy(
        deep=True,
        update={
            "baseline_job_id": job_id_map.get(snapshot.project.review_draft.baseline_job_id)
            if snapshot.project.review_draft.baseline_job_id is not None
            else None,
        },
    )
    imported_project = snapshot.project.model_copy(
        deep=True,
        update={
            "id": project_id,
            "name": imported_name,
            "created_at": now,
            "updated_at": now,
            "review_draft": review_draft,
            "artifacts": artifacts,
        },
    )
    project_store.create_project(imported_project)

    for job in snapshot.jobs:
        imported_job_id = job_id_map[job.record.id]
        imported_record = job.record.model_copy(
            update={
                "id": imported_job_id,
                "project_id": project_id,
            }
        )
        job_store.create_job(imported_record)
        if job.result is not None:
            job_store.write_result(imported_job_id, job.result)
        _write_snapshot_artifacts(
            job_store,
            job_id=imported_job_id,
            artifacts=job.artifacts,
        )

    return imported_project
