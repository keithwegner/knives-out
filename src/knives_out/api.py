from __future__ import annotations

import os
import re
import threading
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import yaml
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse

from knives_out import __version__
from knives_out.api_models import (
    ApiJobStatus,
    ArtifactListResponse,
    ArtifactReferenceKind,
    ArtifactReferenceResponse,
    DeleteJobResponse,
    DeltaChangeResponse,
    DiscoverRequest,
    DiscoverResponse,
    FindingSummaryResponse,
    GenerateRequest,
    GenerateResponse,
    InspectRequest,
    InspectResponse,
    JobFindingEvidenceResponse,
    JobListResponse,
    JobRecord,
    JobRetentionEntry,
    JobStatusResponse,
    ProjectCreateRequest,
    ProjectJobsResponse,
    ProjectListResponse,
    ProjectRecord,
    ProjectReviewBaselineMode,
    ProjectReviewDraft,
    ProjectReviewRequest,
    ProjectReviewResponse,
    ProjectSourceMode,
    ProjectSummaryResponse,
    ProjectUpdateRequest,
    PromoteRequest,
    PromoteResponse,
    PruneJobsRequest,
    PruneJobsResponse,
    ReportRequest,
    ReportResponse,
    RunRequest,
    SourcePayload,
    SummaryRequest,
    SummaryResponse,
    TriageRequest,
    TriageResponse,
    VerifyRequest,
    VerifyResponse,
)
from knives_out.api_store import ActiveJobDeletionError, DeletedJob, JobNotFoundError, JobStore
from knives_out.models import AttackResult, AttackResults, ResultsSummary
from knives_out.project_store import ProjectNotFoundError, ProjectStore
from knives_out.services import (
    InlineInput,
    discover_model_inline,
    generate_suite_from_inline,
    inspect_source_inline,
    promote_results_from_models,
    render_report_from_models,
    run_suite_from_inline,
    summarize_results_from_models,
    triage_results_from_model,
    verify_results_from_models,
)

PRUNEABLE_JOB_STATUSES = frozenset({ApiJobStatus.completed, ApiJobStatus.failed})
JOB_SUMMARY_TOP_LIMIT = 3
PROJECT_REVIEW_TOP_LIMIT = 50
_PROFILE_ARTIFACT_SEGMENT_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _finding_summary(finding) -> FindingSummaryResponse:
    result = finding.result if hasattr(finding, "result") else finding
    delta_changes = []
    if hasattr(finding, "delta") and finding.delta is not None:
        delta_changes = [
            DeltaChangeResponse(
                field=change.field,
                baseline=change.baseline,
                current=change.current,
            )
            for change in finding.delta.changes
        ]
    return FindingSummaryResponse(
        change=getattr(finding, "change", "current"),
        attack_id=result.attack_id,
        name=result.name,
        protocol="rest" if result.protocol == "openapi" else result.protocol,
        kind=result.kind,
        method=result.method,
        path=result.path,
        tags=list(result.tags),
        issue=result.issue,
        severity=result.severity,
        confidence=result.confidence,
        status_code=result.status_code,
        url=result.url,
        delta_changes=delta_changes,
    )


def _verify_response(verification) -> VerifyResponse:
    comparison = verification.comparison
    return VerifyResponse(
        passed=verification.passed,
        baseline_used=verification.baseline_used,
        min_severity=verification.min_severity,
        min_confidence=verification.min_confidence,
        current_findings_count=len(comparison.current_findings),
        new_findings_count=len(comparison.new_findings),
        resolved_findings_count=len(comparison.resolved_findings),
        persisting_findings_count=len(comparison.persisting_findings),
        suppressed_current_findings_count=len(comparison.suppressed_current_findings),
        current_findings=[_finding_summary(finding) for finding in comparison.current_findings],
        failing_findings=[_finding_summary(finding) for finding in verification.failing_findings],
        new_findings=[_finding_summary(finding) for finding in comparison.new_findings],
        resolved_findings=[_finding_summary(finding) for finding in comparison.resolved_findings],
        persisting_findings=[
            _finding_summary(finding) for finding in comparison.persisting_findings
        ],
    )


def _inline(source) -> InlineInput:
    return InlineInput(name=source.name, content=source.content)


def _default_data_dir() -> Path:
    configured = os.environ.get("KNIVES_OUT_API_DATA_DIR")
    if configured:
        return Path(configured)
    return Path.cwd() / ".knives-out-api"


def _job_result_summary(job_store: JobStore, job_id: str) -> ResultsSummary:
    return summarize_results_from_models(
        job_store.load_result(job_id),
        top_limit=JOB_SUMMARY_TOP_LIMIT,
    )


def _job_status_response(job_store: JobStore, record: JobRecord) -> JobStatusResponse:
    result_available = job_store.result_exists(record.id)
    return JobStatusResponse(
        id=record.id,
        kind=record.kind,
        status=record.status,
        created_at=record.created_at,
        started_at=record.started_at,
        completed_at=record.completed_at,
        base_url=record.base_url,
        attack_count=record.attack_count,
        project_id=record.project_id,
        error=record.error,
        result_available=result_available,
        artifact_names=job_store.list_artifacts(record.id),
        result_summary=_job_result_summary(job_store, record.id) if result_available else None,
    )


def _retention_entry(deleted: DeletedJob) -> JobRetentionEntry:
    record = deleted.record
    return JobRetentionEntry(
        id=record.id,
        status=record.status,
        created_at=record.created_at,
        completed_at=record.completed_at,
        base_url=record.base_url,
        attack_count=record.attack_count,
        error=record.error,
        result_available=deleted.result_available,
        artifact_names=deleted.artifact_names,
    )


def _validate_prune_statuses(statuses: list[ApiJobStatus]) -> None:
    invalid = [status.value for status in statuses if status not in PRUNEABLE_JOB_STATUSES]
    if invalid:
        joined = ", ".join(sorted(invalid))
        raise HTTPException(
            status_code=400,
            detail=(
                "Only completed and failed jobs can be pruned. "
                f"Received unsupported statuses: {joined}."
            ),
        )


def _matching_job_records(
    job_store: JobStore,
    *,
    statuses: list[ApiJobStatus],
    completed_before: datetime | None,
    limit: int,
    project_id: str | None = None,
) -> list[JobRecord]:
    matched_records: list[JobRecord] = []
    for record in job_store.list_job_records():
        if project_id is not None and record.project_id != project_id:
            continue
        if record.status not in statuses:
            continue
        if completed_before is not None:
            if record.completed_at is None or record.completed_at > completed_before:
                continue
        matched_records.append(record)
        if len(matched_records) >= limit:
            break
    return matched_records


def _default_frontend_dir() -> Path:
    configured = os.environ.get("KNIVES_OUT_FRONTEND_DIR")
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parents[2] / "frontend" / "dist"


def _cors_allowed_origins() -> list[str]:
    configured = os.environ.get("KNIVES_OUT_CORS_ALLOW_ORIGINS", "")
    return [origin.strip() for origin in configured.split(",") if origin.strip()]


def _default_source_for_mode(source_mode: ProjectSourceMode) -> SourcePayload | None:
    if source_mode == ProjectSourceMode.openapi:
        return SourcePayload(name="openapi.yaml", content="")
    if source_mode == ProjectSourceMode.graphql:
        return SourcePayload(name="schema.graphql", content="")
    if source_mode == ProjectSourceMode.learned:
        return SourcePayload(name="learned-model.json", content="")
    return None


def _profile_artifact_segment(profile_name: str) -> str:
    return _PROFILE_ARTIFACT_SEGMENT_RE.sub("-", profile_name).strip("-") or "profile"


def _artifact_reference(
    available_artifacts: set[str],
    *,
    label: str,
    kind: ArtifactReferenceKind,
    artifact_name: str,
    profile: str | None = None,
    step_index: int | None = None,
) -> ArtifactReferenceResponse:
    return ArtifactReferenceResponse(
        label=label,
        kind=kind,
        artifact_name=artifact_name,
        available=artifact_name in available_artifacts,
        profile=profile,
        step_index=step_index,
    )


def _finding_artifact_references(
    available_artifacts: set[str],
    result: AttackResult,
) -> list[ArtifactReferenceResponse]:
    references = [
        _artifact_reference(
            available_artifacts,
            label="Request artifact" if result.type == "request" else "Workflow terminal artifact",
            kind=(
                ArtifactReferenceKind.request
                if result.type == "request"
                else ArtifactReferenceKind.workflow_terminal
            ),
            artifact_name=f"{result.attack_id}.json",
        )
    ]
    for index, _ in enumerate(result.workflow_steps or [], start=1):
        references.append(
            _artifact_reference(
                available_artifacts,
                label=f"Workflow step {index}",
                kind=ArtifactReferenceKind.workflow_step,
                artifact_name=f"{result.attack_id}-step-{index:02d}.json",
                step_index=index,
            )
        )
    for profile_result in result.profile_results or []:
        profile_segment = _profile_artifact_segment(profile_result.profile)
        references.append(
            _artifact_reference(
                available_artifacts,
                label=f"{profile_result.profile} profile artifact",
                kind=ArtifactReferenceKind.profile_request,
                artifact_name=f"{profile_segment}/{result.attack_id}.json",
                profile=profile_result.profile,
            )
        )
        for index, _ in enumerate(profile_result.workflow_steps or [], start=1):
            references.append(
                _artifact_reference(
                    available_artifacts,
                    label=f"{profile_result.profile} step {index}",
                    kind=ArtifactReferenceKind.profile_workflow_step,
                    artifact_name=f"{profile_segment}/{result.attack_id}-step-{index:02d}.json",
                    profile=profile_result.profile,
                    step_index=index,
                )
            )
    return references


def _finding_result(results: AttackResults, attack_id: str) -> AttackResult:
    for result in results.results:
        if result.attack_id == attack_id:
            return result
    raise HTTPException(status_code=404, detail="Finding not found for job.")


def _highlighted_auth_events(results: AttackResults, result: AttackResult):
    if not result.profile_results:
        return []
    profiles = {profile_result.profile for profile_result in result.profile_results}
    return [event for event in results.auth_events if event.profile in profiles]


def _project_source_name(project: ProjectRecord) -> str | None:
    if project.source is not None:
        return project.source.name
    if project.discover_inputs:
        return project.discover_inputs[0].name
    return None


def _project_summary(
    project: ProjectRecord,
    *,
    jobs: list[JobStatusResponse],
) -> ProjectSummaryResponse:
    latest_job = jobs[0] if jobs else None
    active_flagged_count = None
    if project.artifacts.latest_summary is not None:
        active_flagged_count = project.artifacts.latest_summary.active_flagged_count
    return ProjectSummaryResponse(
        id=project.id,
        name=project.name,
        source_mode=project.source_mode,
        active_step=project.active_step,
        created_at=project.created_at,
        updated_at=project.updated_at,
        source_name=_project_source_name(project),
        job_count=len(jobs),
        last_run_job_id=(
            latest_job.id if latest_job is not None else project.artifacts.last_run_job_id
        ),
        last_run_status=latest_job.status if latest_job is not None else None,
        last_run_at=(
            latest_job.completed_at or latest_job.started_at or latest_job.created_at
            if latest_job is not None
            else None
        ),
        active_flagged_count=active_flagged_count,
    )


def _effective_project_review_draft(
    project: ProjectRecord,
    request: ProjectReviewRequest,
) -> ProjectReviewDraft:
    changes = request.model_dump(exclude_unset=True)
    if not changes:
        return project.review_draft
    return ProjectReviewDraft.model_validate(
        {
            **project.review_draft.model_dump(mode="python"),
            **changes,
        }
    )


def _latest_completed_project_job(job_store: JobStore, project_id: str) -> JobRecord | None:
    for record in job_store.list_job_records():
        if record.project_id != project_id:
            continue
        if record.status != ApiJobStatus.completed:
            continue
        if not job_store.result_exists(record.id):
            continue
        return record
    return None


def _project_baseline_job(job_store: JobStore, project_id: str, baseline_job_id: str) -> JobRecord:
    try:
        record = job_store.load_job(baseline_job_id)
    except JobNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Baseline job not found.") from exc
    if record.project_id != project_id:
        raise HTTPException(
            status_code=400,
            detail="Baseline job must belong to the same project.",
        )
    if record.status != ApiJobStatus.completed or not job_store.result_exists(record.id):
        raise HTTPException(
            status_code=400,
            detail="Baseline job must be completed and have stored results.",
        )
    return record


def _frontend_missing_response(frontend_root: Path) -> HTMLResponse:
    return HTMLResponse(
        (
            '<!DOCTYPE html><html><body style="font-family:sans-serif;padding:24px;">'
            "<h1>knives-out frontend not built</h1>"
            f"<p>Expected frontend assets under <code>{frontend_root}</code>.</p>"
            "<p>Run <code>npm install</code> and <code>npm run build</code> in "
            "<code>frontend/</code>, then restart the API.</p>"
            "</body></html>"
        ),
        status_code=503,
    )


def _frontend_response(frontend_root: Path, asset_path: str) -> FileResponse | HTMLResponse:
    if not frontend_root.exists():
        return _frontend_missing_response(frontend_root)

    clean_path = asset_path.lstrip("/")
    candidate = frontend_root / clean_path if clean_path else frontend_root / "index.html"
    if candidate.exists() and candidate.is_file():
        return FileResponse(candidate)

    if clean_path and "." in Path(clean_path).name:
        raise HTTPException(status_code=404, detail="Frontend asset not found.")

    index_path = frontend_root / "index.html"
    if not index_path.exists():
        return _frontend_missing_response(frontend_root)
    return FileResponse(index_path)


def _run_job_worker(job_store: JobStore, job_id: str, request: RunRequest) -> None:
    record = job_store.load_job(job_id).model_copy(
        update={"status": ApiJobStatus.running, "started_at": datetime.now(UTC)}
    )
    job_store.update_job(record)
    try:
        run_result = run_suite_from_inline(
            request.suite,
            base_url=request.base_url,
            default_headers=request.headers,
            default_query=request.query,
            timeout_seconds=request.timeout,
            artifact_dir=job_store.artifact_dir(job_id) if request.store_artifacts else None,
            auth_plugin_names=request.auth_plugin_names,
            auth_config_yaml=request.auth_config_yaml,
            auth_profile_names=request.auth_profile_names,
            profile_file_yaml=request.profile_file_yaml,
            profile_names=request.profile_names,
            operation=request.operation,
            exclude_operation=request.exclude_operation,
            method=request.method,
            exclude_method=request.exclude_method,
            kind=request.kind,
            exclude_kind=request.exclude_kind,
            tag=request.tag,
            exclude_tag=request.exclude_tag,
            path=request.path,
            exclude_path=request.exclude_path,
        )
        job_store.write_result(job_id, run_result.results)
        completed = record.model_copy(
            update={
                "status": ApiJobStatus.completed,
                "completed_at": datetime.now(UTC),
                "attack_count": len(run_result.suite.attacks),
            }
        )
        job_store.update_job(completed)
    except Exception as exc:  # noqa: BLE001
        failed = record.model_copy(
            update={
                "status": ApiJobStatus.failed,
                "completed_at": datetime.now(UTC),
                "error": str(exc),
            }
        )
        job_store.update_job(failed)


def create_app(
    *,
    data_dir: Path | None = None,
    frontend_dir: Path | None = None,
) -> FastAPI:
    app = FastAPI(
        title="knives-out API",
        version=__version__,
        description="Local-first API for adversarial API testing from specs and observed traffic.",
    )
    allowed_origins = _cors_allowed_origins()
    if allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=allowed_origins,
            allow_credentials=False,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    root = data_dir or _default_data_dir()
    app.state.job_store = JobStore(root)
    app.state.project_store = ProjectStore(root)
    app.state.frontend_dir = frontend_dir or _default_frontend_dir()

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/", include_in_schema=False)
    def root():
        return RedirectResponse(url="/app/")

    @app.get("/v1/projects", response_model=ProjectListResponse)
    def list_projects() -> ProjectListResponse:
        project_store: ProjectStore = app.state.project_store
        job_store: JobStore = app.state.job_store
        jobs_by_project: dict[str, list[JobStatusResponse]] = defaultdict(list)
        for record in job_store.list_job_records():
            if record.project_id is None:
                continue
            jobs_by_project[record.project_id].append(_job_status_response(job_store, record))
        return ProjectListResponse(
            projects=[
                _project_summary(project, jobs=jobs_by_project.get(project.id, []))
                for project in project_store.list_projects()
            ]
        )

    @app.post("/v1/projects", response_model=ProjectRecord)
    def create_project(request: ProjectCreateRequest) -> ProjectRecord:
        project_store: ProjectStore = app.state.project_store
        now = datetime.now(UTC)
        record = ProjectRecord(
            name=request.name,
            source_mode=request.source_mode,
            active_step=request.active_step,
            created_at=now,
            updated_at=now,
            graphql_endpoint=request.graphql_endpoint,
            source=request.source or _default_source_for_mode(request.source_mode),
            discover_inputs=request.discover_inputs,
            inspect_draft=request.inspect_draft,
            generate_draft=request.generate_draft,
            run_draft=request.run_draft,
            review_draft=request.review_draft,
            artifacts=request.artifacts,
        )
        return project_store.create_project(record)

    @app.get("/v1/projects/{project_id}", response_model=ProjectRecord)
    def get_project(project_id: str) -> ProjectRecord:
        project_store: ProjectStore = app.state.project_store
        try:
            return project_store.load_project(project_id)
        except ProjectNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Project not found.") from exc

    @app.patch("/v1/projects/{project_id}", response_model=ProjectRecord)
    def update_project(project_id: str, request: ProjectUpdateRequest) -> ProjectRecord:
        project_store: ProjectStore = app.state.project_store
        try:
            current = project_store.load_project(project_id)
        except ProjectNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Project not found.") from exc

        changes = request.model_dump(exclude_unset=True)
        if (
            "source_mode" in changes
            and "source" not in changes
            and current.source is None
            and changes["source_mode"] != ProjectSourceMode.capture_upload
        ):
            changes["source"] = _default_source_for_mode(changes["source_mode"])

        updated = ProjectRecord.model_validate(
            {
                **current.model_dump(mode="python"),
                **changes,
                "updated_at": datetime.now(UTC),
            }
        )
        return project_store.update_project(updated)

    @app.delete("/v1/projects/{project_id}")
    def delete_project(project_id: str) -> dict[str, bool]:
        project_store: ProjectStore = app.state.project_store
        job_store: JobStore = app.state.job_store
        try:
            project_store.load_project(project_id)
        except ProjectNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Project not found.") from exc

        for record in job_store.list_job_records():
            if record.project_id != project_id:
                continue
            try:
                job_store.delete_job(record.id)
            except ActiveJobDeletionError as exc:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "Projects with active jobs cannot be deleted; wait for those jobs to "
                        "complete or fail first."
                    ),
                ) from exc
        project_store.delete_project(project_id)
        return {"deleted": True}

    @app.get("/v1/projects/{project_id}/jobs", response_model=ProjectJobsResponse)
    def list_project_jobs(project_id: str) -> ProjectJobsResponse:
        project_store: ProjectStore = app.state.project_store
        job_store: JobStore = app.state.job_store
        try:
            project_store.load_project(project_id)
        except ProjectNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Project not found.") from exc
        jobs = [
            _job_status_response(job_store, record)
            for record in job_store.list_job_records()
            if record.project_id == project_id
        ]
        return ProjectJobsResponse(
            project_id=project_id,
            jobs=jobs,
        )

    @app.post("/v1/projects/{project_id}/review", response_model=ProjectReviewResponse)
    def review_project(
        project_id: str,
        request: ProjectReviewRequest,
    ) -> ProjectReviewResponse:
        project_store: ProjectStore = app.state.project_store
        job_store: JobStore = app.state.job_store
        try:
            project = project_store.load_project(project_id)
        except ProjectNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Project not found.") from exc

        review_draft = _effective_project_review_draft(project, request)
        current_job = _latest_completed_project_job(job_store, project_id)
        if current_job is None:
            raise HTTPException(
                status_code=409,
                detail="No completed project run with stored results is available for review.",
            )

        waiting_for_new_run = False
        baseline_results = None
        if review_draft.baseline_mode == ProjectReviewBaselineMode.job:
            if review_draft.baseline_job_id:
                baseline_job = _project_baseline_job(
                    job_store,
                    project_id,
                    review_draft.baseline_job_id,
                )
                if baseline_job.id == current_job.id:
                    waiting_for_new_run = True
                else:
                    baseline_results = job_store.load_result(baseline_job.id)
        elif review_draft.baseline is not None:
            baseline_results = review_draft.baseline

        results = job_store.load_result(current_job.id)
        summary = summarize_results_from_models(
            results,
            baseline=baseline_results,
            suppressions_yaml=review_draft.suppressions_yaml,
            top_limit=PROJECT_REVIEW_TOP_LIMIT,
        )
        verification = verify_results_from_models(
            results,
            baseline=baseline_results,
            suppressions_yaml=review_draft.suppressions_yaml,
            min_severity=review_draft.min_severity,
            min_confidence=review_draft.min_confidence,
        )
        markdown_report = render_report_from_models(
            results,
            baseline=baseline_results,
            suppressions_yaml=review_draft.suppressions_yaml,
            format="markdown",
        )
        html_report = render_report_from_models(
            results,
            baseline=baseline_results,
            suppressions_yaml=review_draft.suppressions_yaml,
            format="html",
        )
        return ProjectReviewResponse(
            project_id=project_id,
            current_job_id=current_job.id,
            baseline_mode=review_draft.baseline_mode,
            baseline_job_id=review_draft.baseline_job_id,
            baseline_used=summary.baseline_used,
            waiting_for_new_run=waiting_for_new_run,
            results=results,
            summary=SummaryResponse(**summary.model_dump(mode="python")),
            verification=_verify_response(verification),
            markdown_report=markdown_report,
            html_report=html_report,
        )

    @app.post("/v1/projects/{project_id}/jobs/prune", response_model=PruneJobsResponse)
    def prune_project_jobs(project_id: str, request: PruneJobsRequest) -> PruneJobsResponse:
        project_store: ProjectStore = app.state.project_store
        job_store: JobStore = app.state.job_store
        try:
            project_store.load_project(project_id)
        except ProjectNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Project not found.") from exc

        _validate_prune_statuses(request.statuses)
        matched_records = _matching_job_records(
            job_store,
            statuses=request.statuses,
            completed_before=request.completed_before,
            limit=request.limit,
            project_id=project_id,
        )

        if request.dry_run:
            jobs = [
                JobRetentionEntry(
                    id=record.id,
                    status=record.status,
                    created_at=record.created_at,
                    completed_at=record.completed_at,
                    base_url=record.base_url,
                    attack_count=record.attack_count,
                    error=record.error,
                    result_available=job_store.result_exists(record.id),
                    artifact_names=job_store.list_artifacts(record.id),
                )
                for record in matched_records
            ]
            return PruneJobsResponse(
                dry_run=True,
                matched_count=len(jobs),
                deleted_count=0,
                jobs=jobs,
            )

        deleted_jobs = [
            _retention_entry(job_store.delete_job(record.id)) for record in matched_records
        ]
        return PruneJobsResponse(
            dry_run=False,
            matched_count=len(matched_records),
            deleted_count=len(deleted_jobs),
            jobs=deleted_jobs,
        )

    @app.delete("/v1/projects/{project_id}/jobs/{job_id}", response_model=DeleteJobResponse)
    def delete_project_job(project_id: str, job_id: str) -> DeleteJobResponse:
        project_store: ProjectStore = app.state.project_store
        job_store: JobStore = app.state.job_store
        try:
            project_store.load_project(project_id)
        except ProjectNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Project not found.") from exc

        try:
            record = job_store.load_job(job_id)
        except JobNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Job not found.") from exc
        if record.project_id != project_id:
            raise HTTPException(status_code=404, detail="Job not found.")

        try:
            deleted = job_store.delete_job(job_id)
        except ActiveJobDeletionError as exc:
            raise HTTPException(
                status_code=409,
                detail="Active jobs cannot be deleted; wait for completion or failure first.",
            ) from exc
        return DeleteJobResponse(deleted=_retention_entry(deleted))

    @app.post("/v1/inspect", response_model=InspectResponse)
    def inspect_endpoint(request: InspectRequest) -> InspectResponse:
        result = inspect_source_inline(
            _inline(request.source),
            graphql_endpoint=request.graphql_endpoint,
            tag=request.tag or None,
            exclude_tag=request.exclude_tag or None,
            path=request.path or None,
            exclude_path=request.exclude_path or None,
        )
        return InspectResponse(
            source_kind=result.loaded.source_kind,
            operations=result.operations,
            warnings=result.loaded.warnings,
            learned_workflow_count=len(result.loaded.learned_model.workflows)
            if result.loaded.learned_model is not None
            else 0,
        )

    @app.post("/v1/generate", response_model=GenerateResponse)
    def generate_endpoint(request: GenerateRequest) -> GenerateResponse:
        result = generate_suite_from_inline(
            _inline(request.source),
            graphql_endpoint=request.graphql_endpoint,
            operation=request.operation or None,
            exclude_operation=request.exclude_operation or None,
            method=request.method or None,
            exclude_method=request.exclude_method or None,
            kind=request.kind or None,
            exclude_kind=request.exclude_kind or None,
            tag=request.tag or None,
            exclude_tag=request.exclude_tag or None,
            path=request.path or None,
            exclude_path=request.exclude_path or None,
            pack_names=request.pack_names or None,
            auto_workflows=request.auto_workflows,
            workflow_pack_names=request.workflow_pack_names or None,
        )
        return GenerateResponse(
            source_kind=result.loaded.source_kind,
            suite=result.suite,
            warnings=result.loaded.warnings,
        )

    @app.post("/v1/discover", response_model=DiscoverResponse)
    def discover_endpoint(request: DiscoverRequest) -> DiscoverResponse:
        learned_model = discover_model_inline([_inline(current) for current in request.inputs])
        return DiscoverResponse(learned_model=learned_model)

    @app.post("/v1/report", response_model=ReportResponse)
    def report_endpoint(request: ReportRequest) -> ReportResponse:
        rendered = render_report_from_models(
            request.results,
            baseline=request.baseline,
            suppressions_yaml=request.suppressions_yaml,
            format=request.format.value,
        )
        return ReportResponse(format=request.format, content=rendered)

    @app.post("/v1/summary", response_model=SummaryResponse)
    def summary_endpoint(request: SummaryRequest) -> SummaryResponse:
        summary = summarize_results_from_models(
            request.results,
            baseline=request.baseline,
            suppressions_yaml=request.suppressions_yaml,
            top_limit=request.top_limit,
        )
        return SummaryResponse(**summary.model_dump(mode="python"))

    @app.post("/v1/verify", response_model=VerifyResponse)
    def verify_endpoint(request: VerifyRequest) -> VerifyResponse:
        verification = verify_results_from_models(
            request.results,
            baseline=request.baseline,
            suppressions_yaml=request.suppressions_yaml,
            min_severity=request.min_severity,
            min_confidence=request.min_confidence,
        )
        return _verify_response(verification)

    @app.post("/v1/promote", response_model=PromoteResponse)
    def promote_endpoint(request: PromoteRequest) -> PromoteResponse:
        promotion = promote_results_from_models(
            request.results,
            request.attacks,
            baseline=request.baseline,
            suppressions_yaml=request.suppressions_yaml,
            min_severity=request.min_severity,
            min_confidence=request.min_confidence,
        )
        return PromoteResponse(
            promoted_suite=promotion.promoted_suite,
            promoted_attack_ids=promotion.promoted_attack_ids,
            baseline_used=promotion.verification.baseline_used,
        )

    @app.post("/v1/triage", response_model=TriageResponse)
    def triage_endpoint(request: TriageRequest) -> TriageResponse:
        suppressions_file, added_count = triage_results_from_model(
            request.results,
            existing_suppressions_yaml=request.existing_suppressions_yaml,
        )
        rendered_yaml = yaml.safe_dump(
            suppressions_file.model_dump(mode="json", exclude_none=True),
            sort_keys=False,
            allow_unicode=False,
        )
        return TriageResponse(
            suppressions=suppressions_file,
            added_count=added_count,
            rendered_yaml=rendered_yaml,
        )

    @app.post("/v1/runs", response_model=JobStatusResponse)
    def create_run_job(request: RunRequest) -> JobStatusResponse:
        job_store: JobStore = app.state.job_store
        project_store: ProjectStore = app.state.project_store
        if request.project_id is not None:
            try:
                project_store.load_project(request.project_id)
            except ProjectNotFoundError as exc:
                raise HTTPException(status_code=404, detail="Project not found.") from exc
        record = job_store.create_job(
            JobRecord(
                base_url=request.base_url,
                attack_count=len(request.suite.attacks),
                project_id=request.project_id,
            )
        )
        thread = threading.Thread(
            target=_run_job_worker,
            args=(job_store, record.id, request),
            daemon=True,
        )
        thread.start()
        return _job_status_response(job_store, record)

    @app.get("/v1/jobs", response_model=JobListResponse)
    def list_jobs(
        status: Annotated[list[ApiJobStatus] | None, Query()] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 20,
    ) -> JobListResponse:
        job_store: JobStore = app.state.job_store
        records = job_store.list_jobs(
            statuses=set(status) if status else None,
            limit=limit,
        )
        jobs = [_job_status_response(job_store, record) for record in records]
        return JobListResponse(count=len(jobs), jobs=jobs)

    @app.get("/v1/jobs/{job_id}", response_model=JobStatusResponse)
    def get_job(job_id: str) -> JobStatusResponse:
        job_store: JobStore = app.state.job_store
        try:
            return _job_status_response(job_store, job_store.load_job(job_id))
        except JobNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Job not found.") from exc

    @app.delete("/v1/jobs/{job_id}", response_model=DeleteJobResponse)
    def delete_job(job_id: str) -> DeleteJobResponse:
        job_store: JobStore = app.state.job_store
        try:
            deleted = job_store.delete_job(job_id)
        except JobNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Job not found.") from exc
        except ActiveJobDeletionError as exc:
            raise HTTPException(
                status_code=409,
                detail="Active jobs cannot be deleted; wait for completion or failure first.",
            ) from exc
        return DeleteJobResponse(deleted=_retention_entry(deleted))

    @app.post("/v1/jobs/prune", response_model=PruneJobsResponse)
    def prune_jobs(request: PruneJobsRequest) -> PruneJobsResponse:
        _validate_prune_statuses(request.statuses)
        job_store: JobStore = app.state.job_store

        matched_records = _matching_job_records(
            job_store,
            statuses=request.statuses,
            completed_before=request.completed_before,
            limit=request.limit,
        )

        if request.dry_run:
            jobs = [
                JobRetentionEntry(
                    id=record.id,
                    status=record.status,
                    created_at=record.created_at,
                    completed_at=record.completed_at,
                    base_url=record.base_url,
                    attack_count=record.attack_count,
                    error=record.error,
                    result_available=job_store.result_exists(record.id),
                    artifact_names=job_store.list_artifacts(record.id),
                )
                for record in matched_records
            ]
            return PruneJobsResponse(
                dry_run=True,
                matched_count=len(jobs),
                deleted_count=0,
                jobs=jobs,
            )

        deleted_jobs = [
            _retention_entry(job_store.delete_job(record.id)) for record in matched_records
        ]
        return PruneJobsResponse(
            dry_run=False,
            matched_count=len(matched_records),
            deleted_count=len(deleted_jobs),
            jobs=deleted_jobs,
        )

    @app.get("/v1/jobs/{job_id}/result", response_model=AttackResults)
    def get_job_result(job_id: str) -> AttackResults:
        job_store: JobStore = app.state.job_store
        try:
            return job_store.load_result(job_id)
        except JobNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Job result not available.") from exc

    @app.get(
        "/v1/jobs/{job_id}/findings/{attack_id}/evidence",
        response_model=JobFindingEvidenceResponse,
    )
    def get_job_finding_evidence(job_id: str, attack_id: str) -> JobFindingEvidenceResponse:
        job_store: JobStore = app.state.job_store
        try:
            job_store.load_job(job_id)
        except JobNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Job not found.") from exc
        try:
            results = job_store.load_result(job_id)
        except JobNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Job result not available.") from exc

        result = _finding_result(results, attack_id)
        artifacts = _finding_artifact_references(set(job_store.list_artifacts(job_id)), result)
        return JobFindingEvidenceResponse(
            job_id=job_id,
            attack_id=attack_id,
            result=result,
            artifacts=artifacts,
            auth_events=results.auth_events,
            highlighted_auth_events=_highlighted_auth_events(results, result),
        )

    @app.get("/v1/jobs/{job_id}/artifacts", response_model=ArtifactListResponse)
    def get_job_artifacts(job_id: str) -> ArtifactListResponse:
        job_store: JobStore = app.state.job_store
        try:
            job_store.load_job(job_id)
            return job_store.artifact_list_response(job_id)
        except JobNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Job not found.") from exc

    @app.get("/v1/jobs/{job_id}/artifacts/{artifact_name:path}")
    def get_job_artifact(job_id: str, artifact_name: str):
        job_store: JobStore = app.state.job_store
        try:
            path = job_store.artifact_path_for_name(job_id, artifact_name)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Artifact not found.") from exc
        return FileResponse(path)

    @app.get("/app", include_in_schema=False)
    def serve_frontend_index():
        frontend_root: Path = app.state.frontend_dir
        return _frontend_response(frontend_root, "")

    @app.get("/app/", include_in_schema=False)
    def serve_frontend_index_slash():
        frontend_root: Path = app.state.frontend_dir
        return _frontend_response(frontend_root, "")

    @app.get("/app/{asset_path:path}", include_in_schema=False)
    def serve_frontend_asset(asset_path: str):
        frontend_root: Path = app.state.frontend_dir
        return _frontend_response(frontend_root, asset_path)

    return app


app = create_app()
