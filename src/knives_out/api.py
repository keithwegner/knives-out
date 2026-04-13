from __future__ import annotations

import os
import threading
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse

from knives_out.api_models import (
    ApiJobStatus,
    ArtifactListResponse,
    DeltaChangeResponse,
    DiscoverRequest,
    DiscoverResponse,
    FindingSummaryResponse,
    GenerateRequest,
    GenerateResponse,
    InspectRequest,
    InspectResponse,
    JobListResponse,
    JobRecord,
    JobStatusResponse,
    PromoteRequest,
    PromoteResponse,
    ReportRequest,
    ReportResponse,
    RunRequest,
    SummaryRequest,
    SummaryResponse,
    TriageRequest,
    TriageResponse,
    VerifyRequest,
    VerifyResponse,
)
from knives_out.api_store import JobNotFoundError, JobStore
from knives_out.models import AttackResults, ResultsSummary
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

JOB_SUMMARY_TOP_LIMIT = 3


def _finding_summary(finding) -> FindingSummaryResponse:
    result = finding.result
    delta_changes = []
    if finding.delta is not None:
        delta_changes = [
            DeltaChangeResponse(
                field=change.field,
                baseline=change.baseline,
                current=change.current,
            )
            for change in finding.delta.changes
        ]
    return FindingSummaryResponse(
        change=finding.change,
        attack_id=result.attack_id,
        name=result.name,
        protocol="rest" if result.protocol == "openapi" else result.protocol,
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
        error=record.error,
        result_available=result_available,
        artifact_names=job_store.list_artifacts(record.id),
        result_summary=_job_result_summary(job_store, record.id) if result_available else None,
    )


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


def create_app(*, data_dir: Path | None = None) -> FastAPI:
    app = FastAPI(
        title="knives-out API",
        version="0.11.0",
        description="Local-first API for adversarial API testing from specs and observed traffic.",
    )
    app.state.job_store = JobStore(data_dir or _default_data_dir())

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

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
        return TriageResponse(suppressions=suppressions_file, added_count=added_count)

    @app.post("/v1/runs", response_model=JobStatusResponse)
    def create_run_job(request: RunRequest) -> JobStatusResponse:
        job_store: JobStore = app.state.job_store
        record = job_store.create_job(
            JobRecord(base_url=request.base_url, attack_count=len(request.suite.attacks))
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
        status: list[ApiJobStatus] | None = Query(default=None),
        limit: int = Query(default=20, ge=1, le=100),
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

    @app.get("/v1/jobs/{job_id}/result", response_model=AttackResults)
    def get_job_result(job_id: str) -> AttackResults:
        job_store: JobStore = app.state.job_store
        try:
            return job_store.load_result(job_id)
        except JobNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Job result not available.") from exc

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

    return app


app = create_app()
