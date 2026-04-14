from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from knives_out.models import (
    AttackResults,
    AttackSuite,
    LearnedModel,
    OperationSpec,
    PreflightWarning,
    ResultsSummary,
    SourceKind,
)
from knives_out.suppressions import SuppressionsFile


class ApiReportFormat(StrEnum):
    markdown = "markdown"
    html = "html"


class ApiJobStatus(StrEnum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class ProjectSourceMode(StrEnum):
    openapi = "openapi"
    graphql = "graphql"
    learned = "learned"
    capture_upload = "capture_upload"


class ProjectStep(StrEnum):
    source = "source"
    inspect = "inspect"
    generate = "generate"
    run = "run"
    review = "review"


class SourcePayload(BaseModel):
    name: str
    content: str


class InspectRequest(BaseModel):
    source: SourcePayload
    graphql_endpoint: str = "/graphql"
    tag: list[str] = Field(default_factory=list)
    exclude_tag: list[str] = Field(default_factory=list)
    path: list[str] = Field(default_factory=list)
    exclude_path: list[str] = Field(default_factory=list)


class InspectResponse(BaseModel):
    source_kind: SourceKind
    operations: list[OperationSpec]
    warnings: list[PreflightWarning] = Field(default_factory=list)
    learned_workflow_count: int = 0


class GenerateRequest(BaseModel):
    source: SourcePayload
    graphql_endpoint: str = "/graphql"
    operation: list[str] = Field(default_factory=list)
    exclude_operation: list[str] = Field(default_factory=list)
    method: list[str] = Field(default_factory=list)
    exclude_method: list[str] = Field(default_factory=list)
    kind: list[str] = Field(default_factory=list)
    exclude_kind: list[str] = Field(default_factory=list)
    tag: list[str] = Field(default_factory=list)
    exclude_tag: list[str] = Field(default_factory=list)
    path: list[str] = Field(default_factory=list)
    exclude_path: list[str] = Field(default_factory=list)
    pack_names: list[str] = Field(default_factory=list)
    auto_workflows: bool = False
    workflow_pack_names: list[str] = Field(default_factory=list)


class GenerateResponse(BaseModel):
    source_kind: SourceKind
    suite: AttackSuite
    warnings: list[PreflightWarning] = Field(default_factory=list)


class DiscoverRequest(BaseModel):
    inputs: list[SourcePayload]


class DiscoverResponse(BaseModel):
    learned_model: LearnedModel


class RunRequest(BaseModel):
    project_id: str | None = None
    suite: AttackSuite
    base_url: str
    headers: dict[str, str] = Field(default_factory=dict)
    query: dict[str, Any] = Field(default_factory=dict)
    timeout: float = 10.0
    store_artifacts: bool = True
    auth_plugin_names: list[str] = Field(default_factory=list)
    auth_config_yaml: str | None = None
    auth_profile_names: list[str] = Field(default_factory=list)
    profile_file_yaml: str | None = None
    profile_names: list[str] = Field(default_factory=list)
    operation: list[str] = Field(default_factory=list)
    exclude_operation: list[str] = Field(default_factory=list)
    method: list[str] = Field(default_factory=list)
    exclude_method: list[str] = Field(default_factory=list)
    kind: list[str] = Field(default_factory=list)
    exclude_kind: list[str] = Field(default_factory=list)
    tag: list[str] = Field(default_factory=list)
    exclude_tag: list[str] = Field(default_factory=list)
    path: list[str] = Field(default_factory=list)
    exclude_path: list[str] = Field(default_factory=list)


class DeltaChangeResponse(BaseModel):
    field: str
    baseline: str
    current: str


class FindingSummaryResponse(BaseModel):
    change: str
    attack_id: str
    name: str
    protocol: str
    kind: str
    method: str
    path: str | None = None
    tags: list[str] = Field(default_factory=list)
    issue: str | None = None
    severity: str
    confidence: str
    status_code: int | None = None
    url: str
    delta_changes: list[DeltaChangeResponse] = Field(default_factory=list)


class SummaryRequest(BaseModel):
    results: AttackResults
    baseline: AttackResults | None = None
    suppressions_yaml: str | None = None
    top_limit: int = Field(default=10, ge=0)


class VerifyRequest(BaseModel):
    results: AttackResults
    baseline: AttackResults | None = None
    suppressions_yaml: str | None = None
    min_severity: str = "high"
    min_confidence: str = "medium"


class VerifyResponse(BaseModel):
    passed: bool
    baseline_used: bool
    min_severity: str
    min_confidence: str
    current_findings_count: int
    new_findings_count: int
    resolved_findings_count: int
    persisting_findings_count: int
    suppressed_current_findings_count: int
    current_findings: list[FindingSummaryResponse] = Field(default_factory=list)
    failing_findings: list[FindingSummaryResponse] = Field(default_factory=list)
    new_findings: list[FindingSummaryResponse] = Field(default_factory=list)
    resolved_findings: list[FindingSummaryResponse] = Field(default_factory=list)
    persisting_findings: list[FindingSummaryResponse] = Field(default_factory=list)


class ReportRequest(BaseModel):
    results: AttackResults
    baseline: AttackResults | None = None
    suppressions_yaml: str | None = None
    format: ApiReportFormat = ApiReportFormat.markdown


class ReportResponse(BaseModel):
    format: ApiReportFormat
    content: str


class SummaryResponse(ResultsSummary):
    pass


class PromoteRequest(BaseModel):
    results: AttackResults
    attacks: AttackSuite
    baseline: AttackResults | None = None
    suppressions_yaml: str | None = None
    min_severity: str = "high"
    min_confidence: str = "medium"


class PromoteResponse(BaseModel):
    promoted_suite: AttackSuite
    promoted_attack_ids: list[str]
    baseline_used: bool


class TriageRequest(BaseModel):
    results: AttackResults
    existing_suppressions_yaml: str | None = None


class TriageResponse(BaseModel):
    suppressions: SuppressionsFile
    added_count: int
    rendered_yaml: str


class JobRecord(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    kind: str = "run"
    status: ApiJobStatus = ApiJobStatus.pending
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    base_url: str
    attack_count: int
    project_id: str | None = None
    error: str | None = None


class JobStatusResponse(BaseModel):
    id: str
    kind: str
    status: ApiJobStatus
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    base_url: str
    attack_count: int
    project_id: str | None = None
    error: str | None = None
    result_available: bool = False
    artifact_names: list[str] = Field(default_factory=list)
    result_summary: ResultsSummary | None = None


class ArtifactListResponse(BaseModel):
    job_id: str
    artifacts: list[str] = Field(default_factory=list)


class JobListResponse(BaseModel):
    count: int
    jobs: list[JobStatusResponse] = Field(default_factory=list)


class JobRetentionEntry(BaseModel):
    id: str
    status: ApiJobStatus
    created_at: datetime
    completed_at: datetime | None = None
    base_url: str
    attack_count: int
    error: str | None = None
    result_available: bool = False
    artifact_names: list[str] = Field(default_factory=list)


class DeleteJobResponse(BaseModel):
    deleted: JobRetentionEntry


class PruneJobsRequest(BaseModel):
    statuses: list[ApiJobStatus] = Field(
        default_factory=lambda: [ApiJobStatus.completed, ApiJobStatus.failed]
    )
    completed_before: datetime | None = None
    limit: int = Field(default=100, ge=1, le=500)
    dry_run: bool = False


class PruneJobsResponse(BaseModel):
    dry_run: bool = False
    matched_count: int = 0
    deleted_count: int = 0
    jobs: list[JobRetentionEntry] = Field(default_factory=list)


class ProjectInspectDraft(BaseModel):
    tag: list[str] = Field(default_factory=list)
    exclude_tag: list[str] = Field(default_factory=list)
    path: list[str] = Field(default_factory=list)
    exclude_path: list[str] = Field(default_factory=list)


class ProjectGenerateDraft(BaseModel):
    operation: list[str] = Field(default_factory=list)
    exclude_operation: list[str] = Field(default_factory=list)
    method: list[str] = Field(default_factory=list)
    exclude_method: list[str] = Field(default_factory=list)
    kind: list[str] = Field(default_factory=list)
    exclude_kind: list[str] = Field(default_factory=list)
    tag: list[str] = Field(default_factory=list)
    exclude_tag: list[str] = Field(default_factory=list)
    path: list[str] = Field(default_factory=list)
    exclude_path: list[str] = Field(default_factory=list)
    pack_names: list[str] = Field(default_factory=list)
    auto_workflows: bool = False
    workflow_pack_names: list[str] = Field(default_factory=list)


class ProjectRunDraft(BaseModel):
    base_url: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    query: dict[str, Any] = Field(default_factory=dict)
    timeout: float = 10.0
    store_artifacts: bool = True
    auth_plugin_names: list[str] = Field(default_factory=list)
    auth_config_yaml: str | None = None
    auth_profile_names: list[str] = Field(default_factory=list)
    profile_file_yaml: str | None = None
    profile_names: list[str] = Field(default_factory=list)
    operation: list[str] = Field(default_factory=list)
    exclude_operation: list[str] = Field(default_factory=list)
    method: list[str] = Field(default_factory=list)
    exclude_method: list[str] = Field(default_factory=list)
    kind: list[str] = Field(default_factory=list)
    exclude_kind: list[str] = Field(default_factory=list)
    tag: list[str] = Field(default_factory=list)
    exclude_tag: list[str] = Field(default_factory=list)
    path: list[str] = Field(default_factory=list)
    exclude_path: list[str] = Field(default_factory=list)


class ProjectReviewDraft(BaseModel):
    baseline_job_id: str | None = None
    baseline: AttackResults | None = None
    suppressions_yaml: str | None = None
    min_severity: str = "high"
    min_confidence: str = "medium"


class ProjectArtifacts(BaseModel):
    learned_model: LearnedModel | None = None
    inspect_result: InspectResponse | None = None
    generated_suite: AttackSuite | None = None
    latest_results: AttackResults | None = None
    latest_summary: ResultsSummary | None = None
    latest_verification: VerifyResponse | None = None
    latest_markdown_report: str | None = None
    latest_html_report: str | None = None
    latest_suppressions: SuppressionsFile | None = None
    latest_promoted_suite: AttackSuite | None = None
    last_run_job_id: str | None = None


class ProjectRecord(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    name: str
    source_mode: ProjectSourceMode = ProjectSourceMode.openapi
    active_step: ProjectStep = ProjectStep.source
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    graphql_endpoint: str = "/graphql"
    source: SourcePayload | None = None
    discover_inputs: list[SourcePayload] = Field(default_factory=list)
    inspect_draft: ProjectInspectDraft = Field(default_factory=ProjectInspectDraft)
    generate_draft: ProjectGenerateDraft = Field(default_factory=ProjectGenerateDraft)
    run_draft: ProjectRunDraft = Field(default_factory=ProjectRunDraft)
    review_draft: ProjectReviewDraft = Field(default_factory=ProjectReviewDraft)
    artifacts: ProjectArtifacts = Field(default_factory=ProjectArtifacts)


class ProjectCreateRequest(BaseModel):
    name: str
    source_mode: ProjectSourceMode = ProjectSourceMode.openapi
    active_step: ProjectStep = ProjectStep.source
    graphql_endpoint: str = "/graphql"
    source: SourcePayload | None = None
    discover_inputs: list[SourcePayload] = Field(default_factory=list)
    inspect_draft: ProjectInspectDraft = Field(default_factory=ProjectInspectDraft)
    generate_draft: ProjectGenerateDraft = Field(default_factory=ProjectGenerateDraft)
    run_draft: ProjectRunDraft = Field(default_factory=ProjectRunDraft)
    review_draft: ProjectReviewDraft = Field(default_factory=ProjectReviewDraft)
    artifacts: ProjectArtifacts = Field(default_factory=ProjectArtifacts)


class ProjectUpdateRequest(BaseModel):
    name: str | None = None
    source_mode: ProjectSourceMode | None = None
    active_step: ProjectStep | None = None
    graphql_endpoint: str | None = None
    source: SourcePayload | None = None
    discover_inputs: list[SourcePayload] | None = None
    inspect_draft: ProjectInspectDraft | None = None
    generate_draft: ProjectGenerateDraft | None = None
    run_draft: ProjectRunDraft | None = None
    review_draft: ProjectReviewDraft | None = None
    artifacts: ProjectArtifacts | None = None


class ProjectSummaryResponse(BaseModel):
    id: str
    name: str
    source_mode: ProjectSourceMode
    active_step: ProjectStep
    created_at: datetime
    updated_at: datetime
    source_name: str | None = None
    job_count: int = 0
    last_run_job_id: str | None = None
    last_run_status: ApiJobStatus | None = None
    last_run_at: datetime | None = None
    active_flagged_count: int | None = None


class ProjectListResponse(BaseModel):
    projects: list[ProjectSummaryResponse] = Field(default_factory=list)


class ProjectJobsResponse(BaseModel):
    project_id: str
    jobs: list[JobStatusResponse] = Field(default_factory=list)
