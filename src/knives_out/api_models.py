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


class JobRecord(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    kind: str = "run"
    status: ApiJobStatus = ApiJobStatus.pending
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    base_url: str
    attack_count: int
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
    error: str | None = None
    result_available: bool = False
    artifact_names: list[str] = Field(default_factory=list)


class ArtifactListResponse(BaseModel):
    job_id: str
    artifacts: list[str] = Field(default_factory=list)
