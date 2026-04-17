from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, model_validator

SeverityLevel = Literal["none", "low", "medium", "high", "critical"]
ConfidenceLevel = Literal["none", "low", "medium", "high"]
AttackType = Literal["request", "workflow"]
AuthEventPhase = Literal["acquire", "refresh"]
SourceKind = Literal["openapi", "graphql", "learned"]
CaptureSource = Literal["proxy", "har"]
LearnedBindingTarget = Literal["path", "query", "body"]
GraphQLOutputKind = Literal["scalar", "enum", "object", "list", "interface", "union"]
GraphQLOperationType = Literal["query", "mutation", "subscription"]


class CapturedRequest(BaseModel):
    method: str
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    query: dict[str, Any] = Field(default_factory=dict)
    body_json: Any | None = None
    raw_body: str | None = None
    content_type: str | None = None


class CapturedResponse(BaseModel):
    status_code: int | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    body_json: Any | None = None
    raw_body: str | None = None
    content_type: str | None = None
    duration_ms: float | None = None
    error: str | None = None


class CaptureEvent(BaseModel):
    artifact_type: Literal["capture-event"] = "capture-event"
    version: int = 1
    captured_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: CaptureSource = "proxy"
    identity_context: str | None = None
    request: CapturedRequest
    response: CapturedResponse | None = None


class ObservedRequestExample(BaseModel):
    path_params: dict[str, Any] = Field(default_factory=dict)
    query: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    body_json: Any | None = None
    raw_body: str | None = None
    content_type: str | None = None
    status_code: int | None = None
    response_json: Any | None = None
    response_content_type: str | None = None
    identity_context: str | None = None


class ParameterSpec(BaseModel):
    name: str
    location: str
    required: bool = False
    schema_def: dict[str, Any] = Field(default_factory=dict)


class ResponseSpec(BaseModel):
    content_type: str | None = None
    schema_def: dict[str, Any] | None = None


class GraphQLOutputShape(BaseModel):
    kind: GraphQLOutputKind
    type_name: str
    nullable: bool = True
    fields: dict[str, GraphQLOutputShape] = Field(default_factory=dict)
    item_shape: GraphQLOutputShape | None = None
    possible_types: dict[str, GraphQLOutputShape] = Field(default_factory=dict)
    federated_entity: bool = False
    federation_hint: str | None = None


class OperationSpec(BaseModel):
    operation_id: str
    method: str
    path: str
    protocol: SourceKind = "openapi"
    summary: str | None = None
    tags: list[str] = Field(default_factory=list)
    parameters: list[ParameterSpec] = Field(default_factory=list)
    request_body_required: bool = False
    request_body_schema: dict[str, Any] | None = None
    request_body_content_type: str | None = None
    auth_required: bool = False
    auth_header_names: list[str] = Field(default_factory=list)
    auth_query_names: list[str] = Field(default_factory=list)
    response_schemas: dict[str, ResponseSpec] = Field(default_factory=dict)
    graphql_operation_type: GraphQLOperationType | None = None
    graphql_document: str | None = None
    graphql_variables_schema: dict[str, Any] | None = None
    graphql_root_field_name: str | None = None
    graphql_output_shape: GraphQLOutputShape | None = None
    graphql_federated: bool = False
    graphql_entity_types: list[str] = Field(default_factory=list)
    observed_examples: list[ObservedRequestExample] = Field(default_factory=list)
    learned_confidence: float | None = None
    observation_count: int = 0
    identity_contexts: list[str] = Field(default_factory=list)


class PreflightWarning(BaseModel):
    code: str
    message: str
    operation_id: str | None = None
    method: str | None = None
    path: str | None = None


class LearnedBinding(BaseModel):
    source_name: str
    source_pointer: str
    target: LearnedBindingTarget
    target_name: str
    confidence: float = 1.0


class LearnedWorkflow(BaseModel):
    id: str
    name: str
    producer_operation_id: str
    consumer_operation_id: str
    delete_operation_id: str | None = None
    delete_bindings: list[LearnedBinding] = Field(default_factory=list)
    bindings: list[LearnedBinding] = Field(default_factory=list)
    confidence: float = 1.0
    observation_count: int = 0


class LearnedModel(BaseModel):
    artifact_type: Literal["learned-model"] = "learned-model"
    version: int = 1
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source_inputs: list[str] = Field(default_factory=list)
    operations: list[OperationSpec] = Field(default_factory=list)
    workflows: list[LearnedWorkflow] = Field(default_factory=list)
    warnings: list[PreflightWarning] = Field(default_factory=list)


class LoadedOperations(BaseModel):
    source_kind: SourceKind = "openapi"
    operations: list[OperationSpec] = Field(default_factory=list)
    warnings: list[PreflightWarning] = Field(default_factory=list)
    learned_model: LearnedModel | None = None


class InspectSummary(BaseModel):
    operation_count: int = 0
    auth_required_count: int = 0
    request_body_count: int = 0
    required_request_body_count: int = 0
    parameter_count: int = 0
    untagged_operation_count: int = 0
    warning_count: int = 0
    learned_workflow_count: int = 0
    method_counts: dict[str, int] = Field(default_factory=dict)
    tag_counts: dict[str, int] = Field(default_factory=dict)


class AuthProfile(BaseModel):
    name: str
    level: int = 0
    anonymous: bool = False
    description: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    query: dict[str, Any] = Field(default_factory=dict)
    auth_config: str | None = None
    auth_plugins: list[str] = Field(default_factory=list)
    auth_plugin_modules: list[str] = Field(default_factory=list)


class AuthProfilesFile(BaseModel):
    profiles: list[AuthProfile] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_unique_names(self) -> AuthProfilesFile:
        seen: set[str] = set()
        for profile in self.profiles:
            normalized = profile.name.casefold()
            if normalized in seen:
                raise ValueError(f"Duplicate auth profile name {profile.name!r}.")
            seen.add(normalized)
        return self


class AttackCase(BaseModel):
    type: Literal["request"] = "request"
    id: str
    name: str
    kind: str
    operation_id: str
    protocol: SourceKind = "openapi"
    method: str
    path: str
    tags: list[str] = Field(default_factory=list)
    auth_required: bool = False
    description: str
    path_params: dict[str, Any] = Field(default_factory=dict)
    query: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    body_json: Any | None = None
    raw_body: str | None = None
    content_type: str | None = None
    omit_body: bool = False
    omit_header_names: list[str] = Field(default_factory=list)
    omit_query_names: list[str] = Field(default_factory=list)
    expected_outcomes: list[str] = Field(default_factory=lambda: ["4xx"])
    response_schemas: dict[str, ResponseSpec] = Field(default_factory=dict)
    graphql_operation_type: GraphQLOperationType | None = None
    graphql_root_field_name: str | None = None
    graphql_output_shape: GraphQLOutputShape | None = None
    graphql_federated: bool = False
    graphql_entity_types: list[str] = Field(default_factory=list)


class ExtractRule(BaseModel):
    name: str
    json_pointer: str
    required: bool = True


class WorkflowStep(BaseModel):
    name: str
    operation_id: str
    method: str
    path: str
    path_params: dict[str, Any] = Field(default_factory=dict)
    query: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    body_json: Any | None = None
    raw_body: str | None = None
    content_type: str | None = None
    omit_body: bool = False
    omit_header_names: list[str] = Field(default_factory=list)
    omit_query_names: list[str] = Field(default_factory=list)
    expected_outcomes: list[str] = Field(default_factory=lambda: ["2xx"])
    extracts: list[ExtractRule] = Field(default_factory=list)


class WorkflowAttackCase(BaseModel):
    type: Literal["workflow"] = "workflow"
    id: str
    name: str
    kind: str
    operation_id: str
    protocol: SourceKind = "openapi"
    method: str
    path: str
    tags: list[str] = Field(default_factory=list)
    auth_required: bool = False
    description: str
    setup_steps: list[WorkflowStep] = Field(default_factory=list)
    terminal_attack: AttackCase


AttackDefinition = Annotated[AttackCase | WorkflowAttackCase, Field(discriminator="type")]


def _coerce_attack_definition(attack: Any) -> Any:
    if not isinstance(attack, dict):
        return attack

    coerced = dict(attack)
    coerced.setdefault(
        "type",
        "workflow" if "setup_steps" in coerced or "terminal_attack" in coerced else "request",
    )
    terminal_attack = coerced.get("terminal_attack")
    if isinstance(terminal_attack, dict):
        terminal_coerced = dict(terminal_attack)
        terminal_coerced.setdefault("type", "request")
        coerced["terminal_attack"] = terminal_coerced
    return coerced


class AttackSuite(BaseModel):
    source: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    attacks: list[AttackDefinition] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _default_attack_types(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        attacks = data.get("attacks")
        if not isinstance(attacks, list):
            return data

        coerced = dict(data)
        coerced["attacks"] = [_coerce_attack_definition(attack) for attack in attacks]
        return coerced


class WorkflowStepResult(BaseModel):
    name: str
    operation_id: str
    method: str
    url: str
    status_code: int | None = None
    error: str | None = None
    duration_ms: float | None = None
    response_excerpt: str | None = None


class AuthEvent(BaseModel):
    name: str
    strategy: str
    phase: AuthEventPhase
    success: bool = True
    profile: str | None = None
    trigger: str | None = None
    endpoint: str | None = None
    status_code: int | None = None
    error: str | None = None


class ProfileAttackResult(BaseModel):
    protocol: SourceKind = "openapi"
    profile: str
    level: int = 0
    anonymous: bool = False
    url: str
    status_code: int | None = None
    error: str | None = None
    duration_ms: float | None = None
    flagged: bool = False
    issue: str | None = None
    severity: SeverityLevel = "none"
    confidence: ConfidenceLevel = "none"
    response_excerpt: str | None = None
    response_schema_status: str | None = None
    response_schema_valid: bool | None = None
    response_schema_error: str | None = None
    graphql_response_valid: bool | None = None
    graphql_response_error: str | None = None
    graphql_response_hint: str | None = None
    workflow_steps: list[WorkflowStepResult] | None = None


class AttackResult(BaseModel):
    type: AttackType = "request"
    attack_id: str
    operation_id: str
    kind: str
    name: str
    protocol: SourceKind = "openapi"
    method: str
    path: str | None = None
    tags: list[str] = Field(default_factory=list)
    url: str
    status_code: int | None = None
    error: str | None = None
    duration_ms: float | None = None
    flagged: bool = False
    issue: str | None = None
    severity: SeverityLevel = "none"
    confidence: ConfidenceLevel = "none"
    response_excerpt: str | None = None
    response_schema_status: str | None = None
    response_schema_valid: bool | None = None
    response_schema_error: str | None = None
    graphql_response_valid: bool | None = None
    graphql_response_error: str | None = None
    graphql_response_hint: str | None = None
    workflow_steps: list[WorkflowStepResult] | None = None
    profile_results: list[ProfileAttackResult] | None = None


class AttackResults(BaseModel):
    source: str
    base_url: str
    executed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    profiles: list[str] = Field(default_factory=list)
    auth_events: list[AuthEvent] = Field(default_factory=list)
    results: list[AttackResult] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _default_result_types(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        results = data.get("results")
        if not isinstance(results, list):
            return data

        coerced = dict(data)
        coerced["results"] = []
        for result in results:
            if not isinstance(result, dict):
                coerced["results"].append(result)
                continue
            result_coerced = dict(result)
            result_coerced.setdefault("protocol", "openapi")
            result_coerced.setdefault(
                "type",
                "workflow" if result_coerced.get("workflow_steps") else "request",
            )
            coerced["results"].append(result_coerced)
        return coerced


class SummaryFinding(BaseModel):
    attack_id: str
    name: str
    protocol: str
    kind: str
    issue: str | None = None
    severity: SeverityLevel
    confidence: ConfidenceLevel
    status_code: int | None = None
    url: str
    schema_status: str = "-"


class AuthSummaryEntry(BaseModel):
    profile: str
    name: str
    strategy: str
    acquire: int = 0
    refresh: int = 0
    failures: int = 0
    triggers: list[str] = Field(default_factory=list)


class ResultsSummary(BaseModel):
    source: str
    base_url: str
    executed_at: datetime
    baseline_used: bool = False
    baseline_executed_at: datetime | None = None
    total_results: int
    profile_count: int = 0
    profile_names: list[str] = Field(default_factory=list)
    active_flagged_count: int = 0
    suppressed_flagged_count: int = 0
    new_findings_count: int = 0
    resolved_findings_count: int = 0
    persisting_findings_count: int = 0
    persisting_deltas_count: int = 0
    auth_failures: int = 0
    refresh_attempts: int = 0
    response_schema_mismatches: int = 0
    graphql_shape_mismatches: int = 0
    protocol_counts: dict[str, int] = Field(default_factory=dict)
    issue_counts: dict[str, int] = Field(default_factory=dict)
    finding_severity_counts: dict[str, int] = Field(default_factory=dict)
    finding_confidence_counts: dict[str, int] = Field(default_factory=dict)
    auth_summary: list[AuthSummaryEntry] = Field(default_factory=list)
    top_findings: list[SummaryFinding] = Field(default_factory=list)


GraphQLOutputShape.model_rebuild()
