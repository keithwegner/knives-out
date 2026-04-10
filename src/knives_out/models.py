from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, model_validator

SeverityLevel = Literal["none", "low", "medium", "high", "critical"]
ConfidenceLevel = Literal["none", "low", "medium", "high"]
AttackType = Literal["request", "workflow"]


class ParameterSpec(BaseModel):
    name: str
    location: str
    required: bool = False
    schema_def: dict[str, Any] = Field(default_factory=dict)


class ResponseSpec(BaseModel):
    content_type: str | None = None
    schema_def: dict[str, Any] | None = None


class OperationSpec(BaseModel):
    operation_id: str
    method: str
    path: str
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


class PreflightWarning(BaseModel):
    code: str
    message: str
    operation_id: str | None = None
    method: str | None = None
    path: str | None = None


class LoadedOperations(BaseModel):
    operations: list[OperationSpec] = Field(default_factory=list)
    warnings: list[PreflightWarning] = Field(default_factory=list)


class AuthProfile(BaseModel):
    name: str
    level: int = 0
    anonymous: bool = False
    description: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    query: dict[str, Any] = Field(default_factory=dict)
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


class ProfileAttackResult(BaseModel):
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
    workflow_steps: list[WorkflowStepResult] | None = None


class AttackResult(BaseModel):
    type: AttackType = "request"
    attack_id: str
    operation_id: str
    kind: str
    name: str
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
    workflow_steps: list[WorkflowStepResult] | None = None
    profile_results: list[ProfileAttackResult] | None = None


class AttackResults(BaseModel):
    source: str
    base_url: str
    executed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    profiles: list[str] = Field(default_factory=list)
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
            result_coerced.setdefault(
                "type",
                "workflow" if result_coerced.get("workflow_steps") else "request",
            )
            coerced["results"].append(result_coerced)
        return coerced
