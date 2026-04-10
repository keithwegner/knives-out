from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


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
    parameters: list[ParameterSpec] = Field(default_factory=list)
    request_body_required: bool = False
    request_body_schema: dict[str, Any] | None = None
    request_body_content_type: str | None = None
    auth_required: bool = False
    auth_header_names: list[str] = Field(default_factory=list)
    auth_query_names: list[str] = Field(default_factory=list)
    response_schemas: dict[str, ResponseSpec] = Field(default_factory=dict)


class AttackCase(BaseModel):
    id: str
    name: str
    kind: str
    operation_id: str
    method: str
    path: str
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


class AttackSuite(BaseModel):
    source: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    attacks: list[AttackCase] = Field(default_factory=list)


class AttackResult(BaseModel):
    attack_id: str
    operation_id: str
    kind: str
    name: str
    method: str
    url: str
    status_code: int | None = None
    error: str | None = None
    duration_ms: float | None = None
    flagged: bool = False
    issue: str | None = None
    response_excerpt: str | None = None
    response_schema_status: str | None = None
    response_schema_valid: bool | None = None
    response_schema_error: str | None = None


class AttackResults(BaseModel):
    source: str
    base_url: str
    executed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    results: list[AttackResult] = Field(default_factory=list)
