from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from knives_out.models import (
    AttackCase,
    AttackResult,
    AttackResults,
    AttackSuite,
    ConfidenceLevel,
    ResponseSpec,
    SeverityLevel,
    WorkflowAttackCase,
    WorkflowStep,
    WorkflowStepResult,
)

ISSUE_SCORES: dict[str, tuple[SeverityLevel, ConfidenceLevel]] = {
    "transport_error": ("low", "low"),
    "no_status": ("low", "low"),
    "server_error": ("high", "high"),
    "unexpected_success": ("high", "medium"),
    "response_schema_mismatch": ("medium", "high"),
}

_PLACEHOLDER_RE = re.compile(r"\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}")
_EXACT_PLACEHOLDER_RE = re.compile(r"^\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}$")


@dataclass
class _ExecutedRequest:
    url: str
    headers: dict[str, str]
    query: dict[str, Any]
    response: httpx.Response | None
    error: str | None
    duration_ms: float
    resolution_error: bool = False


@dataclass
class WorkflowContext:
    client: httpx.Client
    extracted_values: dict[str, Any] = field(default_factory=dict)


class WorkflowHook:
    def before_workflow(self, workflow: WorkflowAttackCase, context: WorkflowContext) -> None:
        return None

    def before_step(
        self,
        workflow: WorkflowAttackCase,
        step: WorkflowStep | AttackCase,
        context: WorkflowContext,
    ) -> None:
        return None

    def after_step(
        self,
        workflow: WorkflowAttackCase,
        step: WorkflowStep | AttackCase,
        context: WorkflowContext,
        execution: _ExecutedRequest,
    ) -> None:
        return None


class WorkflowResolutionError(ValueError):
    pass


def load_attack_suite(path: str | Path) -> AttackSuite:
    raw = Path(path).read_text(encoding="utf-8")
    return AttackSuite.model_validate_json(raw)


def _render_path(path_template: str, path_params: dict[str, Any]) -> str:
    rendered = path_template
    for name, value in path_params.items():
        rendered = rendered.replace(f"{{{name}}}", quote(str(value), safe=""))
    return rendered


def _remove_header_names(headers: dict[str, str], names: list[str]) -> dict[str, str]:
    if not names:
        return headers
    lowered = {name.lower() for name in names}
    return {key: value for key, value in headers.items() if key.lower() not in lowered}


def evaluate_result(status_code: int | None, error: str | None) -> tuple[bool, str | None]:
    if error:
        return True, "transport_error"
    if status_code is None:
        return True, "no_status"
    if 500 <= status_code < 600:
        return True, "server_error"
    if 200 <= status_code < 400:
        return True, "unexpected_success"
    return False, None


def score_result(
    *,
    flagged: bool,
    issue: str | None,
) -> tuple[SeverityLevel, ConfidenceLevel]:
    if not flagged or issue is None:
        return "none", "none"
    return ISSUE_SCORES.get(issue, ("medium", "medium"))


def _excerpt(text: str, limit: int = 300) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _request_body_artifact(
    attack: AttackCase | WorkflowStep,
    headers: dict[str, str],
    request_kwargs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if attack.omit_body:
        return {"present": False}
    if request_kwargs and "content" in request_kwargs:
        return {
            "present": True,
            "kind": "raw",
            "content_type": headers.get("Content-Type") or attack.content_type,
            "excerpt": _excerpt(str(request_kwargs["content"])),
        }
    if request_kwargs and "json" in request_kwargs:
        serialized = json.dumps(request_kwargs["json"], sort_keys=True)
        return {
            "present": True,
            "kind": "json",
            "content_type": headers.get("Content-Type") or "application/json",
            "excerpt": _excerpt(serialized),
        }
    if attack.raw_body is not None:
        return {
            "present": True,
            "kind": "raw",
            "content_type": headers.get("Content-Type") or attack.content_type,
            "excerpt": _excerpt(attack.raw_body),
        }
    if attack.body_json is not None:
        serialized = json.dumps(attack.body_json, sort_keys=True)
        return {
            "present": True,
            "kind": "json",
            "content_type": headers.get("Content-Type") or "application/json",
            "excerpt": _excerpt(serialized),
        }
    return {"present": False}


def _write_request_artifact(
    artifact_root: Path,
    *,
    filename: str,
    request: AttackCase | WorkflowStep,
    metadata: dict[str, Any],
    url: str,
    headers: dict[str, str],
    query: dict[str, Any],
    request_kwargs: dict[str, Any] | None,
    response: httpx.Response | None,
    error: str | None,
    duration_ms: float,
) -> None:
    artifact = {
        "attack": metadata,
        "request": {
            "method": request.method,
            "url": url,
            "headers": headers,
            "query": query,
            "body": _request_body_artifact(request, headers, request_kwargs),
        },
        "response": {
            "status_code": response.status_code if response is not None else None,
            "error": error,
            "duration_ms": round(duration_ms, 2),
            "body_excerpt": _excerpt(response.text) if response is not None else None,
        },
    }
    artifact_path = artifact_root / filename
    artifact_path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")


def _normalized_content_type(content_type: str | None) -> str:
    if not content_type:
        return ""
    return content_type.split(";", 1)[0].strip().lower()


def _schema_type(schema: dict[str, Any]) -> str | None:
    schema_type = schema.get("type")
    if isinstance(schema_type, str):
        return schema_type
    if schema.get("properties") or schema.get("required"):
        return "object"
    if "items" in schema:
        return "array"
    return None


def _describe_value_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _validate_schema_value(
    value: Any,
    schema: dict[str, Any] | None,
    *,
    path: str = "$",
) -> str | None:
    if schema is None:
        return None
    if schema == {}:
        return None
    if schema.get("nullable") and value is None:
        return None

    if "enum" in schema and value not in schema["enum"]:
        return f"{path}: expected one of {schema['enum']!r}, got {value!r}"
    if "const" in schema and value != schema["const"]:
        return f"{path}: expected {schema['const']!r}, got {value!r}"

    if "allOf" in schema:
        for subschema in schema["allOf"]:
            mismatch = _validate_schema_value(value, subschema, path=path)
            if mismatch:
                return mismatch
        return None

    if "anyOf" in schema:
        if any(
            _validate_schema_value(value, subschema, path=path) is None
            for subschema in schema["anyOf"]
        ):
            return None
        return f"{path}: value did not match any declared schema"

    if "oneOf" in schema:
        matches = sum(
            1
            for subschema in schema["oneOf"]
            if _validate_schema_value(value, subschema, path=path) is None
        )
        if matches == 1:
            return None
        if matches == 0:
            return f"{path}: value did not match any declared schema"
        return f"{path}: value matched multiple mutually exclusive schemas"

    schema_type = _schema_type(schema)

    if schema_type == "null":
        if value is None:
            return None
        return f"{path}: expected null, got {_describe_value_type(value)}"
    if schema_type == "string":
        if isinstance(value, str):
            return None
        return f"{path}: expected string, got {_describe_value_type(value)}"
    if schema_type == "integer":
        if isinstance(value, int) and not isinstance(value, bool):
            return None
        return f"{path}: expected integer, got {_describe_value_type(value)}"
    if schema_type == "number":
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return None
        return f"{path}: expected number, got {_describe_value_type(value)}"
    if schema_type == "boolean":
        if isinstance(value, bool):
            return None
        return f"{path}: expected boolean, got {_describe_value_type(value)}"
    if schema_type == "array":
        if not isinstance(value, list):
            return f"{path}: expected array, got {_describe_value_type(value)}"
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                mismatch = _validate_schema_value(item, item_schema, path=f"{path}[{index}]")
                if mismatch:
                    return mismatch
        return None
    if schema_type == "object":
        if not isinstance(value, dict):
            return f"{path}: expected object, got {_describe_value_type(value)}"

        properties = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in value:
                return f"{path}: missing required property '{name}'"

        for name, property_schema in properties.items():
            if name not in value:
                continue
            mismatch = _validate_schema_value(value[name], property_schema, path=f"{path}.{name}")
            if mismatch:
                return mismatch

        additional_properties = schema.get("additionalProperties", True)
        extra_names = sorted(name for name in value if name not in properties)
        if additional_properties is False and extra_names:
            return f"{path}: unexpected properties {extra_names!r}"
        if isinstance(additional_properties, dict):
            for name in extra_names:
                mismatch = _validate_schema_value(
                    value[name],
                    additional_properties,
                    path=f"{path}.{name}",
                )
                if mismatch:
                    return mismatch
        return None

    return None


def _matched_response_schema(
    attack: AttackCase,
    status_code: int,
) -> tuple[str | None, ResponseSpec | None]:
    status_key = str(status_code)
    if status_key in attack.response_schemas:
        return status_key, attack.response_schemas[status_key]
    if "default" in attack.response_schemas:
        return "default", attack.response_schemas["default"]
    return None, None


def _response_uses_json(
    response: httpx.Response,
    response_spec: ResponseSpec,
) -> bool:
    schema_type = _schema_type(response_spec.schema_def or {})
    actual_content_type = _normalized_content_type(response.headers.get("Content-Type"))
    expected_content_type = _normalized_content_type(response_spec.content_type)
    return (
        "json" in actual_content_type
        or "json" in expected_content_type
        or schema_type in {"object", "array", "null"}
    )


def _coerce_response_body(
    response: httpx.Response,
    response_spec: ResponseSpec,
) -> tuple[Any | None, str | None]:
    response_text = response.text.strip()
    if _response_uses_json(response, response_spec):
        if not response_text:
            if _schema_type(response_spec.schema_def or {}) == "null":
                return None, None
            return None, "Response body is empty."
        try:
            return response.json(), None
        except ValueError as exc:
            return None, f"Response body is not valid JSON: {exc}"

    return response.text, None


def _validate_response_schema(
    attack: AttackCase,
    response: httpx.Response,
) -> tuple[str | None, bool | None, str | None]:
    matched_status, response_spec = _matched_response_schema(attack, response.status_code)
    if response_spec is None:
        return None, None, None
    if response_spec.schema_def is None:
        return matched_status, None, None

    response_body, parse_error = _coerce_response_body(response, response_spec)
    if parse_error:
        return matched_status, False, parse_error

    mismatch = _validate_schema_value(response_body, response_spec.schema_def)
    if mismatch:
        return matched_status, False, mismatch
    return matched_status, True, None


def _resolve_templates(value: Any, extracted_values: dict[str, Any]) -> Any:
    if isinstance(value, str):
        exact_match = _EXACT_PLACEHOLDER_RE.fullmatch(value)
        if exact_match:
            placeholder_name = exact_match.group(1)
            if placeholder_name not in extracted_values:
                raise WorkflowResolutionError(f"Missing extracted value '{placeholder_name}'.")
            return extracted_values[placeholder_name]

        def _replace(match: re.Match[str]) -> str:
            placeholder_name = match.group(1)
            if placeholder_name not in extracted_values:
                raise WorkflowResolutionError(f"Missing extracted value '{placeholder_name}'.")
            return str(extracted_values[placeholder_name])

        return _PLACEHOLDER_RE.sub(_replace, value)
    if isinstance(value, list):
        return [_resolve_templates(item, extracted_values) for item in value]
    if isinstance(value, dict):
        return {str(key): _resolve_templates(item, extracted_values) for key, item in value.items()}
    return value


def _status_matches_expected(status_code: int | None, expected_outcomes: list[str]) -> bool:
    if status_code is None:
        return False
    for expected in expected_outcomes:
        normalized = expected.strip().lower()
        if not normalized:
            continue
        if normalized.endswith("xx") and len(normalized) == 3 and normalized[0].isdigit():
            if status_code // 100 == int(normalized[0]):
                return True
            continue
        if normalized.isdigit() and status_code == int(normalized):
            return True
    return False


def _extract_json_pointer(value: Any, pointer: str) -> Any:
    if pointer == "":
        return value
    if not pointer.startswith("/"):
        raise ValueError(f"Invalid JSON pointer {pointer!r}.")

    current = value
    for token in pointer.split("/")[1:]:
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            if not token.isdigit():
                raise ValueError(f"Expected array index in JSON pointer {pointer!r}.")
            index = int(token)
            if index >= len(current):
                raise ValueError(f"JSON pointer {pointer!r} did not match the response body.")
            current = current[index]
        elif isinstance(current, dict):
            if token not in current:
                raise ValueError(f"JSON pointer {pointer!r} did not match the response body.")
            current = current[token]
        else:
            raise ValueError(f"JSON pointer {pointer!r} did not match the response body.")
    return current


def _resolved_headers(
    request: AttackCase | WorkflowStep,
    *,
    default_headers: dict[str, str],
    extracted_values: dict[str, Any],
) -> dict[str, str]:
    resolved = _resolve_templates(request.headers, extracted_values)
    merged = {
        **default_headers,
        **{name: str(value) for name, value in resolved.items()},
    }
    return _remove_header_names(merged, request.omit_header_names)


def _resolved_query(
    request: AttackCase | WorkflowStep,
    *,
    default_query: dict[str, Any],
    extracted_values: dict[str, Any],
) -> dict[str, Any]:
    resolved = _resolve_templates(request.query, extracted_values)
    merged = {**default_query, **resolved}
    for name in request.omit_query_names:
        merged.pop(name, None)
    return merged


def _resolve_request_path(
    request: AttackCase | WorkflowStep,
    *,
    base_url: str,
    extracted_values: dict[str, Any],
) -> str:
    resolved_path_template = _resolve_templates(request.path, extracted_values)
    resolved_path_params = _resolve_templates(request.path_params, extracted_values)
    return base_url.rstrip("/") + _render_path(resolved_path_template, resolved_path_params)


def _execute_request(
    client: httpx.Client,
    request: AttackCase | WorkflowStep,
    *,
    base_url: str,
    default_headers: dict[str, str],
    default_query: dict[str, Any],
    extracted_values: dict[str, Any],
    artifact_root: Path | None,
    artifact_filename: str | None,
    artifact_metadata: dict[str, Any] | None,
) -> _ExecutedRequest:
    try:
        url = _resolve_request_path(
            request,
            base_url=base_url,
            extracted_values=extracted_values,
        )
        headers = _resolved_headers(
            request,
            default_headers=default_headers,
            extracted_values=extracted_values,
        )
        query = _resolved_query(
            request,
            default_query=default_query,
            extracted_values=extracted_values,
        )
        request_kwargs: dict[str, Any] = {
            "params": query,
            "headers": headers,
        }
        if not request.omit_body:
            if request.raw_body is not None:
                request_kwargs["content"] = str(
                    _resolve_templates(request.raw_body, extracted_values)
                )
                content_type = request.content_type
                if content_type is not None:
                    content_type = str(_resolve_templates(content_type, extracted_values))
                if content_type and "Content-Type" not in headers:
                    request_kwargs["headers"] = {**headers, "Content-Type": content_type}
                    headers = request_kwargs["headers"]
            elif request.body_json is not None:
                request_kwargs["json"] = _resolve_templates(request.body_json, extracted_values)
    except WorkflowResolutionError as exc:
        execution = _ExecutedRequest(
            url=base_url.rstrip("/") + request.path,
            headers={},
            query={},
            response=None,
            error=str(exc),
            duration_ms=0.0,
            resolution_error=True,
        )
        if (
            artifact_root is not None
            and artifact_filename is not None
            and artifact_metadata is not None
        ):
            _write_request_artifact(
                artifact_root,
                filename=artifact_filename,
                request=request,
                metadata=artifact_metadata,
                url=execution.url,
                headers=execution.headers,
                query=execution.query,
                request_kwargs=None,
                response=None,
                error=execution.error,
                duration_ms=execution.duration_ms,
            )
        return execution

    start = time.perf_counter()
    response: httpx.Response | None = None
    error: str | None = None
    try:
        response = client.request(request.method, url, **request_kwargs)
    except Exception as exc:  # noqa: BLE001
        error = str(exc)
    duration_ms = (time.perf_counter() - start) * 1000.0

    if (
        artifact_root is not None
        and artifact_filename is not None
        and artifact_metadata is not None
    ):
        _write_request_artifact(
            artifact_root,
            filename=artifact_filename,
            request=request,
            metadata=artifact_metadata,
            url=url,
            headers=headers,
            query=query,
            request_kwargs=request_kwargs,
            response=response,
            error=error,
            duration_ms=duration_ms,
        )

    return _ExecutedRequest(
        url=url,
        headers=headers,
        query=query,
        response=response,
        error=error,
        duration_ms=duration_ms,
    )


def _request_result(
    attack: AttackCase,
    execution: _ExecutedRequest,
    *,
    attack_type: str,
    workflow_steps: list[WorkflowStepResult] | None = None,
) -> AttackResult:
    flagged, issue = evaluate_result(
        execution.response.status_code if execution.response else None,
        execution.error,
    )
    response_schema_status: str | None = None
    response_schema_valid: bool | None = None
    response_schema_error: str | None = None
    if execution.response is not None:
        (
            response_schema_status,
            response_schema_valid,
            response_schema_error,
        ) = _validate_response_schema(attack, execution.response)
    if response_schema_valid is False:
        flagged = True
        if issue in {None, "unexpected_success"}:
            issue = "response_schema_mismatch"
    severity, confidence = score_result(flagged=flagged, issue=issue)

    return AttackResult(
        type=attack_type,
        attack_id=attack.id,
        operation_id=attack.operation_id,
        kind=attack.kind,
        name=attack.name,
        method=attack.method,
        url=execution.url,
        status_code=execution.response.status_code if execution.response else None,
        error=execution.error,
        duration_ms=round(execution.duration_ms, 2),
        flagged=flagged,
        issue=issue,
        severity=severity,
        confidence=confidence,
        response_excerpt=_excerpt(execution.response.text)
        if execution.response is not None
        else None,
        response_schema_status=response_schema_status,
        response_schema_valid=response_schema_valid,
        response_schema_error=response_schema_error,
        workflow_steps=workflow_steps,
    )


def _workflow_step_result(
    step: WorkflowStep,
    execution: _ExecutedRequest,
) -> WorkflowStepResult:
    return WorkflowStepResult(
        name=step.name,
        operation_id=step.operation_id,
        method=step.method,
        url=execution.url,
        status_code=execution.response.status_code if execution.response else None,
        error=execution.error,
        duration_ms=round(execution.duration_ms, 2),
        response_excerpt=_excerpt(execution.response.text)
        if execution.response is not None
        else None,
    )


def _workflow_terminal_fallback_url(
    workflow: WorkflowAttackCase,
    *,
    base_url: str,
    extracted_values: dict[str, Any],
) -> str:
    try:
        return _resolve_request_path(
            workflow.terminal_attack,
            base_url=base_url,
            extracted_values=extracted_values,
        )
    except WorkflowResolutionError:
        return base_url.rstrip("/") + workflow.path


def _workflow_failure_result(
    workflow: WorkflowAttackCase,
    *,
    base_url: str,
    error: str,
    workflow_steps: list[WorkflowStepResult],
    status_code: int | None = None,
    response_excerpt: str | None = None,
    duration_ms: float = 0.0,
    extracted_values: dict[str, Any] | None = None,
) -> AttackResult:
    return AttackResult(
        type="workflow",
        attack_id=workflow.id,
        operation_id=workflow.operation_id,
        kind=workflow.kind,
        name=workflow.name,
        method=workflow.method,
        url=_workflow_terminal_fallback_url(
            workflow,
            base_url=base_url,
            extracted_values=extracted_values or {},
        ),
        status_code=status_code,
        error=error,
        duration_ms=round(duration_ms, 2),
        flagged=False,
        issue=None,
        severity="none",
        confidence="none",
        response_excerpt=response_excerpt,
        workflow_steps=workflow_steps,
    )


def _extract_step_values(
    step: WorkflowStep,
    response: httpx.Response | None,
) -> dict[str, Any]:
    if not step.extracts:
        return {}
    if response is None:
        raise WorkflowResolutionError(
            f"Workflow setup failed during '{step.name}': no response was available for extraction."
        )
    try:
        payload = response.json()
    except ValueError as exc:
        raise WorkflowResolutionError(
            f"Workflow setup failed during '{step.name}': response body was not JSON ({exc})."
        ) from exc

    extracted: dict[str, Any] = {}
    for extract in step.extracts:
        try:
            extracted[extract.name] = _extract_json_pointer(payload, extract.json_pointer)
        except ValueError as exc:
            if extract.required:
                raise WorkflowResolutionError(
                    f"Workflow setup failed during '{step.name}': {exc}"
                ) from exc
    return extracted


def _execute_workflow_attack(
    workflow: WorkflowAttackCase,
    *,
    base_url: str,
    default_headers: dict[str, str],
    default_query: dict[str, Any],
    timeout_seconds: float,
    artifact_root: Path | None,
    workflow_hooks: list[WorkflowHook],
) -> AttackResult:
    total_duration_ms = 0.0
    with httpx.Client(timeout=timeout_seconds, follow_redirects=False) as client:
        context = WorkflowContext(client=client)
        for hook in workflow_hooks:
            hook.before_workflow(workflow, context)

        workflow_steps: list[WorkflowStepResult] = []
        for index, step in enumerate(workflow.setup_steps, start=1):
            for hook in workflow_hooks:
                hook.before_step(workflow, step, context)

            execution = _execute_request(
                client,
                step,
                base_url=base_url,
                default_headers=default_headers,
                default_query=default_query,
                extracted_values=context.extracted_values,
                artifact_root=artifact_root,
                artifact_filename=f"{workflow.id}-step-{index:02d}.json" if artifact_root else None,
                artifact_metadata=(
                    {
                        "id": f"{workflow.id}-step-{index:02d}",
                        "name": step.name,
                        "kind": "workflow_setup",
                        "operation_id": step.operation_id,
                        "type": "workflow_step",
                        "workflow_id": workflow.id,
                    }
                    if artifact_root
                    else None
                ),
            )
            total_duration_ms += execution.duration_ms
            step_result = _workflow_step_result(step, execution)
            workflow_steps.append(step_result)

            setup_error = execution.error
            if execution.response is not None and not _status_matches_expected(
                execution.response.status_code,
                step.expected_outcomes,
            ):
                setup_error = (
                    f"unexpected status {execution.response.status_code}; "
                    f"expected one of {', '.join(step.expected_outcomes)}"
                )

            if setup_error is None:
                try:
                    context.extracted_values.update(
                        _extract_step_values(
                            step,
                            execution.response,
                        )
                    )
                except WorkflowResolutionError as exc:
                    setup_error = str(exc)

            for hook in workflow_hooks:
                hook.after_step(workflow, step, context, execution)

            if setup_error is not None:
                if not setup_error.startswith("Workflow setup failed"):
                    setup_error = f"Workflow setup failed during '{step.name}': {setup_error}"
                return _workflow_failure_result(
                    workflow,
                    base_url=base_url,
                    error=setup_error,
                    workflow_steps=workflow_steps,
                    status_code=execution.response.status_code if execution.response else None,
                    response_excerpt=(
                        _excerpt(execution.response.text)
                        if execution.response is not None
                        else None
                    ),
                    duration_ms=total_duration_ms,
                    extracted_values=context.extracted_values,
                )

        for hook in workflow_hooks:
            hook.before_step(workflow, workflow.terminal_attack, context)

        terminal_execution = _execute_request(
            client,
            workflow.terminal_attack,
            base_url=base_url,
            default_headers=default_headers,
            default_query=default_query,
            extracted_values=context.extracted_values,
            artifact_root=artifact_root,
            artifact_filename=f"{workflow.id}.json" if artifact_root else None,
            artifact_metadata=(
                {
                    "id": workflow.id,
                    "name": workflow.name,
                    "kind": workflow.kind,
                    "operation_id": workflow.operation_id,
                    "type": "workflow",
                    "terminal_attack_id": workflow.terminal_attack.id,
                }
                if artifact_root
                else None
            ),
        )
        total_duration_ms += terminal_execution.duration_ms
        for hook in workflow_hooks:
            hook.after_step(workflow, workflow.terminal_attack, context, terminal_execution)

        if terminal_execution.resolution_error:
            return _workflow_failure_result(
                workflow,
                base_url=base_url,
                error=f"Workflow setup failed before terminal step: {terminal_execution.error}",
                workflow_steps=workflow_steps,
                duration_ms=total_duration_ms,
                extracted_values=context.extracted_values,
            )

        result = _request_result(
            workflow.terminal_attack,
            terminal_execution,
            attack_type="workflow",
            workflow_steps=workflow_steps,
        )
        return result.model_copy(
            update={
                "attack_id": workflow.id,
                "name": workflow.name,
                "duration_ms": round(total_duration_ms, 2),
            }
        )


def execute_attack_suite(
    suite: AttackSuite,
    *,
    base_url: str,
    default_headers: dict[str, str] | None = None,
    default_query: dict[str, Any] | None = None,
    timeout_seconds: float = 10.0,
    artifact_dir: str | Path | None = None,
    workflow_hooks: list[WorkflowHook] | None = None,
) -> AttackResults:
    default_headers = dict(default_headers or {})
    default_query = dict(default_query or {})
    results: list[AttackResult] = []
    artifact_root = Path(artifact_dir) if artifact_dir is not None else None
    if artifact_root is not None:
        artifact_root.mkdir(parents=True, exist_ok=True)

    hooks = list(workflow_hooks or [])
    with httpx.Client(timeout=timeout_seconds, follow_redirects=False) as client:
        for attack in suite.attacks:
            if isinstance(attack, WorkflowAttackCase):
                results.append(
                    _execute_workflow_attack(
                        attack,
                        base_url=base_url,
                        default_headers=default_headers,
                        default_query=default_query,
                        timeout_seconds=timeout_seconds,
                        artifact_root=artifact_root,
                        workflow_hooks=hooks,
                    )
                )
                continue

            execution = _execute_request(
                client,
                attack,
                base_url=base_url,
                default_headers=default_headers,
                default_query=default_query,
                extracted_values={},
                artifact_root=artifact_root,
                artifact_filename=f"{attack.id}.json" if artifact_root else None,
                artifact_metadata=(
                    {
                        "id": attack.id,
                        "name": attack.name,
                        "kind": attack.kind,
                        "operation_id": attack.operation_id,
                        "type": "request",
                    }
                    if artifact_root
                    else None
                ),
            )
            results.append(_request_result(attack, execution, attack_type="request"))

    return AttackResults(source=suite.source, base_url=base_url, results=results)
