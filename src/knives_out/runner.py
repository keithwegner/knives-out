from __future__ import annotations

import json
import re
import time
from copy import deepcopy
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from knives_out.auth_plugins import (
    LoadedAuthPlugin,
    PluginRuntimeError,
    PreparedRequest,
    RequestExecution,
    RuntimeContext,
    RuntimePlugin,
    WorkflowHook,
    extract_json_pointer,
    make_auth_plugin,
)
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


class WorkflowResolutionError(ValueError):
    pass


def load_attack_suite(path: str | Path) -> AttackSuite:
    raw = Path(path).read_text(encoding="utf-8")
    return AttackSuite.model_validate_json(raw)


def _prepared_request_from_attack(attack: AttackCase, *, phase: str = "request") -> PreparedRequest:
    return PreparedRequest(
        phase=phase,
        attack_id=attack.id,
        name=attack.name,
        kind=attack.kind,
        operation_id=attack.operation_id,
        method=attack.method,
        path=attack.path,
        description=attack.description,
        path_params=deepcopy(attack.path_params),
        query=deepcopy(attack.query),
        headers=deepcopy(attack.headers),
        body_json=deepcopy(attack.body_json),
        raw_body=attack.raw_body,
        content_type=attack.content_type,
        omit_body=attack.omit_body,
        omit_header_names=list(attack.omit_header_names),
        omit_query_names=list(attack.omit_query_names),
    )


def _prepared_request_from_step(
    workflow: WorkflowAttackCase,
    step: WorkflowStep,
    *,
    step_index: int,
) -> PreparedRequest:
    return PreparedRequest(
        phase="workflow_setup",
        attack_id=f"{workflow.id}-step-{step_index:02d}",
        name=step.name,
        kind="workflow_setup",
        operation_id=step.operation_id,
        method=step.method,
        path=step.path,
        description=step.name,
        path_params=deepcopy(step.path_params),
        query=deepcopy(step.query),
        headers=deepcopy(step.headers),
        body_json=deepcopy(step.body_json),
        raw_body=step.raw_body,
        content_type=step.content_type,
        omit_body=step.omit_body,
        omit_header_names=list(step.omit_header_names),
        omit_query_names=list(step.omit_query_names),
    )


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
    request: PreparedRequest,
    headers: dict[str, str],
    request_kwargs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if request.omit_body:
        return {"present": False}
    if request_kwargs and "content" in request_kwargs:
        return {
            "present": True,
            "kind": "raw",
            "content_type": headers.get("Content-Type") or request.content_type,
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
    if request.raw_body is not None:
        return {
            "present": True,
            "kind": "raw",
            "content_type": headers.get("Content-Type") or request.content_type,
            "excerpt": _excerpt(request.raw_body),
        }
    if request.body_json is not None:
        serialized = json.dumps(request.body_json, sort_keys=True)
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
    request: PreparedRequest,
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


def _resolved_headers(
    request: PreparedRequest,
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
    request: PreparedRequest,
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
    request: PreparedRequest,
    *,
    base_url: str,
    extracted_values: dict[str, Any],
) -> str:
    resolved_path_template = _resolve_templates(request.path, extracted_values)
    resolved_path_params = _resolve_templates(request.path_params, extracted_values)
    return base_url.rstrip("/") + _render_path(resolved_path_template, resolved_path_params)


def _invoke_auth_plugin_hook(
    loaded_plugin: LoadedAuthPlugin,
    hook_name: str,
    *args: Any,
) -> None:
    hook = getattr(loaded_plugin.plugin, hook_name, None)
    if not callable(hook):
        return
    try:
        hook(*args)
    except PluginRuntimeError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise PluginRuntimeError(
            f"Auth plugin '{loaded_plugin.name}' failed during '{hook_name}': {exc}"
        ) from exc


def _invoke_auth_plugins(
    loaded_plugins: list[LoadedAuthPlugin],
    hook_name: str,
    *args: Any,
) -> None:
    for loaded_plugin in loaded_plugins:
        _invoke_auth_plugin_hook(loaded_plugin, hook_name, *args)


def _coerce_loaded_auth_plugin(candidate: object, *, default_name: str) -> LoadedAuthPlugin:
    if isinstance(candidate, LoadedAuthPlugin):
        return candidate
    if isinstance(candidate, RuntimePlugin):
        plugin_name = getattr(candidate, "name", default_name)
        return make_auth_plugin(str(plugin_name), candidate)
    if isinstance(candidate, type) and issubclass(candidate, RuntimePlugin):
        plugin_name = getattr(candidate, "name", default_name)
        return make_auth_plugin(str(plugin_name), candidate())
    raise TypeError(
        "Auth plugins must be LoadedAuthPlugin instances, RuntimePlugin instances, "
        "or RuntimePlugin subclasses."
    )


def _loaded_auth_plugins(
    *,
    auth_plugins: list[LoadedAuthPlugin | RuntimePlugin | type[RuntimePlugin]] | None,
    workflow_hooks: list[WorkflowHook] | None,
) -> list[LoadedAuthPlugin]:
    loaded: list[LoadedAuthPlugin] = []
    for index, plugin in enumerate(auth_plugins or [], start=1):
        loaded.append(_coerce_loaded_auth_plugin(plugin, default_name=f"auth-plugin-{index}"))
    for index, hook in enumerate(workflow_hooks or [], start=1):
        loaded.append(_coerce_loaded_auth_plugin(hook, default_name=f"workflow-hook-{index}"))
    return loaded


def _execute_request(
    client: httpx.Client,
    request: PreparedRequest,
    *,
    context: RuntimeContext,
    default_headers: dict[str, str],
    default_query: dict[str, Any],
    artifact_root: Path | None,
    artifact_filename: str | None,
    artifact_metadata: dict[str, Any] | None,
    auth_plugins: list[LoadedAuthPlugin],
) -> RequestExecution:
    _invoke_auth_plugins(auth_plugins, "before_request", request, context)

    request_kwargs: dict[str, Any] | None = None
    try:
        url = _resolve_request_path(
            request,
            base_url=context.base_url,
            extracted_values=context.extracted_values,
        )
        headers = _resolved_headers(
            request,
            default_headers=default_headers,
            extracted_values=context.extracted_values,
        )
        query = _resolved_query(
            request,
            default_query=default_query,
            extracted_values=context.extracted_values,
        )
        request_kwargs = {
            "params": query,
            "headers": headers,
        }
        if not request.omit_body:
            if request.raw_body is not None:
                request_kwargs["content"] = str(
                    _resolve_templates(request.raw_body, context.extracted_values)
                )
                content_type = request.content_type
                if content_type is not None:
                    content_type = str(_resolve_templates(content_type, context.extracted_values))
                if content_type and "Content-Type" not in headers:
                    request_kwargs["headers"] = {**headers, "Content-Type": content_type}
                    headers = request_kwargs["headers"]
            elif request.body_json is not None:
                request_kwargs["json"] = _resolve_templates(
                    request.body_json,
                    context.extracted_values,
                )
        execution = RequestExecution(
            url=url,
            headers=headers,
            query=query,
            response=None,
            error=None,
            duration_ms=0.0,
        )
    except WorkflowResolutionError as exc:
        execution = RequestExecution(
            url=context.build_url(request.path),
            headers={},
            query={},
            response=None,
            error=str(exc),
            duration_ms=0.0,
            resolution_error=True,
        )
        _invoke_auth_plugins(auth_plugins, "after_request", request, context, execution)
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
    try:
        execution.response = client.request(request.method, execution.url, **request_kwargs)
    except Exception as exc:  # noqa: BLE001
        execution.error = str(exc)
    execution.duration_ms = (time.perf_counter() - start) * 1000.0

    _invoke_auth_plugins(auth_plugins, "after_request", request, context, execution)
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
            request_kwargs=request_kwargs,
            response=execution.response,
            error=execution.error,
            duration_ms=execution.duration_ms,
        )

    return execution


def _request_result(
    attack: AttackCase,
    execution: RequestExecution,
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
        path=attack.path,
        tags=list(attack.tags),
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
    execution: RequestExecution,
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
            _prepared_request_from_attack(
                workflow.terminal_attack,
                phase="workflow_terminal",
            ),
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
        path=workflow.path,
        tags=list(workflow.tags),
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
            extracted[extract.name] = extract_json_pointer(payload, extract.json_pointer)
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
    auth_plugins: list[LoadedAuthPlugin],
    initial_state: dict[str, Any],
) -> AttackResult:
    total_duration_ms = 0.0
    with httpx.Client(timeout=timeout_seconds, follow_redirects=False) as client:
        context = RuntimeContext(
            client=client,
            base_url=base_url,
            scope="workflow",
            state=dict(initial_state),
            extracted_values={},
            workflow_id=workflow.id,
        )
        _invoke_auth_plugins(auth_plugins, "before_workflow", workflow, context)

        workflow_steps: list[WorkflowStepResult] = []
        for index, step in enumerate(workflow.setup_steps, start=1):
            execution = _execute_request(
                client,
                _prepared_request_from_step(workflow, step, step_index=index),
                context=context,
                default_headers=default_headers,
                default_query=default_query,
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
                auth_plugins=auth_plugins,
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

            if setup_error is not None:
                if not setup_error.startswith("Workflow setup failed"):
                    setup_error = f"Workflow setup failed during '{step.name}': {setup_error}"
                result = _workflow_failure_result(
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
                _invoke_auth_plugins(auth_plugins, "after_workflow", workflow, context, result)
                return result

        terminal_execution = _execute_request(
            client,
            _prepared_request_from_attack(
                workflow.terminal_attack,
                phase="workflow_terminal",
            ),
            context=context,
            default_headers=default_headers,
            default_query=default_query,
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
            auth_plugins=auth_plugins,
        )
        total_duration_ms += terminal_execution.duration_ms

        if terminal_execution.resolution_error:
            result = _workflow_failure_result(
                workflow,
                base_url=base_url,
                error=f"Workflow setup failed before terminal step: {terminal_execution.error}",
                workflow_steps=workflow_steps,
                duration_ms=total_duration_ms,
                extracted_values=context.extracted_values,
            )
            _invoke_auth_plugins(auth_plugins, "after_workflow", workflow, context, result)
            return result

        result = _request_result(
            workflow.terminal_attack,
            terminal_execution,
            attack_type="workflow",
            workflow_steps=workflow_steps,
        ).model_copy(
            update={
                "attack_id": workflow.id,
                "name": workflow.name,
                "duration_ms": round(total_duration_ms, 2),
            }
        )
        _invoke_auth_plugins(auth_plugins, "after_workflow", workflow, context, result)
        return result


def execute_attack_suite(
    suite: AttackSuite,
    *,
    base_url: str,
    default_headers: dict[str, str] | None = None,
    default_query: dict[str, Any] | None = None,
    timeout_seconds: float = 10.0,
    artifact_dir: str | Path | None = None,
    auth_plugins: list[LoadedAuthPlugin | RuntimePlugin | type[RuntimePlugin]] | None = None,
    workflow_hooks: list[WorkflowHook] | None = None,
) -> AttackResults:
    default_headers = dict(default_headers or {})
    default_query = dict(default_query or {})
    results: list[AttackResult] = []
    artifact_root = Path(artifact_dir) if artifact_dir is not None else None
    if artifact_root is not None:
        artifact_root.mkdir(parents=True, exist_ok=True)

    loaded_plugins = _loaded_auth_plugins(
        auth_plugins=auth_plugins,
        workflow_hooks=workflow_hooks,
    )
    with httpx.Client(timeout=timeout_seconds, follow_redirects=False) as client:
        suite_context = RuntimeContext(
            client=client,
            base_url=base_url,
            scope="suite",
        )
        _invoke_auth_plugins(loaded_plugins, "before_suite", suite_context)
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
                        auth_plugins=loaded_plugins,
                        initial_state=suite_context.state,
                    )
                )
                continue

            execution = _execute_request(
                client,
                _prepared_request_from_attack(attack),
                context=suite_context,
                default_headers=default_headers,
                default_query=default_query,
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
                auth_plugins=loaded_plugins,
            )
            results.append(_request_result(attack, execution, attack_type="request"))

    return AttackResults(source=suite.source, base_url=base_url, results=results)
