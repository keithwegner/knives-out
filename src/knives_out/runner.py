from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from knives_out.models import AttackCase, AttackResult, AttackResults, AttackSuite, ResponseSpec


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


def _excerpt(text: str, limit: int = 300) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _request_body_artifact(attack: AttackCase, headers: dict[str, str]) -> dict[str, Any]:
    if attack.omit_body:
        return {"present": False}
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


def _write_attack_artifact(
    artifact_root: Path,
    *,
    attack: AttackCase,
    url: str,
    headers: dict[str, str],
    query: dict[str, Any],
    response: httpx.Response | None,
    error: str | None,
    duration_ms: float,
) -> None:
    artifact = {
        "attack": {
            "id": attack.id,
            "name": attack.name,
            "kind": attack.kind,
            "operation_id": attack.operation_id,
        },
        "request": {
            "method": attack.method,
            "url": url,
            "headers": headers,
            "query": query,
            "body": _request_body_artifact(attack, headers),
        },
        "response": {
            "status_code": response.status_code if response is not None else None,
            "error": error,
            "duration_ms": round(duration_ms, 2),
            "body_excerpt": _excerpt(response.text) if response is not None else None,
        },
    }
    artifact_path = artifact_root / f"{attack.id}.json"
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


def execute_attack_suite(
    suite: AttackSuite,
    *,
    base_url: str,
    default_headers: dict[str, str] | None = None,
    default_query: dict[str, Any] | None = None,
    timeout_seconds: float = 10.0,
    artifact_dir: str | Path | None = None,
) -> AttackResults:
    default_headers = dict(default_headers or {})
    default_query = dict(default_query or {})
    results: list[AttackResult] = []
    artifact_root = Path(artifact_dir) if artifact_dir is not None else None
    if artifact_root is not None:
        artifact_root.mkdir(parents=True, exist_ok=True)

    normalized_base_url = base_url.rstrip("/")

    with httpx.Client(timeout=timeout_seconds, follow_redirects=False) as client:
        for attack in suite.attacks:
            url = normalized_base_url + _render_path(attack.path, attack.path_params)
            headers = {**default_headers, **attack.headers}
            headers = _remove_header_names(headers, attack.omit_header_names)
            query = {**default_query, **attack.query}
            for name in attack.omit_query_names:
                query.pop(name, None)

            request_kwargs: dict[str, Any] = {
                "params": query,
                "headers": headers,
            }

            if not attack.omit_body:
                if attack.raw_body is not None:
                    request_kwargs["content"] = attack.raw_body
                    if attack.content_type and "Content-Type" not in headers:
                        request_kwargs["headers"] = {**headers, "Content-Type": attack.content_type}
                elif attack.body_json is not None:
                    request_kwargs["json"] = attack.body_json

            start = time.perf_counter()
            response: httpx.Response | None = None
            error: str | None = None
            try:
                response = client.request(attack.method, url, **request_kwargs)
            except Exception as exc:  # noqa: BLE001
                error = str(exc)
            duration_ms = (time.perf_counter() - start) * 1000.0

            if artifact_root is not None:
                _write_attack_artifact(
                    artifact_root,
                    attack=attack,
                    url=url,
                    headers=request_kwargs["headers"],
                    query=query,
                    response=response,
                    error=error,
                    duration_ms=duration_ms,
                )

            flagged, issue = evaluate_result(response.status_code if response else None, error)
            response_schema_status: str | None = None
            response_schema_valid: bool | None = None
            response_schema_error: str | None = None
            if response is not None:
                (
                    response_schema_status,
                    response_schema_valid,
                    response_schema_error,
                ) = _validate_response_schema(attack, response)
            if response_schema_valid is False:
                flagged = True
                if issue in {None, "unexpected_success"}:
                    issue = "response_schema_mismatch"

            results.append(
                AttackResult(
                    attack_id=attack.id,
                    operation_id=attack.operation_id,
                    kind=attack.kind,
                    name=attack.name,
                    method=attack.method,
                    url=url,
                    status_code=response.status_code if response else None,
                    error=error,
                    duration_ms=round(duration_ms, 2),
                    flagged=flagged,
                    issue=issue,
                    response_excerpt=_excerpt(response.text) if response is not None else None,
                    response_schema_status=response_schema_status,
                    response_schema_valid=response_schema_valid,
                    response_schema_error=response_schema_error,
                )
            )

    return AttackResults(source=suite.source, base_url=base_url, results=results)
