from __future__ import annotations

import hashlib
from copy import deepcopy
from typing import Any

from knives_out.attack_packs import LoadedAttackPack
from knives_out.models import AttackCase, AttackSuite, OperationSpec, ParameterSpec

MAX_SAMPLE_DEPTH = 4


def _normalize_schema(schema: dict[str, Any] | None) -> dict[str, Any]:
    if not schema:
        return {}

    result = deepcopy(schema)
    if "allOf" in result:
        merged: dict[str, Any] = {"type": "object", "properties": {}, "required": []}
        for part in result["allOf"]:
            normalized_part = _normalize_schema(part)
            merged["properties"].update(normalized_part.get("properties", {}))
            merged["required"] = sorted(
                set(merged["required"]) | set(normalized_part.get("required", []))
            )
        result = merged
    elif "oneOf" in result:
        result = _normalize_schema(result["oneOf"][0])
    elif "anyOf" in result:
        result = _normalize_schema(result["anyOf"][0])

    return result


def _sample_scalar_value(schema: dict[str, Any]) -> Any:
    schema_type = schema.get("type")
    schema_format = schema.get("format")

    if schema_type == "string":
        if schema_format == "date-time":
            return "2026-01-01T00:00:00Z"
        if schema_format == "date":
            return "2026-01-01"
        if schema_format == "uuid":
            return "00000000-0000-4000-8000-000000000000"
        if schema_format == "email":
            return "person@example.com"
        return "example"
    if schema_type == "integer":
        return 1
    if schema_type == "number":
        return 1.0
    if schema_type == "boolean":
        return True
    return "example"


def _properties_to_sample(schema: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    properties = schema.get("properties", {})
    required = set(schema.get("required", []))

    if required:
        return [
            (name, property_schema)
            for name, property_schema in properties.items()
            if name in required
        ]
    if properties:
        first_name, first_schema = next(iter(properties.items()))
        return [(first_name, first_schema)]
    return []


def _limited_sample_value(schema: dict[str, Any], *, budget: int = 2) -> Any:
    if "default" in schema:
        return schema["default"]
    if "enum" in schema and schema["enum"]:
        return schema["enum"][0]

    schema_type = schema.get("type")
    if budget <= 0:
        if schema_type == "array":
            return []
        if schema_type == "object" or schema.get("properties"):
            return {}
        return _sample_scalar_value(schema)

    if schema_type == "array":
        return [_limited_sample_value(schema.get("items", {}), budget=budget - 1)]
    if schema_type == "object" or schema.get("properties"):
        body: dict[str, Any] = {}
        for name, property_schema in _properties_to_sample(schema):
            body[name] = _limited_sample_value(
                _normalize_schema(property_schema),
                budget=budget - 1,
            )
        return body

    return _sample_scalar_value(schema)


def sample_value(schema: dict[str, Any] | None, *, depth: int = 0) -> Any:
    schema = _normalize_schema(schema)
    if depth > MAX_SAMPLE_DEPTH:
        # Preserve container shapes after the recursion limit so deep samples stay useful.
        return _limited_sample_value(schema)

    if "default" in schema:
        return schema["default"]
    if "enum" in schema and schema["enum"]:
        return schema["enum"][0]

    schema_type = schema.get("type")

    if schema_type in {"string", "integer", "number", "boolean"}:
        return _sample_scalar_value(schema)
    if schema_type == "array":
        return [sample_value(schema.get("items", {}), depth=depth + 1)]
    if schema_type == "object" or schema.get("properties"):
        body: dict[str, Any] = {}
        for name, property_schema in _properties_to_sample(schema):
            body[name] = sample_value(property_schema, depth=depth + 1)
        return body

    return _sample_scalar_value(schema)


def invalid_scalar_value(schema: dict[str, Any] | None) -> Any:
    schema = _normalize_schema(schema)
    if "enum" in schema:
        return "__invalid_enum__"

    schema_type = schema.get("type")
    if schema_type == "integer":
        return "not-an-integer"
    if schema_type == "number":
        return "not-a-number"
    if schema_type == "boolean":
        return "not-a-boolean"
    if schema_type == "array":
        return {"not": "an-array"}
    if schema_type == "object" or schema.get("properties"):
        return "not-an-object"
    return "__invalid__"


def invalid_enum_value(schema: dict[str, Any] | None) -> Any:
    schema = _normalize_schema(schema)
    enum_values = schema.get("enum") or []
    if "__invalid_enum__" not in enum_values:
        return "__invalid_enum__"
    return "__definitely_invalid_enum__"


def malformed_json_body(_: dict[str, Any] | None) -> str:
    return '{"unterminated": true'


def attack_id(operation_id: str, kind: str, target: str) -> str:
    digest = hashlib.sha1(f"{operation_id}:{kind}:{target}".encode()).hexdigest()[:12]
    return f"atk_{digest}"


def base_request_context(
    operation: OperationSpec,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, str], Any | None]:
    path_params: dict[str, Any] = {}
    query_params: dict[str, Any] = {}
    headers: dict[str, str] = {}

    for parameter in operation.parameters:
        value = sample_value(parameter.schema_def)
        if parameter.location == "path":
            path_params[parameter.name] = value
        elif parameter.location == "query" and parameter.required:
            query_params[parameter.name] = value
        elif parameter.location == "header" and parameter.required:
            headers[parameter.name] = str(value)

    body = sample_value(operation.request_body_schema) if operation.request_body_schema else None
    return path_params, query_params, headers, body


def _copy_context(
    path_params: dict[str, Any],
    query_params: dict[str, Any],
    headers: dict[str, str],
    body: Any | None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, str], Any | None]:
    return deepcopy(path_params), deepcopy(query_params), deepcopy(headers), deepcopy(body)


def _parameter_target_label(parameter: ParameterSpec) -> str:
    return f"{parameter.location}:{parameter.name}"


def _response_schemas_for_attack(operation: OperationSpec) -> dict[str, Any]:
    return deepcopy(operation.response_schemas)


def generate_attacks_for_operation(operation: OperationSpec) -> list[AttackCase]:
    attacks: list[AttackCase] = []
    base_path_params, base_query_params, base_headers, base_body = base_request_context(operation)

    for parameter in operation.parameters:
        if parameter.required and parameter.location in {"query", "header"}:
            path_params, query_params, headers, body = _copy_context(
                base_path_params, base_query_params, base_headers, base_body
            )
            if parameter.location == "query":
                query_params.pop(parameter.name, None)
            elif parameter.location == "header":
                headers.pop(parameter.name, None)

            attacks.append(
                AttackCase(
                    id=attack_id(
                        operation.operation_id,
                        "missing_required_param",
                        _parameter_target_label(parameter),
                    ),
                    name=f"Missing required {parameter.location} parameter '{parameter.name}'",
                    kind="missing_required_param",
                    operation_id=operation.operation_id,
                    method=operation.method,
                    path=operation.path,
                    description=(
                        f"Omits required {parameter.location} parameter '{parameter.name}'."
                    ),
                    path_params=path_params,
                    query=query_params,
                    headers=headers,
                    body_json=body,
                    response_schemas=_response_schemas_for_attack(operation),
                )
            )

        path_params, query_params, headers, body = _copy_context(
            base_path_params, base_query_params, base_headers, base_body
        )
        invalid_value = invalid_scalar_value(parameter.schema_def)
        if parameter.location == "path":
            path_params[parameter.name] = invalid_value
        elif parameter.location == "query":
            query_params[parameter.name] = invalid_value
        elif parameter.location == "header":
            headers[parameter.name] = str(invalid_value)
        else:
            continue

        attacks.append(
            AttackCase(
                id=attack_id(
                    operation.operation_id,
                    "wrong_type_param",
                    _parameter_target_label(parameter),
                ),
                name=f"Wrong-type {parameter.location} parameter '{parameter.name}'",
                kind="wrong_type_param",
                operation_id=operation.operation_id,
                method=operation.method,
                path=operation.path,
                description=(
                    f"Substitutes a wrong-type value for {parameter.location} "
                    f"parameter '{parameter.name}'."
                ),
                path_params=path_params,
                query=query_params,
                headers=headers,
                body_json=body,
                response_schemas=_response_schemas_for_attack(operation),
            )
        )

        if parameter.schema_def.get("enum"):
            path_params, query_params, headers, body = _copy_context(
                base_path_params, base_query_params, base_headers, base_body
            )
            enum_value = invalid_enum_value(parameter.schema_def)
            if parameter.location == "path":
                path_params[parameter.name] = enum_value
            elif parameter.location == "query":
                query_params[parameter.name] = enum_value
            elif parameter.location == "header":
                headers[parameter.name] = str(enum_value)
            else:
                continue

            attacks.append(
                AttackCase(
                    id=attack_id(
                        operation.operation_id,
                        "invalid_enum",
                        _parameter_target_label(parameter),
                    ),
                    name=f"Invalid enum {parameter.location} parameter '{parameter.name}'",
                    kind="invalid_enum",
                    operation_id=operation.operation_id,
                    method=operation.method,
                    path=operation.path,
                    description=f"Uses a value outside the declared enum for '{parameter.name}'.",
                    path_params=path_params,
                    query=query_params,
                    headers=headers,
                    body_json=body,
                    response_schemas=_response_schemas_for_attack(operation),
                )
            )

    if operation.request_body_required:
        path_params, query_params, headers, _ = _copy_context(
            base_path_params, base_query_params, base_headers, base_body
        )
        attacks.append(
            AttackCase(
                id=attack_id(operation.operation_id, "missing_request_body", "body"),
                name="Missing request body",
                kind="missing_request_body",
                operation_id=operation.operation_id,
                method=operation.method,
                path=operation.path,
                description="Omits the required request body.",
                path_params=path_params,
                query=query_params,
                headers=headers,
                omit_body=True,
                response_schemas=_response_schemas_for_attack(operation),
            )
        )

    if operation.request_body_schema and operation.request_body_content_type == "application/json":
        path_params, query_params, headers, _ = _copy_context(
            base_path_params, base_query_params, base_headers, base_body
        )
        attacks.append(
            AttackCase(
                id=attack_id(operation.operation_id, "malformed_json_body", "body"),
                name="Malformed JSON body",
                kind="malformed_json_body",
                operation_id=operation.operation_id,
                method=operation.method,
                path=operation.path,
                description="Sends invalid JSON for a JSON request body.",
                path_params=path_params,
                query=query_params,
                headers=headers,
                raw_body=malformed_json_body(operation.request_body_schema),
                content_type="application/json",
                response_schemas=_response_schemas_for_attack(operation),
            )
        )

    if operation.auth_required and (operation.auth_header_names or operation.auth_query_names):
        path_params, query_params, headers, body = _copy_context(
            base_path_params, base_query_params, base_headers, base_body
        )
        attacks.append(
            AttackCase(
                id=attack_id(operation.operation_id, "missing_auth", "auth"),
                name="Missing auth",
                kind="missing_auth",
                operation_id=operation.operation_id,
                method=operation.method,
                path=operation.path,
                description="Removes the declared auth credential from the request.",
                path_params=path_params,
                query=query_params,
                headers=headers,
                body_json=body,
                omit_header_names=operation.auth_header_names,
                omit_query_names=operation.auth_query_names,
                response_schemas=_response_schemas_for_attack(operation),
            )
        )

    return attacks


def generate_attack_suite(
    operations: list[OperationSpec],
    source: str,
    *,
    extra_packs: list[LoadedAttackPack] | None = None,
) -> AttackSuite:
    attacks: list[AttackCase] = []
    packs = list(extra_packs or [])
    for operation in operations:
        attacks.extend(generate_attacks_for_operation(operation))
        for pack in packs:
            attacks.extend(pack.generate(operation))
    return AttackSuite(source=source, attacks=attacks)
