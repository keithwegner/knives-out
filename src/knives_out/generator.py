from __future__ import annotations

import hashlib
import re
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from knives_out.attack_packs import LoadedAttackPack
from knives_out.models import (
    AttackCase,
    AttackSuite,
    ExtractRule,
    OperationSpec,
    ParameterSpec,
    WorkflowAttackCase,
    WorkflowStep,
)
from knives_out.workflow_packs import LoadedWorkflowPack

MAX_SAMPLE_DEPTH = 4
_SCALAR_SCHEMA_TYPES = {"string", "integer", "number", "boolean"}


@dataclass(frozen=True)
class _ExtractCandidate:
    name: str
    json_pointer: str


@dataclass(frozen=True)
class _TargetBinding:
    target: str
    name: str


@dataclass(frozen=True)
class _BindingAssignment:
    binding: _TargetBinding
    extract: _ExtractCandidate
    exact_name: bool


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


def _schema_type(schema: dict[str, Any] | None) -> str | None:
    if not schema:
        return None
    normalized = _normalize_schema(schema)
    schema_type = normalized.get("type")
    if isinstance(schema_type, str):
        return schema_type
    if normalized.get("properties") or normalized.get("required"):
        return "object"
    if "items" in normalized:
        return "array"
    return None


def _is_scalar_schema(schema: dict[str, Any] | None) -> bool:
    return _schema_type(schema) in _SCALAR_SCHEMA_TYPES


def _escape_json_pointer_token(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _name_tokens(name: str) -> tuple[str, ...]:
    expanded = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return tuple(token.lower() for token in re.split(r"[^A-Za-z0-9]+", expanded) if token)


def _match_names(source_name: str, target_name: str) -> tuple[bool, bool]:
    source_tokens = _name_tokens(source_name)
    target_tokens = _name_tokens(target_name)
    if not source_tokens or not target_tokens:
        return False, False
    if source_tokens == target_tokens:
        return True, True
    if source_tokens[-1] == "id" and target_tokens[-1] == "id":
        if source_tokens == ("id",) or target_tokens == ("id",):
            return True, False
    return False, False


def _is_json_response_schema(content_type: str | None, schema: dict[str, Any] | None) -> bool:
    normalized_content_type = (content_type or "").split(";", 1)[0].strip().lower()
    return "json" in normalized_content_type or _schema_type(schema) in {"object", "array"}


def _producer_extract_candidates(operation: OperationSpec) -> list[_ExtractCandidate]:
    if operation.auth_required:
        return []

    candidates: dict[tuple[str, str], _ExtractCandidate] = {}
    for status_code, response_spec in operation.response_schemas.items():
        if not status_code.startswith("2"):
            continue
        if not _is_json_response_schema(response_spec.content_type, response_spec.schema_def):
            continue

        schema = _normalize_schema(response_spec.schema_def)
        if _schema_type(schema) == "object":
            for name, property_schema in schema.get("properties", {}).items():
                property_schema = _normalize_schema(property_schema)
                if _is_scalar_schema(property_schema):
                    candidate = _ExtractCandidate(
                        name=name,
                        json_pointer=f"/{_escape_json_pointer_token(name)}",
                    )
                    candidates[(candidate.name, candidate.json_pointer)] = candidate
        elif _schema_type(schema) == "array":
            item_schema = _normalize_schema(schema.get("items", {}))
            if _schema_type(item_schema) != "object":
                continue
            for name, property_schema in item_schema.get("properties", {}).items():
                property_schema = _normalize_schema(property_schema)
                if _is_scalar_schema(property_schema):
                    candidate = _ExtractCandidate(
                        name=name,
                        json_pointer=f"/0/{_escape_json_pointer_token(name)}",
                    )
                    candidates[(candidate.name, candidate.json_pointer)] = candidate

    return list(candidates.values())


def _terminal_required_bindings(
    operation: OperationSpec,
    attack: AttackCase,
) -> list[_TargetBinding]:
    bindings: list[_TargetBinding] = []
    for parameter in operation.parameters:
        if parameter.location == "path" and parameter.name in attack.path_params:
            bindings.append(_TargetBinding(target="path", name=parameter.name))
        elif (
            parameter.location == "query" and parameter.required and parameter.name in attack.query
        ):
            bindings.append(_TargetBinding(target="query", name=parameter.name))

    body_schema = _normalize_schema(operation.request_body_schema)
    if isinstance(attack.body_json, dict) and _schema_type(body_schema) == "object":
        properties = body_schema.get("properties", {})
        for name in body_schema.get("required", []):
            if name not in attack.body_json:
                continue
            property_schema = _normalize_schema(properties.get(name, {}))
            if _is_scalar_schema(property_schema):
                bindings.append(_TargetBinding(target="body", name=name))

    return bindings


def _best_binding_assignment(
    binding: _TargetBinding,
    extracts: list[_ExtractCandidate],
) -> _BindingAssignment | None:
    best_assignment: _BindingAssignment | None = None
    best_score = (-1, -1)

    for extract in extracts:
        matched, exact_name = _match_names(extract.name, binding.name)
        if not matched:
            continue
        score = (1 if exact_name else 0, -len(_name_tokens(extract.name)))
        if score > best_score:
            best_assignment = _BindingAssignment(
                binding=binding,
                extract=extract,
                exact_name=exact_name,
            )
            best_score = score

    return best_assignment


def _set_placeholder_value(attack: AttackCase, binding: _TargetBinding, placeholder: str) -> None:
    if binding.target == "path":
        attack.path_params[binding.name] = placeholder
    elif binding.target == "query":
        attack.query[binding.name] = placeholder
    elif binding.target == "body" and isinstance(attack.body_json, dict):
        attack.body_json[binding.name] = placeholder


def _workflow_attack_from_assignments(
    producer: OperationSpec,
    terminal_attack: AttackCase,
    assignments: list[_BindingAssignment],
) -> WorkflowAttackCase:
    path_params, query, headers, body = base_request_context(producer)
    terminal_copy = terminal_attack.model_copy(deep=True)

    extracts: list[ExtractRule] = []
    seen_extracts: set[tuple[str, str]] = set()
    for assignment in assignments:
        extract_key = (assignment.extract.name, assignment.extract.json_pointer)
        if extract_key not in seen_extracts:
            extracts.append(
                ExtractRule(
                    name=assignment.extract.name,
                    json_pointer=assignment.extract.json_pointer,
                )
            )
            seen_extracts.add(extract_key)
        _set_placeholder_value(
            terminal_copy,
            assignment.binding,
            f"{{{{{assignment.extract.name}}}}}",
        )

    workflow_id = attack_id(
        terminal_attack.operation_id,
        f"workflow_{terminal_attack.kind}",
        f"{producer.operation_id}:{','.join(sorted(name for name, _ in seen_extracts))}",
    )
    return WorkflowAttackCase(
        id=workflow_id,
        name=f"Workflow via {producer.operation_id}: {terminal_attack.name}",
        kind=terminal_attack.kind,
        operation_id=terminal_attack.operation_id,
        method=terminal_attack.method,
        path=terminal_attack.path,
        description=(
            f"Creates state with {producer.operation_id} before executing "
            f"the terminal attack '{terminal_attack.name}'."
        ),
        setup_steps=[
            WorkflowStep(
                name=f"Setup via {producer.operation_id}",
                operation_id=producer.operation_id,
                method=producer.method,
                path=producer.path,
                path_params=path_params,
                query=query,
                headers=headers,
                body_json=body,
                extracts=extracts,
            )
        ],
        terminal_attack=terminal_copy,
    )


def generate_workflow_attacks(
    operations: list[OperationSpec],
    request_attacks: list[AttackCase],
) -> list[WorkflowAttackCase]:
    operations_by_id = {operation.operation_id: operation for operation in operations}
    producer_candidates = [
        (operation, _producer_extract_candidates(operation)) for operation in operations
    ]

    workflows: list[WorkflowAttackCase] = []
    for attack in request_attacks:
        operation = operations_by_id.get(attack.operation_id)
        if operation is None:
            continue

        bindings = _terminal_required_bindings(operation, attack)
        if not bindings:
            continue

        candidate_matches: list[tuple[tuple[int, int], WorkflowAttackCase]] = []
        for producer, extracts in producer_candidates:
            if producer.operation_id == attack.operation_id or not extracts:
                continue

            assignments: list[_BindingAssignment] = []
            exact_matches = 0
            for binding in bindings:
                assignment = _best_binding_assignment(binding, extracts)
                if assignment is None:
                    continue
                assignments.append(assignment)
                if assignment.exact_name:
                    exact_matches += 1

            if not assignments:
                continue

            score = (exact_matches, len(assignments))
            candidate_matches.append(
                (score, _workflow_attack_from_assignments(producer, attack, assignments))
            )

        if not candidate_matches:
            continue

        candidate_matches.sort(key=lambda item: item[0], reverse=True)
        best_score, best_workflow = candidate_matches[0]
        if len(candidate_matches) > 1 and candidate_matches[1][0] == best_score:
            continue
        workflows.append(best_workflow)

    return workflows


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
    auto_workflows: bool = False,
    workflow_packs: list[LoadedWorkflowPack] | None = None,
) -> AttackSuite:
    attacks: list[AttackCase] = []
    packs = list(extra_packs or [])
    for operation in operations:
        attacks.extend(generate_attacks_for_operation(operation))
        for pack in packs:
            attacks.extend(pack.generate(operation))

    workflows: list[WorkflowAttackCase] = []
    if auto_workflows:
        workflows.extend(generate_workflow_attacks(operations, attacks))

    for workflow_pack in workflow_packs or []:
        workflows.extend(workflow_pack.generate(operations, attacks))

    return AttackSuite(source=source, attacks=[*attacks, *workflows])
