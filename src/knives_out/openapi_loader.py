from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from knives_out.models import OperationSpec, ParameterSpec, ResponseSpec

HTTP_METHODS = ["get", "post", "put", "patch", "delete", "head", "options"]
PARAMETER_LOCATION_ORDER = {"path": 0, "query": 1, "header": 2, "cookie": 3}


def load_openapi_document(path: str | Path) -> dict[str, Any]:
    spec_path = Path(path)
    raw = spec_path.read_text(encoding="utf-8")
    if spec_path.suffix.lower() == ".json":
        import json

        document = json.loads(raw)
    else:
        document = yaml.safe_load(raw)

    if not isinstance(document, dict):
        raise ValueError("OpenAPI document did not parse to an object.")
    if "paths" not in document:
        raise ValueError("OpenAPI document is missing a 'paths' section.")
    return document


def resolve_refs(node: Any, root: dict[str, Any]) -> Any:
    if isinstance(node, dict):
        if "$ref" in node:
            ref = node["$ref"]
            if not isinstance(ref, str) or not ref.startswith("#/"):
                raise ValueError(f"Only local refs are supported right now: {ref!r}")
            target: Any = root
            for part in ref[2:].split("/"):
                target = target[part]
            resolved = resolve_refs(deepcopy(target), root)
            sibling_keys = {k: v for k, v in node.items() if k != "$ref"}
            if sibling_keys and isinstance(resolved, dict):
                merged = deepcopy(resolved)
                merged.update(resolve_refs(sibling_keys, root))
                return merged
            return resolved
        return {key: resolve_refs(value, root) for key, value in node.items()}
    if isinstance(node, list):
        return [resolve_refs(item, root) for item in node]
    return node


def _merge_parameters(
    root: dict[str, Any],
    path_parameters: list[dict[str, Any]],
    operation_parameters: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for parameter in path_parameters + operation_parameters:
        resolved = resolve_refs(parameter, root)
        merged[(resolved["name"], resolved["in"])] = resolved
    return sorted(
        merged.values(),
        key=lambda parameter: (
            PARAMETER_LOCATION_ORDER.get(parameter["in"], len(PARAMETER_LOCATION_ORDER)),
            parameter["name"].casefold(),
        ),
    )


def _extract_request_body(
    operation: dict[str, Any],
    root: dict[str, Any],
) -> tuple[bool, dict[str, Any] | None, str | None]:
    request_body = operation.get("requestBody")
    if not request_body:
        return False, None, None

    resolved = resolve_refs(request_body, root)
    content = resolved.get("content", {})
    if not isinstance(content, dict) or not content:
        return bool(resolved.get("required", False)), None, None

    preferred_type, schema = _extract_content_schema(content, root)
    return bool(resolved.get("required", False)), schema, preferred_type


def _extract_content_schema(
    content: dict[str, Any],
    root: dict[str, Any],
) -> tuple[str | None, dict[str, Any] | None]:
    if "application/json" in content:
        preferred_type = "application/json"
    else:
        preferred_type = next(iter(content), None)

    if preferred_type is None:
        return None, None

    media_type = content.get(preferred_type, {})
    schema = resolve_refs(media_type.get("schema"), root) if media_type.get("schema") else None
    return preferred_type, schema


def _extract_security(
    operation: dict[str, Any],
    root: dict[str, Any],
) -> tuple[bool, list[str], list[str]]:
    if "security" in operation:
        security = operation["security"]
    else:
        security = root.get("security")

    if not security:
        return False, [], []

    schemes = root.get("components", {}).get("securitySchemes", {})
    header_names: set[str] = set()
    query_names: set[str] = set()

    for requirement in security:
        if not isinstance(requirement, dict):
            continue
        for scheme_name in requirement:
            scheme = resolve_refs(schemes.get(scheme_name, {}), root)
            scheme_type = scheme.get("type")
            if scheme_type == "http":
                header_names.add("Authorization")
            elif scheme_type == "apiKey":
                location = scheme.get("in")
                name = scheme.get("name")
                if location == "header" and name:
                    header_names.add(name)
                elif location == "query" and name:
                    query_names.add(name)

    return True, sorted(header_names), sorted(query_names)


def _extract_response_schemas(
    operation: dict[str, Any],
    root: dict[str, Any],
) -> dict[str, ResponseSpec]:
    responses = operation.get("responses", {})
    if not isinstance(responses, dict):
        return {}

    extracted: dict[str, ResponseSpec] = {}
    for status_code, response in responses.items():
        resolved = resolve_refs(response, root)
        content = resolved.get("content", {})
        if not isinstance(content, dict) or not content:
            extracted[str(status_code)] = ResponseSpec()
            continue

        content_type, schema = _extract_content_schema(content, root)
        extracted[str(status_code)] = ResponseSpec(
            content_type=content_type,
            schema_def=schema,
        )

    return extracted


def load_operations(path: str | Path) -> list[OperationSpec]:
    document = load_openapi_document(path)
    operations: list[OperationSpec] = []

    for route, path_item in document.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue

        path_parameters = path_item.get("parameters", [])
        for method in HTTP_METHODS:
            operation = path_item.get(method)
            if not operation:
                continue

            operation_parameters = operation.get("parameters", [])
            merged_parameters = _merge_parameters(document, path_parameters, operation_parameters)
            parsed_parameters = [
                ParameterSpec(
                    name=parameter["name"],
                    location=parameter["in"],
                    required=bool(parameter.get("required", False)),
                    schema_def=parameter.get("schema", {}) or {},
                )
                for parameter in merged_parameters
            ]

            (
                request_body_required,
                request_body_schema,
                request_body_content_type,
            ) = _extract_request_body(operation, document)
            auth_required, auth_header_names, auth_query_names = _extract_security(
                operation,
                document,
            )
            response_schemas = _extract_response_schemas(operation, document)

            operation_id = operation.get("operationId")
            if not operation_id:
                sanitized_path = (
                    route.strip("/").replace("/", "_").replace("{", "").replace("}", "") or "root"
                )
                operation_id = f"{method}_{sanitized_path}"

            operations.append(
                OperationSpec(
                    operation_id=operation_id,
                    method=method.upper(),
                    path=route,
                    summary=operation.get("summary") or operation.get("description"),
                    parameters=parsed_parameters,
                    request_body_required=request_body_required,
                    request_body_schema=request_body_schema,
                    request_body_content_type=request_body_content_type,
                    auth_required=auth_required,
                    auth_header_names=auth_header_names,
                    auth_query_names=auth_query_names,
                    response_schemas=response_schemas,
                )
            )

    return operations
