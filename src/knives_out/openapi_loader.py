from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

from knives_out.models import (
    LoadedOperations,
    OperationSpec,
    ParameterSpec,
    PreflightWarning,
    ResponseSpec,
)

HTTP_METHODS = ["get", "post", "put", "patch", "delete", "head", "options"]
PARAMETER_LOCATION_ORDER = {"path": 0, "query": 1, "header": 2, "cookie": 3}


class RefResolutionError(ValueError):
    def __init__(self, *, code: str, ref: Any) -> None:
        self.code = code
        self.ref = ref
        if code == "unsupported_ref":
            message = f"Unsupported ref {ref!r}; only local '#/...' refs are supported."
        else:
            message = f"Unresolved local ref {ref!r}."
        super().__init__(message)


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


def _operation_id(route: str, method: str, operation: dict[str, Any]) -> str:
    operation_id = operation.get("operationId")
    if operation_id:
        return operation_id

    sanitized_path = route.strip("/").replace("/", "_").replace("{", "").replace("}", "") or "root"
    return f"{method}_{sanitized_path}"


def _warning_context(route: str, method: str, operation: dict[str, Any]) -> dict[str, str]:
    return {
        "operation_id": _operation_id(route, method, operation),
        "method": method.upper(),
        "path": route,
    }


def _add_warning(
    warnings: list[PreflightWarning],
    seen: set[tuple[str, str, str | None, str | None, str | None]],
    *,
    code: str,
    message: str,
    operation_id: str | None = None,
    method: str | None = None,
    path: str | None = None,
) -> None:
    key = (code, message, operation_id, method, path)
    if key in seen:
        return
    seen.add(key)
    warnings.append(
        PreflightWarning(
            code=code,
            message=message,
            operation_id=operation_id,
            method=method,
            path=path,
        )
    )


def _resolve_ref_target(ref: Any, root: dict[str, Any]) -> Any:
    if not isinstance(ref, str) or not ref.startswith("#/"):
        raise RefResolutionError(code="unsupported_ref", ref=ref)

    target: Any = root
    try:
        for part in ref[2:].split("/"):
            target = target[part]
    except (KeyError, IndexError, TypeError) as exc:
        raise RefResolutionError(code="unresolved_ref", ref=ref) from exc
    return target


def _record_ref_warning(
    error: RefResolutionError,
    warnings: list[PreflightWarning],
    seen: set[tuple[str, str, str | None, str | None, str | None]],
    *,
    operation_id: str,
    method: str,
    path: str,
) -> None:
    _add_warning(
        warnings,
        seen,
        code=error.code,
        message=str(error),
        operation_id=operation_id,
        method=method,
        path=path,
    )


def _lint_refs(
    node: Any,
    root: dict[str, Any],
    warnings: list[PreflightWarning],
    seen: set[tuple[str, str, str | None, str | None, str | None]],
    *,
    operation_id: str,
    method: str,
    path: str,
) -> None:
    if isinstance(node, dict):
        if "$ref" in node:
            try:
                _resolve_ref_target(node["$ref"], root)
            except RefResolutionError as exc:
                _record_ref_warning(
                    exc,
                    warnings,
                    seen,
                    operation_id=operation_id,
                    method=method,
                    path=path,
                )
        for value in node.values():
            _lint_refs(
                value,
                root,
                warnings,
                seen,
                operation_id=operation_id,
                method=method,
                path=path,
            )
        return

    if isinstance(node, list):
        for item in node:
            _lint_refs(
                item,
                root,
                warnings,
                seen,
                operation_id=operation_id,
                method=method,
                path=path,
            )


def resolve_refs(node: Any, root: dict[str, Any]) -> Any:
    if isinstance(node, dict):
        if "$ref" in node:
            target = _resolve_ref_target(node["$ref"], root)
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
    *,
    warnings: list[PreflightWarning],
    seen: set[tuple[str, str, str | None, str | None, str | None]],
    operation_id: str,
    method: str,
    path: str,
) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for parameter in path_parameters + operation_parameters:
        try:
            resolved = resolve_refs(parameter, root)
        except RefResolutionError as exc:
            _record_ref_warning(
                exc,
                warnings,
                seen,
                operation_id=operation_id,
                method=method,
                path=path,
            )
            continue
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
    *,
    warnings: list[PreflightWarning],
    seen: set[tuple[str, str, str | None, str | None, str | None]],
    operation_id: str,
    method: str,
    path: str,
) -> tuple[bool, dict[str, Any] | None, str | None]:
    request_body = operation.get("requestBody")
    if not request_body:
        return False, None, None

    try:
        resolved = resolve_refs(request_body, root)
    except RefResolutionError as exc:
        _record_ref_warning(
            exc,
            warnings,
            seen,
            operation_id=operation_id,
            method=method,
            path=path,
        )
        return False, None, None
    content = resolved.get("content", {})
    if not isinstance(content, dict) or not content:
        _add_warning(
            warnings,
            seen,
            code="missing_request_schema",
            message="Request body is declared but no usable schema was found.",
            operation_id=operation_id,
            method=method,
            path=path,
        )
        return bool(resolved.get("required", False)), None, None

    preferred_type, schema = _extract_content_schema(
        content,
        root,
        warnings=warnings,
        seen=seen,
        operation_id=operation_id,
        method=method,
        path=path,
    )
    if schema is None:
        _add_warning(
            warnings,
            seen,
            code="missing_request_schema",
            message="Request body is declared but no usable schema was found.",
            operation_id=operation_id,
            method=method,
            path=path,
        )
    return bool(resolved.get("required", False)), schema, preferred_type


def _extract_content_schema(
    content: dict[str, Any],
    root: dict[str, Any],
    *,
    warnings: list[PreflightWarning] | None = None,
    seen: set[tuple[str, str, str | None, str | None, str | None]] | None = None,
    operation_id: str | None = None,
    method: str | None = None,
    path: str | None = None,
) -> tuple[str | None, dict[str, Any] | None]:
    if "application/json" in content:
        preferred_type = "application/json"
    else:
        preferred_type = next(iter(content), None)

    if preferred_type is None:
        return None, None

    media_type = content.get(preferred_type, {})
    if not media_type.get("schema"):
        return preferred_type, None

    try:
        schema = resolve_refs(media_type.get("schema"), root)
    except RefResolutionError as exc:
        if warnings is not None and seen is not None and operation_id and method and path:
            _record_ref_warning(
                exc,
                warnings,
                seen,
                operation_id=operation_id,
                method=method,
                path=path,
            )
        return preferred_type, None
    return preferred_type, schema


def _extract_security(
    operation: dict[str, Any],
    root: dict[str, Any],
    *,
    warnings: list[PreflightWarning],
    seen: set[tuple[str, str, str | None, str | None, str | None]],
    operation_id: str,
    method: str,
    path: str,
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
    has_non_optional_requirement = False
    has_optional_requirement = False
    vague_security_reasons: set[str] = set()

    for requirement in security:
        if not isinstance(requirement, dict):
            continue
        if not requirement:
            has_optional_requirement = True
            continue
        has_non_optional_requirement = True
        for scheme_name in requirement:
            try:
                scheme = resolve_refs(schemes.get(scheme_name, {}), root)
            except RefResolutionError as exc:
                _record_ref_warning(
                    exc,
                    warnings,
                    seen,
                    operation_id=operation_id,
                    method=method,
                    path=path,
                )
                vague_security_reasons.add(str(scheme_name))
                continue
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
                else:
                    vague_security_reasons.add(str(scheme_name))
            else:
                vague_security_reasons.add(str(scheme_name))

    auth_required = has_non_optional_requirement and not has_optional_requirement
    if has_non_optional_requirement and vague_security_reasons:
        scheme_list = ", ".join(sorted(vague_security_reasons))
        _add_warning(
            warnings,
            seen,
            code="vague_security",
            message=(
                f"Security requirements include unsupported or ambiguous schemes: {scheme_list}."
            ),
            operation_id=operation_id,
            method=method,
            path=path,
        )
    return auth_required, sorted(header_names), sorted(query_names)


def _extract_response_schemas(
    operation: dict[str, Any],
    root: dict[str, Any],
    *,
    warnings: list[PreflightWarning],
    seen: set[tuple[str, str, str | None, str | None, str | None]],
    operation_id: str,
    method: str,
    path: str,
) -> dict[str, ResponseSpec]:
    responses = operation.get("responses", {})
    if not isinstance(responses, dict):
        return {}

    extracted: dict[str, ResponseSpec] = {}
    for status_code, response in responses.items():
        try:
            resolved = resolve_refs(response, root)
        except RefResolutionError as exc:
            _record_ref_warning(
                exc,
                warnings,
                seen,
                operation_id=operation_id,
                method=method,
                path=path,
            )
            extracted[str(status_code)] = ResponseSpec()
            continue
        content = resolved.get("content", {})
        if not isinstance(content, dict) or not content:
            extracted[str(status_code)] = ResponseSpec()
            continue

        content_type, schema = _extract_content_schema(
            content,
            root,
            warnings=warnings,
            seen=seen,
            operation_id=operation_id,
            method=method,
            path=path,
        )
        extracted[str(status_code)] = ResponseSpec(
            content_type=content_type,
            schema_def=schema,
        )

    return extracted


def load_operations_with_warnings(path: str | Path) -> LoadedOperations:
    document = load_openapi_document(path)
    operations: list[OperationSpec] = []
    warnings: list[PreflightWarning] = []
    seen_warnings: set[tuple[str, str, str | None, str | None, str | None]] = set()

    for route, path_item in document.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue

        path_parameters = path_item.get("parameters", [])
        for method in HTTP_METHODS:
            operation = path_item.get(method)
            if not operation:
                continue

            context = _warning_context(route, method, operation)
            _lint_refs(
                {
                    "path_parameters": path_parameters,
                    "operation": operation,
                },
                document,
                warnings,
                seen_warnings,
                operation_id=context["operation_id"],
                method=context["method"],
                path=context["path"],
            )

            operation_parameters = operation.get("parameters", [])
            merged_parameters = _merge_parameters(
                document,
                path_parameters,
                operation_parameters,
                warnings=warnings,
                seen=seen_warnings,
                operation_id=context["operation_id"],
                method=context["method"],
                path=context["path"],
            )
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
            ) = _extract_request_body(
                operation,
                document,
                warnings=warnings,
                seen=seen_warnings,
                operation_id=context["operation_id"],
                method=context["method"],
                path=context["path"],
            )
            auth_required, auth_header_names, auth_query_names = _extract_security(
                operation,
                document,
                warnings=warnings,
                seen=seen_warnings,
                operation_id=context["operation_id"],
                method=context["method"],
                path=context["path"],
            )
            response_schemas = _extract_response_schemas(
                operation,
                document,
                warnings=warnings,
                seen=seen_warnings,
                operation_id=context["operation_id"],
                method=context["method"],
                path=context["path"],
            )

            operations.append(
                OperationSpec(
                    operation_id=context["operation_id"],
                    method=context["method"],
                    path=route,
                    summary=operation.get("summary") or operation.get("description"),
                    tags=[tag for tag in operation.get("tags", []) if isinstance(tag, str)],
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

    return LoadedOperations(operations=operations, warnings=warnings)


def load_operations(path: str | Path) -> list[OperationSpec]:
    return load_operations_with_warnings(path).operations
