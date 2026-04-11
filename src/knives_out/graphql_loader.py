from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from graphql import (
    GraphQLEnumType,
    GraphQLInputObjectType,
    GraphQLInterfaceType,
    GraphQLList,
    GraphQLNonNull,
    GraphQLObjectType,
    GraphQLScalarType,
    GraphQLSchema,
    GraphQLUnionType,
    build_client_schema,
    build_schema,
    get_named_type,
)

from knives_out.models import LoadedOperations, OperationSpec, ParameterSpec


def _load_graphql_schema(path: str | Path) -> GraphQLSchema:
    schema_path = Path(path)
    raw = schema_path.read_text(encoding="utf-8")

    if schema_path.suffix.lower() == ".json":
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("GraphQL introspection JSON did not parse to an object.")
        if "__schema" in payload:
            return build_client_schema(payload)
        data = payload.get("data")
        if isinstance(data, dict) and "__schema" in data:
            return build_client_schema(data)
        raise ValueError("GraphQL introspection JSON is missing '__schema'.")

    return build_schema(raw)


def _json_schema_for_input_type(type_: Any) -> tuple[dict[str, Any], bool]:
    if isinstance(type_, GraphQLNonNull):
        schema, _ = _json_schema_for_input_type(type_.of_type)
        return schema, True

    if isinstance(type_, GraphQLList):
        item_schema, _ = _json_schema_for_input_type(type_.of_type)
        return {"type": "array", "items": item_schema}, False

    named_type = get_named_type(type_)
    if isinstance(named_type, GraphQLScalarType):
        scalar_name = named_type.name
        if scalar_name == "Int":
            return {"type": "integer"}, False
        if scalar_name == "Float":
            return {"type": "number"}, False
        if scalar_name == "Boolean":
            return {"type": "boolean"}, False
        return {"type": "string"}, False

    if isinstance(named_type, GraphQLEnumType):
        return {"type": "string", "enum": list(named_type.values)}, False

    if isinstance(named_type, GraphQLInputObjectType):
        properties: dict[str, Any] = {}
        required: list[str] = []
        for field_name, field in named_type.fields.items():
            field_schema, field_required = _json_schema_for_input_type(field.type)
            properties[field_name] = field_schema
            if field_required:
                required.append(field_name)
        schema: dict[str, Any] = {"type": "object", "properties": properties}
        if required:
            schema["required"] = required
        return schema, False

    return {"type": "string"}, False


def _selection_set_for_output_type(type_: Any) -> str:
    named_type = get_named_type(type_)
    if isinstance(named_type, (GraphQLObjectType, GraphQLInterfaceType, GraphQLUnionType)):
        return "{ __typename }"
    return ""


def _graphql_document(
    *,
    operation_type: str,
    field_name: str,
    field: Any,
) -> str:
    variable_definitions: list[str] = []
    argument_bindings: list[str] = []
    for argument_name, argument in field.args.items():
        variable_definitions.append(f"${argument_name}: {argument.type}")
        argument_bindings.append(f"{argument_name}: ${argument_name}")

    operation_name = field_name[:1].upper() + field_name[1:]
    definitions = f"({', '.join(variable_definitions)})" if variable_definitions else ""
    bindings = f"({', '.join(argument_bindings)})" if argument_bindings else ""
    selection_set = _selection_set_for_output_type(field.type)
    selection = f" {selection_set}" if selection_set else ""
    return f"{operation_type} {operation_name}{definitions} {{ {field_name}{bindings}{selection} }}"


def _variables_schema(field: Any) -> dict[str, Any]:
    properties: dict[str, Any] = {}
    required: list[str] = []
    for argument_name, argument in field.args.items():
        argument_schema, argument_required = _json_schema_for_input_type(argument.type)
        properties[argument_name] = argument_schema
        if argument_required:
            required.append(argument_name)

    schema: dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return schema


def _request_body_schema(document: str, variables_schema: dict[str, Any]) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "query": {"type": "string", "default": document},
            "variables": variables_schema,
        },
        "required": ["query"],
    }
    if variables_schema.get("properties"):
        schema["required"] = ["query", "variables"]
    return schema


def _operation_specs(
    *,
    root: GraphQLObjectType | None,
    operation_type: str,
    endpoint: str,
) -> list[OperationSpec]:
    if root is None:
        return []

    operations: list[OperationSpec] = []
    for field_name, field in root.fields.items():
        variables_schema = _variables_schema(field)
        document = _graphql_document(
            operation_type=operation_type,
            field_name=field_name,
            field=field,
        )
        operations.append(
            OperationSpec(
                operation_id=field_name,
                method="POST",
                path=endpoint,
                protocol="graphql",
                summary=getattr(field, "description", None),
                tags=["graphql", operation_type],
                parameters=[
                    ParameterSpec(
                        name=argument_name,
                        location="graphql-variable",
                        required=isinstance(argument.type, GraphQLNonNull),
                        schema_def=_json_schema_for_input_type(argument.type)[0],
                    )
                    for argument_name, argument in field.args.items()
                ],
                request_body_required=True,
                request_body_schema=_request_body_schema(document, variables_schema),
                request_body_content_type="application/json",
                graphql_operation_type=operation_type,
                graphql_document=document,
                graphql_variables_schema=variables_schema,
            )
        )

    return operations


def load_graphql_operations_with_warnings(
    path: str | Path,
    *,
    endpoint: str = "/graphql",
) -> LoadedOperations:
    schema = _load_graphql_schema(path)
    operations = [
        *_operation_specs(root=schema.query_type, operation_type="query", endpoint=endpoint),
        *_operation_specs(root=schema.mutation_type, operation_type="mutation", endpoint=endpoint),
    ]
    return LoadedOperations(source_kind="graphql", operations=operations, warnings=[])


def load_graphql_operations(path: str | Path, *, endpoint: str = "/graphql") -> list[OperationSpec]:
    return load_graphql_operations_with_warnings(path, endpoint=endpoint).operations
