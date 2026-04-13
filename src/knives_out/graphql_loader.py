from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from graphql import (
    GraphQLEnumType,
    GraphQLField,
    GraphQLInputObjectType,
    GraphQLInterfaceType,
    GraphQLList,
    GraphQLNonNull,
    GraphQLObjectType,
    GraphQLScalarType,
    GraphQLSchema,
    GraphQLUnionType,
    Undefined,
    build_client_schema,
    build_schema,
    get_named_type,
)

from knives_out.models import (
    GraphQLOutputShape,
    LoadedOperations,
    OperationSpec,
    ParameterSpec,
    ResponseSpec,
)


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


def _nullable_schema(schema: dict[str, Any], *, nullable: bool) -> dict[str, Any]:
    if not nullable:
        return schema
    return {**schema, "nullable": True}


def _json_schema_for_output_type(type_: Any, *, schema: GraphQLSchema) -> dict[str, Any]:
    if isinstance(type_, GraphQLNonNull):
        output_schema = dict(_json_schema_for_output_type(type_.of_type, schema=schema))
        output_schema.pop("nullable", None)
        return output_schema

    named_type = get_named_type(type_)
    nullable = not isinstance(type_, GraphQLNonNull)

    if isinstance(type_, GraphQLList):
        item_schema = _json_schema_for_output_type(type_.of_type, schema=schema)
        return _nullable_schema({"type": "array", "items": item_schema}, nullable=nullable)

    if isinstance(named_type, GraphQLScalarType):
        scalar_name = named_type.name
        if scalar_name == "Int":
            return _nullable_schema({"type": "integer"}, nullable=nullable)
        if scalar_name == "Float":
            return _nullable_schema({"type": "number"}, nullable=nullable)
        if scalar_name == "Boolean":
            return _nullable_schema({"type": "boolean"}, nullable=nullable)
        return _nullable_schema({"type": "string"}, nullable=nullable)

    if isinstance(named_type, GraphQLEnumType):
        return _nullable_schema(
            {"type": "string", "enum": list(named_type.values)},
            nullable=nullable,
        )

    if isinstance(named_type, GraphQLObjectType):
        return _nullable_schema(
            {
                "type": "object",
                "properties": {
                    "__typename": {
                        "type": "string",
                        "const": named_type.name,
                    }
                },
                "required": ["__typename"],
            },
            nullable=nullable,
        )

    if isinstance(named_type, (GraphQLInterfaceType, GraphQLUnionType)):
        possible_types = [possible.name for possible in schema.get_possible_types(named_type)]
        typename_schema: dict[str, Any] = {"type": "string"}
        if possible_types:
            typename_schema["enum"] = possible_types
        return _nullable_schema(
            {
                "type": "object",
                "properties": {
                    "__typename": typename_schema,
                },
                "required": ["__typename"],
            },
            nullable=nullable,
        )

    return _nullable_schema({"type": "string"}, nullable=nullable)


def _required_argument(argument: Any) -> bool:
    return isinstance(argument.type, GraphQLNonNull) and argument.default_value is Undefined


def _selectable_field(field: GraphQLField) -> bool:
    return not any(_required_argument(argument) for argument in field.args.values())


def _federated_entity_type(type_: Any) -> bool:
    directives = getattr(getattr(type_, "ast_node", None), "directives", None) or []
    return any(getattr(directive.name, "value", None) == "key" for directive in directives)


def _graphql_shape(
    type_: Any,
    *,
    schema: GraphQLSchema,
    depth: int = 0,
    seen: tuple[str, ...] = (),
    federated_schema: bool = False,
) -> tuple[GraphQLOutputShape, str]:
    nullable = not isinstance(type_, GraphQLNonNull)
    inner_type = type_.of_type if isinstance(type_, GraphQLNonNull) else type_

    if isinstance(inner_type, GraphQLList):
        item_shape, item_selection = _graphql_shape(
            inner_type.of_type,
            schema=schema,
            depth=depth,
            seen=seen,
            federated_schema=federated_schema,
        )
        return (
            GraphQLOutputShape(
                kind="list",
                type_name=str(get_named_type(inner_type)),
                nullable=nullable,
                item_shape=item_shape,
                federation_hint=(
                    "Selection crosses a federated list boundary."
                    if federated_schema and item_shape.kind in {"object", "interface", "union"}
                    else None
                ),
            ),
            item_selection,
        )

    named_type = get_named_type(inner_type)
    if isinstance(named_type, GraphQLScalarType):
        return (
            GraphQLOutputShape(
                kind="scalar",
                type_name=named_type.name,
                nullable=nullable,
            ),
            "",
        )

    if isinstance(named_type, GraphQLEnumType):
        return (
            GraphQLOutputShape(
                kind="enum",
                type_name=named_type.name,
                nullable=nullable,
            ),
            "",
        )

    if isinstance(named_type, GraphQLObjectType):
        type_name = named_type.name
        if type_name in seen or depth >= 3:
            fields = {
                "__typename": GraphQLOutputShape(
                    kind="scalar",
                    type_name="String",
                    nullable=False,
                )
            }
            return (
                GraphQLOutputShape(
                    kind="object",
                    type_name=type_name,
                    nullable=nullable,
                    fields=fields,
                    federated_entity=federated_schema and _federated_entity_type(named_type),
                    federation_hint=(
                        f"Type '{type_name}' is revisited inside a federated schema."
                        if federated_schema
                        else None
                    ),
                ),
                "{ __typename }",
            )

        fields: dict[str, GraphQLOutputShape] = {
            "__typename": GraphQLOutputShape(
                kind="scalar",
                type_name="String",
                nullable=False,
            )
        }
        selections = ["__typename"]
        for field_name, field in named_type.fields.items():
            if field_name.startswith("__") or not _selectable_field(field):
                continue
            field_shape, field_selection = _graphql_shape(
                field.type,
                schema=schema,
                depth=depth + 1,
                seen=(*seen, type_name),
                federated_schema=federated_schema,
            )
            fields[field_name] = field_shape
            if field_selection:
                selections.append(f"{field_name} {field_selection}")
            else:
                selections.append(field_name)
        return (
            GraphQLOutputShape(
                kind="object",
                type_name=type_name,
                nullable=nullable,
                fields=fields,
                federated_entity=federated_schema and _federated_entity_type(named_type),
                federation_hint=(
                    f"Type '{type_name}' may resolve across federated entity boundaries."
                    if federated_schema and _federated_entity_type(named_type)
                    else None
                ),
            ),
            "{ " + " ".join(selections) + " }",
        )

    if isinstance(named_type, GraphQLInterfaceType):
        possible_types: dict[str, GraphQLOutputShape] = {}
        fragments: list[str] = ["__typename"]
        for possible_type in schema.get_possible_types(named_type):
            possible_shape, possible_selection = _graphql_shape(
                possible_type,
                schema=schema,
                depth=depth + 1,
                seen=(*seen, named_type.name),
                federated_schema=federated_schema,
            )
            possible_types[possible_type.name] = possible_shape
            fragments.append(f"... on {possible_type.name} {possible_selection}")
        return (
            GraphQLOutputShape(
                kind="interface",
                type_name=named_type.name,
                nullable=nullable,
                possible_types=possible_types,
                federation_hint=(
                    f"Interface '{named_type.name}' spans possible runtime types "
                    "in a federated schema."
                    if federated_schema
                    else None
                ),
            ),
            "{ " + " ".join(fragments) + " }",
        )

    if isinstance(named_type, GraphQLUnionType):
        possible_types = {}
        fragments = ["__typename"]
        for possible_type in named_type.types:
            possible_shape, possible_selection = _graphql_shape(
                possible_type,
                schema=schema,
                depth=depth + 1,
                seen=(*seen, named_type.name),
                federated_schema=federated_schema,
            )
            possible_types[possible_type.name] = possible_shape
            fragments.append(f"... on {possible_type.name} {possible_selection}")
        return (
            GraphQLOutputShape(
                kind="union",
                type_name=named_type.name,
                nullable=nullable,
                possible_types=possible_types,
                federation_hint=(
                    f"Union '{named_type.name}' crosses runtime type boundaries "
                    "in a federated schema."
                    if federated_schema
                    else None
                ),
            ),
            "{ " + " ".join(fragments) + " }",
        )

    return (
        GraphQLOutputShape(
            kind="scalar",
            type_name=str(named_type),
            nullable=nullable,
        ),
        "",
    )


def _graphql_document(
    *,
    operation_type: str,
    field_name: str,
    field: Any,
    schema: GraphQLSchema,
    federated_schema: bool,
) -> str:
    variable_definitions: list[str] = []
    argument_bindings: list[str] = []
    for argument_name, argument in field.args.items():
        variable_definitions.append(f"${argument_name}: {argument.type}")
        argument_bindings.append(f"{argument_name}: ${argument_name}")

    operation_name = field_name[:1].upper() + field_name[1:]
    definitions = f"({', '.join(variable_definitions)})" if variable_definitions else ""
    bindings = f"({', '.join(argument_bindings)})" if argument_bindings else ""
    _, selection_set = _graphql_shape(
        field.type,
        schema=schema,
        federated_schema=federated_schema,
    )
    selection = f" {selection_set}" if selection_set else ""
    return f"{operation_type} {operation_name}{definitions} {{ {field_name}{bindings}{selection} }}"


def _graphql_schema_is_federated(schema: GraphQLSchema) -> bool:
    query_fields = schema.query_type.fields if schema.query_type is not None else {}
    return "_service" in query_fields or "_entities" in query_fields or "_Entity" in schema.type_map


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


def _response_schema(field_name: str, field: Any, *, schema: GraphQLSchema) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "data": {
                "type": "object",
                "properties": {
                    field_name: _json_schema_for_output_type(field.type, schema=schema),
                },
                "required": [field_name],
            }
        },
        "required": ["data"],
    }


def _operation_specs(
    *,
    schema: GraphQLSchema,
    root: GraphQLObjectType | None,
    operation_type: str,
    endpoint: str,
) -> list[OperationSpec]:
    if root is None:
        return []

    federated_schema = _graphql_schema_is_federated(schema)
    operations: list[OperationSpec] = []
    for field_name, field in root.fields.items():
        variables_schema = _variables_schema(field)
        output_shape, _ = _graphql_shape(
            field.type,
            schema=schema,
            federated_schema=federated_schema,
        )
        document = _graphql_document(
            operation_type=operation_type,
            field_name=field_name,
            field=field,
            schema=schema,
            federated_schema=federated_schema,
        )
        entity_types = sorted(
            type_name
            for type_name, shape in output_shape.possible_types.items()
            if shape.federated_entity
        )
        if output_shape.federated_entity:
            entity_types.append(output_shape.type_name)
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
                response_schemas={
                    "200": ResponseSpec(
                        content_type="application/json",
                        schema_def=_response_schema(field_name, field, schema=schema),
                    )
                },
                graphql_operation_type=operation_type,
                graphql_document=document,
                graphql_variables_schema=variables_schema,
                graphql_root_field_name=field_name,
                graphql_output_shape=output_shape,
                graphql_federated=federated_schema,
                graphql_entity_types=sorted(set(entity_types)),
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
        *_operation_specs(
            schema=schema,
            root=schema.query_type,
            operation_type="query",
            endpoint=endpoint,
        ),
        *_operation_specs(
            schema=schema,
            root=schema.mutation_type,
            operation_type="mutation",
            endpoint=endpoint,
        ),
    ]
    return LoadedOperations(source_kind="graphql", operations=operations, warnings=[])


def load_graphql_operations(path: str | Path, *, endpoint: str = "/graphql") -> list[OperationSpec]:
    return load_graphql_operations_with_warnings(path, endpoint=endpoint).operations
