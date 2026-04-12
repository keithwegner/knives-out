from __future__ import annotations

import json
from textwrap import dedent

from graphql import build_schema
from graphql.utilities import introspection_from_schema

from knives_out.graphql_loader import load_graphql_operations
from knives_out.spec_loader import is_graphql_schema_path, load_operations_with_warnings


def _graphql_schema_text() -> str:
    return dedent(
        """
        interface Node {
          id: ID!
        }

        type Query {
          book(id: ID!): Book
          books(limit: Int, genre: Genre): [Book!]!
          node(id: ID!): Node
        }

        type Mutation {
          createBook(input: CreateBookInput!): Book!
        }

        type Book implements Node {
          id: ID!
          title: String!
          genre: Genre!
        }

        input CreateBookInput {
          title: String!
          genre: Genre!
          rating: Int
        }

        enum Genre {
          FICTION
          NONFICTION
        }
        """
    ).strip()


def test_load_graphql_operations_from_sdl(tmp_path) -> None:
    schema_path = tmp_path / "library.graphql"
    schema_path.write_text(_graphql_schema_text(), encoding="utf-8")

    operations = load_graphql_operations(schema_path, endpoint="/api/graphql")

    assert [operation.operation_id for operation in operations] == [
        "book",
        "books",
        "node",
        "createBook",
    ]

    book = operations[0]
    assert book.protocol == "graphql"
    assert book.graphql_operation_type == "query"
    assert book.method == "POST"
    assert book.path == "/api/graphql"
    assert book.tags == ["graphql", "query"]
    assert (
        book.graphql_document
        == "query Book($id: ID!) { book(id: $id) { __typename id title genre } }"
    )
    assert book.graphql_root_field_name == "book"
    assert book.graphql_output_shape is not None
    assert book.graphql_output_shape.kind == "object"
    assert sorted(book.graphql_output_shape.fields) == ["__typename", "genre", "id", "title"]
    assert book.graphql_variables_schema == {
        "type": "object",
        "properties": {"id": {"type": "string"}},
        "required": ["id"],
    }

    create_book = operations[-1]
    assert create_book.graphql_operation_type == "mutation"
    assert create_book.graphql_variables_schema == {
        "type": "object",
        "properties": {
            "input": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "genre": {"type": "string", "enum": ["FICTION", "NONFICTION"]},
                    "rating": {"type": "integer"},
                },
                "required": ["title", "genre"],
            }
        },
        "required": ["input"],
    }
    assert create_book.graphql_output_shape is not None
    assert create_book.graphql_output_shape.fields["title"].type_name == "String"

    node = next(operation for operation in operations if operation.operation_id == "node")
    assert node.graphql_output_shape is not None
    assert node.graphql_output_shape.kind == "interface"
    assert "Book" in node.graphql_output_shape.possible_types


def test_spec_loader_detects_graphql_introspection_json(tmp_path) -> None:
    schema = build_schema(_graphql_schema_text())
    introspection_path = tmp_path / "library-introspection.json"
    introspection_path.write_text(
        json.dumps({"data": introspection_from_schema(schema)}),
        encoding="utf-8",
    )

    loaded = load_operations_with_warnings(introspection_path)

    assert is_graphql_schema_path(introspection_path) is True
    assert loaded.warnings == []
    assert {operation.operation_id for operation in loaded.operations} == {
        "book",
        "books",
        "node",
        "createBook",
    }


def test_load_graphql_operations_detects_federation_hints(tmp_path) -> None:
    schema_path = tmp_path / "federated.graphql"
    schema_path.write_text(
        dedent(
            """
            directive @key(fields: String!) repeatable on OBJECT | INTERFACE

            type Query {
              _service: String
              book(id: ID!): Book
            }

            type Book @key(fields: "id") {
              id: ID!
              title: String!
            }
            """
        ).strip(),
        encoding="utf-8",
    )

    operations = load_graphql_operations(schema_path)
    book = next(operation for operation in operations if operation.operation_id == "book")

    assert book.graphql_federated is True
    assert book.graphql_output_shape is not None
    assert book.graphql_output_shape.federated_entity is True
    assert book.graphql_entity_types == ["Book"]
