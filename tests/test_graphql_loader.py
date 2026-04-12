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
        type Query {
          book(id: ID!): Book
          books(limit: Int, genre: Genre): [Book!]!
        }

        type Mutation {
          createBook(input: CreateBookInput!): Book!
        }

        type Book {
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
        "createBook",
    ]

    book = operations[0]
    assert book.protocol == "graphql"
    assert book.graphql_operation_type == "query"
    assert book.method == "POST"
    assert book.path == "/api/graphql"
    assert book.tags == ["graphql", "query"]
    assert book.graphql_document == "query Book($id: ID!) { book(id: $id) { __typename } }"
    assert book.graphql_variables_schema == {
        "type": "object",
        "properties": {"id": {"type": "string"}},
        "required": ["id"],
    }
    assert book.response_schemas["200"].content_type == "application/json"
    assert book.response_schemas["200"].schema_def == {
        "type": "object",
        "properties": {
            "data": {
                "type": "object",
                "properties": {
                    "book": {
                        "type": "object",
                        "properties": {
                            "__typename": {"type": "string", "const": "Book"},
                        },
                        "required": ["__typename"],
                        "nullable": True,
                    }
                },
                "required": ["book"],
            }
        },
        "required": ["data"],
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
    assert create_book.response_schemas["200"].schema_def == {
        "type": "object",
        "properties": {
            "data": {
                "type": "object",
                "properties": {
                    "createBook": {
                        "type": "object",
                        "properties": {
                            "__typename": {"type": "string", "const": "Book"},
                        },
                        "required": ["__typename"],
                    }
                },
                "required": ["createBook"],
            }
        },
        "required": ["data"],
    }


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
        "createBook",
    }
