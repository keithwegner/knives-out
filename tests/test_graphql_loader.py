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
          search(id: ID!): SearchResult
        }

        type Mutation {
          createBook(input: CreateBookInput!): Book!
        }

        type Book implements Node {
          id: ID!
          title: String!
          genre: Genre!
          author: Author
        }

        type Author {
          id: ID!
          name: String!
          favoriteBook: Book
        }

        type Magazine implements Node {
          id: ID!
          title: String!
          issue: Int!
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

        union SearchResult = Book | Magazine
        """
    ).strip()


def _graphql_subscription_schema_text() -> str:
    return dedent(
        """
        type Query {
          health: String!
        }

        type Subscription {
          bookEvents(id: ID!): Book!
        }

        type Book {
          id: ID!
          title: String!
          rating: Int
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
        "search",
        "createBook",
    ]

    book = operations[0]
    assert book.protocol == "graphql"
    assert book.graphql_operation_type == "query"
    assert book.method == "POST"
    assert book.path == "/api/graphql"
    assert book.tags == ["graphql", "query"]
    assert book.graphql_document == (
        "query Book($id: ID!) { "
        "book(id: $id) { "
        "__typename id title genre author { __typename id name favoriteBook { __typename } } "
        "} }"
    )
    assert book.graphql_root_field_name == "book"
    assert book.graphql_output_shape is not None
    assert book.graphql_output_shape.kind == "object"
    assert sorted(book.graphql_output_shape.fields) == [
        "__typename",
        "author",
        "genre",
        "id",
        "title",
    ]
    assert sorted(book.graphql_output_shape.fields["author"].fields["favoriteBook"].fields) == [
        "__typename"
    ]
    assert book.graphql_variables_schema == {
        "type": "object",
        "properties": {"id": {"type": "string"}},
        "required": ["id"],
    }
    assert book.response_schemas["200"].content_type == "application/json"
    book_schema = book.response_schemas["200"].schema_def["properties"]["data"]["properties"][
        "book"
    ]
    assert book_schema["required"] == ["__typename", "id", "title", "genre", "author"]
    assert book_schema["properties"]["author"]["required"] == [
        "__typename",
        "id",
        "name",
        "favoriteBook",
    ]
    assert book_schema["properties"]["author"]["properties"]["favoriteBook"] == {
        "type": "object",
        "properties": {
            "__typename": {"type": "string", "const": "Book"},
        },
        "required": ["__typename"],
        "nullable": True,
    }
    assert book_schema["properties"]["author"]["nullable"] is True

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
    create_book_schema = create_book.response_schemas["200"].schema_def["properties"]["data"][
        "properties"
    ]["createBook"]
    assert create_book_schema["required"] == ["__typename", "id", "title", "genre", "author"]
    assert create_book_schema["properties"]["author"]["properties"]["name"] == {"type": "string"}

    node = next(operation for operation in operations if operation.operation_id == "node")
    assert node.graphql_output_shape is not None
    assert node.graphql_output_shape.kind == "interface"
    assert sorted(node.graphql_output_shape.possible_types) == ["Book", "Magazine"]
    assert "... on Book { __typename id title genre author" in (node.graphql_document or "")
    assert "... on Magazine { __typename id title issue }" in (node.graphql_document or "")
    node_schema = node.response_schemas["200"].schema_def["properties"]["data"]["properties"][
        "node"
    ]
    assert len(node_schema["oneOf"]) == 2
    book_variant = next(
        variant
        for variant in node_schema["oneOf"]
        if variant["properties"]["__typename"]["const"] == "Book"
    )
    magazine_variant = next(
        variant
        for variant in node_schema["oneOf"]
        if variant["properties"]["__typename"]["const"] == "Magazine"
    )
    assert "author" in book_variant["properties"]
    assert "issue" in magazine_variant["properties"]

    search = next(operation for operation in operations if operation.operation_id == "search")
    assert search.graphql_output_shape is not None
    assert search.graphql_output_shape.kind == "union"
    assert "... on Book { __typename id title genre author" in (search.graphql_document or "")
    assert "... on Magazine { __typename id title issue }" in (search.graphql_document or "")
    search_schema = search.response_schemas["200"].schema_def["properties"]["data"]["properties"][
        "search"
    ]
    assert len(search_schema["oneOf"]) == 2
    assert {variant["properties"]["__typename"]["const"] for variant in search_schema["oneOf"]} == {
        "Book",
        "Magazine",
    }


def test_load_graphql_operations_includes_subscription_roots(tmp_path) -> None:
    schema_path = tmp_path / "subscriptions.graphql"
    schema_path.write_text(_graphql_subscription_schema_text(), encoding="utf-8")

    operations = load_graphql_operations(schema_path, endpoint="/api/graphql")

    subscription = next(
        operation for operation in operations if operation.operation_id == "bookEvents"
    )

    assert subscription.graphql_operation_type == "subscription"
    assert subscription.method == "SUBSCRIBE"
    assert subscription.tags == ["graphql", "subscription"]
    assert subscription.graphql_document == (
        "subscription BookEvents($id: ID!) { bookEvents(id: $id) { __typename id title rating } }"
    )
    assert subscription.graphql_variables_schema == {
        "type": "object",
        "properties": {"id": {"type": "string"}},
        "required": ["id"],
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
        "node",
        "search",
        "createBook",
    }


def test_spec_loader_detects_graphql_subscription_introspection_json(tmp_path) -> None:
    schema = build_schema(_graphql_subscription_schema_text())
    introspection_path = tmp_path / "subscription-introspection.json"
    introspection_path.write_text(
        json.dumps({"data": introspection_from_schema(schema)}),
        encoding="utf-8",
    )

    loaded = load_operations_with_warnings(introspection_path)

    assert loaded.warnings == []
    assert {operation.operation_id for operation in loaded.operations} == {
        "health",
        "bookEvents",
    }
    subscription = next(
        operation for operation in loaded.operations if operation.operation_id == "bookEvents"
    )
    assert subscription.graphql_operation_type == "subscription"
    assert subscription.method == "SUBSCRIBE"


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
