from textwrap import dedent

from knives_out.openapi_loader import load_operations


def test_load_operations_prefers_operation_level_parameter_overrides(tmp_path) -> None:
    spec = tmp_path / "override-spec.yaml"
    spec.write_text(
        dedent(
            """
            openapi: 3.0.3
            info:
              title: Override test
              version: 1.0.0
            paths:
              /pets/{petId}:
                parameters:
                  - name: X-Mode
                    in: header
                    required: true
                    schema:
                      type: string
                      enum: [path]
                  - name: petId
                    in: path
                    required: true
                    schema:
                      type: string
                  - name: expand
                    in: query
                    required: false
                    schema:
                      type: string
                get:
                  operationId: getPet
                  parameters:
                    - name: expand
                      in: query
                      required: true
                      schema:
                        type: integer
                    - name: alpha
                      in: query
                      required: false
                      schema:
                        type: boolean
                    - name: X-Mode
                      in: header
                      required: false
                      schema:
                        type: string
                        enum: [operation]
            """
        ),
        encoding="utf-8",
    )

    operations = load_operations(spec)

    assert len(operations) == 1
    operation = operations[0]
    parameters = {
        (parameter.location, parameter.name): parameter for parameter in operation.parameters
    }

    assert parameters[("path", "petId")].required is True
    assert parameters[("path", "petId")].schema_def["type"] == "string"

    assert parameters[("query", "expand")].required is True
    assert parameters[("query", "expand")].schema_def["type"] == "integer"

    assert parameters[("query", "alpha")].required is False
    assert parameters[("query", "alpha")].schema_def["type"] == "boolean"

    assert parameters[("header", "X-Mode")].required is False
    assert parameters[("header", "X-Mode")].schema_def["enum"] == ["operation"]


def test_load_operations_orders_parameters_deterministically(tmp_path) -> None:
    spec = tmp_path / "ordered-params.yaml"
    spec.write_text(
        dedent(
            """
            openapi: 3.0.3
            info:
              title: Ordering test
              version: 1.0.0
            paths:
              /pets/{petId}:
                parameters:
                  - name: zQuery
                    in: query
                    required: false
                    schema:
                      type: string
                  - name: petId
                    in: path
                    required: true
                    schema:
                      type: string
                get:
                  operationId: orderedPet
                  parameters:
                    - name: X-Mode
                      in: header
                      required: false
                      schema:
                        type: string
                    - name: aQuery
                      in: query
                      required: false
                      schema:
                        type: string
            """
        ),
        encoding="utf-8",
    )

    operations = load_operations(spec)

    assert len(operations) == 1
    operation = operations[0]

    assert [(parameter.location, parameter.name) for parameter in operation.parameters] == [
        ("path", "petId"),
        ("query", "aQuery"),
        ("query", "zQuery"),
        ("header", "X-Mode"),
    ]


def test_load_operations_extracts_response_schemas(tmp_path) -> None:
    spec = tmp_path / "response-schemas.yaml"
    spec.write_text(
        dedent(
            """
            openapi: 3.0.3
            info:
              title: Response schema test
              version: 1.0.0
            paths:
              /pets:
                get:
                  operationId: listPets
                  responses:
                    "200":
                      description: Pet list
                      content:
                        application/json:
                          schema:
                            type: array
                            items:
                              type: object
                              required: [id]
                              properties:
                                id:
                                  type: integer
                    default:
                      description: Error response
                      content:
                        application/json:
                          schema:
                            type: object
                            required: [error]
                            properties:
                              error:
                                type: string
            """
        ),
        encoding="utf-8",
    )

    operations = load_operations(spec)

    assert len(operations) == 1
    operation = operations[0]
    assert operation.response_schemas["200"].content_type == "application/json"
    assert operation.response_schemas["200"].schema_def == {
        "type": "array",
        "items": {
            "type": "object",
            "required": ["id"],
            "properties": {
                "id": {"type": "integer"},
            },
        },
    }
    assert operation.response_schemas["default"].schema_def == {
        "type": "object",
        "required": ["error"],
        "properties": {
            "error": {"type": "string"},
        },
    }
