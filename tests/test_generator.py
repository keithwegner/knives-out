from pathlib import Path
from textwrap import dedent

from knives_out.generator import generate_attack_suite, sample_value
from knives_out.models import WorkflowAttackCase
from knives_out.openapi_loader import load_operations

EXAMPLE_SPEC = Path(__file__).resolve().parents[1] / "examples" / "openapi" / "petstore.yaml"


def test_load_operations_extracts_core_operation_shapes() -> None:
    operations = load_operations(EXAMPLE_SPEC)

    assert len(operations) == 3

    create_pet = next(
        operation for operation in operations if operation.operation_id == "createPet"
    )
    assert create_pet.method == "POST"
    assert create_pet.request_body_required is True
    assert create_pet.auth_required is True
    assert create_pet.auth_header_names == ["Authorization"]
    assert create_pet.response_schemas["201"].content_type == "application/json"
    assert create_pet.response_schemas["201"].schema_def == {
        "allOf": [
            {
                "type": "object",
                "required": ["name", "species"],
                "properties": {
                    "name": {"type": "string"},
                    "species": {
                        "type": "string",
                        "enum": ["dog", "cat", "bird"],
                    },
                    "age": {"type": "integer"},
                },
            },
            {
                "type": "object",
                "required": ["id"],
                "properties": {
                    "id": {"type": "integer"},
                },
            },
        ]
    }


def test_generate_attack_suite_contains_expected_attack_types() -> None:
    operations = load_operations(EXAMPLE_SPEC)
    suite = generate_attack_suite(operations, source=str(EXAMPLE_SPEC))

    create_pet_kinds = {
        attack.kind for attack in suite.attacks if attack.operation_id == "createPet"
    }
    assert "missing_request_body" in create_pet_kinds
    assert "malformed_json_body" in create_pet_kinds
    assert "missing_auth" in create_pet_kinds
    assert "missing_required_param" in create_pet_kinds

    create_pet_attacks = [attack for attack in suite.attacks if attack.operation_id == "createPet"]
    assert create_pet_attacks
    assert all(
        attack.response_schemas["201"].content_type == "application/json"
        for attack in create_pet_attacks
    )


def test_sample_value_preserves_nested_required_fields() -> None:
    schema = {
        "type": "object",
        "required": ["profile"],
        "properties": {
            "profile": {
                "type": "object",
                "required": ["name", "contact"],
                "properties": {
                    "name": {"type": "string"},
                    "contact": {
                        "type": "object",
                        "required": ["email"],
                        "properties": {
                            "email": {"type": "string", "format": "email"},
                            "phone": {"type": "string"},
                        },
                    },
                    "nickname": {"type": "string"},
                },
            },
            "ignored": {"type": "string"},
        },
    }

    assert sample_value(schema) == {
        "profile": {
            "name": "example",
            "contact": {
                "email": "person@example.com",
            },
        }
    }


def test_sample_value_uses_one_representative_property_for_optional_objects() -> None:
    schema = {
        "type": "object",
        "properties": {
            "id": {"type": "integer"},
            "name": {"type": "string"},
        },
    }

    assert sample_value(schema) == {"id": 1}


def test_sample_value_preserves_array_item_shapes_past_depth_limit() -> None:
    schema = {
        "type": "object",
        "required": ["outer"],
        "properties": {
            "outer": {
                "type": "object",
                "required": ["items"],
                "properties": {
                    "items": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["children"],
                            "properties": {
                                "children": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "required": ["name"],
                                        "properties": {
                                            "name": {"type": "string"},
                                        },
                                    },
                                }
                            },
                        },
                    }
                },
            }
        },
    }

    assert sample_value(schema) == {
        "outer": {
            "items": [
                {
                    "children": [
                        {
                            "name": "example",
                        }
                    ]
                }
            ]
        }
    }


def test_generate_missing_auth_attacks_target_only_api_key_credentials(tmp_path) -> None:
    spec = tmp_path / "api-key-attacks.yaml"
    spec.write_text(
        dedent(
            """
            openapi: 3.0.3
            info:
              title: API key attack test
              version: 1.0.0
            components:
              securitySchemes:
                headerKey:
                  type: apiKey
                  in: header
                  name: X-API-Key
                queryKey:
                  type: apiKey
                  in: query
                  name: api_key
            paths:
              /header-auth:
                get:
                  operationId: headerAuth
                  security:
                    - headerKey: []
                  parameters:
                    - name: X-Tenant
                      in: header
                      required: true
                      schema:
                        type: string
              /query-auth:
                get:
                  operationId: queryAuth
                  security:
                    - queryKey: []
                  parameters:
                    - name: limit
                      in: query
                      required: true
                      schema:
                        type: integer
            """
        ),
        encoding="utf-8",
    )

    operations = load_operations(spec)
    suite = generate_attack_suite(operations, source=str(spec))

    header_attack = next(
        attack
        for attack in suite.attacks
        if attack.operation_id == "headerAuth" and attack.kind == "missing_auth"
    )
    assert header_attack.headers == {"X-Tenant": "example"}
    assert header_attack.omit_header_names == ["X-API-Key"]
    assert header_attack.omit_query_names == []

    query_attack = next(
        attack
        for attack in suite.attacks
        if attack.operation_id == "queryAuth" and attack.kind == "missing_auth"
    )
    assert query_attack.query == {"limit": 1}
    assert query_attack.omit_header_names == []
    assert query_attack.omit_query_names == ["api_key"]


def test_generate_attack_suite_keeps_request_only_default() -> None:
    operations = load_operations(EXAMPLE_SPEC)

    suite = generate_attack_suite(operations, source=str(EXAMPLE_SPEC))

    assert suite.attacks
    assert all(attack.type == "request" for attack in suite.attacks)


def test_generate_attack_suite_can_emit_built_in_workflows() -> None:
    operations = load_operations(EXAMPLE_SPEC)

    suite = generate_attack_suite(
        operations,
        source=str(EXAMPLE_SPEC),
        auto_workflows=True,
    )

    workflows = [attack for attack in suite.attacks if isinstance(attack, WorkflowAttackCase)]
    assert workflows
    get_pet_workflow = next(workflow for workflow in workflows if workflow.operation_id == "getPet")
    assert get_pet_workflow.kind == "wrong_type_param"
    assert get_pet_workflow.setup_steps[0].operation_id == "listPets"
    assert get_pet_workflow.setup_steps[0].extracts[0].json_pointer == "/0/id"
    assert get_pet_workflow.terminal_attack.path_params["petId"] == "{{id}}"


def test_generate_attack_suite_skips_ambiguous_workflow_producers(tmp_path: Path) -> None:
    spec = tmp_path / "ambiguous-workflows.yaml"
    spec.write_text(
        dedent(
            """
            openapi: 3.0.3
            info:
              title: Ambiguous workflow spec
              version: 1.0.0
            paths:
              /pets:
                get:
                  operationId: listPets
                  responses:
                    '200':
                      description: Pets
                      content:
                        application/json:
                          schema:
                            type: array
                            items:
                              type: object
                              properties:
                                id:
                                  type: integer
              /archived-pets:
                get:
                  operationId: listArchivedPets
                  responses:
                    '200':
                      description: Archived pets
                      content:
                        application/json:
                          schema:
                            type: array
                            items:
                              type: object
                              properties:
                                id:
                                  type: integer
              /pets/{petId}:
                get:
                  operationId: getPet
                  parameters:
                    - name: petId
                      in: path
                      required: true
                      schema:
                        type: integer
                  responses:
                    '200':
                      description: Pet
                      content:
                        application/json:
                          schema:
                            type: object
                            properties:
                              id:
                                type: integer
            """
        ),
        encoding="utf-8",
    )

    operations = load_operations(spec)
    suite = generate_attack_suite(operations, source=str(spec), auto_workflows=True)

    assert all(attack.type == "request" for attack in suite.attacks)
