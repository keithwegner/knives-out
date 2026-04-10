from pathlib import Path

from knives_out.generator import generate_attack_suite, sample_value
from knives_out.openapi_loader import load_operations

EXAMPLE_SPEC = Path(__file__).resolve().parents[1] / "examples" / "openapi" / "petstore.yaml"


def test_load_operations_extracts_core_operation_shapes() -> None:
    operations = load_operations(EXAMPLE_SPEC)

    assert len(operations) == 3

    create_pet = next(operation for operation in operations if operation.operation_id == "createPet")
    assert create_pet.method == "POST"
    assert create_pet.request_body_required is True
    assert create_pet.auth_required is True
    assert create_pet.auth_header_names == ["Authorization"]


def test_generate_attack_suite_contains_expected_attack_types() -> None:
    operations = load_operations(EXAMPLE_SPEC)
    suite = generate_attack_suite(operations, source=str(EXAMPLE_SPEC))

    create_pet_kinds = {attack.kind for attack in suite.attacks if attack.operation_id == "createPet"}
    assert "missing_request_body" in create_pet_kinds
    assert "malformed_json_body" in create_pet_kinds
    assert "missing_auth" in create_pet_kinds
    assert "missing_required_param" in create_pet_kinds


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
