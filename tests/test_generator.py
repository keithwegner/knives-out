from pathlib import Path

from knives_out.generator import generate_attack_suite
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
