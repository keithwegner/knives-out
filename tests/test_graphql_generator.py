from __future__ import annotations

from pathlib import Path

from knives_out.generator import generate_attack_suite
from knives_out.spec_loader import load_operations

GRAPHQL_SPEC = Path(__file__).resolve().parents[1] / "examples" / "graphql" / "library.graphql"


def test_generate_graphql_attack_suite_emits_variable_mutations() -> None:
    suite = generate_attack_suite(
        load_operations(GRAPHQL_SPEC),
        source=str(GRAPHQL_SPEC),
    )

    create_book_attacks = [
        attack for attack in suite.attacks if attack.operation_id == "createBook"
    ]
    kinds = {attack.kind for attack in create_book_attacks}

    assert "missing_request_body" in kinds
    assert "malformed_json_body" in kinds
    assert "wrong_type_variable" in kinds
    assert "missing_required_variable" in kinds
    assert "invalid_enum" in kinds

    wrong_type_attack = next(
        attack for attack in create_book_attacks if attack.kind == "wrong_type_variable"
    )
    assert wrong_type_attack.path == "/graphql"
    assert wrong_type_attack.protocol == "graphql"
    assert wrong_type_attack.expected_outcomes == ["graphql_error", "4xx"]
    assert wrong_type_attack.body_json["query"].startswith("mutation CreateBook")
    assert wrong_type_attack.graphql_root_field_name == "createBook"
    assert wrong_type_attack.graphql_output_shape is not None
    assert "__typename" in wrong_type_attack.graphql_output_shape.fields
    assert "variables" in wrong_type_attack.body_json
