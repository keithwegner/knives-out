from __future__ import annotations

from pathlib import Path

from knives_out.spec_loader import is_graphql_schema_path, is_learned_model_path


def test_is_learned_model_path_returns_false_for_invalid_json(tmp_path: Path) -> None:
    model_path = tmp_path / "model.json"
    model_path.write_text("{", encoding="utf-8")

    assert is_learned_model_path(model_path) is False


def test_is_graphql_schema_path_detects_top_level_introspection_json(tmp_path: Path) -> None:
    schema_path = tmp_path / "schema.json"
    schema_path.write_text('{"__schema": {}}', encoding="utf-8")

    assert is_graphql_schema_path(schema_path) is True


def test_is_graphql_schema_path_rejects_non_mapping_json(tmp_path: Path) -> None:
    schema_path = tmp_path / "schema.json"
    schema_path.write_text("[]", encoding="utf-8")

    assert is_graphql_schema_path(schema_path) is False
