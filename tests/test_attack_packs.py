from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from knives_out.attack_packs import (
    ENTRY_POINT_GROUP,
    load_attack_packs,
    load_entry_point_attack_packs,
    load_module_attack_packs,
    make_attack_pack,
)
from knives_out.generator import generate_attack_suite
from knives_out.models import AttackCase, OperationSpec


def _operation() -> OperationSpec:
    return OperationSpec(
        operation_id="createPet",
        method="POST",
        path="/pets",
    )


def test_generate_attack_suite_accepts_custom_attack_packs() -> None:
    pack = make_attack_pack(
        "custom-pack",
        lambda operation: [
            AttackCase(
                id=f"atk_{operation.operation_id}_custom",
                name="Custom attack",
                kind="custom_probe",
                operation_id=operation.operation_id,
                method=operation.method,
                path=operation.path,
                description="Custom attack",
            )
        ],
    )

    suite = generate_attack_suite([_operation()], source="unit", extra_packs=[pack])

    assert any(attack.kind == "custom_probe" for attack in suite.attacks)


def test_load_module_attack_packs_supports_local_modules(tmp_path: Path) -> None:
    module_path = tmp_path / "custom_pack.py"
    module_path.write_text(
        dedent(
            """
            from knives_out.attack_packs import make_attack_pack
            from knives_out.models import AttackCase, OperationSpec

            def generate(operation: OperationSpec) -> list[AttackCase]:
                return [
                    AttackCase(
                        id=f"atk_{operation.operation_id}_module",
                        name="Module pack attack",
                        kind="module_probe",
                        operation_id=operation.operation_id,
                        method=operation.method,
                        path=operation.path,
                        description="Module pack attack",
                    )
                ]

            attack_pack = make_attack_pack("module-pack", generate)
            """
        ),
        encoding="utf-8",
    )

    packs = load_module_attack_packs([module_path])

    assert [pack.name for pack in packs] == ["module-pack"]
    attacks = packs[0].generate(_operation())
    assert attacks[0].kind == "module_probe"


def test_load_module_attack_packs_reports_import_failures(tmp_path: Path) -> None:
    module_path = tmp_path / "broken_pack.py"
    module_path.write_text("raise RuntimeError('boom')\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Failed to import attack pack module"):
        load_module_attack_packs([module_path])


def test_load_entry_point_attack_packs_supports_registered_names(monkeypatch) -> None:
    class _FakeEntryPoint:
        def __init__(self, name: str) -> None:
            self.name = name

        def load(self):
            return make_attack_pack(
                self.name,
                lambda operation: [
                    AttackCase(
                        id=f"atk_{operation.operation_id}_entry",
                        name="Entry point attack",
                        kind="entry_probe",
                        operation_id=operation.operation_id,
                        method=operation.method,
                        path=operation.path,
                        description="Entry point attack",
                    )
                ],
            )

    class _FakeEntryPoints:
        def select(self, *, group: str):
            assert group == ENTRY_POINT_GROUP
            return [_FakeEntryPoint("example-pack")]

    monkeypatch.setattr("knives_out.attack_packs.entry_points", lambda: _FakeEntryPoints())

    packs = load_entry_point_attack_packs(["example-pack"])

    assert [pack.name for pack in packs] == ["example-pack"]
    assert packs[0].generate(_operation())[0].kind == "entry_probe"


def test_load_attack_packs_raises_for_missing_entry_point() -> None:
    with pytest.raises(ValueError, match="Unknown attack pack entry point"):
        load_attack_packs(entry_point_names=["missing-pack"])


def test_load_attack_packs_supports_project_entry_point() -> None:
    packs = load_attack_packs(entry_point_names=["unexpected-header"])

    assert [pack.name for pack in packs] == ["unexpected-header"]
