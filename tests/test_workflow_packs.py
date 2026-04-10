from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from knives_out.models import AttackCase, OperationSpec, WorkflowAttackCase
from knives_out.workflow_packs import (
    ENTRY_POINT_GROUP,
    load_entry_point_workflow_packs,
    load_module_workflow_packs,
    load_workflow_packs,
    make_workflow_pack,
)


def _operations() -> list[OperationSpec]:
    return [
        OperationSpec(operation_id="listPets", method="GET", path="/pets"),
        OperationSpec(operation_id="getPet", method="GET", path="/pets/{petId}"),
    ]


def _request_attacks() -> list[AttackCase]:
    return [
        AttackCase(
            id="atk_get_pet",
            name="Get pet wrong type",
            kind="wrong_type_param",
            operation_id="getPet",
            method="GET",
            path="/pets/{petId}",
            description="Get pet wrong type",
            path_params={"petId": "not-an-integer"},
        )
    ]


def test_load_module_workflow_packs_supports_local_modules(tmp_path: Path) -> None:
    module_path = tmp_path / "custom_workflow_pack.py"
    module_path.write_text(
        dedent(
            """
            from knives_out.models import WorkflowAttackCase
            from knives_out.workflow_packs import make_workflow_pack

            def generate(operations, request_attacks):
                attack = request_attacks[0]
                return [
                    WorkflowAttackCase(
                        id=f"{attack.id}_workflow",
                        name="Workflow probe",
                        kind=attack.kind,
                        operation_id=attack.operation_id,
                        method=attack.method,
                        path=attack.path,
                        description="Workflow probe",
                        terminal_attack=attack,
                    )
                ]

            workflow_pack = make_workflow_pack("module-workflow-pack", generate)
            """
        ),
        encoding="utf-8",
    )

    packs = load_module_workflow_packs([module_path])

    assert [pack.name for pack in packs] == ["module-workflow-pack"]
    workflows = packs[0].generate(_operations(), _request_attacks())
    assert workflows[0].type == "workflow"


def test_load_module_workflow_packs_reports_import_failures(tmp_path: Path) -> None:
    module_path = tmp_path / "broken_workflow_pack.py"
    module_path.write_text("raise RuntimeError('boom')\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Failed to import workflow pack module"):
        load_module_workflow_packs([module_path])


def test_load_entry_point_workflow_packs_supports_registered_names(monkeypatch) -> None:
    class _FakeEntryPoint:
        def __init__(self, name: str) -> None:
            self.name = name

        def load(self):
            return make_workflow_pack(
                self.name,
                lambda operations, request_attacks: [
                    WorkflowAttackCase(
                        id=f"{request_attacks[0].id}_workflow",
                        name="Entry point workflow",
                        kind=request_attacks[0].kind,
                        operation_id=request_attacks[0].operation_id,
                        method=request_attacks[0].method,
                        path=request_attacks[0].path,
                        description="Entry point workflow",
                        terminal_attack=request_attacks[0],
                    )
                ],
            )

    class _FakeEntryPoints:
        def select(self, *, group: str):
            assert group == ENTRY_POINT_GROUP
            return [_FakeEntryPoint("example-workflow-pack")]

    monkeypatch.setattr("knives_out.workflow_packs.entry_points", lambda: _FakeEntryPoints())

    packs = load_entry_point_workflow_packs(["example-workflow-pack"])

    assert [pack.name for pack in packs] == ["example-workflow-pack"]
    assert packs[0].generate(_operations(), _request_attacks())[0].type == "workflow"


def test_load_workflow_packs_raises_for_missing_entry_point() -> None:
    with pytest.raises(ValueError, match="Unknown workflow pack entry point"):
        load_workflow_packs(entry_point_names=["missing-workflow-pack"])


def test_load_workflow_packs_supports_project_entry_point() -> None:
    packs = load_workflow_packs(entry_point_names=["listed-id-lookup"])

    assert [pack.name for pack in packs] == ["listed-id-lookup"]
