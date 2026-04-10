from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from importlib import util
from importlib.metadata import entry_points
from pathlib import Path
from types import ModuleType
from typing import Any

from knives_out.models import AttackCase, OperationSpec, WorkflowAttackCase

ENTRY_POINT_GROUP = "knives_out.workflow_packs"

WorkflowPackGenerator = Callable[
    [list[OperationSpec], list[AttackCase]],
    list[WorkflowAttackCase] | list[dict[str, Any]],
]


@dataclass(frozen=True)
class LoadedWorkflowPack:
    name: str
    generate_fn: WorkflowPackGenerator

    def generate(
        self,
        operations: list[OperationSpec],
        request_attacks: list[AttackCase],
    ) -> list[WorkflowAttackCase]:
        generated = self.generate_fn(operations, request_attacks)
        return [WorkflowAttackCase.model_validate(workflow) for workflow in generated]


def make_workflow_pack(name: str, generate_fn: WorkflowPackGenerator) -> LoadedWorkflowPack:
    return LoadedWorkflowPack(name=name, generate_fn=generate_fn)


def _module_name_for_path(module_path: Path) -> str:
    resolved = module_path.resolve()
    digest = abs(hash(str(resolved)))
    return f"knives_out_custom_workflow_pack_{digest}"


def _coerce_workflow_pack(candidate: object, *, name_hint: str) -> LoadedWorkflowPack:
    if isinstance(candidate, LoadedWorkflowPack):
        return candidate
    if callable(candidate):
        return make_workflow_pack(name_hint, candidate)

    generate = getattr(candidate, "generate", None)
    if callable(generate):
        name = getattr(candidate, "name", name_hint)
        return make_workflow_pack(str(name), generate)

    raise ValueError(
        f"Workflow pack {name_hint!r} must be a callable or expose a callable 'generate'."
    )


def _workflow_pack_from_module(module: ModuleType, *, name_hint: str) -> LoadedWorkflowPack:
    if hasattr(module, "workflow_pack"):
        return _coerce_workflow_pack(module.workflow_pack, name_hint=name_hint)
    if hasattr(module, "generate"):
        return _coerce_workflow_pack(module.generate, name_hint=name_hint)
    raise ValueError(
        f"Workflow pack module {name_hint!r} must define 'workflow_pack' or 'generate'."
    )


def load_entry_point_workflow_packs(names: list[str] | None) -> list[LoadedWorkflowPack]:
    if not names:
        return []

    selected_entry_points = {
        entry_point.name: entry_point
        for entry_point in entry_points().select(group=ENTRY_POINT_GROUP)
    }
    loaded: list[LoadedWorkflowPack] = []
    for name in names:
        entry_point = selected_entry_points.get(name)
        if entry_point is None:
            raise ValueError(
                f"Unknown workflow pack entry point {name!r}. "
                f"Install a package exposing [{ENTRY_POINT_GROUP}] {name}."
            )
        loaded.append(_coerce_workflow_pack(entry_point.load(), name_hint=name))
    return loaded


def load_module_workflow_packs(module_paths: list[Path] | None) -> list[LoadedWorkflowPack]:
    if not module_paths:
        return []

    loaded: list[LoadedWorkflowPack] = []
    for module_path in module_paths:
        if not module_path.exists():
            raise ValueError(f"Workflow pack module path does not exist: {module_path}")

        spec = util.spec_from_file_location(_module_name_for_path(module_path), module_path)
        if spec is None or spec.loader is None:
            raise ValueError(f"Could not load workflow pack module from: {module_path}")

        module = util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception as exc:  # noqa: BLE001
            raise ValueError(f"Failed to import workflow pack module {module_path}: {exc}") from exc

        loaded.append(_workflow_pack_from_module(module, name_hint=module_path.stem))
    return loaded


def load_workflow_packs(
    *,
    entry_point_names: list[str] | None = None,
    module_paths: list[Path] | None = None,
) -> list[LoadedWorkflowPack]:
    return load_entry_point_workflow_packs(entry_point_names) + load_module_workflow_packs(
        module_paths
    )
