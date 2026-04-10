from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from importlib import util
from importlib.metadata import entry_points
from pathlib import Path
from types import ModuleType
from typing import Any

from knives_out.models import AttackCase, OperationSpec

ENTRY_POINT_GROUP = "knives_out.attack_packs"


AttackPackGenerator = Callable[[OperationSpec], list[AttackCase] | list[dict[str, Any]]]


@dataclass(frozen=True)
class LoadedAttackPack:
    name: str
    generate_fn: AttackPackGenerator

    def generate(self, operation: OperationSpec) -> list[AttackCase]:
        generated = self.generate_fn(operation)
        return [AttackCase.model_validate(attack) for attack in generated]


def make_attack_pack(name: str, generate_fn: AttackPackGenerator) -> LoadedAttackPack:
    return LoadedAttackPack(name=name, generate_fn=generate_fn)


def _module_name_for_path(module_path: Path) -> str:
    resolved = module_path.resolve()
    digest = abs(hash(str(resolved)))
    return f"knives_out_custom_pack_{digest}"


def _coerce_attack_pack(candidate: object, *, name_hint: str) -> LoadedAttackPack:
    if isinstance(candidate, LoadedAttackPack):
        return candidate
    if callable(candidate):
        return make_attack_pack(name_hint, candidate)

    generate = getattr(candidate, "generate", None)
    if callable(generate):
        name = getattr(candidate, "name", name_hint)
        return make_attack_pack(str(name), generate)

    raise ValueError(
        f"Attack pack {name_hint!r} must be a callable or expose a callable 'generate'."
    )


def _attack_pack_from_module(module: ModuleType, *, name_hint: str) -> LoadedAttackPack:
    if hasattr(module, "attack_pack"):
        return _coerce_attack_pack(module.attack_pack, name_hint=name_hint)
    if hasattr(module, "generate"):
        return _coerce_attack_pack(module.generate, name_hint=name_hint)
    raise ValueError(f"Attack pack module {name_hint!r} must define 'attack_pack' or 'generate'.")


def load_entry_point_attack_packs(names: list[str] | None) -> list[LoadedAttackPack]:
    if not names:
        return []

    selected_entry_points = {
        entry_point.name: entry_point
        for entry_point in entry_points().select(group=ENTRY_POINT_GROUP)
    }
    loaded: list[LoadedAttackPack] = []
    for name in names:
        entry_point = selected_entry_points.get(name)
        if entry_point is None:
            raise ValueError(
                f"Unknown attack pack entry point {name!r}. "
                f"Install a package exposing [{ENTRY_POINT_GROUP}] {name}."
            )
        loaded.append(_coerce_attack_pack(entry_point.load(), name_hint=name))
    return loaded


def load_module_attack_packs(module_paths: list[Path] | None) -> list[LoadedAttackPack]:
    if not module_paths:
        return []

    loaded: list[LoadedAttackPack] = []
    for module_path in module_paths:
        if not module_path.exists():
            raise ValueError(f"Attack pack module path does not exist: {module_path}")

        spec = util.spec_from_file_location(_module_name_for_path(module_path), module_path)
        if spec is None or spec.loader is None:
            raise ValueError(f"Could not load attack pack module from: {module_path}")

        module = util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception as exc:  # noqa: BLE001
            raise ValueError(f"Failed to import attack pack module {module_path}: {exc}") from exc

        loaded.append(_attack_pack_from_module(module, name_hint=module_path.stem))
    return loaded


def load_attack_packs(
    *,
    entry_point_names: list[str] | None = None,
    module_paths: list[Path] | None = None,
) -> list[LoadedAttackPack]:
    return load_entry_point_attack_packs(entry_point_names) + load_module_attack_packs(module_paths)
