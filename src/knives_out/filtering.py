from __future__ import annotations

from knives_out.models import AttackCase, AttackSuite, WorkflowAttackCase


def _normalized_values(values: list[str] | None) -> set[str]:
    return {value.strip().casefold() for value in values or [] if value.strip()}


def _matches_attack(
    attack: AttackCase | WorkflowAttackCase,
    *,
    include_operations: set[str],
    exclude_operations: set[str],
    include_methods: set[str],
    exclude_methods: set[str],
    include_kinds: set[str],
    exclude_kinds: set[str],
) -> bool:
    operation_id = attack.operation_id.casefold()
    method = attack.method.casefold()
    kind = attack.kind.casefold()

    if include_operations and operation_id not in include_operations:
        return False
    if include_methods and method not in include_methods:
        return False
    if include_kinds and kind not in include_kinds:
        return False
    if operation_id in exclude_operations:
        return False
    if method in exclude_methods:
        return False
    if kind in exclude_kinds:
        return False
    return True


def filter_attack_suite(
    suite: AttackSuite,
    *,
    include_operations: list[str] | None = None,
    exclude_operations: list[str] | None = None,
    include_methods: list[str] | None = None,
    exclude_methods: list[str] | None = None,
    include_kinds: list[str] | None = None,
    exclude_kinds: list[str] | None = None,
) -> AttackSuite:
    include_operation_set = _normalized_values(include_operations)
    exclude_operation_set = _normalized_values(exclude_operations)
    include_method_set = _normalized_values(include_methods)
    exclude_method_set = _normalized_values(exclude_methods)
    include_kind_set = _normalized_values(include_kinds)
    exclude_kind_set = _normalized_values(exclude_kinds)

    filtered_attacks = [
        attack
        for attack in suite.attacks
        if _matches_attack(
            attack,
            include_operations=include_operation_set,
            exclude_operations=exclude_operation_set,
            include_methods=include_method_set,
            exclude_methods=exclude_method_set,
            include_kinds=include_kind_set,
            exclude_kinds=exclude_kind_set,
        )
    ]

    return suite.model_copy(update={"attacks": filtered_attacks})
