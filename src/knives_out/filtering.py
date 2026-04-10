from __future__ import annotations

from knives_out.models import AttackCase, AttackSuite, OperationSpec, WorkflowAttackCase


def _normalized_values(values: list[str] | None) -> set[str]:
    return {value.strip().casefold() for value in values or [] if value.strip()}


def _exact_values(values: list[str] | None) -> set[str]:
    return {value.strip() for value in values or [] if value.strip()}


def _matches_path_and_tags(
    *,
    path: str,
    tags: list[str],
    include_paths: set[str],
    exclude_paths: set[str],
    include_tags: set[str],
    exclude_tags: set[str],
) -> bool:
    if include_paths and path not in include_paths:
        return False
    if path in exclude_paths:
        return False
    if include_tags and not any(tag in include_tags for tag in tags):
        return False
    if exclude_tags and any(tag in exclude_tags for tag in tags):
        return False
    return True


def _matches_attack(
    attack: AttackCase | WorkflowAttackCase,
    *,
    include_operations: set[str],
    exclude_operations: set[str],
    include_methods: set[str],
    exclude_methods: set[str],
    include_kinds: set[str],
    exclude_kinds: set[str],
    include_paths: set[str],
    exclude_paths: set[str],
    include_tags: set[str],
    exclude_tags: set[str],
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
    if not _matches_path_and_tags(
        path=attack.path,
        tags=attack.tags,
        include_paths=include_paths,
        exclude_paths=exclude_paths,
        include_tags=include_tags,
        exclude_tags=exclude_tags,
    ):
        return False
    return True


def filter_operations(
    operations: list[OperationSpec],
    *,
    include_paths: list[str] | None = None,
    exclude_paths: list[str] | None = None,
    include_tags: list[str] | None = None,
    exclude_tags: list[str] | None = None,
) -> list[OperationSpec]:
    include_path_set = _exact_values(include_paths)
    exclude_path_set = _exact_values(exclude_paths)
    include_tag_set = _exact_values(include_tags)
    exclude_tag_set = _exact_values(exclude_tags)

    return [
        operation
        for operation in operations
        if _matches_path_and_tags(
            path=operation.path,
            tags=operation.tags,
            include_paths=include_path_set,
            exclude_paths=exclude_path_set,
            include_tags=include_tag_set,
            exclude_tags=exclude_tag_set,
        )
    ]


def filter_attack_suite(
    suite: AttackSuite,
    *,
    include_operations: list[str] | None = None,
    exclude_operations: list[str] | None = None,
    include_methods: list[str] | None = None,
    exclude_methods: list[str] | None = None,
    include_kinds: list[str] | None = None,
    exclude_kinds: list[str] | None = None,
    include_paths: list[str] | None = None,
    exclude_paths: list[str] | None = None,
    include_tags: list[str] | None = None,
    exclude_tags: list[str] | None = None,
) -> AttackSuite:
    include_operation_set = _normalized_values(include_operations)
    exclude_operation_set = _normalized_values(exclude_operations)
    include_method_set = _normalized_values(include_methods)
    exclude_method_set = _normalized_values(exclude_methods)
    include_kind_set = _normalized_values(include_kinds)
    exclude_kind_set = _normalized_values(exclude_kinds)
    include_path_set = _exact_values(include_paths)
    exclude_path_set = _exact_values(exclude_paths)
    include_tag_set = _exact_values(include_tags)
    exclude_tag_set = _exact_values(exclude_tags)

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
            include_paths=include_path_set,
            exclude_paths=exclude_path_set,
            include_tags=include_tag_set,
            exclude_tags=exclude_tag_set,
        )
    ]

    return suite.model_copy(update={"attacks": filtered_attacks})
