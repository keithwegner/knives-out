from knives_out.filtering import filter_attack_suite
from knives_out.models import AttackCase, AttackSuite, WorkflowAttackCase


def _suite() -> AttackSuite:
    return AttackSuite(
        source="unit",
        attacks=[
            AttackCase(
                id="atk_get_missing",
                name="GET missing auth",
                kind="missing_auth",
                operation_id="listPets",
                method="GET",
                path="/pets",
                tags=["pets", "read"],
                description="GET missing auth",
            ),
            AttackCase(
                id="atk_post_body",
                name="POST malformed body",
                kind="malformed_json_body",
                operation_id="createPet",
                method="POST",
                path="/pets",
                tags=["pets", "write"],
                description="POST malformed body",
            ),
            AttackCase(
                id="atk_post_auth",
                name="POST missing auth",
                kind="missing_auth",
                operation_id="createPet",
                method="POST",
                path="/pets",
                tags=["pets", "write"],
                description="POST missing auth",
            ),
        ],
    )


def test_filter_attack_suite_by_method() -> None:
    suite = filter_attack_suite(_suite(), include_methods=["post"])

    assert [attack.id for attack in suite.attacks] == [
        "atk_post_body",
        "atk_post_auth",
    ]


def test_filter_attack_suite_by_operation() -> None:
    suite = filter_attack_suite(_suite(), include_operations=["createPet"])

    assert [attack.id for attack in suite.attacks] == [
        "atk_post_body",
        "atk_post_auth",
    ]


def test_filter_attack_suite_combines_include_and_exclude_filters() -> None:
    suite = filter_attack_suite(
        _suite(),
        include_methods=["post"],
        include_kinds=["missing_auth", "malformed_json_body"],
        exclude_kinds=["malformed_json_body"],
    )

    assert [attack.id for attack in suite.attacks] == ["atk_post_auth"]


def test_filter_attack_suite_by_exact_tag() -> None:
    suite = filter_attack_suite(_suite(), include_tags=["write"])

    assert [attack.id for attack in suite.attacks] == [
        "atk_post_body",
        "atk_post_auth",
    ]


def test_filter_attack_suite_by_exact_path() -> None:
    suite = filter_attack_suite(_suite(), include_paths=["/pets"])

    assert [attack.id for attack in suite.attacks] == [
        "atk_get_missing",
        "atk_post_body",
        "atk_post_auth",
    ]


def test_filter_attack_suite_treats_tags_as_case_sensitive() -> None:
    suite = filter_attack_suite(_suite(), include_tags=["WRITE"])

    assert suite.attacks == []


def test_filter_attack_suite_matches_workflow_terminal_metadata() -> None:
    suite = AttackSuite(
        source="unit",
        attacks=[
            WorkflowAttackCase(
                id="wf_post_auth",
                name="Workflow missing auth",
                kind="missing_auth",
                operation_id="createPet",
                method="POST",
                path="/pets",
                tags=["pets", "write"],
                description="Workflow missing auth",
                terminal_attack=AttackCase(
                    id="atk_post_auth",
                    name="POST missing auth",
                    kind="missing_auth",
                    operation_id="createPet",
                    method="POST",
                    path="/pets",
                    tags=["pets", "write"],
                    description="POST missing auth",
                ),
            )
        ],
    )

    filtered = filter_attack_suite(
        suite,
        include_operations=["createPet"],
        include_methods=["post"],
        include_kinds=["missing_auth"],
    )

    assert [attack.id for attack in filtered.attacks] == ["wf_post_auth"]


def test_filter_attack_suite_matches_workflow_tags_and_paths() -> None:
    suite = AttackSuite(
        source="unit",
        attacks=[
            WorkflowAttackCase(
                id="wf_post_auth",
                name="Workflow missing auth",
                kind="missing_auth",
                operation_id="createPet",
                method="POST",
                path="/pets/{petId}",
                tags=["pets", "write"],
                description="Workflow missing auth",
                terminal_attack=AttackCase(
                    id="atk_post_auth",
                    name="POST missing auth",
                    kind="missing_auth",
                    operation_id="createPet",
                    method="POST",
                    path="/pets/{petId}",
                    tags=["pets", "write"],
                    description="POST missing auth",
                ),
            )
        ],
    )

    filtered = filter_attack_suite(
        suite,
        include_paths=["/pets/{petId}"],
        include_tags=["write"],
    )

    assert [attack.id for attack in filtered.attacks] == ["wf_post_auth"]
