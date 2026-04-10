from __future__ import annotations

from knives_out.models import (
    AttackCase,
    AttackResult,
    AttackResults,
    AttackSuite,
    WorkflowAttackCase,
)
from knives_out.promotion import PromotionError, promote_attack_suite


def _results(*results: AttackResult) -> AttackResults:
    return AttackResults(
        source="unit",
        base_url="https://example.com",
        results=list(results),
    )


def _finding(
    attack_id: str,
    *,
    issue: str,
    severity: str,
    confidence: str,
) -> AttackResult:
    return AttackResult(
        attack_id=attack_id,
        operation_id="createPet",
        kind="wrong_type_param",
        name=f"Finding {attack_id}",
        method="POST",
        url=f"https://example.com/pets/{attack_id}",
        status_code=500,
        flagged=True,
        issue=issue,
        severity=severity,
        confidence=confidence,
    )


def _suite() -> AttackSuite:
    return AttackSuite(
        source="unit",
        attacks=[
            AttackCase(
                id="atk_one",
                name="Attack one",
                kind="wrong_type_param",
                operation_id="createPet",
                method="POST",
                path="/pets",
                description="Attack one",
            ),
            AttackCase(
                id="atk_two",
                name="Attack two",
                kind="wrong_type_param",
                operation_id="createPet",
                method="POST",
                path="/pets",
                description="Attack two",
            ),
            AttackCase(
                id="atk_three",
                name="Attack three",
                kind="wrong_type_param",
                operation_id="createPet",
                method="POST",
                path="/pets",
                description="Attack three",
            ),
        ],
    )


def test_promote_attack_suite_without_baseline_preserves_attack_file_order() -> None:
    current = _results(
        _finding("atk_three", issue="server_error", severity="high", confidence="high"),
        _finding("atk_one", issue="server_error", severity="high", confidence="high"),
    )

    promotion = promote_attack_suite(current, _suite())

    assert promotion.promoted_attack_ids == ["atk_three", "atk_one"]
    assert [attack.id for attack in promotion.promoted_suite.attacks] == [
        "atk_one",
        "atk_three",
    ]


def test_promote_attack_suite_with_baseline_only_promotes_new_qualifying_findings() -> None:
    current = _results(
        _finding("atk_one", issue="server_error", severity="high", confidence="high"),
        _finding("atk_two", issue="server_error", severity="high", confidence="high"),
    )
    baseline = _results(
        _finding("atk_one", issue="server_error", severity="high", confidence="high"),
    )

    promotion = promote_attack_suite(current, _suite(), baseline=baseline)

    assert [attack.id for attack in promotion.promoted_suite.attacks] == ["atk_two"]


def test_promote_attack_suite_writes_empty_suite_when_nothing_qualifies() -> None:
    current = _results(
        _finding(
            "atk_one",
            issue="response_schema_mismatch",
            severity="medium",
            confidence="high",
        )
    )

    promotion = promote_attack_suite(current, _suite())

    assert promotion.promoted_attack_ids == []
    assert promotion.promoted_suite.attacks == []


def test_promote_attack_suite_deduplicates_multiple_findings_for_one_attack() -> None:
    current = _results(
        _finding("atk_one", issue="server_error", severity="high", confidence="high"),
        _finding(
            "atk_one",
            issue="unexpected_success",
            severity="high",
            confidence="medium",
        ),
    )

    promotion = promote_attack_suite(current, _suite())

    assert promotion.promoted_attack_ids == ["atk_one"]
    assert [attack.id for attack in promotion.promoted_suite.attacks] == ["atk_one"]


def test_promote_attack_suite_errors_when_results_reference_missing_attack_ids() -> None:
    current = _results(
        _finding("atk_missing", issue="server_error", severity="high", confidence="high"),
    )

    try:
        promote_attack_suite(current, _suite())
    except PromotionError as exc:
        assert "atk_missing" in str(exc)
    else:
        raise AssertionError("Expected PromotionError for missing attack ids.")


def test_promote_attack_suite_supports_workflow_attack_ids() -> None:
    current = _results(
        _finding("wf_lookup", issue="server_error", severity="high", confidence="high"),
    )
    suite = AttackSuite(
        source="unit",
        attacks=[
            WorkflowAttackCase(
                id="wf_lookup",
                name="Workflow lookup",
                kind="missing_auth",
                operation_id="getPet",
                method="GET",
                path="/pets/{petId}",
                description="Workflow lookup",
                terminal_attack=AttackCase(
                    id="atk_terminal",
                    name="Terminal attack",
                    kind="missing_auth",
                    operation_id="getPet",
                    method="GET",
                    path="/pets/{petId}",
                    description="Terminal attack",
                ),
            )
        ],
    )

    promotion = promote_attack_suite(current, suite)

    assert [attack.id for attack in promotion.promoted_suite.attacks] == ["wf_lookup"]
