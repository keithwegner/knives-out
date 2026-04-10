from __future__ import annotations

from knives_out.models import AttackResult, AttackResults
from knives_out.verification import compare_attack_results, evaluate_verification


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
    flagged: bool = True,
) -> AttackResult:
    return AttackResult(
        attack_id=attack_id,
        operation_id="createPet",
        kind="wrong_type_param",
        name=f"Finding {attack_id}",
        method="POST",
        url=f"https://example.com/pets/{attack_id}",
        status_code=500 if flagged else 400,
        flagged=flagged,
        issue=issue if flagged else None,
        severity=severity,
        confidence=confidence,
    )


def test_compare_attack_results_classifies_new_resolved_and_persisting_findings() -> None:
    current = _results(
        _finding("atk_new", issue="server_error", severity="high", confidence="high"),
        _finding(
            "atk_shared",
            issue="response_schema_mismatch",
            severity="medium",
            confidence="high",
        ),
    )
    baseline = _results(
        _finding(
            "atk_shared",
            issue="response_schema_mismatch",
            severity="medium",
            confidence="high",
        ),
        _finding("atk_old", issue="transport_error", severity="low", confidence="low"),
    )

    comparison = compare_attack_results(current, baseline)

    assert [finding.attack_id for finding in comparison.new_findings] == ["atk_new"]
    assert [finding.attack_id for finding in comparison.resolved_findings] == ["atk_old"]
    assert [finding.attack_id for finding in comparison.persisting_findings] == ["atk_shared"]


def test_compare_attack_results_ignores_non_flagged_results() -> None:
    current = _results(
        _finding("atk_flagged", issue="server_error", severity="high", confidence="high"),
        _finding(
            "atk_ok",
            issue="server_error",
            severity="high",
            confidence="high",
            flagged=False,
        ),
    )

    comparison = compare_attack_results(current)

    assert [result.attack_id for result in comparison.current_findings] == ["atk_flagged"]
    assert [finding.attack_id for finding in comparison.new_findings] == ["atk_flagged"]


def test_compare_attack_results_treats_issue_changes_as_resolved_and_new() -> None:
    current = _results(
        _finding("atk_same", issue="server_error", severity="high", confidence="high"),
    )
    baseline = _results(
        _finding("atk_same", issue="transport_error", severity="low", confidence="low"),
    )

    comparison = compare_attack_results(current, baseline)

    assert [finding.issue for finding in comparison.new_findings] == ["server_error"]
    assert [finding.issue for finding in comparison.resolved_findings] == ["transport_error"]
    assert comparison.persisting_findings == []


def test_evaluate_verification_without_baseline_filters_by_thresholds() -> None:
    current = _results(
        _finding("atk_high", issue="server_error", severity="high", confidence="high"),
        _finding(
            "atk_medium",
            issue="response_schema_mismatch",
            severity="medium",
            confidence="high",
        ),
    )

    verification = evaluate_verification(current)

    assert verification.passed is False
    assert [finding.attack_id for finding in verification.failing_findings] == ["atk_high"]


def test_evaluate_verification_with_baseline_fails_only_on_new_findings() -> None:
    current = _results(
        _finding("atk_shared", issue="server_error", severity="high", confidence="high"),
        _finding("atk_new", issue="server_error", severity="high", confidence="high"),
    )
    baseline = _results(
        _finding("atk_shared", issue="server_error", severity="high", confidence="high"),
    )

    verification = evaluate_verification(current, baseline=baseline)

    assert verification.passed is False
    assert [finding.attack_id for finding in verification.failing_findings] == ["atk_new"]
