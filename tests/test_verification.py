from __future__ import annotations

from knives_out.models import AttackResult, AttackResults
from knives_out.suppressions import SuppressionRule
from knives_out.verification import (
    compare_attack_results,
    evaluate_verification,
    verification_report_payload,
)


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


def test_compare_attack_results_exposes_persisting_deltas() -> None:
    current = _results(
        _finding("atk_shared", issue="server_error", severity="high", confidence="high"),
    )
    baseline = _results(
        _finding("atk_shared", issue="server_error", severity="medium", confidence="low"),
    )
    current.results[0].status_code = 500
    baseline.results[0].status_code = 401

    comparison = compare_attack_results(current, baseline)

    assert len(comparison.persisting_findings) == 1
    finding = comparison.persisting_findings[0]
    assert finding.has_delta is True
    assert finding.delta_fragments == [
        "severity medium -> high",
        "confidence low -> high",
        "status 401 -> 500",
    ]
    assert (
        finding.delta_summary
        == "severity medium -> high; confidence low -> high; status 401 -> 500"
    )


def test_verification_report_payload_includes_counts_and_delta_details() -> None:
    current = _results(
        _finding("atk_new", issue="server_error", severity="high", confidence="high"),
        _finding("atk_shared", issue="server_error", severity="critical", confidence="medium"),
    )
    baseline = _results(
        _finding("atk_shared", issue="server_error", severity="high", confidence="high"),
        _finding("atk_resolved", issue="server_error", severity="high", confidence="high"),
    )
    current.results[1].status_code = 500
    baseline.results[0].status_code = 403

    verification = evaluate_verification(
        current,
        baseline=baseline,
        min_severity="high",
        min_confidence="medium",
    )

    payload = verification_report_payload(verification)

    assert payload["passed"] is False
    assert payload["baseline_used"] is True
    assert payload["policy"] == {"min_severity": "high", "min_confidence": "medium"}
    assert payload["counts"] == {
        "current_findings": 2,
        "baseline_findings": 2,
        "new_findings": 1,
        "resolved_findings": 1,
        "persisting_findings": 1,
        "persisting_findings_with_deltas": 1,
        "suppressed_current_findings": 0,
        "suppressed_baseline_findings": 0,
        "failing_findings": 1,
    }
    assert payload["failing_findings"][0]["attack_id"] == "atk_new"
    assert payload["persisting_findings"][0]["change"] == "persisting"
    assert payload["persisting_findings"][0]["delta_changes"] == [
        {"field": "severity", "baseline": "high", "current": "critical"},
        {"field": "confidence", "baseline": "high", "current": "medium"},
        {"field": "status", "baseline": "403", "current": "500"},
    ]


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


def test_compare_attack_results_tracks_persisting_deltas() -> None:
    current = _results(
        AttackResult(
            attack_id="atk_shared",
            operation_id="createPet",
            kind="wrong_type_param",
            name="Shared finding",
            method="POST",
            url="https://example.com/pets/atk_shared",
            status_code=500,
            flagged=True,
            issue="server_error",
            severity="critical",
            confidence="medium",
            response_schema_valid=False,
        )
    )
    baseline = _results(
        AttackResult(
            attack_id="atk_shared",
            operation_id="createPet",
            kind="wrong_type_param",
            name="Shared finding",
            method="POST",
            url="https://example.com/pets/atk_shared",
            status_code=403,
            flagged=True,
            issue="server_error",
            severity="high",
            confidence="high",
            response_schema_valid=True,
        )
    )

    comparison = compare_attack_results(current, baseline)

    assert len(comparison.persisting_findings) == 1
    delta = comparison.persisting_findings[0].delta
    assert delta is not None
    assert [(change.field, change.baseline, change.current) for change in delta.changes] == [
        ("severity", "high", "critical"),
        ("confidence", "high", "medium"),
        ("status", "403", "500"),
        ("schema", "ok", "mismatch"),
    ]


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


def test_compare_attack_results_excludes_suppressed_findings() -> None:
    current = _results(
        _finding("atk_suppressed", issue="server_error", severity="high", confidence="high"),
        _finding("atk_visible", issue="server_error", severity="high", confidence="high"),
    )

    comparison = compare_attack_results(
        current,
        suppressions=[
            SuppressionRule(
                attack_id="atk_suppressed",
                issue="server_error",
                reason="known issue",
                owner="api-team",
            )
        ],
    )

    assert [result.attack_id for result in comparison.current_findings] == ["atk_visible"]
    assert [finding.result.attack_id for finding in comparison.suppressed_current_findings] == [
        "atk_suppressed"
    ]


def test_evaluate_verification_respects_suppressions() -> None:
    current = _results(
        _finding("atk_suppressed", issue="server_error", severity="high", confidence="high"),
    )

    verification = evaluate_verification(
        current,
        suppressions=[
            SuppressionRule(
                attack_id="atk_suppressed",
                issue="server_error",
                reason="known issue",
                owner="api-team",
            )
        ],
    )

    assert verification.passed is True
    assert verification.comparison.current_findings == []
    assert [
        finding.result.attack_id for finding in verification.comparison.suppressed_current_findings
    ] == ["atk_suppressed"]
