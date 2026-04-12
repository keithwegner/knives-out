from __future__ import annotations

from datetime import date, timedelta

import pytest

from knives_out.models import AttackResult
from knives_out.suppressions import (
    SuppressionRule,
    SuppressionsFile,
    load_suppressions,
    merge_suppressions,
    suppression_identity,
    triage_rule_for_result,
    write_suppressions,
)


def _result() -> AttackResult:
    return AttackResult(
        attack_id="atk_widget",
        operation_id="createWidget",
        kind="missing_request_body",
        name="Widget failure",
        method="POST",
        path="/widgets",
        tags=["widgets", "write"],
        url="https://example.com/widgets",
        status_code=500,
        flagged=True,
        issue="server_error",
        severity="high",
        confidence="high",
    )


def test_suppression_rule_requires_a_selector() -> None:
    with pytest.raises(ValueError, match="at least one matching selector"):
        SuppressionRule(reason="known issue", owner="api-team")


def test_suppression_rule_matches_exact_path_and_tags() -> None:
    rule = SuppressionRule(
        issue="server_error",
        method="POST",
        path="/widgets",
        tags=["widgets"],
        reason="known issue",
        owner="api-team",
    )

    assert rule.matches(_result()) is True


def test_suppression_rule_does_not_match_when_expired() -> None:
    rule = SuppressionRule(
        attack_id="atk_widget",
        reason="known issue",
        owner="api-team",
        expires_on=date.today() - timedelta(days=1),
    )

    assert rule.matches(_result()) is False


def test_merge_suppressions_deduplicates_generated_entries() -> None:
    rule = triage_rule_for_result(_result())

    merged = merge_suppressions([rule], [rule])

    assert len(merged) == 1
    assert suppression_identity(merged[0]) == suppression_identity(rule)


@pytest.mark.parametrize(
    ("rule_kwargs", "expected"),
    [
        ({"issue": "unexpected_success"}, False),
        ({"operation_id": "listWidgets"}, False),
        ({"method": "GET"}, False),
        ({"path": "/other"}, False),
        ({"kind": "missing_auth"}, False),
        ({"tags": ["admin"]}, False),
        ({"method": "post", "issue": "server_error"}, True),
    ],
)
def test_suppression_rule_matches_all_supported_selectors(
    rule_kwargs: dict[str, object],
    expected: bool,
) -> None:
    rule = SuppressionRule(reason="known issue", owner="api-team", **rule_kwargs)

    assert rule.matches(_result()) is expected


def test_load_suppressions_rejects_non_mapping_documents(tmp_path) -> None:
    path = tmp_path / "suppressions.yml"
    path.write_text("- invalid\n", encoding="utf-8")

    with pytest.raises(ValueError, match="top-level mapping"):
        load_suppressions(path)


def test_load_suppressions_wraps_validation_errors(tmp_path) -> None:
    path = tmp_path / "suppressions.yml"
    path.write_text(
        "suppressions:\n  - reason: missing selector\n    owner: api-team\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="at least one matching selector"):
        load_suppressions(path)


def test_write_suppressions_round_trips_rules(tmp_path) -> None:
    path = tmp_path / "suppressions.yml"
    expected = triage_rule_for_result(_result())

    write_suppressions(path, SuppressionsFile(suppressions=[expected]))
    loaded = load_suppressions(path)

    assert loaded.suppressions[0].attack_id == expected.attack_id
