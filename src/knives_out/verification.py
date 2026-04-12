from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from knives_out.models import AttackResult, AttackResults
from knives_out.suppressions import SuppressedFinding, SuppressionRule

SeverityThreshold = Literal["low", "medium", "high", "critical"]
ConfidenceThreshold = Literal["low", "medium", "high"]
FindingChange = Literal["new", "resolved", "persisting"]
FindingDeltaFieldName = Literal["status", "severity", "confidence", "schema"]

SEVERITY_ORDER = {
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

CONFIDENCE_ORDER = {
    "none": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
}


@dataclass(frozen=True)
class ComparedFinding:
    change: FindingChange
    current: AttackResult | None
    baseline: AttackResult | None

    @property
    def result(self) -> AttackResult:
        if self.current is not None:
            return self.current
        if self.baseline is not None:
            return self.baseline
        raise ValueError("ComparedFinding requires a current or baseline result.")

    @property
    def attack_id(self) -> str:
        return self.result.attack_id

    @property
    def issue(self) -> str:
        issue = self.result.issue
        if issue is None:
            raise ValueError("ComparedFinding requires a flagged result with an issue.")
        return issue

    @property
    def delta(self) -> FindingDelta | None:
        if self.current is None or self.baseline is None:
            return None
        return finding_delta(self.current, self.baseline)


@dataclass(frozen=True)
class FindingDeltaChange:
    field: FindingDeltaFieldName
    baseline: str
    current: str


@dataclass(frozen=True)
class FindingDelta:
    changes: list[FindingDeltaChange]

    @property
    def changed(self) -> bool:
        return bool(self.changes)


@dataclass(frozen=True)
class ResultComparison:
    current: AttackResults
    baseline: AttackResults | None
    current_findings: list[AttackResult]
    baseline_findings: list[AttackResult]
    suppressed_current_findings: list[SuppressedFinding]
    suppressed_baseline_findings: list[SuppressedFinding]
    new_findings: list[ComparedFinding]
    resolved_findings: list[ComparedFinding]
    persisting_findings: list[ComparedFinding]


@dataclass(frozen=True)
class VerificationResult:
    comparison: ResultComparison
    min_severity: SeverityThreshold
    min_confidence: ConfidenceThreshold
    failing_findings: list[ComparedFinding]

    @property
    def passed(self) -> bool:
        return not self.failing_findings

    @property
    def baseline_used(self) -> bool:
        return self.comparison.baseline is not None


def attack_result_sort_key(result: AttackResult) -> tuple[int, int, str, str]:
    return (
        -SEVERITY_ORDER.get(result.severity, 0),
        -CONFIDENCE_ORDER.get(result.confidence, 0),
        result.issue or "",
        result.name.lower(),
    )


def compared_finding_sort_key(finding: ComparedFinding) -> tuple[int, int, str, str]:
    return attack_result_sort_key(finding.result)


def suppressed_finding_sort_key(finding: SuppressedFinding) -> tuple[int, int, str, str]:
    return attack_result_sort_key(finding.result)


def _status_value(result: AttackResult) -> str:
    return str(result.status_code) if result.status_code is not None else "-"


def _schema_value(result: AttackResult) -> str:
    if result.response_schema_valid is True:
        return "ok"
    if result.response_schema_valid is False:
        return "mismatch"
    if result.response_schema_status:
        return result.response_schema_status
    return "-"


def finding_delta(current: AttackResult, baseline: AttackResult) -> FindingDelta:
    changes: list[FindingDeltaChange] = []
    values = [
        ("status", _status_value(baseline), _status_value(current)),
        ("severity", baseline.severity, current.severity),
        ("confidence", baseline.confidence, current.confidence),
        ("schema", _schema_value(baseline), _schema_value(current)),
    ]
    for field, baseline_value, current_value in values:
        if baseline_value != current_value:
            changes.append(
                FindingDeltaChange(
                    field=field,
                    baseline=baseline_value,
                    current=current_value,
                )
            )
    return FindingDelta(changes=changes)


def _matching_suppression(
    result: AttackResult,
    suppressions: list[SuppressionRule],
) -> SuppressionRule | None:
    for rule in suppressions:
        if rule.matches(result):
            return rule
    return None


def _flagged_findings(
    results: AttackResults,
    *,
    suppressions: list[SuppressionRule] | None = None,
) -> tuple[dict[tuple[str, str], AttackResult], list[SuppressedFinding]]:
    flagged: dict[tuple[str, str], AttackResult] = {}
    suppressed: list[SuppressedFinding] = []
    active_suppressions = list(suppressions or [])
    for result in results.results:
        if not result.flagged or result.issue is None:
            continue
        matched_rule = _matching_suppression(result, active_suppressions)
        if matched_rule is not None:
            suppressed.append(SuppressedFinding(result=result, rule=matched_rule))
            continue
        flagged[(result.attack_id, result.issue)] = result
    return flagged, sorted(suppressed, key=suppressed_finding_sort_key)


def compare_attack_results(
    current: AttackResults,
    baseline: AttackResults | None = None,
    *,
    suppressions: list[SuppressionRule] | None = None,
) -> ResultComparison:
    current_flagged, suppressed_current = _flagged_findings(current, suppressions=suppressions)
    if baseline is not None:
        baseline_flagged, suppressed_baseline = _flagged_findings(
            baseline,
            suppressions=suppressions,
        )
    else:
        baseline_flagged, suppressed_baseline = {}, []

    current_keys = set(current_flagged)
    baseline_keys = set(baseline_flagged)

    new_findings = sorted(
        (
            ComparedFinding(change="new", current=current_flagged[key], baseline=None)
            for key in current_keys - baseline_keys
        ),
        key=compared_finding_sort_key,
    )
    resolved_findings = sorted(
        (
            ComparedFinding(change="resolved", current=None, baseline=baseline_flagged[key])
            for key in baseline_keys - current_keys
        ),
        key=compared_finding_sort_key,
    )
    persisting_findings = sorted(
        (
            ComparedFinding(
                change="persisting",
                current=current_flagged[key],
                baseline=baseline_flagged[key],
            )
            for key in current_keys & baseline_keys
        ),
        key=compared_finding_sort_key,
    )

    return ResultComparison(
        current=current,
        baseline=baseline,
        current_findings=sorted(current_flagged.values(), key=attack_result_sort_key),
        baseline_findings=sorted(baseline_flagged.values(), key=attack_result_sort_key),
        suppressed_current_findings=suppressed_current,
        suppressed_baseline_findings=suppressed_baseline,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        persisting_findings=persisting_findings,
    )


def meets_thresholds(
    result: AttackResult,
    *,
    min_severity: SeverityThreshold,
    min_confidence: ConfidenceThreshold,
) -> bool:
    return (
        SEVERITY_ORDER.get(result.severity, 0) >= SEVERITY_ORDER[min_severity]
        and CONFIDENCE_ORDER.get(result.confidence, 0) >= CONFIDENCE_ORDER[min_confidence]
    )


def evaluate_verification(
    current: AttackResults,
    *,
    baseline: AttackResults | None = None,
    min_severity: SeverityThreshold = "high",
    min_confidence: ConfidenceThreshold = "medium",
    suppressions: list[SuppressionRule] | None = None,
) -> VerificationResult:
    comparison = compare_attack_results(current, baseline, suppressions=suppressions)
    if baseline is None:
        failing_findings = [
            ComparedFinding(change="new", current=result, baseline=None)
            for result in comparison.current_findings
            if meets_thresholds(
                result,
                min_severity=min_severity,
                min_confidence=min_confidence,
            )
        ]
    else:
        failing_findings = [
            finding
            for finding in comparison.new_findings
            if meets_thresholds(
                finding.result,
                min_severity=min_severity,
                min_confidence=min_confidence,
            )
        ]

    return VerificationResult(
        comparison=comparison,
        min_severity=min_severity,
        min_confidence=min_confidence,
        failing_findings=failing_findings,
    )
