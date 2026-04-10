from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from knives_out.models import AttackResult, AttackResults

SeverityThreshold = Literal["low", "medium", "high", "critical"]
ConfidenceThreshold = Literal["low", "medium", "high"]
FindingChange = Literal["new", "resolved", "persisting"]

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


@dataclass(frozen=True)
class ResultComparison:
    current: AttackResults
    baseline: AttackResults | None
    current_findings: list[AttackResult]
    baseline_findings: list[AttackResult]
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


def _flagged_findings(results: AttackResults) -> dict[tuple[str, str], AttackResult]:
    flagged: dict[tuple[str, str], AttackResult] = {}
    for result in results.results:
        if not result.flagged or result.issue is None:
            continue
        flagged[(result.attack_id, result.issue)] = result
    return flagged


def compare_attack_results(
    current: AttackResults,
    baseline: AttackResults | None = None,
) -> ResultComparison:
    current_flagged = _flagged_findings(current)
    baseline_flagged = _flagged_findings(baseline) if baseline is not None else {}

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
) -> VerificationResult:
    comparison = compare_attack_results(current, baseline)
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
