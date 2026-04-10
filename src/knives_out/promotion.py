from __future__ import annotations

from dataclasses import dataclass

from knives_out.models import AttackResults, AttackSuite
from knives_out.verification import (
    ConfidenceThreshold,
    SeverityThreshold,
    VerificationResult,
    evaluate_verification,
)


class PromotionError(ValueError):
    pass


@dataclass(frozen=True)
class PromotionResult:
    verification: VerificationResult
    promoted_suite: AttackSuite
    promoted_attack_ids: list[str]


def _unique_attack_ids(results: AttackResults) -> list[str]:
    seen: set[str] = set()
    ordered_ids: list[str] = []
    for result in results.results:
        if result.attack_id in seen:
            continue
        seen.add(result.attack_id)
        ordered_ids.append(result.attack_id)
    return ordered_ids


def _promoted_attack_ids(verification: VerificationResult) -> list[str]:
    seen: set[str] = set()
    ordered_ids: list[str] = []
    for finding in verification.failing_findings:
        if finding.attack_id in seen:
            continue
        seen.add(finding.attack_id)
        ordered_ids.append(finding.attack_id)
    return ordered_ids


def promote_attack_suite(
    current: AttackResults,
    attacks: AttackSuite,
    *,
    baseline: AttackResults | None = None,
    min_severity: SeverityThreshold = "high",
    min_confidence: ConfidenceThreshold = "medium",
) -> PromotionResult:
    verification = evaluate_verification(
        current,
        baseline=baseline,
        min_severity=min_severity,
        min_confidence=min_confidence,
    )

    available_ids = {attack.id for attack in attacks.attacks}
    missing_ids = sorted(
        attack_id for attack_id in _unique_attack_ids(current) if attack_id not in available_ids
    )
    if missing_ids:
        raise PromotionError(
            "Results reference attack ids that are missing from the attack suite: "
            + ", ".join(missing_ids)
        )

    promoted_ids = _promoted_attack_ids(verification)
    promoted_id_set = set(promoted_ids)
    promoted_attacks = [attack for attack in attacks.attacks if attack.id in promoted_id_set]

    return PromotionResult(
        verification=verification,
        promoted_suite=attacks.model_copy(update={"attacks": promoted_attacks}),
        promoted_attack_ids=promoted_ids,
    )
