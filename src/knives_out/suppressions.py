from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, ValidationError, model_validator

from knives_out.models import AttackResult

DEFAULT_SUPPRESSIONS_PATH = Path(".knives-out-ignore.yml")


class SuppressionRule(BaseModel):
    attack_id: str | None = None
    issue: str | None = None
    operation_id: str | None = None
    method: str | None = None
    path: str | None = None
    kind: str | None = None
    tags: list[str] = Field(default_factory=list)
    reason: str
    owner: str
    expires_on: date | None = None

    @model_validator(mode="after")
    def _validate_selectors(self) -> SuppressionRule:
        if not any(
            [
                self.attack_id,
                self.issue,
                self.operation_id,
                self.method,
                self.path,
                self.kind,
                self.tags,
            ]
        ):
            raise ValueError("Suppression rules require at least one matching selector.")
        return self

    def is_active(self, *, today: date | None = None) -> bool:
        if self.expires_on is None:
            return True
        return self.expires_on >= (today or date.today())

    def matches(self, result: AttackResult) -> bool:
        if not self.is_active():
            return False
        if self.attack_id is not None and result.attack_id != self.attack_id:
            return False
        if self.issue is not None and result.issue != self.issue:
            return False
        if self.operation_id is not None and result.operation_id != self.operation_id:
            return False
        if self.method is not None and result.method.casefold() != self.method.casefold():
            return False
        if self.path is not None and result.path != self.path:
            return False
        if self.kind is not None and result.kind != self.kind:
            return False
        if self.tags and not set(self.tags).issubset(set(result.tags)):
            return False
        return True


class SuppressionsFile(BaseModel):
    suppressions: list[SuppressionRule] = Field(default_factory=list)


@dataclass(frozen=True)
class SuppressedFinding:
    result: AttackResult
    rule: SuppressionRule


def load_suppressions(path: str | Path) -> SuppressionsFile:
    raw = Path(path).read_text(encoding="utf-8")
    data = yaml.safe_load(raw) or {}
    if not isinstance(data, dict):
        raise ValueError("Suppression file must contain a top-level mapping.")
    try:
        return SuppressionsFile.model_validate(data)
    except ValidationError as exc:
        raise ValueError(str(exc)) from exc


def write_suppressions(path: str | Path, suppressions_file: SuppressionsFile) -> None:
    rendered = yaml.safe_dump(
        suppressions_file.model_dump(mode="json", exclude_none=True),
        sort_keys=False,
        allow_unicode=False,
    )
    Path(path).write_text(rendered, encoding="utf-8")


def suppression_identity(rule: SuppressionRule) -> tuple[str | None, ...]:
    return (
        rule.attack_id,
        rule.issue,
        rule.operation_id,
        rule.method.casefold() if rule.method is not None else None,
        rule.path,
        rule.kind,
        ",".join(rule.tags),
    )


def triage_rule_for_result(result: AttackResult) -> SuppressionRule:
    return SuppressionRule(
        attack_id=result.attack_id,
        issue=result.issue,
        operation_id=result.operation_id,
        method=result.method,
        path=result.path,
        kind=result.kind,
        tags=list(result.tags),
        reason="TODO: explain why this finding is suppressed",
        owner="TODO: assign an owner",
    )


def merge_suppressions(
    existing: list[SuppressionRule],
    additions: list[SuppressionRule],
) -> list[SuppressionRule]:
    merged = list(existing)
    seen = {suppression_identity(rule) for rule in existing}
    for rule in additions:
        identity = suppression_identity(rule)
        if identity in seen:
            continue
        seen.add(identity)
        merged.append(rule)
    return merged
