from __future__ import annotations

from collections import Counter
from pathlib import Path

from knives_out.models import AttackResults, ProfileAttackResult
from knives_out.suppressions import SuppressedFinding, SuppressionRule
from knives_out.verification import (
    ComparedFinding,
    compare_attack_results,
)


def load_attack_results(path: str | Path) -> AttackResults:
    raw = Path(path).read_text(encoding="utf-8")
    return AttackResults.model_validate_json(raw)


def _finding_table_rows(findings: list[ComparedFinding]) -> list[str]:
    rows: list[str] = []
    for finding in findings:
        result = finding.result
        status = str(result.status_code) if result.status_code is not None else "-"
        schema = "mismatch" if result.response_schema_valid is False else "-"
        rows.append(
            f"| {result.name} | {result.kind} | {status} | "
            f"{result.issue or '-'} | {result.severity} | {result.confidence} | "
            f"{schema} | `{result.url}` |"
        )
    return rows


def _suppressed_table_rows(findings: list[SuppressedFinding]) -> list[str]:
    rows: list[str] = []
    for finding in findings:
        result = finding.result
        rule = finding.rule
        expires = rule.expires_on.isoformat() if rule.expires_on is not None else "-"
        rows.append(
            f"| {result.name} | {result.issue or '-'} | {rule.reason} | {rule.owner} | {expires} |"
        )
    return rows


def _profile_table_rows(profile_results: list[ProfileAttackResult]) -> list[str]:
    rows: list[str] = []
    for profile_result in sorted(
        profile_results,
        key=lambda result: (result.level, result.profile.casefold()),
    ):
        status = str(profile_result.status_code) if profile_result.status_code is not None else "-"
        schema = "mismatch" if profile_result.response_schema_valid is False else "-"
        profile_name = profile_result.profile
        if profile_result.anonymous:
            profile_name = f"{profile_name} (anonymous)"
        rows.append(
            f"| {profile_name} | {profile_result.level} | {status} | "
            f"{profile_result.issue or 'ok'} | {schema} | `{profile_result.url}` |"
        )
    return rows


def _workflow_phase(result) -> str:
    if result.type != "workflow":
        return "request"
    if result.error and result.error.startswith("Workflow setup failed"):
        return "setup"
    return "terminal"


def render_markdown_report(
    results: AttackResults,
    *,
    baseline: AttackResults | None = None,
    suppressions: list[SuppressionRule] | None = None,
) -> str:
    comparison = compare_attack_results(results, baseline, suppressions=suppressions)

    total = len(results.results)
    flagged = len(comparison.current_findings)
    suppressed_flagged = len(comparison.suppressed_current_findings)
    response_schema_mismatches = sum(
        1 for result in results.results if result.response_schema_valid is False
    )
    issue_counter = Counter(result.issue or "ok" for result in results.results)

    lines: list[str] = []
    lines.append("# knives-out report")
    lines.append("")
    lines.append(f"- Source: `{results.source}`")
    lines.append(f"- Base URL: `{results.base_url}`")
    lines.append(f"- Executed at: `{results.executed_at.isoformat()}`")
    lines.append(f"- Total attacks: **{total}**")
    if results.profiles:
        lines.append(f"- Profiles: **{len(results.profiles)}**")
        lines.append(f"- Profile names: `{', '.join(results.profiles)}`")
    lines.append(f"- Active flagged results: **{flagged}**")
    lines.append(f"- Suppressed flagged results: **{suppressed_flagged}**")
    lines.append(f"- Response schema mismatches: **{response_schema_mismatches}**")
    lines.append("")
    lines.append("## Outcome summary")
    lines.append("")
    lines.append("| Outcome | Count |")
    lines.append("| --- | ---: |")
    for outcome, count in sorted(issue_counter.items()):
        lines.append(f"| {outcome} | {count} |")

    lines.append("")
    lines.append("## Flagged findings")
    lines.append("")
    lines.append("| Attack | Kind | Status | Issue | Severity | Confidence | Schema | URL |")
    lines.append("| --- | --- | ---: | --- | --- | --- | --- | --- |")

    found_flagged = False
    for result in comparison.current_findings:
        found_flagged = True
        status = str(result.status_code) if result.status_code is not None else "-"
        schema = "mismatch" if result.response_schema_valid is False else "-"
        lines.append(
            f"| {result.name} | {result.kind} | {status} | "
            f"{result.issue or '-'} | {result.severity} | {result.confidence} | "
            f"{schema} | `{result.url}` |"
        )

    if not found_flagged:
        lines.append("| None | - | - | - | - | - | - | - |")

    lines.append("")
    lines.append("## Suppressed findings")
    lines.append("")
    lines.append("| Attack | Issue | Reason | Owner | Expires |")
    lines.append("| --- | --- | --- | --- | --- |")
    lines.extend(_suppressed_table_rows(comparison.suppressed_current_findings))
    if not comparison.suppressed_current_findings:
        lines.append("| None | - | - | - | - |")

    if baseline is not None:
        lines.append("")
        lines.append("## Verification summary")
        lines.append("")
        lines.append(f"- Baseline executed at: `{baseline.executed_at.isoformat()}`")
        lines.append(f"- New findings: **{len(comparison.new_findings)}**")
        lines.append(f"- Resolved findings: **{len(comparison.resolved_findings)}**")
        lines.append(f"- Persisting findings: **{len(comparison.persisting_findings)}**")
        lines.append(
            f"- Suppressed current findings: **{len(comparison.suppressed_current_findings)}**"
        )

        lines.append("")
        lines.append("## New findings")
        lines.append("")
        lines.append("| Attack | Kind | Status | Issue | Severity | Confidence | Schema | URL |")
        lines.append("| --- | --- | ---: | --- | --- | --- | --- | --- |")
        lines.extend(_finding_table_rows(comparison.new_findings))
        if not comparison.new_findings:
            lines.append("| None | - | - | - | - | - | - | - |")

        lines.append("")
        lines.append("## Resolved findings")
        lines.append("")
        lines.append("| Attack | Kind | Status | Issue | Severity | Confidence | Schema | URL |")
        lines.append("| --- | --- | ---: | --- | --- | --- | --- | --- |")
        lines.extend(_finding_table_rows(comparison.resolved_findings))
        if not comparison.resolved_findings:
            lines.append("| None | - | - | - | - | - | - | - |")

        lines.append("")
        lines.append("## Persisting findings")
        lines.append("")
        lines.append("| Attack | Kind | Status | Issue | Severity | Confidence | Schema | URL |")
        lines.append("| --- | --- | ---: | --- | --- | --- | --- | --- |")
        lines.extend(_finding_table_rows(comparison.persisting_findings))
        if not comparison.persisting_findings:
            lines.append("| None | - | - | - | - | - | - | - |")

    lines.append("")
    lines.append("## Detailed results")
    lines.append("")
    for result in results.results:
        lines.append(f"### {result.name}")
        lines.append("")
        lines.append(f"- Type: `{result.type}`")
        lines.append(f"- Operation: `{result.operation_id}`")
        lines.append(f"- Method: `{result.method}`")
        lines.append(f"- URL: `{result.url}`")
        if result.type == "workflow":
            lines.append(f"- Workflow phase: `{_workflow_phase(result)}`")
            lines.append(f"- Setup steps executed: `{len(result.workflow_steps or [])}`")
        lines.append(
            f"- Status: `{result.status_code}`"
            if result.status_code is not None
            else "- Status: `-`"
        )
        lines.append(f"- Issue: `{result.issue}`" if result.issue else "- Issue: `ok`")
        lines.append(f"- Severity: `{result.severity}`")
        lines.append(f"- Confidence: `{result.confidence}`")
        if result.response_schema_status:
            lines.append(f"- Declared response schema: `{result.response_schema_status}`")
        if result.response_schema_valid is True:
            lines.append("- Response schema: `ok`")
        elif result.response_schema_error:
            lines.append(f"- Response schema mismatch: `{result.response_schema_error}`")
        if result.error:
            lines.append(f"- Error: `{result.error}`")
        if result.duration_ms is not None:
            lines.append(f"- Duration: `{result.duration_ms:.2f} ms`")
        if result.profile_results:
            lines.append("")
            lines.append("| Profile | Level | Status | Issue | Schema | URL |")
            lines.append("| --- | ---: | ---: | --- | --- | --- |")
            lines.extend(_profile_table_rows(result.profile_results))
        if result.response_excerpt:
            lines.append("")
            lines.append("```text")
            lines.append(result.response_excerpt)
            lines.append("```")
        if result.workflow_steps:
            lines.append("")
            lines.append("| Step | Operation | Method | Status | URL |")
            lines.append("| --- | --- | --- | ---: | --- |")
            for step in result.workflow_steps:
                step_status = str(step.status_code) if step.status_code is not None else "-"
                lines.append(
                    f"| {step.name} | {step.operation_id} | {step.method} | "
                    f"{step_status} | `{step.url}` |"
                )
                if step.error:
                    lines.append(f"| Error | - | - | - | `{step.error}` |")
        lines.append("")

    return "\n".join(lines).strip() + "\n"
