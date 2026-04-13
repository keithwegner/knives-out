from __future__ import annotations

import re
from collections import Counter
from html import escape
from pathlib import Path

from knives_out.models import (
    AttackResult,
    AttackResults,
    AuthEvent,
    AuthSummaryEntry,
    ProfileAttackResult,
    ResultsSummary,
    SummaryFinding,
)
from knives_out.suppressions import SuppressedFinding, SuppressionRule
from knives_out.verification import (
    ComparedFinding,
    compare_attack_results,
)


def load_attack_results(path: str | Path) -> AttackResults:
    raw = Path(path).read_text(encoding="utf-8")
    return AttackResults.model_validate_json(raw)


def _protocol_label(protocol: str) -> str:
    if protocol == "openapi":
        return "rest"
    return protocol


def _schema_summary(result) -> str:
    if result.protocol == "graphql":
        if result.graphql_response_valid is False:
            return "graphql-mismatch"
        if result.graphql_response_valid is True:
            return "graphql-ok"
        return "-"
    if result.response_schema_valid is False:
        return "mismatch"
    if result.response_schema_valid is True:
        return "ok"
    return "-"


def _finding_table_rows(findings: list[ComparedFinding]) -> list[str]:
    rows: list[str] = []
    for finding in findings:
        result = finding.result
        status = str(result.status_code) if result.status_code is not None else "-"
        schema = _schema_summary(result)
        rows.append(
            f"| {_protocol_label(result.protocol)} | {result.name} | {result.kind} | {status} | "
            f"{result.issue or '-'} | {result.severity} | {result.confidence} | "
            f"{schema} | `{result.url}` |"
        )
    return rows


def _finding_result(finding: AttackResult | ComparedFinding) -> AttackResult:
    if isinstance(finding, ComparedFinding):
        return finding.result
    return finding


def _finding_group_rows(
    findings: list[AttackResult] | list[ComparedFinding],
    *,
    attribute: str,
) -> list[str]:
    counter = Counter(getattr(_finding_result(finding), attribute) or "-" for finding in findings)
    rows: list[str] = []
    for group, count in sorted(counter.items()):
        rows.append(f"| {group} | {count} |")
    return rows


def _persisting_delta_findings(findings: list[ComparedFinding]) -> list[ComparedFinding]:
    return [finding for finding in findings if finding.delta is not None and finding.delta.changed]


def _delta_summary(finding: ComparedFinding) -> str:
    delta = finding.delta
    if delta is None or not delta.changed:
        return "unchanged"
    return finding.delta_summary


def _persisting_delta_rows(findings: list[ComparedFinding]) -> list[str]:
    rows: list[str] = []
    for finding in _persisting_delta_findings(findings):
        result = finding.result
        rows.append(
            f"| {result.name} | {result.kind} | {result.issue or '-'} | "
            f"{_delta_summary(finding)} | `{result.url}` |"
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
        schema = _schema_summary(profile_result)
        profile_name = profile_result.profile
        if profile_result.anonymous:
            profile_name = f"{profile_name} (anonymous)"
        rows.append(
            f"| {profile_name} | {_protocol_label(profile_result.protocol)} | "
            f"{profile_result.level} | {status} | "
            f"{profile_result.issue or 'ok'} | {schema} | `{profile_result.url}` |"
        )
    return rows


def _auth_event_sort_key(event: AuthEvent) -> tuple[str, str, str, str]:
    return (
        (event.profile or "").casefold(),
        event.name.casefold(),
        event.phase,
        event.trigger or "",
    )


def _auth_event_table_rows(events: list[AuthEvent]) -> list[str]:
    rows: list[str] = []
    for event in sorted(events, key=_auth_event_sort_key):
        profile = event.profile or "-"
        status = str(event.status_code) if event.status_code is not None else "-"
        outcome = "ok" if event.success else "failed"
        rows.append(
            f"| {profile} | {event.name} | {event.strategy} | {event.phase} | "
            f"{event.trigger or '-'} | {outcome} | {status} | {event.error or '-'} |"
        )
    return rows


def _auth_summary_entries(events: list[AuthEvent]) -> list[dict[str, object]]:
    grouped: dict[tuple[str, str, str], dict[str, object]] = {}
    for event in sorted(events, key=_auth_event_sort_key):
        key = (event.profile or "-", event.name, event.strategy)
        entry = grouped.setdefault(
            key,
            {
                "profile": event.profile or "-",
                "name": event.name,
                "strategy": event.strategy,
                "acquire": 0,
                "refresh": 0,
                "failures": 0,
                "triggers": set(),
            },
        )
        entry[event.phase] += 1
        if not event.success:
            entry["failures"] += 1
        if event.trigger:
            entry["triggers"].add(event.trigger)
    return list(grouped.values())


def _auth_summary_table_rows(events: list[AuthEvent]) -> list[str]:
    rows: list[str] = []
    for entry in _auth_summary_entries(events):
        triggers = ", ".join(sorted(entry["triggers"])) or "-"
        rows.append(
            f"| {entry['profile']} | {entry['name']} | {entry['strategy']} | "
            f"{entry['acquire']} | {entry['refresh']} | {entry['failures']} | {triggers} |"
        )
    return rows


def _workflow_phase(result) -> str:
    if result.type != "workflow":
        return "request"
    if result.error and result.error.startswith("Workflow setup failed"):
        return "setup"
    return "terminal"


def _counter_dict(counter: Counter[str]) -> dict[str, int]:
    return {key: counter[key] for key in sorted(counter)}


def summarize_results(
    results: AttackResults,
    *,
    baseline: AttackResults | None = None,
    suppressions: list[SuppressionRule] | None = None,
    top_limit: int = 10,
) -> ResultsSummary:
    if top_limit < 0:
        raise ValueError("top_limit must be >= 0.")

    comparison = compare_attack_results(results, baseline, suppressions=suppressions)
    persisting_deltas = _persisting_delta_findings(comparison.persisting_findings)

    auth_summary = [
        AuthSummaryEntry(
            profile=str(entry["profile"]),
            name=str(entry["name"]),
            strategy=str(entry["strategy"]),
            acquire=int(entry["acquire"]),
            refresh=int(entry["refresh"]),
            failures=int(entry["failures"]),
            triggers=sorted(str(trigger) for trigger in entry["triggers"]),
        )
        for entry in _auth_summary_entries(results.auth_events)
    ]
    top_findings = [
        SummaryFinding(
            attack_id=result.attack_id,
            name=result.name,
            protocol=_protocol_label(result.protocol),
            kind=result.kind,
            issue=result.issue,
            severity=result.severity,
            confidence=result.confidence,
            status_code=result.status_code,
            url=result.url,
            schema_status=_schema_summary(result),
        )
        for result in comparison.current_findings[:top_limit]
    ]

    return ResultsSummary(
        source=results.source,
        base_url=results.base_url,
        executed_at=results.executed_at,
        baseline_used=baseline is not None,
        baseline_executed_at=baseline.executed_at if baseline is not None else None,
        total_results=len(results.results),
        profile_count=len(results.profiles),
        profile_names=list(results.profiles),
        active_flagged_count=len(comparison.current_findings),
        suppressed_flagged_count=len(comparison.suppressed_current_findings),
        new_findings_count=len(comparison.new_findings),
        resolved_findings_count=len(comparison.resolved_findings),
        persisting_findings_count=len(comparison.persisting_findings),
        persisting_deltas_count=len(persisting_deltas),
        auth_failures=sum(1 for event in results.auth_events if not event.success),
        refresh_attempts=sum(1 for event in results.auth_events if event.phase == "refresh"),
        response_schema_mismatches=sum(
            1 for result in results.results if result.response_schema_valid is False
        ),
        graphql_shape_mismatches=sum(
            1 for result in results.results if result.graphql_response_valid is False
        ),
        protocol_counts=_counter_dict(
            Counter(_protocol_label(result.protocol) for result in results.results)
        ),
        issue_counts=_counter_dict(Counter(result.issue or "ok" for result in results.results)),
        finding_severity_counts=_counter_dict(
            Counter(result.severity for result in comparison.current_findings)
        ),
        finding_confidence_counts=_counter_dict(
            Counter(result.confidence for result in comparison.current_findings)
        ),
        auth_summary=auth_summary,
        top_findings=top_findings,
    )


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
    auth_failures = sum(1 for event in results.auth_events if not event.success)
    response_schema_mismatches = sum(
        1 for result in results.results if result.response_schema_valid is False
    )
    graphql_shape_mismatches = sum(
        1 for result in results.results if result.graphql_response_valid is False
    )
    issue_counter = Counter(result.issue or "ok" for result in results.results)
    protocol_counter = Counter(_protocol_label(result.protocol) for result in results.results)

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
    lines.append(f"- Auth setup/refresh failures: **{auth_failures}**")
    lines.append(f"- Response schema mismatches: **{response_schema_mismatches}**")
    lines.append(f"- GraphQL response-shape mismatches: **{graphql_shape_mismatches}**")
    lines.append(
        "- Protocol mix: "
        + ", ".join(f"`{protocol}`={count}" for protocol, count in sorted(protocol_counter.items()))
    )
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
    lines.append("### By issue")
    lines.append("")
    lines.append("| Issue | Count |")
    lines.append("| --- | ---: |")
    lines.extend(_finding_group_rows(comparison.current_findings, attribute="issue"))
    if not comparison.current_findings:
        lines.append("| None | 0 |")

    lines.append("")
    lines.append("### By attack kind")
    lines.append("")
    lines.append("| Kind | Count |")
    lines.append("| --- | ---: |")
    lines.extend(_finding_group_rows(comparison.current_findings, attribute="kind"))
    if not comparison.current_findings:
        lines.append("| None | 0 |")

    lines.append("")
    lines.append(
        "| Protocol | Attack | Kind | Status | Issue | Severity | Confidence | Schema | URL |"
    )
    lines.append("| --- | --- | --- | ---: | --- | --- | --- | --- | --- |")

    found_flagged = False
    for result in comparison.current_findings:
        found_flagged = True
        status = str(result.status_code) if result.status_code is not None else "-"
        schema = _schema_summary(result)
        lines.append(
            f"| {_protocol_label(result.protocol)} | {result.name} | {result.kind} | {status} | "
            f"{result.issue or '-'} | {result.severity} | {result.confidence} | "
            f"{schema} | `{result.url}` |"
        )

    if not found_flagged:
        lines.append("| None | - | - | - | - | - | - | - | - |")

    lines.append("")
    lines.append("## Suppressed findings")
    lines.append("")
    lines.append("| Attack | Issue | Reason | Owner | Expires |")
    lines.append("| --- | --- | --- | --- | --- |")
    lines.extend(_suppressed_table_rows(comparison.suppressed_current_findings))
    if not comparison.suppressed_current_findings:
        lines.append("| None | - | - | - | - |")

    lines.append("")
    lines.append("## Auth summary")
    lines.append("")
    lines.append("| Profile | Auth config | Strategy | Acquire | Refresh | Failures | Triggers |")
    lines.append("| --- | --- | --- | ---: | ---: | ---: | --- |")
    lines.extend(_auth_summary_table_rows(results.auth_events))
    if not results.auth_events:
        lines.append("| None | - | - | - | - | - | - |")

    lines.append("")
    lines.append("## Auth diagnostics")
    lines.append("")
    lines.append(
        "| Profile | Auth config | Strategy | Phase | Trigger | Outcome | Status | Error |"
    )
    lines.append("| --- | --- | --- | --- | --- | --- | ---: | --- |")
    lines.extend(_auth_event_table_rows(results.auth_events))
    if not results.auth_events:
        lines.append("| None | - | - | - | - | - | - | - |")

    if baseline is not None:
        persisting_deltas = _persisting_delta_findings(comparison.persisting_findings)
        lines.append("")
        lines.append("## Verification summary")
        lines.append("")
        lines.append(f"- Baseline executed at: `{baseline.executed_at.isoformat()}`")
        lines.append(f"- New findings: **{len(comparison.new_findings)}**")
        lines.append(f"- Resolved findings: **{len(comparison.resolved_findings)}**")
        lines.append(f"- Persisting findings: **{len(comparison.persisting_findings)}**")
        lines.append(f"- Persisting findings with deltas: **{len(persisting_deltas)}**")
        lines.append(
            f"- Suppressed current findings: **{len(comparison.suppressed_current_findings)}**"
        )

        lines.append("")
        lines.append("## New findings")
        lines.append("")
        lines.append(
            "| Protocol | Attack | Kind | Status | Issue | Severity | Confidence | Schema | URL |"
        )
        lines.append("| --- | --- | --- | ---: | --- | --- | --- | --- | --- |")
        lines.extend(_finding_table_rows(comparison.new_findings))
        if not comparison.new_findings:
            lines.append("| None | - | - | - | - | - | - | - | - |")

        lines.append("")
        lines.append("## Resolved findings")
        lines.append("")
        lines.append(
            "| Protocol | Attack | Kind | Status | Issue | Severity | Confidence | Schema | URL |"
        )
        lines.append("| --- | --- | --- | ---: | --- | --- | --- | --- | --- |")
        lines.extend(_finding_table_rows(comparison.resolved_findings))
        if not comparison.resolved_findings:
            lines.append("| None | - | - | - | - | - | - | - | - |")

        lines.append("")
        lines.append("## Persisting findings")
        lines.append("")
        lines.append(
            "| Protocol | Attack | Kind | Status | Issue | Severity | Confidence | Schema | URL |"
        )
        lines.append("| --- | --- | --- | ---: | --- | --- | --- | --- | --- |")
        lines.extend(_finding_table_rows(comparison.persisting_findings))
        if not comparison.persisting_findings:
            lines.append("| None | - | - | - | - | - | - | - | - |")

        lines.append("")
        lines.append("## Persisting deltas")
        lines.append("")
        lines.append("| Attack | Kind | Issue | Changes | URL |")
        lines.append("| --- | --- | --- | --- | --- |")
        lines.extend(_persisting_delta_rows(comparison.persisting_findings))
        if not persisting_deltas:
            lines.append("| None | - | - | - | - |")

    lines.append("")
    lines.append("## Detailed results")
    lines.append("")
    for result in results.results:
        lines.append(f"### {result.name}")
        lines.append("")
        lines.append(f"- Type: `{result.type}`")
        lines.append(f"- Protocol: `{_protocol_label(result.protocol)}`")
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
        if result.graphql_response_valid is True:
            lines.append("- GraphQL response shape: `ok`")
        elif result.graphql_response_error:
            lines.append(f"- GraphQL response shape mismatch: `{result.graphql_response_error}`")
        if result.graphql_response_hint:
            lines.append(f"- GraphQL federation hint: `{result.graphql_response_hint}`")
        if result.error:
            lines.append(f"- Error: `{result.error}`")
        if result.duration_ms is not None:
            lines.append(f"- Duration: `{result.duration_ms:.2f} ms`")
        if result.profile_results:
            lines.append("")
            lines.append("| Profile | Protocol | Level | Status | Issue | Schema | URL |")
            lines.append("| --- | --- | ---: | ---: | --- | --- | --- |")
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


def _profile_artifact_segment(profile_name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", profile_name).strip("-") or "profile"


def _artifact_candidates(
    result,
    *,
    artifact_root: Path | None,
) -> list[tuple[str, Path]]:
    if artifact_root is None or not artifact_root.exists():
        return []

    candidates: list[tuple[str, Path]] = []
    if result.profile_results:
        for profile_result in result.profile_results:
            profile_root = artifact_root / _profile_artifact_segment(profile_result.profile)
            artifact_path = profile_root / f"{result.attack_id}.json"
            if artifact_path.exists():
                candidates.append((f"{profile_result.profile} artifact", artifact_path))
            for index, _ in enumerate(profile_result.workflow_steps or [], start=1):
                step_path = profile_root / f"{result.attack_id}-step-{index:02d}.json"
                if step_path.exists():
                    candidates.append((f"{profile_result.profile} step {index}", step_path))
        return candidates

    artifact_path = artifact_root / f"{result.attack_id}.json"
    if artifact_path.exists():
        candidates.append(("artifact", artifact_path))
    for index, _ in enumerate(result.workflow_steps or [], start=1):
        step_path = artifact_root / f"{result.attack_id}-step-{index:02d}.json"
        if step_path.exists():
            candidates.append((f"step {index}", step_path))
    return candidates


def _artifact_links_html(result, *, artifact_root: Path | None) -> str:
    candidates = _artifact_candidates(result, artifact_root=artifact_root)
    if not candidates:
        return "<span class='muted'>No linked artifact</span>"
    return "<br>".join(
        f"<a href='{escape(path.as_posix(), quote=True)}'>{escape(label)}</a>"
        for label, path in candidates
    )


def _issue_badge_class(issue: str | None) -> str:
    if issue in {"anonymous_access", "authorization_inversion", "server_error"}:
        return "critical"
    if issue in {
        "unexpected_success",
        "response_schema_mismatch",
        "graphql_response_shape_mismatch",
    }:
        return "warning"
    return "neutral"


def _summary_card_html(label: str, value: str) -> str:
    return (
        "<div class='summary-card'>"
        f"<span class='label'>{escape(label)}</span>"
        f"<strong>{escape(value)}</strong>"
        "</div>"
    )


def _result_meta_item_html(label: str, value: str) -> str:
    return f"<div><span class='label'>{escape(label)}</span><strong>{escape(value)}</strong></div>"


def _suppressed_finding_row_html(finding: SuppressedFinding) -> str:
    expires = finding.rule.expires_on.isoformat() if finding.rule.expires_on else "-"
    return (
        "<tr>"
        f"<td>{escape(finding.result.name)}</td>"
        f"<td>{escape(finding.result.issue or '-')}</td>"
        f"<td>{escape(finding.rule.reason)}</td>"
        f"<td>{escape(finding.rule.owner)}</td>"
        f"<td>{escape(expires)}</td>"
        "</tr>"
    )


def _finding_group_row_html(group: str, count: int) -> str:
    return f"<tr><td>{escape(group)}</td><td>{count}</td></tr>"


def _auth_event_row_html(event: AuthEvent) -> str:
    profile = event.profile or "-"
    status = str(event.status_code) if event.status_code is not None else "-"
    outcome = "ok" if event.success else "failed"
    return (
        "<tr>"
        f"<td>{escape(profile)}</td>"
        f"<td>{escape(event.name)}</td>"
        f"<td>{escape(event.strategy)}</td>"
        f"<td>{escape(event.phase)}</td>"
        f"<td>{escape(event.trigger or '-')}</td>"
        f"<td>{escape(outcome)}</td>"
        f"<td>{escape(status)}</td>"
        f"<td>{escape(event.error or '-')}</td>"
        "</tr>"
    )


def _auth_summary_row_html(entry: dict[str, object]) -> str:
    triggers = ", ".join(sorted(entry["triggers"])) or "-"
    return (
        "<tr>"
        f"<td>{escape(str(entry['profile']))}</td>"
        f"<td>{escape(str(entry['name']))}</td>"
        f"<td>{escape(str(entry['strategy']))}</td>"
        f"<td>{escape(str(entry['acquire']))}</td>"
        f"<td>{escape(str(entry['refresh']))}</td>"
        f"<td>{escape(str(entry['failures']))}</td>"
        f"<td>{escape(triggers)}</td>"
        "</tr>"
    )


def _persisting_delta_row_html(finding: ComparedFinding) -> str:
    result = finding.result
    return (
        "<tr>"
        f"<td>{escape(result.name)}</td>"
        f"<td>{escape(result.kind)}</td>"
        f"<td>{escape(result.issue or '-')}</td>"
        f"<td>{escape(_delta_summary(finding))}</td>"
        f"<td><code>{escape(result.url)}</code></td>"
        "</tr>"
    )


def _result_card_html(result, *, artifact_root: Path | None) -> str:
    status = str(result.status_code) if result.status_code is not None else "-"
    issue = result.issue or "ok"
    profile_rows = ""
    if result.profile_results:
        rows = []
        for profile_result in sorted(
            result.profile_results,
            key=lambda current: (current.level, current.profile.casefold()),
        ):
            profile_name = profile_result.profile
            if profile_result.anonymous:
                profile_name = f"{profile_name} (anonymous)"
            profile_status = (
                str(profile_result.status_code) if profile_result.status_code is not None else "-"
            )
            profile_schema = _schema_summary(profile_result)
            rows.append(
                "<tr>"
                f"<td>{escape(profile_name)}</td>"
                f"<td>{escape(_protocol_label(profile_result.protocol))}</td>"
                f"<td>{profile_result.level}</td>"
                f"<td>{escape(profile_status)}</td>"
                f"<td>{escape(profile_result.issue or 'ok')}</td>"
                f"<td>{escape(profile_schema)}</td>"
                f"<td><code>{escape(profile_result.url)}</code></td>"
                "</tr>"
            )
        profile_rows = (
            "<div class='subsection'><h4>Profile outcomes</h4>"
            "<table><thead><tr><th>Profile</th><th>Protocol</th><th>Level</th><th>Status</th>"
            "<th>Issue</th><th>Schema</th><th>URL</th></tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table></div>"
        )

    workflow_rows = ""
    if result.workflow_steps:
        rows = []
        for step in result.workflow_steps:
            step_status = str(step.status_code) if step.status_code is not None else "-"
            rows.append(
                "<tr>"
                f"<td>{escape(step.name)}</td>"
                f"<td>{escape(step.operation_id)}</td>"
                f"<td>{escape(step.method)}</td>"
                f"<td>{escape(step_status)}</td>"
                f"<td><code>{escape(step.url)}</code></td>"
                "</tr>"
            )
        workflow_rows = (
            "<div class='subsection'><h4>Workflow steps</h4>"
            "<table><thead><tr><th>Step</th><th>Operation</th><th>Method</th>"
            "<th>Status</th><th>URL</th></tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table></div>"
        )

    excerpt = ""
    if result.response_excerpt:
        excerpt = (
            "<div class='subsection'><h4>Response excerpt</h4>"
            f"<pre>{escape(result.response_excerpt)}</pre></div>"
        )

    error = ""
    if result.error:
        error = f"<p class='callout'>{escape(result.error)}</p>"
    graphql_details = ""
    if result.graphql_response_error or result.graphql_response_hint:
        graphql_details = (
            "<div class='subsection'><h4>GraphQL validation</h4>"
            f"<p>{escape(result.graphql_response_error or 'ok')}</p>"
            + (
                f"<p class='muted'>{escape(result.graphql_response_hint)}</p>"
                if result.graphql_response_hint
                else ""
            )
            + "</div>"
        )

    meta_grid = "".join(
        [
            _result_meta_item_html("Type", result.type),
            _result_meta_item_html("Protocol", _protocol_label(result.protocol)),
            _result_meta_item_html("Operation", result.operation_id),
            _result_meta_item_html("Method", result.method),
            _result_meta_item_html("Status", status),
            _result_meta_item_html("Severity", result.severity),
            _result_meta_item_html("Confidence", result.confidence),
        ]
    )
    artifact_html = _artifact_links_html(result, artifact_root=artifact_root)

    return (
        "<article class='result-card'>"
        f"<header><h3>{escape(result.name)}</h3>"
        f"<span class='badge {escape(_issue_badge_class(result.issue))}'>{escape(issue)}</span>"
        "</header>"
        "<div class='meta-grid'>"
        f"{meta_grid}"
        "</div>"
        f"<p><code>{escape(result.url)}</code></p>"
        f"<div class='subsection'><h4>Artifacts</h4>{artifact_html}</div>"
        f"{error}{graphql_details}{profile_rows}{workflow_rows}{excerpt}"
        "</article>"
    )


def render_html_report(
    results: AttackResults,
    *,
    baseline: AttackResults | None = None,
    suppressions: list[SuppressionRule] | None = None,
    artifact_root: str | Path | None = None,
) -> str:
    comparison = compare_attack_results(results, baseline, suppressions=suppressions)
    artifact_root_path = Path(artifact_root) if artifact_root is not None else None
    artifact_index_paths = (
        sorted(artifact_root_path.rglob("*.json"))
        if artifact_root_path and artifact_root_path.exists()
        else []
    )
    issue_counter = Counter(result.issue or "ok" for result in results.results)
    protocol_counter = Counter(_protocol_label(result.protocol) for result in results.results)
    refresh_attempts = sum(1 for event in results.auth_events if event.phase == "refresh")

    summary_cards = [
        ("Total results", str(len(results.results))),
        ("Active flagged", str(len(comparison.current_findings))),
        ("Suppressed", str(len(comparison.suppressed_current_findings))),
        ("Auth failures", str(sum(1 for event in results.auth_events if not event.success))),
        ("Refresh attempts", str(refresh_attempts)),
        (
            "Protocols",
            ", ".join(f"{name}:{count}" for name, count in sorted(protocol_counter.items())),
        ),
        (
            "Profiles",
            str(len(results.profiles)) if results.profiles else "single",
        ),
    ]
    if baseline is not None:
        summary_cards.extend(
            [
                ("New", str(len(comparison.new_findings))),
                ("Resolved", str(len(comparison.resolved_findings))),
                ("Persisting", str(len(comparison.persisting_findings))),
            ]
        )

    flagged_rows = "".join(
        "<tr>"
        f"<td>{escape(_protocol_label(finding.protocol))}</td>"
        f"<td>{escape(finding.name)}</td>"
        f"<td>{escape(finding.kind)}</td>"
        f"<td>{escape(str(finding.status_code) if finding.status_code is not None else '-')}</td>"
        f"<td>{escape(finding.issue or '-')}</td>"
        f"<td>{escape(finding.severity)}</td>"
        f"<td>{escape(finding.confidence)}</td>"
        f"<td>{_artifact_links_html(finding, artifact_root=artifact_root_path)}</td>"
        "</tr>"
        for finding in comparison.current_findings
    ) or ("<tr><td colspan='8' class='muted'>No active flagged findings.</td></tr>")
    issue_group_rows = (
        "".join(
            _finding_group_row_html(group, count)
            for group, count in sorted(
                Counter(finding.issue or "-" for finding in comparison.current_findings).items()
            )
        )
        or "<tr><td colspan='2' class='muted'>No active flagged findings.</td></tr>"
    )
    kind_group_rows = (
        "".join(
            _finding_group_row_html(group, count)
            for group, count in sorted(
                Counter(finding.kind for finding in comparison.current_findings).items()
            )
        )
        or "<tr><td colspan='2' class='muted'>No active flagged findings.</td></tr>"
    )

    suppressed_rows = (
        "".join(
            _suppressed_finding_row_html(finding)
            for finding in comparison.suppressed_current_findings
        )
        or "<tr><td colspan='5' class='muted'>No suppressed findings.</td></tr>"
    )
    auth_event_rows = (
        "".join(
            _auth_event_row_html(event)
            for event in sorted(results.auth_events, key=_auth_event_sort_key)
        )
        or "<tr><td colspan='8' class='muted'>No auth diagnostics recorded.</td></tr>"
    )
    auth_summary_entries = _auth_summary_entries(results.auth_events)
    auth_summary_rows = (
        "".join(_auth_summary_row_html(entry) for entry in auth_summary_entries)
        or "<tr><td colspan='7' class='muted'>No auth summary recorded.</td></tr>"
    )

    outcome_rows = "".join(
        f"<tr><td>{escape(outcome)}</td><td>{count}</td></tr>"
        for outcome, count in sorted(issue_counter.items())
    )

    artifact_index = ""
    if artifact_index_paths:
        artifact_rows = "".join(
            (
                f"<li><a href='{escape(path.as_posix(), quote=True)}'>"
                f"{escape(path.relative_to(artifact_root_path).as_posix())}</a></li>"
            )
            for path in artifact_index_paths
        )
        artifact_index = (
            "<section class='panel'><h2>Artifact index</h2>"
            f"<ul class='artifact-list'>{artifact_rows}</ul></section>"
        )

    diff_panels = ""
    if baseline is not None:
        persisting_deltas = _persisting_delta_findings(comparison.persisting_findings)
        persisting_delta_rows = (
            "".join(_persisting_delta_row_html(finding) for finding in persisting_deltas)
            or "<tr><td colspan='5' class='muted'>No persisting deltas detected.</td></tr>"
        )
        diff_panels = (
            "<section class='panel'>"
            "<h2>Regression summary</h2>"
            "<div class='summary-grid'>"
            f"{_summary_card_html('Baseline executed at', baseline.executed_at.isoformat())}"
            f"{_summary_card_html('New findings', str(len(comparison.new_findings)))}"
            f"{_summary_card_html('Resolved findings', str(len(comparison.resolved_findings)))}"
            f"{_summary_card_html('Persisting findings', str(len(comparison.persisting_findings)))}"
            f"{_summary_card_html('Persisting with deltas', str(len(persisting_deltas)))}"
            "</div></section>"
            "<section class='panel'>"
            "<h2>Persisting deltas</h2>"
            "<table>"
            "<thead><tr><th>Attack</th><th>Kind</th><th>Issue</th><th>Changes</th><th>URL</th></tr></thead>"
            f"<tbody>{persisting_delta_rows}</tbody>"
            "</table></section>"
        )

    cards_html = "".join(
        _result_card_html(result, artifact_root=artifact_root_path) for result in results.results
    )

    return f"""<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>knives-out report</title>
    <style>
      :root {{
        --bg: #f7f2e8;
        --panel: rgba(255, 252, 247, 0.92);
        --ink: #1d1a16;
        --muted: #6b6359;
        --border: rgba(69, 50, 28, 0.16);
        --accent: #0f766e;
        --warning: #b45309;
        --critical: #b42318;
        --shadow: 0 20px 60px rgba(31, 24, 17, 0.08);
      }}
      * {{ box-sizing: border-box; }}
      body {{
        margin: 0;
        background:
          radial-gradient(circle at top left, rgba(15, 118, 110, 0.12), transparent 36%),
          radial-gradient(circle at top right, rgba(180, 83, 9, 0.12), transparent 28%),
          linear-gradient(180deg, #fbf6ee 0%, var(--bg) 100%);
        color: var(--ink);
        font-family: Charter, "Iowan Old Style", "Palatino Linotype", "Book Antiqua", serif;
        line-height: 1.55;
      }}
      main {{
        width: min(1180px, calc(100vw - 32px));
        margin: 0 auto;
        padding: 40px 0 56px;
      }}
      h1, h2, h3, h4 {{ margin: 0; }}
      h1 {{ font-size: clamp(2rem, 3vw, 3.2rem); }}
      h2 {{ font-size: 1.35rem; margin-bottom: 16px; }}
      h3 {{ font-size: 1.15rem; }}
      p, ul {{ margin: 0; }}
      code, pre {{
        font-family: "IBM Plex Mono", "SFMono-Regular", "Menlo", "Consolas", monospace;
      }}
      .hero {{
        padding: 32px;
        border-bottom: 1px solid var(--border);
      }}
      .hero p {{
        margin-top: 10px;
        color: var(--muted);
      }}
      .panel, .result-card {{
        background: var(--panel);
        border: 1px solid var(--border);
        border-radius: 24px;
        box-shadow: var(--shadow);
        backdrop-filter: blur(12px);
      }}
      .panel {{
        padding: 28px;
        margin-top: 24px;
      }}
      .summary-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
        gap: 14px;
      }}
      .summary-card {{
        padding: 18px;
        background: rgba(255, 255, 255, 0.72);
        border-radius: 18px;
        border: 1px solid var(--border);
      }}
      .label {{
        display: block;
        font-size: 0.75rem;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: var(--muted);
        margin-bottom: 6px;
      }}
      .badge {{
        display: inline-flex;
        align-items: center;
        padding: 0.28rem 0.7rem;
        border-radius: 999px;
        font-size: 0.75rem;
        font-weight: 600;
        letter-spacing: 0.04em;
        text-transform: uppercase;
      }}
      .badge.critical {{ background: rgba(180, 35, 24, 0.12); color: var(--critical); }}
      .badge.warning {{ background: rgba(180, 83, 9, 0.12); color: var(--warning); }}
      .badge.neutral {{ background: rgba(15, 118, 110, 0.12); color: var(--accent); }}
      table {{
        width: 100%;
        border-collapse: collapse;
        font-size: 0.95rem;
      }}
      th, td {{
        padding: 12px 10px;
        border-bottom: 1px solid var(--border);
        text-align: left;
        vertical-align: top;
      }}
      th {{
        font-size: 0.78rem;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: var(--muted);
      }}
      .muted {{ color: var(--muted); }}
      .result-grid {{
        display: grid;
        gap: 18px;
        margin-top: 24px;
      }}
      .result-card {{
        padding: 24px;
      }}
      .result-card header {{
        display: flex;
        justify-content: space-between;
        gap: 16px;
        align-items: flex-start;
        margin-bottom: 16px;
      }}
      .meta-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
        gap: 12px;
        margin-bottom: 12px;
      }}
      .subsection {{
        margin-top: 16px;
      }}
      .subsection h4 {{
        margin-bottom: 10px;
        color: var(--muted);
      }}
      .callout {{
        margin-top: 14px;
        padding: 14px 16px;
        border-left: 4px solid var(--warning);
        background: rgba(180, 83, 9, 0.08);
        border-radius: 12px;
      }}
      pre {{
        margin: 0;
        padding: 14px;
        border-radius: 16px;
        background: #1f1a17;
        color: #f6ede1;
        overflow-x: auto;
      }}
      .artifact-list {{
        display: grid;
        gap: 10px;
        padding-left: 20px;
      }}
      a {{ color: var(--accent); text-decoration: none; }}
      a:hover {{ text-decoration: underline; }}
      @media (max-width: 720px) {{
        main {{ width: min(100vw - 20px, 100%); padding-top: 20px; }}
        .hero, .panel, .result-card {{ border-radius: 20px; }}
        .result-card header {{ flex-direction: column; }}
      }}
    </style>
  </head>
  <body>
    <main>
      <section class="panel hero">
        <h1>knives-out report</h1>
        <p>
          Source: <code>{escape(results.source)}</code><br>
          Base URL: <code>{escape(results.base_url)}</code><br>
          Executed at: <code>{escape(results.executed_at.isoformat())}</code>
        </p>
      </section>

      <section class="panel">
        <h2>Summary</h2>
        <div class="summary-grid">
          {"".join(_summary_card_html(label, value) for label, value in summary_cards)}
        </div>
      </section>

      <section class="panel">
        <h2>Outcome summary</h2>
        <table>
          <thead><tr><th>Outcome</th><th>Count</th></tr></thead>
          <tbody>{outcome_rows}</tbody>
        </table>
      </section>

      <section class="panel">
        <h2>Flagged findings</h2>
        <div class="summary-grid">
          <div>
            <h3>By issue</h3>
            <table>
              <thead><tr><th>Issue</th><th>Count</th></tr></thead>
              <tbody>{issue_group_rows}</tbody>
            </table>
          </div>
          <div>
            <h3>By attack kind</h3>
            <table>
              <thead><tr><th>Kind</th><th>Count</th></tr></thead>
              <tbody>{kind_group_rows}</tbody>
            </table>
          </div>
        </div>
        <div class="subsection">
        <table>
          <thead><tr><th>Protocol</th><th>Attack</th><th>Kind</th><th>Status</th><th>Issue</th><th>Severity</th><th>Confidence</th><th>Artifacts</th></tr></thead>
          <tbody>{flagged_rows}</tbody>
        </table>
        </div>
      </section>

      <section class="panel">
        <h2>Suppressed findings</h2>
        <table>
          <thead><tr><th>Attack</th><th>Issue</th><th>Reason</th><th>Owner</th><th>Expires</th></tr></thead>
          <tbody>{suppressed_rows}</tbody>
        </table>
      </section>

      <section class="panel">
        <h2>Auth summary</h2>
        <table>
          <thead>
            <tr>
              <th>Profile</th><th>Auth config</th><th>Strategy</th><th>Acquire</th>
              <th>Refresh</th><th>Failures</th><th>Triggers</th>
            </tr>
          </thead>
          <tbody>{auth_summary_rows}</tbody>
        </table>
      </section>

      <section class="panel">
        <h2>Auth diagnostics</h2>
        <table>
          <thead>
            <tr>
              <th>Profile</th><th>Auth config</th><th>Strategy</th><th>Phase</th>
              <th>Trigger</th><th>Outcome</th><th>Status</th><th>Error</th>
            </tr>
          </thead>
          <tbody>{auth_event_rows}</tbody>
        </table>
      </section>

      {diff_panels}
      {artifact_index}

      <section class="panel">
        <h2>Detailed results</h2>
        <div class="result-grid">{cards_html}</div>
      </section>
    </main>
  </body>
</html>
"""
