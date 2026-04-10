from __future__ import annotations

from collections import Counter
from pathlib import Path

from knives_out.models import AttackResult, AttackResults

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


def load_attack_results(path: str | Path) -> AttackResults:
    raw = Path(path).read_text(encoding="utf-8")
    return AttackResults.model_validate_json(raw)


def _flagged_sort_key(result: AttackResult) -> tuple[int, int, str, str]:
    return (
        -SEVERITY_ORDER.get(result.severity, 0),
        -CONFIDENCE_ORDER.get(result.confidence, 0),
        result.issue or "",
        result.name.lower(),
    )


def render_markdown_report(results: AttackResults) -> str:
    total = len(results.results)
    flagged = sum(1 for result in results.results if result.flagged)
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
    lines.append(f"- Flagged results: **{flagged}**")
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
    flagged_results = sorted(
        (result for result in results.results if result.flagged),
        key=_flagged_sort_key,
    )
    for result in flagged_results:
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
    lines.append("## Detailed results")
    lines.append("")
    for result in results.results:
        lines.append(f"### {result.name}")
        lines.append("")
        lines.append(f"- Operation: `{result.operation_id}`")
        lines.append(f"- Method: `{result.method}`")
        lines.append(f"- URL: `{result.url}`")
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
        if result.response_excerpt:
            lines.append("")
            lines.append("```text")
            lines.append(result.response_excerpt)
            lines.append("```")
        lines.append("")

    return "\n".join(lines).strip() + "\n"
