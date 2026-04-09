from __future__ import annotations

from collections import Counter
from pathlib import Path

from knives_out.models import AttackResults


def load_attack_results(path: str | Path) -> AttackResults:
    raw = Path(path).read_text(encoding="utf-8")
    return AttackResults.model_validate_json(raw)


def render_markdown_report(results: AttackResults) -> str:
    total = len(results.results)
    flagged = sum(1 for result in results.results if result.flagged)
    issue_counter = Counter(result.issue or "ok" for result in results.results)

    lines: list[str] = []
    lines.append("# knives-out report")
    lines.append("")
    lines.append(f"- Source: `{results.source}`")
    lines.append(f"- Base URL: `{results.base_url}`")
    lines.append(f"- Executed at: `{results.executed_at.isoformat()}`")
    lines.append(f"- Total attacks: **{total}**")
    lines.append(f"- Flagged results: **{flagged}**")
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
    lines.append("| Attack | Kind | Status | Issue | URL |")
    lines.append("| --- | --- | ---: | --- | --- |")

    found_flagged = False
    for result in results.results:
        if not result.flagged:
            continue
        found_flagged = True
        status = str(result.status_code) if result.status_code is not None else "-"
        lines.append(
            f"| {result.name} | {result.kind} | {status} | {result.issue or '-'} | `{result.url}` |"
        )

    if not found_flagged:
        lines.append("| None | - | - | - | - |")

    lines.append("")
    lines.append("## Detailed results")
    lines.append("")
    for result in results.results:
        lines.append(f"### {result.name}")
        lines.append("")
        lines.append(f"- Operation: `{result.operation_id}`")
        lines.append(f"- Method: `{result.method}`")
        lines.append(f"- URL: `{result.url}`")
        lines.append(f"- Status: `{result.status_code}`" if result.status_code is not None else "- Status: `-`")
        lines.append(f"- Issue: `{result.issue}`" if result.issue else "- Issue: `ok`")
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
