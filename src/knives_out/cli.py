from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

import typer
import uvicorn
from rich.console import Console
from rich.table import Table

from knives_out.api import create_app
from knives_out.auth_plugins import PluginRuntimeError
from knives_out.capture import serve_capture_proxy
from knives_out.models import AttackResults, PreflightWarning
from knives_out.promotion import PromotionError
from knives_out.reporting import render_markdown_summary
from knives_out.services import (
    DEFAULT_SUPPRESSIONS_PATH,
    SuppressionRule,
    discover_model_paths,
    export_results_from_paths,
    generate_suite_from_path,
    inspect_source_path,
    load_attack_results_or_raise,
    load_attack_suite_or_raise,
    load_suppressions_or_default,
    parse_key_value_map,
    promote_results_from_paths,
    render_report_from_paths,
    run_suite,
    summarize_results_from_paths,
    triage_results_from_path,
    verify_results_from_paths,
)
from knives_out.verification import ComparedFinding

app = typer.Typer(
    no_args_is_help=True,
    help="Adversarial API testing from OpenAPI and GraphQL schemas.",
)
console = Console()


class SeverityThresholdOption(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ConfidenceThresholdOption(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"


class ReportFormatOption(StrEnum):
    markdown = "markdown"
    html = "html"


class ExportFormatOption(StrEnum):
    sarif = "sarif"


class SummaryFormatOption(StrEnum):
    json = "json"
    markdown = "markdown"


class InspectFormatOption(StrEnum):
    text = "text"
    json = "json"


def _warning_target(warning: PreflightWarning) -> str:
    if warning.operation_id:
        return f"{warning.operation_id} ({warning.method} {warning.path})"
    if warning.method and warning.path:
        return f"{warning.method} {warning.path}"
    return "spec"


def _print_preflight_warnings(warnings: list[PreflightWarning]) -> None:
    if not warnings:
        return

    table = Table(title=f"Preflight warnings ({len(warnings)})")
    table.add_column("Code")
    table.add_column("Target")
    table.add_column("Message")

    for warning in warnings:
        table.add_row(warning.code, _warning_target(warning), warning.message)

    console.print("")
    console.print(table)


def _inspect_payload(
    *,
    spec: Path,
    source_kind: str,
    operation_count: int,
    operations: list[Any],
    warnings: list[PreflightWarning],
    learned_workflow_count: int,
) -> dict[str, Any]:
    return {
        "source": str(spec),
        "source_kind": source_kind,
        "operation_count": operation_count,
        "operations": [operation.model_dump(mode="json") for operation in operations],
        "warning_count": len(warnings),
        "warnings": [warning.model_dump(mode="json") for warning in warnings],
        "learned_workflow_count": learned_workflow_count,
    }


def _load_attack_results_or_error(path: Path, *, label: str) -> AttackResults:
    try:
        return load_attack_results_or_raise(path, label=label)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc


def _load_suppressions_or_error(
    path: Path | None,
) -> tuple[Path | None, list[SuppressionRule]]:
    try:
        return load_suppressions_or_default(path)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc


def _print_suppression_summary(
    path: Path | None,
    suppressions: list[SuppressionRule],
) -> None:
    if path is None:
        return
    console.print(f"Applied {len(suppressions)} suppression rule(s) from [bold]{path}[/bold].")


def _print_compared_findings(title: str, findings: list[ComparedFinding]) -> None:
    if not findings:
        return

    table = Table(title=title)
    table.add_column("Protocol")
    table.add_column("Attack")
    table.add_column("Issue")
    table.add_column("Severity")
    table.add_column("Confidence")
    table.add_column("Status")

    for finding in findings:
        result = finding.result
        table.add_row(
            "rest" if result.protocol == "openapi" else result.protocol,
            result.name,
            result.issue or "-",
            result.severity,
            result.confidence,
            str(result.status_code) if result.status_code is not None else "-",
        )

    console.print("")
    console.print(table)


def _print_persisting_delta_findings(findings: list[ComparedFinding]) -> None:
    delta_findings = [
        finding for finding in findings if finding.delta is not None and finding.delta.changed
    ]
    if not delta_findings:
        return

    table = Table(title="Persisting findings with deltas")
    table.add_column("Protocol")
    table.add_column("Attack")
    table.add_column("Issue")
    table.add_column("Changes", overflow="fold")

    for finding in delta_findings:
        changes = ", ".join(
            f"{change.field} {change.baseline} -> {change.current}"
            for change in (finding.delta.changes if finding.delta is not None else [])
        )
        table.add_row(
            "rest" if finding.result.protocol == "openapi" else finding.result.protocol,
            finding.result.name,
            finding.result.issue or "-",
            changes,
        )

    console.print("")
    console.print(table)
    for finding in delta_findings:
        console.print(f"- {finding.result.name}: {finding.delta_summary}")


@app.command()
def capture(
    target_base_url: Annotated[
        str,
        typer.Option(help="Base URL to proxy captured traffic to."),
    ],
    out: Annotated[
        Path,
        typer.Option(help="Where to write captured NDJSON events."),
    ] = Path("capture.ndjson"),
    listen_host: Annotated[
        str,
        typer.Option(help="Host interface for the local capture proxy."),
    ] = "127.0.0.1",
    listen_port: Annotated[
        int,
        typer.Option(help="Port for the local capture proxy."),
    ] = 8080,
    timeout: Annotated[
        float,
        typer.Option(help="Forwarding timeout in seconds."),
    ] = 30.0,
    max_events: Annotated[
        int | None,
        typer.Option(help="Optional number of captured requests before the proxy exits."),
    ] = None,
) -> None:
    """Run a local reverse proxy and capture redacted HTTP traffic."""
    console.print(
        "Shadow Twin capture proxy listening on "
        f"[bold]http://{listen_host}:{listen_port}[/bold] "
        f"and forwarding to [bold]{target_base_url}[/bold]."
    )
    console.print(f"Writing redacted capture events to [bold]{out}[/bold].")
    if max_events is None:
        console.print("Press Ctrl-C to stop capturing.")
    else:
        console.print(f"The proxy will stop automatically after {max_events} captured request(s).")

    try:
        serve_capture_proxy(
            listen_host=listen_host,
            listen_port=listen_port,
            target_base_url=target_base_url,
            output_path=out,
            timeout_seconds=timeout,
            max_events=max_events,
        )
    except KeyboardInterrupt:
        console.print("\nCapture stopped.")


@app.command()
def discover(
    inputs: Annotated[
        list[Path],
        typer.Argument(help="Capture NDJSON or HAR files to learn from."),
    ],
    out: Annotated[
        Path,
        typer.Option(help="Where to write the learned-model artifact."),
    ] = Path("learned-model.json"),
) -> None:
    """Discover a replayable learned API model from captured traffic."""
    learned_model = discover_model_paths(inputs)
    out.write_text(learned_model.model_dump_json(indent=2, exclude_none=True), encoding="utf-8")
    console.print(
        f"Wrote learned model with {len(learned_model.operations)} operation(s) and "
        f"{len(learned_model.workflows)} workflow(s) to [bold]{out}[/bold]."
    )
    _print_preflight_warnings(learned_model.warnings)


@app.command()
def inspect(
    spec: Path,
    graphql_endpoint: Annotated[
        str,
        typer.Option(help="GraphQL endpoint path to use when inspecting GraphQL schemas."),
    ] = "/graphql",
    tag: Annotated[
        list[str] | None,
        typer.Option(help="Only include operations with these tags. Repeatable."),
    ] = None,
    exclude_tag: Annotated[
        list[str] | None,
        typer.Option(help="Exclude operations with these tags. Repeatable."),
    ] = None,
    path: Annotated[
        list[str] | None,
        typer.Option(help="Only include operations for these exact OpenAPI paths. Repeatable."),
    ] = None,
    exclude_path: Annotated[
        list[str] | None,
        typer.Option(help="Exclude operations for these exact OpenAPI paths. Repeatable."),
    ] = None,
    format: Annotated[
        InspectFormatOption,
        typer.Option(help="Output format for inspection results."),
    ] = InspectFormatOption.text,
) -> None:
    """Show the operations discovered in an OpenAPI, GraphQL, or learned model."""
    inspected = inspect_source_path(
        spec,
        graphql_endpoint=graphql_endpoint,
        tag=tag,
        exclude_tag=exclude_tag,
        path=path,
        exclude_path=exclude_path,
    )
    loaded = inspected.loaded
    operations = inspected.operations
    learned_workflow_count = (
        len(loaded.learned_model.workflows) if loaded.learned_model is not None else 0
    )

    if format == InspectFormatOption.json:
        payload = _inspect_payload(
            spec=spec,
            source_kind=loaded.source_kind,
            operation_count=len(operations),
            operations=operations,
            warnings=loaded.warnings,
            learned_workflow_count=learned_workflow_count,
        )
        typer.echo(json.dumps(payload, indent=2))
        return

    table = Table(title=f"knives-out inspect: {spec}")
    table.add_column("Operation ID")
    table.add_column("Method")
    table.add_column("Path")
    table.add_column("Params")
    table.add_column("Body")
    table.add_column("Auth")
    if loaded.source_kind == "learned":
        table.add_column("Confidence")

    for operation in operations:
        row = [
            operation.operation_id,
            operation.method,
            operation.path,
            str(len(operation.parameters)),
            "yes" if operation.request_body_schema else "no",
            "yes" if operation.auth_required else "no",
        ]
        if loaded.source_kind == "learned":
            confidence = (
                f"{operation.learned_confidence:.2f}"
                if operation.learned_confidence is not None
                else "-"
            )
            row.append(confidence)
        table.add_row(*row)

    console.print(table)
    console.print(f"\nFound {len(operations)} operations.")
    if loaded.learned_model is not None:
        console.print(f"Learned workflows: {learned_workflow_count}.")
    _print_preflight_warnings(loaded.warnings)


@app.command()
def generate(
    spec: Path,
    graphql_endpoint: Annotated[
        str,
        typer.Option(help="GraphQL endpoint path to use when generating from GraphQL schemas."),
    ] = "/graphql",
    out: Annotated[
        Path,
        typer.Option(help="Where to write the generated attack suite."),
    ] = Path("attacks.json"),
    operation: Annotated[
        list[str] | None,
        typer.Option(help="Only include attacks for these operation ids. Repeatable."),
    ] = None,
    exclude_operation: Annotated[
        list[str] | None,
        typer.Option(help="Exclude attacks for these operation ids. Repeatable."),
    ] = None,
    method: Annotated[
        list[str] | None,
        typer.Option(help="Only include attacks for these HTTP methods. Repeatable."),
    ] = None,
    exclude_method: Annotated[
        list[str] | None,
        typer.Option(help="Exclude attacks for these HTTP methods. Repeatable."),
    ] = None,
    kind: Annotated[
        list[str] | None,
        typer.Option(help="Only include attacks for these attack kinds. Repeatable."),
    ] = None,
    exclude_kind: Annotated[
        list[str] | None,
        typer.Option(help="Exclude attacks for these attack kinds. Repeatable."),
    ] = None,
    tag: Annotated[
        list[str] | None,
        typer.Option(help="Only include attacks for these tags. Repeatable."),
    ] = None,
    exclude_tag: Annotated[
        list[str] | None,
        typer.Option(help="Exclude attacks for these tags. Repeatable."),
    ] = None,
    path: Annotated[
        list[str] | None,
        typer.Option(help="Only include attacks for these exact OpenAPI paths. Repeatable."),
    ] = None,
    exclude_path: Annotated[
        list[str] | None,
        typer.Option(help="Exclude attacks for these exact OpenAPI paths. Repeatable."),
    ] = None,
    pack: Annotated[
        list[str] | None,
        typer.Option(help="Load custom attack packs from installed entry point names. Repeatable."),
    ] = None,
    pack_module: Annotated[
        list[Path] | None,
        typer.Option(help="Load custom attack packs from local Python module paths. Repeatable."),
    ] = None,
    auto_workflows: Annotated[
        bool,
        typer.Option(
            "--auto-workflows/--no-auto-workflows",
            help="Opt in to built-in setup+terminal workflow generation.",
        ),
    ] = False,
    workflow_pack: Annotated[
        list[str] | None,
        typer.Option(
            help="Load custom workflow packs from installed entry point names. Repeatable."
        ),
    ] = None,
    workflow_pack_module: Annotated[
        list[Path] | None,
        typer.Option(help="Load custom workflow packs from local Python module paths. Repeatable."),
    ] = None,
) -> None:
    """Generate a replayable attack suite from an OpenAPI, GraphQL, or learned model.

    Filters are applied after attack generation and before the suite is written.
    """
    generated = generate_suite_from_path(
        spec,
        graphql_endpoint=graphql_endpoint,
        operation=operation,
        exclude_operation=exclude_operation,
        method=method,
        exclude_method=exclude_method,
        kind=kind,
        exclude_kind=exclude_kind,
        tag=tag,
        exclude_tag=exclude_tag,
        path=path,
        exclude_path=exclude_path,
        pack_names=pack,
        pack_module_paths=pack_module,
        auto_workflows=auto_workflows,
        workflow_pack_names=workflow_pack,
        workflow_pack_module_paths=workflow_pack_module,
    )
    loaded = generated.loaded
    suite = generated.suite
    out.write_text(suite.model_dump_json(indent=2, exclude_none=True), encoding="utf-8")
    workflow_count = sum(1 for attack in suite.attacks if attack.type == "workflow")
    request_count = len(suite.attacks) - workflow_count
    console.print(
        f"Wrote {len(suite.attacks)} attack entries to [bold]{out}[/bold]. "
        f"({request_count} request attacks, {workflow_count} workflows)"
    )
    _print_preflight_warnings(loaded.warnings)


@app.command()
def run(
    attacks: Path,
    base_url: Annotated[
        str,
        typer.Option(help="Base URL of the target API."),
    ],
    out: Annotated[
        Path,
        typer.Option(help="Where to write execution results."),
    ] = Path("results.json"),
    header: Annotated[
        list[str] | None,
        typer.Option(help="Default header in the form 'Name: value'."),
    ] = None,
    query: Annotated[
        list[str] | None,
        typer.Option(help="Default query value in the form 'name=value'."),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option(help="HTTP or subscription timeout in seconds."),
    ] = 10.0,
    artifact_dir: Annotated[
        Path | None,
        typer.Option(help="Optional directory for per-attack request/response artifacts."),
    ] = None,
    auth_plugin: Annotated[
        list[str] | None,
        typer.Option(
            help="Load auth/session plugins from installed entry point names. Repeatable."
        ),
    ] = None,
    auth_plugin_module: Annotated[
        list[Path] | None,
        typer.Option(help="Load auth/session plugins from local Python module paths. Repeatable."),
    ] = None,
    auth_config: Annotated[
        Path | None,
        typer.Option(help="Optional built-in auth config YAML file."),
    ] = None,
    auth_profile: Annotated[
        list[str] | None,
        typer.Option(help="Only execute these named auth configs from --auth-config. Repeatable."),
    ] = None,
    profile_file: Annotated[
        Path | None,
        typer.Option(help="Optional auth profile YAML file for multi-profile execution."),
    ] = None,
    profile: Annotated[
        list[str] | None,
        typer.Option(help="Only execute these named auth profiles. Repeatable."),
    ] = None,
    operation: Annotated[
        list[str] | None,
        typer.Option(help="Only run attacks for these operation ids. Repeatable."),
    ] = None,
    exclude_operation: Annotated[
        list[str] | None,
        typer.Option(help="Exclude attacks for these operation ids. Repeatable."),
    ] = None,
    method: Annotated[
        list[str] | None,
        typer.Option(help="Only run attacks for these HTTP methods. Repeatable."),
    ] = None,
    exclude_method: Annotated[
        list[str] | None,
        typer.Option(help="Exclude attacks for these HTTP methods. Repeatable."),
    ] = None,
    kind: Annotated[
        list[str] | None,
        typer.Option(help="Only run attacks for these attack kinds. Repeatable."),
    ] = None,
    exclude_kind: Annotated[
        list[str] | None,
        typer.Option(help="Exclude attacks for these attack kinds. Repeatable."),
    ] = None,
    tag: Annotated[
        list[str] | None,
        typer.Option(help="Only run attacks for these tags. Repeatable."),
    ] = None,
    exclude_tag: Annotated[
        list[str] | None,
        typer.Option(help="Exclude attacks for these tags. Repeatable."),
    ] = None,
    path: Annotated[
        list[str] | None,
        typer.Option(help="Only run attacks for these exact OpenAPI paths. Repeatable."),
    ] = None,
    exclude_path: Annotated[
        list[str] | None,
        typer.Option(help="Exclude attacks for these exact OpenAPI paths. Repeatable."),
    ] = None,
) -> None:
    """Run a saved attack suite against a live API.

    Filters are applied to the loaded suite before any requests are executed.
    """
    try:
        run_result = run_suite(
            load_attack_suite_or_raise(attacks),
            base_url=base_url,
            default_headers=parse_key_value_map(header, separator=":"),
            default_query=parse_key_value_map(query, separator="="),
            timeout_seconds=timeout,
            artifact_dir=artifact_dir,
            auth_plugin_names=auth_plugin,
            auth_plugin_module_paths=auth_plugin_module,
            auth_config_path=auth_config,
            auth_profile_names=auth_profile,
            profile_file_path=profile_file,
            profile_names=profile,
            operation=operation,
            exclude_operation=exclude_operation,
            method=method,
            exclude_method=exclude_method,
            kind=kind,
            exclude_kind=exclude_kind,
            tag=tag,
            exclude_tag=exclude_tag,
            path=path,
            exclude_path=exclude_path,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    except PluginRuntimeError as exc:
        console.print(f"[red]Auth plugin error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    suite = run_result.suite
    results = run_result.results
    out.write_text(results.model_dump_json(indent=2, exclude_none=True), encoding="utf-8")

    flagged = sum(1 for result in results.results if result.flagged)
    auth_failures = sum(1 for event in results.auth_events if not event.success)
    if results.profiles:
        console.print(
            f"Executed {len(suite.attacks)} attacks across {len(results.profiles)} profile(s) "
            f"against [bold]{base_url}[/bold] and produced {len(results.results)} result(s). "
            f"Flagged {flagged} result(s). "
            f"Recorded {auth_failures} auth failure(s)."
        )
    else:
        console.print(
            f"Executed {len(results.results)} attacks against [bold]{base_url}[/bold]. "
            f"Flagged {flagged} result(s). "
            f"Recorded {auth_failures} auth failure(s)."
        )
    console.print(f"Wrote results to [bold]{out}[/bold].")


@app.command()
def export(
    results: Path,
    baseline: Annotated[
        Path | None,
        typer.Option(help="Optional baseline results file for regression comparison."),
    ] = None,
    suppressions: Annotated[
        Path | None,
        typer.Option(
            help="Optional suppressions file. Defaults to .knives-out-ignore.yml if present."
        ),
    ] = None,
    out: Annotated[
        Path | None,
        typer.Option(help="Optional export output file."),
    ] = None,
    format: Annotated[
        ExportFormatOption,
        typer.Option(help="Machine-readable export format."),
    ] = ExportFormatOption.sarif,
) -> None:
    """Render a machine-readable CI export from a results file."""
    try:
        export_result = export_results_from_paths(
            results,
            baseline_path=baseline,
            suppressions_path=suppressions,
            format=format.value,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    rendered = json.dumps(export_result.content, indent=2)
    if out is None:
        typer.echo(rendered)
        return

    out.write_text(rendered + "\n", encoding="utf-8")
    _print_suppression_summary(export_result.suppressions_path, export_result.suppressions)
    console.print(f"Wrote {format.value} export to [bold]{out}[/bold].")


@app.command()
def report(
    results: Path,
    baseline: Annotated[
        Path | None,
        typer.Option(help="Optional baseline results file for regression comparison."),
    ] = None,
    suppressions: Annotated[
        Path | None,
        typer.Option(
            help="Optional suppressions file. Defaults to .knives-out-ignore.yml if present."
        ),
    ] = None,
    out: Annotated[
        Path | None,
        typer.Option(help="Optional report output file."),
    ] = None,
    format: Annotated[
        ReportFormatOption,
        typer.Option(help="Report output format."),
    ] = ReportFormatOption.markdown,
    artifact_root: Annotated[
        Path | None,
        typer.Option(help="Optional artifact directory to index and link in HTML reports."),
    ] = None,
) -> None:
    """Render a report from a results file."""
    try:
        report_result = render_report_from_paths(
            results,
            baseline_path=baseline,
            suppressions_path=suppressions,
            format=format.value,
            artifact_root=artifact_root,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    if out is None:
        _print_suppression_summary(report_result.suppressions_path, report_result.suppressions)
        console.print(report_result.rendered)
        return

    out.write_text(report_result.rendered, encoding="utf-8")
    _print_suppression_summary(report_result.suppressions_path, report_result.suppressions)
    console.print(f"Wrote report to [bold]{out}[/bold].")


@app.command()
def summary(
    results: Path,
    baseline: Annotated[
        Path | None,
        typer.Option(help="Optional baseline results file for regression comparison."),
    ] = None,
    suppressions: Annotated[
        Path | None,
        typer.Option(
            help="Optional suppressions file. Defaults to .knives-out-ignore.yml if present."
        ),
    ] = None,
    out: Annotated[
        Path | None,
        typer.Option(help="Optional summary JSON output file."),
    ] = None,
    top: Annotated[
        int,
        typer.Option(help="How many top active findings to include in the summary."),
    ] = 10,
    format: Annotated[
        SummaryFormatOption,
        typer.Option(help="Summary output format."),
    ] = SummaryFormatOption.json,
) -> None:
    """Render a compact summary from a results file."""
    try:
        summary_result = summarize_results_from_paths(
            results,
            baseline_path=baseline,
            suppressions_path=suppressions,
            top_limit=top,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    if format == SummaryFormatOption.markdown:
        rendered = render_markdown_summary(summary_result.summary)
        format_label = "Markdown"
    else:
        rendered = json.dumps(
            summary_result.summary.model_dump(mode="json", exclude_none=True),
            indent=2,
        )
        format_label = "JSON"

    if out is None:
        typer.echo(rendered, nl=not rendered.endswith("\n"))
        return

    out.write_text(rendered if rendered.endswith("\n") else rendered + "\n", encoding="utf-8")
    _print_suppression_summary(summary_result.suppressions_path, summary_result.suppressions)
    console.print(f"Wrote summary {format_label} to [bold]{out}[/bold].")


@app.command()
def verify(
    results: Path,
    baseline: Annotated[
        Path | None,
        typer.Option(help="Optional baseline results file for regression comparison."),
    ] = None,
    suppressions: Annotated[
        Path | None,
        typer.Option(
            help="Optional suppressions file. Defaults to .knives-out-ignore.yml if present."
        ),
    ] = None,
    min_severity: Annotated[
        SeverityThresholdOption,
        typer.Option(help="Minimum severity that should fail verification."),
    ] = SeverityThresholdOption.high,
    min_confidence: Annotated[
        ConfidenceThresholdOption,
        typer.Option(help="Minimum confidence that should fail verification."),
    ] = ConfidenceThresholdOption.medium,
) -> None:
    """Verify results against CI policy, optionally compared to a baseline."""
    try:
        verify_result = verify_results_from_paths(
            results,
            baseline_path=baseline,
            suppressions_path=suppressions,
            min_severity=min_severity.value,
            min_confidence=min_confidence.value,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    verification = verify_result.verification
    comparison = verification.comparison

    console.print(
        "Verification policy: "
        f"severity >= [bold]{min_severity.value}[/bold], "
        f"confidence >= [bold]{min_confidence.value}[/bold]."
    )
    _print_suppression_summary(verify_result.suppressions_path, verify_result.suppressions)
    if verification.baseline_used:
        persisting_deltas = [
            finding
            for finding in comparison.persisting_findings
            if finding.delta is not None and finding.delta.changed
        ]
        console.print(
            "Compared current findings against a baseline. "
            f"New: {len(comparison.new_findings)}, "
            f"Resolved: {len(comparison.resolved_findings)}, "
            f"Persisting: {len(comparison.persisting_findings)}, "
            f"Persisting with deltas: {len(persisting_deltas)}, "
            f"Suppressed current: {len(comparison.suppressed_current_findings)}."
        )
        _print_compared_findings(
            "New findings meeting policy",
            verification.failing_findings,
        )
        _print_persisting_delta_findings(comparison.persisting_findings)
    else:
        console.print(
            "Evaluated current flagged findings only. "
            f"Active flagged: {len(comparison.current_findings)}, "
            f"suppressed: {len(comparison.suppressed_current_findings)}, "
            f"meeting policy: {len(verification.failing_findings)}."
        )
        _print_compared_findings(
            "Current findings meeting policy",
            verification.failing_findings,
        )

    if verification.passed:
        console.print("Verification passed.")
        return

    console.print("Verification failed.")
    raise typer.Exit(code=1)


@app.command()
def promote(
    results: Path,
    attacks: Annotated[
        Path,
        typer.Option(help="Attack suite JSON used to produce the results."),
    ],
    out: Annotated[
        Path,
        typer.Option(help="Where to write the promoted regression attack suite."),
    ] = Path("regression-attacks.json"),
    baseline: Annotated[
        Path | None,
        typer.Option(help="Optional baseline results file for regression comparison."),
    ] = None,
    suppressions: Annotated[
        Path | None,
        typer.Option(
            help="Optional suppressions file. Defaults to .knives-out-ignore.yml if present."
        ),
    ] = None,
    min_severity: Annotated[
        SeverityThresholdOption,
        typer.Option(help="Minimum severity that should be promoted."),
    ] = SeverityThresholdOption.high,
    min_confidence: Annotated[
        ConfidenceThresholdOption,
        typer.Option(help="Minimum confidence that should be promoted."),
    ] = ConfidenceThresholdOption.medium,
) -> None:
    """Promote qualifying findings back into a reusable attack suite."""
    try:
        promote_result = promote_results_from_paths(
            results,
            attacks,
            baseline_path=baseline,
            suppressions_path=suppressions,
            min_severity=min_severity.value,
            min_confidence=min_confidence.value,
        )
    except PromotionError as exc:
        console.print(f"[red]Promotion error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    promotion = promote_result.promotion

    out.write_text(
        promotion.promoted_suite.model_dump_json(indent=2, exclude_none=True),
        encoding="utf-8",
    )

    console.print(
        "Promotion policy: "
        f"severity >= [bold]{min_severity.value}[/bold], "
        f"confidence >= [bold]{min_confidence.value}[/bold]."
    )
    _print_suppression_summary(promote_result.suppressions_path, promote_result.suppressions)
    if promotion.verification.baseline_used:
        console.print(
            "Promoted new qualifying attacks against a baseline. "
            f"Qualifying attacks: {len(promotion.promoted_attack_ids)}."
        )
    else:
        console.print(
            "Promoted qualifying attacks from the current results only. "
            f"Qualifying attacks: {len(promotion.promoted_attack_ids)}."
        )
    console.print(
        f"Wrote {len(promotion.promoted_suite.attacks)} promoted attack(s) to [bold]{out}[/bold]."
    )


@app.command()
def triage(
    results: Path,
    out: Annotated[
        Path,
        typer.Option(help="Where to write the suppressions file."),
    ] = DEFAULT_SUPPRESSIONS_PATH,
) -> None:
    """Append review-ready suppressions for current active findings."""
    try:
        triage_result = triage_results_from_path(results, out_path=out)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    console.print(
        f"Triaged {len(triage_result.comparison.current_findings)} active finding(s). "
        f"Added {triage_result.added_count} suppression rule(s)."
    )
    console.print(f"Wrote suppressions to [bold]{out}[/bold].")


@app.command()
def serve(
    host: Annotated[
        str,
        typer.Option(help="Host interface for the local knives-out API."),
    ] = "127.0.0.1",
    port: Annotated[
        int,
        typer.Option(help="Port for the local knives-out API."),
    ] = 8787,
    data_dir: Annotated[
        Path | None,
        typer.Option(help="Optional data directory for API jobs and artifacts."),
    ] = None,
) -> None:
    """Start the local-first knives-out HTTP API."""
    uvicorn.run(create_app(data_dir=data_dir), host=host, port=port)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
