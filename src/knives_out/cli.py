from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from knives_out.attack_packs import load_attack_packs
from knives_out.auth_plugins import PluginRuntimeError, load_auth_plugins
from knives_out.filtering import filter_attack_suite, filter_operations
from knives_out.generator import generate_attack_suite
from knives_out.models import AttackResults, PreflightWarning
from knives_out.openapi_loader import load_operations_with_warnings
from knives_out.reporting import load_attack_results, render_markdown_report
from knives_out.runner import execute_attack_suite, load_attack_suite
from knives_out.verification import ComparedFinding, evaluate_verification
from knives_out.workflow_packs import load_workflow_packs

app = typer.Typer(no_args_is_help=True, help="Adversarial API testing from OpenAPI specs.")
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


def _parse_key_value(items: list[str] | None, *, separator: str) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    for item in items or []:
        if separator not in item:
            raise typer.BadParameter(f"Expected '{separator}' in value: {item!r}")
        key, value = item.split(separator, 1)
        key = key.strip()
        value = value.strip()
        if not key:
            raise typer.BadParameter(f"Missing key in value: {item!r}")
        parsed[key] = value
    return parsed


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


def _load_attack_results_or_error(path: Path, *, label: str) -> AttackResults:
    try:
        return load_attack_results(path)
    except (OSError, ValidationError, ValueError) as exc:
        raise typer.BadParameter(f"Could not read {label} results file '{path}': {exc}") from exc


def _print_compared_findings(title: str, findings: list[ComparedFinding]) -> None:
    if not findings:
        return

    table = Table(title=title)
    table.add_column("Attack")
    table.add_column("Issue")
    table.add_column("Severity")
    table.add_column("Confidence")
    table.add_column("Status")

    for finding in findings:
        result = finding.result
        table.add_row(
            result.name,
            result.issue or "-",
            result.severity,
            result.confidence,
            str(result.status_code) if result.status_code is not None else "-",
        )

    console.print("")
    console.print(table)


@app.command()
def inspect(
    spec: Path,
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
) -> None:
    """Show the operations discovered in an OpenAPI spec."""
    loaded = load_operations_with_warnings(spec)
    operations = filter_operations(
        loaded.operations,
        include_paths=path,
        exclude_paths=exclude_path,
        include_tags=tag,
        exclude_tags=exclude_tag,
    )

    table = Table(title=f"knives-out inspect: {spec}")
    table.add_column("Operation ID")
    table.add_column("Method")
    table.add_column("Path")
    table.add_column("Params")
    table.add_column("Body")
    table.add_column("Auth")

    for operation in operations:
        table.add_row(
            operation.operation_id,
            operation.method,
            operation.path,
            str(len(operation.parameters)),
            "yes" if operation.request_body_schema else "no",
            "yes" if operation.auth_required else "no",
        )

    console.print(table)
    console.print(f"\nFound {len(operations)} operations.")
    _print_preflight_warnings(loaded.warnings)


@app.command()
def generate(
    spec: Path,
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
    """Generate a replayable attack suite from an OpenAPI spec.

    Filters are applied after attack generation and before the suite is written.
    """
    loaded = load_operations_with_warnings(spec)
    operations = loaded.operations
    attack_packs = load_attack_packs(entry_point_names=pack, module_paths=pack_module)
    workflow_packs = load_workflow_packs(
        entry_point_names=workflow_pack,
        module_paths=workflow_pack_module,
    )
    suite = generate_attack_suite(
        operations,
        source=str(spec),
        extra_packs=attack_packs,
        auto_workflows=auto_workflows,
        workflow_packs=workflow_packs,
    )
    suite = filter_attack_suite(
        suite,
        include_operations=operation,
        exclude_operations=exclude_operation,
        include_methods=method,
        exclude_methods=exclude_method,
        include_kinds=kind,
        exclude_kinds=exclude_kind,
        include_paths=path,
        exclude_paths=exclude_path,
        include_tags=tag,
        exclude_tags=exclude_tag,
    )
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
        typer.Option(help="HTTP timeout in seconds."),
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
    suite = load_attack_suite(attacks)
    suite = filter_attack_suite(
        suite,
        include_operations=operation,
        exclude_operations=exclude_operation,
        include_methods=method,
        exclude_methods=exclude_method,
        include_kinds=kind,
        exclude_kinds=exclude_kind,
        include_paths=path,
        exclude_paths=exclude_path,
        include_tags=tag,
        exclude_tags=exclude_tag,
    )
    default_headers = _parse_key_value(header, separator=":")
    default_query = _parse_key_value(query, separator="=")
    try:
        auth_plugins = load_auth_plugins(
            entry_point_names=auth_plugin,
            module_paths=auth_plugin_module,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    try:
        results = execute_attack_suite(
            suite,
            base_url=base_url,
            default_headers=default_headers,
            default_query=default_query,
            timeout_seconds=timeout,
            artifact_dir=artifact_dir,
            auth_plugins=auth_plugins,
        )
    except PluginRuntimeError as exc:
        console.print(f"[red]Auth plugin error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    out.write_text(results.model_dump_json(indent=2, exclude_none=True), encoding="utf-8")

    flagged = sum(1 for result in results.results if result.flagged)
    console.print(
        f"Executed {len(results.results)} attacks against [bold]{base_url}[/bold]. "
        f"Flagged {flagged} result(s)."
    )
    console.print(f"Wrote results to [bold]{out}[/bold].")


@app.command()
def report(
    results: Path,
    baseline: Annotated[
        Path | None,
        typer.Option(help="Optional baseline results file for regression comparison."),
    ] = None,
    out: Annotated[
        Path | None,
        typer.Option(help="Optional Markdown output file."),
    ] = None,
) -> None:
    """Render a Markdown report from a results file."""
    attack_results = _load_attack_results_or_error(results, label="current")
    baseline_results = (
        _load_attack_results_or_error(baseline, label="baseline") if baseline is not None else None
    )
    markdown = render_markdown_report(attack_results, baseline=baseline_results)

    if out is None:
        console.print(markdown)
        return

    out.write_text(markdown, encoding="utf-8")
    console.print(f"Wrote report to [bold]{out}[/bold].")


@app.command()
def verify(
    results: Path,
    baseline: Annotated[
        Path | None,
        typer.Option(help="Optional baseline results file for regression comparison."),
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
    attack_results = _load_attack_results_or_error(results, label="current")
    baseline_results = (
        _load_attack_results_or_error(baseline, label="baseline") if baseline is not None else None
    )
    verification = evaluate_verification(
        attack_results,
        baseline=baseline_results,
        min_severity=min_severity.value,
        min_confidence=min_confidence.value,
    )
    comparison = verification.comparison

    console.print(
        "Verification policy: "
        f"severity >= [bold]{min_severity.value}[/bold], "
        f"confidence >= [bold]{min_confidence.value}[/bold]."
    )
    if verification.baseline_used:
        console.print(
            "Compared current findings against a baseline. "
            f"New: {len(comparison.new_findings)}, "
            f"Resolved: {len(comparison.resolved_findings)}, "
            f"Persisting: {len(comparison.persisting_findings)}."
        )
        _print_compared_findings(
            "New findings meeting policy",
            verification.failing_findings,
        )
    else:
        console.print(
            "Evaluated current flagged findings only. "
            f"Flagged: {len(comparison.current_findings)}, "
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


def main() -> None:
    app()


if __name__ == "__main__":
    main()
