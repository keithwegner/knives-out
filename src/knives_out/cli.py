from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from knives_out.attack_packs import load_attack_packs
from knives_out.auth_config import (
    auth_config_map,
    auth_profiles_from_configs,
    load_auth_configs,
    select_auth_configs,
)
from knives_out.auth_plugins import PluginRuntimeError, load_auth_plugins
from knives_out.capture import serve_capture_proxy
from knives_out.filtering import filter_attack_suite, filter_operations
from knives_out.generator import generate_attack_suite
from knives_out.learned_discovery import discover_learned_model
from knives_out.models import AttackResults, AuthProfile, PreflightWarning
from knives_out.profiles import (
    load_auth_profiles,
    resolve_auth_profile_modules,
    select_auth_profiles,
)
from knives_out.promotion import PromotionError, promote_attack_suite
from knives_out.reporting import (
    load_attack_results,
    render_html_report,
    render_markdown_report,
)
from knives_out.runner import (
    execute_attack_suite,
    execute_attack_suite_profiles,
    load_attack_suite,
)
from knives_out.spec_loader import load_operations_with_warnings
from knives_out.suppressions import (
    DEFAULT_SUPPRESSIONS_PATH,
    SuppressionRule,
    SuppressionsFile,
    load_suppressions,
    merge_suppressions,
    triage_rule_for_result,
    write_suppressions,
)
from knives_out.verification import (
    ComparedFinding,
    compare_attack_results,
    evaluate_verification,
)
from knives_out.workflow_packs import load_workflow_packs

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


def _load_suppressions_or_error(
    path: Path | None,
) -> tuple[Path | None, list[SuppressionRule]]:
    resolved_path = path
    if resolved_path is None and DEFAULT_SUPPRESSIONS_PATH.exists():
        resolved_path = DEFAULT_SUPPRESSIONS_PATH
    if resolved_path is None:
        return None, []

    try:
        suppressions_file = load_suppressions(resolved_path)
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(
            f"Could not read suppressions file '{resolved_path}': {exc}"
        ) from exc

    return resolved_path, suppressions_file.suppressions


def _load_auth_profiles_or_error(
    path: Path | None,
    *,
    include_names: list[str] | None = None,
) -> list[AuthProfile]:
    if path is None:
        if include_names:
            raise typer.BadParameter("--profile requires --profile-file.")
        return []

    try:
        profiles_file = load_auth_profiles(path)
        selected_profiles = select_auth_profiles(profiles_file, include_names=include_names)
        return resolve_auth_profile_modules(selected_profiles, relative_to=path)
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(f"Could not read auth profile file '{path}': {exc}") from exc


def _load_auth_configs_or_error(
    path: Path | None,
    *,
    include_names: list[str] | None = None,
):
    if path is None:
        if include_names:
            raise typer.BadParameter("--auth-profile requires --auth-config.")
        return []

    try:
        auth_file = load_auth_configs(path)
        selected_configs = select_auth_configs(auth_file, include_names=include_names)
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(f"Could not read auth config file '{path}': {exc}") from exc

    if not selected_configs:
        raise typer.BadParameter(f"Auth config file '{path}' did not define any auth entries.")
    return selected_configs


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
    learned_model = discover_learned_model(inputs)
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
) -> None:
    """Show the operations discovered in an OpenAPI, GraphQL, or learned model."""
    loaded = load_operations_with_warnings(spec, graphql_endpoint=graphql_endpoint)
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
        console.print(f"Learned workflows: {len(loaded.learned_model.workflows)}.")
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
    loaded = load_operations_with_warnings(spec, graphql_endpoint=graphql_endpoint)
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
        learned_model=loaded.learned_model,
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
    auth_profiles = _load_auth_profiles_or_error(profile_file, include_names=profile)
    built_in_auth_configs = _load_auth_configs_or_error(auth_config, include_names=auth_profile)
    built_in_auth_by_name = auth_config_map(built_in_auth_configs)
    global_auth_plugin_modules = [str(path.resolve()) for path in auth_plugin_module or []]

    if auth_profiles or built_in_auth_configs:
        if not auth_profiles:
            auth_profiles = auth_profiles_from_configs(built_in_auth_configs)
        auth_profiles = [
            auth_profile.model_copy(
                update={
                    "auth_plugins": [*(auth_plugin or []), *auth_profile.auth_plugins],
                    "auth_plugin_modules": [
                        *global_auth_plugin_modules,
                        *auth_profile.auth_plugin_modules,
                    ],
                }
            )
            for auth_profile in auth_profiles
        ]
        auth_plugins = None
    else:
        try:
            auth_plugins = load_auth_plugins(
                entry_point_names=auth_plugin,
                module_paths=auth_plugin_module,
            )
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc

    try:
        if auth_profiles:
            results = execute_attack_suite_profiles(
                suite,
                base_url=base_url,
                profiles=auth_profiles,
                default_headers=default_headers,
                default_query=default_query,
                timeout_seconds=timeout,
                artifact_dir=artifact_dir,
                built_in_auth_configs=built_in_auth_by_name,
            )
        else:
            results = execute_attack_suite(
                suite,
                base_url=base_url,
                default_headers=default_headers,
                default_query=default_query,
                timeout_seconds=timeout,
                artifact_dir=artifact_dir,
                auth_plugins=auth_plugins,
                built_in_auth_configs=built_in_auth_configs,
            )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    except PluginRuntimeError as exc:
        console.print(f"[red]Auth plugin error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
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
    attack_results = _load_attack_results_or_error(results, label="current")
    baseline_results = (
        _load_attack_results_or_error(baseline, label="baseline") if baseline is not None else None
    )
    suppressions_path, suppression_rules = _load_suppressions_or_error(suppressions)

    if format is ReportFormatOption.html:
        rendered = render_html_report(
            attack_results,
            baseline=baseline_results,
            suppressions=suppression_rules,
            artifact_root=artifact_root,
        )
    else:
        rendered = render_markdown_report(
            attack_results,
            baseline=baseline_results,
            suppressions=suppression_rules,
        )

    if out is None:
        _print_suppression_summary(suppressions_path, suppression_rules)
        console.print(rendered)
        return

    out.write_text(rendered, encoding="utf-8")
    _print_suppression_summary(suppressions_path, suppression_rules)
    console.print(f"Wrote report to [bold]{out}[/bold].")


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
    attack_results = _load_attack_results_or_error(results, label="current")
    baseline_results = (
        _load_attack_results_or_error(baseline, label="baseline") if baseline is not None else None
    )
    suppressions_path, suppression_rules = _load_suppressions_or_error(suppressions)
    verification = evaluate_verification(
        attack_results,
        baseline=baseline_results,
        min_severity=min_severity.value,
        min_confidence=min_confidence.value,
        suppressions=suppression_rules,
    )
    comparison = verification.comparison

    console.print(
        "Verification policy: "
        f"severity >= [bold]{min_severity.value}[/bold], "
        f"confidence >= [bold]{min_confidence.value}[/bold]."
    )
    _print_suppression_summary(suppressions_path, suppression_rules)
    if verification.baseline_used:
        console.print(
            "Compared current findings against a baseline. "
            f"New: {len(comparison.new_findings)}, "
            f"Resolved: {len(comparison.resolved_findings)}, "
            f"Persisting: {len(comparison.persisting_findings)}, "
            f"Suppressed current: {len(comparison.suppressed_current_findings)}."
        )
        _print_compared_findings(
            "New findings meeting policy",
            verification.failing_findings,
        )
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
    current_results = _load_attack_results_or_error(results, label="current")
    baseline_results = (
        _load_attack_results_or_error(baseline, label="baseline") if baseline is not None else None
    )
    suppressions_path, suppression_rules = _load_suppressions_or_error(suppressions)

    try:
        attack_suite = load_attack_suite(attacks)
    except (OSError, ValidationError, ValueError) as exc:
        raise typer.BadParameter(f"Could not read attacks file '{attacks}': {exc}") from exc

    try:
        promotion = promote_attack_suite(
            current_results,
            attack_suite,
            baseline=baseline_results,
            min_severity=min_severity.value,
            min_confidence=min_confidence.value,
            suppressions=suppression_rules,
        )
    except PromotionError as exc:
        console.print(f"[red]Promotion error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    out.write_text(
        promotion.promoted_suite.model_dump_json(indent=2, exclude_none=True),
        encoding="utf-8",
    )

    console.print(
        "Promotion policy: "
        f"severity >= [bold]{min_severity.value}[/bold], "
        f"confidence >= [bold]{min_confidence.value}[/bold]."
    )
    _print_suppression_summary(suppressions_path, suppression_rules)
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
    current_results = _load_attack_results_or_error(results, label="current")

    existing_file = SuppressionsFile()
    if out.exists():
        try:
            existing_file = load_suppressions(out)
        except (OSError, ValueError) as exc:
            raise typer.BadParameter(f"Could not read suppressions file '{out}': {exc}") from exc

    comparison = compare_attack_results(
        current_results,
        suppressions=existing_file.suppressions,
    )
    generated_rules = [triage_rule_for_result(result) for result in comparison.current_findings]
    merged_rules = merge_suppressions(existing_file.suppressions, generated_rules)
    added_count = len(merged_rules) - len(existing_file.suppressions)

    write_suppressions(out, SuppressionsFile(suppressions=merged_rules))

    console.print(
        f"Triaged {len(comparison.current_findings)} active finding(s). "
        f"Added {added_count} suppression rule(s)."
    )
    console.print(f"Wrote suppressions to [bold]{out}[/bold].")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
