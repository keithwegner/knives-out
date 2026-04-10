from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from knives_out.filtering import filter_attack_suite
from knives_out.generator import generate_attack_suite
from knives_out.openapi_loader import load_operations
from knives_out.reporting import load_attack_results, render_markdown_report
from knives_out.runner import execute_attack_suite, load_attack_suite

app = typer.Typer(no_args_is_help=True, help="Adversarial API testing from OpenAPI specs.")
console = Console()


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


@app.command()
def inspect(spec: Path) -> None:
    """Show the operations discovered in an OpenAPI spec."""
    operations = load_operations(spec)

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
) -> None:
    """Generate a replayable attack suite from an OpenAPI spec.

    Filters are applied after attack generation and before the suite is written.
    """
    operations = load_operations(spec)
    suite = generate_attack_suite(operations, source=str(spec))
    suite = filter_attack_suite(
        suite,
        include_operations=operation,
        exclude_operations=exclude_operation,
        include_methods=method,
        exclude_methods=exclude_method,
        include_kinds=kind,
        exclude_kinds=exclude_kind,
    )
    out.write_text(suite.model_dump_json(indent=2, exclude_none=True), encoding="utf-8")
    console.print(f"Wrote {len(suite.attacks)} attacks to [bold]{out}[/bold].")


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
    )
    default_headers = _parse_key_value(header, separator=":")
    default_query = _parse_key_value(query, separator="=")
    results = execute_attack_suite(
        suite,
        base_url=base_url,
        default_headers=default_headers,
        default_query=default_query,
        timeout_seconds=timeout,
        artifact_dir=artifact_dir,
    )
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
    out: Annotated[
        Path | None,
        typer.Option(help="Optional Markdown output file."),
    ] = None,
) -> None:
    """Render a Markdown report from a results file."""
    attack_results = load_attack_results(results)
    markdown = render_markdown_report(attack_results)

    if out is None:
        console.print(markdown)
        return

    out.write_text(markdown, encoding="utf-8")
    console.print(f"Wrote report to [bold]{out}[/bold].")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
