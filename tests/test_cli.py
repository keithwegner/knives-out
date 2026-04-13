import json
import re
from pathlib import Path
from textwrap import dedent

from fastapi import FastAPI
from typer.testing import CliRunner

from knives_out.auth_plugins import PluginRuntimeError
from knives_out.cli import app
from knives_out.models import (
    AttackCase,
    AttackResult,
    AttackResults,
    AttackSuite,
    LoadedOperations,
    PreflightWarning,
)
from knives_out.suppressions import load_suppressions

runner = CliRunner()
EXAMPLE_SPEC = Path(__file__).resolve().parents[1] / "examples" / "openapi" / "petstore.yaml"
GRAPHQL_EXAMPLE_SPEC = (
    Path(__file__).resolve().parents[1] / "examples" / "graphql" / "library.graphql"
)


def _graphql_subscription_schema_text() -> str:
    return dedent(
        """
        type Query {
          health: String!
        }

        type Subscription {
          bookEvents(id: ID!): Book!
        }

        type Book {
          id: ID!
          title: String!
          rating: Int
        }
        """
    ).strip()


def _write_results(path: Path, results: AttackResults) -> None:
    path.write_text(results.model_dump_json(indent=2, exclude_none=True), encoding="utf-8")


def _results_with_findings(*results: AttackResult) -> AttackResults:
    return AttackResults(
        source="unit",
        base_url="https://example.com",
        results=list(results),
    )


def _normalized_output(output: str) -> str:
    return re.sub(r"\s+", " ", output).strip()


def test_inspect_command_runs() -> None:
    result = runner.invoke(app, ["inspect", str(EXAMPLE_SPEC)])

    assert result.exit_code == 0
    assert "Found 3 operations." in result.stdout


def test_inspect_command_shows_preflight_warnings(monkeypatch) -> None:
    monkeypatch.setattr(
        "knives_out.services.load_operations_with_warnings",
        lambda spec, **_: LoadedOperations(
            operations=[],
            warnings=[
                PreflightWarning(
                    code="missing_request_schema",
                    message="Request body is declared but no usable schema was found.",
                    operation_id="createPet",
                    method="POST",
                    path="/pets",
                )
            ],
        ),
    )

    result = runner.invoke(app, ["inspect", str(EXAMPLE_SPEC)])

    assert result.exit_code == 0
    assert "Preflight warnings" in result.stdout
    assert "missing_request_schema" in result.stdout
    assert "createPet" in result.stdout


def test_inspect_command_filters_operations_by_tag(monkeypatch) -> None:
    monkeypatch.setattr(
        "knives_out.services.load_operations_with_warnings",
        lambda spec, **_: LoadedOperations(
            operations=[
                {
                    "operation_id": "listPets",
                    "method": "GET",
                    "path": "/pets",
                    "tags": ["pets", "read"],
                },
                {
                    "operation_id": "createPet",
                    "method": "POST",
                    "path": "/pets",
                    "tags": ["pets", "write"],
                },
            ],
            warnings=[],
        ),
    )

    result = runner.invoke(app, ["inspect", str(EXAMPLE_SPEC), "--tag", "write"])

    assert result.exit_code == 0
    assert "createPet" in result.stdout
    assert "listPets" not in result.stdout
    assert "Found 1 operations." in result.stdout


def test_inspect_command_supports_graphql_schema(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "inspect",
            str(GRAPHQL_EXAMPLE_SPEC),
            "--graphql-endpoint",
            "/api/graphql",
        ],
    )

    assert result.exit_code == 0
    assert "Found 4 operations." in result.stdout
    assert "/api/graphql" in result.stdout


def test_inspect_command_supports_graphql_subscription_schema(tmp_path: Path) -> None:
    schema_path = tmp_path / "subscriptions.graphql"
    schema_path.write_text(_graphql_subscription_schema_text(), encoding="utf-8")

    result = runner.invoke(app, ["inspect", str(schema_path)])

    assert result.exit_code == 0
    assert "Found 2 operations." in result.stdout
    assert "bookEvents" in result.stdout
    assert "SUBSCRIBE" in result.stdout


def test_inspect_command_supports_json_output(monkeypatch) -> None:
    monkeypatch.setattr(
        "knives_out.services.load_operations_with_warnings",
        lambda spec, **_: LoadedOperations(
            source_kind="learned",
            operations=[
                {
                    "operation_id": "listPets",
                    "method": "GET",
                    "path": "/pets",
                    "tags": ["pets", "read"],
                    "parameters": [{"name": "limit", "location": "query"}],
                    "auth_required": False,
                    "learned_confidence": 0.75,
                },
                {
                    "operation_id": "createPet",
                    "method": "POST",
                    "path": "/pets",
                    "tags": ["pets", "write"],
                    "request_body_schema": {"type": "object"},
                    "auth_required": True,
                },
            ],
            warnings=[
                PreflightWarning(
                    code="missing_request_schema",
                    message="Request body is declared but no usable schema was found.",
                    operation_id="createPet",
                    method="POST",
                    path="/pets",
                )
            ],
            learned_model={
                "workflows": [
                    {
                        "id": "wf_create_pet",
                        "name": "Create pet flow",
                        "producer_operation_id": "createPet",
                        "consumer_operation_id": "listPets",
                    }
                ]
            },
        ),
    )

    result = runner.invoke(
        app,
        ["inspect", str(EXAMPLE_SPEC), "--tag", "write", "--format", "json"],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["source"] == str(EXAMPLE_SPEC)
    assert payload["source_kind"] == "learned"
    assert payload["operation_count"] == 1
    assert payload["warning_count"] == 1
    assert payload["learned_workflow_count"] == 1
    assert [operation["operation_id"] for operation in payload["operations"]] == ["createPet"]
    assert payload["warnings"][0]["code"] == "missing_request_schema"


def test_generate_command_writes_attack_suite(tmp_path: Path) -> None:
    out_path = tmp_path / "attacks.json"
    result = runner.invoke(app, ["generate", str(EXAMPLE_SPEC), "--out", str(out_path)])

    assert result.exit_code == 0
    assert out_path.exists()
    suite = AttackSuite.model_validate_json(out_path.read_text(encoding="utf-8"))
    assert suite.attacks
    assert all(attack.type == "request" for attack in suite.attacks)


def test_generate_command_supports_graphql_schema(tmp_path: Path) -> None:
    out_path = tmp_path / "graphql-attacks.json"
    result = runner.invoke(app, ["generate", str(GRAPHQL_EXAMPLE_SPEC), "--out", str(out_path)])

    assert result.exit_code == 0
    suite = AttackSuite.model_validate_json(out_path.read_text(encoding="utf-8"))
    assert any(attack.kind == "wrong_type_variable" for attack in suite.attacks)
    assert all(attack.path == "/graphql" for attack in suite.attacks)


def test_generate_command_supports_graphql_subscription_schema(tmp_path: Path) -> None:
    schema_path = tmp_path / "subscriptions.graphql"
    schema_path.write_text(_graphql_subscription_schema_text(), encoding="utf-8")
    out_path = tmp_path / "graphql-subscriptions.json"

    result = runner.invoke(app, ["generate", str(schema_path), "--out", str(out_path)])

    assert result.exit_code == 0
    suite = AttackSuite.model_validate_json(out_path.read_text(encoding="utf-8"))
    assert any(attack.method == "SUBSCRIBE" for attack in suite.attacks)
    assert any(attack.graphql_operation_type == "subscription" for attack in suite.attacks)


def test_generate_command_supports_auto_workflows(tmp_path: Path) -> None:
    out_path = tmp_path / "attacks.json"

    result = runner.invoke(
        app,
        [
            "generate",
            str(EXAMPLE_SPEC),
            "--auto-workflows",
            "--out",
            str(out_path),
        ],
    )

    assert result.exit_code == 0
    suite = AttackSuite.model_validate_json(out_path.read_text(encoding="utf-8"))
    assert any(attack.type == "workflow" for attack in suite.attacks)


def test_report_command_supports_baseline(tmp_path: Path) -> None:
    current_path = tmp_path / "current.json"
    baseline_path = tmp_path / "baseline.json"
    report_path = tmp_path / "report.md"

    _write_results(
        current_path,
        _results_with_findings(
            AttackResult(
                attack_id="atk_new",
                operation_id="createPet",
                kind="missing_request_body",
                name="New server failure",
                method="POST",
                url="https://example.com/pets",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
            ),
            AttackResult(
                attack_id="atk_shared",
                operation_id="createPet",
                kind="wrong_type_param",
                name="Persisting mismatch",
                method="POST",
                url="https://example.com/pets",
                status_code=500,
                flagged=True,
                issue="response_schema_mismatch",
                severity="high",
                confidence="high",
            ),
        ),
    )
    _write_results(
        baseline_path,
        _results_with_findings(
            AttackResult(
                attack_id="atk_shared",
                operation_id="createPet",
                kind="wrong_type_param",
                name="Persisting mismatch",
                method="POST",
                url="https://example.com/pets",
                status_code=401,
                flagged=True,
                issue="response_schema_mismatch",
                severity="medium",
                confidence="low",
            ),
            AttackResult(
                attack_id="atk_old",
                operation_id="listPets",
                kind="missing_auth",
                name="Resolved auth failure",
                method="GET",
                url="https://example.com/pets",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
            ),
        ),
    )

    result = runner.invoke(
        app,
        [
            "report",
            str(current_path),
            "--baseline",
            str(baseline_path),
            "--out",
            str(report_path),
        ],
    )

    assert result.exit_code == 0
    report = report_path.read_text(encoding="utf-8")
    assert "## Verification summary" in report
    assert "## New findings" in report
    assert "## Resolved findings" in report
    assert "## Persisting findings" in report
    assert "Persisting findings with deltas: **1**" in report
    assert "severity medium -> high; confidence low -> high; status 401 -> 500" in report


def test_report_command_shows_persisting_deltas(tmp_path: Path) -> None:
    current_path = tmp_path / "current.json"
    baseline_path = tmp_path / "baseline.json"
    report_path = tmp_path / "report.md"

    _write_results(
        current_path,
        _results_with_findings(
            AttackResult(
                attack_id="atk_shared",
                operation_id="createPet",
                kind="wrong_type_param",
                name="Persisting mismatch",
                method="POST",
                url="https://example.com/pets",
                status_code=500,
                flagged=True,
                issue="response_schema_mismatch",
                severity="high",
                confidence="medium",
                response_schema_valid=False,
            )
        ),
    )
    _write_results(
        baseline_path,
        _results_with_findings(
            AttackResult(
                attack_id="atk_shared",
                operation_id="createPet",
                kind="wrong_type_param",
                name="Persisting mismatch",
                method="POST",
                url="https://example.com/pets",
                status_code=200,
                flagged=True,
                issue="response_schema_mismatch",
                severity="medium",
                confidence="high",
                response_schema_valid=True,
            )
        ),
    )

    result = runner.invoke(
        app,
        [
            "report",
            str(current_path),
            "--baseline",
            str(baseline_path),
            "--out",
            str(report_path),
        ],
    )

    assert result.exit_code == 0
    report = report_path.read_text(encoding="utf-8")
    assert "## Persisting deltas" in report
    assert "status 200 -> 500" in report
    assert "severity medium -> high" in report
    assert "confidence high -> medium" in report
    assert "schema ok -> mismatch" in report


def test_summary_command_writes_json_summary(tmp_path: Path) -> None:
    results_path = tmp_path / "results.json"
    summary_path = tmp_path / "summary.json"
    _write_results(
        results_path,
        _results_with_findings(
            AttackResult(
                attack_id="atk_server",
                operation_id="createPet",
                kind="missing_request_body",
                name="Server failure",
                method="POST",
                url="https://example.com/pets",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
            )
        ),
    )

    result = runner.invoke(
        app,
        [
            "summary",
            str(results_path),
            "--out",
            str(summary_path),
            "--top",
            "5",
        ],
    )

    assert result.exit_code == 0
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["active_flagged_count"] == 1
    assert summary["issue_counts"]["server_error"] == 1
    assert summary["top_findings"][0]["attack_id"] == "atk_server"


def test_summary_command_prints_json_to_stdout(tmp_path: Path) -> None:
    results_path = tmp_path / "results.json"
    _write_results(
        results_path,
        _results_with_findings(
            AttackResult(
                attack_id="atk_graphql",
                operation_id="book",
                kind="wrong_type_variable",
                name="GraphQL mismatch",
                protocol="graphql",
                method="POST",
                path="/graphql",
                url="https://example.com/graphql",
                status_code=200,
                flagged=True,
                issue="graphql_response_shape_mismatch",
                severity="medium",
                confidence="high",
                graphql_response_valid=False,
            )
        ),
    )

    result = runner.invoke(app, ["summary", str(results_path), "--top", "1"])

    assert result.exit_code == 0
    summary = json.loads(result.stdout)
    assert summary["protocol_counts"]["graphql"] == 1
    assert summary["graphql_shape_mismatches"] == 1
    assert summary["top_findings"][0]["schema_status"] == "graphql-mismatch"


def test_report_command_supports_html_and_artifact_links(tmp_path: Path) -> None:
    results_path = tmp_path / "results.json"
    report_path = tmp_path / "report.html"
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    (artifact_root / "atk_html.json").write_text("{}", encoding="utf-8")

    _write_results(
        results_path,
        _results_with_findings(
            AttackResult(
                attack_id="atk_html",
                operation_id="createPet",
                kind="missing_request_body",
                name="HTML failure",
                method="POST",
                url="https://example.com/pets",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
            )
        ),
    )

    result = runner.invoke(
        app,
        [
            "report",
            str(results_path),
            "--format",
            "html",
            "--artifact-root",
            str(artifact_root),
            "--out",
            str(report_path),
        ],
    )

    assert result.exit_code == 0
    report = report_path.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in report
    assert "<h2>Artifact index</h2>" in report
    assert "atk_html.json" in report


def test_report_command_supports_html_persisting_deltas(tmp_path: Path) -> None:
    current_path = tmp_path / "current.json"
    baseline_path = tmp_path / "baseline.json"
    report_path = tmp_path / "report.html"

    _write_results(
        current_path,
        _results_with_findings(
            AttackResult(
                attack_id="atk_shared",
                operation_id="createPet",
                kind="wrong_type_param",
                name="Persisting mismatch",
                method="POST",
                url="https://example.com/pets",
                status_code=500,
                flagged=True,
                issue="response_schema_mismatch",
                severity="high",
                confidence="medium",
                response_schema_valid=False,
            )
        ),
    )
    _write_results(
        baseline_path,
        _results_with_findings(
            AttackResult(
                attack_id="atk_shared",
                operation_id="createPet",
                kind="wrong_type_param",
                name="Persisting mismatch",
                method="POST",
                url="https://example.com/pets",
                status_code=200,
                flagged=True,
                issue="response_schema_mismatch",
                severity="medium",
                confidence="high",
                response_schema_valid=True,
            )
        ),
    )

    result = runner.invoke(
        app,
        [
            "report",
            str(current_path),
            "--baseline",
            str(baseline_path),
            "--format",
            "html",
            "--out",
            str(report_path),
        ],
    )

    assert result.exit_code == 0
    report = report_path.read_text(encoding="utf-8")
    assert "<h2>Persisting deltas</h2>" in report
    assert "Persisting with deltas" in report
    assert "status 200 -&gt; 500" in report


def test_run_command_passes_artifact_dir(tmp_path: Path, monkeypatch) -> None:
    attacks_path = tmp_path / "attacks.json"
    out_path = tmp_path / "results.json"
    artifact_dir = tmp_path / "artifacts"
    attacks_path.write_text(
        AttackSuite(source="unit", attacks=[]).model_dump_json(indent=2),
        encoding="utf-8",
    )

    captured: dict[str, object] = {}

    def _fake_execute_attack_suite(
        suite: AttackSuite,
        *,
        base_url: str,
        default_headers: dict[str, str],
        default_query: dict[str, str],
        timeout_seconds: float,
        artifact_dir: Path | None,
        auth_plugins=None,
        workflow_hooks=None,
        built_in_auth_configs=None,
        profile_name=None,
        profile_level=0,
        profile_anonymous=False,
    ) -> AttackResults:
        del built_in_auth_configs, profile_name, profile_level, profile_anonymous
        captured["suite_source"] = suite.source
        captured["base_url"] = base_url
        captured["artifact_dir"] = artifact_dir
        captured["auth_plugins"] = auth_plugins
        return AttackResults(source=suite.source, base_url=base_url, results=[])

    monkeypatch.setattr("knives_out.services.execute_attack_suite", _fake_execute_attack_suite)

    result = runner.invoke(
        app,
        [
            "run",
            str(attacks_path),
            "--base-url",
            "https://example.com",
            "--artifact-dir",
            str(artifact_dir),
            "--out",
            str(out_path),
        ],
    )

    assert result.exit_code == 0
    assert out_path.exists()
    assert captured["suite_source"] == "unit"
    assert captured["base_url"] == "https://example.com"
    assert captured["artifact_dir"] == artifact_dir
    assert captured["auth_plugins"] == []


def test_verify_command_passes_without_baseline_when_no_qualifying_findings(tmp_path: Path) -> None:
    results_path = tmp_path / "results.json"
    _write_results(
        results_path,
        _results_with_findings(
            AttackResult(
                attack_id="atk_medium",
                operation_id="createPet",
                kind="wrong_type_param",
                name="Medium mismatch",
                method="POST",
                url="https://example.com/pets",
                status_code=200,
                flagged=True,
                issue="response_schema_mismatch",
                severity="medium",
                confidence="high",
            )
        ),
    )

    result = runner.invoke(app, ["verify", str(results_path)])

    assert result.exit_code == 0
    assert "Verification passed." in result.stdout


def test_verify_command_fails_without_baseline_when_qualifying_findings_exist(
    tmp_path: Path,
) -> None:
    results_path = tmp_path / "results.json"
    _write_results(
        results_path,
        _results_with_findings(
            AttackResult(
                attack_id="atk_server",
                operation_id="createPet",
                kind="missing_request_body",
                name="Server failure",
                method="POST",
                url="https://example.com/pets",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
            )
        ),
    )

    result = runner.invoke(app, ["verify", str(results_path)])

    assert result.exit_code == 1
    assert "Verification failed." in result.stdout
    assert "Server failure" in result.stdout


def test_verify_command_passes_with_baseline_when_findings_only_persist(tmp_path: Path) -> None:
    current_path = tmp_path / "current.json"
    baseline_path = tmp_path / "baseline.json"
    shared = AttackResult(
        attack_id="atk_shared",
        operation_id="createPet",
        kind="missing_request_body",
        name="Shared failure",
        method="POST",
        url="https://example.com/pets",
        status_code=500,
        flagged=True,
        issue="server_error",
        severity="high",
        confidence="high",
    )
    _write_results(current_path, _results_with_findings(shared))
    _write_results(baseline_path, _results_with_findings(shared))

    result = runner.invoke(
        app,
        ["verify", str(current_path), "--baseline", str(baseline_path)],
    )

    assert result.exit_code == 0
    normalized = _normalized_output(result.stdout)
    assert "Persisting: 1" in normalized
    assert "Verification passed." in normalized


def test_verify_command_shows_persisting_delta_summary(tmp_path: Path) -> None:
    current_path = tmp_path / "current.json"
    baseline_path = tmp_path / "baseline.json"
    _write_results(
        current_path,
        _results_with_findings(
            AttackResult(
                attack_id="atk_shared",
                operation_id="createPet",
                kind="missing_request_body",
                name="Shared failure",
                method="POST",
                url="https://example.com/pets",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="critical",
                confidence="medium",
                response_schema_valid=False,
            )
        ),
    )
    _write_results(
        baseline_path,
        _results_with_findings(
            AttackResult(
                attack_id="atk_shared",
                operation_id="createPet",
                kind="missing_request_body",
                name="Shared failure",
                method="POST",
                url="https://example.com/pets",
                status_code=403,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
                response_schema_valid=True,
            )
        ),
    )

    result = runner.invoke(
        app,
        ["verify", str(current_path), "--baseline", str(baseline_path)],
    )

    assert result.exit_code == 0
    normalized = _normalized_output(result.stdout)
    assert "Persisting with deltas: 1" in normalized
    assert "Persisting findings with deltas" in result.stdout
    assert "status 403 -> 500" in normalized
    assert "critical" in normalized
    assert "confidence high ->" in normalized


def test_verify_command_fails_with_baseline_when_new_qualifying_findings_appear(
    tmp_path: Path,
) -> None:
    current_path = tmp_path / "current.json"
    baseline_path = tmp_path / "baseline.json"
    _write_results(
        current_path,
        _results_with_findings(
            AttackResult(
                attack_id="atk_new",
                operation_id="createPet",
                kind="missing_request_body",
                name="New server failure",
                method="POST",
                url="https://example.com/pets",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
            )
        ),
    )
    _write_results(baseline_path, _results_with_findings())

    result = runner.invoke(
        app,
        ["verify", str(current_path), "--baseline", str(baseline_path)],
    )

    assert result.exit_code == 1
    assert "New: 1" in result.stdout
    normalized = _normalized_output(result.stdout)
    assert "New server" in normalized
    assert "failure" in normalized
    assert "Verification failed." in result.stdout


def test_verify_command_supports_threshold_overrides(tmp_path: Path) -> None:
    results_path = tmp_path / "results.json"
    _write_results(
        results_path,
        _results_with_findings(
            AttackResult(
                attack_id="atk_mismatch",
                operation_id="createPet",
                kind="wrong_type_param",
                name="Schema mismatch",
                method="POST",
                url="https://example.com/pets",
                status_code=200,
                flagged=True,
                issue="response_schema_mismatch",
                severity="medium",
                confidence="high",
            )
        ),
    )

    result = runner.invoke(
        app,
        [
            "verify",
            str(results_path),
            "--min-severity",
            "medium",
            "--min-confidence",
            "high",
        ],
    )

    assert result.exit_code == 1
    assert "Schema mismatch" in result.stdout


def test_verify_command_reports_bad_baseline_file(tmp_path: Path) -> None:
    current_path = tmp_path / "current.json"
    baseline_path = tmp_path / "baseline.json"
    _write_results(current_path, _results_with_findings())
    baseline_path.write_text("{}", encoding="utf-8")

    result = runner.invoke(
        app,
        ["verify", str(current_path), "--baseline", str(baseline_path)],
    )

    assert result.exit_code == 2
    assert "Could not read baseline results file" in result.stderr


def test_promote_command_writes_promoted_suite(tmp_path: Path) -> None:
    current_path = tmp_path / "current.json"
    attacks_path = tmp_path / "attacks.json"
    out_path = tmp_path / "regression-attacks.json"
    _write_results(
        current_path,
        _results_with_findings(
            AttackResult(
                attack_id="atk_two",
                operation_id="createPet",
                kind="missing_request_body",
                name="Server failure",
                method="POST",
                url="https://example.com/pets",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
            )
        ),
    )
    attacks_path.write_text(
        AttackSuite(
            source="unit",
            attacks=[
                AttackCase(
                    id="atk_one",
                    name="Attack one",
                    kind="wrong_type_param",
                    operation_id="createPet",
                    method="POST",
                    path="/pets",
                    description="Attack one",
                ),
                AttackCase(
                    id="atk_two",
                    name="Attack two",
                    kind="missing_request_body",
                    operation_id="createPet",
                    method="POST",
                    path="/pets",
                    description="Attack two",
                ),
            ],
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "promote",
            str(current_path),
            "--attacks",
            str(attacks_path),
            "--out",
            str(out_path),
        ],
    )

    assert result.exit_code == 0
    suite = AttackSuite.model_validate_json(out_path.read_text(encoding="utf-8"))
    assert [attack.id for attack in suite.attacks] == ["atk_two"]
    assert "Wrote 1 promoted attack(s)" in result.stdout


def test_promote_command_with_baseline_only_selects_new_findings(tmp_path: Path) -> None:
    current_path = tmp_path / "current.json"
    baseline_path = tmp_path / "baseline.json"
    attacks_path = tmp_path / "attacks.json"
    out_path = tmp_path / "regression-attacks.json"

    _write_results(
        current_path,
        _results_with_findings(
            AttackResult(
                attack_id="atk_shared",
                operation_id="createPet",
                kind="missing_request_body",
                name="Shared failure",
                method="POST",
                url="https://example.com/pets",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
            ),
            AttackResult(
                attack_id="atk_new",
                operation_id="createPet",
                kind="missing_request_body",
                name="New failure",
                method="POST",
                url="https://example.com/pets",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
            ),
        ),
    )
    _write_results(
        baseline_path,
        _results_with_findings(
            AttackResult(
                attack_id="atk_shared",
                operation_id="createPet",
                kind="missing_request_body",
                name="Shared failure",
                method="POST",
                url="https://example.com/pets",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
            )
        ),
    )
    attacks_path.write_text(
        AttackSuite(
            source="unit",
            attacks=[
                AttackCase(
                    id="atk_shared",
                    name="Shared attack",
                    kind="missing_request_body",
                    operation_id="createPet",
                    method="POST",
                    path="/pets",
                    description="Shared attack",
                ),
                AttackCase(
                    id="atk_new",
                    name="New attack",
                    kind="missing_request_body",
                    operation_id="createPet",
                    method="POST",
                    path="/pets",
                    description="New attack",
                ),
            ],
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "promote",
            str(current_path),
            "--attacks",
            str(attacks_path),
            "--baseline",
            str(baseline_path),
            "--out",
            str(out_path),
        ],
    )

    assert result.exit_code == 0
    suite = AttackSuite.model_validate_json(out_path.read_text(encoding="utf-8"))
    assert [attack.id for attack in suite.attacks] == ["atk_new"]
    assert "Promoted new qualifying attacks against a baseline." in result.stdout


def test_promote_command_reports_missing_attack_ids(tmp_path: Path) -> None:
    current_path = tmp_path / "current.json"
    attacks_path = tmp_path / "attacks.json"

    _write_results(
        current_path,
        _results_with_findings(
            AttackResult(
                attack_id="atk_missing",
                operation_id="createPet",
                kind="missing_request_body",
                name="Missing attack",
                method="POST",
                url="https://example.com/pets",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
            )
        ),
    )
    attacks_path.write_text(
        AttackSuite(source="unit", attacks=[]).model_dump_json(indent=2),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "promote",
            str(current_path),
            "--attacks",
            str(attacks_path),
        ],
    )

    assert result.exit_code == 1
    assert "Promotion error:" in result.stdout
    assert "atk_missing" in result.stdout


def test_verify_command_applies_suppressions(tmp_path: Path) -> None:
    results_path = tmp_path / "results.json"
    suppressions_path = tmp_path / ".knives-out-ignore.yml"
    _write_results(
        results_path,
        _results_with_findings(
            AttackResult(
                attack_id="atk_server",
                operation_id="createPet",
                kind="missing_request_body",
                name="Server failure",
                method="POST",
                path="/pets",
                tags=["pets", "write"],
                url="https://example.com/pets",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
            )
        ),
    )
    suppressions_path.write_text(
        "suppressions:\n"
        "  - attack_id: atk_server\n"
        "    issue: server_error\n"
        "    reason: known issue\n"
        "    owner: api-team\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["verify", str(results_path), "--suppressions", str(suppressions_path)],
    )

    assert result.exit_code == 0
    assert "Applied 1 suppression rule" in result.stdout
    assert "suppressed: 1" in result.stdout


def test_promote_command_respects_suppressions(tmp_path: Path) -> None:
    current_path = tmp_path / "current.json"
    attacks_path = tmp_path / "attacks.json"
    suppressions_path = tmp_path / ".knives-out-ignore.yml"
    out_path = tmp_path / "regression-attacks.json"
    _write_results(
        current_path,
        _results_with_findings(
            AttackResult(
                attack_id="atk_two",
                operation_id="createPet",
                kind="missing_request_body",
                name="Server failure",
                method="POST",
                path="/pets",
                tags=["pets", "write"],
                url="https://example.com/pets",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
            )
        ),
    )
    attacks_path.write_text(
        AttackSuite(
            source="unit",
            attacks=[
                AttackCase(
                    id="atk_two",
                    name="Attack two",
                    kind="missing_request_body",
                    operation_id="createPet",
                    method="POST",
                    path="/pets",
                    description="Attack two",
                ),
            ],
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )
    suppressions_path.write_text(
        "suppressions:\n"
        "  - attack_id: atk_two\n"
        "    issue: server_error\n"
        "    reason: known issue\n"
        "    owner: api-team\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "promote",
            str(current_path),
            "--attacks",
            str(attacks_path),
            "--suppressions",
            str(suppressions_path),
            "--out",
            str(out_path),
        ],
    )

    assert result.exit_code == 0
    suite = AttackSuite.model_validate_json(out_path.read_text(encoding="utf-8"))
    assert suite.attacks == []
    normalized = _normalized_output(result.stdout)
    assert "Qualifying attacks: 0." in normalized


def test_triage_command_writes_review_ready_suppressions(tmp_path: Path) -> None:
    results_path = tmp_path / "results.json"
    suppressions_path = tmp_path / ".knives-out-ignore.yml"
    _write_results(
        results_path,
        _results_with_findings(
            AttackResult(
                attack_id="atk_one",
                operation_id="createPet",
                kind="missing_request_body",
                name="Server failure",
                method="POST",
                path="/pets",
                tags=["pets", "write"],
                url="https://example.com/pets",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
            )
        ),
    )

    result = runner.invoke(
        app,
        ["triage", str(results_path), "--out", str(suppressions_path)],
    )

    assert result.exit_code == 0
    suppressions = load_suppressions(suppressions_path)
    assert len(suppressions.suppressions) == 1
    suppression = suppressions.suppressions[0]
    assert suppression.attack_id == "atk_one"
    assert suppression.issue == "server_error"
    assert suppression.reason.startswith("TODO:")
    assert suppression.owner.startswith("TODO:")


def test_report_command_applies_suppressions(tmp_path: Path) -> None:
    current_path = tmp_path / "current.json"
    suppressions_path = tmp_path / ".knives-out-ignore.yml"
    report_path = tmp_path / "report.md"
    _write_results(
        current_path,
        _results_with_findings(
            AttackResult(
                attack_id="atk_one",
                operation_id="createPet",
                kind="missing_request_body",
                name="Server failure",
                method="POST",
                path="/pets",
                tags=["pets", "write"],
                url="https://example.com/pets",
                status_code=500,
                flagged=True,
                issue="server_error",
                severity="high",
                confidence="high",
            )
        ),
    )
    suppressions_path.write_text(
        "suppressions:\n"
        "  - attack_id: atk_one\n"
        "    issue: server_error\n"
        "    reason: known issue\n"
        "    owner: api-team\n",
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "report",
            str(current_path),
            "--suppressions",
            str(suppressions_path),
            "--out",
            str(report_path),
        ],
    )

    assert result.exit_code == 0
    report = report_path.read_text(encoding="utf-8")
    assert "## Suppressed findings" in report
    assert "known issue" in report


def test_generate_command_filters_attacks(tmp_path: Path, monkeypatch) -> None:
    out_path = tmp_path / "attacks.json"

    monkeypatch.setattr(
        "knives_out.services.load_operations_with_warnings",
        lambda spec, **_: LoadedOperations(operations=[], warnings=[]),
    )
    monkeypatch.setattr(
        "knives_out.services.generate_attack_suite",
        lambda operations, source, **_: AttackSuite(
            source=source,
            attacks=[
                AttackCase(
                    id="atk_get",
                    name="GET attack",
                    kind="missing_auth",
                    operation_id="listPets",
                    method="GET",
                    path="/pets",
                    tags=["pets", "read"],
                    description="GET attack",
                ),
                AttackCase(
                    id="atk_post",
                    name="POST attack",
                    kind="missing_request_body",
                    operation_id="createPet",
                    method="POST",
                    path="/pets",
                    tags=["pets", "write"],
                    description="POST attack",
                ),
            ],
        ),
    )

    result = runner.invoke(
        app,
        [
            "generate",
            str(EXAMPLE_SPEC),
            "--out",
            str(out_path),
            "--operation",
            "createPet",
        ],
    )

    assert result.exit_code == 0
    suite = AttackSuite.model_validate_json(out_path.read_text(encoding="utf-8"))
    assert [attack.id for attack in suite.attacks] == ["atk_post"]


def test_generate_command_filters_attacks_by_tag(tmp_path: Path, monkeypatch) -> None:
    out_path = tmp_path / "attacks.json"

    monkeypatch.setattr(
        "knives_out.services.load_operations_with_warnings",
        lambda spec, **_: LoadedOperations(operations=[], warnings=[]),
    )
    monkeypatch.setattr(
        "knives_out.services.generate_attack_suite",
        lambda operations, source, **_: AttackSuite(
            source=source,
            attacks=[
                AttackCase(
                    id="atk_read",
                    name="Read attack",
                    kind="missing_auth",
                    operation_id="listPets",
                    method="GET",
                    path="/pets",
                    tags=["pets", "read"],
                    description="Read attack",
                ),
                AttackCase(
                    id="atk_write",
                    name="Write attack",
                    kind="missing_request_body",
                    operation_id="createPet",
                    method="POST",
                    path="/pets",
                    tags=["pets", "write"],
                    description="Write attack",
                ),
            ],
        ),
    )

    result = runner.invoke(
        app,
        [
            "generate",
            str(EXAMPLE_SPEC),
            "--out",
            str(out_path),
            "--tag",
            "write",
        ],
    )

    assert result.exit_code == 0
    suite = AttackSuite.model_validate_json(out_path.read_text(encoding="utf-8"))
    assert [attack.id for attack in suite.attacks] == ["atk_write"]


def test_generate_command_echoes_preflight_warnings(tmp_path: Path, monkeypatch) -> None:
    out_path = tmp_path / "attacks.json"

    monkeypatch.setattr(
        "knives_out.services.load_operations_with_warnings",
        lambda spec, **_: LoadedOperations(
            operations=[],
            warnings=[
                PreflightWarning(
                    code="vague_security",
                    message=(
                        "Security requirements include unsupported or ambiguous schemes: "
                        "oauthSecurity."
                    ),
                    operation_id="createPet",
                    method="POST",
                    path="/pets",
                )
            ],
        ),
    )
    monkeypatch.setattr(
        "knives_out.services.generate_attack_suite",
        lambda operations, source, **_: AttackSuite(
            source=source,
            attacks=[],
        ),
    )

    result = runner.invoke(app, ["generate", str(EXAMPLE_SPEC), "--out", str(out_path)])

    assert result.exit_code == 0
    assert "Preflight warnings" in result.stdout
    assert "vague_security" in result.stdout


def test_run_command_filters_attacks_before_execution(tmp_path: Path, monkeypatch) -> None:
    attacks_path = tmp_path / "attacks.json"
    out_path = tmp_path / "results.json"
    attacks_path.write_text(
        AttackSuite(
            source="unit",
            attacks=[
                AttackCase(
                    id="atk_get",
                    name="GET attack",
                    kind="missing_auth",
                    operation_id="listPets",
                    method="GET",
                    path="/pets",
                    tags=["pets", "read"],
                    description="GET attack",
                ),
                AttackCase(
                    id="atk_post",
                    name="POST attack",
                    kind="missing_request_body",
                    operation_id="createPet",
                    method="POST",
                    path="/pets",
                    tags=["pets", "write"],
                    description="POST attack",
                ),
            ],
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )

    captured: dict[str, object] = {}

    def _fake_execute_attack_suite(
        suite: AttackSuite,
        *,
        base_url: str,
        default_headers: dict[str, str],
        default_query: dict[str, str],
        timeout_seconds: float,
        artifact_dir: Path | None,
        auth_plugins=None,
        workflow_hooks=None,
        built_in_auth_configs=None,
        profile_name=None,
        profile_level=0,
        profile_anonymous=False,
    ) -> AttackResults:
        del default_headers, default_query, timeout_seconds, artifact_dir
        del workflow_hooks, built_in_auth_configs, profile_name, profile_level, profile_anonymous
        captured["attack_ids"] = [attack.id for attack in suite.attacks]
        captured["auth_plugins"] = auth_plugins
        return AttackResults(source=suite.source, base_url=base_url, results=[])

    monkeypatch.setattr("knives_out.services.execute_attack_suite", _fake_execute_attack_suite)

    result = runner.invoke(
        app,
        [
            "run",
            str(attacks_path),
            "--base-url",
            "https://example.com",
            "--method",
            "POST",
            "--out",
            str(out_path),
        ],
    )

    assert result.exit_code == 0
    assert captured["attack_ids"] == ["atk_post"]
    assert captured["auth_plugins"] == []


def test_run_command_filters_attacks_by_path_before_execution(tmp_path: Path, monkeypatch) -> None:
    attacks_path = tmp_path / "attacks.json"
    out_path = tmp_path / "results.json"
    attacks_path.write_text(
        AttackSuite(
            source="unit",
            attacks=[
                AttackCase(
                    id="atk_get",
                    name="GET attack",
                    kind="missing_auth",
                    operation_id="listPets",
                    method="GET",
                    path="/pets",
                    tags=["pets", "read"],
                    description="GET attack",
                ),
                AttackCase(
                    id="atk_post",
                    name="POST attack",
                    kind="missing_request_body",
                    operation_id="createPet",
                    method="POST",
                    path="/pets/{petId}",
                    tags=["pets", "write"],
                    description="POST attack",
                ),
            ],
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )

    captured: dict[str, object] = {}

    def _fake_execute_attack_suite(
        suite: AttackSuite,
        *,
        base_url: str,
        default_headers: dict[str, str],
        default_query: dict[str, str],
        timeout_seconds: float,
        artifact_dir: Path | None,
        auth_plugins=None,
        workflow_hooks=None,
        built_in_auth_configs=None,
        profile_name=None,
        profile_level=0,
        profile_anonymous=False,
    ) -> AttackResults:
        del (
            base_url,
            default_headers,
            default_query,
            timeout_seconds,
            artifact_dir,
            auth_plugins,
            workflow_hooks,
            built_in_auth_configs,
            profile_name,
            profile_level,
            profile_anonymous,
        )
        captured["attack_ids"] = [attack.id for attack in suite.attacks]
        return AttackResults(source=suite.source, base_url="https://example.com", results=[])

    monkeypatch.setattr("knives_out.services.execute_attack_suite", _fake_execute_attack_suite)

    result = runner.invoke(
        app,
        [
            "run",
            str(attacks_path),
            "--base-url",
            "https://example.com",
            "--path",
            "/pets/{petId}",
            "--out",
            str(out_path),
        ],
    )

    assert result.exit_code == 0
    assert captured["attack_ids"] == ["atk_post"]


def test_run_command_loads_local_auth_plugin(tmp_path: Path, monkeypatch) -> None:
    attacks_path = tmp_path / "attacks.json"
    out_path = tmp_path / "results.json"
    module_path = tmp_path / "auth_plugin.py"
    attacks_path.write_text(
        AttackSuite(source="unit", attacks=[]).model_dump_json(indent=2),
        encoding="utf-8",
    )
    module_path.write_text(
        dedent(
            """
            from knives_out.auth_plugins import RuntimePlugin, make_auth_plugin

            class ModulePlugin(RuntimePlugin):
                pass

            auth_plugin = make_auth_plugin("module-auth-plugin", ModulePlugin())
            """
        ),
        encoding="utf-8",
    )

    captured: dict[str, object] = {}

    def _fake_execute_attack_suite(
        suite: AttackSuite,
        *,
        base_url: str,
        default_headers: dict[str, str],
        default_query: dict[str, str],
        timeout_seconds: float,
        artifact_dir: Path | None,
        auth_plugins=None,
        workflow_hooks=None,
        built_in_auth_configs=None,
        profile_name=None,
        profile_level=0,
        profile_anonymous=False,
    ) -> AttackResults:
        del (
            default_headers,
            default_query,
            timeout_seconds,
            artifact_dir,
            workflow_hooks,
            built_in_auth_configs,
            profile_name,
            profile_level,
            profile_anonymous,
        )
        captured["suite_source"] = suite.source
        captured["base_url"] = base_url
        captured["auth_plugin_names"] = [plugin.name for plugin in auth_plugins]
        return AttackResults(source=suite.source, base_url=base_url, results=[])

    monkeypatch.setattr("knives_out.services.execute_attack_suite", _fake_execute_attack_suite)

    result = runner.invoke(
        app,
        [
            "run",
            str(attacks_path),
            "--base-url",
            "https://example.com",
            "--auth-plugin-module",
            str(module_path),
            "--out",
            str(out_path),
        ],
    )

    assert result.exit_code == 0
    assert captured["suite_source"] == "unit"
    assert captured["base_url"] == "https://example.com"
    assert captured["auth_plugin_names"] == ["module-auth-plugin"]


def test_run_command_executes_selected_auth_profiles(tmp_path: Path, monkeypatch) -> None:
    attacks_path = tmp_path / "attacks.json"
    out_path = tmp_path / "results.json"
    profile_path = tmp_path / "profiles.yml"
    attacks_path.write_text(
        AttackSuite(
            source="unit",
            attacks=[
                AttackCase(
                    id="atk_profiled",
                    name="Profiled attack",
                    kind="missing_auth",
                    operation_id="getSecret",
                    method="GET",
                    path="/secrets",
                    description="Profiled attack",
                )
            ],
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )
    profile_path.write_text(
        "profiles:\n"
        "  - name: anonymous\n"
        "    anonymous: true\n"
        "    level: 0\n"
        "  - name: user\n"
        "    level: 10\n"
        "    headers:\n"
        "      Authorization: Bearer user\n",
        encoding="utf-8",
    )

    captured: dict[str, object] = {}

    def _fake_execute_attack_suite_profiles(
        suite: AttackSuite,
        *,
        base_url: str,
        profiles,
        default_headers: dict[str, str],
        default_query: dict[str, str],
        timeout_seconds: float,
        artifact_dir: Path | None,
        built_in_auth_configs=None,
    ) -> AttackResults:
        del default_headers, default_query, timeout_seconds, artifact_dir
        captured["suite_source"] = suite.source
        captured["base_url"] = base_url
        captured["profile_names"] = [profile.name for profile in profiles]
        captured["built_in_auth_configs"] = built_in_auth_configs
        return AttackResults(
            source=suite.source,
            base_url=base_url,
            profiles=[profile.name for profile in profiles],
            results=[
                AttackResult(
                    attack_id="atk_profiled",
                    operation_id="getSecret",
                    kind="missing_auth",
                    name="Profiled attack",
                    method="GET",
                    path="/secrets",
                    url=f"{base_url}/secrets",
                )
            ],
        )

    monkeypatch.setattr(
        "knives_out.services.execute_attack_suite_profiles",
        _fake_execute_attack_suite_profiles,
    )

    result = runner.invoke(
        app,
        [
            "run",
            str(attacks_path),
            "--base-url",
            "https://example.com",
            "--profile-file",
            str(profile_path),
            "--profile",
            "user",
            "--out",
            str(out_path),
        ],
    )

    assert result.exit_code == 0
    assert captured["suite_source"] == "unit"
    assert captured["base_url"] == "https://example.com"
    assert captured["profile_names"] == ["user"]
    assert captured["built_in_auth_configs"] == {}
    assert "Executed 1 attacks across 1 profile(s)" in _normalized_output(result.stdout)
    saved = AttackResults.model_validate_json(out_path.read_text(encoding="utf-8"))
    assert saved.profiles == ["user"]


def test_run_command_combines_profile_file_with_built_in_auth_config(
    tmp_path: Path,
    monkeypatch,
) -> None:
    attacks_path = tmp_path / "attacks.json"
    out_path = tmp_path / "results.json"
    profile_path = tmp_path / "profiles.yml"
    auth_config_path = tmp_path / "auth.yml"
    attacks_path.write_text(
        AttackSuite(source="unit", attacks=[]).model_dump_json(indent=2),
        encoding="utf-8",
    )
    profile_path.write_text(
        "profiles:\n  - name: user\n    level: 10\n    auth_config: user\n",
        encoding="utf-8",
    )
    auth_config_path.write_text(
        "auth:\n"
        "  - name: user\n"
        "    strategy: static_bearer\n"
        "    token: user-token\n"
        "    level: 10\n",
        encoding="utf-8",
    )

    captured: dict[str, object] = {}

    def _fake_execute_attack_suite_profiles(
        suite: AttackSuite,
        *,
        base_url: str,
        profiles,
        default_headers: dict[str, str],
        default_query: dict[str, str],
        timeout_seconds: float,
        artifact_dir: Path | None,
        built_in_auth_configs=None,
    ) -> AttackResults:
        del suite, base_url, default_headers, default_query, timeout_seconds, artifact_dir
        captured["profile_auth_configs"] = [profile.auth_config for profile in profiles]
        captured["built_in_auth_configs"] = sorted((built_in_auth_configs or {}).keys())
        return AttackResults(
            source="unit",
            base_url="https://example.com",
            profiles=[profile.name for profile in profiles],
            results=[],
        )

    monkeypatch.setattr(
        "knives_out.services.execute_attack_suite_profiles",
        _fake_execute_attack_suite_profiles,
    )

    result = runner.invoke(
        app,
        [
            "run",
            str(attacks_path),
            "--base-url",
            "https://example.com",
            "--profile-file",
            str(profile_path),
            "--auth-config",
            str(auth_config_path),
            "--out",
            str(out_path),
        ],
    )

    assert result.exit_code == 0
    assert captured["profile_auth_configs"] == ["user"]
    assert captured["built_in_auth_configs"] == ["user"]


def test_run_command_supports_built_in_auth_config_profiles(tmp_path: Path, monkeypatch) -> None:
    attacks_path = tmp_path / "attacks.json"
    out_path = tmp_path / "results.json"
    auth_config_path = tmp_path / "auth.yml"
    attacks_path.write_text(
        AttackSuite(source="unit", attacks=[]).model_dump_json(indent=2),
        encoding="utf-8",
    )
    auth_config_path.write_text(
        "auth:\n"
        "  - name: user\n"
        "    strategy: static_bearer\n"
        "    token: user-token\n"
        "    level: 10\n"
        "  - name: admin\n"
        "    strategy: static_bearer\n"
        "    token: admin-token\n"
        "    level: 20\n",
        encoding="utf-8",
    )

    captured: dict[str, object] = {}

    def _fake_execute_attack_suite_profiles(
        suite: AttackSuite,
        *,
        base_url: str,
        profiles,
        default_headers: dict[str, str],
        default_query: dict[str, str],
        timeout_seconds: float,
        artifact_dir: Path | None,
        built_in_auth_configs=None,
    ) -> AttackResults:
        del suite, default_headers, default_query, timeout_seconds, artifact_dir
        captured["base_url"] = base_url
        captured["profile_names"] = [profile.name for profile in profiles]
        captured["profile_auth_configs"] = [profile.auth_config for profile in profiles]
        captured["built_in_auth_configs"] = sorted((built_in_auth_configs or {}).keys())
        return AttackResults(
            source="unit",
            base_url=base_url,
            profiles=[profile.name for profile in profiles],
            results=[],
        )

    monkeypatch.setattr(
        "knives_out.services.execute_attack_suite_profiles",
        _fake_execute_attack_suite_profiles,
    )

    result = runner.invoke(
        app,
        [
            "run",
            str(attacks_path),
            "--base-url",
            "https://example.com",
            "--auth-config",
            str(auth_config_path),
            "--auth-profile",
            "admin",
            "--out",
            str(out_path),
        ],
    )

    assert result.exit_code == 0
    assert captured["base_url"] == "https://example.com"
    assert captured["profile_names"] == ["admin"]
    assert captured["profile_auth_configs"] == ["admin"]
    assert captured["built_in_auth_configs"] == ["admin"]


def test_run_command_requires_auth_config_for_auth_profile_name(tmp_path: Path) -> None:
    attacks_path = tmp_path / "attacks.json"
    attacks_path.write_text(
        AttackSuite(source="unit", attacks=[]).model_dump_json(indent=2),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "run",
            str(attacks_path),
            "--base-url",
            "https://example.com",
            "--auth-profile",
            "admin",
        ],
    )

    assert result.exit_code == 2


def test_run_command_requires_profile_file_for_profile_name(tmp_path: Path) -> None:
    attacks_path = tmp_path / "attacks.json"
    attacks_path.write_text(
        AttackSuite(source="unit", attacks=[]).model_dump_json(indent=2),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        [
            "run",
            str(attacks_path),
            "--base-url",
            "https://example.com",
            "--profile",
            "user",
        ],
    )

    assert result.exit_code == 2


def test_run_command_reports_auth_plugin_runtime_error(tmp_path: Path, monkeypatch) -> None:
    attacks_path = tmp_path / "attacks.json"
    attacks_path.write_text(
        AttackSuite(source="unit", attacks=[]).model_dump_json(indent=2),
        encoding="utf-8",
    )

    def _fake_execute_attack_suite(
        suite: AttackSuite,
        *,
        base_url: str,
        default_headers: dict[str, str],
        default_query: dict[str, str],
        timeout_seconds: float,
        artifact_dir: Path | None,
        auth_plugins=None,
        workflow_hooks=None,
        built_in_auth_configs=None,
        profile_name=None,
        profile_level=0,
        profile_anonymous=False,
    ) -> AttackResults:
        del (
            suite,
            base_url,
            default_headers,
            default_query,
            timeout_seconds,
            artifact_dir,
            auth_plugins,
            workflow_hooks,
            built_in_auth_configs,
            profile_name,
            profile_level,
            profile_anonymous,
        )
        raise PluginRuntimeError("boom")

    monkeypatch.setattr("knives_out.services.execute_attack_suite", _fake_execute_attack_suite)

    result = runner.invoke(
        app,
        [
            "run",
            str(attacks_path),
            "--base-url",
            "https://example.com",
        ],
    )

    assert result.exit_code == 1
    assert "Auth plugin error:" in result.stdout
    assert "boom" in result.stdout


def test_generate_command_loads_local_attack_pack(tmp_path: Path) -> None:
    spec_path = tmp_path / "custom-pack-spec.yaml"
    spec_path.write_text(
        dedent(
            """
            openapi: 3.0.3
            info:
              title: Custom pack test
              version: 1.0.0
            paths:
              /pets:
                get:
                  operationId: listPets
            """
        ),
        encoding="utf-8",
    )

    module_path = tmp_path / "custom_pack.py"
    module_path.write_text(
        dedent(
            """
            from knives_out.attack_packs import make_attack_pack
            from knives_out.models import AttackCase, OperationSpec

            def generate(operation: OperationSpec) -> list[AttackCase]:
                return [
                    AttackCase(
                        id=f"atk_{operation.operation_id}_custom",
                        name="Custom probe",
                        kind="custom_probe",
                        operation_id=operation.operation_id,
                        method=operation.method,
                        path=operation.path,
                        description="Custom probe",
                    )
                ]

            attack_pack = make_attack_pack("custom-pack", generate)
            """
        ),
        encoding="utf-8",
    )

    out_path = tmp_path / "attacks.json"
    result = runner.invoke(
        app,
        [
            "generate",
            str(spec_path),
            "--pack-module",
            str(module_path),
            "--out",
            str(out_path),
        ],
    )

    assert result.exit_code == 0
    suite = AttackSuite.model_validate_json(out_path.read_text(encoding="utf-8"))
    assert any(attack.kind == "custom_probe" for attack in suite.attacks)


def test_generate_command_loads_local_workflow_pack(tmp_path: Path) -> None:
    module_path = tmp_path / "custom_workflow_pack.py"
    module_path.write_text(
        dedent(
            """
            from knives_out.models import ExtractRule, WorkflowAttackCase, WorkflowStep
            from knives_out.workflow_packs import make_workflow_pack

            def generate(operations, request_attacks):
                attack = next(
                    attack for attack in request_attacks if attack.operation_id == "getPet"
                )
                terminal_attack = attack.model_copy(deep=True)
                terminal_attack.path_params["petId"] = "{{id}}"
                return [
                    WorkflowAttackCase(
                        id="wf_custom",
                        name="Custom workflow",
                        kind=attack.kind,
                        operation_id=attack.operation_id,
                        method=attack.method,
                        path=attack.path,
                        description="Custom workflow",
                        setup_steps=[
                            WorkflowStep(
                                name="List pets",
                                operation_id="listPets",
                                method="GET",
                                path="/pets",
                                extracts=[ExtractRule(name="id", json_pointer="/0/id")],
                            )
                        ],
                        terminal_attack=terminal_attack,
                    )
                ]

            workflow_pack = make_workflow_pack("custom-workflow-pack", generate)
            """
        ),
        encoding="utf-8",
    )

    out_path = tmp_path / "attacks.json"
    result = runner.invoke(
        app,
        [
            "generate",
            str(EXAMPLE_SPEC),
            "--workflow-pack-module",
            str(module_path),
            "--out",
            str(out_path),
        ],
    )

    assert result.exit_code == 0
    suite = AttackSuite.model_validate_json(out_path.read_text(encoding="utf-8"))
    assert any(attack.type == "workflow" for attack in suite.attacks)


def test_serve_command_starts_local_api(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def _fake_run(app_instance: object, *, host: str, port: int) -> None:
        captured["app"] = app_instance
        captured["host"] = host
        captured["port"] = port

    monkeypatch.setattr("knives_out.cli.uvicorn.run", _fake_run)

    result = runner.invoke(
        app,
        [
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            "8787",
        ],
    )

    assert result.exit_code == 0
    assert isinstance(captured["app"], FastAPI)
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 8787
