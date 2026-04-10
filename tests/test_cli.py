from pathlib import Path
from textwrap import dedent

from typer.testing import CliRunner

from knives_out.cli import app
from knives_out.models import (
    AttackCase,
    AttackResult,
    AttackResults,
    AttackSuite,
    LoadedOperations,
    PreflightWarning,
)

runner = CliRunner()
EXAMPLE_SPEC = Path(__file__).resolve().parents[1] / "examples" / "openapi" / "petstore.yaml"


def _write_results(path: Path, results: AttackResults) -> None:
    path.write_text(results.model_dump_json(indent=2, exclude_none=True), encoding="utf-8")


def _results_with_findings(*results: AttackResult) -> AttackResults:
    return AttackResults(
        source="unit",
        base_url="https://example.com",
        results=list(results),
    )


def test_inspect_command_runs() -> None:
    result = runner.invoke(app, ["inspect", str(EXAMPLE_SPEC)])

    assert result.exit_code == 0
    assert "Found 3 operations." in result.stdout


def test_inspect_command_shows_preflight_warnings(monkeypatch) -> None:
    monkeypatch.setattr(
        "knives_out.cli.load_operations_with_warnings",
        lambda spec: LoadedOperations(
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


def test_generate_command_writes_attack_suite(tmp_path: Path) -> None:
    out_path = tmp_path / "attacks.json"
    result = runner.invoke(app, ["generate", str(EXAMPLE_SPEC), "--out", str(out_path)])

    assert result.exit_code == 0
    assert out_path.exists()
    raw = out_path.read_text(encoding="utf-8")
    assert '"attacks"' in raw


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
                status_code=200,
                flagged=True,
                issue="response_schema_mismatch",
                severity="medium",
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
                status_code=200,
                flagged=True,
                issue="response_schema_mismatch",
                severity="medium",
                confidence="high",
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
    ) -> AttackResults:
        captured["suite_source"] = suite.source
        captured["base_url"] = base_url
        captured["artifact_dir"] = artifact_dir
        return AttackResults(source=suite.source, base_url=base_url, results=[])

    monkeypatch.setattr("knives_out.cli.execute_attack_suite", _fake_execute_attack_suite)

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
    assert "Persisting: 1" in result.stdout
    assert "Verification passed." in result.stdout


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
    assert "New server failure" in result.stdout
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
    assert "Could not read baseline results file" in result.stdout


def test_generate_command_filters_attacks(tmp_path: Path, monkeypatch) -> None:
    out_path = tmp_path / "attacks.json"

    monkeypatch.setattr(
        "knives_out.cli.load_operations_with_warnings",
        lambda spec: LoadedOperations(operations=[], warnings=[]),
    )
    monkeypatch.setattr(
        "knives_out.cli.generate_attack_suite",
        lambda operations, source, extra_packs=None: AttackSuite(
            source=source,
            attacks=[
                AttackCase(
                    id="atk_get",
                    name="GET attack",
                    kind="missing_auth",
                    operation_id="listPets",
                    method="GET",
                    path="/pets",
                    description="GET attack",
                ),
                AttackCase(
                    id="atk_post",
                    name="POST attack",
                    kind="missing_request_body",
                    operation_id="createPet",
                    method="POST",
                    path="/pets",
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


def test_generate_command_echoes_preflight_warnings(tmp_path: Path, monkeypatch) -> None:
    out_path = tmp_path / "attacks.json"

    monkeypatch.setattr(
        "knives_out.cli.load_operations_with_warnings",
        lambda spec: LoadedOperations(
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
        "knives_out.cli.generate_attack_suite",
        lambda operations, source, extra_packs=None: AttackSuite(source=source, attacks=[]),
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
                    description="GET attack",
                ),
                AttackCase(
                    id="atk_post",
                    name="POST attack",
                    kind="missing_request_body",
                    operation_id="createPet",
                    method="POST",
                    path="/pets",
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
    ) -> AttackResults:
        captured["attack_ids"] = [attack.id for attack in suite.attacks]
        return AttackResults(source=suite.source, base_url=base_url, results=[])

    monkeypatch.setattr("knives_out.cli.execute_attack_suite", _fake_execute_attack_suite)

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
