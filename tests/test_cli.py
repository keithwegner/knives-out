from pathlib import Path

from typer.testing import CliRunner

from knives_out.cli import app
from knives_out.models import AttackResults, AttackSuite

runner = CliRunner()
EXAMPLE_SPEC = Path(__file__).resolve().parents[1] / "examples" / "openapi" / "petstore.yaml"


def test_inspect_command_runs() -> None:
    result = runner.invoke(app, ["inspect", str(EXAMPLE_SPEC)])

    assert result.exit_code == 0
    assert "Found 3 operations." in result.stdout


def test_generate_command_writes_attack_suite(tmp_path: Path) -> None:
    out_path = tmp_path / "attacks.json"
    result = runner.invoke(app, ["generate", str(EXAMPLE_SPEC), "--out", str(out_path)])

    assert result.exit_code == 0
    assert out_path.exists()
    raw = out_path.read_text(encoding="utf-8")
    assert '"attacks"' in raw


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
