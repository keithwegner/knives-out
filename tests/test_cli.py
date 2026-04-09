from pathlib import Path

from typer.testing import CliRunner

from knives_out.cli import app

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
