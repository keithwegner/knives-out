from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
CI_DOC = ROOT / "docs" / "ci.md"
DEV_WORKFLOW = ROOT / ".github" / "workflows" / "dev-environment-example.yml"


def test_readme_includes_ci_guidance() -> None:
    readme = README.read_text(encoding="utf-8")

    assert "## CI usage" in readme
    assert ".github/workflows/dev-environment-example.yml" in readme
    assert "KNIVES_OUT_BASE_URL" in readme
    assert "`knives-out run` currently exits with status `0`" in readme
    assert "knives-out verify results.json" in readme


def test_dev_environment_workflow_matches_current_cli_surface() -> None:
    workflow = DEV_WORKFLOW.read_text(encoding="utf-8")

    assert "workflow_dispatch:" in workflow
    assert "actions/checkout@v5" in workflow
    assert "actions/setup-python@v6" in workflow
    assert "actions/upload-artifact@v6" in workflow
    assert 'knives-out generate "$SPEC_PATH" --out attacks.json' in workflow
    assert 'knives-out run attacks.json "${args[@]}"' in workflow
    assert "knives-out report results.json --out report.md" in workflow
    assert "knives-out verify results.json" in workflow
    assert "KNIVES_OUT_BASE_URL" in workflow


def test_ci_doc_describes_artifacts_and_optional_gating() -> None:
    ci_doc = CI_DOC.read_text(encoding="utf-8")

    assert "results.json" in ci_doc
    assert "report.md" in ci_doc
    assert "artifacts/" in ci_doc
    assert "Simple gating with no baseline" in ci_doc
    assert "Baseline-aware gating" in ci_doc
    assert "--baseline previous-results.json" in ci_doc
