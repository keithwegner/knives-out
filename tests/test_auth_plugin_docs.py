from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
CI_DOC = ROOT / "docs" / "ci.md"
DEV_WORKFLOW = ROOT / ".github" / "workflows" / "dev-environment-example.yml"


def test_readme_documents_auth_session_plugins() -> None:
    readme = README.read_text(encoding="utf-8")

    assert "## Auth/session plugins" in readme
    assert "examples/auth_plugins/login_bearer.py" in readme
    assert "--auth-plugin env-bearer" in readme


def test_dev_workflow_documents_auth_plugin_module_usage() -> None:
    workflow = DEV_WORKFLOW.read_text(encoding="utf-8")

    assert "--auth-plugin-module examples/auth_plugins/login_bearer.py" in workflow
    assert "KNIVES_OUT_LOGIN_USERNAME" in workflow


def test_ci_doc_includes_auth_plugin_guidance() -> None:
    ci_doc = CI_DOC.read_text(encoding="utf-8")

    assert "Optional: auth/session plugins" in ci_doc
    assert "--auth-plugin-module examples/auth_plugins/login_bearer.py" in ci_doc
