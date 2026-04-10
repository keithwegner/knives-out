from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
CI_DOC = ROOT / "docs" / "ci.md"
ARCHITECTURE_DOC = ROOT / "docs" / "architecture.md"
ROADMAP_DOC = ROOT / "docs" / "roadmap.md"
DEV_WORKFLOW = ROOT / ".github" / "workflows" / "dev-environment-example.yml"
SYNC_WIKI_WORKFLOW = ROOT / ".github" / "workflows" / "sync-wiki.yml"


def test_readme_includes_ci_guidance() -> None:
    readme = README.read_text(encoding="utf-8")

    assert "Project wiki:" in readme
    assert "https://github.com/keithwegner/knives-out/wiki" in readme
    assert "## CI usage" in readme
    assert ".github/workflows/dev-environment-example.yml" in readme
    assert "KNIVES_OUT_BASE_URL" in readme
    assert "`knives-out run` currently exits with status `0`" in readme
    assert "knives-out verify results.json" in readme
    assert "knives-out promote results.json" in readme
    assert "knives-out triage results.json" in readme
    assert ".knives-out-ignore.yml" in readme
    assert "--profile-file examples/auth_profiles/anonymous-user-admin.yml" in readme
    assert "anonymous_access" in readme
    assert "--auto-workflows" in readme
    assert "--tag orders" in readme
    assert "--path /draft-orders/{draftId}" in readme
    assert "knives-out report results.json --format html" in readme
    assert "--artifact-root artifacts" in readme
    assert "report.html" in readme
    assert "examples/openapi/storefront.yaml" in readme
    assert "examples/graphql/library.graphql" in readme
    assert "--graphql-endpoint /api/graphql" in readme
    assert "graphql-attacks.json" in readme
    assert "examples/workflow_packs/listed_pet_lookup.py" in readme
    assert "**v0.9:** first-class auth and session realism" in readme
    assert "**v0.10:** deeper GraphQL coverage" in readme


def test_dev_environment_workflow_matches_current_cli_surface() -> None:
    workflow = DEV_WORKFLOW.read_text(encoding="utf-8")

    assert "workflow_dispatch:" in workflow
    assert "actions/checkout@v5" in workflow
    assert "actions/setup-python@v6" in workflow
    assert "actions/upload-artifact@v6" in workflow
    assert "SPEC_PATH: examples/openapi/storefront.yaml" in workflow
    assert 'knives-out generate "$SPEC_PATH" --tag orders --out attacks.json' in workflow
    assert "--path /draft-orders/{draftId}" in workflow
    assert "--auto-workflows" in workflow
    assert "--workflow-pack-module examples/workflow_packs/listed_pet_lookup.py" in workflow
    assert "examples/graphql/library.graphql" in workflow
    assert "--graphql-endpoint /graphql" in workflow
    assert "--profile-file examples/auth_profiles/anonymous-user-admin.yml" in workflow
    assert "--profile anonymous" in workflow
    assert 'knives-out run attacks.json "${args[@]}"' in workflow
    assert "knives-out report results.json --out report.md" in workflow
    assert (
        "knives-out report results.json --format html --artifact-root artifacts --out report.html"
        in workflow
    )
    assert "knives-out report results.json \\" in workflow
    assert "knives-out verify results.json" in workflow
    assert "knives-out triage results.json --out .knives-out-ignore.yml" in workflow
    assert ".knives-out-ignore.yml" in workflow
    assert "knives-out promote results.json" in workflow
    assert "KNIVES_OUT_BASE_URL" in workflow


def test_ci_doc_describes_artifacts_and_optional_gating() -> None:
    ci_doc = CI_DOC.read_text(encoding="utf-8")

    assert "results.json" in ci_doc
    assert "report.md" in ci_doc
    assert "report.html" in ci_doc
    assert "artifacts/" in ci_doc
    assert "Simple gating with no baseline" in ci_doc
    assert "Baseline-aware gating" in ci_doc
    assert "Optional: checked-in suppressions" in ci_doc
    assert "Optional: multi-profile authorization runs" in ci_doc
    assert "Optional: HTML report and artifact index" in ci_doc
    assert "Optional: GraphQL schemas" in ci_doc
    assert "examples/auth_profiles/anonymous-user-admin.yml" in ci_doc
    assert "examples/graphql/library.graphql" in ci_doc
    assert "knives-out triage results.json --out .knives-out-ignore.yml" in ci_doc
    assert ".knives-out-ignore.yml" in ci_doc
    assert "--baseline previous-results.json" in ci_doc
    assert "Generate attacks with built-in workflows" in ci_doc
    assert "--tag orders" in ci_doc
    assert "--path /draft-orders/{draftId}" in ci_doc
    assert "Promote qualifying findings" in ci_doc
    assert "pytest --cov=src/knives_out --cov-report=term-missing" in ci_doc
    assert "--workflow-pack-module examples/workflow_packs/listed_pet_lookup.py" in ci_doc
    assert "--format html" in ci_doc
    assert "--artifact-root artifacts" in ci_doc
    assert "--out report.html" in ci_doc


def test_sync_wiki_workflow_uses_dedicated_secret_and_sync_script() -> None:
    workflow = SYNC_WIKI_WORKFLOW.read_text(encoding="utf-8")

    assert "workflow_dispatch:" in workflow
    assert "README.md" in workflow
    assert "docs/**" in workflow
    assert "scripts/sync_wiki.py" in workflow
    assert "WIKI_PUSH_TOKEN" in workflow
    assert "python scripts/sync_wiki.py publish" in workflow
    assert "github.repository }}.wiki.git" in workflow


def test_roadmap_and_architecture_describe_next_milestones() -> None:
    roadmap = ROADMAP_DOC.read_text(encoding="utf-8")
    architecture = ARCHITECTURE_DOC.read_text(encoding="utf-8")

    assert "## Recently completed" in roadmap
    assert "v0.8: GraphQL schema support" in roadmap
    assert "## v0.9 — first-class auth and session realism" in roadmap
    assert "client_credentials" in roadmap
    assert "## v0.10 — deeper GraphQL coverage" in roadmap
    assert "subscription coverage" in roadmap
    assert "LLM application and tool-misuse testing" in roadmap

    assert "graphql_loader.py" in architecture
    assert "spec_loader.py" in architecture
    assert "GraphQL SDL or introspection JSON" in architecture
    assert "200` response with an `errors` array" in architecture
    assert "first-class auth/session profile strategies" in architecture
    assert "GraphQL response-shape validation, federation awareness" in architecture
    assert "redirect-driven OAuth auth-code flows" in architecture
