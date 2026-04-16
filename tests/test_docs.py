from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
CI_DOC = ROOT / "docs" / "ci.md"
ARCHITECTURE_DOC = ROOT / "docs" / "architecture.md"
ROADMAP_DOC = ROOT / "docs" / "roadmap.md"
DEV_WORKFLOW = ROOT / ".github" / "workflows" / "dev-environment-example.yml"
SYNC_WIKI_WORKFLOW = ROOT / ".github" / "workflows" / "sync-wiki.yml"
MAIN_MAINTENANCE_WORKFLOW = ROOT / ".github" / "workflows" / "main-maintenance.yml"


def test_readme_includes_ci_guidance() -> None:
    readme = README.read_text(encoding="utf-8")

    assert "coverage-badge.json" in readme
    assert "actions/workflows/main-maintenance.yml" in readme
    assert "Project wiki:" in readme
    assert "https://github.com/keithwegner/knives-out/wiki" in readme
    assert "Shadow Twin" in readme
    assert "observed traffic" in readme
    assert "## CI usage" in readme
    assert ".github/workflows/dev-environment-example.yml" in readme
    assert "KNIVES_OUT_BASE_URL" in readme
    assert "`knives-out run` currently exits with status `0`" in readme
    assert "knives-out verify results.json" in readme
    assert "knives-out export results.json --format sarif --out results.sarif" in readme
    assert "knives-out export results.json --format junit --out results.xml" in readme
    assert "status, severity, confidence, or schema outcome drifted" in readme
    assert "knives-out promote results.json" in readme
    assert "knives-out triage results.json" in readme
    assert "knives-out summary results.json --out summary.json" in readme
    assert "summary.json" in readme
    assert ".knives-out-ignore.yml" in readme
    assert "## Local API" in readme
    assert "knives-out serve --host 127.0.0.1 --port 8787" in readme
    assert "KNIVES_OUT_API_DATA_DIR" in readme
    assert "## Container deployment" in readme
    assert "docker build -t knives-out ." in readme
    assert "docker compose up --build -d" in readme
    assert "compose.env.example" in readme
    assert "KNIVES_OUT_BASIC_AUTH_USERNAME" in readme
    assert "KNIVES_OUT_BASIC_AUTH_PASSWORD" in readme
    assert "same-origin self-hosted deployment" in readme
    assert "POST /v1/inspect" in readme
    assert "POST /v1/summary" in readme
    assert "POST /v1/export" in readme
    assert "POST /v1/runs" in readme
    assert "DELETE /v1/jobs/{id}" in readme
    assert "POST /v1/jobs/prune" in readme
    assert "GET /v1/jobs/{id}/findings/{attack_id}/evidence" in readme
    assert "GET /v1/jobs/{id}/artifacts" in readme
    assert "completed or failed jobs" in readme
    assert "GET /v1/jobs" in readme
    assert "GET /v1/jobs/{id}/artifacts" in readme
    assert "result_summary" in readme
    assert "POST /v1/projects/{id}/review" in readme
    assert "baseline_job_id" in readme
    assert "external baseline mode" in readme
    assert "--profile-file examples/auth_profiles/anonymous-user-admin.yml" in readme
    assert "anonymous_access" in readme
    assert "--auto-workflows" in readme
    assert "--tag orders" in readme
    assert "--path /draft-orders/{draftId}" in readme
    assert "--kind missing_auth" in readme
    assert "--exclude-kind malformed_json_body" in readme
    assert "--format json" in readme
    assert "knives-out report results.json --format html" in readme
    assert "--artifact-root artifacts" in readme
    assert "report.html" in readme
    assert "examples/openapi/storefront.yaml" in readme
    assert "examples/graphql/library.graphql" in readme
    assert "--graphql-endpoint /api/graphql" in readme
    assert "graphql-attacks.json" in readme
    assert "SUBSCRIBE" in readme
    assert "graphql-transport-ws" in readme
    assert "knives-out capture" in readme
    assert "knives-out discover capture.ndjson --out learned-model.json" in readme
    assert "knives-out generate learned-model.json --out shadow-attacks.json" in readme
    assert "capture.ndjson" in readme
    assert "learned-model.json" in readme
    assert "shadow-attacks.json" in readme
    assert "examples/auth_configs/user-admin.yml" in readme
    assert "examples/auth_configs/client-credentials.yml" in readme
    assert "--auth-config examples/auth_configs/user-admin.yml" in readme
    assert "--auth-profile user" in readme
    assert "examples/workflow_packs/listed_pet_lookup.py" in readme
    assert "**v0.11:** deeper GraphQL coverage" in readme
    assert "Shadow Twin learned-model capture is now" in readme
    assert "available." in readme


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
    assert "--auth-config examples/auth_configs/client-credentials.yml" in workflow
    assert "--auth-config examples/auth_configs/user-admin.yml" in workflow
    assert "--auth-profile user" in workflow
    assert "--profile-file examples/auth_profiles/anonymous-user-admin.yml" in workflow
    assert "--profile anonymous" in workflow
    assert 'knives-out run attacks.json "${args[@]}"' in workflow
    assert "knives-out report results.json --out report.md" in workflow
    assert "knives-out export results.json --format sarif --out results.sarif" in workflow
    assert "github/codeql-action/upload-sarif@v4" in workflow
    assert "sarif_file: results.sarif" in workflow
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
    assert "security-events: write" in workflow
    assert "results.sarif" in workflow


def test_ci_doc_describes_artifacts_and_optional_gating() -> None:
    ci_doc = CI_DOC.read_text(encoding="utf-8")

    assert "results.json" in ci_doc
    assert "report.md" in ci_doc
    assert "report.html" in ci_doc
    assert "results.sarif" in ci_doc
    assert "artifacts/" in ci_doc
    assert "Simple gating with no baseline" in ci_doc
    assert "Baseline-aware gating" in ci_doc
    assert "Optional: checked-in suppressions" in ci_doc
    assert "Optional: multi-profile authorization runs" in ci_doc
    assert "built-in auth config" in ci_doc
    assert "Optional: HTML report and artifact index" in ci_doc
    assert "Optional: GraphQL schemas" in ci_doc
    assert "SUBSCRIBE" in ci_doc
    assert "graphql-transport-ws" in ci_doc
    assert "Optional: Shadow Twin learned models" in ci_doc
    assert "learned-model.json" in ci_doc
    assert "capture.ndjson" in ci_doc
    assert "knives-out capture" in ci_doc
    assert "knives-out discover capture.ndjson --out learned-model.json" in ci_doc
    assert "GET /v1/jobs" in ci_doc
    assert "result_summary" in ci_doc
    assert "POST /v1/projects/{id}/review" in ci_doc
    assert "baseline_job_id" in ci_doc
    assert "examples/auth_configs/user-admin.yml" in ci_doc
    assert "examples/auth_configs/client-credentials.yml" in ci_doc
    assert "examples/auth_profiles/anonymous-user-admin.yml" in ci_doc
    assert "examples/graphql/library.graphql" in ci_doc
    assert "knives-out triage results.json --out .knives-out-ignore.yml" in ci_doc
    assert ".knives-out-ignore.yml" in ci_doc
    assert "--baseline previous-results.json" in ci_doc
    assert "status, severity, confidence, or schema outcome changed" in ci_doc
    assert "Persisting deltas" in ci_doc
    assert "Optional: local HTTP API" in ci_doc
    assert "knives-out serve --host 127.0.0.1 --port 8787" in ci_doc
    assert "POST /v1/inspect" in ci_doc
    assert "POST /v1/summary" in ci_doc
    assert "POST /v1/export" in ci_doc
    assert "POST /v1/runs" in ci_doc
    assert "DELETE /v1/jobs/{id}" in ci_doc
    assert "POST /v1/jobs/prune" in ci_doc
    assert "GET /v1/jobs/{id}/findings/{attack_id}/evidence" in ci_doc
    assert "KNIVES_OUT_API_DATA_DIR" in ci_doc
    assert "Dockerfile" in ci_doc
    assert "compose.yml" in ci_doc
    assert "compose.env.example" in ci_doc
    assert "docker build -t knives-out ." in ci_doc
    assert "docker compose up --build" in ci_doc
    assert "KNIVES_OUT_BASIC_AUTH_USERNAME" in ci_doc
    assert "KNIVES_OUT_BASIC_AUTH_PASSWORD" in ci_doc
    assert "knives-out summary results.json --out summary.json" in ci_doc
    assert "knives-out export results.json --format sarif --out results.sarif" in ci_doc
    assert "Optional: JUnit export for test reports" in ci_doc
    assert "--format junit" in ci_doc
    assert "results.xml" in ci_doc
    assert "github/codeql-action/upload-sarif@v4" in ci_doc
    assert "Generate attacks with built-in workflows" in ci_doc
    assert "--tag orders" in ci_doc
    assert "--path /draft-orders/{draftId}" in ci_doc
    assert "--kind missing_auth" in ci_doc
    assert "--exclude-kind malformed_json_body" in ci_doc
    assert "Promote qualifying findings" in ci_doc
    assert "pytest --cov=src/knives_out --cov-report=term-missing" in ci_doc
    assert "coverage-badge.json" in ci_doc
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


def test_main_maintenance_workflow_checks_docs_links_and_coverage_regressions() -> None:
    workflow = MAIN_MAINTENANCE_WORKFLOW.read_text(encoding="utf-8")

    assert "workflow_dispatch:" in workflow
    assert "branches:" in workflow
    assert "- main" in workflow
    assert "actions/upload-artifact@v6" in workflow
    assert "actions/github-script@v7" in workflow
    assert "contents: write" in workflow
    assert "ruff check ." in workflow
    assert "ruff format --check ." in workflow
    assert "tests/test_maintenance_scripts.py" in workflow
    assert "python scripts/check_markdown_links.py README.md docs" in workflow
    assert (
        'python scripts/sync_wiki.py render --out-dir "${{ runner.temp }}/wiki-render"' in workflow
    )
    assert (
        "pytest --cov=src/knives_out --cov-report=term-missing --cov-report=json:coverage.json"
        in workflow
    )
    assert "main-maintenance-coverage" in workflow
    assert "python scripts/sync_coverage_badge.py publish" in workflow
    assert "coverage-badge" in workflow
    assert "x-access-token:${GITHUB_TOKEN}" in workflow
    assert 'workflow_id: "main-maintenance.yml"' in workflow
    assert "python scripts/check_coverage_drop.py" in workflow


def test_roadmap_and_architecture_describe_next_milestones() -> None:
    roadmap = ROADMAP_DOC.read_text(encoding="utf-8")
    architecture = ARCHITECTURE_DOC.read_text(encoding="utf-8")

    assert "## Recently completed" in roadmap
    assert "v0.8: GraphQL schema support" in roadmap
    assert "v0.9: built-in auth acquisition and refresh flows" in roadmap
    assert "client_credentials" in roadmap
    assert "v0.10: Shadow Twin learned-model capture and discovery" in roadmap
    assert "learned-model artifacts" in roadmap
    assert "v0.11: deeper GraphQL coverage" in roadmap
    assert "v0.15: staged GraphQL subscription coverage" in roadmap
    assert "v0.16: ReviewOps baseline workbench" in roadmap
    assert "v0.17: Artifact deep dive drawer" in roadmap
    assert "## v0.14 — smoke-test integration coverage" in roadmap
    assert "deterministic fixture apps and checked-in inputs only" in roadmap
    assert "#58: CLI happy path against a local API fixture" in roadmap
    assert "tests/test_api_integration.py" in roadmap
    assert "real FastAPI app with uvicorn" in roadmap
    assert "LLM application and tool-misuse testing" in roadmap

    assert "capture.py" in architecture
    assert "api.py" in architecture
    assert "api_models.py" in architecture
    assert "api_store.py" in architecture
    assert "learned_discovery.py" in architecture
    assert "learned_loader.py" in architecture
    assert "graphql_loader.py" in architecture
    assert "services.py" in architecture
    assert "spec_loader.py" in architecture
    assert "auth_config.py" in architecture
    assert "builtin_auth.py" in architecture
    assert "OpenAPI, GraphQL, or learned traffic in" in architecture
    assert "learned-model.json" in architecture
    assert "`200` response" in architecture
    assert "`errors`" in architecture
    assert "built-in auth acquisition/refresh" in architecture
    assert "Shadow Twin inference around state machines" in architecture
    assert "GraphQL response-shape validation, federation awareness" in architecture
    assert "staged subscription attacks now use `graphql-transport-ws`" in architecture
    assert "CLI and the HTTP API now sit on top of `services.py`" in architecture
    assert "FastAPI surface" in architecture
    assert "redirect-driven OAuth auth-code flows" in architecture

    assert "v0.11: deeper GraphQL coverage" in roadmap
    assert "response-shape validation, federation-aware diagnostics" in roadmap
    assert "## v0.12 — local-first HTTP API" in roadmap
    assert "FastAPI server that mirrors the current CLI surface" in roadmap
    assert "background run jobs with polling and artifact retrieval" in roadmap
    assert "## v0.13 — richer CI and triage ergonomics" in roadmap
