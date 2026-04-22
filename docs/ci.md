# CI usage

`knives-out` is designed to fit a normal CI workflow:

1. generate a replayable attack suite from a checked-in OpenAPI schema, GraphQL schema, or learned model
2. optionally opt in to workflow generation for stateful coverage
3. run that suite against a dev or staging deployment
4. render a Markdown report for review
5. optionally render an HTML report with linked artifacts
6. optionally export SARIF for code scanning or PR-native review
7. optionally bundle the review inputs for local workbench import
8. verify the results against a CI policy
9. optionally promote qualifying findings into a smaller regression suite
10. optionally maintain a checked-in suppressions file for accepted findings
11. publish the JSON results, reports, SARIF export, review bundle, regression suite, and per-attack artifacts

The repository includes a ready-to-adapt GitHub Actions example at
`.github/workflows/dev-environment-example.yml`.

## Required secrets

The sample workflow expects:

- `KNIVES_OUT_BASE_URL`

Optional secrets:

- `KNIVES_OUT_AUTH_HEADER`
- `KNIVES_OUT_AUTH_QUERY`
- `KNIVES_OUT_USER_TOKEN`
- `KNIVES_OUT_ADMIN_TOKEN`
- `KNIVES_OUT_CLIENT_ID`
- `KNIVES_OUT_CLIENT_SECRET`
- `KNIVES_OUT_CLIENT_AUDIENCE`
- plugin-specific login or bearer env vars if you use an auth plugin module

The optional values should match the current CLI surface:

- `KNIVES_OUT_AUTH_HEADER`: `Authorization: Bearer dev-token`
- `KNIVES_OUT_AUTH_QUERY`: `api_key=dev-secret`

For static credentials, `--header` and `--query` are still the simplest fit. For common auth
flows, prefer `--auth-config examples/auth_configs/user-admin.yml` or
`--auth-config examples/auth_configs/client-credentials.yml`. Use auth/session plugins when your
CI flow needs custom logic beyond the built-in bearer and session-cookie strategies.

If you want identity-aware authorization coverage, the repo also includes
`examples/auth_profiles/anonymous-user-admin.yml` as a starter profile file.

For richer checked-in examples, the repo now includes `examples/openapi/storefront.yaml`, which
combines exact tags, path filters, schema constraints, and a producer/consumer workflow chain.
For GraphQL, the repo includes `examples/graphql/library.graphql`, which demonstrates query and
mutation variable attacks from SDL input.
When you have incomplete specs, Shadow Twin can instead learn a replayable `learned-model.json`
from captured staging traffic and feed that into the same generate/run/report flow.

## Expected exit behavior

`knives-out run` currently exits with status `0` when it finishes executing the suite, even if the
results contain flagged findings such as `server_error`, `unexpected_success`, or
`response_schema_mismatch`.

That default behavior is intentional for review-first workflows:

- `results.json` stays available for automation
- `report.md` stays available for humans
- `report.html` can present a linked artifact index for faster triage
- `results.sarif` can feed code scanning and pipeline-native review systems
- `artifacts/` keeps one request/response record per attack for debugging

`knives-out verify` is the built-in gating step. It reads `results.json`, applies severity and
confidence thresholds, and exits with:

- `0` when the policy passes
- `1` when the policy fails

If `.knives-out-ignore.yml` exists in the repository root, `report`, `verify`, and `promote` load
it automatically. Use `--suppressions path/to/file.yml` to point at a different suppression file.

## Simple gating with no baseline

Use this when you want CI to fail on qualifying findings in the current run:

```yaml
- name: Verify findings
  run: |
    knives-out verify results.json \
      --min-severity high \
      --min-confidence medium
```

## Baseline-aware gating

If your workflow can provide a prior `results.json`, `verify` can fail only on new qualifying
findings:

```yaml
- name: Verify against baseline
  run: |
    knives-out verify results.json \
      --baseline previous-results.json \
      --min-severity high \
      --min-confidence medium
```

The tool does not fetch that baseline for you. Your workflow is responsible for placing
`previous-results.json` in the workspace before this step.
When you use a baseline, `verify` also prints a compact summary for persisting findings whose
status, severity, confidence, or schema outcome changed between runs.

## Optional: SARIF export for code scanning

Use this when you want the active unsuppressed findings to show up in GitHub code scanning or any
other SARIF-capable pipeline sink. This export is complementary to `verify`: it helps teams review
findings in native CI surfaces, but it does not change pass/fail behavior by itself.

The simplest form is:

```bash
knives-out export results.json --format sarif --out results.sarif
```

```yaml
permissions:
  contents: read
  security-events: write
```

```yaml
- name: Export SARIF findings
  if: always()
  run: |
    knives-out export results.json \
      --format sarif \
      --out results.sarif
    # To add regression context to the SARIF properties:
    # knives-out export results.json \
    #   --format sarif \
    #   --baseline previous-results.json \
    #   --out results.sarif
```

```yaml
- name: Upload SARIF to GitHub code scanning
  if: always()
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: results.sarif
```

## Optional: checked-in suppressions

Use suppressions when the team has reviewed a finding and wants CI to stay focused on active,
unsuppressed regressions.

Seed a review-ready file from the current active findings:

```yaml
- name: Seed or refresh suppressions for review
  if: always()
  run: knives-out triage results.json --out .knives-out-ignore.yml
```

The generated file includes placeholder `reason` and `owner` fields so a reviewer can edit the
entries before committing them. A typical checked-in file looks like:

```yaml
suppressions:
  - attack_id: atk_create_pet_missing_body
    issue: server_error
    operation_id: createPet
    method: POST
    path: /pets
    tags:
      - pets
      - write
    reason: Known issue tracked in API backlog
    owner: api-team
    expires_on: 2026-06-30
```

If you keep that file at the repo root, the standard commands pick it up automatically:

```yaml
- name: Verify findings with checked-in suppressions
  run: knives-out verify results.json
```

```yaml
- name: Promote qualifying findings with checked-in suppressions
  if: always()
  run: |
    knives-out promote results.json \
      --attacks attacks.json \
      --out regression-attacks.json
```

## Optional: portable review bundle handoff

When CI needs to hand the exact review inputs to a developer’s local workbench, build a portable
zip bundle after the run finishes:

```yaml
- name: Package a portable review bundle
  if: always()
  run: |
    knives-out bundle results.json \
      --artifact-dir artifacts \
      --out review-bundle.zip
    knives-out inspect-bundle review-bundle.zip
    # Optional review context:
    # knives-out bundle results.json \
    #   --baseline previous-results.json \
    #   --artifact-dir artifacts \
    #   --name "Staging review handoff" \
    #   --min-severity medium \
    #   --min-confidence low \
    #   --out review-bundle.zip
```

The resulting zip has a fixed layout:

- `manifest.json`
- `current/results.json`
- `baseline/results.json` when `--baseline` is present
- `review/suppressions.yml` when suppressions are present
- `artifacts/**` when `--artifact-dir` is present

Import that file from the workbench home page with **Import review bundle**. v1 imports are
review-only on purpose: they materialize one completed `import` job plus project review state so
the existing review tabs, suppressions editor, run history, and artifact inspection keep working.
Use `knives-out inspect-bundle review-bundle.zip --format json` when a CI job needs a
machine-readable validation step before publishing the zip as an artifact.

## Optional: project snapshot validation

Project snapshots are exported from the local API or workbench when a developer needs to move a
rerunnable saved project, including source, drafts, generated suite, project-scoped job history,
stored results, and artifacts. Before publishing or importing that archive, validate it with the
same loader used by workbench import:

```bash
knives-out inspect-snapshot project-snapshot.zip
knives-out inspect-snapshot project-snapshot.zip --format json
```

The JSON form exposes manifest counts and job status counts for CI gates that need to confirm the
archive is complete before attaching it to a workflow run or handing it to another workbench.

## Optional: stateful workflow coverage

Start simple with request-only generation:

```yaml
- name: Generate request attacks
  run: knives-out generate "$SPEC_PATH" --out attacks.json
```

When you want stateful setup-plus-terminal coverage, opt in:

```yaml
- name: Generate attacks with built-in workflows
  run: knives-out generate "$SPEC_PATH" --auto-workflows --out attacks.json
```

You can add app-specific journeys by loading a workflow pack module or entry point:

```yaml
- name: Generate attacks with custom workflows
  run: |
    knives-out generate "$SPEC_PATH" \
      --auto-workflows \
      --workflow-pack-module examples/workflow_packs/listed_pet_lookup.py \
      --out attacks.json
```

## Optional: GraphQL schemas

GraphQL SDL or introspection JSON follows the same generate/run/report/verify flow. The generated
attacks target invalid variables, required-variable removal, and type coercion failures.
When the schema includes subscriptions, the generated suite also includes staged `SUBSCRIBE`
attacks that use `graphql-transport-ws`, wait only up to the normal run timeout for the first
event or error frame, and report protocol failures separately from application findings.

```yaml
- name: Inspect a GraphQL schema
  run: knives-out inspect examples/graphql/library.graphql
```

```yaml
- name: Generate GraphQL attacks
  run: |
    knives-out generate examples/graphql/library.graphql \
      --graphql-endpoint /graphql \
      --out graphql-attacks.json
```

## Optional: local HTTP API

If another local tool needs to drive the workflow without shelling out to the CLI, start the
server on loopback:

```yaml
- name: Start local knives-out API
  run: knives-out serve --host 127.0.0.1 --port 8787
```

The API mirrors the same JSON artifacts through `POST /v1/inspect`, `POST /v1/generate`,
`POST /v1/discover`, `POST /v1/export`, `POST /v1/report`, `POST /v1/summary`, `POST /v1/verify`,
`POST /v1/promote`, `POST /v1/triage`, and background `POST /v1/runs` jobs with `GET /v1/jobs` browsing and
`GET /v1/jobs/{id}` polling.
Completed jobs expose a compact `result_summary` on the collection and status responses so
downstream local tools can rank recent runs before fetching full result payloads.
Saved projects also expose `POST /v1/projects/import-review-bundle`,
`GET /v1/projects/{id}/jobs`, and `POST /v1/projects/{id}/review` for the workbench’s
baseline-aware review loop. Imported review bundles create a new `review_bundle` project plus one
completed `import` job, while the review endpoint always compares the latest completed run in the
project against an optional pinned `baseline_job_id` from the same project, with external baseline
JSON kept as an explicit advanced fallback.
For current-run drilldown, `GET /v1/jobs/{id}/findings/{attack_id}/evidence` returns the selected
finding result, typed artifact references derived from stored filenames, workflow/profile metadata,
and the run’s auth-event context. Raw artifact bodies stay on
`GET /v1/jobs/{id}/artifacts/{artifact_name}` so local tools can load them lazily.
When local tools need cleanup, use `DELETE /v1/jobs/{id}` for a specific completed or failed run or
`POST /v1/jobs/prune` to remove older completed/failed jobs in batch.
Use `KNIVES_OUT_API_DATA_DIR` when you want the job store somewhere other than `.knives-out-api/`.

For a small same-origin self-hosted deployment, the repo also ships a `Dockerfile`, `compose.yml`,
and `compose.env.example`. Build the image with `docker build -t knives-out .`, run it with
`docker run`, or copy the env example to `.env` and use `docker compose up --build`. When you set
both `KNIVES_OUT_BASIC_AUTH_USERNAME` and `KNIVES_OUT_BASIC_AUTH_PASSWORD`, the app protects the
workbench and `/v1/*` API with HTTP Basic auth while leaving `/healthz` open for probes.

## Optional: machine-readable summary export

When CI, chatops, or downstream dashboards need a compact JSON artifact instead of full Markdown or
HTML, render a summary file after execution:

```yaml
- name: Build machine-readable summary
  run: knives-out summary results.json --out summary.json
```

When GitHub Actions reviewers need a smaller human-readable note in the job UI, render the same
summary as Markdown and append it to the step summary:

```yaml
- name: Publish knives-out job summary
  run: knives-out summary results.json --format markdown >> "$GITHUB_STEP_SUMMARY"
```

## Optional: Shadow Twin learned models

Shadow Twin adds a capture/discover front end for real-behavior API learning when the checked-in
spec is incomplete or missing workflow detail.

```yaml
- name: Capture traffic through a local proxy
  run: |
    knives-out capture \
      --target-base-url "${KNIVES_OUT_BASE_URL}" \
      --out capture.ndjson \
      --max-events 100
```

```yaml
- name: Discover a learned model from captured traffic
  run: knives-out discover capture.ndjson --out learned-model.json
```

```yaml
- name: Generate learned attacks
  run: knives-out generate learned-model.json --out attacks.json
```

## Optional: tag, path, and kind filtering

The same exact-match filters work in `inspect`, `generate`, and `run`, and `generate` also
supports repeatable attack-kind filters for narrowing or muting specific attack categories:

```yaml
- name: Generate only order-related attacks
  run: |
    knives-out generate "$SPEC_PATH" \
      --tag orders \
      --path /draft-orders/{draftId} \
      --out attacks.json
```

```yaml
- name: Run only order-related attacks
  run: |
    knives-out run attacks.json \
      --base-url "${KNIVES_OUT_BASE_URL}" \
      --tag orders \
      --path /draft-orders/{draftId} \
      --out results.json
```

```yaml
- name: Generate only auth-focused attacks
  run: |
    knives-out generate "$SPEC_PATH" \
      --kind missing_auth \
      --out attacks.json
```

```yaml
- name: Exclude noisy malformed-body attacks
  run: |
    knives-out generate "$SPEC_PATH" \
      --exclude-kind malformed_json_body \
      --out attacks.json
```

## Optional: auth/session plugins

For many protected APIs, a built-in auth config is enough:

```yaml
- name: Run suite with built-in auth config
  run: |
    knives-out run attacks.json \
      --base-url "${KNIVES_OUT_BASE_URL}" \
      --auth-config examples/auth_configs/client-credentials.yml \
      --artifact-dir artifacts \
      --out results.json
```

Or execute checked-in named auth configs as profiles:

```yaml
- name: Run suite across built-in user and admin auth configs
  run: |
    knives-out run attacks.json \
      --base-url "${KNIVES_OUT_BASE_URL}" \
      --auth-config examples/auth_configs/user-admin.yml \
      --auth-profile user \
      --auth-profile admin \
      --artifact-dir artifacts \
      --out results.json
```

Built-in auth config examples live at:

- `examples/auth_configs/user-admin.yml`
- `examples/auth_configs/client-credentials.yml`

If your target needs custom Python logic instead, fall back to plugins:

For login or shared-session flows, load a local auth plugin module during `run`:

```yaml
- name: Run suite with an auth plugin
  run: |
    knives-out run attacks.json \
      --base-url "${KNIVES_OUT_BASE_URL}" \
      --auth-plugin-module examples/auth_plugins/login_bearer.py \
      --artifact-dir artifacts \
      --out results.json
```

The sample `examples/auth_plugins/login_bearer.py` expects:

- `KNIVES_OUT_LOGIN_USERNAME`
- `KNIVES_OUT_LOGIN_PASSWORD`

You can also install auth plugins as entry points and load them with `--auth-plugin env-bearer`.

## Optional: multi-profile authorization runs

To compare the same suite across multiple identities, pass a profile file to `run`:

```yaml
- name: Run suite across anonymous, user, and admin profiles
  run: |
    knives-out run attacks.json \
      --base-url "${KNIVES_OUT_BASE_URL}" \
      --profile-file examples/auth_profiles/anonymous-user-admin.yml \
      --artifact-dir artifacts \
      --out results.json
```

You can narrow the run to a subset of profiles when needed:

```yaml
- name: Run only anonymous and admin profiles
  run: |
    knives-out run attacks.json \
      --base-url "${KNIVES_OUT_BASE_URL}" \
      --profile-file examples/auth_profiles/anonymous-user-admin.yml \
      --profile anonymous \
      --profile admin \
      --out results.json
```

Each profile can contribute its own headers, query params, installed auth plugins, or local
`auth_plugin_modules`. The resulting `results.json` keeps a normal top-level result list so
`report`, `verify`, `promote`, and suppressions continue to work, while the Markdown report adds
per-profile outcome tables for deeper authorization review.

## Optional: baseline-aware report

You can also render a Markdown report that highlights new, resolved, and persisting findings,
including delta notes when a persisting finding changed severity, confidence, status, or schema:

```yaml
- name: Render baseline-aware report
  run: |
    knives-out report results.json \
      --baseline previous-results.json \
      --out report.md
```

That baseline-aware report includes the usual new/resolved/persisting sections plus a
`Persisting deltas` section for persisting findings that drifted between runs.

## Optional: HTML report and artifact index

When you already capture per-attack request and response artifacts, `report` can also emit an
HTML view with linked artifacts, detailed result cards, and profile/workflow sections:

```yaml
- name: Render HTML report
  run: |
    knives-out report results.json \
      --format html \
      --artifact-root artifacts \
      --out report.html
```

## Optional: promote a regression suite

When you want to preserve only qualifying findings as a smaller replayable suite, use `promote`:

```yaml
- name: Promote qualifying findings
  if: always()
  run: |
    knives-out promote results.json \
      --attacks attacks.json \
      --out regression-attacks.json
```

To promote only new regressions, pass the same baseline file you use with `verify`:

```yaml
- name: Promote new qualifying regressions
  if: always()
  run: |
    knives-out promote results.json \
      --attacks attacks.json \
      --baseline previous-results.json \
      --out regression-attacks.json
```

## Coverage in repository CI

The repository now has two complementary repository workflows:

- `ci.yml` runs on pushes and pull requests to keep the main Python test and lint loop fast
- `main-maintenance.yml` runs on pushes to `main` and `workflow_dispatch` for deeper post-merge maintenance checks

The `main-maintenance.yml` workflow currently runs:

- `ruff check .`
- `ruff format --check .`
- `pytest tests/test_docs.py tests/test_sync_wiki.py tests/test_examples.py tests/test_maintenance_scripts.py`
- `python scripts/check_markdown_links.py README.md docs`
- `python scripts/sync_wiki.py render --out-dir ...`
- `pytest --cov=src/knives_out --cov-report=term-missing --cov-report=json:coverage.json`
- `python scripts/sync_coverage_badge.py publish ...`

After the full test pass, it uploads `coverage.json` as the `main-maintenance-coverage` artifact,
publishes a Shields-compatible `coverage-badge.json` file to the repo's `badges` branch for the
README badge, downloads the previous successful artifact from the same workflow on `main`, and
fails if total coverage drops. The first successful run seeds both the baseline and badge branch
automatically, so there is no separate manual setup step.
