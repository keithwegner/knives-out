# knives-out

<p align="center">
  <img src="docs/assets/knives-out-logo.svg" alt="knives-out logo" width="460">
</p>

[![CI](https://github.com/keithwegner/knives-out/actions/workflows/ci.yml/badge.svg)](https://github.com/keithwegner/knives-out/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/keithwegner/knives-out/badges/coverage-badge.json)](https://github.com/keithwegner/knives-out/actions/workflows/main-maintenance.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Project wiki: [GitHub Wiki](https://github.com/keithwegner/knives-out/wiki)

Community: [Code of Conduct](CODE_OF_CONDUCT.md) · [Contributing](CONTRIBUTING.md) ·
[Security Policy](SECURITY.md) ·
[Discussions](https://github.com/keithwegner/knives-out/discussions)

`knives-out` is a CLI for adversarial API testing from API specs and observed traffic.

It helps developers break their APIs on purpose before someone else does.

## Table of contents

- [What it does](#what-it-does)
- [Current attack types](#current-attack-types)
- [Why this shape](#why-this-shape)
- [Quick start](#quick-start)
- [Web workbench](#web-workbench)
  - [GitHub Pages](#github-pages)
- [Local API](#local-api)
- [Container deployment](#container-deployment)
- [CI usage](#ci-usage)
- [CLI](#cli)
  - [`inspect`](#inspect)
  - [`generate`](#generate)
  - [`run`](#run)
  - [`report`](#report)
  - [`export`](#export)
  - [`verify`](#verify)
  - [`promote`](#promote)
  - [`triage`](#triage)
- [Development](#development)
  - [Dev Container](#dev-container)
- [Custom attack packs](#custom-attack-packs)
- [Custom workflow packs](#custom-workflow-packs)
- [Built-in auth configs](#built-in-auth-configs)
- [Auth/session plugins](#authsession-plugins)
- [Roadmap](#roadmap)

## What it does

Given an OpenAPI spec, GraphQL schema, or learned traffic model, `knives-out` can:

- inspect the operations in the spec
- capture redacted HTTP traffic through a local reverse proxy
- discover a replayable learned API model from `capture.ndjson` or HAR files
- generate replayable negative test cases
- generate schema-aware mutation attacks from declared constraints
- generate learned invariant attacks from observed producer/consumer workflows
- optionally chain setup requests into replayable workflow attacks
- generate GraphQL query and mutation attacks from SDL or introspection output
- load built-in auth configs for common bearer-token and session-cookie flows
- load auth/session plugins for bearer tokens, login flows, and shared sessions
- execute the same suite across named auth profiles and compare their outcomes
- run those attacks against a live base URL
- produce a Markdown report that highlights suspicious outcomes
- produce an HTML report with linked request and response artifacts
- export SARIF findings for CI-native code-scanning review
- verify findings for CI gating
- promote qualifying findings back into a reusable regression suite
- suppress or triage known findings so CI stays focused on active risk

The initial focus is narrow by design:

- OpenAPI, GraphQL, and learned HTTP input
- replayable JSON artifacts
- deterministic attack generation
- CI-friendly output

## Current attack types

The starter scaffold generates a first wave of useful negative tests:

- missing required query/header parameters
- wrong-type parameter values
- invalid enum values
- below-minimum and above-maximum numeric values
- too-short and too-long string values
- too-few and too-many array items
- invalid `uuid`, `email`, `date`, `date-time`, and `uri` formats
- unexpected JSON properties and missing required JSON properties
- missing request bodies
- malformed JSON bodies
- missing auth headers or query credentials when the spec declares security
- opt-in setup-plus-terminal workflow attacks that reuse extracted response values
- GraphQL variable type coercion, required-variable removal, and invalid enum values
- learned missing-setup, stale-reference, and invalid lifecycle reuse attacks

This is not a full fuzzing engine yet. It is a structured attack generator, runner, and CI gate.

## Why this shape

The project is split into three explicit phases:

1. **Generate** attack cases from the spec.
2. **Run** those attack cases against a target.
3. **Report** findings in a stable, reviewable format.

That makes the architecture easier to evolve further with:

- custom attack packs
- deeper stateful workflows
- Shadow Twin discovery from real traffic
- LLM application testing
- richer CI policies
- protocol expansion beyond OpenAPI REST

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Inspect the sample specs:

```bash
knives-out inspect examples/openapi/petstore.yaml
knives-out inspect examples/openapi/storefront.yaml --tag orders
knives-out inspect examples/graphql/library.graphql
```

Generate attacks:

```bash
knives-out generate examples/openapi/petstore.yaml --out attacks.json
knives-out generate examples/openapi/storefront.yaml --tag orders --out attacks.json
knives-out generate examples/openapi/petstore.yaml --kind missing_auth --out auth-attacks.json
knives-out generate examples/openapi/petstore.yaml --exclude-kind malformed_json_body --out quieter-attacks.json
knives-out generate examples/graphql/library.graphql --out graphql-attacks.json
```

Learn a model from real traffic:

```bash
knives-out capture \
  --target-base-url http://localhost:8000 \
  --out capture.ndjson

knives-out discover capture.ndjson --out learned-model.json
knives-out inspect learned-model.json
knives-out generate learned-model.json --out shadow-attacks.json
```

The learned model keeps auth material redacted, records confidence-scored workflows, and feeds the
same replayable attack suite format as spec-driven generation.

If your GraphQL endpoint is not `/graphql`, pass it during inspection or generation:

```bash
knives-out generate examples/graphql/library.graphql \
  --graphql-endpoint /api/graphql \
  --out graphql-attacks.json
```

Opt in to built-in stateful workflows:

```bash
knives-out generate examples/openapi/storefront.yaml \
  --tag orders \
  --auto-workflows \
  --out attacks.json
```

The checked-in `examples/openapi/storefront.yaml` demonstrates exact tag/path filters, schema
constraints, and a producer/consumer workflow chain via `createDraftOrder` -> `getDraftOrder`.

Run them against a live API:

```bash
knives-out run attacks.json \
  --base-url http://localhost:8000 \
  --header "Authorization: Bearer dev-token" \
  --out results.json
```

Or use a built-in auth config when static headers are not enough:

```bash
knives-out run attacks.json \
  --base-url http://localhost:8000 \
  --auth-config examples/auth_configs/user-admin.yml \
  --auth-profile user \
  --out results.json
```

Or move up to a custom plugin when the built-in config strategies are not enough:

```bash
knives-out run attacks.json \
  --base-url http://localhost:8000 \
  --auth-plugin-module examples/auth_plugins/login_bearer.py \
  --out results.json
```

Or execute the same suite across named profiles:

```bash
knives-out run attacks.json \
  --base-url http://localhost:8000 \
  --profile-file examples/auth_profiles/anonymous-user-admin.yml \
  --out results.json
```

Create a Markdown report:

```bash
knives-out report results.json --out report.md
```

Or render an HTML report with an artifact index for CI review:

```bash
knives-out report results.json --format html --artifact-root artifacts --out report.html
```

Verify findings against the default CI policy:

```bash
knives-out verify results.json
```

Generate a machine-readable summary for dashboards or CI annotations:

```bash
knives-out summary results.json --out summary.json
```

Publish a compact Markdown summary in GitHub Actions:

```bash
knives-out summary results.json --format markdown >> "$GITHUB_STEP_SUMMARY"
```

Export active findings as SARIF for CI-native code scanning:

```bash
knives-out export results.json --format sarif --out results.sarif
```

Promote qualifying findings back into a reusable regression suite:

```bash
knives-out promote results.json --attacks attacks.json --out regression-attacks.json
```

Generate a review-ready suppressions file for known findings:

```bash
knives-out triage results.json --out .knives-out-ignore.yml
```

## Web workbench

`knives-out` also includes a local-first web workbench for saved projects, guided attack
generation, background runs, and native review panels.

The review step is now baseline-first: it treats the latest completed run in a saved project as the
current comparison target, lets you pin an older completed project run as the baseline, and keeps
that baseline selection in the saved project draft. Raw baseline JSON is still available, but only
as an advanced external fallback when project history is not the right comparison source.
Inside that review step, findings in Overview, New, Persisting, and Deltas now open an inline
evidence drawer for the current compared run. The drawer resolves linked request/response
artifacts, workflow setup steps, per-profile evidence, and run auth events without forcing you to
leave the workbench or manually guess artifact filenames.

For normal local use, build the frontend once and let the API serve it under `/app/`:

```bash
cd frontend
npm install
npm run build
cd ..

knives-out serve --host 127.0.0.1 --port 8787
```

Then open [http://127.0.0.1:8787/app/](http://127.0.0.1:8787/app/).

By default the API looks for built frontend assets in `frontend/dist/`. Set
`KNIVES_OUT_FRONTEND_DIR` if you want to serve a different build output directory.

For frontend development, run the API and Vite side by side:

```bash
# terminal 1
knives-out serve --host 127.0.0.1 --port 8787

# terminal 2
cd frontend
npm install
npm run dev -- --host 127.0.0.1
```

Then open [http://127.0.0.1:4173/app/](http://127.0.0.1:4173/app/). The Vite dev server proxies
`/v1` and `/healthz` to the API on `127.0.0.1:8787`.

The workbench is still single-user and self-hosted in v1. You can run it directly on localhost or
inside a small same-origin Docker deployment, but it is not intended as a multi-tenant service.
Saved project drafts, jobs, and artifacts all live under `.knives-out-api/` unless you override
`KNIVES_OUT_API_DATA_DIR`.

### GitHub Pages

This repository also includes a GitHub Pages workflow at `.github/workflows/pages.yml` that
publishes the frontend as a static SPA under the repository path, for example
`https://keithwegner.github.io/knives-out/`.

That Pages site is only the frontend shell. To make it functional you must point it at a reachable
`knives-out` API:

1. deploy the API somewhere reachable over HTTPS
2. enable CORS on that API with `KNIVES_OUT_CORS_ALLOW_ORIGINS=https://keithwegner.github.io`
3. open the published Pages site and set the API base URL in the `API endpoint` panel

If you prefer a baked-in default for the static build, set `VITE_API_BASE_URL` when building the
frontend for Pages.

## Local API

`knives-out` can also run as a local-first HTTP API instead of only as a CLI.

Start it on the loopback interface:

```bash
knives-out serve --host 127.0.0.1 --port 8787
```

By default the API stores job state and request/response artifacts under `.knives-out-api/`.
Set `KNIVES_OUT_API_DATA_DIR` if you want that store somewhere else.

For browser clients hosted on a different origin, set `KNIVES_OUT_CORS_ALLOW_ORIGINS` to a
comma-separated list of allowed origins, for example:

```bash
export KNIVES_OUT_CORS_ALLOW_ORIGINS="https://keithwegner.github.io"
knives-out serve --host 0.0.0.0 --port 8787
```

The synchronous endpoints mirror the short CLI flows:

- `POST /v1/inspect`
- `POST /v1/generate`
- `POST /v1/discover`
- `POST /v1/export`
- `POST /v1/report`
- `POST /v1/summary`
- `POST /v1/verify`
- `POST /v1/promote`
- `POST /v1/triage`

Longer execution runs use a job resource instead:

- `POST /v1/runs`
- `GET /v1/jobs`
- `GET /v1/jobs/{id}`
- `DELETE /v1/jobs/{id}`
- `POST /v1/jobs/prune`
- `GET /v1/jobs/{id}/result`
- `GET /v1/jobs/{id}/findings/{attack_id}/evidence`
- `GET /v1/jobs/{id}/artifacts`

The job collection and per-job status routes include a compact `result_summary` payload whenever a
run has finished writing `result.json`, so local tools can triage recent runs without downloading
the full result body first.
When a caller needs structured drilldown for a current-run finding, `GET /v1/jobs/{id}/findings/{attack_id}/evidence`
returns the selected result plus typed artifact references, workflow/profile metadata, and run auth
context, while raw artifact bodies still come from `GET /v1/jobs/{id}/artifacts/{artifact_name}`.
Cleanup stays explicit and local-only: the delete and prune endpoints only remove completed or failed jobs,
and active jobs must finish before they can be deleted.

The web workbench also uses project resources for saved drafts and project-scoped run history:

- `GET /v1/projects`
- `POST /v1/projects`
- `GET /v1/projects/{id}`
- `PATCH /v1/projects/{id}`
- `DELETE /v1/projects/{id}`
- `GET /v1/projects/{id}/jobs`
- `POST /v1/projects/{id}/review`
- `DELETE /v1/projects/{id}/jobs/{job_id}`
- `POST /v1/projects/{id}/jobs/prune`

`POST /v1/projects/{id}/review` bundles the summary, verify, and report refresh path that the web
workbench uses. It always reviews the latest completed run with stored results in that project as
the current run, accepts an optional `baseline_job_id` from the same project, and only falls back
to external baseline JSON when the review draft switches to external baseline mode.

The API accepts uploaded source content and JSON artifacts in the request body. It does not expose
arbitrary server-side file reads. FastAPI also publishes the schema at `/openapi.json` and the
interactive docs at `/docs`.

## Container deployment

The repository now includes a first-party `Dockerfile`, `compose.yml`, and `compose.env.example`
for a same-origin self-hosted deployment. That path avoids the GitHub Pages CORS and API-base
setup dance because the frontend shell and `/v1/*` API live behind one origin.

Build the image:

```bash
docker build -t knives-out .
```

Run it directly with a persistent volume:

```bash
docker run --rm \
  -p 127.0.0.1:8787:8787 \
  -v knives-out-data:/var/lib/knives-out \
  knives-out
```

Then open [http://127.0.0.1:8787/app/](http://127.0.0.1:8787/app/).

If you want a lightweight exposure guard for an end user, set both
`KNIVES_OUT_BASIC_AUTH_USERNAME` and `KNIVES_OUT_BASIC_AUTH_PASSWORD`:

```bash
docker run --rm \
  -p 127.0.0.1:8787:8787 \
  -v knives-out-data:/var/lib/knives-out \
  -e KNIVES_OUT_BASIC_AUTH_USERNAME=demo \
  -e KNIVES_OUT_BASIC_AUTH_PASSWORD=change-me \
  knives-out
```

That enables HTTP Basic auth for `/`, `/app/*`, `/v1/*`, `/docs`, and `/openapi.json`, while
keeping `/healthz` unauthenticated for container and load-balancer health checks.

For the default self-hosted path, use Compose:

```bash
cp compose.env.example .env
# edit .env before exposing the service
docker compose up --build -d
```

The example env file documents:

- bind host and published port
- the persistent data directory inside the container
- optional basic-auth credentials
- optional `KNIVES_OUT_CORS_ALLOW_ORIGINS` for advanced split-origin deployments

The same-origin container deployment is the recommended exposed setup in v1. It is still
single-user and not a multi-tenant service, and TLS is expected to be terminated outside the app
when you move beyond localhost.

## CI usage

`knives-out` works well in CI when you follow the same generate/run/report flow and add a final
verification step:

1. generate attacks from a checked-in OpenAPI spec, GraphQL schema, or learned model
2. run them against a dev or staging environment
3. render a Markdown report for review
4. optionally render an HTML report with linked artifacts
5. verify the results against a CI policy
6. optionally promote qualifying findings into a smaller regression suite
7. upload the JSON results, reports, and request artifacts for triage

A ready-to-adapt GitHub Actions example lives at `.github/workflows/dev-environment-example.yml`.
It uses repository secrets instead of hard-coded targets:

- `KNIVES_OUT_BASE_URL` for the dev or staging base URL
- `KNIVES_OUT_AUTH_HEADER` for an optional header like `Authorization: Bearer ...`
- `KNIVES_OUT_AUTH_QUERY` for an optional query credential like `api_key=...`
- `KNIVES_OUT_USER_TOKEN` / `KNIVES_OUT_ADMIN_TOKEN` when you use `examples/auth_configs/user-admin.yml`
- `KNIVES_OUT_CLIENT_ID` / `KNIVES_OUT_CLIENT_SECRET` / `KNIVES_OUT_CLIENT_AUDIENCE` when you use
  `examples/auth_configs/client-credentials.yml`
- plugin-specific login or bearer env vars when you use `--auth-plugin` or `--auth-plugin-module`

`knives-out run` currently exits with status `0` when the suite executes successfully, even if
some findings are flagged in `results.json`. That keeps execution review-friendly:
teams can always upload `results.json`, `report.md`, and per-attack artifacts for triage.
For faster review inside CI artifacts, `knives-out report --format html --artifact-root artifacts`
also produces a linked `report.html` with an artifact index and detailed result cards.

For built-in gating, use `knives-out verify` after `run`. It can fail on qualifying findings in the
current run, or only on new qualifying findings when you also pass `--baseline previous-results.json`.
With a baseline, both `verify` and baseline-aware `report` also summarize persisting findings whose
status, severity, confidence, or schema outcome drifted between runs.
When you want a compact machine-readable artifact for dashboards, annotations, or follow-on
automation, `knives-out summary results.json --out summary.json` emits the same counts and top
findings as structured JSON. For a smaller human-readable CI note, append
`knives-out summary results.json --format markdown` output to `$GITHUB_STEP_SUMMARY`.
When you want code-scanning or PR-native triage inside CI, `knives-out export results.json --format sarif --out results.sarif`
emits SARIF 2.1.0 from the same active unsuppressed findings, with optional baseline change
metadata when you also pass `--baseline previous-results.json`.
When you want stateful coverage, generate with `--auto-workflows` first, then add
`--workflow-pack-module examples/workflow_packs/listed_pet_lookup.py` or your own custom pack as
you move from generic coverage to app-specific journeys. For protected APIs, keep simple static
credentials on `--header` or `--query`, or move up to
`--auth-config examples/auth_configs/user-admin.yml` or
`--auth-config examples/auth_configs/client-credentials.yml` for common bearer/session flows.
Custom logic can still use `--auth-plugin-module examples/auth_plugins/login_bearer.py`. When you
want to keep only the highest-signal regressions around, follow `verify` with
`knives-out promote results.json --attacks attacks.json`. See `docs/ci.md` for the sample
workflow, secret setup, filtering patterns, baseline-aware CI flows, and checked-in suppressions.
GraphQL schemas follow the same `inspect` / `generate` / `run` / `report` / `verify` flow, with
`generate` automatically emitting variable-coercion attacks from SDL or introspection input.
Generated GraphQL contracts now stay fragment-aware across nested selection sets, response-shape
validation, and response-schema metadata for object, interface, and union results.
Subscription roots are now staged into the same artifact flow as `SUBSCRIBE` attacks when the
schema exposes them, using the `graphql-transport-ws` protocol and capturing the first event or
error frame within the normal `--timeout` budget.
Shadow Twin capture and discovery fit the same path too:
`capture -> discover -> generate -> run -> report -> verify`.
If you want to drive that workflow from another local tool instead of shelling out, `knives-out serve`
now exposes the same core actions over HTTP with background `run` jobs, summary responses, export
responses, and
artifact download routes.
If you keep a `.knives-out-ignore.yml` file in the repo root, `report`, `verify`, and `promote`
will load it automatically. Use `knives-out triage results.json` to seed new entries when you want
to capture known findings without hand-writing YAML. For authorization-focused regression coverage,
you can also run one suite across `anonymous`, `user`, and `admin` profiles with
`--profile-file examples/auth_profiles/anonymous-user-admin.yml`.

## CLI

### `inspect`

Shows a summary of operations discovered in an OpenAPI document, GraphQL schema, or learned model.

```bash
knives-out inspect path/to/openapi.yaml
```

GraphQL SDL or introspection JSON works too:

```bash
knives-out inspect examples/graphql/library.graphql --graphql-endpoint /graphql
```

`inspect` surfaces preflight warnings for spec gaps such as missing request schemas, vague
security declarations, broken `$ref` pointers, and low-confidence learned inferences.

Learned-model inputs work with the same command:

```bash
knives-out inspect learned-model.json
```

You can filter inspection to exact tags or paths:

```bash
knives-out inspect examples/openapi/storefront.yaml \
  --tag orders \
  --path /draft-orders/{draftId}
```

For machine-readable inspection output:

```bash
knives-out inspect examples/openapi/storefront.yaml --format json
```

### `generate`

Builds an `AttackSuite` JSON file from an OpenAPI document, GraphQL schema, or learned model.

```bash
knives-out generate path/to/openapi.yaml --out attacks.json
```

GraphQL SDL or introspection JSON uses the same command:

```bash
knives-out generate examples/graphql/library.graphql --out graphql-attacks.json
```

Learned-model inputs use the same command too:

```bash
knives-out generate learned-model.json --out shadow-attacks.json
```

`generate` echoes the same preflight warnings as `inspect` because many CI flows skip an explicit
inspection step. `run` does not re-lint the spec because it operates on a saved attack suite.

You can load custom attack packs from installed entry points or local modules:

```bash
knives-out generate path/to/openapi.yaml \
  --pack unexpected-header \
  --pack-module examples/custom_packs/unexpected_header.py \
  --out attacks.json
```

You can also opt in to built-in workflow generation or load workflow packs:

```bash
knives-out generate path/to/openapi.yaml \
  --auto-workflows \
  --workflow-pack-module examples/workflow_packs/listed_pet_lookup.py \
  --out attacks.json
```

Filters are also available during generation:

```bash
knives-out generate examples/openapi/storefront.yaml \
  --tag orders \
  --path /draft-orders/{draftId} \
  --out attacks.json
```

When the spec declares constraints, `generate` now emits additive schema-aware mutations such as
`below_minimum`, `too_long`, `too_many_items`, `invalid_format`,
`unexpected_property`, and `missing_required_property`.

### `run`

Executes a saved attack suite against a base URL.

```bash
knives-out run attacks.json --base-url http://localhost:8000 --out results.json
```

You can provide default headers and query params that will be merged into every request:

```bash
knives-out run attacks.json \
  --base-url http://localhost:8000 \
  --header "Authorization: Bearer dev-token" \
  --query "api_key=dev-secret" \
  --out results.json
```

You can also use a built-in auth config for common bearer/session flows:

```bash
knives-out run attacks.json \
  --base-url http://localhost:8000 \
  --auth-config examples/auth_configs/client-credentials.yml \
  --out results.json
```

Or load a custom auth/session plugin from entry points or local modules:

```bash
knives-out run attacks.json \
  --base-url http://localhost:8000 \
  --auth-plugin env-bearer \
  --auth-plugin-module examples/auth_plugins/login_bearer.py \
  --out results.json
```

For authorization testing, you can load a profile file and optionally narrow to specific profiles:

```bash
knives-out run attacks.json \
  --base-url http://localhost:8000 \
  --profile-file examples/auth_profiles/anonymous-user-admin.yml \
  --profile anonymous \
  --profile admin \
  --out results.json
```

Each profile can contribute its own headers, query params, entry-point plugins, or local
`auth_plugin_modules`, and can optionally reference a named built-in auth config with
`auth_config`. Multi-profile runs aggregate per-profile outcomes into one `results.json` and add
auth comparison findings such as `anonymous_access` and `authorization_inversion` when those
differences are strong enough to infer safely.

Run-time filters match the same exact tag/path semantics:

```bash
knives-out run attacks.json \
  --base-url http://localhost:8000 \
  --tag orders \
  --path /draft-orders/{draftId} \
  --out results.json
```

### `report`

Renders Markdown from a results JSON file.

```bash
knives-out report results.json --out report.md
```

You can include a prior `results.json` as a baseline to add regression sections for new, resolved,
and persisting findings. Persisting entries also show whether severity, confidence, status, or
schema outcome drifted since the baseline:

```bash
knives-out report results.json --baseline previous-results.json --out report.md
```

If `.knives-out-ignore.yml` exists in the repo root, `report` will automatically show suppressed
findings separately. You can also point at another file explicitly with `--suppressions path/to.yml`.
When the run used `--profile-file`, the report includes a per-profile outcome table under each
attack so you can compare status codes and issues by identity.

### `export`

Renders a machine-readable CI export from a results JSON file.

```bash
knives-out export results.json --format sarif --out results.sarif
```

You can include a prior `results.json` as a baseline to attach `new` vs `persisting` metadata and
persisting delta details to the exported SARIF findings:

```bash
knives-out export results.json \
  --format sarif \
  --baseline previous-results.json \
  --out results.sarif
```

`export` auto-loads `.knives-out-ignore.yml` when present and excludes suppressed findings by
default, so CI-facing SARIF stays aligned with the rest of the review flow.

### `verify`

Checks a results JSON file against a CI policy and exits non-zero when the policy fails.

```bash
knives-out verify results.json
```

To fail only on new high-signal regressions, compare against a prior results file:

```bash
knives-out verify results.json \
  --baseline previous-results.json \
  --min-severity high \
  --min-confidence medium
```

`verify` also auto-loads `.knives-out-ignore.yml` when present, so known accepted findings do not
fail CI. Use `--suppressions path/to.yml` when you want a different file.

### `promote`

Turns qualifying findings from `results.json` back into a replayable `AttackSuite`.

```bash
knives-out promote results.json \
  --attacks attacks.json \
  --out regression-attacks.json
```

For baseline-aware regression promotion, pass the same prior `results.json` you would use with
`verify`:

```bash
knives-out promote results.json \
  --attacks attacks.json \
  --baseline previous-results.json \
  --out regression-attacks.json
```

`promote` uses the same suppression behavior as `verify`, so suppressed findings stay out of the
generated regression suite.

### `triage`

Generates review-ready suppression entries for the current active findings.

```bash
knives-out triage results.json --out .knives-out-ignore.yml
```

If the output file already exists, `triage` appends only new selector entries and keeps the
existing rules intact. The generated YAML includes placeholder `reason` and `owner` fields so the
team can review and fill them in before committing.

Example suppression file:

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

Example auth profile file:

```yaml
profiles:
  - name: anonymous
    anonymous: true
    level: 0

  - name: user
    level: 10
    headers:
      Authorization: Bearer user-token

  - name: admin
    level: 20
    headers:
      Authorization: Bearer admin-token
```

## Development

### Dev Container

This repo includes a VS Code devcontainer for a ready-to-use Python 3.12 environment.

Open the folder in VS Code and run `Dev Containers: Reopen in Container`.
On first create, the container installs the project with dev dependencies via `pip install -e ".[dev]"`.

Run tests:

```bash
pytest
```

Run lint:

```bash
ruff check .
ruff format .
```

## Custom attack packs

Custom attack packs let you contribute additional `AttackCase` records without forking the core generator.

An attack pack can be either:

- a callable `generate(operation: OperationSpec) -> list[AttackCase]`
- an object exposed as `attack_pack` with a `name` and `generate(operation)` method

The easiest helper is `make_attack_pack()` from `knives_out.attack_packs`.

Local module example:

```python
from knives_out.attack_packs import make_attack_pack
from knives_out.generator import attack_id, base_request_context
from knives_out.models import AttackCase, OperationSpec


def generate(operation: OperationSpec) -> list[AttackCase]:
    path_params, query, headers, body = base_request_context(operation)
    headers["X-Example-Custom-Pack"] = "unexpected-header"
    return [
        AttackCase(
            id=attack_id(operation.operation_id, "unexpected_header", "header:X-Example"),
            name="Unexpected header probe",
            kind="unexpected_header",
            operation_id=operation.operation_id,
            method=operation.method,
            path=operation.path,
            description="Adds an unexpected header to probe strict header handling.",
            path_params=path_params,
            query=query,
            headers=headers,
            body_json=body,
        )
    ]


attack_pack = make_attack_pack("unexpected-header", generate)
```

Load that module with:

```bash
knives-out generate examples/openapi/petstore.yaml \
  --pack-module examples/custom_packs/unexpected_header.py \
  --out attacks.json
```

Installed entry point example:

```toml
[project.entry-points."knives_out.attack_packs"]
unexpected-header = "my_package.attack_packs:attack_pack"
```

Then load it with:

```bash
knives-out generate examples/openapi/petstore.yaml --pack unexpected-header --out attacks.json
```

## Custom workflow packs

Workflow packs contribute `WorkflowAttackCase` records after the request attacks are generated, so
they can reuse existing terminal attacks instead of rebuilding request payloads from scratch.

A workflow pack can be either:

- a callable `generate(operations: list[OperationSpec], request_attacks: list[AttackCase]) -> list[WorkflowAttackCase]`
- an object exposed as `workflow_pack` with a `name` and `generate(operations, request_attacks)` method

The easiest helper is `make_workflow_pack()` from `knives_out.workflow_packs`.

Local module example:

```bash
knives-out generate examples/openapi/petstore.yaml \
  --auto-workflows \
  --workflow-pack-module examples/workflow_packs/listed_pet_lookup.py \
  --out attacks.json
```

Installed entry point example:

```toml
[project.entry-points."knives_out.workflow_packs"]
listed-id-lookup = "my_package.workflow_packs:workflow_pack"
```

Then load it with:

```bash
knives-out generate examples/openapi/petstore.yaml \
  --workflow-pack listed-id-lookup \
  --out attacks.json
```

## Built-in auth configs

Built-in auth configs cover the common cases where you want realistic auth without writing Python.

Supported strategies:

- `static_bearer`
- `client_credentials`
- `password_json`
- `login_json_bearer`
- `login_form_cookie`

The repo includes checked-in examples at:

- `examples/auth_configs/user-admin.yml`
- `examples/auth_configs/client-credentials.yml`

Single-profile example:

```bash
knives-out run attacks.json \
  --base-url http://localhost:8000 \
  --auth-config examples/auth_configs/client-credentials.yml \
  --out results.json
```

Named auth-config profiles:

```bash
knives-out run attacks.json \
  --base-url http://localhost:8000 \
  --auth-config examples/auth_configs/user-admin.yml \
  --auth-profile user \
  --auth-profile admin \
  --out results.json
```

Built-in auth events are recorded in `results.json` and rendered separately in reports, so auth
bootstrap or refresh failures do not masquerade as attack findings.

## Auth/session plugins

Auth/session plugins run at execution time and can mutate outgoing requests or establish shared
runtime state before the suite or a workflow runs.

They are a good fit when simple static credentials are not enough:

- add a bearer token from an environment variable
- log in once before the suite and inject the returned token into later requests
- establish a session cookie before each workflow

An auth plugin can be either:

- an object exposed as `auth_plugin`
- an object exposed as `plugin`
- a zero-argument `build_plugin()` factory

The easiest helper is `make_auth_plugin()` from `knives_out.auth_plugins`.

Local module example:

```bash
knives-out run attacks.json \
  --base-url http://localhost:8000 \
  --auth-plugin-module examples/auth_plugins/login_bearer.py \
  --out results.json
```

Installed entry point example:

```toml
[project.entry-points."knives_out.auth_plugins"]
env-bearer = "my_package.auth_plugins:auth_plugin"
```

Then load it with:

```bash
export KNIVES_OUT_BEARER_TOKEN=dev-token
knives-out run attacks.json \
  --base-url http://localhost:8000 \
  --auth-plugin env-bearer \
  --out results.json
```

## Roadmap

The built-in auth/config milestone, deeper GraphQL coverage, and Shadow Twin learned-model capture
are now available. The next likely milestone is:

- **v0.11:** deeper GraphQL coverage with response validation, federation awareness, and
  mixed-protocol reporting is now shipped
- **v0.12:** a local-first HTTP API with shared service-layer execution, JSON-first endpoints,
  and background run jobs with artifact retrieval

After that, the likely follow-on is richer CI and report navigation for large regression programs.
LLM application testing stays deferred until after that API-focused expansion. See
`docs/architecture.md` and `docs/roadmap.md` for the current milestone notes.
Shadow Twin learned-model capture is now available.
