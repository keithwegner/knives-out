# knives-out

[![CI](https://github.com/keithwegner/knives-out/actions/workflows/ci.yml/badge.svg)](https://github.com/keithwegner/knives-out/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Project wiki: [GitHub Wiki](https://github.com/keithwegner/knives-out/wiki)

`knives-out` is a CLI for adversarial API testing from OpenAPI specs.

It helps developers break their APIs on purpose before someone else does.

## What it does

Given an OpenAPI document, `knives-out` can:

- inspect the operations in the spec
- generate replayable negative test cases
- generate schema-aware mutation attacks from declared constraints
- optionally chain setup requests into replayable workflow attacks
- load auth/session plugins for bearer tokens, login flows, and shared sessions
- execute the same suite across named auth profiles and compare their outcomes
- run those attacks against a live base URL
- produce a Markdown report that highlights suspicious outcomes
- verify findings for CI gating
- promote qualifying findings back into a reusable regression suite
- suppress or triage known findings so CI stays focused on active risk

The initial focus is narrow by design:

- OpenAPI input
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

This is not a full fuzzing engine yet. It is a structured attack generator, runner, and CI gate.

## Why this shape

The project is split into three explicit phases:

1. **Generate** attack cases from the spec.
2. **Run** those attack cases against a target.
3. **Report** findings in a stable, reviewable format.

That makes the architecture easier to evolve further with:

- custom attack packs
- deeper stateful workflows
- LLM application testing
- GraphQL support
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
```

Generate attacks:

```bash
knives-out generate examples/openapi/petstore.yaml --out attacks.json
knives-out generate examples/openapi/storefront.yaml --tag orders --out attacks.json
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

Or load an auth/session plugin when static headers are not enough:

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

Verify findings against the default CI policy:

```bash
knives-out verify results.json
```

Promote qualifying findings back into a reusable regression suite:

```bash
knives-out promote results.json --attacks attacks.json --out regression-attacks.json
```

Generate a review-ready suppressions file for known findings:

```bash
knives-out triage results.json --out .knives-out-ignore.yml
```

## CI usage

`knives-out` works well in CI when you follow the same generate/run/report flow and add a final
verification step:

1. generate attacks from a checked-in OpenAPI spec
2. run them against a dev or staging environment
3. render a Markdown report for review
4. verify the results against a CI policy
5. optionally promote qualifying findings into a smaller regression suite
6. upload the JSON results, request artifacts, and Markdown report for triage

A ready-to-adapt GitHub Actions example lives at `.github/workflows/dev-environment-example.yml`.
It uses repository secrets instead of hard-coded targets:

- `KNIVES_OUT_BASE_URL` for the dev or staging base URL
- `KNIVES_OUT_AUTH_HEADER` for an optional header like `Authorization: Bearer ...`
- `KNIVES_OUT_AUTH_QUERY` for an optional query credential like `api_key=...`
- plugin-specific login or bearer env vars when you use `--auth-plugin` or `--auth-plugin-module`

`knives-out run` currently exits with status `0` when the suite executes successfully, even if
some findings are flagged in `results.json`. That keeps execution review-friendly:
teams can always upload `results.json`, `report.md`, and per-attack artifacts for triage.

For built-in gating, use `knives-out verify` after `run`. It can fail on qualifying findings in the
current run, or only on new qualifying findings when you also pass `--baseline previous-results.json`.
When you want stateful coverage, generate with `--auto-workflows` first, then add
`--workflow-pack-module examples/workflow_packs/listed_pet_lookup.py` or your own custom pack as
you move from generic coverage to app-specific journeys. For protected APIs, keep simple static
credentials on `--header` or `--query`, or move up to
`--auth-plugin-module examples/auth_plugins/login_bearer.py` for login/session flows. When you want
to keep only the highest-signal regressions around, follow `verify` with
`knives-out promote results.json --attacks attacks.json`. See `docs/ci.md` for the sample
workflow, secret setup, filtering patterns, baseline-aware CI flows, and checked-in suppressions.
If you keep a `.knives-out-ignore.yml` file in the repo root, `report`, `verify`, and `promote`
will load it automatically. Use `knives-out triage results.json` to seed new entries when you want
to capture known findings without hand-writing YAML. For authorization-focused regression coverage,
you can also run one suite across `anonymous`, `user`, and `admin` profiles with
`--profile-file examples/auth_profiles/anonymous-user-admin.yml`.

## CLI

### `inspect`

Shows a summary of operations discovered in an OpenAPI document.

```bash
knives-out inspect path/to/openapi.yaml
```

`inspect` surfaces preflight warnings for spec gaps such as missing request schemas, vague
security declarations, and broken `$ref` pointers.

You can filter inspection to exact tags or paths:

```bash
knives-out inspect examples/openapi/storefront.yaml \
  --tag orders \
  --path /draft-orders/{draftId}
```

### `generate`

Builds an `AttackSuite` JSON file from an OpenAPI document.

```bash
knives-out generate path/to/openapi.yaml --out attacks.json
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

You can also load auth/session plugins from entry points or local modules:

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
`auth_plugin_modules`. Multi-profile runs aggregate per-profile outcomes into one `results.json`
and add auth comparison findings such as `anonymous_access` and `authorization_inversion` when
those differences are strong enough to infer safely.

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
and persisting findings:

```bash
knives-out report results.json --baseline previous-results.json --out report.md
```

If `.knives-out-ignore.yml` exists in the repo root, `report` will automatically show suppressed
findings separately. You can also point at another file explicitly with `--suppressions path/to.yml`.
When the run used `--profile-file`, the report includes a per-profile outcome table under each
attack so you can compare status codes and issues by identity.

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

The current direction is still intentionally modest:

- parse common OpenAPI patterns well
- generate useful negative tests with low noise
- make every generated attack replayable
- make result triage fast and obvious

See `docs/architecture.md` and `docs/roadmap.md` for the initial direction.
