# knives-out

[![CI](https://github.com/keithwegner/knives-out/actions/workflows/ci.yml/badge.svg)](https://github.com/keithwegner/knives-out/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

`knives-out` is a CLI for adversarial API testing from OpenAPI specs.

It helps developers break their APIs on purpose before someone else does.

## What it does

Given an OpenAPI document, `knives-out` can:

- inspect the operations in the spec
- generate replayable negative test cases
- run those attacks against a live base URL
- produce a Markdown report that highlights suspicious outcomes

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
- missing request bodies
- malformed JSON bodies
- missing auth headers or query credentials when the spec declares security

This is not a full fuzzing engine yet. It is a structured attack generator and runner.

## Why this shape

The project is split into three explicit phases:

1. **Generate** attack cases from the spec.
2. **Run** those attack cases against a target.
3. **Report** findings in a stable, reviewable format.

That makes the architecture easier to extend later with:

- auth/session plugins
- custom attack packs
- schema-aware payload mutation
- LLM application testing
- CI gating policies
- regression suites for previously found bugs

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Inspect the sample spec:

```bash
knives-out inspect examples/openapi/petstore.yaml
```

Generate attacks:

```bash
knives-out generate examples/openapi/petstore.yaml --out attacks.json
```

Run them against a live API:

```bash
knives-out run attacks.json \
  --base-url http://localhost:8000 \
  --header "Authorization: Bearer dev-token" \
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

## CI usage

`knives-out` works well in CI when you follow the same generate/run/report flow and add a final
verification step:

1. generate attacks from a checked-in OpenAPI spec
2. run them against a dev or staging environment
3. render a Markdown report for review
4. verify the results against a CI policy
5. upload the JSON results, request artifacts, and Markdown report for triage

A ready-to-adapt GitHub Actions example lives at `.github/workflows/dev-environment-example.yml`.
It uses repository secrets instead of hard-coded targets:

- `KNIVES_OUT_BASE_URL` for the dev or staging base URL
- `KNIVES_OUT_AUTH_HEADER` for an optional header like `Authorization: Bearer ...`
- `KNIVES_OUT_AUTH_QUERY` for an optional query credential like `api_key=...`

`knives-out run` currently exits with status `0` when the suite executes successfully, even if
some findings are flagged in `results.json`. That keeps execution review-friendly:
teams can always upload `results.json`, `report.md`, and per-attack artifacts for triage.

For built-in gating, use `knives-out verify` after `run`. It can fail on qualifying findings in the
current run, or only on new qualifying findings when you also pass `--baseline previous-results.json`.
See `docs/ci.md` for the sample workflow, secret setup, and baseline-aware CI patterns.

## CLI

### `inspect`

Shows a summary of operations discovered in an OpenAPI document.

```bash
knives-out inspect path/to/openapi.yaml
```

`inspect` surfaces preflight warnings for spec gaps such as missing request schemas, vague
security declarations, and broken `$ref` pointers.

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

## Roadmap

The first milestone is intentionally modest:

- parse common OpenAPI patterns well
- generate useful negative tests with low noise
- make every generated attack replayable
- make result triage fast and obvious

See `docs/architecture.md` and `docs/roadmap.md` for the initial direction.
