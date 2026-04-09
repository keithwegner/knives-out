# knives-out

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

## CLI

### `inspect`

Shows a summary of operations discovered in an OpenAPI document.

```bash
knives-out inspect path/to/openapi.yaml
```

### `generate`

Builds an `AttackSuite` JSON file from an OpenAPI document.

```bash
knives-out generate path/to/openapi.yaml --out attacks.json
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

## Roadmap

The first milestone is intentionally modest:

- parse common OpenAPI patterns well
- generate useful negative tests with low noise
- make every generated attack replayable
- make result triage fast and obvious

See `docs/architecture.md` and `docs/roadmap.md` for the initial direction.
