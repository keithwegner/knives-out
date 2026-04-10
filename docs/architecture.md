# Architecture

## Principles

The project starts with a deliberately narrow architecture:

- **OpenAPI in**
- **Replayable attack artifacts out**
- **Deterministic execution**
- **Simple triage**

The core idea is that generation, execution, and reporting are separate concerns.

## Module layout

```text
src/knives_out/
  cli.py             # Typer entrypoint
  graphql_loader.py  # GraphQL SDL/introspection parsing
  models.py          # Pydantic models for operations, attacks, results, and profiles
  openapi_loader.py  # OpenAPI parsing and local $ref resolution
  spec_loader.py     # Schema autodetection for OpenAPI or GraphQL
  generator.py       # Request and workflow attack generation
  filtering.py       # Tag and path filtering helpers
  runner.py          # HTTP execution, workflows, profiles, and auth runtime
  auth_plugins.py    # Auth/session plugin helpers
  profiles.py        # Multi-profile loading and comparison inputs
  reporting.py       # Markdown and HTML report rendering
  verification.py    # CI policy checks
  promotion.py       # Regression-suite promotion from results
  suppressions.py    # Checked-in finding suppressions and triage helpers
  attack_packs.py    # Custom request attack extensions
  workflow_packs.py  # Custom workflow attack extensions
```

## Flow

### 1. Load spec

`spec_loader.py` autodetects whether the input is OpenAPI or GraphQL. `openapi_loader.py` reads
YAML/JSON, resolves local `$ref` values, and extracts a simplified list of `OperationSpec`
objects. `graphql_loader.py` does the same for GraphQL SDL or introspection JSON.

### 2. Generate suite

`generator.py` turns each `OperationSpec` into a set of request and workflow attacks. Those cases
are serialized into a stable JSON artifact.

That JSON should become the contract between future generators and future runners.

### 3. Execute suite

`runner.py` executes the saved suite against a concrete base URL. Runtime auth, query values,
profile-specific defaults, and workflow state are merged at this phase rather than baked into
generation. For GraphQL attacks, a `200` response with an `errors` array is treated as an
expected validation failure instead of an unexpected success.

### 4. Report findings

`reporting.py` reduces the results into Markdown or HTML. `verification.py`, `promotion.py`, and
`suppressions.py` then build CI and triage workflows on the same result model.

Today, a result is typically flagged when it produces:

- a transport error
- a 5xx response
- an unexpected 2xx/3xx response to a negative test
- a response-schema mismatch
- a high-signal authorization comparison issue across profiles

## Why save attacks as JSON?

This is the most important architectural choice in the first version.

It gives the project:

- reproducibility
- easier debugging
- stable regression suites
- compatibility with future custom generators
- a clean seam for CI

## Expected near-term evolution

The next milestone work should extend the current architecture in two directions:

1. first-class auth/session profile strategies for common OAuth and session-login flows
2. clearer auth setup diagnostics in reports and CI flows
3. protocol-aware filtering that still shares the current run/report/verify pipeline
4. stronger GraphQL response-shape validation on top of the new protocol loader

## Things intentionally deferred

These are still interesting, but they should wait until the next two milestones are solid:

- browser/session automation
- redirect-driven OAuth auth-code flows
- gRPC
- LLM toolchain testing
- distributed fuzzing
