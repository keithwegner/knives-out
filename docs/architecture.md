# Architecture

## Principles

The project starts with a deliberately narrow architecture:

- **OpenAPI, GraphQL, or learned traffic in**
- **Replayable attack artifacts out**
- **Deterministic execution**
- **Simple triage**

The core idea is that generation, execution, and reporting are separate concerns.
Both the CLI and the HTTP API now sit on top of `services.py` so they can share the same behavior
without shelling out or forking a second workflow stack.

## Module layout

```text
src/knives_out/
  cli.py             # Typer entrypoint
  api.py             # FastAPI entrypoint and route wiring
  api_models.py      # HTTP request/response models
  api_store.py       # Filesystem-backed API job/artifact persistence
  capture.py         # Reverse-proxy capture and NDJSON helpers
  learned_discovery.py  # Capture/HAR inference into learned models
  learned_loader.py  # Learned-model loading
  graphql_loader.py  # GraphQL SDL/introspection parsing
  models.py          # Pydantic models for operations, attacks, results, and profiles
  openapi_loader.py  # OpenAPI parsing and local $ref resolution
  spec_loader.py     # Input autodetection for OpenAPI, GraphQL, or learned models
  generator.py       # Request, learned-invariant, and workflow attack generation
  filtering.py       # Tag and path filtering helpers
  runner.py          # HTTP execution, workflows, profiles, and auth runtime
  auth_config.py     # Built-in auth config loading and profile helpers
  builtin_auth.py    # Built-in bearer/session acquisition and refresh runtime
  auth_plugins.py    # Auth/session plugin helpers
  profiles.py        # Multi-profile loading and comparison inputs
  services.py        # Shared CLI/API orchestration helpers
  reporting.py       # Markdown and HTML report rendering
  verification.py    # CI policy checks
  promotion.py       # Regression-suite promotion from results
  suppressions.py    # Checked-in finding suppressions and triage helpers
  attack_packs.py    # Custom request attack extensions
  workflow_packs.py  # Custom workflow attack extensions
```

## Flow

### 1. Capture and discover (optional)

`capture.py` runs a local reverse proxy that records redacted request/response traffic as
`capture.ndjson`. `learned_discovery.py` then turns NDJSON or HAR inputs into a canonical
`learned-model.json` artifact with inferred operations, request/response shapes, auth hints,
producer/consumer workflows, lifecycle invalidation edges, and confidence-scored warnings.

### 2. Load input model

`spec_loader.py` autodetects whether the input is OpenAPI, GraphQL, or a learned model.
`openapi_loader.py` reads YAML/JSON, resolves local `$ref` values, and extracts a simplified list
of `OperationSpec` objects. `graphql_loader.py` does the same for GraphQL SDL or introspection
JSON. `learned_loader.py` maps learned-model artifacts onto that same `OperationSpec` surface
while preserving workflow metadata for learned generation.

### 3. Generate suite

`generator.py` turns each `OperationSpec` into a set of request and workflow attacks. For learned
models, it also emits missing-setup, stale-reference, and workflow-driven attacks based on observed
producer/consumer bindings and lifecycle invalidation. Those cases are serialized into a stable
JSON artifact.

That JSON should become the contract between future generators and future runners.

### 4. Execute suite

`runner.py` executes the saved suite against a concrete base URL. Runtime auth, query values,
profile-specific defaults, built-in auth acquisition/refresh, and workflow state are merged at
this phase rather than baked into generation. For GraphQL attacks, a `200` response with an `errors`
array is treated as an expected validation failure instead of an unexpected success, and
GraphQL response-shape validation now checks returned `data` against the generated selection shape
with federation-aware hints when mismatches cross entity or abstract-type boundaries.
That shipped GraphQL response-shape validation, federation awareness, and clearer mixed-protocol
diagnostics without changing the core pipeline shape.

### 5. Report findings

`reporting.py` reduces the results into Markdown or HTML. `verification.py`, `promotion.py`, and
`suppressions.py` then build CI and triage workflows on the same result model, while auth setup
and refresh diagnostics stay visible without becoming attack findings by themselves.

Today, a result is typically flagged when it produces:

- a transport error
- a 5xx response
- an unexpected 2xx/3xx response to a negative test
- a response-schema mismatch
- a learned stale-reference or missing-setup path that succeeds unexpectedly
- a high-signal authorization comparison issue across profiles

### 6. Serve or script the workflow

`services.py` exposes the shared orchestration layer for inspection, generation, execution,
reporting, verification, promotion, and triage. `cli.py` is now a thin Typer adapter on top of
those helpers, and `api.py` exposes the same behavior over a local-first FastAPI surface.
Long-running API execution uses a filesystem-backed job store in `api_store.py` so local tools can
list recent jobs, poll for status, and fetch artifacts without introducing a database in the first
version.

## Why save attacks as JSON?

This is the most important architectural choice in the first version.

It gives the project:

- reproducibility
- easier debugging
- stable regression suites
- compatibility with future custom generators
- a clean seam for CI
- a place to land learned models without inventing a parallel runner

## Expected near-term evolution

The next milestone work should extend the current architecture in four directions:

1. richer local API ergonomics on top of the shared service layer, including better artifact
   browsing and job summaries
2. richer Shadow Twin inference around state machines, confidence review, and ownership-sensitive
   workflows
3. clearer CI and artifact navigation for large regression suites
4. browser-free auth acquisition can keep expanding, but redirect-driven OAuth stays out of scope

## Things intentionally deferred

These are still interesting, but they should wait until the next two milestones are solid:

- browser/session automation
- redirect-driven OAuth auth-code flows
- gRPC
- LLM toolchain testing
- distributed fuzzing
