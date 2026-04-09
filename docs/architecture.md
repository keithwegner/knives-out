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
  models.py          # Pydantic models for operations, attacks, and results
  openapi_loader.py  # OpenAPI parsing and local $ref resolution
  generator.py       # Attack generation from OperationSpec objects
  runner.py          # HTTP execution and basic evaluation
  reporting.py       # Markdown report rendering
```

## Flow

### 1. Load spec

`openapi_loader.py` reads YAML/JSON, resolves local `$ref` values, and extracts a simplified list of `OperationSpec` objects.

### 2. Generate suite

`generator.py` turns each `OperationSpec` into a set of `AttackCase` objects. Those cases are serialized into a stable JSON artifact.

That JSON should become the contract between future generators and future runners.

### 3. Execute suite

`runner.py` executes the saved suite against a concrete base URL. Runtime auth, query values, or environment-specific defaults are merged at this phase rather than baked into generation.

### 4. Report findings

`reporting.py` reduces the results into a Markdown report. For the initial milestone, a result is flagged when it produces:

- a transport error
- a 5xx response
- an unexpected 2xx/3xx response to a negative test

## Why save attacks as JSON?

This is the most important architectural choice in the first version.

It gives the project:

- reproducibility
- easier debugging
- stable regression suites
- compatibility with future custom generators
- a clean seam for CI

## Expected near-term evolution

The next additions should probably be:

1. richer schema sampling
2. better security scheme handling
3. custom rule packs
4. OpenAPI response-schema validation
5. request/response artifact storage per attack
6. baseline vs. regression comparisons

## Things intentionally deferred

These are interesting, but they should wait until the first milestone is solid:

- browser/session automation
- OAuth flows
- multi-step workflow attacks
- GraphQL
- gRPC
- LLM toolchain testing
- distributed fuzzing
