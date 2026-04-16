# Roadmap

`knives-out` now ships the milestone stack that used to define the near-term roadmap:

- replayable REST request attacks
- workflow attacks with shared state and extracted values
- response-schema validation, CI verification, suppressions, and regression-suite promotion
- auth/session plugins, multi-profile authorization comparisons, and built-in auth acquisition
- HTML reporting with linked artifacts
- GraphQL SDL and introspection loading with replayable variable-coercion attacks

That means the next roadmap should keep following real usage instead of the original bootstrap
guesswork.

## Recently completed

- v0.5: suppressions and triage
- v0.6: multi-profile authorization testing
- v0.7: HTML report and artifact index
- v0.8: GraphQL schema support
- v0.9: built-in auth acquisition and refresh flows
  - shipped strategies include `static_bearer`, `client_credentials`, `password_json`,
    `login_json_bearer`, and `login_form_cookie`
- v0.10: Shadow Twin learned-model capture and discovery
  - ships local reverse-proxy capture, HAR import, learned-model artifacts, and learned workflow attacks
- v0.11: deeper GraphQL coverage
  - ships response-shape validation, federation-aware diagnostics, and protocol-aware reporting
- v0.15: staged GraphQL subscription coverage
  - ships subscription-root discovery plus bounded `graphql-transport-ws` execution in the
    existing generate/run/report pipeline
- v0.16: ReviewOps baseline workbench
  - ships project-scoped review refresh, pinned baseline run selection, diff-first review tabs,
    and advanced external baseline fallback in the local web workbench
- v0.17: Artifact deep dive drawer
  - ships finding-first current-run evidence drilldown, typed artifact references, and inline
    request/response, workflow, profile, and auth-event inspection in the review workbench
- v0.18: fragment-aware GraphQL contracts
  - ships nested object/interface/union GraphQL contract generation with parity across emitted
    documents, output-shape validation, and response-schema metadata

## v0.12 — local-first HTTP API

The next likely milestone is an API expansion on top of the shared load/generate/run/report
pipeline we now have. The strongest targets are:

- a local-only FastAPI server that mirrors the current CLI surface
- synchronous endpoints for inspect, generate, discover, report, verify, promote, and triage
- background run jobs with polling and artifact retrieval
- a shared service layer so the CLI and API do not drift apart

## v0.13 — richer CI and triage ergonomics

After the API pass, the next best leverage point is day-to-day review ergonomics:

- stronger artifact navigation for large suites
- machine-readable summary exports for CI annotations and dashboards
- better suppression and baseline review flows
- clearer auth diagnostic summaries in HTML and Markdown reports
- smaller, higher-signal CI summaries for long-lived regression programs

## v0.14 — smoke-test integration coverage

Before we grow a broad end-to-end matrix, the better next step is a tiny local-only smoke-test
layer aimed at product-critical flows. The goal is confidence, not exhaustive scenario coverage:

- deterministic fixture apps and checked-in inputs only
- no external services, sleeps, or timing-sensitive assertions
- a few high-signal scenarios that protect the main user journeys

Initial issue-backed scenarios:

- #58: CLI happy path against a local API fixture
- #59: workflow attack execution against a local stateful API
- #60: multi-profile authorization comparison with anonymous/user/admin behavior
- #61: built-in auth acquisition against a fake local token endpoint
- #62: Shadow Twin capture -> discover -> generate smoke coverage

The integration baseline now has two layers. `tests/test_integration_smoke.py` protects
CLI/runner flows against local fixture services, while `tests/test_api_integration.py` starts
the real FastAPI app with uvicorn and exercises workbench-critical HTTP behavior over localhost
with `httpx`.

## Still deferred

These remain interesting, but they should not displace the next planning pass:

- browser-assisted login and redirect-driven OAuth auth-code flows
- gRPC support
- LLM application and tool-misuse testing
- distributed fuzzing or large-scale orchestration
