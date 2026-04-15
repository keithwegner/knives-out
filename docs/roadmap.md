# Roadmap

`knives-out` now ships the original bootstrap stack plus the first real review and portability
passes:

- replayable REST request attacks and workflow attacks with extracted shared state
- response-schema validation, CI verification, suppressions, regression-suite promotion, and SARIF export
- auth/session plugins, multi-profile authorization comparisons, and built-in auth acquisition
- HTML reporting with linked artifacts plus a local-first HTTP API and saved-project workbench
- GraphQL SDL and introspection loading with nested, fragment-aware contract generation
- review-only portable bundle handoff from CI into the local workbench

That means the roadmap now needs to follow usage patterns instead of the old bootstrap sequence.

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
- v0.19: CI-native SARIF export
  - ships `knives-out export`, `POST /v1/export`, and GitHub code-scanning upload guidance
- v0.20: portable review bundles
  - ships `knives-out bundle`, `POST /v1/projects/import-review-bundle`, review-only imported
    projects, and bundle round-trip coverage

## v0.21 — full snapshot portability

The next portability step is to move beyond review-only handoff and allow rerunnable project
snapshots:

- export and import full saved-project snapshots instead of only review evidence
- preserve source documents, learned inputs, inspect/generate/run drafts, and reusable suites
- keep imported snapshots runnable after they land in the workbench
- support safe duplication and promotion on imported snapshots because the suite is present

## v0.22 — CI and workbench sync ergonomics

Once snapshot portability exists, the next leverage point is tighter sync between CI and local
review loops:

- smoother baseline handoff across bundle generations
- richer imported-run history and evidence metadata
- easier bundle production and retrieval in GitHub Actions or other CI systems
- smaller, higher-signal review summaries for long-lived regression programs

## Still deferred

These remain interesting, but they should not displace the portability pass:

- browser-assisted login and redirect-driven OAuth auth-code flows
- gRPC support
- LLM application and tool-misuse testing
- distributed fuzzing or large-scale orchestration
