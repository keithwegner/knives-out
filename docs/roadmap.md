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

## v0.11 — deeper GraphQL coverage

The next likely milestone is a GraphQL-focused expansion on top of the loader and runner we now
have. The strongest targets are:

- response-shape validation against declared GraphQL result structure
- federation awareness and clearer subgraph-related diagnostics
- staged subscription coverage that still fits the current generate/run/report pipeline
- better protocol-aware reporting for mixed OpenAPI and GraphQL programs

## v0.12 — richer CI and triage ergonomics

After the GraphQL pass, the next best leverage point is day-to-day review ergonomics:

- stronger artifact navigation for large suites
- better suppression and baseline review flows
- clearer auth diagnostic summaries in HTML and Markdown reports
- smaller, higher-signal CI summaries for long-lived regression programs

## Still deferred

These remain interesting, but they should not displace the next planning pass:

- browser-assisted login and redirect-driven OAuth auth-code flows
- gRPC support
- LLM application and tool-misuse testing
- distributed fuzzing or large-scale orchestration
