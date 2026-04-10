# Roadmap

`knives-out` now has a strong OpenAPI and GraphQL base:

- replayable REST request and workflow attacks
- schema-aware mutation generation
- response-schema validation, suppressions, and regression-suite promotion
- auth/session plugins and multi-profile authorization comparisons
- Markdown and HTML reporting with linked artifacts
- GraphQL SDL and introspection loading with replayable variable-coercion attacks

That means the roadmap should now focus on making protected APIs easier to adopt in real CI flows
and then deepening the newly added GraphQL surface.

## Recently completed

- v0.5: suppressions and triage
- v0.6: multi-profile authorization testing
- v0.7: HTML report and artifact index
- v0.8: GraphQL schema support

## v0.9 — first-class auth and session realism

**Goal:** Make common protected API flows work from profile YAML alone, without requiring custom
Python plugins for the happy path.

### Committed scope

- Add a built-in `auth` block to profile files used by `knives-out run --profile-file ...`
- Support OAuth 2.0 `client_credentials`
- Support trusted internal resource-owner/password flows
- Reuse and refresh bearer tokens when a profile exposes refresh-token state
- Support session login via HTTP `POST` form or JSON endpoints with cookie reuse
- Acquire auth state once per profile and reuse it across request attacks and workflow attacks
- Surface auth setup and acquisition failures distinctly in reports without breaking `verify`,
  `promote`, suppressions, or HTML reporting
- Keep the current plugin/module path fully supported as the escape hatch for nonstandard auth

### Acceptance criteria

- A team can run one suite across named profiles that use built-in OAuth/session config only
- Token refresh and cookie reuse work across normal request attacks and workflow attacks
- Auth acquisition failures are visible and actionable without being misclassified as API findings
- Existing plugin-based runs and static header/query runs remain backward compatible

### Explicitly out of scope

- browser automation
- redirect-driven OAuth auth-code login

## v0.10 — deeper GraphQL coverage

**Goal:** Extend the existing GraphQL support from schema loading and coercion attacks into fuller
execution and review coverage while preserving the current replayable artifact model.

### Committed core

- Strengthen GraphQL response validation and result classification for `data` plus `errors`
  payloads
- Preserve report, verify, promote, triage, suppression, and HTML-report parity for GraphQL suites
- Keep the same auth profiles and session machinery used by REST runs
- Improve filtering around GraphQL operation names and root fields
- Add federation-aware schema loading for subgraph or supergraph inputs where the schema source is
  still a checked-in artifact

### Stretch track

- staged subscription coverage with a deliberately limited initial transport
- higher-order attack packs such as fragment or alias amplification
- persisted-query misuse coverage once the base path is stable

### Acceptance criteria

- A team can check in SDL or introspection JSON, generate a replayable GraphQL suite, run it, and
  review findings with the current report/verify flow
- GraphQL runs support the same auth profiles and suppressions model as REST runs
- Federation-aware loading lands behind the same artifact model rather than a separate workflow
- Subscriptions remain stretch scope and are not required to complete the milestone

## Deferred beyond v0.10

These remain interesting, but they should not displace the next two milestones:

- browser-assisted login and redirect-driven OAuth flows
- gRPC support
- LLM application and tool-misuse testing
- distributed fuzzing or large-scale orchestration
