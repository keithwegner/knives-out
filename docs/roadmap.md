# Roadmap

`knives-out` now ships the milestone stack that used to define the near-term roadmap:

- replayable REST request attacks
- workflow attacks with shared state and extracted values
- response-schema validation, CI verification, suppressions, and regression-suite promotion
- auth/session plugins and multi-profile authorization comparisons
- HTML reporting with linked artifacts
- GraphQL SDL and introspection loading with replayable variable-coercion attacks

That means the next roadmap should be shaped by real usage instead of the original bootstrap plan.

## Recently completed

- v0.5: suppressions and triage
- v0.6: multi-profile authorization testing
- v0.7: HTML report and artifact index
- v0.8: GraphQL support

## Next planning pass

The next milestone set is not locked yet, but the strongest candidates are:

1. built-in auth acquisition and refresh flows for common OAuth/session patterns
2. deeper GraphQL response validation, federation awareness, and subscription coverage
3. richer CI and artifact navigation for large suites
4. stronger reporting and triage ergonomics for long-lived regression programs

## Still deferred

These remain interesting, but they should not displace the next planning pass:

- browser-assisted login and redirect-driven OAuth flows
- gRPC support
- LLM application and tool-misuse testing
- distributed fuzzing or large-scale orchestration
