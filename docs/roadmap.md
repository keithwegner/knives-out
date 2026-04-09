# Initial roadmap

## Milestone: v0.1 — useful negative testing from OpenAPI

The first release should answer a simple question:

> Can `knives-out` generate and run a meaningful set of adversarial API tests from a normal OpenAPI spec?

## First 10 GitHub issues

### 1. Improve schema sampling for nested objects and arrays
**Goal:** Generate better valid baseline payloads so the negative tests are less noisy.

**Acceptance criteria:**
- object generation includes nested required fields
- array generation handles item schemas recursively
- unit tests cover nested schemas

### 2. Support path-level and operation-level parameter overrides correctly
**Goal:** Confirm operation parameters replace path parameters with the same name/in location.

**Acceptance criteria:**
- override logic is explicitly tested
- duplicate parameters are resolved deterministically

### 3. Add response-schema validation against declared OpenAPI responses
**Goal:** Flag cases where the API returns the wrong response shape.

**Acceptance criteria:**
- runner can map status code to declared schema
- report highlights response-schema mismatches

### 4. Add auth scheme support for API keys in headers and query strings
**Goal:** Make missing-auth tests more accurate for real-world APIs.

**Acceptance criteria:**
- security schemes are extracted from components
- missing-auth attacks remove the right credential
- tests cover header and query apiKey schemes

### 5. Add output directory with per-attack request/response artifacts
**Goal:** Make triage easier by preserving concrete request and response evidence.

**Acceptance criteria:**
- optional artifact directory is created on run
- each attack has a stable artifact file name
- artifacts include request metadata and response body excerpt

### 6. Add attack filtering by operation, method, and kind
**Goal:** Let users target a subset of the suite while iterating.

**Acceptance criteria:**
- CLI supports include/exclude filters
- filtering works during generation and/or run

### 7. Add custom attack packs via Python entry points or local modules
**Goal:** Let users extend the generator without forking the project.

**Acceptance criteria:**
- attack pack interface is documented
- one example custom pack exists
- CLI can load custom packs

### 8. Introduce severity/confidence scoring
**Goal:** Rank findings so the report is useful on larger suites.

**Acceptance criteria:**
- each finding has confidence and severity fields
- report sorts flagged findings by score

### 9. Add CI examples for running against a dev environment
**Goal:** Make the tool usable in a normal engineering workflow.

**Acceptance criteria:**
- README includes CI usage
- a sample GitHub Actions workflow can run generation + execution

### 10. Add OpenAPI spec linting and preflight warnings
**Goal:** Tell users when the spec itself is too incomplete to generate reliable attacks.

**Acceptance criteria:**
- warnings for missing request schemas, vague security, and unresolved refs
- inspect command surfaces preflight warnings clearly

## After v0.1

Once the fundamentals are solid, the next larger expansions are:

- stateful workflow attacks
- auth/session plugins
- GraphQL support
- prompt-injection and tool-misuse testing for LLM apps
- regression suites generated from previously discovered findings
