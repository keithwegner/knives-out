# CI usage

`knives-out` is designed to fit a normal CI workflow:

1. generate a replayable attack suite from a checked-in OpenAPI or GraphQL schema
2. optionally opt in to workflow generation for stateful coverage
3. run that suite against a dev or staging deployment
4. render a Markdown report for review
5. optionally render an HTML report with linked artifacts
6. verify the results against a CI policy
7. optionally promote qualifying findings into a smaller regression suite
8. optionally maintain a checked-in suppressions file for accepted findings
9. publish the JSON results, reports, regression suite, and per-attack artifacts

The repository includes a ready-to-adapt GitHub Actions example at
`.github/workflows/dev-environment-example.yml`.

## Required secrets

The sample workflow expects:

- `KNIVES_OUT_BASE_URL`

Optional secrets:

- `KNIVES_OUT_AUTH_HEADER`
- `KNIVES_OUT_AUTH_QUERY`
- plugin-specific login or bearer env vars if you use an auth plugin module

The optional values should match the current CLI surface:

- `KNIVES_OUT_AUTH_HEADER`: `Authorization: Bearer dev-token`
- `KNIVES_OUT_AUTH_QUERY`: `api_key=dev-secret`

For static credentials, `--header` and `--query` are still the simplest fit. Use auth/session
plugins when your CI flow needs to log in, fetch a bearer token, or establish a shared session
before the suite or each workflow runs.

If you want identity-aware authorization coverage, the repo also includes
`examples/auth_profiles/anonymous-user-admin.yml` as a starter profile file.

For richer checked-in examples, the repo now includes `examples/openapi/storefront.yaml`, which
combines exact tags, path filters, schema constraints, and a producer/consumer workflow chain.
For GraphQL, the repo includes `examples/graphql/library.graphql`, which demonstrates query and
mutation variable attacks from SDL input.

## Expected exit behavior

`knives-out run` currently exits with status `0` when it finishes executing the suite, even if the
results contain flagged findings such as `server_error`, `unexpected_success`, or
`response_schema_mismatch`.

That default behavior is intentional for review-first workflows:

- `results.json` stays available for automation
- `report.md` stays available for humans
- `report.html` can present a linked artifact index for faster triage
- `artifacts/` keeps one request/response record per attack for debugging

`knives-out verify` is the built-in gating step. It reads `results.json`, applies severity and
confidence thresholds, and exits with:

- `0` when the policy passes
- `1` when the policy fails

If `.knives-out-ignore.yml` exists in the repository root, `report`, `verify`, and `promote` load
it automatically. Use `--suppressions path/to/file.yml` to point at a different suppression file.

## Simple gating with no baseline

Use this when you want CI to fail on qualifying findings in the current run:

```yaml
- name: Verify findings
  run: |
    knives-out verify results.json \
      --min-severity high \
      --min-confidence medium
```

## Baseline-aware gating

If your workflow can provide a prior `results.json`, `verify` can fail only on new qualifying
findings:

```yaml
- name: Verify against baseline
  run: |
    knives-out verify results.json \
      --baseline previous-results.json \
      --min-severity high \
      --min-confidence medium
```

The tool does not fetch that baseline for you. Your workflow is responsible for placing
`previous-results.json` in the workspace before this step.

## Optional: checked-in suppressions

Use suppressions when the team has reviewed a finding and wants CI to stay focused on active,
unsuppressed regressions.

Seed a review-ready file from the current active findings:

```yaml
- name: Seed or refresh suppressions for review
  if: always()
  run: knives-out triage results.json --out .knives-out-ignore.yml
```

The generated file includes placeholder `reason` and `owner` fields so a reviewer can edit the
entries before committing them. A typical checked-in file looks like:

```yaml
suppressions:
  - attack_id: atk_create_pet_missing_body
    issue: server_error
    operation_id: createPet
    method: POST
    path: /pets
    tags:
      - pets
      - write
    reason: Known issue tracked in API backlog
    owner: api-team
    expires_on: 2026-06-30
```

If you keep that file at the repo root, the standard commands pick it up automatically:

```yaml
- name: Verify findings with checked-in suppressions
  run: knives-out verify results.json
```

```yaml
- name: Promote qualifying findings with checked-in suppressions
  if: always()
  run: |
    knives-out promote results.json \
      --attacks attacks.json \
      --out regression-attacks.json
```

## Optional: stateful workflow coverage

Start simple with request-only generation:

```yaml
- name: Generate request attacks
  run: knives-out generate "$SPEC_PATH" --out attacks.json
```

When you want stateful setup-plus-terminal coverage, opt in:

```yaml
- name: Generate attacks with built-in workflows
  run: knives-out generate "$SPEC_PATH" --auto-workflows --out attacks.json
```

You can add app-specific journeys by loading a workflow pack module or entry point:

```yaml
- name: Generate attacks with custom workflows
  run: |
    knives-out generate "$SPEC_PATH" \
      --auto-workflows \
      --workflow-pack-module examples/workflow_packs/listed_pet_lookup.py \
      --out attacks.json
```

## Optional: GraphQL schemas

GraphQL SDL or introspection JSON follows the same generate/run/report/verify flow. The generated
attacks target invalid variables, required-variable removal, and type coercion failures.

```yaml
- name: Inspect a GraphQL schema
  run: knives-out inspect examples/graphql/library.graphql
```

```yaml
- name: Generate GraphQL attacks
  run: |
    knives-out generate examples/graphql/library.graphql \
      --graphql-endpoint /graphql \
      --out graphql-attacks.json
```

## Optional: tag and path filtering

The same exact-match filters work in `inspect`, `generate`, and `run`:

```yaml
- name: Generate only order-related attacks
  run: |
    knives-out generate "$SPEC_PATH" \
      --tag orders \
      --path /draft-orders/{draftId} \
      --out attacks.json
```

```yaml
- name: Run only order-related attacks
  run: |
    knives-out run attacks.json \
      --base-url "${KNIVES_OUT_BASE_URL}" \
      --tag orders \
      --path /draft-orders/{draftId} \
      --out results.json
```

## Optional: auth/session plugins

For login or shared-session flows, load a local auth plugin module during `run`:

```yaml
- name: Run suite with an auth plugin
  run: |
    knives-out run attacks.json \
      --base-url "${KNIVES_OUT_BASE_URL}" \
      --auth-plugin-module examples/auth_plugins/login_bearer.py \
      --artifact-dir artifacts \
      --out results.json
```

The sample `examples/auth_plugins/login_bearer.py` expects:

- `KNIVES_OUT_LOGIN_USERNAME`
- `KNIVES_OUT_LOGIN_PASSWORD`

You can also install auth plugins as entry points and load them with `--auth-plugin env-bearer`.

## Optional: multi-profile authorization runs

To compare the same suite across multiple identities, pass a profile file to `run`:

```yaml
- name: Run suite across anonymous, user, and admin profiles
  run: |
    knives-out run attacks.json \
      --base-url "${KNIVES_OUT_BASE_URL}" \
      --profile-file examples/auth_profiles/anonymous-user-admin.yml \
      --artifact-dir artifacts \
      --out results.json
```

You can narrow the run to a subset of profiles when needed:

```yaml
- name: Run only anonymous and admin profiles
  run: |
    knives-out run attacks.json \
      --base-url "${KNIVES_OUT_BASE_URL}" \
      --profile-file examples/auth_profiles/anonymous-user-admin.yml \
      --profile anonymous \
      --profile admin \
      --out results.json
```

Each profile can contribute its own headers, query params, installed auth plugins, or local
`auth_plugin_modules`. The resulting `results.json` keeps a normal top-level result list so
`report`, `verify`, `promote`, and suppressions continue to work, while the Markdown report adds
per-profile outcome tables for deeper authorization review.

## Optional: baseline-aware report

You can also render a Markdown report that highlights new, resolved, and persisting findings:

```yaml
- name: Render baseline-aware report
  run: |
    knives-out report results.json \
      --baseline previous-results.json \
      --out report.md
```

## Optional: HTML report and artifact index

When you already capture per-attack request and response artifacts, `report` can also emit an
HTML view with linked artifacts, detailed result cards, and profile/workflow sections:

```yaml
- name: Render HTML report
  run: |
    knives-out report results.json \
      --format html \
      --artifact-root artifacts \
      --out report.html
```

## Optional: promote a regression suite

When you want to preserve only qualifying findings as a smaller replayable suite, use `promote`:

```yaml
- name: Promote qualifying findings
  if: always()
  run: |
    knives-out promote results.json \
      --attacks attacks.json \
      --out regression-attacks.json
```

To promote only new regressions, pass the same baseline file you use with `verify`:

```yaml
- name: Promote new qualifying regressions
  if: always()
  run: |
    knives-out promote results.json \
      --attacks attacks.json \
      --baseline previous-results.json \
      --out regression-attacks.json
```

## Coverage in repository CI

The repository's own `ci.yml` now runs:

- `ruff check .`
- `ruff format --check .`
- `pytest --cov=src/knives_out --cov-report=term-missing`

Coverage is printed in CI for visibility, but there is no hard percentage gate yet.
