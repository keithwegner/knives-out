# CI usage

`knives-out` is designed to fit a normal CI workflow:

1. generate a replayable attack suite from a checked-in OpenAPI spec
2. optionally opt in to workflow generation for stateful coverage
3. run that suite against a dev or staging deployment
4. render a Markdown report for review
5. verify the results against a CI policy
6. publish the JSON results, Markdown report, and per-attack artifacts

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

## Expected exit behavior

`knives-out run` currently exits with status `0` when it finishes executing the suite, even if the
results contain flagged findings such as `server_error`, `unexpected_success`, or
`response_schema_mismatch`.

That default behavior is intentional for review-first workflows:

- `results.json` stays available for automation
- `report.md` stays available for humans
- `artifacts/` keeps one request/response record per attack for debugging

`knives-out verify` is the built-in gating step. It reads `results.json`, applies severity and
confidence thresholds, and exits with:

- `0` when the policy passes
- `1` when the policy fails

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

## Optional: baseline-aware report

You can also render a Markdown report that highlights new, resolved, and persisting findings:

```yaml
- name: Render baseline-aware report
  run: |
    knives-out report results.json \
      --baseline previous-results.json \
      --out report.md
```
