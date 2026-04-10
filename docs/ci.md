# CI usage

`knives-out` is designed to fit a normal CI workflow:

1. generate a replayable attack suite from a checked-in OpenAPI spec
2. run that suite against a dev or staging deployment
3. publish the JSON results, Markdown report, and per-attack artifacts

The repository includes a ready-to-adapt GitHub Actions example at
`.github/workflows/dev-environment-example.yml`.

## Required secrets

The sample workflow expects:

- `KNIVES_OUT_BASE_URL`

Optional secrets:

- `KNIVES_OUT_AUTH_HEADER`
- `KNIVES_OUT_AUTH_QUERY`

The optional values should match the current CLI surface:

- `KNIVES_OUT_AUTH_HEADER`: `Authorization: Bearer dev-token`
- `KNIVES_OUT_AUTH_QUERY`: `api_key=dev-secret`

## Expected exit behavior

`knives-out run` currently exits with status `0` when it finishes executing the suite, even if the
results contain flagged findings such as `server_error`, `unexpected_success`, or
`response_schema_mismatch`.

That default behavior is intentional for review-first workflows:

- `results.json` stays available for automation
- `report.md` stays available for humans
- `artifacts/` keeps one request/response record per attack for debugging

## Optional: fail the job when findings are present

If you want the workflow to gate merges, add a follow-up step after `knives-out run`:

```yaml
- name: Fail on flagged findings
  run: |
    python - <<'PY'
    import json
    from pathlib import Path

    results = json.loads(Path("results.json").read_text(encoding="utf-8"))
    flagged = sum(1 for result in results["results"] if result.get("flagged"))
    print(f"Flagged results: {flagged}")
    raise SystemExit(1 if flagged else 0)
    PY
```

You can replace that logic with a severity threshold later if you only want to fail on higher
signal findings.
