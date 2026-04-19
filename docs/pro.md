# Knives-Out Pro

Knives-Out Pro is the planned self-hosted commercial add-on for developer teams that want
CI ReviewOps on top of the MIT core.

The open-source core remains useful on its own: CLI generation and execution, the local API,
the single-user workbench, Docker deployment, reports, SARIF export, verification, promotion,
and suppressions all stay in the MIT package.

## Pro positioning

The first paid bundle is CI ReviewOps:

- import CI runs, reports, SARIF, and artifacts into a shared self-hosted workbench
- compare pull request runs against branch or main baselines
- post one stable GitHub pull request comment per run context
- preserve linked request/response evidence for team review
- manage repository-level run history without sending customer APIs or traffic to a hosted service

Pro is packaged as a private `knives-out-pro` Python distribution and a private Pro Docker image
layered on the public image. Customers receive an offline signed license file; the product does
not call home for v1 subscription checks.

## Editions

| Edition | Package | Intended use |
| --- | --- | --- |
| Free | MIT `knives-out` | Local-first CLI/API/workbench, CI artifacts, and individual project review |
| Pro Team | Private `knives-out-pro` add-on | CI ReviewOps for up to 5 repositories |
| Pro Business | Private `knives-out-pro` add-on | CI ReviewOps for up to 25 repositories plus priority support |

Suggested launch pricing:

- Pro Team: `$299/month`
- Pro Business: `$999/month`

Billing and license issuance are manual for v1. A Stripe Payment Link or invoice can collect
payment, then a signed license is issued out of band.

## Extension contract

The MIT package exposes a small extension surface for Pro without depending on proprietary code:

- `GET /v1/edition` returns the active edition, license state, enabled capabilities, expiry
  metadata, and locked capabilities.
- Python entry points in the `knives_out.extensions` group can register additional FastAPI routes
  and Typer CLI commands.
- The default edition is Free with `ci_reviewops` locked when no Pro extension is installed.

A private Pro package should expose an entry point similar to:

```toml
[project.entry-points."knives_out.extensions"]
pro = "knives_out_pro.extension:Extension"
```

The extension object may implement:

- `edition_status() -> dict | EditionStatus`
- `register_api(app: fastapi.FastAPI) -> None`
- `register_cli(app: typer.Typer) -> None`

## License model

The Pro package owns license validation. The intended v1 behavior is:

- read a signed JSON license from `KNIVES_OUT_LICENSE` or `KNIVES_OUT_LICENSE_PATH`
- validate an Ed25519 signature offline
- support license fields for customer, plan, expiry, max repositories, and capabilities
- enable `ci_reviewops` only for valid licenses or licenses inside a 14-day grace window
- expose missing, invalid, expired, and grace-period states through `/v1/edition`

## Private Pro feature shape

The first private implementation should add:

- `knives-out-pro publish` for GitHub Actions
- a CI import endpoint accepting results, report, SARIF, artifacts, repo, branch, commit SHA,
  workflow URL, and pull request number
- repository and pull request views in the workbench
- baseline-aware comparisons across imported CI runs
- stable GitHub pull request comments with summary counts, policy outcome, deltas, and evidence links

GitLab, Bitbucket, hosted SaaS, SSO, RBAC, call-home subscription checks, and advanced paid attack
packs are deferred until CI ReviewOps has paying users.
