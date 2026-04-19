# Contributing to knives-out

Thanks for contributing to `knives-out`.

This project is intentionally practical: small focused changes, reproducible
validation, and clear GitHub history are preferred over broad speculative
refactors.

## Before you open a pull request

- Open or link an issue first for net-new features, behavior changes, or larger
  refactors.
- Use [GitHub Discussions](https://github.com/keithwegner/knives-out/discussions)
  for usage questions, setup help, or early design conversation.
- Use [`SECURITY.md`](SECURITY.md) instead of a public issue for vulnerability
  reports.

If you want to send a small typo fix or other narrow docs correction directly as
a pull request, that is fine.

## Development setup

Create a Python environment and install the project with development
dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

The frontend lives in [`frontend/`](frontend):

```bash
cd frontend
npm ci
```

## Validation

Run the checks that match the surface you changed.

Backend / docs:

```bash
pytest
ruff check .
ruff format --check .
```

Frontend:

```bash
cd frontend
npm test -- --run
npm run build
```

If your change touches both Python and frontend code, run both sets.

## Pull request expectations

- Keep PRs scoped to one coherent change.
- Link the relevant issue in the PR description.
- Update docs, examples, or screenshots when the user-facing workflow changes.
- Add or update tests when behavior changes.
- Note any follow-up work explicitly instead of leaving it implicit in review.

For workbench or other UI changes, include screenshots or a short video/GIF in
the pull request so reviewers can verify the intended experience quickly.

## Style and workflow

- Prefer clear names and predictable behavior over clever abstractions.
- Match the established repo structure and conventions instead of introducing a
  new pattern unless the change clearly justifies it.
- Keep commits intentional and reviewable.
- Do not mix unrelated cleanup into feature PRs.

## Issue intake

The repository uses GitHub Issue Forms for bugs, feature requests, and
documentation or community process improvements.

Questions belong in
[GitHub Discussions](https://github.com/keithwegner/knives-out/discussions)
instead of Issues so bug and feature tracking stays focused.
