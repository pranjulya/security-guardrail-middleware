# Contributing

Thanks for your interest. This is a small, security-focused project, so the
bar for changes is "reviewed, tested, and explained".

## Ground rules

- **Synthetic data only.** Never commit real PII, production logs, tokens or
  credentials — not in code, fixtures, tests, issues or PRs. Fixture values use
  reserved example domains, fictional phone ranges and public test-card
  numbers (see `tests/fixtures/README.md`).
- Security issues: follow `SECURITY.md`, not public issues.
- Policy changes (entities, thresholds, rules) need a version bump and an
  ADR/owner approval; see `docs/architecture/ADRs/`.

## Development setup

```bash
python3.12 -m venv .venv
.venv/bin/pip install --require-hashes --no-deps -r requirements-dev-lock.txt
.venv/bin/pip install --no-deps -e .
```

## Before opening a PR

Run what CI runs (`.github/workflows/ci.yml`):

```bash
pytest -q
ruff check . && ruff format --check .
mypy                      # strict, configured in pyproject.toml
bandit -q -r src tools examples
python tools/strip_url_requirements.py requirements-lock.txt > /tmp/audit.txt
pip-audit --strict --require-hashes --disable-pip -r /tmp/audit.txt
gitleaks git --no-banner --redact .
```

Every behaviour change needs a regression test. Keep the library contract
total: `Pipeline.inspect()` must always return a `Decision` and fail closed.

If you change dependencies, regenerate both hashed locks (commands in
`docs/environment.md`). If you change fixtures, regenerate them with
`python tools/generate_fixtures.py` (the test suite checks they are
reproducible).

## Commits and PRs

One logical change per commit with a descriptive message; reference the
finding or issue ID where relevant. PRs need a passing CI run and review by a
code owner (`.github/CODEOWNERS`).
