# Environment baseline (phase 00)

Status: IMPLEMENTED baseline, pending threat-review acceptance.

Date: 2026-09-25. Machine: darwin arm64, local dev host.

## Approved versions (pinned)

| Component | Version | Origin / license |
|---|---|---|
| Python | 3.12.13 (`/Users/pranjulyabajpai/.local/bin/python3.12`, venv `.venv`) | python.org / PSF |
| presidio-analyzer | 2.2.360 (PyPI) | MIT, https://github.com/Microsoft/presidio (now data-privacy-stack) |
| spacy | 3.8.16 (PyPI) | MIT, Explosion |
| en_core_web_lg | 3.8.0 (`python -m spacy download en_core_web_lg`) | MIT, Explosion |
| pytest | 9.1.1 (PyPI; >=9.0.3 required for CVE-2025-71176) | MIT |

Presidio supported Python per docs: 3.10/3.11/3.12/3.13. System Python 3.9.6 is NOT used.
Install (review 02, one step; the model wheel is pinned by URL + sha256 in `pyproject.toml` because spaCy models are not on PyPI):
`python3.12 -m venv .venv && .venv/bin/pip install -e ".[test]"` (or `uv venv -p 3.12 && uv pip install -e ".[test]"`).
Building requires `setuptools>=77` (PEP 639 SPDX `license = "MIT"`); `python -m build` fetches it automatically in an isolated build env.
Reproducible install from the hashed lock (review 02, M8; all ~55 transitive packages pinned with sha256):
`pip install --require-hashes -r requirements-lock.txt && pip install --no-deps -e .`
Regenerate after any dependency change with
`uv pip compile pyproject.toml --extra test --generate-hashes --universal --python-version 3.12 -o requirements-lock.txt`.
`presidio-anonymizer` was removed (review 02, M8): nothing imported it and it pinned a vulnerable `cryptography<44.1`.
Dev tools (`pip install -e ".[dev]"`): ruff, mypy, bandit, pip-audit (pinned in `pyproject.toml`); hashed dev lock `requirements-dev-lock.txt` (`uv pip compile pyproject.toml --extra test --extra dev --generate-hashes --universal --python-version 3.12 -o requirements-dev-lock.txt`).
CI (`.github/workflows/ci.yml`, review 02 M9/L13) runs on every push/PR: clean install from `requirements-lock.txt --require-hashes` + pytest + example smoke run; ruff check/format, mypy --strict, bandit; pip-audit `--strict` on both locks (the direct-URL model wheel is excluded by `tools/strip_url_requirements.py` because pip-audit cannot look it up; it stays sha256-pinned); gitleaks over full history (checksum-verified binary). Actions are SHA-pinned, token is `contents: read`. `.github/dependabot.yml` opens weekly update PRs for pip and GitHub Actions.
Previous instruction (`pip install -e .` then `spacy download`) failed on a clean machine because `en-core-web-lg==3.8.0` cannot be resolved from PyPI.
Clean-install reproduction (this host, 2026-09-25): `pip install -e .` OK after adding explicit `[tool.setuptools.packages.find]` (auto-discovery refused flat layout with no packages yet); `pytest --collect-only` → 0 items, no errors.

## Verified results

- venv creation: OK (Python 3.12.13, pip 25.0.1).
- Pinned install (phase 00: `presidio-analyzer==2.2.360 presidio-anonymizer==2.2.360 spacy==3.8.16 pytest==8.4.2`): OK, no resolver conflicts. Review 02 dropped `presidio-anonymizer` and moved to pytest 9.1.1.
- spaCy model download `en_core_web_lg`: OK (3.8.0), `spacy.load` metadata name `core_web_lg` 3.8.0.
- spaCy cold `load()` on this host: ~0.5 s (single sample, not a benchmark).
- No GPU required; CPU-only single process.

## Required local resources

- Disk for venv + model (~1 GB class), outbound PyPI + model download at setup only.
- Demo runs offline after install; disable unneeded egress for local demo.

## Limitations / not claimed

- Compatibility verified only on this host/interpreter; clean-install reproduction on a second machine not yet run.
- Latency budgets (PRD p95 targets), concurrency-4, and repeated-trial figures are UNMEASURED; phase 05 measures them.
- Container image references from Presidio examples were NOT copied; legacy `mcr.microsoft.com/presidio-*` images are stale per docs — use `ghcr.io/data-privacy-stack/*` only if containers are ever needed (not V1).
