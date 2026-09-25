# Environment baseline (phase 00)

Status: IMPLEMENTED baseline, pending threat-review acceptance.

Date: 2026-09-25. Machine: darwin arm64, local dev host.

## Approved versions (pinned)

| Component | Version | Origin / license |
|---|---|---|
| Python | 3.12.13 (`/Users/pranjulyabajpai/.local/bin/python3.12`, venv `.venv`) | python.org / PSF |
| presidio-analyzer | 2.2.360 (PyPI) | MIT, https://github.com/Microsoft/presidio (now data-privacy-stack) |
| presidio-anonymizer | 2.2.360 (PyPI) | MIT |
| spacy | 3.8.16 (PyPI) | MIT, Explosion |
| en_core_web_lg | 3.8.0 (`python -m spacy download en_core_web_lg`) | MIT, Explosion |
| pytest | 8.4.2 (PyPI) | MIT |

Presidio supported Python per docs: 3.10/3.11/3.12/3.13. System Python 3.9.6 is NOT used.
Install: `python3.12 -m venv .venv && .venv/bin/pip install -e . && .venv/bin/python -m spacy download en_core_web_lg`
Clean-install reproduction (this host, 2026-09-25): `pip install -e .` OK after adding explicit `[tool.setuptools.packages.find]` (auto-discovery refused flat layout with no packages yet); `pytest --collect-only` → 0 items, no errors.

## Verified results

- venv creation: OK (Python 3.12.13, pip 25.0.1).
- Pinned install (`presidio-analyzer==2.2.360 presidio-anonymizer==2.2.360 spacy==3.8.16 pytest==8.4.2`): OK, no resolver conflicts.
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
