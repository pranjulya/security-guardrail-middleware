# PII calibration (phase 02)

Status: frozen for V1 on development data, 2026-09-25.

## Seed and frozen thresholds

Seed per LLD: 0.5 per category. Frozen policy (unchanged after dev probe):

| Entity | Threshold | Evidence |
|---|---|---|
| EMAIL_ADDRESS | 0.5 | pattern recognizer score 1.0 on synthetic email |
| PHONE_NUMBER | 0.5 | recognizer 0.4–0.9 on synthetic phones; 0.5 keeps dev fixtures detected |
| CREDIT_CARD | 0.5 | Luhn + pattern score 1.0 on `4111 1111 1111 1111` |
| PERSON | 0.5 | 5/5 synthetic names detected at 0.4–0.8 probe with en_core_web_lg 3.8.0 |

## Method

- Golden original-text spans annotated first (`tests/fixtures/pii-development.jsonl`).
- Stubs assert exact replacement strings; live Presidio check covers email + card only (deterministic), PERSON live coverage deferred to phase 05 held-out per-category metrics.
- Detector scope limited to the 4 approved entities; DATE_TIME/URL findings filtered.

## Warnings

- PERSON recall on real names is the known V1 risk; phase 05 must report per-category recall with >=100 positives each and narrow scope with owner approval if the target misses — never silently drop PERSON.
- Thresholds frozen before held-out use; retuning on held-out data requires a fresh split.
