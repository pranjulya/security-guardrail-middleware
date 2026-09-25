# PII calibration (phase 02, revised in phase 05 eval)

Status: REVISED 2026-09-25 — PHONE threshold lowered after dev-eval evidence.

## Seed and frozen thresholds

Seed per LLD: 0.5 per category.

| Entity | Threshold | Evidence |
|---|---|---|
| EMAIL_ADDRESS | 0.5 | pattern recognizer score 1.0 on synthetic email |
| PHONE_NUMBER | 0.4 | recognizer emits 0.4 on `415-555-0132` / `+1-415-555-0132`; 0.5 filtered every dev phone case (eval: recall 0.0) |
| CREDIT_CARD | 0.5 | Luhn + pattern score 1.0 on `4111 1111 1111 1111` |
| PERSON | 0.5 | 5/5 synthetic names detected at 0.4–0.8 probe with en_core_web_lg 3.8.0 |

## Method

- Golden original-text spans annotated first (`tests/fixtures/pii-development.jsonl`).
- Stubs assert exact replacement strings; live Presidio check covers email + card only (deterministic), PERSON live coverage deferred to phase 05 held-out per-category metrics.
- Detector scope limited to the 4 approved entities; DATE_TIME/URL findings filtered.

## Warnings

- PERSON recall on real names is the known V1 risk; phase 05 must report per-category recall with >=100 positives each and narrow scope with owner approval if the target misses — never silently drop PERSON.
- Thresholds frozen before held-out use; retuning on held-out data requires a fresh split.
