# Release checklist (phase 05)

Status: DRAFT — provisional, pending owner acceptance of targets and ADRs.

## Gates

- [x] Deterministic enforcement invariants pass (`tests/evaluation/test_invariants.py`, 9 cases).
- [x] Full regression passes (61 tests: contracts 12, PII 14, injection 7, tool-auth 7, pipeline 12, invariants 9).
- [x] Dev-eval report generated (`reports/evaluation/phase05-dev/`): per-category precision/recall, leakage 0, warm timing p50/p95, content-free export, canary check.
- [ ] Held-out evaluation on disjoint fixtures (>=100 positives/category, 120 injection, 200 benign, 40 enforcement) — NOT RUN; dev fixtures only.
- [ ] PRD targets accepted or scope revised: PII recall >=95%/precision >=90% per category; injection >=90% prevention / <=5% FP; perf p95 <=200ms/4KiB warm.
- [ ] Cold startup + concurrency-4 measured on recorded hardware — stub cold ~13ms import; Presidio-model cold + concurrency-4 NOT measured.
- [ ] Rollback drill recorded — procedure: `git revert` phase branch or reset to last green tag; rerun invariants + canary grep before resume. Drill execution pending.
- [ ] Owner accepts ADRs 001–004, threat review, and release notes with limitations.

## Known deviations from PRD provisional budgets

- Warm p95 on this host (stub detector): ~423ms @512B / ~502ms @4KiB — EXCEEDS provisional p95 <=200ms/4KiB. Live Presidio timing not yet measured; budget revision or optimization required before release claim.
- No real model run: end-to-end attack prevention UNMEASURED (detector metrics only).

## Change policy

Unmet security invariant blocks release. Quality/perf misses require tuning on dev data or explicit scope/target revision before a fresh held-out run. Never edit held-out labels to win.
