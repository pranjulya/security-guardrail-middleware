# ADR 004 — Synthetic evaluation and honest claims

Status: PROPOSED

## Context

A good-looking demo is not evidence of universal protection.

## Recommended decision

Use synthetic held-out cases, publish confusion matrices, baseline comparisons and known bypasses; no real PII.

## Alternatives

A single attack pass/fail score hides false positives; production-log replay adds privacy and permission requirements.

## Consequences

Synthetic distributions may not represent actual deployment; real-world effectiveness remains unproven.

## Acceptance evidence

Phase 05 reproduces report and separates detector metrics from end-to-end model attack success.
