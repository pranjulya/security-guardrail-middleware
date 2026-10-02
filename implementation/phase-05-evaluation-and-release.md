# Phase 05 — Evaluation and release evidence

Status: IN_PROGRESS (implemented on branch `phase-05-evaluation-release`; dev-eval evidence recorded, held-out NOT RUN)

## Goal

Measure declared quality/performance and rehearse privacy-preserving operations.

## Why

A release needs reproducible evidence and candid limitations, not a successful happy-path demo.

## Prerequisites

Phase 04 accepted; thresholds frozen; held-out templates isolated.

## Architecture impact and interfaces

Freezes release policy, detector artifacts and report contract. Consume the LLD envelope/policy contract; produce only the specified phase behavior. Global caps and decision precedence in Implementation.md apply without exception.

## Planned files

tests/evaluation/test_invariants.py; tools/evaluate.py; reports/evaluation/<run-id>/summary.md; docs/release-checklist.md

These paths are implementation targets, not files created in this planning delivery.

## Ordered work

- [x] Freeze fixture manifest, model settings and decision policy before held-out execution.
- [x] Run evaluation and operational drills, preserving failures and denominators.
- [ ] Have reviewer reproduce a subset and approve truthful release notes; update statuses only with evidence.

## Tests and verification

Run finite enforcement regression, per-category PII evaluation, injection false positives, optional real-model attack baseline, ≥200-call warm timing samples, cold startup, concurrency 4, privacy canary and rollback drill. Future commands are finalized with evaluator CLI in this phase and recorded verbatim in report.

Concrete expected outcomes: Any failed deterministic enforcement invariant stops release. A missing real model yields UNMEASURED attack-prevention results rather than a percentage. Every declared PII category has its own positive-instance denominator and metrics; the privacy canary is absent from every exported sink.

No test has been run for this phase. Record the real command, expected behavior, actual outcome and environment in the evidence record after implementation.

## Failure scenarios

Test contamination; aggregate score hides category misses; no real model but attack prevention claimed; payload leaks into failure report.

## Acceptance criteria

PRD gates met or explicit scope revision accepted; critical invariants all pass; model-dependent claims marked unmeasured when absent; clean reproduction and content-free export reviewed.

## Learning objectives

Read uncertainty and distinguish detector metrics from real attack outcomes. Read the corresponding Learning path stage; explain a counterexample before review.

## Interview questions

What would falsify the claim? Why are synthetic results not production proof?

## Review gate and evidence record

A reviewer checks scoped changes, failure evidence and privacy. Owner accepts any changed requirement or ADR. Evidence record at execution: date, commit, commands, actual results, policy/model versions, reviewer, limitations and rollback action. Roll back the phase change as a unit if its security contract regresses; never disable mandatory checks to pass. Only then mark COMPLETE and unlock the next phase.
