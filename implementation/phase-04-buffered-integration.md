# Phase 04 — Buffered end-to-end integration

Status: NOT_STARTED

## Goal

Route all four boundaries through inspection and release only completed safe output.

## Why

Correct individual detectors do not help when an application bypasses them or streams first.

## Prerequisites

Phase 03 accepted; fake model and read-only tool available.

## Architecture impact and interfaces

Owns aggregate request bounds, call ordering, deadlines and output release gate. Consume the LLD envelope/policy contract; produce only the specified phase behavior. Global caps and decision precedence in Implementation.md apply without exception.

## Planned files

src/guardrails/pipeline.py; examples/synthetic_assistant.py; tests/test_pipeline.py

These paths are implementation targets, not files created in this planning delivery.

## Ordered work

- [ ] Write sink/call-order spies and inject failures at every boundary.
- [ ] Implement ordered pipeline and bounded request accounting with fixed safe refusal.
- [ ] Run integration plus prior tests; inspect all captured sinks for synthetic sensitive markers.

## Tests and verification

Input BLOCK causes zero model calls; retrieval/tool output inspected before use; output PII redacted; exception/timeout/oversize after generation releases zero bytes; policy snapshot unchanged mid-request; aggregate four-block limit; future output budget enforcement during private collection; delayed synchronous detector completion. Future command: python -m pytest tests/test_pipeline.py.

No test has been run for this phase. Record the real command, expected behavior, actual outcome and environment in the evidence record after implementation.

## Failure scenarios

Late exception leaks buffered text; fallback returns raw response; tool loop grows; telemetry failure changes security decision.

## Acceptance criteria

A detector returning after the two-second cumulative inspection budget yields DEADLINE_EXCEEDED and zero released bytes, without claiming the call was preempted. A 16 KiB+1 generated response is discarded at collection cap; a fifth text block is rejected before forwarding; a structured authorized tool proposal alone does not consume a free-text slot. Every blocking/error route returns fixed refusal; sink receives no raw content; optional event outage does not bypass detectors; no user-visible streaming or more than one tool invocation.

## Learning objectives

Explain transactional output release and cancellation limits. Read the corresponding Learning path stage; explain a counterexample before review.

## Interview questions

Why cannot a timeout thread guarantee detector cancellation? What does buffering cost?

## Review gate and evidence record

A reviewer checks scoped changes, failure evidence and privacy. Owner accepts any changed requirement or ADR. Evidence record at execution: date, commit, commands, actual results, policy/model versions, reviewer, limitations and rollback action. Roll back the phase change as a unit if its security contract regresses; never disable mandatory checks to pass. Only then mark COMPLETE and unlock the next phase.
