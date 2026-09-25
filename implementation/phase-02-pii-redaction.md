# Phase 02 — PII redaction

Status: NOT_STARTED

## Goal

Detect the four supported English entity categories and replace original-text spans deterministically.

## Why

The system must prevent detectable PII crossing boundaries without corrupting unrelated text.

## Prerequisites

Phase 01 accepted; pinned model installed; development fixtures available.

## Architecture impact and interfaces

Adds a local detector reused across requests without retained identity mappings. Consume the LLD envelope/policy contract; produce only the specified phase behavior. Global caps and decision precedence in Implementation.md apply without exception.

## Planned files

src/guardrails/pii.py; tests/test_pii.py; tests/fixtures/pii-development.jsonl; docs/evaluation/calibration.md

These paths are implementation targets, not files created in this planning delivery.

## Ordered work

- [ ] Annotate golden original-text spans before detector integration.
- [ ] Implement local detection, deterministic union/replacement and one residual scan.
- [ ] Calibrate thresholds on development cases, freeze policy version and review golden/exception tests.

## Tests and verification

Golden replacements for email/phone/card/person, Unicode, overlaps, adjacency, no-match, unsupported category limitations, detector failure and residual detections. Future command: python -m pytest tests/test_pii.py.

Concrete expected outcomes: A synthetic email fixture becomes exactly [EMAIL_ADDRESS] in the golden text; overlapping supported entities leave no source characters from their union. A detector exception or invalid span yields BLOCK/DETECTOR_ERROR, and a residual finding yields BLOCK/RESIDUAL_PII with no text.

No test has been run for this phase. Record the real command, expected behavior, actual outcome and environment in the evidence record after implementation.

## Failure scenarios

Normalized offsets applied to original text; overlapped entities leave fragments; name false positives; model unavailable.

## Acceptance criteria

Original-text span tests pass; overlapping ranges union deterministically; fixed category precedence documented; residual PII blocks; calibrated thresholds frozen on development data.

## Learning objectives

Explain precision/recall, original offsets and redaction versus anonymization. Read the corresponding Learning path stage; explain a counterexample before review.

## Interview questions

Why can a PERSON recognizer miss names? Why not store token mappings?

## Review gate and evidence record

A reviewer checks scoped changes, failure evidence and privacy. Owner accepts any changed requirement or ADR. Evidence record at execution: date, commit, commands, actual results, policy/model versions, reviewer, limitations and rollback action. Roll back the phase change as a unit if its security contract regresses; never disable mandatory checks to pass. Only then mark COMPLETE and unlock the next phase.
