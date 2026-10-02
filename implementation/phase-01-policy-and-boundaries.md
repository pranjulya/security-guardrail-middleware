# Phase 01 — Policy and boundary validation

Status: IN_PROGRESS (implemented on branch `phase-01-policy-boundaries`, tests passing)

## Goal

Implement strict envelope/policy validation, immutable snapshots, fixed reason codes and safe event serialization.

## Why

Later detectors need one unambiguous failure and decision contract.

## Prerequisites

Phase 00 accepted; LLD interface reviewed.

## Architecture impact and interfaces

Creates the shared contract and default-deny startup behavior. Consume the LLD envelope/policy contract; produce only the specified phase behavior. Global caps and decision precedence in Implementation.md apply without exception.

## Planned files

src/guardrails/contracts.py; src/guardrails/policy.py; src/guardrails/audit.py; tests/test_contracts.py

These paths are implementation targets, not files created in this planning delivery.

## Ordered work

- [x] Write named failing cases for every limit and malformed-field class.
- [x] Implement the smallest validators and allowlisted serializer matching LLD.
- [x] Run targeted tests, inspect captured logs for synthetic markers, and review the contract.

## Tests and verification

Unknown boundary, unsupported language, empty/invalid type, unknown policy fields, byte caps at limit and +1 including multibyte text, aggregate block/byte limit, and PII canary in exception messages. Future command: python -m pytest tests/test_contracts.py.

Concrete expected outcomes: A 16 KiB valid English block passes size validation; 16 KiB+1 returns LIMIT_EXCEEDED with safe_text absent. Unsupported language returns UNSUPPORTED_LANGUAGE. A malformed policy prevents readiness, and captured events contain no synthetic canary string.

No test has been run for this phase. Record the real command, expected behavior, actual outcome and environment in the evidence record after implementation.

## Failure scenarios

Invalid policy silently defaults; user overrides required checks; character count mistaken for bytes; exception text leaks payload.

## Acceptance criteria

Every malformed input rejects consistently; policy cannot weaken approved caps; only allowlisted event fields serialize; no payload in errors.

## Learning objectives

Understand immutable policy and validation at trust boundaries. Read the corresponding Learning path stage; explain a counterexample before review.

## Interview questions

Why use bytes for caps? Does ALLOW certify safety?

## Review gate and evidence record

A reviewer checks scoped changes, failure evidence and privacy. Owner accepts any changed requirement or ADR. Evidence record at execution: date, commit, commands, actual results, policy/model versions, reviewer, limitations and rollback action. Roll back the phase change as a unit if its security contract regresses; never disable mandatory checks to pass. Only then mark COMPLETE and unlock the next phase.
