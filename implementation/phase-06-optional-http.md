# Phase 06 — Optional HTTP adapter

Status: IMPLEMENTED (stdlib adapter, auth/body/admission/parity tests recorded passing; blocking: load/supervisor drill + deployment review pending)

## Goal

Expose the accepted inspection contract to a named external client without expanding it into an agent proxy.

## Why

Useful only when an actual non-Python consumer or process boundary requires HTTP.

## Prerequisites

Phase 05 accepted plus explicit adapter scope approval; otherwise remain NOT_STARTED.

## Architecture impact and interfaces

Adds network authentication, body limits, bounded admission and supervised worker lifecycle. Consume the LLD envelope/policy contract; produce only the specified phase behavior. Global caps and decision precedence in Implementation.md apply without exception.

## Planned files

src/guardrails/http.py; tests/test_http.py; docs/operations/http-deployment.md

These paths are implementation targets, not files created in this planning delivery.

## Ordered work

- [x] Confirm the named client and choose the smallest established web dependency at implementation time.
- [x] Write auth/body/admission/parity tests before wrapping inspect.
- [ ] Load-test supervisor recovery, document limitations and obtain deployment review.

## Tests and verification

Missing/invalid auth, malformed JSON, body >16 KiB text cap and bounded wire body, saturation 429, detector unavailable 503, decision parity with library, cancellation and memory under stalled detectors. Future command: python -m pytest tests/test_http.py.

Concrete expected outcomes: Missing auth yields 401; excess body size yields 413 before full parsing; saturation yields 429; unavailable mandatory detector yields 503. Completed BLOCK decisions use 200 with action BLOCK and no safe_text, matching the library contract.

No test has been run for this phase. Record the real command, expected behavior, actual outcome and environment in the evidence record after implementation.

## Failure scenarios

Body parsed before cap; public endpoint without auth; worker hangs after client disconnect; 200 BLOCK misunderstood as ALLOW.

## Acceptance criteria

Loopback default; authenticated private use only; response semantics documented; parity tests pass; process supervision caps abandoned work; public hosting remains separately approved.

## Learning objectives

Understand service trust boundaries and backpressure. Read the corresponding Learning path stage; explain a counterexample before review.

## Interview questions

Why does an HTTP adapter not enforce the host tool permissions?

## Review gate and evidence record

A reviewer checks scoped changes, failure evidence and privacy. Owner accepts any changed requirement or ADR. Evidence record at execution: date, commit, commands, actual results, policy/model versions, reviewer, limitations and rollback action. Roll back the phase change as a unit if its security contract regresses; never disable mandatory checks to pass. Only then mark COMPLETE and unlock the next phase.
