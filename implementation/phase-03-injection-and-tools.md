# Phase 03 — Injection rules and tool authorization

Status: IN_PROGRESS (implemented on branch `phase-03-injection-tools`, tests passing)

## Goal

Add bounded injection-risk rules and a separate host-owned read-only tool authorization example.

## Why

A classifier miss must never grant a new capability.

## Prerequisites

Phase 02 accepted; policy and boundary types stable.

## Architecture impact and interfaces

Adds original/normalized inspection views and a fixed catalog tool outside model authority. Consume the LLD envelope/policy contract; produce only the specified phase behavior. Global caps and decision precedence in Implementation.md apply without exception.

## Planned files

src/guardrails/injection.py; examples/synthetic_assistant.py; tests/test_injection.py; tests/test_tool_authorization.py

These paths are implementation targets, not files created in this planning delivery.

## Ordered work

- [x] Write contrasting malicious/benign rule examples and tool denial spies.
- [x] Implement finite reviewed rules and a strict host allowlist without URL/shell tools.
- [x] Run tests and document a detector-missed case whose tool action is nevertheless denied.

## Tests and verification

Direct override, indirect retrieved instruction, tool-output instruction, Unicode/encoding variants, benign quotation; fake model proposes unknown tool, extra argument or unauthorized item. Future command: python -m pytest tests/test_injection.py tests/test_tool_authorization.py.

Concrete expected outcomes: A matching blocking rule yields BLOCK/INJECTION_RULE with its stable rule ID. An unavailable tool or caller-forged principal yields TOOL_DENIED and zero dispatches. A benign quotation false positive is recorded as such, not relabeled malicious.

No test has been run for this phase. Record the real command, expected behavior, actual outcome and environment in the evidence record after implementation.

## Failure scenarios

Broad keyword rules block education; model supplies its own principal; a tool result is trusted by origin alone.

## Acceptance criteria

All unauthorized proposal cases dispatch zero tools; rules emit stable IDs; benign errors recorded; no recursive decoding or unbounded regex behavior.

## Learning objectives

Separate probabilistic risk detection from deterministic authorization. Read the corresponding Learning path stage; explain a counterexample before review.

## Interview questions

Can redacted instructions still be malicious? Where does the principal come from?

## Review gate and evidence record

A reviewer checks scoped changes, failure evidence and privacy. Owner accepts any changed requirement or ADR. Evidence record at execution: date, commit, commands, actual results, policy/model versions, reviewer, limitations and rollback action. Roll back the phase change as a unit if its security contract regresses; never disable mandatory checks to pass. Only then mark COMPLETE and unlock the next phase.
