# ADR 003 — Buffered fail-closed decisions

Status: PROPOSED

## Context

A streamed token cannot be recalled after disclosure.

## Recommended decision

Buffer complete output; mandatory detector failures, deadline or invalid policy block with no text.

## Alternatives

Streaming improves perceived latency but needs a different audited release protocol; fail-open improves availability while violating the security contract.

## Consequences

Higher perceived latency and reduced availability on detector failure; bounded response size and operational alerts are required.

## Acceptance evidence

Phase 04 zero-release tests on errors and phase 05 recovery drill.
