# ADR 001 — Library and trust boundaries

Status: PROPOSED

## Context

A shared inspection contract is needed without adopting a whole agent framework.

## Recommended decision

Use an in-process Python library; host controls identity, retrieval ACLs and fixed tool authorization.

## Alternatives

A generic HTTP proxy would miss application-specific permissions; framework hooks would couple the core to one stack.

## Consequences

Host bypass remains possible; integration tests must prove all four boundaries are called.

## Acceptance evidence

Phase 01 contracts and phase 04 call-order tests; add HTTP only for a named consumer.
