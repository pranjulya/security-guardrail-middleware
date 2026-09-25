# ADR 002 — Local PII and irreversible replacement

Status: PROPOSED

## Context

Detector coverage and privacy claims must be explicit.

## Recommended decision

Use local Presidio with English model and four declared entities; replace detected spans with category labels and retain no mapping.

## Alternatives

Regex-only reduces footprint but lacks PERSON coverage; hosted detection sends content outside the process; reversible pseudonyms create state and disclosure risk.

## Consequences

NER adds startup/memory cost and makes errors possible. Dates, addresses, national identifiers and other languages remain outside coverage.

## Acceptance evidence

Phase 02 exact-span and overlap cases; phase 05 per-category metrics and licensing record.
