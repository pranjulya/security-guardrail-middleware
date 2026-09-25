# Phase 00 — Contract and environment

Status: NOT_STARTED

## Goal

Confirm a reproducible local environment, declared threat boundary and safe fixture plan before writing detector logic.

## Why

Wrong model/package assumptions or an undefined host boundary invalidate later results.

## Prerequisites

Owner approves implementation and repository destination. Read PRD, HLD and sources.

## Architecture impact and interfaces

Locks runtime/model compatibility and the host/library boundary. Consume the LLD envelope/policy contract; produce only the specified phase behavior. Global caps and decision precedence in Implementation.md apply without exception.

## Planned files

docs/environment.md; docs/threat-review.md; tests/fixtures/README.md; pyproject.toml (future implementation only)

These paths are implementation targets, not files created in this planning delivery.

## Ordered work

- [ ] Record approved versions and required local resources without claiming compatibility until installed.
- [ ] Design five synthetic boundary cases and label expected outcomes by hand.
- [ ] Verify the clean environment and record exact results, then review the threat map.

## Tests and verification

Verify chosen Python/Presidio/NLP-model versions install together in a clean environment; record artifact origins/licenses. Review a matrix of four boundaries, trusted principal ownership and synthetic fixture provenance.

No test has been run for this phase. Record the real command, expected behavior, actual outcome and environment in the evidence record after implementation.

## Failure scenarios

Unavailable model artifact; incompatible runtime; copied real PII; a supposed trusted boundary controlled by the user.

## Acceptance criteria

Compatibility record reproduces; scope and threat review accepted; synthetic fixture schema and split policy frozen.

## Learning objectives

Distinguish data provenance, model licensing and threat boundaries. Read the corresponding Learning path stage; explain a counterexample before review.

## Interview questions

Which assumptions invalidate the security claim? How does a local library differ from a gateway?

## Review gate and evidence record

A reviewer checks scoped changes, failure evidence and privacy. Owner accepts any changed requirement or ADR. Evidence record at execution: date, commit, commands, actual results, policy/model versions, reviewer, limitations and rollback action. Roll back the phase change as a unit if its security contract regresses; never disable mandatory checks to pass. Only then mark COMPLETE and unlock the next phase.
