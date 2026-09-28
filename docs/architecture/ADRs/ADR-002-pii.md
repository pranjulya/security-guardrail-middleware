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

## Review 02 amendment (M3) — PROPOSED, pending owner acceptance

- **Normalised detection.** Detection runs on NFKC text with Unicode format characters (`Cf`: zero-width space/joiner, soft hyphen, bidi controls) removed; spans are mapped back to original offsets and the *original* text is redacted. Closes zero-width, full-width digit and full-width `@` evasions.
- **Separator-tolerant recognizers.** Card numbers split by dots, newlines, slashes, underscores or tabs (Luhn-validated), and bracketed e-mail obfuscation (`[at]`, `(at)`, `{at}`, `<at>` with `[dot]`/`.`; TLD-validated offline) are recognised. The plain-word form `name at domain dot com` is deliberately **not** matched (false positives on ordinary prose).
- **Out-of-scope categories — written decision.** `US_SSN`, `IBAN_CODE` and `SECRET_TOKEN` (common API-key/token/private-key formats) are available as **opt-in** policy entities. They are not enabled in the default policy `v1.1` because changing the default scope is a product decision; enabling `SECRET_TOKEN` at least for `model_output` is recommended. Other national identifiers, addresses and dates remain uncovered.
- **Still not covered (accepted limitations).** Spelled-out digits ("four one one one …"), PII split across separately inspected blocks, non-English text, and novel obfuscations. The library is a data-minimisation layer, not an anonymisation guarantee.
