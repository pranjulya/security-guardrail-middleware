# Review 02 findings (security review, Critical + High only)

Date: 2026-09-28. Scope: Critical and High findings from the consolidated security review of PRs #1–#8; Medium/Low items are intentionally out of scope for this branch. Branch: `review-02-critical-high-fixes` (stacked on `phase-06-http-adapter`).

| ID | Severity | Finding | Resolution | Regression test |
|---|---|---|---|---|
| C1 | Critical | Overlapping-span union redaction leaked digits on phases 02–05 (fixed in review 01) | Confirmed fixed; property regression added (0/20k failures now, fails against phase-05 code) | `tests/test_redaction_property.py` |
| H1 | High | Injection rules trivially evaded (unicode, zero-width, homoglyphs, spacing, encodings, paraphrase); NFKC-expansion truncation bypass; FPs | Multi-view normalisation (NFKC, Cf stripping, diacritics, confusables, spaced letters, leetspeak, letters-only), single-level decoding (base64/url, hex, percent, HTML), broader phrasing, FP reductions, limits measured after normalisation with fail-closed `InjectionScanLimit` | `tests/test_injection_evasion.py` |
| H2 | High | Library raised on lone surrogates, non-dict envelopes, non-str chunks, failing audit sink | `inspect`/`collect_model_output` are total and fail closed; `ReasonCode.AUDIT_ERROR` | `tests/test_fail_closed.py` |
| H3 | High | HTTP handler crashed (no response) on non-ASCII auth / lone surrogate JSON | Bytes auth compare; 400/500 JSON responses on every path; content-free error logging | `tests/test_http_hardening.py` |
| H4 | High | Single shared per-request slot: interleaving defeated budget, concurrency corrupted deadlines, output misattributed | Per-request-id state map with locks, LRU bound, `end_request`, explicit `request_id` for model output | `tests/test_request_isolation.py` |
| H5 | High | Slow clients held admission slots; unbounded pre-auth threads | Watchdog total read deadline, body read before admission, pre-auth connection cap | `tests/test_http_hardening.py` |
| H6 | High | First request blocked at startup; `/healthz` ready before model load | Locked engine creation, `warm_up()`, readiness only after warm-up | `tests/test_warm_up.py` |
| H7 | High | Clean install/build failed (model not on PyPI; SPDX license vs setuptools>=70) | Model pinned by URL+sha256; `setuptools>=77`; docs | `tests/test_packaging.py` |
| H8 | High | Repo public, no branch protection, Dependabot off | **Not fixed in code** — repository settings require an owner decision | — |

## API changes

- `Pipeline.collect_model_output(chunks, *, request_id)` — request ID is now required and keyword-only.
- `Pipeline.active_request_id` removed; use `request_usage(request_id)`, `end_request(request_id)`, `tracked_requests`.
- `Pipeline.warm_up()`, `PiiRedactor.warm_up()`; `ServerConfig.warm_up`, `max_connections`, `read_deadline_seconds`.
- New `ReasonCode.AUDIT_ERROR`; HTTP `503 AUDIT_UNAVAILABLE`, `503 NOT_READY`, `503 OVERLOADED`, `500 INTERNAL_ERROR`.
- `injection.normalized_view()` no longer truncates; `detect()` may raise `InjectionScanLimit` (callers must fail closed; `is_blocked()` returns True).

## Remaining (not in this branch)

- Injection detection remains a heuristic signal; paraphrases outside the rule families, non-English text, multi-level encodings and ROT-style ciphers still pass. A classifier stage and a held-out adversarial corpus are recommended (review Medium items).
- Hosts that share one `Pipeline` across requests should call `end_request()`; LRU eviction (`max_tracked_requests`) means a request evicted under heavy load starts a fresh budget.
- Connection-cap exhaustion by a client that reconnects every read deadline still denies service; needs per-client limits at a proxy.
- Medium/Low findings (audit field sanitisation, Presidio DEBUG logging, PII obfuscation, policy immutability, unused `presidio-anonymizer`, CI, etc.) are unchanged.
