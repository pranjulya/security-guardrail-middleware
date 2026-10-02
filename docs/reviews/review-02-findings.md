# Review 02 findings (security review, Critical through Low)

Date: 2026-09-28. Scope: Critical, High, Medium and Low findings from the consolidated security review of PRs #1–#8. Repository-settings items (visibility, branch protection, Dependabot toggles) are excluded at the owner's request. The review report has no L4. Branch: `review-02-critical-high-fixes` (stacked on `phase-06-http-adapter`).

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

## Medium and Low findings

| ID | Severity | Finding | Resolution | Regression test |
|---|---|---|---|---|
| M1 | Medium | Audit events echoed caller-controlled `boundary`/`request_id` (raw text leaked) | `request_id`/`policy_id` patterns, `safe_request_id`/`safe_boundary` log `"invalid"`, `InspectionEvent` validates every field, `ENVELOPE_KEYS` | `tests/test_audit_privacy.py` |
| M2 | Medium | Presidio DEBUG logging wrote raw user text | `quiet_detector_loggers()` pins presidio/spaCy loggers at WARNING with non-propagating handlers on engine creation | `tests/test_logging_privacy.py` |
| M3 | Medium | Trivial PII evasion (zero-width, full-width digits/＠, dotted/spaced cards) | Normalised detection view with offset map back to the raw text; `ObfuscatedEmail` and separator-tolerant card recognizers; opt-in `US_SSN`/`IBAN_CODE`/`SECRET_TOKEN`; bounded regex (a ReDoS introduced by the first version was found and fixed) | `tests/test_pii_obfuscation.py`, `tests/test_pii_redos.py` — **partial**, see Remaining |
| M4 | Medium | Policy snapshot not authoritative/immutable; `policy_id` bound to version only | Read-only thresholds; `policy_id = version@sha256[:16]`; `Pipeline` refuses a redactor built from a different policy; `Pipeline.from_policy`, `PiiRedactor.from_policy`; `Decision.policy_id` | `tests/test_policy_binding.py` |
| M5 | Medium | Policy validation gaps (unknown keys, bad types, bool-as-int, NaN, unknown entities) | Strict schema validation raising `PolicyError` | `tests/test_policy_validation.py` |
| M6 | Medium | Deadline didn't cover output collection; detectors not pre-emptible | Deadline checked per chunk from collection start; `DetectorRunner` (bounded worker slots, budget-bounded wait) with `preemptive_deadline=True` | `tests/test_deadlines.py` |
| M7 | Medium | Tool authorization: model-supplied principal, no entitlements, budget unenforced, type confusion | Session-only principal, entitlement map, `ToolBudget`/`max_tool_invocations`, strict argument types, `tool_decision` audit events, `Pipeline.dispatch_tool` | `tests/test_tool_authorization.py` |
| M8 | Medium | Unused `presidio-anonymizer` pulled vulnerable `cryptography`; pytest advisory; floating transitives | Dependency dropped; pytest 9.1.1; hashed `requirements-lock.txt` / `requirements-dev-lock.txt` | `tests/test_packaging.py`, CI `audit` job |
| M9 | Medium | No CI or automated gates | `.github/workflows/ci.yml` (SHA-pinned actions, read-only token): hashed clean install + pytest + example, ruff/format/mypy/bandit, pip-audit `--strict`, gitleaks full history | `tests/test_ci_config.py` |
| M10 | Medium | Evaluation evidence too small to support claims | Seeded generator (`tools/generate_fixtures.py`): 520 PII held-out, 104 obfuscated, 120 injection, 200 benign; evaluator reports Wilson CIs, latency, concurrency, cold start; report in `reports/evaluation/review02/` | `tests/evaluation/test_eval_fixtures.py` — fixtures are author-written, not independent |
| M11 | Medium | Tests didn't test what they claimed (G1 outage/failing hook realism, injection-before-model) | Rewritten with fake model call counters, raising/flaky sinks, structured tool proposals; seeded pipeline fuzz | `tests/test_pipeline.py`, `tests/test_pipeline_fuzz.py` |
| M12 | Medium | Reference example released uninspected model/tool output | Example rebuilt on `Pipeline` (inspect input, collect+inspect output, `dispatch_tool`), `--stub` mode | `tests/test_example_assistant.py` |
| L1 | Low | PHONE threshold 0.4 equals base score | Trade-off measured and documented with three options | `docs/evaluation/calibration.md` — **pending owner decision** |
| L2 | Low | Runtime egress via tldextract | Offline suffix-list snapshot; restricted recognizer registry | `tests/test_offline_detector.py` |
| L3 | Low | HTTP hardening gaps | no-store/nosniff/X-Request-Id, `WWW-Authenticate`, token ≥32 chars, config validation, non-string fields → 400, TE/duplicate CL → 400, `request_id` in body, `http_access` events, graceful shutdown, `python -m guardrails.http` | `tests/test_http_l3.py` |
| L5 | Low | Hard-coded detector version | Version read from installed package metadata | `tests/test_detector_hygiene.py` |
| L6 | Low | Bad detector scores dropped silently | Non-finite/out-of-range score → `DetectorFailure` (BLOCK `DETECTOR_ERROR`); thresholds required | `tests/test_detector_hygiene.py` |
| L7 | Low | Engine initialisation race | Fixed by H6 (locked creation, `warm_up`) | `tests/test_warm_up.py` |
| L8 | Low | Envelope strictness | Exact key set, typed fields, pattern-checked IDs | `tests/test_audit_privacy.py`, `tests/test_contracts.py` |
| L9 | Low | Lint and type debt | ruff config + fixes, repo formatted, `mypy --strict` clean on `src`, `examples`, `tools`; `py.typed` | CI `lint` job |
| L10 | Low | License/governance files missing | `LICENSE` (MIT), `SECURITY.md`, `CODEOWNERS`, `CONTRIBUTING.md` | `tests/test_packaging.py` (wheel contains LICENSE) |
| L11 | Low | Hygiene (personal path, host e-mail) | Personal path removed; old commit author e-mails need a history rewrite (not done) | `tests/test_repo_hygiene.py` |
| L12 | Low | Docs and status drift | Phase statuses corrected (00–04 TESTED, 05/06 IMPLEMENTED, ADRs PROPOSED), LLD updated, "update scans" now points to CI | — (docs) |
| L13 | Low | Packaging churn | CI clean-install job from the hashed lock | CI `test` job |

## API changes

- `Pipeline.collect_model_output(chunks, *, request_id)` — request ID is now required and keyword-only.
- `Pipeline.active_request_id` removed; use `request_usage(request_id)`, `end_request(request_id)`, `tracked_requests`.
- `Pipeline.warm_up()`, `PiiRedactor.warm_up()`; `ServerConfig.warm_up`, `max_connections`, `read_deadline_seconds`.
- New `ReasonCode.AUDIT_ERROR`; HTTP `503 AUDIT_UNAVAILABLE`, `503 NOT_READY`, `503 OVERLOADED`, `500 INTERNAL_ERROR`.
- `injection.normalized_view()` no longer truncates; `detect()` may raise `InjectionScanLimit` (callers must fail closed; `is_blocked()` returns True).
- Policies: `policy_id` is `version@digest` and is required and pattern-checked in envelopes; thresholds are read-only; `Pipeline.from_policy(policy)` and `PiiRedactor.from_policy(policy)`; `Pipeline(...)` raises `PolicyError` if the redactor's policy differs; `Decision.policy_id`.
- PII: `PiiRedactor.detect(text)` (public detection API); thresholds are required; `US_SSN`, `IBAN_CODE`, `SECRET_TOKEN` are opt-in entities; non-finite detector scores raise `DetectorFailure`.
- Tools: `authorize_and_dispatch(proposal, *, session_principal, catalog, entitlements, budget)`; `Pipeline.dispatch_tool(proposal, *, request_id, session_principal, ...)`.
- Deadlines: `DetectorRunner`/`DETECTOR_RUNNER`; `Pipeline(..., preemptive_deadline=True)`.
- HTTP: token must be ≥32 non-whitespace characters; `ServerConfig.event_sink`; `shutdown_gracefully()`; `python -m guardrails.http` reading `GUARDRAIL_TOKEN_FILE` / `GUARDRAIL_TOKEN`.
- Packaging: `presidio-anonymizer` removed; `[dev]` extra; hashed lock files.

## Remaining (not in this branch)

- Repository settings (H8: visibility, branch protection, Dependabot alerts, CODEOWNERS enforcement) are left to the owner.
- ADRs and the threat review remain PROPOSED; L1 (PHONE threshold) needs an owner decision.
- PII: spelled-out digits and spelled "at"/"dot" e-mails, slash-separated cards and PII split across chunks/blocks are still missed; opt-in entities are off in the default policy; PERSON NER misses uncommon surnames; PHONE/PERSON false positives on business numbers and technical terms (benign FP 9.5%).
- Injection detection remains heuristic (held-out recall 0.758, role-play family 0.47); paraphrases, non-English text and multi-level encodings still pass. A classifier stage is recommended.
- Deadlines: a stream whose `next()` hangs can't be interrupted by the library; timed-out detector threads can't be killed (bounded by worker slots). Token-dense 16 KiB inputs cost 1–2.4 s in spaCy, close to the 2 s budget.
- Evaluation fixtures are author-generated, not independent; no evaluation against a real model.
- Hosts that share one `Pipeline` across requests should call `end_request()`; LRU eviction (`max_tracked_requests`) means a request evicted under heavy load starts a fresh budget.
- Connection-cap exhaustion by a client that reconnects every read deadline still denies service; needs per-client limits at a proxy.
- Old commit author e-mails expose a hostname; fixing needs a history rewrite.
