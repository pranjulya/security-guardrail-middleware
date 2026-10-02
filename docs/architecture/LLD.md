# Low-level design and contracts

Status: PROPOSED (design awaiting owner acceptance). The files below now exist; review 02 (PR #9) changes are noted inline.

## Module ownership

| File | Responsibility |
|---|---|
| src/guardrails/contracts.py | Boundary and decision types, validated envelope |
| src/guardrails/policy.py | Strict local policy validation and immutable snapshot |
| src/guardrails/pii.py | Presidio integration and original-text span replacement |
| src/guardrails/injection.py | Bounded rule detector, stable rule identifiers |
| src/guardrails/pipeline.py | Ordered execution, deadline and decision precedence |
| src/guardrails/audit.py | Allowlisted content-free event serializer |
| examples/synthetic_assistant.py | Reference host flow on `Pipeline`: every boundary inspected, only `safe_text` released (review 02, M12) |
| tools/generate_fixtures.py, tools/evaluate.py | Reproducible synthetic fixtures; public-API evaluator (review 02, M10) |
| src/guardrails/http.py | Optional phase 06 adapter only |

## Logical interface

`inspect(envelope, policy_snapshot, deadline) → Decision` is synchronous. Envelope contains boundary enum (user_input, retrieved_content, tool_output, model_output), text string, declared language `en`, server-generated opaque request_id and trusted application policy ID. Neither text nor callers can override detector requirements. The host tracks aggregate bytes and maximum block count across the request. The four block slots cover user input, at most one retrieved text block, at most one tool-output text block and final model output. Absent retrieval/tool stages leave their slots unused; they do not authorize unbounded extra calls. All inspected text counts in the 64 KiB aggregate budget, including content eventually blocked. An empty or whitespace-only text is INVALID_ENVELOPE. Inspect rejects individual limit violations and the orchestrator rejects known aggregate violations before initial model execution and reserves slots/remaining byte capacity for later stages. It cannot validate unknown future text in advance. As each tool output or final model output arrives, enforce its per-block cap and remaining aggregate budget before any forwarding/release. Buffering must enforce the smaller of the 16 KiB per-text cap and remaining request bytes as data arrives; cancel/discard generation on overflow without exposing partial text.

Review 02 binding (M4/L8): the envelope key set is fixed (unknown keys → INVALID_ENVELOPE); `request_id` must match `[A-Za-z0-9._:-]{1,64}`; `policy_id` must equal `PolicySnapshot.policy_id` = `<version>@<first 16 hex of digest>`, so a policy whose content changed without a version bump is refused. `Pipeline` refuses (PolicyError) a redactor whose entities/thresholds differ from the policy; use `Pipeline.from_policy()` / `PiiRedactor.from_policy()`. Thresholds are read-only.

Decision fields: action ALLOW/REDACT/BLOCK; safe_text (string only for ALLOW/REDACT, absent for BLOCK); reason_codes (fixed enum values); policy_version; policy_id (review 02); detector_versions; elapsed_ms. No original text, matched text or precise spans in the returned public audit summary. Internal spans are ephemeral and never serialized. ALLOW means no configured rule fired, not proof of safety.

Precedence: validation failure or mandatory detector error → BLOCK; blocking injection rule → BLOCK; detected PII → REDACT; otherwise ALLOW. Injection inspection checks the original text and a bounded normalized detection view. Review 02 (M3): PII detection also runs on a normalized view (NFKC, format characters removed) with an index map back to original offsets; redaction is always applied to the original text via the mapped offsets. Never use unmapped normalized offsets on original text. Redacted output is rescanned for supported PII once; residual detections block, with no indefinite recursion. Redaction uses category labels such as [EMAIL_ADDRESS], not identity-specific reversible tokens. For overlapping spans, merge each connected overlap group, replace its entire original-text union, and choose the label by fixed precedence CREDIT_CARD, EMAIL_ADDRESS, PHONE_NUMBER, PERSON. Adjacent non-overlapping spans remain separate. Apply replacements from highest start offset to lowest so earlier indices remain valid. Reject invalid detector spans (negative, end before start, or outside text) as DETECTOR_ERROR.

Policy fields: version, enabled entity set fixed to approved coverage, entity-specific thresholds, rule IDs/actions, per-text/aggregate byte limits, max_blocks, cumulative inspection budget. Unknown keys and missing mandatory rules invalidate startup. Values outside approved caps fail validation. Proposed detector threshold seed is 0.5 per category for calibration only; phase 02 calibrates on development data and freezes values before held-out evaluation. A policy change creates a new version/digest.

## Flow and failure semantics

1. Host validates principal, request size and supported language before invoking model or tools.
2. Inspect user input and up to remaining allowed evidence blocks. Stop on BLOCK; do not forward discarded text.
3. Host sends only safe text to model. No user-visible streaming callback is registered.
4. Tool proposals use a fixed read-only catalog tool, a trusted host principal and strict scalar argument schema. Unknown tool/extra arguments/unauthorized item return denial; never evaluate shell, SQL or URLs supplied by model. Review 02 (M7): the principal comes only from host session state (`Pipeline.dispatch_tool(proposal, *, request_id, session_principal, ...)`); a proposal that names a principal is denied; non-string arguments are denied; per-principal entitlements are supported; `max_tool_invocations` is enforced per request; every decision emits a content-free `tool_decision` event and an audit failure denies the call.
5. Inspect tool output before any second model call. Intermediate structured tool-proposal control data is validated by host authorization and is not counted as a scanned free-text block. If any proposal field is reused as model-facing content, it becomes inspected text and consumes the appropriate available block/byte budget; otherwise reject the extra-content flow rather than bypass inspection. Tool loop maximum one invocation for V1, keeping the four-block request bound predictable.
6. Buffer full model output internally; enforce caps incrementally while collecting, without a user-visible streaming callback. The host may consume a provider token stream privately for capped collection, but no token is released before final inspection. Inspect before returning safe_text. A partial generation, failure or timeout returns generic refusal without buffered content.

Reason codes: INVALID_ENVELOPE, UNSUPPORTED_LANGUAGE, LIMIT_EXCEEDED, POLICY_INVALID, DETECTOR_ERROR, DEADLINE_EXCEEDED, INJECTION_RULE, PII_REDACTED, RESIDUAL_PII, TOOL_DENIED. Public refusal describes inability to safely process; detailed rule IDs stay in operator events. Safe refusals are fixed application text, never interpolated exception strings.

## State and retention

Per request: immutable policy reference, opaque ID, byte/block counters, remaining inspection-time budget and transient text. No cross-request content memory. Content-free event retention default seven days, configurable only within deployment approval. Fixture IDs are allowed in offline evaluation artifacts; real request IDs never become metric labels. No claim of secure zeroization in Python.

## Optional HTTP mapping

POST /v1/inspect accepts text, boundary and language; service creates request ID, authenticates caller and resolves policy server-side. 200 for completed ALLOW/REDACT/BLOCK decisions (with `request_id`); 400 malformed schema (including non-string fields and any Transfer-Encoding), 413 too large, 401/403 access rejection, 429 saturation, 503 unavailable detector. Error bodies contain stable code only. This endpoint inspects a single boundary; it does not replace the host's full multi-step pipeline. Health endpoints expose readiness/version without payloads. No universal agent proxy is planned.

## Deadline semantics (cooperative, with a pre-emptive detector wait since review 02)

The core tracks a 2-second cumulative inspection-time budget, excluding model and tool execution. Before each detector, check remaining budget; after it returns, debit elapsed time and BLOCK with DEADLINE_EXCEEDED if exhausted. Review 02 (M6): time spent collecting buffered model output counts against the budget and is checked after every chunk; the PII detector runs on a bounded pool of daemon threads (`DetectorRunner`, 16 process-wide) and the caller waits at most the remaining budget, then returns BLOCK DEADLINE_EXCEEDED while the abandoned result is discarded. A stream whose `next()` never returns is still the host's responsibility. An in-process synchronous call may return much later than the budget and cannot be force-cancelled safely. The invariant is no text forwarded or released after a failed deadline check, not hard execution-time termination. Bound text sizes and host concurrency, and do not admit replacement work indefinitely while a detector is still running. A supervisor may mark the worker unhealthy, but process isolation and forced termination are optional phase 06 deployment capabilities requiring separate tests.
