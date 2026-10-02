# HTTP adapter deployment (phase 06)

Status: IMPLEMENTED on branch `phase-06-http-adapter`, hardened in review 02 (PR #9); supervisor/load drill pending owner review.

## Scope

Optional authenticated adapter exposing the same `inspect` contract to a named non-Python client. It inspects a single boundary per call; it does not replace the host's multi-step pipeline and does not enforce host tool permissions.

## Dependency choice

Stdlib only (`http.server`, `hmac`, `json`) — no new runtime dependency was added. Chosen over Flask/FastAPI because the surface is one endpoint and dependency growth is a review concern.

## Interface

- `POST /v1/inspect` body `{"boundary", "language", "text"}` (unknown keys rejected; every field must be a JSON string, else `400 BAD_REQUEST`). Framing: exactly one `Content-Length`; any `Transfer-Encoding` header → `400` (no CL/TE ambiguity behind a proxy). Server generates `request_id` and resolves `policy_id` server-side; callers cannot supply either.
- Responses: `200` with public decision plus `request_id` (`safe_text` only for ALLOW/REDACT — BLOCK has none); `400` `BAD_JSON`/`BAD_REQUEST` (incl. invalid UTF-8, escaped lone surrogates, excessive nesting); `401` `UNAUTHORIZED` (incl. non-ASCII headers); `413` `BODY_TOO_LARGE` (checked against `Content-Length` before reading/parsing); `429` `SATURATED`; `503` `DETECTOR_UNAVAILABLE` / `AUDIT_UNAVAILABLE` / `NOT_READY` / `OVERLOADED` (connection cap); `500` `INTERNAL_ERROR` for anything unexpected; `404` `NOT_FOUND`. Every request receives a response; tracebacks are never written. `503 SHUTTING_DOWN` while draining.
- Every response carries `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` and `X-Request-Id` (same value as the body `request_id` and the audit events); `401` carries `WWW-Authenticate: Bearer realm="guardrail"` (review 02, L3).
- `GET /healthz` unauthenticated, returns readiness + policy version only (no payloads): `200 {"status":"ready"}` only after a successful detector warm-up, otherwise `503 {"status":"starting"}` (review 02).

## Controls

- Loopback bind only (`127.0.0.1` default); `create_server` refuses non-loopback hosts — public hosting requires separate G4 approval.
- Bearer token compared with `hmac.compare_digest`; token required at startup, at least 32 characters, no whitespace/control characters. Generate with e.g. `python -c 'import secrets; print(secrets.token_urlsafe(32))'`.
- Audit/access trail: `ServerConfig(event_sink=...)` receives the pipeline's content-free inspection events plus one `http_access` event per request (`request_id`, method, route from a closed set, status, elapsed_ms). A failing sink fails inspection closed (`503 AUDIT_UNAVAILABLE`); access-event failures are counted and logged without content.
- Graceful drain: `server.shutdown_gracefully(timeout)` stops accepting, answers `503 SHUTTING_DOWN` on already-open connections, waits for in-flight requests and returns whether they all finished.
- Wire cap 17 KiB (`MAX_WIRE_BYTES`) enforced on the header before the body is read; text still capped at 16 KiB by the pipeline (LIMIT_EXCEEDED → 200 BLOCK).
- Bounded admission semaphore (`max_concurrent`, default 8) with 50ms wait → 429; taken only *after* the full body has been read, released in `finally` on every path.
- Connection cap (`max_connections`, default 32) enforced before parsing/auth: at most that many handler threads; excess connections get `503 OVERLOADED` and are closed.
- Total read deadline (`read_deadline_seconds`, default 10s) for request line + headers + body, enforced by a watchdog that shuts the socket down; the 5s socket timeout still applies per `recv`. Trickling clients are dropped at the deadline.
- Detector warm-up at `create_server()` (`warm_up=True`); engine creation is locked so only one model instance is built.
- Decision parity with library asserted in `tests/test_http.py`.

## Known limitations

- No cross-process supervisor: adapter runs in-process. Since review 02 (M6) the request *answers* at its deadline (`DEADLINE_EXCEEDED`) even if the detector is wedged, but the wedged detector thread itself cannot be killed; at most 16 such threads exist process-wide, after which requests fail closed (`503 DETECTOR_UNAVAILABLE`). Process-level supervision remains an out-of-scope deployment concern, not implemented here.
- Load test (saturation under sustained concurrency, memory under stalled detectors) not yet run; only deterministic 429/503 behavior is tested.
- Connection-cap exhaustion: an attacker that keeps `max_connections` sockets open and reconnects every `read_deadline_seconds` can still deny service; per-client limits need a reverse proxy (all loopback clients share one address).
- No TLS: loopback/private network only; terminate TLS upstream if traffic ever leaves the host (needs separate approval).

## Rollout

1. Run `python -m guardrails.http --port 8080` behind loopback. The token is read from `GUARDRAIL_TOKEN_FILE` (preferred, e.g. a mounted secret) or `GUARDRAIL_TOKEN`; never from code or argv (never commit tokens). Audit/access events are written as JSON lines to the `guardrails.audit` logger (stderr). SIGTERM/SIGINT trigger a graceful drain (`--drain-seconds`, default 10); exit code 0 when drained.
2. Verify `/healthz` policy version matches the intended bundle before traffic.
3. Roll back by stopping the process and reverting the phase branch; library use is unaffected.
