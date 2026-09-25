# HTTP adapter deployment (phase 06)

Status: IMPLEMENTED on branch `phase-06-http-adapter`; supervisor/load drill pending owner review.

## Scope

Optional authenticated adapter exposing the same `inspect` contract to a named non-Python client. It inspects a single boundary per call; it does not replace the host's multi-step pipeline and does not enforce host tool permissions.

## Dependency choice

Stdlib only (`http.server`, `hmac`, `json`) — no new runtime dependency was added. Chosen over Flask/FastAPI because the surface is one endpoint and dependency growth is a review concern.

## Interface

- `POST /v1/inspect` body `{"boundary", "language", "text"}` (unknown keys rejected). Server generates `request_id` and resolves `policy_id` server-side; callers cannot supply either.
- Responses: `200` with public decision (`safe_text` only for ALLOW/REDACT — BLOCK has none); `400` `BAD_JSON`/`BAD_REQUEST`; `401` `UNAUTHORIZED`; `413` `BODY_TOO_LARGE` (checked against `Content-Length` before reading/parsing); `429` `SATURATED`; `503` `DETECTOR_UNAVAILABLE`; `404` `NOT_FOUND`.
- `GET /healthz` unauthenticated, returns readiness + policy version only (no payloads).

## Controls

- Loopback bind only (`127.0.0.1` default); `create_server` refuses non-loopback hosts — public hosting requires separate G4 approval.
- Bearer token compared with `hmac.compare_digest`; token required at startup.
- Wire cap 17 KiB (`MAX_WIRE_BYTES`) enforced on the header before the body is read; text still capped at 16 KiB by the pipeline (LIMIT_EXCEEDED → 200 BLOCK).
- Bounded admission semaphore (`max_concurrent`, default 8) with 50ms wait → 429; released in `finally` on every path.
- Socket timeout 5s: stalled/disconnected clients are dropped and their admission slot released (abandoned work is capped in-process).
- Decision parity with library asserted in `tests/test_http.py`.

## Known limitations

- No cross-process supervisor: adapter runs in-process; a wedged CPU-bound detector inside one request cannot be force-killed (same cooperative-deadline semantics as the library). Process-level supervision remains an out-of-scope deployment concern, not implemented here.
- Load test (saturation under sustained concurrency, memory under stalled detectors) not yet run; only deterministic 429 behavior is tested.
- No TLS: loopback/private network only; terminate TLS upstream if traffic ever leaves the host (needs separate approval).

## Rollout

1. Run behind loopback with token from environment (never commit tokens).
2. Verify `/healthz` policy version matches the intended bundle before traffic.
3. Roll back by stopping the process and reverting the phase branch; library use is unaffected.
