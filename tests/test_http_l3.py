"""Review 02 / L3: HTTP response headers, contract, audit trail, lifecycle."""

from __future__ import annotations

import json
import os
import socket
import threading
import time

import pytest

from guardrails.http import (
    AUTH_ENV_VAR,
    AUTH_FILE_ENV_VAR,
    MIN_TOKEN_CHARS,
    ServerConfig,
    create_server,
    load_token,
    main,
)
from guardrails.pii import PiiRedactor
from guardrails.pipeline import Pipeline
from guardrails.policy import DEFAULT_POLICY, load_policy

POLICY = load_policy(DEFAULT_POLICY)
TOKEN = "test-token-0123456789-abcdefghijkl"
VALID = json.dumps({"boundary": "user_input", "language": "en", "text": "hello"}).encode()


def pipeline(**kw) -> Pipeline:
    return Pipeline(
        policy=POLICY,
        redactor=PiiRedactor.from_policy(POLICY, detector=lambda t, lang, e: []),
        **kw,
    )


def start(**kw):
    server = create_server(ServerConfig(auth_token=TOKEN, pipeline_factory=pipeline, **kw))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def headers_of(response: bytes) -> dict[str, str]:
    head = response.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    out: dict[str, str] = {}
    for line in head.split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip().lower()] = v.strip()
    return out


def status(response: bytes) -> int:
    return int(response.split(b" ", 2)[1])


def body(response: bytes) -> dict:
    return json.loads(response.split(b"\r\n\r\n", 1)[1])


def raw(server, payload: bytes, timeout: float = 5.0) -> bytes:
    sock = socket.create_connection(server.server_address[:2], timeout=timeout)
    try:
        sock.sendall(payload)
        data = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
        return data
    finally:
        sock.close()


def post(server, body_bytes: bytes = VALID, extra_headers: bytes = b"") -> bytes:
    return raw(
        server,
        b"POST /v1/inspect HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer "
        + TOKEN.encode()
        + b"\r\nContent-Length: "
        + str(len(body_bytes)).encode()
        + b"\r\n"
        + extra_headers
        + b"\r\n"
        + body_bytes,
    )


@pytest.fixture
def server():
    srv = start()
    yield srv
    srv.shutdown_gracefully(2)


def test_success_carries_no_store_nosniff_and_request_id(server):
    response = post(server)
    headers = headers_of(response)
    assert status(response) == 200
    assert headers["cache-control"] == "no-store"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-request-id"]
    assert body(response)["request_id"] == headers["x-request-id"]


def test_401_carries_www_authenticate(server):
    response = raw(
        server,
        b"POST /v1/inspect HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer wrong\r\n"
        b"Content-Length: 2\r\n\r\n{}",
    )
    assert status(response) == 401
    assert headers_of(response)["www-authenticate"].startswith("Bearer")
    assert headers_of(response)["cache-control"] == "no-store"


def test_healthz_also_carries_hardening_headers(server):
    response = raw(server, b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
    headers = headers_of(response)
    assert status(response) == 200
    assert headers["cache-control"] == "no-store"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-request-id"]


def test_non_string_text_is_400(server):
    payload = json.dumps({"boundary": "user_input", "language": "en", "text": 1}).encode()
    response = post(server, payload)
    assert status(response) == 400
    assert body(response) == {"code": "BAD_REQUEST"}


def test_transfer_encoding_alone_or_with_content_length_is_400(server):
    for framing in (
        b"Transfer-Encoding: chunked\r\n",
        b"Transfer-Encoding: chunked\r\nContent-Length: " + str(len(VALID)).encode() + b"\r\n",
        b"Content-Length: " + str(len(VALID)).encode() + b"\r\nContent-Length: 1\r\n",
    ):
        response = raw(
            server,
            b"POST /v1/inspect HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer "
            + TOKEN.encode()
            + b"\r\n"
            + framing
            + b"\r\n"
            + VALID,
        )
        assert status(response) == 400, framing
        assert body(response) == {"code": "BAD_REQUEST"}


def test_short_or_whitespace_token_rejected_at_config():
    with pytest.raises(ValueError):
        ServerConfig(auth_token="a", pipeline_factory=pipeline)
    with pytest.raises(ValueError):
        ServerConfig(auth_token="x" * (MIN_TOKEN_CHARS - 1), pipeline_factory=pipeline)
    with pytest.raises(ValueError):
        ServerConfig(auth_token="x" * MIN_TOKEN_CHARS + "\n", pipeline_factory=pipeline)
    with pytest.raises(ValueError):
        ServerConfig(auth_token="x" * MIN_TOKEN_CHARS + " ", pipeline_factory=pipeline)


def test_event_sink_receives_inspection_and_access_events():
    events: list[dict] = []
    srv = start(event_sink=events.append)
    try:
        response = post(srv)
        assert status(response) == 200
        rid = body(response)["request_id"]

        # Wait briefly for the access event (emitted in finish()).
        def has_access() -> bool:
            return any(e.get("event") == "http_access" for e in events)

        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and not has_access():
            time.sleep(0.05)
        inspection = [e for e in events if "action" in e]
        assert [e["action"] for e in inspection] == ["ALLOW"]
        assert inspection[0]["request_id"] == rid
        access = next(e for e in events if e.get("event") == "http_access")
        assert access == {
            "event": "http_access",
            "request_id": rid,
            "method": "POST",
            "route": "/v1/inspect",
            "status": 200,
            "elapsed_ms": access["elapsed_ms"],
        }
        assert access["elapsed_ms"] >= 0
        assert all("hello" not in json.dumps(e) for e in events)
    finally:
        srv.shutdown_gracefully(2)


def test_shutdown_gracefully_drains_in_flight_request():
    gate = threading.Event()

    def slow(t, lang, e):
        gate.wait(5)
        return []

    def factory():
        return Pipeline(
            policy=POLICY,
            redactor=PiiRedactor.from_policy(POLICY, detector=slow),
            preemptive_deadline=False,
        )

    srv = create_server(ServerConfig(auth_token=TOKEN, pipeline_factory=factory, max_concurrent=2))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    result: dict = {}

    def client():
        result["response"] = post(srv)

    t = threading.Thread(target=client)
    t.start()
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and srv.active_connections == 0:
        time.sleep(0.01)
    assert srv.active_connections >= 1
    gate.set()
    drained = srv.shutdown_gracefully(5)
    t.join(5)
    assert drained is True
    assert status(result["response"]) == 200
    assert srv.active_connections == 0


def test_load_token_from_file_preferred_over_env(tmp_path, monkeypatch):
    path = tmp_path / "token"
    path.write_text("file-token-" + "x" * 24)
    monkeypatch.setenv(AUTH_FILE_ENV_VAR, str(path))
    monkeypatch.setenv(AUTH_ENV_VAR, "env-token-" + "y" * 24)
    assert load_token() == "file-token-" + "x" * 24
    monkeypatch.delenv(AUTH_FILE_ENV_VAR)
    assert load_token() == "env-token-" + "y" * 24
    monkeypatch.delenv(AUTH_ENV_VAR)
    with pytest.raises(ValueError):
        load_token()


def test_main_entrypoint_refuses_missing_token(monkeypatch):
    monkeypatch.delenv(AUTH_ENV_VAR, raising=False)
    monkeypatch.delenv(AUTH_FILE_ENV_VAR, raising=False)
    assert main(["--host", "127.0.0.1", "--port", "0"]) == 2


def test_python_m_entrypoint_serves_and_drains_on_sigterm(tmp_path):
    import signal
    import subprocess
    import sys
    import urllib.request

    token_file = tmp_path / "token"
    token_file.write_text("entrypoint-token-" + "z" * 24)
    env = {k: v for k, v in os.environ.items() if k != AUTH_ENV_VAR}
    env[AUTH_FILE_ENV_VAR] = str(token_file)
    proc = subprocess.Popen(
        [sys.executable, "-m", "guardrails.http", "--port", "0"],
        env=env,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        port = None
        deadline = time.monotonic() + 120
        assert proc.stderr is not None
        while time.monotonic() < deadline:
            line = proc.stderr.readline()
            if not line:
                break
            if "listening on" in line:
                assert "ready=True" in line
                port = int(line.split("listening on ", 1)[1].split()[0].rsplit(":", 1)[1])
                break
        assert port, "server did not start"
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=5) as resp:
            assert resp.status == 200
            assert resp.headers["Cache-Control"] == "no-store"
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=30) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
