"""Review 02 / H3 + H5: HTTP adapter always answers, and resists slow clients."""

from __future__ import annotations

import json
import logging
import socket
import threading
import time

import pytest

from guardrails.http import ServerConfig, create_server
from guardrails.pii import PiiRedactor
from guardrails.pipeline import Pipeline
from guardrails.policy import DEFAULT_POLICY, load_policy

POLICY = load_policy(DEFAULT_POLICY)
TOKEN = "test-token-0123456789-abcdefghijkl"
VALID = json.dumps({"boundary": "user_input", "language": "en", "text": "hello"}).encode()


def pipeline(detector=None, **kw) -> Pipeline:
    return Pipeline(
        policy=POLICY,
        redactor=PiiRedactor(
            entities=POLICY.entities, detector=detector or (lambda t, lang, e: [])
        ),
        **kw,
    )


def start(factory=pipeline, token=TOKEN, **kw):
    server = create_server(ServerConfig(auth_token=token, pipeline_factory=factory, **kw))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def server():
    srv = start()
    yield srv
    srv.shutdown()
    srv.server_close()


def raw_request(server, payload: bytes, timeout: float = 5.0) -> bytes:
    sock = socket.create_connection(server.server_address[:2], timeout=timeout)
    try:
        sock.sendall(payload)
        data = b""
        while True:
            try:
                chunk = sock.recv(65536)
            except (TimeoutError, ConnectionResetError):
                break
            if not chunk:
                break
            data += chunk
        return data
    finally:
        sock.close()


def post(server, body: bytes, auth: bytes = b"Bearer " + TOKEN.encode()) -> bytes:
    return raw_request(
        server,
        b"POST /v1/inspect HTTP/1.1\r\nHost: x\r\nAuthorization: "
        + auth
        + b"\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\n\r\n"
        + body,
    )


def status(response: bytes) -> int:
    assert response, "server dropped the connection without a response"
    return int(response.split(b" ", 2)[1])


def body(response: bytes) -> dict:
    return json.loads(response.split(b"\r\n\r\n", 1)[1])


# --------------------------------------------------------------------------- H3


@pytest.mark.parametrize("auth", [b"Bearer \xe9\xe9", b"\xff\xfe", "Bearer tök".encode()])
def test_non_ascii_authorization_gets_401(server, auth):
    response = post(server, VALID, auth=auth)
    assert status(response) == 401
    assert body(response) == {"code": "UNAUTHORIZED"}


def test_non_ascii_configured_token_works():
    token = "tökén-0123456789-abcdefghijklmnop"
    srv = start(token=token)
    try:
        assert status(post(srv, VALID, auth=b"Bearer " + token.encode("utf-8"))) == 200
        assert status(post(srv, VALID, auth=b"Bearer wrong")) == 401
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.mark.parametrize(
    "payload",
    [
        b'{"boundary": "user_input", "language": "en", "text": "hi \\ud800"}',
        b'{"boundary": "user_input", "language": "\\udfff", "text": "hi"}',
        b"\xff\xfe\x00not utf8",
        b'{"boundary": "user_input", "language": "en", "text": "unterminated',
        b"[" * 10000 + b"]" * 10000,
    ],
)
def test_bad_json_always_gets_4xx(server, payload):
    response = post(server, payload)
    assert 400 <= status(response) < 500
    assert body(response)["code"] in {"BAD_JSON", "BAD_REQUEST", "BODY_TOO_LARGE"}


def test_unexpected_error_returns_500_without_traceback(caplog):
    calls = {"n": 0}

    def factory():
        calls["n"] += 1
        if calls["n"] > 1:  # works for startup/warm-up, fails per request
            raise RuntimeError("factory broke SYNTH_HTTP_CANARY")
        return pipeline()

    srv = start(factory=factory)
    try:
        with caplog.at_level(logging.ERROR, logger="guardrails.http"):
            response = post(srv, VALID)
        assert status(response) == 500
        assert body(response) == {"code": "INTERNAL_ERROR"}
        assert "SYNTH_HTTP_CANARY" not in caplog.text
        assert "Traceback" not in caplog.text
    finally:
        srv.shutdown()
        srv.server_close()


def test_failing_audit_sink_returns_503():
    def sink(event):
        raise RuntimeError("sink down")

    srv = start(factory=lambda: pipeline(event_sink=sink))
    try:
        response = post(srv, VALID)
        assert status(response) == 503
        assert body(response) == {"code": "AUDIT_UNAVAILABLE"}
    finally:
        srv.shutdown()
        srv.server_close()


def test_protocol_errors_get_json_error_bodies(server):
    response = raw_request(server, b"BOGUS / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert status(response) == 501
    assert body(response) == {"code": "HTTP_501"}


# --------------------------------------------------------------------------- H5


def _slow_client(server, header_only: bool, interval: float, result: dict) -> None:
    sock = socket.create_connection(server.server_address[:2], timeout=10)
    started = time.monotonic()
    try:
        if header_only:
            sock.sendall(b"POST /v1/inspect HTTP/1.1\r\n")
            filler = b"X-Pad: a\r\n"
        else:
            sock.sendall(
                b"POST /v1/inspect HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer "
                + TOKEN.encode()
                + b"\r\nContent-Length: 5000\r\n\r\n"
            )
            filler = b" "
        for _ in range(40):  # would take ~12s if never cut off
            time.sleep(interval)
            sock.sendall(filler)
        result["closed_after"] = None
    except OSError:
        result["closed_after"] = time.monotonic() - started
    finally:
        sock.close()


@pytest.mark.parametrize("header_only", [False, True])
def test_total_read_deadline_drops_trickling_clients(header_only):
    srv = start(read_deadline_seconds=1.0)
    try:
        result: dict = {}
        _slow_client(srv, header_only, 0.3, result)  # 0.3s << 5s socket timeout
        assert result["closed_after"] is not None
        assert result["closed_after"] < 4.0
    finally:
        srv.shutdown()
        srv.server_close()


def test_slow_body_clients_do_not_hold_admission_slots():
    srv = start(max_concurrent=1, max_connections=8, read_deadline_seconds=3.0)
    try:
        results = [{} for _ in range(3)]
        threads = [
            threading.Thread(target=_slow_client, args=(srv, False, 0.2, r)) for r in results
        ]
        for t in threads:
            t.start()
        time.sleep(0.5)
        codes = [status(post(srv, VALID)) for _ in range(3)]
        assert codes == [200, 200, 200]
        for t in threads:
            t.join()
        assert all(r["closed_after"] is not None for r in results)
    finally:
        srv.shutdown()
        srv.server_close()


def test_connection_cap_limits_threads_before_auth():
    srv = start(max_concurrent=2, max_connections=4, read_deadline_seconds=1.0)
    try:
        before = threading.active_count()
        idle = [socket.create_connection(srv.server_address[:2]) for _ in range(4)]
        time.sleep(0.3)
        extra = raw_request(srv, b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n", timeout=2)
        assert status(extra) == 503
        assert body(extra) == {"code": "OVERLOADED"}
        assert threading.active_count() - before <= 4
        many = [socket.create_connection(srv.server_address[:2]) for _ in range(50)]
        time.sleep(0.3)
        assert threading.active_count() - before <= 4
        assert srv.rejected_connections >= 1
        for s in idle + many:
            s.close()
        time.sleep(1.5)  # idle connections are reaped by the read deadline
        assert status(post(srv, VALID)) == 200
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_concurrent": 0},
        {"max_connections": 0},
        {"max_concurrent": 8, "max_connections": 4},
        {"read_deadline_seconds": 0},
    ],
)
def test_invalid_capacity_config_rejected(kwargs):
    with pytest.raises(ValueError):
        ServerConfig(auth_token=TOKEN, pipeline_factory=pipeline, **kwargs)
