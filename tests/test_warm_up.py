"""Review 02 / H6: warm-up at init, single engine creation, honest readiness."""

from __future__ import annotations

import http.client
import json
import threading
import time

import pytest

from guardrails import pii
from guardrails.contracts import Action, ReasonCode
from guardrails.http import ServerConfig, create_server
from guardrails.pii import DetectorFailure, PiiRedactor
from guardrails.pipeline import Pipeline
from guardrails.policy import DEFAULT_POLICY, load_policy

POLICY = load_policy(DEFAULT_POLICY)
TOKEN = "test-token-0123456789-abcdefghijkl"


def _call(server, method, path, body=None):
    conn = http.client.HTTPConnection(*server.server_address[:2], timeout=10)
    conn.request(
        method,
        path,
        body=json.dumps(body) if body is not None else None,
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    response = conn.getresponse()
    data = response.read()
    conn.close()
    return response.status, json.loads(data)


def _serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_engine_is_created_exactly_once_under_concurrency(monkeypatch):
    import presidio_analyzer

    created = []

    class FakeEngine:
        def __init__(self):
            time.sleep(0.2)
            created.append(self)

    monkeypatch.setattr(presidio_analyzer, "AnalyzerEngine", FakeEngine)
    monkeypatch.setattr(pii, "_ENGINE", None)
    engines = []
    threads = [threading.Thread(target=lambda: engines.append(pii._get_engine())) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(created) == 1
    assert all(e is created[0] for e in engines)


def test_create_server_warms_up_before_reporting_ready():
    calls = []

    def detector(text, lang, entities):
        calls.append(text)
        return []

    def factory():
        return Pipeline(
            policy=POLICY,
            redactor=PiiRedactor(entities=POLICY.entities, detector=detector),
        )

    server = create_server(ServerConfig(auth_token=TOKEN, pipeline_factory=factory))
    try:
        assert calls == [pii.WARM_UP_TEXT]  # warmed before any traffic
        assert server.ready and server.warm_up_ms is not None
        _serve(server)
        status, payload = _call(server, "GET", "/healthz")
        assert status == 200 and payload["status"] == "ready"
    finally:
        server.shutdown()
        server.server_close()


def test_failed_warm_up_is_not_ready_and_refuses_traffic():
    def detector(text, lang, entities):
        raise DetectorFailure()

    def factory():
        return Pipeline(
            policy=POLICY,
            redactor=PiiRedactor(entities=POLICY.entities, detector=detector),
        )

    server = _serve(create_server(ServerConfig(auth_token=TOKEN, pipeline_factory=factory)))
    try:
        assert server.ready is False
        status, payload = _call(server, "GET", "/healthz")
        assert status == 503 and payload["status"] == "starting"
        status, payload = _call(
            server,
            "POST",
            "/v1/inspect",
            {"boundary": "user_input", "language": "en", "text": "hi"},
        )
        assert status == 503 and payload == {"code": "NOT_READY"}
    finally:
        server.shutdown()
        server.server_close()


def test_live_presidio_first_request_after_warm_up_is_not_deadline_blocked(monkeypatch):
    pytest.importorskip("presidio_analyzer")
    monkeypatch.setattr(pii, "_ENGINE", None)  # force a genuine cold start
    pipeline = Pipeline(
        policy=POLICY,
        redactor=PiiRedactor(entities=POLICY.entities, thresholds=dict(POLICY.thresholds)),
    )
    pipeline.warm_up()
    decision = pipeline.inspect(
        {
            "boundary": "model_output",
            "language": "en",
            "text": "mail jane.doe@example.com",
            "request_id": "first",
            "policy_id": POLICY.version,
        }
    )
    assert ReasonCode.DEADLINE_EXCEEDED not in decision.reason_codes
    assert decision.action is Action.REDACT
    assert decision.safe_text == "mail [EMAIL_ADDRESS]"
