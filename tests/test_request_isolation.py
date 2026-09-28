"""Review 02 / H4: per-request state isolation, thread safety, attribution."""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from guardrails.contracts import Action, ReasonCode
from guardrails.pii import PiiRedactor
from guardrails.pipeline import Pipeline
from guardrails.policy import DEFAULT_POLICY, load_policy

POLICY = load_policy(DEFAULT_POLICY)


def make(detector=None, policy=POLICY, **kw) -> Pipeline:
    redactor = PiiRedactor(
        entities=policy.entities,
        detector=detector or (lambda t, lang, e: []),
        detector_version="stub",
    )
    return Pipeline(policy=policy, redactor=redactor, **kw)


def env(request_id: str, text: str = "hello", policy=POLICY):
    return {
        "boundary": "user_input",
        "language": "en",
        "text": text,
        "request_id": request_id,
        "policy_id": policy.version,
    }


def test_interleaved_request_ids_do_not_reset_each_others_budget():
    pipeline = make()
    results = {"A": [], "B": []}
    for i in range(12):
        rid = "A" if i % 2 == 0 else "B"
        results[rid].append(pipeline.inspect(env(rid, f"t{i}")))
    for rid, decisions in results.items():
        actions = [d.action for d in decisions]
        assert actions[:4] == [Action.ALLOW] * 4, rid
        assert all(d.reason_codes == (ReasonCode.LIMIT_EXCEEDED,) for d in decisions[4:]), rid


def test_concurrent_requests_do_not_share_deadline_budget():
    policy = load_policy({**DEFAULT_POLICY, "inspection_budget_ms": 300})

    def slow(t, lang, e):
        time.sleep(0.2)
        return []

    pipeline = make(slow, policy=policy)
    out = {}

    def run(rid):
        out[rid] = pipeline.inspect(env(rid, policy=policy))

    a = threading.Thread(target=run, args=("A",))
    b = threading.Thread(target=run, args=("B",))
    a.start()
    time.sleep(0.05)
    b.start()
    a.join()
    b.join()
    assert out["A"].action is Action.ALLOW
    assert out["B"].action is Action.ALLOW, out["B"].reason_codes


def test_same_request_id_budget_is_atomic_under_concurrency():
    def slowish(t, lang, e):
        time.sleep(0.01)
        return []

    pipeline = make(slowish)
    with ThreadPoolExecutor(16) as pool:
        decisions = list(pool.map(lambda i: pipeline.inspect(env("shared", f"x{i}")), range(32)))
    allowed = [d for d in decisions if d.action is Action.ALLOW]
    assert len(allowed) == POLICY.max_blocks
    assert pipeline.request_usage("shared")[0] == POLICY.max_blocks


def test_many_threads_many_requests_each_get_full_budget():
    pipeline = make(lambda t, lang, e: [])

    def worker(rid):
        return [pipeline.inspect(env(rid, f"{rid}-{i}")).action for i in range(5)]

    with ThreadPoolExecutor(16) as pool:
        results = list(pool.map(worker, [f"req-{i}" for i in range(64)]))
    for actions in results:
        assert actions == [Action.ALLOW] * 4 + [Action.BLOCK]


def test_model_output_attributed_and_charged_to_explicit_request():
    events: list[dict] = []
    pipeline = make(event_sink=events.append)
    pipeline.inspect(env("alice-req"))
    pipeline.inspect(env("bob-req"))
    decision = pipeline.collect_model_output(["model output for alice"], request_id="alice-req")
    assert decision.action is Action.ALLOW
    assert events[-1]["request_id"] == "alice-req"
    assert pipeline.request_usage("alice-req")[0] == 2
    assert pipeline.request_usage("bob-req")[0] == 1


def test_model_output_respects_that_requests_aggregate_bytes():
    policy = load_policy({**DEFAULT_POLICY, "max_aggregate_bytes": 1000})
    pipeline = make(policy=policy)
    assert pipeline.inspect(env("big", "a" * 900, policy=policy)).action is Action.ALLOW
    over = pipeline.collect_model_output(["b" * 200], request_id="big")
    assert over.reason_codes == (ReasonCode.LIMIT_EXCEEDED,)
    ok = pipeline.collect_model_output(["b" * 200], request_id="other")
    assert ok.action is Action.ALLOW


def test_end_request_and_bounded_tracking():
    pipeline = make(max_tracked_requests=3)
    for rid in ("r1", "r2", "r3", "r4"):
        pipeline.inspect(env(rid))
    assert pipeline.tracked_requests == 3
    assert pipeline.request_usage("r1") == (0, 0)  # evicted (LRU)
    pipeline.end_request("r4")
    assert pipeline.tracked_requests == 2
