"""Review 02 / M6: the inspection deadline covers stream collection and is
enforced pre-emptively while the PII detector runs."""

from __future__ import annotations

import threading
import time

import pytest

from guardrails.contracts import Action, ReasonCode
from guardrails.pii import PiiRedactor
from guardrails.pipeline import DETECTOR_RUNNER, DetectorRunner, Pipeline
from guardrails.policy import DEFAULT_POLICY, load_policy

POLICY = load_policy(DEFAULT_POLICY)  # inspection_budget_ms = 2000
FAST = load_policy({**DEFAULT_POLICY, "inspection_budget_ms": 300})


def make(detector=None, policy=POLICY, **kw) -> Pipeline:
    redactor = PiiRedactor.from_policy(
        policy, detector=detector or (lambda t, lang, e: []), detector_version="stub"
    )
    return Pipeline(policy=policy, redactor=redactor, **kw)


def env(text="hello", rid="r1", policy=POLICY):
    return {
        "boundary": "user_input",
        "language": "en",
        "text": text,
        "request_id": rid,
        "policy_id": policy.policy_id,
    }


def slow_stream(n: int, delay: float):
    for i in range(n):
        time.sleep(delay)
        yield f"chunk {i} "


def test_slow_stream_over_budget_is_blocked_during_collection():
    events = []
    pipeline = make(event_sink=events.append)
    t0 = time.monotonic()
    decision = pipeline.collect_model_output(slow_stream(6, 0.5), request_id="s1")
    wall = time.monotonic() - t0
    assert decision.action is Action.BLOCK
    assert decision.reason_codes == (ReasonCode.DEADLINE_EXCEEDED,)
    assert decision.safe_text is None
    assert decision.elapsed_ms > POLICY.inspection_budget_ms
    # Stopped at the first chunk past the budget, not after the whole stream.
    assert wall < 2.9, wall
    assert events[-1]["reason_codes"] == ["DEADLINE_EXCEEDED"]


def test_poc_slow_stream_3s_against_2s_budget_blocks():
    pipeline = make()
    decision = pipeline.collect_model_output(slow_stream(3, 1.0), request_id="s2")
    assert decision.action is Action.BLOCK
    assert decision.reason_codes == (ReasonCode.DEADLINE_EXCEEDED,)


def test_collection_time_is_included_in_elapsed_and_budget():
    pipeline = make()
    decision = pipeline.collect_model_output(slow_stream(2, 0.3), request_id="s3")
    assert decision.action is Action.ALLOW
    assert decision.elapsed_ms >= 550  # was 0 before the fix
    # The time was charged to the request: a follow-up block has less budget.
    with pipeline._states_lock:
        remaining = pipeline._states["s3"].remaining_ms
    assert remaining <= POLICY.inspection_budget_ms - 550


def test_budget_exhausted_by_stream_blocks_later_blocks_of_same_request():
    pipeline = make(policy=FAST)
    first = pipeline.collect_model_output(slow_stream(3, 0.2), request_id="s4")
    assert first.reason_codes == (ReasonCode.DEADLINE_EXCEEDED,)
    later = pipeline.inspect(env(rid="s4", policy=FAST))
    assert later.action is Action.BLOCK
    assert later.reason_codes == (ReasonCode.DEADLINE_EXCEEDED,)


def test_hung_detector_is_cut_off_at_the_deadline_without_late_release():
    release = threading.Event()
    finished = threading.Event()

    def hung(t, lang, e):
        release.wait(10)
        finished.set()
        return []

    runner = DetectorRunner(max_threads=2)
    pipeline = make(hung, policy=FAST, detector_runner=runner)
    t0 = time.monotonic()
    decision = pipeline.inspect(env("benign text", policy=FAST))
    wall = time.monotonic() - t0
    assert decision.action is Action.BLOCK
    assert decision.reason_codes == (ReasonCode.DEADLINE_EXCEEDED,)
    assert decision.safe_text is None
    assert wall < 1.5, wall  # budget is 0.3 s; detector would take 10 s
    assert runner.timeouts == 1
    # Letting the abandoned detector finish changes nothing and frees its slot.
    release.set()
    assert finished.wait(5)
    time.sleep(0.05)
    assert runner._slots.acquire(blocking=False)
    runner._slots.release()


def test_saturated_runner_fails_closed_with_detector_error():
    release = threading.Event()

    def hung(t, lang, e):
        release.wait(10)
        return []

    runner = DetectorRunner(max_threads=1)
    try:
        first = make(hung, policy=FAST, detector_runner=runner).inspect(
            env("a", rid="a", policy=FAST)
        )
        assert first.reason_codes == (ReasonCode.DEADLINE_EXCEEDED,)
        second = make(lambda t, lang, e: [], policy=FAST, detector_runner=runner).inspect(
            env("b", rid="b", policy=FAST)
        )
        assert second.action is Action.BLOCK
        assert second.reason_codes == (ReasonCode.DETECTOR_ERROR,)
        assert runner.saturated == 1
    finally:
        release.set()


def test_detector_exception_in_worker_still_maps_to_detector_error():
    def boom(t, lang, e):
        raise RuntimeError("detector crashed")

    decision = make(boom).inspect(env())
    assert decision.action is Action.BLOCK
    assert decision.reason_codes == (ReasonCode.DETECTOR_ERROR,)


def test_redaction_result_is_unchanged_through_the_runner():
    def finds_email(t, lang, e):
        from guardrails.pii import DetectedSpan

        i = t.find("a@b.co")
        if i < 0:  # residual re-scan of the redacted text
            return []
        return [DetectedSpan("EMAIL_ADDRESS", i, i + 6, 0.99)]

    decision = make(finds_email).inspect(env("mail a@b.co now"))
    assert decision.action is Action.REDACT
    assert "a@b.co" not in decision.safe_text


def test_cooperative_mode_still_blocks_after_a_slow_detector():
    def slow(t, lang, e):
        time.sleep(0.5)
        return []

    decision = make(slow, policy=FAST, preemptive_deadline=False).inspect(env(policy=FAST))
    assert decision.action is Action.BLOCK
    assert decision.reason_codes == (ReasonCode.DEADLINE_EXCEEDED,)


def test_back_to_back_calls_never_spuriously_saturate():
    runner = DetectorRunner(max_threads=1)
    pipeline = make(detector_runner=runner)
    for i in range(50):
        assert pipeline.inspect(env(f"t{i}", rid=f"r{i}")).action is Action.ALLOW
    assert runner.saturated == 0


def test_default_runner_is_shared_and_bounded():
    assert make().detector_runner is None  # uses the process-wide runner
    assert DETECTOR_RUNNER.max_threads >= 8  # >= HTTP max_concurrent default
    with pytest.raises(ValueError):
        DetectorRunner(max_threads=0)
