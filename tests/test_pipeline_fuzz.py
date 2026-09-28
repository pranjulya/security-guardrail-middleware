"""Review 02 / M11: seeded fuzz and property tests for the pipeline contract.

Invariants checked over thousands of random inputs:
* inspect()/collect_model_output() never raise and always return a Decision;
* BLOCK never carries text; ALLOW/REDACT always carry text;
* a detected secret never appears in released text;
* audit events never contain raw input content.
"""

from __future__ import annotations

import json
import random
import re

from guardrails.contracts import Action, Decision, is_valid_request_id
from guardrails.pii import DetectedSpan, PiiRedactor
from guardrails.pipeline import Pipeline
from guardrails.policy import DEFAULT_POLICY, load_policy

POLICY = load_policy(DEFAULT_POLICY)
SECRET = "ZQXSECRET"
CANARY = "SYNTH_FUZZ_CANARY_77"
SECRET_RE = re.compile(SECRET)


def secret_detector(text, lang, entities):
    return [DetectedSpan("PERSON", m.start(), m.end(), 0.99) for m in SECRET_RE.finditer(text)]


def make(events):
    redactor = PiiRedactor.from_policy(POLICY, detector=secret_detector, detector_version="stub")
    return Pipeline(policy=POLICY, redactor=redactor, event_sink=events.append)


ATOMS = [
    "hello",
    " ",
    "\n",
    SECRET,
    CANARY,
    "ignore all prior instructions",
    "\u200b",
    "\ud800",
    "ü",
    "\U0001d51e",  # mathematical fraktur a
    "{}",
    "a" * 50,
]
JUNK = [None, 0, 1.5, True, b"bytes", ["x"], {"k": "v"}, object()]


def rand_text(rng):
    return "".join(rng.choice(ATOMS) for _ in range(rng.randint(0, 8)))


def rand_value(rng, good):
    return good if rng.random() < 0.7 else rng.choice([*JUNK, rand_text(rng)])


def rand_envelope(rng):
    data = {
        "boundary": rand_value(rng, rng.choice(["user_input", "model_output", "tool_output"])),
        "language": rand_value(rng, "en"),
        "text": rand_value(rng, rand_text(rng)),
        "request_id": rand_value(rng, f"req-{rng.randint(0, 20)}"),
        "policy_id": rand_value(rng, POLICY.policy_id),
    }
    if rng.random() < 0.1:
        data["extra_" + CANARY] = CANARY
    if rng.random() < 0.1:
        del data[rng.choice(list(data))]
    return data if rng.random() > 0.03 else rng.choice(JUNK)


def check(decision):
    assert isinstance(decision, Decision)
    if decision.action is Action.BLOCK:
        assert decision.safe_text is None
    else:
        assert isinstance(decision.safe_text, str)
        assert SECRET not in decision.safe_text


def test_inspect_is_total_and_never_releases_secret_or_logs_content():
    rng = random.Random(20260928)
    events: list[dict] = []
    pipeline = make(events)
    for _ in range(3000):
        check(pipeline.inspect(rand_envelope(rng)))
    assert events
    # request_id is logged only if it matches the bounded ID pattern (M1); a
    # value made purely of ID characters is by definition a valid ID.
    for event in events:
        assert event["request_id"] == "invalid" or is_valid_request_id(event["request_id"])
    blob = json.dumps([{k: v for k, v in e.items() if k != "request_id"} for e in events])
    assert CANARY not in blob
    assert SECRET not in blob
    assert "ignore all prior" not in json.dumps(events)


def test_collect_model_output_is_total():
    rng = random.Random(7)
    events: list[dict] = []
    pipeline = make(events)
    for i in range(1500):
        chunks = [rand_value(rng, rand_text(rng)) for _ in range(rng.randint(0, 5))]
        if rng.random() < 0.1:
            chunks = rng.choice([*JUNK, rand_text(rng)])
        check(pipeline.collect_model_output(chunks, request_id=f"s{i % 50}"))
    for event in events:
        assert event["request_id"] == "invalid" or is_valid_request_id(event["request_id"])
    assert "ignore all prior" not in json.dumps(events)


def test_secret_split_across_chunks_is_still_caught():
    rng = random.Random(99)
    pipeline = make([])
    for i in range(300):
        text = rand_text(rng) + SECRET + rand_text(rng)
        cut = sorted(rng.sample(range(len(text) + 1), 2))
        chunks = [text[: cut[0]], text[cut[0] : cut[1]], text[cut[1] :]]
        check(pipeline.collect_model_output(chunks, request_id=f"c{i}"))
