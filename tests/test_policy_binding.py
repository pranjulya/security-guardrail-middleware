"""Review 02 / M4: the policy snapshot is authoritative, immutable and digest-bound."""

from __future__ import annotations

import pytest

from guardrails.contracts import Action, ReasonCode
from guardrails.pii import DetectedSpan, PiiRedactor
from guardrails.pipeline import Pipeline
from guardrails.policy import DEFAULT_POLICY, PolicyError, load_policy

POLICY = load_policy(DEFAULT_POLICY)
CARD = "4111111111111111 is my card"


def card_detector(t, lang, entities):
    return [DetectedSpan("CREDIT_CARD", 0, 16, 1.0)] if t.startswith("4111") else []


def env(policy_id: str, text: str = CARD) -> dict:
    return {
        "boundary": "user_input",
        "language": "en",
        "text": text,
        "request_id": "r1",
        "policy_id": policy_id,
    }


def test_thresholds_cannot_be_mutated_after_load() -> None:
    snap = load_policy(DEFAULT_POLICY)
    digest = snap.digest
    with pytest.raises(TypeError):
        snap.thresholds["PERSON"] = 0.99  # type: ignore[index]
    assert snap.thresholds["PERSON"] == 0.5 and snap.digest == digest


def test_redactor_narrower_than_policy_is_refused() -> None:
    """Previously ALLOWed a card number while claiming policy v1.1."""
    narrow = PiiRedactor(entities=["PERSON"], thresholds={"PERSON": 0.5}, detector=card_detector)
    with pytest.raises(PolicyError):
        Pipeline(policy=POLICY, redactor=narrow)


def test_redactor_with_different_thresholds_is_refused() -> None:
    lax = PiiRedactor(
        entities=POLICY.entities,
        thresholds={**dict(POLICY.thresholds), "PERSON": 0.99},
        detector=card_detector,
    )
    with pytest.raises(PolicyError):
        Pipeline(policy=POLICY, redactor=lax)


def test_from_policy_builds_a_bound_pipeline() -> None:
    pipe = Pipeline.from_policy(POLICY, detector=card_detector)
    decision = pipe.inspect(env(POLICY.policy_id))
    assert decision.action is Action.REDACT
    assert decision.safe_text == "[CREDIT_CARD] is my card"
    assert decision.policy_id == POLICY.policy_id
    assert decision.to_public_dict()["policy_id"] == f"v1.1@{POLICY.digest[:16]}"


def test_policy_id_binds_the_digest() -> None:
    pipe = Pipeline.from_policy(POLICY, detector=card_detector)
    bare = pipe.inspect(env(POLICY.version))
    assert (bare.action, bare.reason_codes) == (Action.BLOCK, (ReasonCode.POLICY_INVALID,))
    drifted = load_policy({**DEFAULT_POLICY, "max_blocks": 3})  # same version, new content
    assert drifted.version == POLICY.version and drifted.policy_id != POLICY.policy_id
    stale = Pipeline.from_policy(drifted, detector=card_detector).inspect(env(POLICY.policy_id))
    assert stale.reason_codes == (ReasonCode.POLICY_INVALID,)


def test_events_carry_the_policy_id() -> None:
    events: list[dict] = []
    Pipeline.from_policy(POLICY, detector=card_detector, event_sink=events.append).inspect(
        env(POLICY.policy_id)
    )
    assert events[0]["policy_id"] == POLICY.policy_id
