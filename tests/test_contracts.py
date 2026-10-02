"""Phase 01 contract tests: limits, malformed fields, policy, privacy."""

import json

import pytest

from guardrails.audit import build_event
from guardrails.contracts import (
    MAX_AGGREGATE_BYTES,
    MAX_BLOCKS,
    MAX_TEXT_BYTES,
    Action,
    Boundary,
    Decision,
    EnvelopeError,
    ReasonCode,
    RequestBudget,
    validate_envelope,
)
from guardrails.policy import DEFAULT_POLICY, PolicyError, load_policy

CANARY = "SYNTH_CANARY_9f8e7d6c5b4a"

VALID_POLICY = load_policy(DEFAULT_POLICY)


def envelope(**overrides):
    data = {
        "boundary": "user_input",
        "language": "en",
        "text": "hello world",
        "request_id": "req-1",
        "policy_id": "v1",
    }
    data.update(overrides)
    return data


def test_valid_envelope_passes():
    env = validate_envelope(envelope(), VALID_POLICY)
    assert env.boundary is Boundary.USER_INPUT
    assert env.text_byte_len == len("hello world".encode("utf-8"))


def test_unknown_boundary_rejected():
    with pytest.raises(EnvelopeError) as exc:
        validate_envelope(envelope(boundary="side_channel"), VALID_POLICY)
    assert exc.value.reason is ReasonCode.INVALID_ENVELOPE


def test_unsupported_language_rejected():
    with pytest.raises(EnvelopeError) as exc:
        validate_envelope(envelope(language="fr"), VALID_POLICY)
    assert exc.value.reason is ReasonCode.UNSUPPORTED_LANGUAGE


def test_empty_and_whitespace_text_rejected():
    for text in ("", "   ", "\n\t "):
        with pytest.raises(EnvelopeError) as exc:
            validate_envelope(envelope(text=text), VALID_POLICY)
        assert exc.value.reason is ReasonCode.INVALID_ENVELOPE


def test_non_string_and_missing_fields_rejected():
    for data in (
        envelope(text=123),
        envelope(request_id=""),
        envelope(policy_id=None),
        "not-a-mapping",
        None,
    ):
        with pytest.raises(EnvelopeError) as exc:
            validate_envelope(data, VALID_POLICY)
        assert exc.value.reason is ReasonCode.INVALID_ENVELOPE


def test_size_cap_at_limit_and_plus_one():
    ok_text = "a" * MAX_TEXT_BYTES
    assert validate_envelope(envelope(text=ok_text), VALID_POLICY).text_byte_len == MAX_TEXT_BYTES
    with pytest.raises(EnvelopeError) as exc:
        validate_envelope(envelope(text=ok_text + "a"), VALID_POLICY)
    assert exc.value.reason is ReasonCode.LIMIT_EXCEEDED


def test_multibyte_size_counts_bytes_not_chars():
    char = "\u00e9"
    per_char = len(char.encode("utf-8"))
    ok_text = char * (MAX_TEXT_BYTES // per_char)
    assert validate_envelope(envelope(text=ok_text), VALID_POLICY).text_byte_len == MAX_TEXT_BYTES
    with pytest.raises(EnvelopeError) as exc:
        validate_envelope(envelope(text=ok_text + char), VALID_POLICY)
    assert exc.value.reason is ReasonCode.LIMIT_EXCEEDED


def test_aggregate_budget_enforced():
    budget = RequestBudget()
    per_block = MAX_AGGREGATE_BYTES // MAX_BLOCKS
    for _ in range(MAX_BLOCKS):
        budget.consume(per_block)
    with pytest.raises(EnvelopeError) as exc:
        budget.consume(1)
    assert exc.value.reason is ReasonCode.LIMIT_EXCEEDED
    overflow = RequestBudget()
    with pytest.raises(EnvelopeError):
        overflow.consume(MAX_AGGREGATE_BYTES + 1)


def test_policy_rejects_unknown_keys_and_weakened_rules():
    with pytest.raises(PolicyError):
        load_policy({**DEFAULT_POLICY, "extra": True})
    with pytest.raises(PolicyError):
        load_policy({**DEFAULT_POLICY, "rules": [{"id": "block-direct-override", "action": "BLOCK"}]})
    with pytest.raises(PolicyError):
        load_policy({**DEFAULT_POLICY, "max_text_bytes": MAX_TEXT_BYTES + 1})
    with pytest.raises(PolicyError):
        load_policy({**DEFAULT_POLICY, "max_blocks": MAX_BLOCKS + 1})
    with pytest.raises(PolicyError):
        load_policy({**DEFAULT_POLICY, "entities": ["EMAIL_ADDRESS", "NATIONAL_ID"]})
    with pytest.raises(PolicyError):
        load_policy("not-a-mapping")


def test_policy_snapshot_immutable_and_versioned():
    first = load_policy(DEFAULT_POLICY)
    second = load_policy(DEFAULT_POLICY)
    assert first.digest == second.digest
    assert first.version == "v1.1"
    with pytest.raises(AttributeError):
        first.version = "v2"


def test_event_serializer_allowlisted_and_canary_free(caplog):
    import logging

    event = build_event(
        request_id="req-1",
        boundary=Boundary.USER_INPUT,
        action=Action.BLOCK,
        reason_codes=[ReasonCode.LIMIT_EXCEEDED],
        policy_version="v1",
        detector_versions={},
        elapsed_ms=3,
        text_byte_len=10,
    )
    payload = json.loads(event.serialize())
    assert set(payload) <= {
        "request_id",
        "boundary",
        "action",
        "reason_codes",
        "rule_ids",
        "policy_version",
        "detector_versions",
        "elapsed_ms",
        "byte_bucket",
    }
    with caplog.at_level(logging.INFO):
        logging.getLogger("guardrails").info(event.serialize())
    assert CANARY not in caplog.text


def test_envelope_error_never_echoes_payload():
    secret = "secret-" + CANARY
    try:
        validate_envelope(envelope(text=secret, language="fr"), VALID_POLICY)
    except EnvelopeError as exc:
        assert CANARY not in str(exc)
        assert exc.reason is ReasonCode.UNSUPPORTED_LANGUAGE


def test_repr_never_contains_text():
    decision = Decision(
        action=Action.ALLOW,
        reason_codes=(),
        policy_version="v1.1",
        safe_text=CANARY,
    )
    assert CANARY not in repr(decision)
    assert CANARY not in str(decision)
    env = validate_envelope(envelope(text=CANARY), VALID_POLICY)
    assert CANARY not in repr(env)
