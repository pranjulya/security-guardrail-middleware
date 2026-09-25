"""Phase 02 PII tests: golden replacements, overlaps, failures."""

import pytest

from guardrails.contracts import Action, ReasonCode
from guardrails.pii import DetectedSpan, DetectorFailure, PiiRedactor
from guardrails.policy import DEFAULT_POLICY, load_policy

POLICY = load_policy(DEFAULT_POLICY)

EMAIL_THRESHOLD = POLICY.thresholds["EMAIL_ADDRESS"]
PHONE_THRESHOLD = POLICY.thresholds["PHONE_NUMBER"]
CARD_THRESHOLD = POLICY.thresholds["CREDIT_CARD"]
PERSON_THRESHOLD = POLICY.thresholds["PERSON"]


def redactor(detector, thresholds=None):
    return PiiRedactor(
        entities=sorted(POLICY.entities),
        thresholds=thresholds or dict(POLICY.thresholds),
        detector=detector,
        detector_version="test",
    )


def span(entity, start, end, score=1.0):
    return DetectedSpan(entity_type=entity, start=start, end=end, score=score)


def test_email_golden_replacement():
    text = "Contact jane.doe@example.com today"
    email = "jane.doe@example.com"
    start = text.index(email)
    end = start + len(email)

    def detector(t, lang, entities):
        if t != text:
            return []
        assert lang == "en"
        return [span("EMAIL_ADDRESS", start, end, 1.0)]

    out, action, reasons = redactor(detector).redact(text)
    assert out == "Contact [EMAIL_ADDRESS] today"
    assert action is Action.REDACT
    assert reasons == (ReasonCode.PII_REDACTED,)


def test_phone_card_person_golden():
    cases = [
        ("Call 415-555-0132 now", "415-555-0132", "[PHONE_NUMBER]"),
        ("Card 4111 1111 1111 1111 ok", "4111 1111 1111 1111", "[CREDIT_CARD]"),
        ("Alice Johnson filed it", "Alice Johnson", "[PERSON]"),
    ]
    entity_for = {
        "[PHONE_NUMBER]": "PHONE_NUMBER",
        "[CREDIT_CARD]": "CREDIT_CARD",
        "[PERSON]": "PERSON",
    }
    for text, value, label in cases:
        start = text.index(value)
        end = start + len(value)
        entity = entity_for[label]

        def detector(t, lang, entities, _s=start, _e=end, _en=entity, _v=value):
            if _v not in t:
                return []
            return [span(_en, _s, _e, 1.0)]

        out, action, _ = redactor(detector).redact(text)
        assert out == text[:start] + label + text[end:]
        assert action is Action.REDACT


def test_unicode_offsets_use_original_text():
    text = "Élise Martin lives here"
    name = "Élise Martin"
    start = text.index(name)
    end = start + len(name)

    def detector(t, lang, entities):
        if t != text:
            return []
        return [span("PERSON", start, end, 0.9)]

    out, action, _ = redactor(detector).redact(text)
    assert out == "[PERSON] lives here"
    assert name not in out


def test_overlapping_spans_union_no_fragments():
    text = "Contact jane.doe@example.com today"

    def detector(t, lang, entities):
        if "jane.doe" not in t:
            return []
        return [
            span("PERSON", 8, 16, 0.9),
            span("EMAIL_ADDRESS", 8, 28, 1.0),
        ]

    out, action, _ = redactor(detector).redact(text)
    assert out == "Contact [EMAIL_ADDRESS] today"
    assert "jane.doe" not in out
    assert "example.com" not in out


def test_precedence_credit_card_over_email():
    text = "4111@example.com paid"

    def detector(t, lang, entities):
        if "[CREDIT_CARD]" in t or "[EMAIL_ADDRESS]" in t:
            return []
        return [
            span("EMAIL_ADDRESS", 0, 16, 1.0),
            span("CREDIT_CARD", 0, 16, 1.0),
        ]

    out, _, _ = redactor(detector).redact(text)
    assert out == "[CREDIT_CARD] paid"


def test_adjacent_non_overlapping_stay_separate():
    text = "a@b.co 415-555-0132"

    def detector(t, lang, entities):
        if "[EMAIL_ADDRESS]" in t or "[PHONE_NUMBER]" in t:
            return []
        return [
            span("EMAIL_ADDRESS", 0, 6, 1.0),
            span("PHONE_NUMBER", 7, 19, 0.9),
        ]

    out, _, _ = redactor(detector).redact(text)
    assert out == "[EMAIL_ADDRESS] [PHONE_NUMBER]"


def test_no_match_allows():
    out, action, reasons = redactor(lambda t, l, e: []).redact("plain benign text")
    assert (out, action, reasons) == ("plain benign text", Action.ALLOW, ())


def test_below_threshold_ignored():
    def detector(t, lang, entities):
        return [span("PERSON", 0, 5, PERSON_THRESHOLD - 0.1)]

    out, action, _ = redactor(detector).redact("Alice went home")
    assert action is Action.ALLOW


def test_unsupported_category_filtered():
    def detector(t, lang, entities):
        return [span("DATE_TIME", 0, 5, 1.0)]

    out, action, _ = redactor(detector).redact("Alice went home")
    assert action is Action.ALLOW


def test_detector_exception_blocks():
    def detector(t, lang, entities):
        raise RuntimeError("synthetic outage")

    with pytest.raises(DetectorFailure):
        redactor(detector).redact("some text")


def test_invalid_span_blocks():
    def detector(t, lang, entities):
        return [span("PERSON", 10, 5, 1.0)]

    with pytest.raises(DetectorFailure):
        redactor(detector).redact("short")


def test_residual_pii_blocks_with_no_text():
    calls = {"n": 0}

    def detector(t, lang, entities):
        calls["n"] += 1
        if calls["n"] == 1:
            return [span("EMAIL_ADDRESS", 8, 14, 1.0)]
        return [span("EMAIL_ADDRESS", 0, 6, 1.0)]

    out, action, reasons = redactor(detector).redact("Contact a@b.co ok")
    assert out == ""
    assert action is Action.BLOCK
    assert reasons == (ReasonCode.RESIDUAL_PII,)


def test_multiple_separate_replacements():
    text = "aa bb cc"

    def detector(t, lang, entities):
        if "[PERSON]" in t:
            return []
        return [span("PERSON", 0, 2, 1.0), span("PERSON", 6, 8, 1.0)]

    out, _, _ = redactor(detector).redact(text)
    assert out == "[PERSON] bb [PERSON]"


def test_real_presidio_email_and_card_redact():
    from guardrails.pii import _presidio_detector

    r = PiiRedactor(
        entities=sorted(POLICY.entities),
        thresholds={"EMAIL_ADDRESS": 0.5, "PHONE_NUMBER": 0.5, "CREDIT_CARD": 0.5, "PERSON": 0.99},
        detector=_presidio_detector,
    )
    out, action, _ = r.redact("Contact jane.doe@example.com today")
    assert out == "Contact [EMAIL_ADDRESS] today"
    assert action is Action.REDACT
    out, action, _ = r.redact("Card 4111 1111 1111 1111 ok")
    assert out == "Card [CREDIT_CARD] ok"
    assert action is Action.REDACT


def test_nested_spans_union_with_stale_index_guard():
    text = "0000000000xxxx"

    def detector(t, lang, entities):
        if "[CREDIT_CARD]" in t:
            return []
        return [
            span("CREDIT_CARD", 0, 10, 1.0),
            span("PERSON", 1, 2, 0.9),
            span("PERSON", 3, 4, 0.9),
        ]

    out, action, _ = redactor(detector).redact(text)
    assert out == "[CREDIT_CARD]xxxx"
    assert "0000000000" not in out
    assert action is Action.REDACT


def test_adjacent_spans_stay_separate_with_own_labels():
    text = "a@b.co415-555-0132"

    def detector(t, lang, entities):
        if "[" in t:
            return []
        return [span("EMAIL_ADDRESS", 0, 6, 1.0), span("PHONE_NUMBER", 6, 18, 0.9)]

    out, action, _ = redactor(detector).redact(text)
    assert out == "[EMAIL_ADDRESS][PHONE_NUMBER]"
    assert action is Action.REDACT


def test_presidio_engine_cached_across_calls():
    from guardrails.pii import _get_engine

    first = _get_engine()
    second = _get_engine()
    assert first is second
