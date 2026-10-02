"""Review 02 / C1: property regression for overlapping-span union redaction.

Every character covered by any detected span must be removed from the output and
every uncovered character must survive in order. Digits are used for the source
text because redaction labels never contain digits, so any surviving digit is
either an uncovered character or a leak.
"""

from __future__ import annotations

import random

import pytest

from guardrails.pii import REDACTION_LABELS, DetectedSpan, PiiRedactor, _replace_union

ENTITIES = sorted(REDACTION_LABELS)


def _random_case(rng: random.Random) -> tuple[str, list[DetectedSpan]]:
    n = rng.randint(1, 48)
    text = "".join(rng.choice("0123456789") for _ in range(n))
    spans = []
    for _ in range(rng.randint(1, 6)):
        start = rng.randint(0, n - 1)
        end = rng.randint(start + 1, n)
        spans.append(DetectedSpan(rng.choice(ENTITIES), start, end, 1.0))
    return text, spans


def _expected_kept(text: str, spans: list[DetectedSpan]) -> str:
    covered = [False] * len(text)
    for s in spans:
        for i in range(s.start, s.end):
            covered[i] = True
    return "".join(c for c, cov in zip(text, covered, strict=True) if not cov)


@pytest.mark.parametrize("seed", range(8))
def test_union_redaction_never_leaks_covered_characters(seed: int) -> None:
    rng = random.Random(seed)
    for _ in range(2500):
        text, spans = _random_case(rng)
        out = _replace_union(text, spans)
        kept = "".join(ch for ch in out if ch.isdigit())
        assert kept == _expected_kept(text, spans), (text, spans, out)
        # Only well-formed labels may appear between kept characters.
        residue = "".join(ch for ch in out if not ch.isdigit())
        for label in REDACTION_LABELS.values():
            residue = residue.replace(label, "")
        assert residue == ""


def test_known_pre_review01_leak_case_stays_fixed() -> None:
    text = "096825067104832385197837805856"
    spans = [
        DetectedSpan("EMAIL_ADDRESS", 6, 28, 1.0),
        DetectedSpan("CREDIT_CARD", 12, 29, 1.0),
        DetectedSpan("PHONE_NUMBER", 23, 28, 1.0),
        DetectedSpan("PHONE_NUMBER", 20, 21, 1.0),
    ]
    assert _replace_union(text, spans) == "096825[CREDIT_CARD]6"


def test_redactor_end_to_end_property_with_stub_detector() -> None:
    rng = random.Random(1234)
    for _ in range(500):
        text, spans = _random_case(rng)

        def detector(t, lang, entities, _text=text, _spans=spans):
            return list(_spans) if t == _text else []

        out, _, _ = PiiRedactor(
            entities=ENTITIES, thresholds=dict.fromkeys(ENTITIES, 0.0), detector=detector
        ).redact(text)
        kept = "".join(ch for ch in out if ch.isdigit())
        assert kept == _expected_kept(text, spans)
