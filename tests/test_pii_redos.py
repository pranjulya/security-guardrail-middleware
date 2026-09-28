"""Review 02 / M3 follow-up: custom PII patterns stay linear on adversarial input.

The first version of the obfuscated-email pattern had an unbounded local part;
16 KiB of "a." took >3 s in the regex alone (8.5 s through Presidio), pushing
every such request to DEADLINE_EXCEEDED while burning a detector thread.
"""

from __future__ import annotations

import re
import time

import pytest

from guardrails import pii
from guardrails.contracts import Action
from guardrails.pii import PiiRedactor, normalized_with_map
from guardrails.policy import DEFAULT_POLICY, load_policy

UNITS = [
    "a.",
    "a@",
    "1.",
    "1-",
    "a-",
    "[at]",
    "a [at] b.",
    "a (dot) ",
    "sk-",
    "eyJ",
    "xoxb-",
    "ghp_",
    "AKIA",
    "4111 ",
    "0 ",
    "a:",
    "-----BEGIN ",
]
FLAGS = re.IGNORECASE | re.DOTALL | re.MULTILINE


def _payload(unit: str, n: int = 16384) -> str:
    text = unit * (n // len(unit) + 1)
    return text[:n]


PATTERNS = [
    ("card", pii._CARD_PATTERN, FLAGS),
    ("obfuscated-email", pii._OBFUSCATED_EMAIL_PATTERN, FLAGS),
    *[(name, rx, re.DOTALL | re.MULTILINE) for name, rx in pii._SECRET_PATTERNS],
]


@pytest.mark.parametrize(("name", "pattern", "flags"), PATTERNS, ids=[p[0] for p in PATTERNS])
def test_custom_patterns_are_linear_on_adversarial_16k(name, pattern, flags):
    compiled = re.compile(pattern, flags)
    worst = 0.0
    for unit in UNITS:
        text = _payload(unit)
        start = time.perf_counter()
        for _ in compiled.finditer(text):
            pass
        worst = max(worst, time.perf_counter() - start)
    assert worst < 0.25, (name, worst)


def test_obfuscated_email_still_matches_real_forms():
    compiled = re.compile(pii._OBFUSCATED_EMAIL_PATTERN, FLAGS)
    for text in (
        "jane.doe [at] example [dot] com",
        "jane.doe(at)example(dot)com",
        "a [ at ] b [dot] co",
        "ops {at} mail {dot} example {dot} org",
    ):
        assert compiled.search(text), text


def test_normalization_is_linear_at_the_cap():
    text = ("a\u200b\uff21" * 22000)[: pii.MAX_NORMALIZED_CHARS]
    start = time.perf_counter()
    view, index_map = normalized_with_map(text)
    assert time.perf_counter() - start < 0.5
    assert len(index_map) == len(view)


def test_dots_payload_end_to_end_is_fast_again():
    redactor = PiiRedactor.from_policy(load_policy(DEFAULT_POLICY))
    redactor.warm_up()
    text = _payload("a.")
    start = time.perf_counter()
    out, action, _ = redactor.redact(text)
    elapsed = time.perf_counter() - start
    assert action is Action.ALLOW and out == text
    assert elapsed < 1.5, elapsed  # was ~8.5 s with the unbounded pattern
