"""Review 02 / M3: obfuscated PII is detected on a normalised view (live Presidio)."""

from __future__ import annotations

import pytest

from guardrails.contracts import Action
from guardrails.pii import (
    MAX_NORMALIZED_CHARS,
    DetectedSpan,
    DetectorFailure,
    PiiRedactor,
    normalized_with_map,
)
from guardrails.policy import DEFAULT_POLICY, load_policy

POLICY = load_policy(DEFAULT_POLICY)
LIVE = PiiRedactor.from_policy(POLICY)

OBFUSCATED = {
    "email [at]/[dot]": ("mail jane.doe [at] example [dot] com", "jane.doe"),
    "email (at)/(dot)": ("reach me: bob.smith (at) example (dot) org", "bob.smith"),
    "email with ZWSP": ("jane.doe\u200b@example.com", "jane.doe"),
    "email full-width at": ("jane.doe\uff20example.com", "jane.doe"),
    "card with ZWSP": ("4111\u200b1111\u200b1111\u200b1111", "1111"),
    "card with soft hyphens": ("4111\u00ad1111\u00ad1111\u00ad1111", "1111"),
    "card full-width digits": ("\uff14\uff11\uff11\uff11" + "\uff11" * 12, "\uff11\uff11"),
    "card dotted": ("4111.1111.1111.1111", "1111"),
    "card slashes": ("pay with 4111/1111/1111/1111 today", "1111"),
    "card split across lines": ("4111 1111\n1111 1111", "1111"),
}


@pytest.mark.parametrize("name", sorted(OBFUSCATED))
def test_obfuscated_forms_are_redacted(name: str) -> None:
    text, fragment = OBFUSCATED[name]
    out, action, _ = LIVE.redact(text)
    assert action is Action.REDACT, name
    assert fragment not in out, (name, out)


@pytest.mark.parametrize(
    "text",
    [
        "Version 1.2.3.4 released",
        "IP 192.168.1.1 blocked",
        "Order 1234.5678.9012.3456 shipped",  # not Luhn-valid
        "Build 4111.1111.1111.1112",  # not Luhn-valid
        "Dates 2026/09/28 and 2026-09-28",
        "look at google dot com",
        "me [at] localhost",
        "ISBN 978-3-16-148410-0",
    ],
)
def test_separator_tolerance_does_not_add_false_positives(text: str) -> None:
    assert LIVE.redact(text) == (text, Action.ALLOW, ())


def test_offsets_map_back_to_the_original_text() -> None:
    text = "hi \ufdfa jane\u200b.doe@example.com bye"
    view, _index_map = normalized_with_map(text)
    assert "\u200b" not in view and "jane.doe@example.com" in view
    start = view.index("jane.doe@example.com")
    end = start + len("jane.doe@example.com")

    def detector(t, lang, e):
        return [DetectedSpan("EMAIL_ADDRESS", start, end, 1.0)] if t == view else []

    out, action, _ = PiiRedactor.from_policy(POLICY, detector=detector).redact(text)
    assert action is Action.REDACT
    assert out == "hi \ufdfa [EMAIL_ADDRESS] bye"


def test_ascii_fast_path_is_identity() -> None:
    view, index_map = normalized_with_map("plain ascii")
    assert view == "plain ascii" and index_map == list(range(11))


def test_normalisation_expansion_beyond_cap_fails_closed() -> None:
    text = "\ufdfa" * (MAX_NORMALIZED_CHARS // 18 + 1)
    with pytest.raises(DetectorFailure):
        PiiRedactor.from_policy(POLICY, detector=lambda t, lang, e: []).redact(text)


OPT_IN = {
    "US_SSN": "my SSN is 536-22-1234 thanks",
    "IBAN_CODE": "IBAN GB82WEST12345698765432",
    "SECRET_TOKEN": "key sk_live_51H8abcdEFGHijkLMNopqrs",
}


def test_opt_in_entities_are_redacted_when_enabled() -> None:
    policy = load_policy(
        {
            **DEFAULT_POLICY,
            "version": "v1.1-optin",
            "entities": [*DEFAULT_POLICY["entities"], *OPT_IN],
            "thresholds": {**DEFAULT_POLICY["thresholds"], **dict.fromkeys(OPT_IN, 0.5)},
        }
    )
    redactor = PiiRedactor.from_policy(policy)
    for entity, text in OPT_IN.items():
        out, action, _ = redactor.redact(text)
        assert action is Action.REDACT, entity
        assert f"[{entity}]" in out, (entity, out)


@pytest.mark.parametrize(
    "secret",
    [
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_" + "a" * 36,
        "xoxb-1234567890-abcdefghij",
        "AIza" + "b" * 35,
        "-----BEGIN RSA PRIVATE KEY-----",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.c2lnbmF0dXJlLXZhbHVl",
    ],
)
def test_secret_token_formats(secret: str) -> None:
    policy = load_policy(
        {
            **DEFAULT_POLICY,
            "version": "v1.1-secrets",
            "entities": [*DEFAULT_POLICY["entities"], "SECRET_TOKEN"],
            "thresholds": {**DEFAULT_POLICY["thresholds"], "SECRET_TOKEN": 0.5},
        }
    )
    out, action, _ = PiiRedactor.from_policy(policy).redact(
        f"The credential is {secret} and it must be rotated."
    )
    assert action is Action.REDACT and secret not in out, out


def test_default_policy_scope_is_unchanged() -> None:
    assert POLICY.version == "v1.1"
    assert set(POLICY.entities) == {"EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "PERSON"}
    for entity, text in OPT_IN.items():  # documented: opt-in only
        assert f"[{entity}]" not in LIVE.redact(text)[0]
