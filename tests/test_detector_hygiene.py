"""Review 02 / L5 + L6: detector version provenance and strict score handling."""

from __future__ import annotations

from importlib.metadata import version

import pytest

from guardrails.contracts import Action, ReasonCode
from guardrails.pii import DetectedSpan, DetectorFailure, PiiRedactor, presidio_detector_version
from guardrails.pipeline import Pipeline
from guardrails.policy import DEFAULT_POLICY, load_policy

POLICY = load_policy(DEFAULT_POLICY)


def test_detector_version_is_derived_from_installed_packages() -> None:
    expected = (
        f"presidio-analyzer=={version('presidio-analyzer')}"
        f"/en_core_web_lg=={version('en-core-web-lg')}"
    )
    assert presidio_detector_version() == expected
    assert PiiRedactor.from_policy(POLICY).detector_version == expected


def test_custom_detector_is_not_labelled_as_presidio() -> None:
    redactor = PiiRedactor.from_policy(POLICY, detector=lambda t, lang, e: [])
    assert redactor.detector_version == "custom"


@pytest.mark.parametrize(
    "score", [float("nan"), float("inf"), -float("inf"), -0.1, 1.5, "0.9", None, True]
)
def test_bad_scores_fail_closed(score: object) -> None:
    def detector(t, lang, e):
        return [DetectedSpan("PERSON", 0, 5, score)]  # type: ignore[arg-type]

    redactor = PiiRedactor.from_policy(POLICY, detector=detector)
    with pytest.raises(DetectorFailure):
        redactor.redact("Alice says hi")
    decision = Pipeline(policy=POLICY, redactor=redactor).inspect(
        {
            "boundary": "model_output",
            "language": "en",
            "text": "Alice says hi",
            "request_id": "r1",
            "policy_id": POLICY.policy_id,
        }
    )
    assert decision.action is Action.BLOCK
    assert decision.reason_codes == (ReasonCode.DETECTOR_ERROR,)
    assert decision.safe_text is None


@pytest.mark.parametrize(
    "bad", [object(), ("PERSON", 0, 5, 0.9), DetectedSpan("PERSON", True, 5, 0.9)]
)
def test_malformed_spans_fail_closed(bad: object) -> None:
    redactor = PiiRedactor.from_policy(POLICY, detector=lambda t, lang, e: [bad])
    with pytest.raises(DetectorFailure):
        redactor.redact("Alice says hi")


def test_valid_scores_at_the_boundaries() -> None:
    for score, expected in ((0.0, Action.ALLOW), (0.5, Action.REDACT), (1, Action.REDACT)):
        spans = [DetectedSpan("PERSON", 0, 5, score)]
        redactor = PiiRedactor.from_policy(
            POLICY, detector=lambda t, lang, e, _s=spans: _s if t.startswith("Alice") else []
        )
        assert redactor.redact("Alice says hi")[1] is expected


@pytest.mark.parametrize(
    "thresholds",
    [
        {},  # missing: used to default to 0.0 (every span passed)
        {"PERSON": 0.5},  # some missing
        {**dict(POLICY.thresholds), "IBAN_CODE": 0.5},  # extra entity
        {**dict(POLICY.thresholds), "PERSON": float("nan")},
        {**dict(POLICY.thresholds), "PERSON": True},
        {**dict(POLICY.thresholds), "PERSON": 1.01},
    ],
)
def test_threshold_configuration_errors(thresholds: dict) -> None:
    with pytest.raises(ValueError):
        PiiRedactor(entities=POLICY.entities, thresholds=thresholds)
