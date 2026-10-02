"""Presidio integration and original-text span replacement."""

from __future__ import annotations

import logging
import math
import re
import threading
import unicodedata
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .contracts import Action, ReasonCode

ENTITY_PRECEDENCE = (
    "SECRET_TOKEN",
    "CREDIT_CARD",
    "IBAN_CODE",
    "US_SSN",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "PERSON",
)

REDACTION_LABELS = {entity: f"[{entity}]" for entity in ENTITY_PRECEDENCE}

# Detection runs on a normalised view (NFKC, format characters removed). NFKC
# can expand a code point up to 18x; beyond this the input is refused.
MAX_NORMALIZED_CHARS = 64 * 1024

# Card numbers with any common separator (review 02, M3): space, tab, CR/LF,
# dot, dash, slash, underscore; Luhn-validated by the card recognizer.
_CARD_SEPARATORS = (" ", "\t", "\r", "\n", ".", "-", "/", "_")
_CARD_PATTERN = r"(?<![\w.])(?:\d[ \t\r\n./_-]{0,2}){12,18}\d(?!\w)"
_SP = r"[ \t]{0,3}"  # bounded horizontal whitespace
_BRACKETS = ((r"\[", r"\]"), (r"\(", r"\)"), (r"\{", r"\}"), ("<", ">"))
_AT = _SP + "(?:" + "|".join(o + _SP + "at" + _SP + c for o, c in _BRACKETS) + ")" + _SP
_DOT = _SP + "(?:" + "|".join(o + _SP + "dot" + _SP + c for o, c in _BRACKETS) + r"|\." + ")" + _SP
# Every quantifier is bounded (RFC 5321 local part <= 64, label <= 63, <= 10
# labels) so the pattern stays linear on adversarial input such as
# "a.a.a...": an unbounded local part made 16 KiB of "a." take >3 s (ReDoS).
_OBFUSCATED_EMAIL_PATTERN = (
    r"\b[A-Za-z0-9._%+-]{1,64}"
    + _AT
    + r"[A-Za-z0-9-]{1,63}(?:"
    + _DOT
    + r"[A-Za-z0-9-]{1,63}){1,10}\b"
)
_SECRET_PATTERNS = (
    ("aws-access-key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("stripe-key", r"\b(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{10,99}\b"),
    ("github-token", r"\b(?:gh[pousr]_[0-9A-Za-z]{36,255}|github_pat_[0-9A-Za-z_]{22,255})\b"),
    ("slack-token", r"\bxox[abposr]-[0-9A-Za-z-]{10,200}\b"),
    ("google-api-key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ("openai-style-key", r"\bsk-(?:proj-)?[0-9A-Za-z_-]{20,}\b"),
    ("jwt", r"\beyJ[0-9A-Za-z_-]{8,}\.eyJ[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{8,}\b"),
    ("private-key", r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----"),
)


def normalized_with_map(text: str) -> tuple[str, list[int]]:
    """NFKC + format-character removal, with a map back to original offsets.

    ``index_map[i]`` is the original index of normalised character ``i``; a
    normalised span ``(s, e)`` covers original ``(index_map[s], index_map[e-1]+1)``.
    """
    if text.isascii():
        return text, list(range(len(text)))
    out: list[str] = []
    index_map: list[int] = []
    for i, ch in enumerate(text):
        if unicodedata.category(ch) == "Cf":  # ZWSP, ZWJ, soft hyphen, bidi controls
            continue
        for c in unicodedata.normalize("NFKC", ch):
            out.append(c)
            index_map.append(i)
    return "".join(out), index_map


@dataclass(frozen=True)
class DetectedSpan:
    entity_type: str
    start: int
    end: int
    score: float


DetectorFn = Callable[[str, str, Iterable[str] | None], list[DetectedSpan]]


class DetectorFailure(Exception):
    pass


# Presidio logs analysed text at DEBUG ("Context list is: <raw text>"). A host
# that enables DEBUG logging must not receive payloads (review 02, M2), so the
# analyzer loggers are pinned at WARNING and filtered below WARNING.
_PRESIDIO_LOGGERS = ("presidio-analyzer", "presidio_analyzer")


class _DropBelowWarning(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno >= logging.WARNING


def quiet_detector_loggers() -> None:
    """Pin third-party detector loggers at WARNING (idempotent)."""
    for name in _PRESIDIO_LOGGERS:
        logger = logging.getLogger(name)
        logger.setLevel(logging.WARNING)
        if not any(isinstance(f, _DropBelowWarning) for f in logger.filters):
            logger.addFilter(_DropBelowWarning())


quiet_detector_loggers()

_ENGINE: Any = None
_ENGINE_LOCK = threading.Lock()

# Exercises the NLP model and every approved recognizer (incl. the e-mail
# recognizer's public-suffix lookup) so the first real request is warm.
WARM_UP_TEXT = (
    "Warm-up: John Smith, john.smith@example.com, 415-555-0132, card 4111 1111 1111 1111."
)


_TLD_EXTRACTOR: Any = None


def offline_tld_extractor() -> Any:
    """tldextract using only the bundled Public Suffix List snapshot.

    Presidio's e-mail recognizer calls ``tldextract.extract``, whose default
    instance downloads the PSL from publicsuffix.org on first use and caches it
    on disk (review 02, L2: runtime egress + supply-chain input). This instance
    never touches the network or the disk.
    """
    global _TLD_EXTRACTOR
    if _TLD_EXTRACTOR is None:
        import tldextract

        _TLD_EXTRACTOR = tldextract.TLDExtract(
            suffix_list_urls=(), cache_dir=None, fallback_to_snapshot=True
        )
    return _TLD_EXTRACTOR


def _build_engine() -> Any:
    """AnalyzerEngine with a registry restricted to the recognizers we use."""
    from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerRegistry
    from presidio_analyzer.predefined_recognizers import (
        CreditCardRecognizer,
        EmailRecognizer,
        IbanRecognizer,
        PhoneRecognizer,
        SpacyRecognizer,
        UsSsnRecognizer,
    )

    class OfflineEmailRecognizer(EmailRecognizer):
        def validate_result(self, pattern_text: str) -> bool:
            return bool(offline_tld_extractor()(pattern_text).fqdn != "")

    class ObfuscatedEmailRecognizer(PatternRecognizer):
        """``jane.doe [at] example [dot] com`` and similar bracketed forms."""

        def validate_result(self, pattern_text: str) -> bool:
            plain = re.sub(_AT, "@", pattern_text, flags=re.IGNORECASE)
            plain = re.sub(_DOT, ".", plain, flags=re.IGNORECASE)
            return bool(offline_tld_extractor()(plain.split("@")[-1]).fqdn != "")

    class SeparatorTolerantCardRecognizer(CreditCardRecognizer):
        """Card numbers split by dots, newlines, slashes, underscores (Luhn-checked)."""

    registry = RecognizerRegistry(supported_languages=["en"])
    for recognizer in (
        SpacyRecognizer(supported_language="en"),
        OfflineEmailRecognizer(),
        ObfuscatedEmailRecognizer(
            supported_entity="EMAIL_ADDRESS",
            name="ObfuscatedEmailRecognizer",
            patterns=[Pattern("obfuscated-email", _OBFUSCATED_EMAIL_PATTERN, 0.6)],
        ),
        PhoneRecognizer(),
        CreditCardRecognizer(),
        SeparatorTolerantCardRecognizer(
            patterns=[Pattern("card-any-separator", _CARD_PATTERN, 0.3)],
            replacement_pairs=[(sep, "") for sep in _CARD_SEPARATORS],
        ),
        # Opt-in entities: only analysed when a policy enables them.
        UsSsnRecognizer(),
        IbanRecognizer(),
        PatternRecognizer(
            supported_entity="SECRET_TOKEN",
            name="SecretTokenRecognizer",
            patterns=[Pattern(name, regex, 0.9) for name, regex in _SECRET_PATTERNS],
            global_regex_flags=re.DOTALL | re.MULTILINE,  # case-sensitive
        ),
    ):
        registry.add_recognizer(recognizer)
    return AnalyzerEngine(registry=registry, supported_languages=["en"])


def _get_engine() -> Any:
    """Return the process-wide AnalyzerEngine, creating it exactly once."""
    global _ENGINE
    engine = _ENGINE
    if engine is not None:
        return engine
    with _ENGINE_LOCK:
        if _ENGINE is None:
            _ENGINE = _build_engine()
            quiet_detector_loggers()  # in case the import reconfigured them
        return _ENGINE


def _presidio_detector(
    text: str, language: str, entities: Iterable[str] | None
) -> list[DetectedSpan]:
    engine = _get_engine()
    try:
        results = engine.analyze(
            text=text, language=language, entities=list(entities) if entities else None
        )
    except Exception as exc:
        raise DetectorFailure() from exc
    spans = []
    for r in results:
        spans.append(
            DetectedSpan(entity_type=r.entity_type, start=r.start, end=r.end, score=r.score)
        )
    return spans


def _dist_version(*names: str) -> str:
    from importlib.metadata import PackageNotFoundError, version

    for name in names:
        try:
            return version(name)
        except PackageNotFoundError:
            continue
    return "unknown"


def presidio_detector_version() -> str:
    """Installed analyzer + model versions (review 02, L5: no hard-coded string)."""
    return (
        f"presidio-analyzer=={_dist_version('presidio-analyzer')}"
        f"/en_core_web_lg=={_dist_version('en-core-web-lg', 'en_core_web_lg')}"
    )


def _valid_score(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and 0.0 <= value <= 1.0
    )


def _validated_thresholds(
    entities: frozenset[str], thresholds: Mapping[str, float] | None
) -> dict[str, float]:
    """Every enabled entity needs an explicit, finite threshold in [0, 1] (L6)."""
    given = dict(thresholds or {})
    if set(given) != set(entities):
        raise ValueError("thresholds must be given for exactly the enabled entities")
    if not all(_valid_score(v) for v in given.values()):
        raise ValueError("thresholds must be finite numbers in [0, 1]")
    return {k: float(v) for k, v in given.items()}


class PiiRedactor:
    def __init__(
        self,
        entities: Iterable[str],
        thresholds: Mapping[str, float] | None = None,
        detector: DetectorFn | None = None,
        detector_version: str | None = None,
    ) -> None:
        self.entities = frozenset(entities)
        self.thresholds = _validated_thresholds(self.entities, thresholds)
        self._detector = detector or _presidio_detector
        if detector_version is None:
            detector_version = presidio_detector_version() if detector is None else "custom"
        self.detector_version = detector_version

    @classmethod
    def from_policy(
        cls,
        policy: Any,
        detector: DetectorFn | None = None,
        detector_version: str | None = None,
    ) -> PiiRedactor:
        """Build a redactor whose entities/thresholds are exactly the policy's."""
        return cls(
            entities=policy.entities,
            thresholds=dict(policy.thresholds),
            detector=detector,
            detector_version=detector_version,
        )

    def _detect(self, text: str, entities: Iterable[str] | None = None) -> list[DetectedSpan]:
        wanted = list(entities) if entities is not None else sorted(self.entities)
        # Detect on a normalised view so zero-width characters, full-width
        # digits / at-signs and other compatibility forms cannot hide PII (M3); spans
        # are mapped back to original offsets and the original text is redacted.
        view, index_map = normalized_with_map(text)
        if len(view) > MAX_NORMALIZED_CHARS:
            raise DetectorFailure()
        try:
            spans = self._detector(view, "en", wanted)
        except DetectorFailure:
            raise
        except Exception as exc:
            raise DetectorFailure() from exc
        valid = []
        try:
            for s in spans:
                if s.entity_type not in self.entities:
                    continue
                if type(s.start) is not int or type(s.end) is not int:
                    raise DetectorFailure()
                if s.start < 0 or s.end <= s.start or s.end > len(view):
                    raise DetectorFailure()
                # A NaN / non-numeric / out-of-range score is a detector fault,
                # not a silent miss (L6): fail closed.
                if not _valid_score(s.score):
                    raise DetectorFailure()
                if s.score >= self.thresholds[s.entity_type]:
                    start, end = index_map[s.start], index_map[s.end - 1] + 1
                    if (start, end) != (s.start, s.end):
                        s = DetectedSpan(s.entity_type, start, end, s.score)
                    valid.append(s)
        except DetectorFailure:
            raise
        except Exception as exc:
            raise DetectorFailure() from exc
        return valid

    def detect(self, text: str) -> list[DetectedSpan]:
        """Public detection API: above-threshold spans in original-text offsets.

        Same normalisation, validation and thresholds as ``redact``; raises
        DetectorFailure. Intended for evaluation/calibration tooling.
        """
        return self._detect(text)

    def warm_up(self) -> None:
        """Load the detector/model and run one analysis; raises DetectorFailure."""
        self._detect(WARM_UP_TEXT)

    def redact(self, text: str) -> tuple[str, Action, tuple[ReasonCode, ...]]:
        spans = self._detect(text)
        if not spans:
            return text, Action.ALLOW, ()
        redacted = _replace_union(text, spans)
        residual = self._detect(redacted)
        if residual:
            return "", Action.BLOCK, (ReasonCode.RESIDUAL_PII,)
        return redacted, Action.REDACT, (ReasonCode.PII_REDACTED,)


def _precedence(entity_type: str) -> int:
    try:
        return ENTITY_PRECEDENCE.index(entity_type)
    except ValueError:
        return len(ENTITY_PRECEDENCE)


def _replace_union(text: str, spans: list[DetectedSpan]) -> str:
    ordered = sorted(spans, key=lambda s: (s.start, s.end))
    groups: list[list[Any]] = []
    for span in ordered:
        if groups and span.start < groups[-1][1]:
            groups[-1][1] = max(groups[-1][1], span.end)
            groups[-1][2].append(span.entity_type)
        else:
            groups.append([span.start, span.end, [span.entity_type]])
    parts: list[str] = []
    prev_end = 0
    for start, end, entities in groups:
        parts.append(text[prev_end:start])
        parts.append(REDACTION_LABELS[min(entities, key=_precedence)])
        prev_end = end
    parts.append(text[prev_end:])
    return "".join(parts)
