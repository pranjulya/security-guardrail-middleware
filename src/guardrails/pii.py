"""Presidio integration and original-text span replacement."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .contracts import Action, ReasonCode

ENTITY_PRECEDENCE = ("CREDIT_CARD", "EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON")

REDACTION_LABELS = {
    "CREDIT_CARD": "[CREDIT_CARD]",
    "EMAIL_ADDRESS": "[EMAIL_ADDRESS]",
    "PHONE_NUMBER": "[PHONE_NUMBER]",
    "PERSON": "[PERSON]",
}


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
    from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
    from presidio_analyzer.predefined_recognizers import (
        CreditCardRecognizer,
        EmailRecognizer,
        PhoneRecognizer,
        SpacyRecognizer,
    )

    class OfflineEmailRecognizer(EmailRecognizer):
        def validate_result(self, pattern_text: str) -> bool:
            return bool(offline_tld_extractor()(pattern_text).fqdn != "")

    registry = RecognizerRegistry(supported_languages=["en"])
    for recognizer in (
        SpacyRecognizer(supported_language="en"),
        OfflineEmailRecognizer(),
        PhoneRecognizer(),
        CreditCardRecognizer(),
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


class PiiRedactor:
    def __init__(
        self,
        entities: Iterable[str],
        thresholds: Mapping[str, float] | None = None,
        detector: DetectorFn | None = None,
        detector_version: str = "presidio-analyzer==2.2.360/en_core_web_lg==3.8.0",
    ) -> None:
        self.entities = frozenset(entities)
        self.thresholds = dict(thresholds or {})
        self._detector = detector or _presidio_detector
        self.detector_version = detector_version

    def _detect(self, text: str, entities: Iterable[str] | None = None) -> list[DetectedSpan]:
        wanted = list(entities) if entities is not None else sorted(self.entities)
        try:
            spans = self._detector(text, "en", wanted)
        except DetectorFailure:
            raise
        except Exception as exc:
            raise DetectorFailure() from exc
        valid = []
        for s in spans:
            if s.entity_type not in self.entities:
                continue
            if not isinstance(s.start, int) or not isinstance(s.end, int):
                raise DetectorFailure()
            if s.start < 0 or s.end <= s.start or s.end > len(text):
                raise DetectorFailure()
            threshold = self.thresholds.get(s.entity_type, 0.0)
            if s.score >= threshold:
                valid.append(s)
        return valid

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
