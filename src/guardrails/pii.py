"""Presidio integration and original-text span replacement."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, List, Mapping, Optional, Tuple

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


DetectorFn = Callable[[str, str, Optional[Iterable[str]]], List[DetectedSpan]]


class DetectorFailure(Exception):
    pass


def _presidio_detector(
    text: str, language: str, entities: Optional[Iterable[str]]
) -> List[DetectedSpan]:
    from presidio_analyzer import AnalyzerEngine

    engine = AnalyzerEngine()
    try:
        results = engine.analyze(text=text, language=language, entities=list(entities) if entities else None)
    except Exception as exc:
        raise DetectorFailure() from exc
    spans = []
    for r in results:
        spans.append(
            DetectedSpan(
                entity_type=r.entity_type, start=r.start, end=r.end, score=r.score
            )
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

    def _detect(
        self, text: str, entities: Optional[Iterable[str]] = None
    ) -> List[DetectedSpan]:
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

    def redact(self, text: str) -> Tuple[str, Action, Tuple[ReasonCode, ...]]:
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


def _replace_union(text: str, spans: List[DetectedSpan]) -> str:
    ordered = sorted(spans, key=lambda s: (s.start, s.end))
    groups: List[List[DetectedSpan]] = []
    for span in ordered:
        if groups and span.start < groups[-1][-1].end:
            groups[-1].append(span)
        elif groups and span.start == groups[-1][-1].end:
            groups[-1].append(span)
        else:
            groups.append([span])
    merged: List[Tuple[int, int, str]] = []
    for group in groups:
        start = min(s.start for s in group)
        end = max(s.end for s in group)
        label_entity = min((s.entity_type for s in group), key=_precedence)
        merged.append((start, end, REDACTION_LABELS[label_entity]))
    out = text
    for start, end, label in sorted(merged, key=lambda m: m[0], reverse=True):
        out = out[:start] + label + out[end:]
    return out
