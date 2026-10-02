"""Ordered pipeline: aggregate bounds, deadlines, buffered release gate."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional

from .contracts import (
    Action,
    Decision,
    EnvelopeError,
    ReasonCode,
    ValidatedEnvelope,
    validate_envelope,
)
from .injection import detect as detect_injection
from .pii import DetectorFailure, PiiRedactor
from .policy import PolicySnapshot

SAFE_REFUSAL = "Cannot safely process this request."

FREE_TEXT_BLOCKS = ("user_input", "retrieved_content", "tool_output", "model_output")


@dataclass
class Pipeline:
    policy: PolicySnapshot
    redactor: PiiRedactor
    clock_ms: Callable[[], int] = field(
        default_factory=lambda: lambda: int(time.monotonic() * 1000)
    )
    detector_versions: Mapping[str, str] = field(default_factory=dict)
    max_tool_invocations: int = 1

    def __post_init__(self) -> None:
        self._blocks_used = 0
        self._bytes_used = 0
        self._budget_remaining_ms = self.policy.inspection_budget_ms

    def _check_deadline(self, start_ms: int) -> int:
        elapsed = self.clock_ms() - start_ms
        self._budget_remaining_ms -= elapsed
        if self._budget_remaining_ms < 0:
            raise _PipelineBlock((ReasonCode.DEADLINE_EXCEEDED,))
        return elapsed

    def _reserve(self, byte_len: int) -> None:
        if self._blocks_used + 1 > self.policy.max_blocks:
            raise _PipelineBlock((ReasonCode.LIMIT_EXCEEDED,))
        if self._bytes_used + byte_len > self.policy.max_aggregate_bytes:
            raise _PipelineBlock((ReasonCode.LIMIT_EXCEEDED,))
        self._blocks_used += 1
        self._bytes_used += byte_len

    def inspect(self, envelope_data: Mapping[str, Any]) -> Decision:
        start = self.clock_ms()
        try:
            envelope = validate_envelope(envelope_data, self.policy)
        except EnvelopeError as exc:
            return self._block((exc.reason,), start)
        if envelope.policy_id != self.policy.version:
            return self._block((ReasonCode.POLICY_INVALID,), start)
        try:
            self._reserve(envelope.text_byte_len)
        except _PipelineBlock as exc:
            return self._block(exc.reasons, start)
        try:
            self._check_deadline(start)
        except _PipelineBlock as exc:
            return self._block(exc.reasons, start)
        findings_start = self.clock_ms()
        try:
            findings = detect_injection(envelope.text, self.policy.rules)
        finally:
            self._debit(findings_start)
        if self._budget_remaining_ms < 0:
            return self._block((ReasonCode.DEADLINE_EXCEEDED,), start)
        if findings:
            return self._block(
                (ReasonCode.INJECTION_RULE,), start,
                extra_versions={"injection": "rules-v1"},
            )
        redact_start = self.clock_ms()
        try:
            safe_text, action, _ = self.redactor.redact(envelope.text)
        except DetectorFailure:
            return self._block((ReasonCode.DETECTOR_ERROR,), start)
        finally:
            self._debit(redact_start)
        if self._budget_remaining_ms < 0:
            return self._block((ReasonCode.DEADLINE_EXCEEDED,), start)
        elapsed = self.clock_ms() - start
        if action is Action.BLOCK:
            return Decision(
                action=Action.BLOCK,
                reason_codes=(ReasonCode.RESIDUAL_PII,),
                policy_version=self.policy.version,
                detector_versions=self._versions(),
                elapsed_ms=elapsed,
            )
        if action is Action.REDACT:
            return Decision(
                action=Action.REDACT,
                reason_codes=(ReasonCode.PII_REDACTED,),
                policy_version=self.policy.version,
                detector_versions=self._versions(),
                elapsed_ms=elapsed,
                safe_text=safe_text,
            )
        return Decision(
            action=Action.ALLOW,
            reason_codes=(),
            policy_version=self.policy.version,
            detector_versions=self._versions(),
            elapsed_ms=elapsed,
            safe_text=envelope.text,
        )

    def collect_model_output(self, chunks: list[str]) -> Decision:
        start = self.clock_ms()
        buffered: list[str] = []
        total = 0
        per_text_cap = min(self.policy.max_text_bytes,
                           self.policy.max_aggregate_bytes - self._bytes_used)
        for chunk in chunks:
            total += len(chunk.encode("utf-8"))
            if total > per_text_cap:
                return self._block((ReasonCode.LIMIT_EXCEEDED,), start)
            buffered.append(chunk)
        full = "".join(buffered)
        if not full.strip():
            return self._block((ReasonCode.INVALID_ENVELOPE,), start)
        return self.inspect(
            {
                "boundary": "model_output",
                "language": "en",
                "text": full,
                "request_id": "collected",
                "policy_id": self.policy.version,
            }
        )

    def _debit(self, stage_start: int) -> None:
        self._budget_remaining_ms -= self.clock_ms() - stage_start

    def _versions(self) -> dict:
        versions = dict(self.detector_versions)
        versions.setdefault("pii", getattr(self.redactor, "detector_version", "unknown"))
        return versions

    def _block(self, reasons: tuple, start: int, extra_versions: Mapping | None = None) -> Decision:
        versions = self._versions()
        if extra_versions:
            versions.update(extra_versions)
        return Decision(
            action=Action.BLOCK,
            reason_codes=tuple(reasons),
            policy_version=self.policy.version,
            detector_versions=versions,
            elapsed_ms=max(0, self.clock_ms() - start),
        )


class _PipelineBlock(Exception):
    def __init__(self, reasons: tuple):
        super().__init__("pipeline block")
        self.reasons = reasons


def refusal_text() -> str:
    return SAFE_REFUSAL
