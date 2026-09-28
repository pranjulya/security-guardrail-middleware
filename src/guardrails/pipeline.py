"""Ordered pipeline: aggregate bounds, deadlines, buffered release gate."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Optional

from .audit import build_event
from .contracts import (
    Action,
    Decision,
    EnvelopeError,
    ReasonCode,
    RequestBudget,
    utf8_len,
    validate_envelope,
)
from .injection import InjectionScanLimit
from .injection import detect as detect_injection
from .pii import DetectorFailure, PiiRedactor
from .policy import PolicySnapshot

SAFE_REFUSAL = "Cannot safely process this request."

EventSink = Callable[[dict], None]


@dataclass
class Pipeline:
    policy: PolicySnapshot
    redactor: PiiRedactor
    clock_ms: Callable[[], int] = field(
        default_factory=lambda: lambda: int(time.monotonic() * 1000)
    )
    detector_versions: Mapping[str, str] = field(default_factory=dict)
    event_sink: Optional[EventSink] = None
    max_tool_invocations: int = 1

    def __post_init__(self) -> None:
        self.sink_failures = 0
        self._active_request_id: Optional[str] = None
        self._reset_request_state()

    def _reset_request_state(self) -> None:
        self._budget = RequestBudget(
            max_blocks=self.policy.max_blocks,
            max_bytes=self.policy.max_aggregate_bytes,
        )
        self._remaining_ms = self.policy.inspection_budget_ms

    def _begin_request(self, request_id: str) -> None:
        if self._active_request_id is None:
            self._active_request_id = request_id
        elif request_id != self._active_request_id:
            self._active_request_id = request_id
            self._reset_request_state()

    @property
    def active_request_id(self) -> Optional[str]:
        return self._active_request_id

    def _check_deadline(self, start_ms: int) -> None:
        self._remaining_ms -= self.clock_ms() - start_ms
        if self._remaining_ms < 0:
            raise _PipelineBlock((ReasonCode.DEADLINE_EXCEEDED,))

    def _stage_debit(self, stage_start: int) -> None:
        self._remaining_ms -= self.clock_ms() - stage_start

    def inspect(self, envelope_data: Mapping[str, Any]) -> Decision:
        """Inspect one block. Total: always returns a Decision, never raises."""
        start = self.clock_ms()
        try:
            return self._inspect(envelope_data, start)
        except Exception:
            return self._fail_closed(ReasonCode.DETECTOR_ERROR, start)

    def _fail_closed(
        self, reason: ReasonCode, start: int, boundary: str = "", request_id: str = ""
    ) -> Decision:
        try:
            decision = self._block((reason,), start)
        except Exception:
            decision = Decision(
                action=Action.BLOCK,
                reason_codes=(reason,),
                policy_version=str(getattr(self.policy, "version", "")),
            )
        return self._finish(decision, boundary, 0, request_id, ())

    def _inspect(self, envelope_data: Any, start: int) -> Decision:
        rule_ids: tuple = ()
        if not isinstance(envelope_data, Mapping):
            return self._fail_closed(ReasonCode.INVALID_ENVELOPE, start)
        raw_boundary = envelope_data.get("boundary", "")
        boundary = str(getattr(raw_boundary, "value", raw_boundary))
        request_id = str(envelope_data.get("request_id", ""))
        try:
            envelope = validate_envelope(envelope_data, self.policy)
        except EnvelopeError as exc:
            return self._finish(
                self._block((exc.reason,), start), boundary, 0, request_id, rule_ids
            )
        self._begin_request(envelope.request_id)
        byte_len = envelope.text_byte_len
        if envelope.policy_id != self.policy.version:
            return self._finish(
                self._block((ReasonCode.POLICY_INVALID,), start),
                boundary, byte_len, envelope.request_id, rule_ids,
            )
        try:
            self._budget.consume(byte_len)
            self._check_deadline(start)
        except _PipelineBlock as exc:
            return self._finish(
                self._block(exc.reasons, start),
                boundary, byte_len, envelope.request_id, rule_ids,
            )
        except EnvelopeError as exc:
            return self._finish(
                self._block((exc.reason,), start),
                boundary, byte_len, envelope.request_id, rule_ids,
            )
        findings_start = self.clock_ms()
        try:
            findings = detect_injection(envelope.text, self.policy.rules)
        except InjectionScanLimit:
            return self._finish(
                self._block((ReasonCode.LIMIT_EXCEEDED,), start),
                boundary, byte_len, envelope.request_id, rule_ids,
            )
        finally:
            self._stage_debit(findings_start)
        if self._remaining_ms < 0:
            return self._finish(
                self._block((ReasonCode.DEADLINE_EXCEEDED,), start),
                boundary, byte_len, envelope.request_id, rule_ids,
            )
        if findings:
            rule_ids = tuple(f.rule_id for f in findings)
            return self._finish(
                self._block((ReasonCode.INJECTION_RULE,), start,
                            extra_versions={"injection": "rules-v1"}),
                boundary, byte_len, envelope.request_id, rule_ids,
            )
        redact_start = self.clock_ms()
        try:
            safe_text, action, _ = self.redactor.redact(envelope.text)
        except DetectorFailure:
            return self._finish(
                self._block((ReasonCode.DETECTOR_ERROR,), start),
                boundary, byte_len, envelope.request_id, rule_ids,
            )
        finally:
            self._stage_debit(redact_start)
        if self._remaining_ms < 0:
            return self._finish(
                self._block((ReasonCode.DEADLINE_EXCEEDED,), start),
                boundary, byte_len, envelope.request_id, rule_ids,
            )
        elapsed = self.clock_ms() - start
        if action is Action.BLOCK:
            decision = Decision(
                action=Action.BLOCK,
                reason_codes=(ReasonCode.RESIDUAL_PII,),
                policy_version=self.policy.version,
                detector_versions=self._versions(),
                elapsed_ms=elapsed,
            )
        elif action is Action.REDACT:
            decision = Decision(
                action=Action.REDACT,
                reason_codes=(ReasonCode.PII_REDACTED,),
                policy_version=self.policy.version,
                detector_versions=self._versions(),
                elapsed_ms=elapsed,
                safe_text=safe_text,
            )
        else:
            decision = Decision(
                action=Action.ALLOW,
                reason_codes=(),
                policy_version=self.policy.version,
                detector_versions=self._versions(),
                elapsed_ms=elapsed,
                safe_text=envelope.text,
            )
        return self._finish(decision, boundary, byte_len,
                            envelope.request_id, rule_ids)

    def collect_model_output(self, chunks: Iterable[str]) -> Decision:
        """Buffer model output privately, then inspect. Never raises."""
        start = self.clock_ms()
        try:
            return self._collect_model_output(chunks, start)
        except Exception:
            return self._fail_closed(ReasonCode.DETECTOR_ERROR, start, "model_output")

    def _collect_model_output(self, chunks: Any, start: int) -> Decision:
        request_id = self._active_request_id or "model-output"
        buffered: list[str] = []
        total = 0
        per_text_cap = min(
            self.policy.max_text_bytes,
            self.policy.max_aggregate_bytes - self._budget.bytes_used,
        )
        if isinstance(chunks, (str, bytes, bytearray)):
            chunks = [chunks]
        try:
            iterator = iter(chunks)
        except TypeError:
            return self._fail_closed(
                ReasonCode.INVALID_ENVELOPE, start, "model_output", request_id
            )
        while True:
            try:
                chunk = next(iterator)
            except StopIteration:
                break
            except Exception:
                # A failing/aborted model stream is incomplete output: release nothing.
                return self._fail_closed(
                    ReasonCode.INVALID_ENVELOPE, start, "model_output", request_id
                )
            if not isinstance(chunk, str):
                return self._fail_closed(
                    ReasonCode.INVALID_ENVELOPE, start, "model_output", request_id
                )
            try:
                total += utf8_len(chunk)
            except EnvelopeError:
                return self._fail_closed(
                    ReasonCode.INVALID_ENVELOPE, start, "model_output", request_id
                )
            if total > per_text_cap:
                return self._finish(
                    self._block((ReasonCode.LIMIT_EXCEEDED,), start),
                    "model_output", total, request_id, (),
                )
            buffered.append(chunk)
        full = "".join(buffered)
        if not full.strip():
            return self._finish(
                self._block((ReasonCode.INVALID_ENVELOPE,), start),
                "model_output", total, request_id, (),
            )
        return self.inspect(
            {
                "boundary": "model_output",
                "language": "en",
                "text": full,
                "request_id": request_id,
                "policy_id": self.policy.version,
            }
        )

    def _versions(self) -> dict:
        versions = dict(self.detector_versions)
        versions.setdefault(
            "pii", getattr(self.redactor, "detector_version", "unknown")
        )
        return versions

    def _block(
        self, reasons: tuple, start: int, extra_versions: Mapping | None = None
    ) -> Decision:
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

    def _finish(
        self,
        decision: Decision,
        boundary: str,
        text_byte_len: int,
        request_id: str,
        rule_ids: tuple,
    ) -> Decision:
        if self.event_sink is None:
            return decision
        try:
            self._emit(decision, boundary, text_byte_len, request_id, rule_ids)
        except Exception:
            # Audit is mandatory once a sink is configured: a failing sink must
            # never crash the caller or silently release text. Fail closed.
            self.sink_failures += 1
            reasons = tuple(r for r in decision.reason_codes if r is not ReasonCode.AUDIT_ERROR)
            blocked = Decision(
                action=Action.BLOCK,
                reason_codes=(*reasons, ReasonCode.AUDIT_ERROR)
                if decision.action is Action.BLOCK
                else (ReasonCode.AUDIT_ERROR,),
                policy_version=decision.policy_version,
                detector_versions=decision.detector_versions,
                elapsed_ms=decision.elapsed_ms,
            )
            try:
                self._emit(blocked, boundary, text_byte_len, request_id, rule_ids)
            except Exception:
                self.sink_failures += 1
            return blocked
        return decision

    def _emit(
        self,
        decision: Decision,
        boundary: str,
        text_byte_len: int,
        request_id: str,
        rule_ids: tuple,
    ) -> None:
        assert self.event_sink is not None
        event = build_event(
            request_id=request_id or "unknown",
            boundary=boundary,
            action=decision.action,
            reason_codes=decision.reason_codes,
            policy_version=decision.policy_version,
            detector_versions=decision.detector_versions,
            elapsed_ms=decision.elapsed_ms,
            text_byte_len=text_byte_len,
            rule_ids=tuple(rule_ids),
        )
        self.event_sink(event.to_dict())


class _PipelineBlock(Exception):
    def __init__(self, reasons: tuple):
        super().__init__("pipeline block")
        self.reasons = reasons


def refusal_text() -> str:
    return SAFE_REFUSAL
