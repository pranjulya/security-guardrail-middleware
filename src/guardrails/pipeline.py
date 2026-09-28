"""Ordered pipeline: aggregate bounds, deadlines, buffered release gate."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
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

    max_tracked_requests: int = 4096

    def __post_init__(self) -> None:
        if self.max_tracked_requests <= 0:
            raise ValueError("max_tracked_requests must be positive")
        self.sink_failures = 0
        # Per-request state, keyed by request_id. Never shared between
        # different request IDs; guarded by locks so a Pipeline can be used from
        # many threads at once.
        self._states: OrderedDict[str, _RequestState] = OrderedDict()
        self._states_lock = threading.Lock()

    # -- per-request state ------------------------------------------------
    def _state_for(self, request_id: str) -> _RequestState:
        with self._states_lock:
            state = self._states.get(request_id)
            if state is None:
                state = _RequestState(
                    budget=RequestBudget(
                        max_blocks=self.policy.max_blocks,
                        max_bytes=self.policy.max_aggregate_bytes,
                    ),
                    remaining_ms=self.policy.inspection_budget_ms,
                )
                self._states[request_id] = state
                # Bounded memory: evict the least recently used request. Hosts
                # should call end_request() when a request completes.
                while len(self._states) > self.max_tracked_requests:
                    self._states.popitem(last=False)
            else:
                self._states.move_to_end(request_id)
            return state

    def end_request(self, request_id: str) -> None:
        """Release the budget/deadline state held for ``request_id``."""
        with self._states_lock:
            self._states.pop(request_id, None)

    def request_usage(self, request_id: str) -> tuple[int, int]:
        """(blocks_used, bytes_used) for ``request_id``; (0, 0) if unknown."""
        with self._states_lock:
            state = self._states.get(request_id)
        if state is None:
            return (0, 0)
        with state.lock:
            return (state.budget.blocks_used, state.budget.bytes_used)

    @property
    def tracked_requests(self) -> int:
        with self._states_lock:
            return len(self._states)

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
        state = self._state_for(envelope.request_id)
        byte_len = envelope.text_byte_len
        if envelope.policy_id != self.policy.version:
            return self._finish(
                self._block((ReasonCode.POLICY_INVALID,), start),
                boundary, byte_len, envelope.request_id, rule_ids,
            )
        try:
            state.consume(byte_len)
            if state.debit(self.clock_ms() - start):
                raise _PipelineBlock((ReasonCode.DEADLINE_EXCEEDED,))
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
            expired = state.debit(self.clock_ms() - findings_start)
        if expired:
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
            expired = state.debit(self.clock_ms() - redact_start)
        if expired:
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

    def collect_model_output(self, chunks: Iterable[str], *, request_id: str) -> Decision:
        """Buffer model output for ``request_id`` privately, then inspect.

        The request ID is explicit so output is always charged to, and audited
        under, the request that produced it. Never raises.
        """
        start = self.clock_ms()
        try:
            return self._collect_model_output(chunks, start, request_id)
        except Exception:
            return self._fail_closed(
                ReasonCode.DETECTOR_ERROR, start, "model_output", _safe_str(request_id)
            )

    def _collect_model_output(self, chunks: Any, start: int, request_id: Any) -> Decision:
        if not isinstance(request_id, str) or not request_id:
            return self._fail_closed(ReasonCode.INVALID_ENVELOPE, start, "model_output")
        buffered: list[str] = []
        total = 0
        _, bytes_used = self.request_usage(request_id)
        per_text_cap = min(
            self.policy.max_text_bytes,
            self.policy.max_aggregate_bytes - bytes_used,
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


@dataclass
class _RequestState:
    budget: RequestBudget
    remaining_ms: int
    lock: threading.Lock = field(default_factory=threading.Lock)

    def consume(self, byte_len: int) -> None:
        with self.lock:
            self.budget.consume(byte_len)

    def debit(self, elapsed_ms: int) -> bool:
        """Charge elapsed time; True once the request's budget is exhausted."""
        with self.lock:
            self.remaining_ms -= max(0, elapsed_ms)
            return self.remaining_ms < 0


def _safe_str(value: Any) -> str:
    return value if isinstance(value, str) else ""


class _PipelineBlock(Exception):
    def __init__(self, reasons: tuple):
        super().__init__("pipeline block")
        self.reasons = reasons


def refusal_text() -> str:
    return SAFE_REFUSAL
