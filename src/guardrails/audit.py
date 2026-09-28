"""Allowlisted, content-free event serializer.

Review 02 (M1): every field is validated against a closed vocabulary or a
bounded charset before it can reach a sink. Caller-controlled values that do
not conform (e.g. an invalid ``boundary`` or ``request_id`` carrying user
text) are replaced by ``"invalid"`` and are never written verbatim.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .contracts import Action, Boundary, ReasonCode, is_valid_policy_id, is_valid_request_id

_ALLOWED_KEYS = frozenset(
    {
        "request_id",
        "boundary",
        "action",
        "reason_codes",
        "rule_ids",
        "policy_version",
        "policy_id",
        "detector_versions",
        "elapsed_ms",
        "byte_bucket",
    }
)

_BYTE_BUCKETS = ((1024, "0-1KiB"), (4096, "1-4KiB"), (16384, "4-16KiB"))
_BUCKET_LABELS = frozenset({label for _, label in _BYTE_BUCKETS} | {">16KiB"})

INVALID = "invalid"
UNKNOWN = "unknown"
_BOUNDARY_VALUES = frozenset(b.value for b in Boundary)
_ACTION_VALUES = frozenset(a.value for a in Action)
_REASON_VALUES = frozenset(r.value for r in ReasonCode)
_RULE_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
_VERSION = re.compile(r"[A-Za-z0-9._:@+=/-]{1,128}")


def byte_bucket(byte_len: int) -> str:
    for limit, label in _BYTE_BUCKETS:
        if byte_len <= limit:
            return label
    return ">16KiB"


def safe_request_id(value: object) -> str:
    """Loggable request id: the value itself only if it is a valid id."""
    if value is None or value == "":
        return UNKNOWN
    return value if is_valid_request_id(value) else INVALID


def safe_boundary(value: object) -> str:
    """Loggable boundary: a known Boundary value, else ``"invalid"``."""
    raw = value.value if isinstance(value, Boundary) else value
    if raw is None or raw == "":
        return UNKNOWN
    return raw if isinstance(raw, str) and raw in _BOUNDARY_VALUES else INVALID


def _check(condition: bool, name: str) -> None:
    if not condition:
        raise ValueError(f"audit event field rejected: {name}")


@dataclass(frozen=True)
class InspectionEvent:
    request_id: str
    boundary: str
    action: str
    reason_codes: tuple[str, ...] = ()
    rule_ids: tuple[str, ...] = ()
    policy_version: str = ""
    detector_versions: Mapping[str, str] = field(default_factory=dict)
    elapsed_ms: int = 0
    byte_bucket: str = ""
    policy_id: str = ""

    def __post_init__(self) -> None:
        # Defence in depth: refuse to construct an event that could carry
        # free text. The pipeline turns a refusal into BLOCK/AUDIT_ERROR.
        _check(
            self.request_id in (INVALID, UNKNOWN) or is_valid_request_id(self.request_id),
            "request_id",
        )
        _check(self.boundary in _BOUNDARY_VALUES | {INVALID, UNKNOWN}, "boundary")
        _check(self.action in _ACTION_VALUES, "action")
        _check(all(r in _REASON_VALUES for r in self.reason_codes), "reason_codes")
        _check(
            all(isinstance(r, str) and _RULE_ID.fullmatch(r) for r in self.rule_ids),
            "rule_ids",
        )
        _check(
            self.policy_version == ""
            or (
                isinstance(self.policy_version, str)
                and bool(_VERSION.fullmatch(self.policy_version))
            ),
            "policy_version",
        )
        _check(
            all(
                isinstance(k, str)
                and isinstance(v, str)
                and _VERSION.fullmatch(k)
                and _VERSION.fullmatch(v)
                for k, v in self.detector_versions.items()
            ),
            "detector_versions",
        )
        _check(
            type(self.elapsed_ms) is int and self.elapsed_ms >= 0,
            "elapsed_ms",
        )
        _check(self.byte_bucket in _BUCKET_LABELS | {""}, "byte_bucket")
        _check(self.policy_id == "" or is_valid_policy_id(self.policy_id), "policy_id")

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "request_id": self.request_id,
            "boundary": self.boundary,
            "action": self.action,
            "reason_codes": list(self.reason_codes),
            "rule_ids": list(self.rule_ids),
            "policy_version": self.policy_version,
            "policy_id": self.policy_id,
            "detector_versions": dict(self.detector_versions),
            "elapsed_ms": self.elapsed_ms,
            "byte_bucket": self.byte_bucket,
        }
        _check(set(data) <= _ALLOWED_KEYS, "keys")
        return data

    def serialize(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def build_event(
    *,
    request_id: object,
    boundary: object,
    action: Any,
    reason_codes: Any,
    policy_version: str,
    policy_id: str = "",
    detector_versions: Mapping[str, str] | None = None,
    elapsed_ms: int = 0,
    text_byte_len: int = 0,
    rule_ids: Any = (),
) -> InspectionEvent:
    action_value = getattr(action, "value", action)
    codes = [getattr(r, "value", r) for r in reason_codes]
    rules = [getattr(r, "value", r) for r in rule_ids]
    return InspectionEvent(
        request_id=safe_request_id(request_id),
        boundary=safe_boundary(boundary),
        action=str(action_value),
        reason_codes=tuple(codes),
        rule_ids=tuple(rules),
        policy_version=policy_version,
        policy_id=policy_id,
        detector_versions=dict(detector_versions or {}),
        elapsed_ms=max(0, int(elapsed_ms)),
        byte_bucket=byte_bucket(text_byte_len),
    )
