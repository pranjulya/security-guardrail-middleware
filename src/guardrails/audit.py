"""Allowlisted content-free event serializer."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Mapping

_ALLOWED_KEYS = frozenset(
    {
        "request_id",
        "boundary",
        "action",
        "reason_codes",
        "policy_version",
        "detector_versions",
        "elapsed_ms",
        "byte_bucket",
    }
)

_BYTE_BUCKETS = ((1024, "0-1KiB"), (4096, "1-4KiB"), (16384, "4-16KiB"))


def byte_bucket(byte_len: int) -> str:
    for limit, label in _BYTE_BUCKETS:
        if byte_len <= limit:
            return label
    return ">16KiB"


@dataclass(frozen=True)
class InspectionEvent:
    request_id: str
    boundary: str
    action: str
    reason_codes: tuple = ()
    policy_version: str = ""
    detector_versions: Mapping[str, str] = field(default_factory=dict)
    elapsed_ms: int = 0
    byte_bucket: str = ""

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "boundary": self.boundary,
            "action": self.action,
            "reason_codes": list(self.reason_codes),
            "policy_version": self.policy_version,
            "detector_versions": dict(self.detector_versions),
            "elapsed_ms": self.elapsed_ms,
            "byte_bucket": self.byte_bucket,
        }

    def serialize(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def build_event(
    *,
    request_id: str,
    boundary: Any,
    action: Any,
    reason_codes: Any,
    policy_version: str,
    detector_versions: Mapping[str, str] | None = None,
    elapsed_ms: int = 0,
    text_byte_len: int = 0,
) -> InspectionEvent:
    boundary_value = getattr(boundary, "value", boundary)
    action_value = getattr(action, "value", action)
    codes = [getattr(r, "value", r) for r in reason_codes]
    return InspectionEvent(
        request_id=request_id,
        boundary=str(boundary_value),
        action=str(action_value),
        reason_codes=tuple(codes),
        policy_version=policy_version,
        detector_versions=dict(detector_versions or {}),
        elapsed_ms=elapsed_ms,
        byte_bucket=byte_bucket(text_byte_len),
    )
