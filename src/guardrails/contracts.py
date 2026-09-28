"""Boundary and decision types, validated envelope, request budget."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TypeGuard

MAX_TEXT_BYTES = 16 * 1024
MAX_AGGREGATE_BYTES = 64 * 1024
MAX_BLOCKS = 4
INSPECTION_BUDGET_MS = 2000
SUPPORTED_LANGUAGE = "en"

# Core entities enabled by the default policy (PRD scope).
DEFAULT_ENTITIES = frozenset({"EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "PERSON"})
# Opt-in entities a policy may enable (review 02, M3): not in the default
# policy because changing its scope is an owner decision; see
# docs/architecture/ADRs/ADR-002-pii.md.
OPT_IN_ENTITIES = frozenset({"US_SSN", "IBAN_CODE", "SECRET_TOKEN"})
APPROVED_ENTITIES = DEFAULT_ENTITIES | OPT_IN_ENTITIES


# Envelope identifiers are bounded and charset-restricted so they are safe to
# log verbatim (review 02, L8/M1). Anything else is rejected, never logged.
REQUEST_ID_PATTERN = re.compile(r"[A-Za-z0-9._:-]{1,64}")
POLICY_ID_PATTERN = re.compile(r"[A-Za-z0-9._:@+-]{1,128}")
ENVELOPE_KEYS = frozenset({"boundary", "language", "text", "request_id", "policy_id"})


def is_valid_request_id(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and REQUEST_ID_PATTERN.fullmatch(value) is not None


def is_valid_policy_id(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and POLICY_ID_PATTERN.fullmatch(value) is not None


class Boundary(str, Enum):
    USER_INPUT = "user_input"
    RETRIEVED_CONTENT = "retrieved_content"
    TOOL_OUTPUT = "tool_output"
    MODEL_OUTPUT = "model_output"


class Action(str, Enum):
    ALLOW = "ALLOW"
    REDACT = "REDACT"
    BLOCK = "BLOCK"


class ReasonCode(str, Enum):
    INVALID_ENVELOPE = "INVALID_ENVELOPE"
    UNSUPPORTED_LANGUAGE = "UNSUPPORTED_LANGUAGE"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    POLICY_INVALID = "POLICY_INVALID"
    DETECTOR_ERROR = "DETECTOR_ERROR"
    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
    INJECTION_RULE = "INJECTION_RULE"
    PII_REDACTED = "PII_REDACTED"
    RESIDUAL_PII = "RESIDUAL_PII"
    TOOL_DENIED = "TOOL_DENIED"
    AUDIT_ERROR = "AUDIT_ERROR"


class EnvelopeError(Exception):
    def __init__(self, reason: ReasonCode):
        super().__init__("envelope rejected")
        self.reason = reason


@dataclass(frozen=True)
class ValidatedEnvelope:
    boundary: Boundary
    text: str = field(repr=False)
    language: str
    request_id: str
    policy_id: str

    @property
    def text_byte_len(self) -> int:
        return len(self.text.encode("utf-8"))


@dataclass(frozen=True)
class Decision:
    action: Action
    reason_codes: tuple[ReasonCode, ...]
    policy_version: str
    detector_versions: Mapping[str, str] = field(default_factory=dict)
    elapsed_ms: int = 0
    safe_text: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.action is Action.BLOCK and self.safe_text is not None:
            raise ValueError("BLOCK decisions carry no text")
        if self.action in (Action.ALLOW, Action.REDACT) and self.safe_text is None:
            raise ValueError("ALLOW/REDACT decisions require safe_text")

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "reason_codes": [r.value for r in self.reason_codes],
            "policy_version": self.policy_version,
            "detector_versions": dict(self.detector_versions),
            "elapsed_ms": self.elapsed_ms,
        }


def utf8_len(text: str) -> int:
    """UTF-8 byte length; unencodable text (e.g. lone surrogates) is invalid."""
    try:
        return len(text.encode("utf-8"))
    except UnicodeEncodeError:
        raise EnvelopeError(ReasonCode.INVALID_ENVELOPE) from None


def validate_envelope(data: Any, policy: Any) -> ValidatedEnvelope:
    if not isinstance(data, Mapping):
        raise EnvelopeError(ReasonCode.INVALID_ENVELOPE)
    if any(key not in ENVELOPE_KEYS for key in data):
        raise EnvelopeError(ReasonCode.INVALID_ENVELOPE)
    try:
        boundary = Boundary(data.get("boundary"))
    except ValueError:
        raise EnvelopeError(ReasonCode.INVALID_ENVELOPE) from None
    if data.get("language") != SUPPORTED_LANGUAGE:
        raise EnvelopeError(ReasonCode.UNSUPPORTED_LANGUAGE)
    text = data.get("text")
    if not isinstance(text, str) or not text.strip():
        raise EnvelopeError(ReasonCode.INVALID_ENVELOPE)
    max_bytes = getattr(policy, "max_text_bytes", MAX_TEXT_BYTES)
    if utf8_len(text) > max_bytes:
        raise EnvelopeError(ReasonCode.LIMIT_EXCEEDED)
    request_id = data.get("request_id")
    policy_id = data.get("policy_id")
    if not is_valid_request_id(request_id):
        raise EnvelopeError(ReasonCode.INVALID_ENVELOPE)
    if not is_valid_policy_id(policy_id):
        raise EnvelopeError(ReasonCode.INVALID_ENVELOPE)
    return ValidatedEnvelope(
        boundary=boundary,
        text=text,
        language=SUPPORTED_LANGUAGE,
        request_id=request_id,
        policy_id=policy_id,
    )


@dataclass
class RequestBudget:
    max_blocks: int = MAX_BLOCKS
    max_bytes: int = MAX_AGGREGATE_BYTES
    blocks_used: int = 0
    bytes_used: int = 0

    def consume(self, byte_len: int) -> None:
        if self.blocks_used + 1 > self.max_blocks:
            raise EnvelopeError(ReasonCode.LIMIT_EXCEEDED)
        if self.bytes_used + byte_len > self.max_bytes:
            raise EnvelopeError(ReasonCode.LIMIT_EXCEEDED)
        self.blocks_used += 1
        self.bytes_used += byte_len
