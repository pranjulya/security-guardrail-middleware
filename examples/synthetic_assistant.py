"""Fake-model synthetic assistant flow (example, not a service)."""

from __future__ import annotations

from .contracts import ReasonCode
from .injection import detect
from .pii import DetectorFailure, PiiRedactor
from .policy import PolicySnapshot
from .tools import CatalogTool, ToolDenied, authorize_and_dispatch


def run_turn(
    user_text: str,
    policy: PolicySnapshot,
    trusted_principal: str,
    redactor: PiiRedactor,
    catalog: CatalogTool | None = None,
    model_reply: str = "Here is your catalog summary.",
    proposed_tool: dict | None = None,
) -> dict:
    findings = detect(user_text, policy.rules)
    if findings:
        return {"action": "BLOCK", "reason": ReasonCode.INJECTION_RULE.value,
                "rule_ids": [f.rule_id for f in findings]}
    try:
        safe_text, _, _ = redactor.redact(user_text)
    except DetectorFailure:
        return {"action": "BLOCK", "reason": ReasonCode.DETECTOR_ERROR.value}
    if safe_text != user_text:
        return {"action": "REDACT", "safe_text": safe_text}
    tool_result = None
    if proposed_tool is not None:
        try:
            tool_result = authorize_and_dispatch(
                proposed_tool, trusted_principal, catalog)
        except ToolDenied as exc:
            return {"action": "BLOCK", "reason": exc.reason.value, "detail": exc.detail}
    return {"action": "ALLOW", "safe_text": model_reply, "tool_result": tool_result}
