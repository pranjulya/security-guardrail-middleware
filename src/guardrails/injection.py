"""Bounded injection-risk rules with stable rule IDs."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Iterable, Optional, Tuple

MAX_NORMALIZED_CHARS = 16 * 1024


@dataclass(frozen=True)
class InjectionFinding:
    rule_id: str
    matched: str


_RULE_PATTERNS: Tuple[Tuple[str, str], ...] = (
    ("block-direct-override", r"ignore\s+(all\s+)?(prior|previous)\s+instructions"),
    ("block-direct-override", r"disregard\s+(all\s+)?(prior|previous)\s+instructions"),
    ("block-direct-override", r"you\s+are\s+now\s+"),
    ("block-direct-override", r"new\s+system\s+instruction"),
    ("block-exfiltration", r"reveal\s+(the\s+)?(admin|secret|system)\s+\w+"),
    ("block-exfiltration", r"exfiltrat\w*"),
    ("block-exfiltration", r"send\s+\w+\s+to\s+(an?\s+)?external\s+\w+"),
    ("block-exfiltration", r"(delete|drop|destroy)\s+(all\s+)?records"),
)

_COMPILED = tuple((rid, re.compile(p, re.IGNORECASE)) for rid, p in _RULE_PATTERNS)


def normalized_view(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    folded = normalized.casefold()
    collapsed = re.sub(r"\s+", " ", folded)
    return collapsed[:MAX_NORMALIZED_CHARS]


def detect(text: str, rule_ids: Optional[Iterable[str]] = None) -> Tuple[InjectionFinding, ...]:
    wanted = set(rule_ids) if rule_ids is not None else None
    findings: list[InjectionFinding] = []
    for view in (text, normalized_view(text)):
        for rule_id, pattern in _COMPILED:
            if wanted is not None and rule_id not in wanted:
                continue
            match = pattern.search(view)
            if match:
                findings.append(InjectionFinding(rule_id=rule_id, matched=match.group(0)[:200]))
                break
        if findings:
            break
    seen: dict[str, InjectionFinding] = {}
    for finding in findings:
        seen.setdefault(finding.rule_id, finding)
    return tuple(seen.values())


def is_blocked(text: str, rule_ids: Optional[Iterable[str]] = None) -> bool:
    return bool(detect(text, rule_ids))
