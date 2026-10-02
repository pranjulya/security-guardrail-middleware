"""Strict local policy validation and immutable snapshot."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

from .contracts import (
    APPROVED_ENTITIES,
    INSPECTION_BUDGET_MS,
    MAX_AGGREGATE_BYTES,
    MAX_BLOCKS,
    MAX_TEXT_BYTES,
    SUPPORTED_LANGUAGE,
    ReasonCode,
)


class PolicyError(Exception):
    def __init__(self) -> None:
        super().__init__("policy invalid")
        self.reason = ReasonCode.POLICY_INVALID


_MANDATORY_RULE_IDS = frozenset({"block-direct-override", "block-exfiltration"})


@dataclass(frozen=True)
class PolicySnapshot:
    version: str
    digest: str
    entities: frozenset
    thresholds: dict
    rules: tuple
    max_text_bytes: int = MAX_TEXT_BYTES
    max_aggregate_bytes: int = MAX_AGGREGATE_BYTES
    max_blocks: int = MAX_BLOCKS
    inspection_budget_ms: int = INSPECTION_BUDGET_MS
    language: str = SUPPORTED_LANGUAGE

    def allows_entity(self, entity: str) -> bool:
        return entity in self.entities


def _digest(canonical: str) -> str:
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_policy(data: Any) -> PolicySnapshot:
    if not isinstance(data, Mapping):
        raise PolicyError()
    allowed_keys = {
        "version",
        "entities",
        "thresholds",
        "rules",
        "max_text_bytes",
        "max_aggregate_bytes",
        "max_blocks",
        "inspection_budget_ms",
        "language",
    }
    if any(k not in allowed_keys for k in data):
        raise PolicyError()
    version = data.get("version")
    entities = data.get("entities")
    thresholds = data.get("thresholds")
    rules = data.get("rules")
    if not isinstance(version, str) or not version:
        raise PolicyError()
    if not isinstance(entities, (list, tuple)) or not entities:
        raise PolicyError()
    if set(entities) - set(APPROVED_ENTITIES):
        raise PolicyError()
    if not isinstance(thresholds, Mapping):
        raise PolicyError()
    for entity, value in thresholds.items():
        if entity not in APPROVED_ENTITIES:
            raise PolicyError()
        if not isinstance(value, (int, float)) or not 0.0 <= value <= 1.0:
            raise PolicyError()
    if not isinstance(rules, (list, tuple)) or not rules:
        raise PolicyError()
    seen_ids = set()
    for rule in rules:
        if not isinstance(rule, Mapping):
            raise PolicyError()
        if set(rule) - {"id", "action"}:
            raise PolicyError()
        rule_id = rule.get("id")
        action = rule.get("action")
        if not isinstance(rule_id, str) or not rule_id:
            raise PolicyError()
        if action != "BLOCK":
            raise PolicyError()
        if rule_id in seen_ids:
            raise PolicyError()
        seen_ids.add(rule_id)
    if not _MANDATORY_RULE_IDS.issubset(seen_ids):
        raise PolicyError()
    max_text_bytes = data.get("max_text_bytes", MAX_TEXT_BYTES)
    max_aggregate_bytes = data.get("max_aggregate_bytes", MAX_AGGREGATE_BYTES)
    max_blocks = data.get("max_blocks", MAX_BLOCKS)
    budget = data.get("inspection_budget_ms", INSPECTION_BUDGET_MS)
    language = data.get("language", SUPPORTED_LANGUAGE)
    if (
        not isinstance(max_text_bytes, int)
        or max_text_bytes <= 0
        or max_text_bytes > MAX_TEXT_BYTES
    ):
        raise PolicyError()
    if (
        not isinstance(max_aggregate_bytes, int)
        or max_aggregate_bytes <= 0
        or max_aggregate_bytes > MAX_AGGREGATE_BYTES
    ):
        raise PolicyError()
    if not isinstance(max_blocks, int) or max_blocks <= 0 or max_blocks > MAX_BLOCKS:
        raise PolicyError()
    if (
        not isinstance(budget, int)
        or budget <= 0
        or budget > INSPECTION_BUDGET_MS
    ):
        raise PolicyError()
    if language != SUPPORTED_LANGUAGE:
        raise PolicyError()
    canonical = json.dumps(
        {
            "version": version,
            "entities": sorted(entities),
            "thresholds": {k: thresholds[k] for k in sorted(thresholds)},
            "rules": sorted(r["id"] for r in rules),
            "max_text_bytes": max_text_bytes,
            "max_aggregate_bytes": max_aggregate_bytes,
            "max_blocks": max_blocks,
            "inspection_budget_ms": budget,
            "language": language,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return PolicySnapshot(
        version=version,
        digest=_digest(canonical),
        entities=frozenset(entities),
        thresholds=dict(thresholds),
        rules=tuple(sorted(seen_ids)),
        max_text_bytes=max_text_bytes,
        max_aggregate_bytes=max_aggregate_bytes,
        max_blocks=max_blocks,
        inspection_budget_ms=budget,
        language=language,
    )


DEFAULT_POLICY = {
    "version": "v1",
    "entities": sorted(APPROVED_ENTITIES),
    "thresholds": {e: (0.4 if e == "PHONE_NUMBER" else 0.5) for e in sorted(APPROVED_ENTITIES)},
    "rules": [
        {"id": "block-direct-override", "action": "BLOCK"},
        {"id": "block-exfiltration", "action": "BLOCK"},
    ],
}
