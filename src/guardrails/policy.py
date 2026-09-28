"""Strict local policy validation and immutable snapshot."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from .contracts import (
    APPROVED_ENTITIES,
    DEFAULT_ENTITIES,
    INSPECTION_BUDGET_MS,
    MAX_AGGREGATE_BYTES,
    MAX_BLOCKS,
    MAX_TEXT_BYTES,
    SUPPORTED_LANGUAGE,
    ReasonCode,
)
from .injection import RULE_ORDER


class PolicyError(Exception):
    def __init__(self) -> None:
        super().__init__("policy invalid")
        self.reason = ReasonCode.POLICY_INVALID


_MANDATORY_RULE_IDS = frozenset({"block-direct-override", "block-exfiltration"})


@dataclass(frozen=True)
class PolicySnapshot:
    version: str
    digest: str
    entities: frozenset[str]
    thresholds: Mapping[str, float]
    rules: tuple[str, ...]
    max_text_bytes: int = MAX_TEXT_BYTES
    max_aggregate_bytes: int = MAX_AGGREGATE_BYTES
    max_blocks: int = MAX_BLOCKS
    inspection_budget_ms: int = INSPECTION_BUDGET_MS
    language: str = SUPPORTED_LANGUAGE

    def allows_entity(self, entity: str) -> bool:
        return entity in self.entities

    @property
    def policy_id(self) -> str:
        """Version@digest[:16] — the binding hosts must put in envelopes (M4)."""
        return f"{self.version}@{self.digest[:16]}"


def _digest(canonical: str) -> str:
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


KNOWN_RULE_IDS = frozenset(RULE_ORDER)
_VERSION_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,32}")
_ALLOWED_KEYS = frozenset(
    {
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
)


def _strict_int(value: object, upper: int) -> int:
    # bool is a subclass of int: reject it explicitly (review 02, M5).
    if type(value) is not int or not 0 < value <= upper:
        raise PolicyError()
    return value


def _strict_threshold(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or not 0.0 <= value <= 1.0
    ):
        raise PolicyError()
    return float(value)


def load_policy(data: Any) -> PolicySnapshot:
    """Validate ``data`` and return a snapshot. Raises only PolicyError."""
    try:
        return _load_policy(data)
    except PolicyError:
        raise
    except Exception as exc:
        raise PolicyError() from exc


def _load_policy(data: Any) -> PolicySnapshot:
    if not isinstance(data, Mapping):
        raise PolicyError()
    if any(k not in _ALLOWED_KEYS for k in data):
        raise PolicyError()
    version = data.get("version")
    entities = data.get("entities")
    thresholds = data.get("thresholds")
    rules = data.get("rules")
    if not isinstance(version, str) or not _VERSION_PATTERN.fullmatch(version):
        raise PolicyError()
    if not isinstance(entities, (list, tuple)) or not entities:
        raise PolicyError()
    if not all(isinstance(e, str) for e in entities) or len(set(entities)) != len(entities):
        raise PolicyError()
    if set(entities) - set(APPROVED_ENTITIES):
        raise PolicyError()
    if not isinstance(thresholds, Mapping):
        raise PolicyError()
    # Exactly one threshold per enabled entity: no silent 0.0 default, no dead
    # thresholds for disabled entities.
    if set(thresholds) != set(entities):
        raise PolicyError()
    clean_thresholds = {entity: _strict_threshold(v) for entity, v in thresholds.items()}
    if not isinstance(rules, (list, tuple)) or not rules:
        raise PolicyError()
    seen_ids: set[str] = set()
    for rule in rules:
        if not isinstance(rule, Mapping):
            raise PolicyError()
        if set(rule) - {"id", "action"}:
            raise PolicyError()
        rule_id = rule.get("id")
        action = rule.get("action")
        # Unknown rule ids would silently do nothing; reject typos.
        if not isinstance(rule_id, str) or rule_id not in KNOWN_RULE_IDS:
            raise PolicyError()
        if action != "BLOCK":
            raise PolicyError()
        if rule_id in seen_ids:
            raise PolicyError()
        seen_ids.add(rule_id)
    if not _MANDATORY_RULE_IDS.issubset(seen_ids):
        raise PolicyError()
    max_text_bytes = _strict_int(data.get("max_text_bytes", MAX_TEXT_BYTES), MAX_TEXT_BYTES)
    max_aggregate_bytes = _strict_int(
        data.get("max_aggregate_bytes", MAX_AGGREGATE_BYTES), MAX_AGGREGATE_BYTES
    )
    max_blocks = _strict_int(data.get("max_blocks", MAX_BLOCKS), MAX_BLOCKS)
    budget = _strict_int(
        data.get("inspection_budget_ms", INSPECTION_BUDGET_MS), INSPECTION_BUDGET_MS
    )
    language = data.get("language", SUPPORTED_LANGUAGE)
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
        thresholds=MappingProxyType(clean_thresholds),
        rules=tuple(sorted(seen_ids)),
        max_text_bytes=max_text_bytes,
        max_aggregate_bytes=max_aggregate_bytes,
        max_blocks=max_blocks,
        inspection_budget_ms=budget,
        language=language,
    )


DEFAULT_POLICY = {
    "version": "v1.1",
    "entities": sorted(DEFAULT_ENTITIES),
    "thresholds": {e: (0.4 if e == "PHONE_NUMBER" else 0.5) for e in sorted(DEFAULT_ENTITIES)},
    "rules": [
        {"id": "block-direct-override", "action": "BLOCK"},
        {"id": "block-exfiltration", "action": "BLOCK"},
    ],
}
