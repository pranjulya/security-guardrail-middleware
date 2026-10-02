"""Review 02 / M5: policy validation rejects every malformed input with PolicyError."""

from __future__ import annotations

import pytest

from guardrails.policy import DEFAULT_POLICY, PolicyError, load_policy

D = DEFAULT_POLICY


def with_(**kw: object) -> dict:
    return {**D, **kw}


BAD = {
    "bool max_blocks": with_(max_blocks=True),
    "bool max_text_bytes": with_(max_text_bytes=True),
    "bool budget": with_(inspection_budget_ms=True),
    "float max_blocks": with_(max_blocks=2.0),
    "bool threshold": with_(thresholds={**D["thresholds"], "PERSON": True}),
    "nan threshold": with_(thresholds={**D["thresholds"], "PERSON": float("nan")}),
    "inf threshold": with_(thresholds={**D["thresholds"], "PERSON": float("inf")}),
    "string threshold": with_(thresholds={**D["thresholds"], "PERSON": "0.5"}),
    "unhashable entity": with_(entities=[["PERSON"]]),
    "dict entity": with_(entities=[{"x": 1}]),
    "duplicate entity": with_(entities=[*D["entities"], "PERSON"]),
    "unknown rule id": with_(rules=[*D["rules"], {"id": "block-typo", "action": "BLOCK"}]),
    "unhashable rule id": with_(rules=[*D["rules"], {"id": ["x"], "action": "BLOCK"}]),
    "threshold for disabled entity": with_(
        entities=["PERSON"], thresholds={"PERSON": 0.5, "CREDIT_CARD": 0.9}
    ),
    "missing threshold": with_(thresholds={"PERSON": 0.5}),
    "version with spaces": with_(version="v1 1"),
    "version too long": with_(version="v" * 33),
    "non-str version": with_(version=1.1),
    "rules not a list": with_(rules="block-direct-override"),
    "thresholds list": with_(thresholds=[("PERSON", 0.5)]),
    "unhashable key in thresholds": with_(thresholds={("a",): 0.5}),
    "top-level list": [D],
}


@pytest.mark.parametrize("name", sorted(BAD))
def test_malformed_policies_raise_policy_error(name: str) -> None:
    with pytest.raises(PolicyError):
        load_policy(BAD[name])


def test_valid_policies_still_load() -> None:
    snap = load_policy(D)
    assert snap.version == "v1.1"
    assert snap.max_blocks == 4 and type(snap.max_blocks) is int
    narrow = load_policy(
        with_(version="v-narrow", entities=["PERSON"], thresholds={"PERSON": 1}, max_blocks=2)
    )
    assert narrow.thresholds["PERSON"] == 1.0 and narrow.max_blocks == 2


def test_default_digest_is_stable() -> None:
    """Stricter validation must not change the digest of the approved policy."""
    assert (
        load_policy(D).digest == "ae230164b8b681685526930bd21a258e6320870773b0a56486e8a7eab3d00fb1"
    )
