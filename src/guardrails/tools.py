"""Host-owned deterministic tool authorization (example)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from .contracts import ReasonCode

CATALOG_TOOL = "catalog_lookup"
CATALOG_ITEMS = frozenset({"item-001", "item-002", "item-003"})
CATALOG_SCHEMA = frozenset({"item_id", "quantity"})


class ToolDenied(Exception):
    def __init__(self, detail: str = "denied"):
        super().__init__("tool denied")
        self.reason = ReasonCode.TOOL_DENIED
        self.detail = detail


@dataclass(frozen=True)
class ToolProposal:
    tool: str
    arguments: Mapping[str, Any]
    principal: str


@dataclass
class CatalogTool:
    calls: list = field(default_factory=list)

    def lookup(self, item_id: str, quantity: int = 1) -> dict:
        self.calls.append({"item_id": item_id, "quantity": quantity})
        return {"item_id": item_id, "quantity": quantity, "price_cents": 999}


def authorize_and_dispatch(
    proposal: Mapping[str, Any],
    trusted_principal: str,
    catalog: CatalogTool | None = None,
) -> dict:
    tool = proposal.get("tool") if isinstance(proposal, Mapping) else None
    arguments = proposal.get("arguments") if isinstance(proposal, Mapping) else None
    principal = proposal.get("principal") if isinstance(proposal, Mapping) else None
    if tool != CATALOG_TOOL:
        raise ToolDenied("unknown-tool")
    if principal != trusted_principal:
        raise ToolDenied("principal-mismatch")
    if not isinstance(arguments, Mapping):
        raise ToolDenied("bad-arguments")
    if set(arguments) - CATALOG_SCHEMA:
        raise ToolDenied("extra-argument")
    item_id = arguments.get("item_id")
    quantity = arguments.get("quantity", 1)
    if item_id not in CATALOG_ITEMS:
        raise ToolDenied("unauthorized-item")
    if not isinstance(quantity, int) or isinstance(quantity, bool):
        raise ToolDenied("bad-quantity")
    if not 1 <= quantity <= 10:
        raise ToolDenied("bad-quantity")
    tool_impl = catalog or CatalogTool()
    return tool_impl.lookup(item_id=item_id, quantity=quantity)
