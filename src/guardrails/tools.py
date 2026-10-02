"""Host-owned deterministic tool authorization (example catalog tool).

Review 02 (M7):

* Authorization uses only host session state. A model proposal carries
  ``tool`` and ``arguments`` and nothing else; a proposal that tries to name a
  principal is refused (it is a spoofing attempt, not an input).
* Per-principal entitlements (``Entitlements``) decide which items a session
  may look up; argument values are type-checked (no ``TypeError`` on lists or
  dicts).
* ``ToolBudget`` enforces ``max_tool_invocations`` per request.
* Denial details come from a closed vocabulary so they are safe to audit.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .contracts import ReasonCode

CATALOG_TOOL = "catalog_lookup"
CATALOG_ITEMS = frozenset({"item-001", "item-002", "item-003"})
CATALOG_SCHEMA = frozenset({"item_id", "quantity"})
PROPOSAL_KEYS = frozenset({"tool", "arguments"})

DENIAL_DETAILS = frozenset(
    {
        "bad-proposal",
        "model-supplied-principal",
        "unknown-tool",
        "no-session-principal",
        "bad-arguments",
        "extra-argument",
        "unauthorized-item",
        "bad-quantity",
        "tool-budget-exhausted",
        "audit-error",
        "denied",
    }
)

# principal -> items that principal may look up
Entitlements = Mapping[str, frozenset[str]]


class ToolDenied(Exception):
    def __init__(self, detail: str = "denied"):
        super().__init__("tool denied")
        self.reason = ReasonCode.TOOL_DENIED
        self.detail = detail if detail in DENIAL_DETAILS else "denied"


@dataclass(frozen=True)
class ToolProposal:
    """What a model may propose. The principal is never part of it."""

    tool: str
    arguments: Mapping[str, Any]


@dataclass(frozen=True)
class AuthorizedCall:
    tool: str
    item_id: str
    quantity: int


@dataclass
class ToolBudget:
    """Per-request cap on tool invocations (thread-safe)."""

    max_invocations: int = 1
    used: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def consume(self) -> None:
        with self._lock:
            if self.used >= self.max_invocations:
                raise ToolDenied("tool-budget-exhausted")
            self.used += 1


@dataclass
class CatalogTool:
    calls: list[dict[str, Any]] = field(default_factory=list)

    def lookup(self, item_id: str, quantity: int = 1) -> dict[str, Any]:
        self.calls.append({"item_id": item_id, "quantity": quantity})
        return {"item_id": item_id, "quantity": quantity, "price_cents": 999}


def authorize(
    proposal: object,
    *,
    session_principal: str,
    entitlements: Entitlements | None = None,
) -> AuthorizedCall:
    """Pure authorization: no side effects. Raises ToolDenied."""
    if not isinstance(proposal, Mapping):
        raise ToolDenied("bad-proposal")
    if "principal" in proposal:
        raise ToolDenied("model-supplied-principal")
    if set(proposal) - PROPOSAL_KEYS or "tool" not in proposal:
        raise ToolDenied("bad-proposal")
    if proposal.get("tool") != CATALOG_TOOL:
        raise ToolDenied("unknown-tool")
    if not isinstance(session_principal, str) or not session_principal:
        raise ToolDenied("no-session-principal")
    arguments = proposal.get("arguments")
    if not isinstance(arguments, Mapping):
        raise ToolDenied("bad-arguments")
    if set(arguments) - CATALOG_SCHEMA:
        raise ToolDenied("extra-argument")
    item_id = arguments.get("item_id")
    quantity = arguments.get("quantity", 1)
    if type(item_id) is not str:
        raise ToolDenied("unauthorized-item")
    allowed = CATALOG_ITEMS if entitlements is None else entitlements.get(session_principal)
    if not allowed or item_id not in allowed or item_id not in CATALOG_ITEMS:
        raise ToolDenied("unauthorized-item")
    if type(quantity) is not int or not 1 <= quantity <= 10:
        raise ToolDenied("bad-quantity")
    return AuthorizedCall(tool=CATALOG_TOOL, item_id=item_id, quantity=quantity)


def authorize_and_dispatch(
    proposal: object,
    *,
    session_principal: str,
    catalog: CatalogTool | None = None,
    entitlements: Entitlements | None = None,
    budget: ToolBudget | None = None,
) -> dict[str, Any]:
    """Authorize with host session state only, charge the budget, dispatch once."""
    call = authorize(proposal, session_principal=session_principal, entitlements=entitlements)
    if budget is not None:
        budget.consume()
    tool_impl = catalog or CatalogTool()
    return tool_impl.lookup(item_id=call.item_id, quantity=call.quantity)
