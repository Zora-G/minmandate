from __future__ import annotations

from copy import deepcopy
from typing import Any

from ap2.sdk.disclosure_metadata import sd_claims_to_disclose
from ap2.sdk.generated.open_checkout_mandate import (
    AllowedMerchants,
    LineItems,
    OpenCheckoutMandate,
)
from ap2.sdk.generated.open_payment_mandate import (
    AllowedPayees,
    AllowedPaymentInstruments,
    OpenPaymentMandate,
)


def _one_hot(length: int, selected: int) -> list[bool]:
    if selected < 0 or selected >= length:
        raise IndexError("selected disclosure index out of range")
    return [i == selected for i in range(length)]


def minimal_checkout_disclosures(
    model: OpenCheckoutMandate,
    merchant_id: str,
    tool_id: str | None,
) -> dict[str, Any]:
    """Select only the matching merchant and, when present, matching tool item.

    The shape is derived from the official SDK metadata rather than hard-coding
    private SD-JWT internals. Formal execution must fail if no matching
    disclosure exists.
    """
    claims = deepcopy(sd_claims_to_disclose(model) or {})
    constraint_claims = claims.get("constraints")
    if constraint_claims is None:
        return {}

    matched_merchant = False
    matched_tool = tool_id is None
    for idx, constraint in enumerate(model.constraints):
        if isinstance(constraint, AllowedMerchants):
            pos = next((i for i, m in enumerate(constraint.allowed) if m.id == merchant_id), None)
            if pos is None:
                raise ValueError(f"merchant {merchant_id} not present in AP2 open checkout mandate")
            constraint_claims[idx] = {"allowed": _one_hot(len(constraint.allowed), pos)}
            matched_merchant = True
        elif isinstance(constraint, LineItems):
            item_claims: dict[int, Any] = {}
            for req_idx, req in enumerate(constraint.items):
                pos = next((i for i, item in enumerate(req.acceptable_items) if item.id == tool_id), None)
                if pos is not None:
                    item_claims[req_idx] = {
                        "acceptable_items": _one_hot(len(req.acceptable_items), pos)
                    }
                    matched_tool = True
            constraint_claims[idx] = {"items": item_claims}

    if not matched_merchant or not matched_tool:
        raise ValueError("minimal checkout disclosure could not satisfy the selected call")
    return claims


def minimal_payment_disclosures(
    model: OpenPaymentMandate,
    merchant_id: str,
    instrument_id: str,
) -> dict[str, Any]:
    claims = deepcopy(sd_claims_to_disclose(model) or {})
    constraint_claims = claims.get("constraints")
    if constraint_claims is None:
        return {}

    matched_payee = False
    matched_instrument = False
    for idx, constraint in enumerate(model.constraints):
        if isinstance(constraint, AllowedPayees):
            pos = next((i for i, m in enumerate(constraint.allowed) if m.id == merchant_id), None)
            if pos is None:
                raise ValueError(f"payee {merchant_id} absent from AP2 payment mandate")
            constraint_claims[idx] = {"allowed": _one_hot(len(constraint.allowed), pos)}
            matched_payee = True
        elif isinstance(constraint, AllowedPaymentInstruments):
            pos = next((i for i, p in enumerate(constraint.allowed) if p.id == instrument_id), None)
            if pos is None:
                raise ValueError(f"instrument {instrument_id} absent from AP2 payment mandate")
            constraint_claims[idx] = {"allowed": _one_hot(len(constraint.allowed), pos)}
            matched_instrument = True

    if not matched_payee or not matched_instrument:
        raise ValueError("minimal payment disclosure could not satisfy the selected call")
    return claims
