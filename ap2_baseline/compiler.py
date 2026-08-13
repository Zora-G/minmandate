from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
import math
import time
from typing import Iterable

from ap2.sdk.generated.open_checkout_mandate import (
    AllowedMerchants,
    Item,
    LineItemRequirements,
    LineItems,
    OpenCheckoutMandate,
)
from ap2.sdk.generated.open_payment_mandate import (
    AgentRecurrence,
    AllowedPayees,
    AllowedPaymentInstruments,
    AmountRange,
    Budget,
    Frequency,
    OpenPaymentMandate,
    PaymentReference,
)
from ap2.sdk.generated.types.merchant import Merchant
from ap2.sdk.generated.types.payment_instrument import PaymentInstrument
from ap2.sdk.mandate import MandateClient
from ap2.sdk.utils import compute_sha256_b64url

from .domain import AP2Profile, NeutralApproval, PaidToolCall
from .keys import KeyBundle, public_jwk_dict


def _budget_major_units(minor_units: int, minor_exponent: int = 2) -> float:
    """Encode AP2's float Budget.max without silently changing its value."""
    if not isinstance(minor_units, int) or minor_units <= 0:
        raise ValueError("budget minor units must be a positive integer")
    scale = 10**minor_exponent
    candidate = float(Decimal(minor_units) / Decimal(scale))
    if int(candidate * scale) == minor_units:
        return candidate
    adjusted = math.nextafter(candidate, math.inf)
    if int(adjusted * scale) == minor_units:
        return adjusted
    raise ValueError(
        "AP2 Budget.max cannot exactly encode canonical minor units: "
        f"{minor_units} at exponent {minor_exponent}"
    )


@dataclass(slots=True)
class AP2MandatePair:
    pair_id: str
    open_checkout_model: OpenCheckoutMandate
    open_payment_model: OpenPaymentMandate
    open_checkout_token: str
    open_payment_token: str
    open_checkout_hash: str
    allowed_tool_ids: frozenset[str]
    allowed_merchant_ids: frozenset[str]
    enforces_line_items: bool
    max_occurrences: int
    budget_minor: int
    per_call_max_minor: int
    use_count: int = 0
    spent_minor: int = 0
    accepted_transactions: dict[str, int] = field(default_factory=dict)

    def can_select(self, call: PaidToolCall) -> bool:
        if call.quote.merchant.id not in self.allowed_merchant_ids:
            return False
        if self.enforces_line_items and call.tool_id not in self.allowed_tool_ids:
            return False
        return True


class AP2Compiler:
    def __init__(
        self,
        profile: AP2Profile,
        keys: KeyBundle,
        payment_instrument: PaymentInstrument,
        now_fn=time.time,
    ) -> None:
        self.profile = profile
        self.keys = keys
        self.instrument = payment_instrument
        self.client = MandateClient()
        self.now_fn = now_fn

    def issue(self, approval: NeutralApproval) -> list[AP2MandatePair]:
        if self.profile is AP2Profile.NATIVE:
            return [self._issue_native(approval)]
        return [self._issue_common(approval, tool) for tool in approval.tools]

    def _issue_native(self, approval: NeutralApproval) -> AP2MandatePair:
        merchants = self._merchants(
            approval.allowed_merchants
            if approval.allowed_merchants is not None
            else (t.merchant for t in approval.tools)
        )
        tool_ids = frozenset(t.tool_id for t in approval.tools)
        return self._issue_pair(
            pair_id=f"{approval.task_id}:ap2-native",
            approval=approval,
            merchants=merchants,
            tool_ids=tool_ids,
            include_line_items=False,
            max_occurrences=approval.max_calls,
            budget_minor=approval.total_budget_minor,
            per_call_max_minor=approval.per_call_max_minor,
        )

    def _issue_common(self, approval: NeutralApproval, tool) -> AP2MandatePair:
        return self._issue_pair(
            pair_id=f"{approval.task_id}:ap2-common:{tool.tool_id}",
            approval=approval,
            merchants=self._merchants([tool.merchant]),
            tool_ids=frozenset([tool.tool_id]),
            include_line_items=True,
            max_occurrences=tool.max_calls,
            budget_minor=tool.allocated_budget_minor,
            per_call_max_minor=tool.per_call_max_minor,
            tool_titles={tool.tool_id: tool.title},
        )

    @staticmethod
    def _merchants(specs: Iterable) -> list[Merchant]:
        by_id = {s.id: Merchant(id=s.id, name=s.name, website=s.website) for s in specs}
        return [by_id[k] for k in sorted(by_id)]

    def _issue_pair(
        self,
        *,
        pair_id: str,
        approval: NeutralApproval,
        merchants: list[Merchant],
        tool_ids: frozenset[str],
        include_line_items: bool,
        max_occurrences: int,
        budget_minor: int,
        per_call_max_minor: int,
        tool_titles: dict[str, str] | None = None,
    ) -> AP2MandatePair:
        now = int(self.now_fn())
        constraints = [AllowedMerchants(allowed=merchants)]
        if include_line_items:
            assert tool_titles is not None
            # One requirement with one acceptable tool item. Each paid tool call is
            # represented as quantity one in the merchant checkout object.
            items = [Item(id=tid, title=tool_titles[tid]) for tid in sorted(tool_ids)]
            constraints.append(
                LineItems(
                    items=[
                        LineItemRequirements(
                            id=f"approved-tool:{pair_id}",
                            acceptable_items=items,
                            quantity=1,
                        )
                    ]
                )
            )

        open_checkout = OpenCheckoutMandate(
            constraints=constraints,
            cnf={"jwk": public_jwk_dict(self.keys.agent)},
            iat=now,
            exp=approval.expires_at,
        )
        open_checkout_token = self.client.create(
            payloads=[open_checkout], issuer_key=self.keys.trusted_surface
        )
        # AP2 v0.2 does not expose one canonical helper for the open-mandate
        # reference in the SDK. We freeze SHA-256 over the exact compact token
        # bytes and record this choice in the conformance manifest.
        open_checkout_hash = compute_sha256_b64url(open_checkout_token)

        open_payment = OpenPaymentMandate(
            constraints=[
                AmountRange(currency=approval.currency, min=1, max=per_call_max_minor),
                AllowedPayees(allowed=merchants),
                AgentRecurrence(
                    frequency=Frequency.ON_DEMAND,
                    max_occurrences=max_occurrences,
                ),
                Budget(max=_budget_major_units(budget_minor), currency=approval.currency),
                PaymentReference(conditional_transaction_id=open_checkout_hash),
                AllowedPaymentInstruments(allowed=[self.instrument]),
            ],
            cnf={"jwk": public_jwk_dict(self.keys.agent)},
            iat=now,
            exp=approval.expires_at,
        )
        open_payment_token = self.client.create(
            payloads=[open_payment], issuer_key=self.keys.trusted_surface
        )
        return AP2MandatePair(
            pair_id=pair_id,
            open_checkout_model=open_checkout,
            open_payment_model=open_payment,
            open_checkout_token=open_checkout_token,
            open_payment_token=open_payment_token,
            open_checkout_hash=open_checkout_hash,
            allowed_tool_ids=tool_ids,
            allowed_merchant_ids=frozenset(m.id for m in merchants),
            enforces_line_items=include_line_items,
            max_occurrences=max_occurrences,
            budget_minor=budget_minor,
            per_call_max_minor=per_call_max_minor,
        )


class AP2MandatePool:
    def __init__(self, pairs: list[AP2MandatePair]) -> None:
        if not pairs:
            raise ValueError("at least one AP2 mandate pair is required")
        self.pairs = pairs

    def select(self, call: PaidToolCall) -> AP2MandatePair | None:
        candidates = [p for p in self.pairs if p.can_select(call)]
        return sorted(candidates, key=lambda p: p.pair_id)[0] if candidates else None
