"""AP2 adapter for the formal AgentDojo simulated merchants.

The adapter is deliberately a protocol boundary: it translates the already
quoted paid call into AP2 objects and delegates execution to AgentDojo's
existing ``FunctionsRuntime``.  No merchant fixture or business operation is
implemented here.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

from experiments.adapters.ap2_money import nanos_to_ap2_minor_units


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _opaque_id(prefix: str, value: Any) -> str:
    digest = hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()[:32]
    return f"{prefix}-{digest}"


# Registry for every field added by this adapter.  Harness identifiers are
# intentionally metadata-only and are never copied into AP2 model payloads.
AP2_ADAPTER_FIELD_REGISTRY: tuple[dict[str, str], ...] = (
    {"field": "merchant.id/name/website", "source": "commerce", "scope": "merchant"},
    {"field": "checkout.id/line_item.id", "source": "SDK", "scope": "call"},
    {"field": "checkout_jwt", "source": "SDK", "scope": "call"},
    {"field": "payment_instrument", "source": "fixture", "scope": "call"},
    {"field": "settlement_mode", "source": "fixture", "scope": "call"},
    {"field": "workflow_id/task_id/condition/seed/run_id", "source": "harness", "scope": "metadata-only"},
    {"field": "call_id", "source": "harness", "scope": "metadata-only"},
)


def formal_merchant_metadata(policy_tools: Mapping[str, Mapping[str, Mapping[str, Any]]]) -> dict[str, dict[str, str]]:
    """Build names from the frozen formal paid-tool policy, not a toy store."""
    result: dict[str, dict[str, str]] = {}
    for tools in policy_tools.values():
        for rule in tools.values():
            if not bool(rule.get("paid")):
                continue
            merchant_id = str(rule["merchant_id"])
            result.setdefault(
                merchant_id,
                {
                    "name": merchant_id,
                    "website": f"https://{merchant_id}.local.invalid",
                },
            )
    return result


@dataclass(frozen=True, slots=True)
class NoFundsAssertions:
    external_payment_requests: int = 0
    network_transactions: int = 0
    funds_moved: bool = False
    settlement_mode: str = "local-no-funds"

    def to_dict(self) -> dict[str, Any]:
        return {
            "external_payment_requests": self.external_payment_requests,
            "network_transactions": self.network_transactions,
            "funds_moved": self.funds_moved,
            "settlement_mode": self.settlement_mode,
        }

    def assert_safe(self) -> None:
        if self.to_dict() != NoFundsAssertions().to_dict():
            raise AssertionError("AP2 LocalNoFundsRail invariant violated")


class LocalNoFundsRail:
    """Rail marker used by AP2; it cannot contact a provider or move funds."""

    def __init__(self, payment_instrument: Any | None = None) -> None:
        from ap2.sdk.generated.types.payment_instrument import PaymentInstrument

        self.payment_instrument = payment_instrument or PaymentInstrument(
            id="local-no-funds-1",
            type="local_no_funds",
            description="Deterministic formal evaluation instrument; no funds move.",
        )
        self.assertions = NoFundsAssertions()
        self.assertions.assert_safe()

    def create_and_verify_receipts(self, **kwargs: Any):
        # Reuse the official receipt implementation; only the reference/order
        # identifiers are supplied by the protocol engine.
        from ap2_baseline.adapters import LocalRailAdapter

        self.assertions.assert_safe()
        result = LocalRailAdapter(self.payment_instrument).create_and_verify_receipts(**kwargs)
        self.assertions.assert_safe()
        return result


class AP2CommerceAdapter:
    """Official AP2 bridge around the current simulated merchant runtime."""

    def __init__(self, *, merchant_metadata: Mapping[str, Mapping[str, Any]] | None = None) -> None:
        self.merchant_metadata = dict(merchant_metadata or {})
        # The SDK adapter performs only checkout serialization/signing.  Its
        # business execution remains ``FunctionsRuntime.run_function``.
        self.checkout_adapter = FormalMerchantCheckoutAdapter(self.merchant_metadata)
        self.rail = LocalNoFundsRail()

    def engine_kwargs(self) -> dict[str, Any]:
        return {
            "tool_to_checkout_adapter": self.checkout_adapter,
            "rail_adapter": self.rail,
        }


class FormalMerchantCheckoutAdapter:
    """Serialize a quote using the official SDK checkout types.

    This class does not inspect or mutate an AgentDojo environment.  The
    existing runtime invokes the original merchant function only after AP2
    authorization succeeds.
    """

    def __init__(self, merchant_metadata: Mapping[str, Mapping[str, Any]]) -> None:
        self.merchant_metadata = dict(merchant_metadata)

    def build_signed_checkout(self, call: Any, approval: Any, merchant_key: Any):
        from datetime import UTC, datetime
        from ap2.sdk.generated.types.checkout import Checkout, Status
        from ap2.sdk.generated.types.item import Item as CheckoutItem
        from ap2.sdk.generated.types.line_item import LineItem
        from ap2.sdk.generated.types.link import Link
        from ap2.sdk.generated.types.merchant import Merchant
        from ap2.sdk.generated.types.total import Total
        from ap2.sdk.jwt_helper import create_jwt
        from ap2.sdk.utils import compute_sha256_b64url
        from ap2_baseline.adapters import SignedCheckout

        merchant_id = str(call.quote.merchant.id)
        info = self.merchant_metadata.get(merchant_id, {})
        merchant = Merchant(
            id=merchant_id,
            name=str(info.get("name") or call.quote.merchant.name or merchant_id),
            website=(str(info["website"]) if info.get("website") else call.quote.merchant.website),
        )
        content_key = {
            "merchant": merchant_id,
            "tool": call.tool_id,
            "title": call.title,
            "amount": call.quote.amount_minor,
            "currency": call.quote.currency,
            "nonce": call.quote.nonce,
            "arguments": call.arguments,
        }
        line_id = _opaque_id("line", content_key)
        checkout_id = _opaque_id("checkout", content_key)
        totals = [
            Total(type="subtotal", amount=call.quote.amount_minor),
            Total(type="total", amount=call.quote.amount_minor),
        ]
        line = LineItem(
            id=line_id,
            item=CheckoutItem(id=call.tool_id, title=call.title, price=call.quote.amount_minor),
            quantity=1,
            totals=totals,
        )
        checkout = Checkout(
            id=checkout_id,
            merchant=merchant,
            line_items=[line],
            status=Status.ready_for_complete,
            currency=call.quote.currency,
            totals=totals,
            links=[Link(type="privacy_policy", url="https://local.invalid/privacy", title="Formal simulated merchant")],
            messages=None,
            expires_at=datetime.fromtimestamp(approval.expires_at, tz=UTC),
        )
        checkout_jwt = create_jwt(
            header={"alg": "ES256", "typ": "JWT", "kid": f"merchant-{merchant_id}"},
            payload=checkout.model_dump(mode="json", exclude_none=True),
            private_key=merchant_key,
        )
        return SignedCheckout(
            checkout=checkout,
            checkout_jwt=checkout_jwt,
            checkout_hash=compute_sha256_b64url(checkout_jwt),
        )


__all__ = [
    "AP2_ADAPTER_FIELD_REGISTRY",
    "AP2CommerceAdapter",
    "FormalMerchantCheckoutAdapter",
    "LocalNoFundsRail",
    "NoFundsAssertions",
    "formal_merchant_metadata",
]
