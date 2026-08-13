"""Explicit adapters for local AP2 v0.2 evaluation roles and commerce data.

The AP2 engine consumes only these adapter interfaces. AgentDojo-specific
translation belongs in a harness-owned ``ToolToCheckoutAdapter``; the
deterministic implementations here are local no-funds smoke fixtures.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from datetime import UTC, datetime
from typing import Protocol

from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.generated.types.checkout import Checkout, Status
from ap2.sdk.generated.types.item import Item as CheckoutItem
from ap2.sdk.generated.types.line_item import LineItem
from ap2.sdk.generated.types.link import Link
from ap2.sdk.generated.types.merchant import Merchant
from ap2.sdk.generated.types.payment_instrument import PaymentInstrument
from ap2.sdk.generated.types.total import Total
from ap2.sdk.jwt_helper import create_jwt
from ap2.sdk.receipt_wrapper import ReceiptClient
from ap2.sdk.utils import compute_sha256_b64url
from jwcrypto.jwk import JWK

from .domain import NeutralApproval, PaidToolCall
from .keys import KeyBundle


def _opaque_id(prefix: str, value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"{prefix}-{hashlib.sha256(encoded.encode('utf-8')).hexdigest()[:32]}"


@dataclass(frozen=True, slots=True)
class SignedCheckout:
    checkout: Checkout
    checkout_jwt: str
    checkout_hash: str


@dataclass(frozen=True, slots=True)
class ReceiptArtifacts:
    checkout_receipt_jwt: str
    payment_receipt_jwt: str
    errors: tuple[str, ...]


class ToolToCheckoutAdapter(Protocol):
    """Maps a confirmed paid call and frozen quote into a merchant checkout."""

    def build_signed_checkout(
        self,
        call: PaidToolCall,
        approval: NeutralApproval,
        merchant_key: JWK,
    ) -> SignedCheckout: ...


class RoleAdapter(Protocol):
    """Provides local keys and audiences for AP2 protocol roles."""

    @property
    def trusted_surface_public_key(self) -> JWK: ...

    @property
    def agent_private_key(self) -> JWK: ...

    @property
    def mpp_private_key(self) -> JWK: ...

    def merchant_private_key(self, merchant_id: str) -> JWK: ...

    def merchant_audience(self, merchant_id: str) -> str: ...

    @property
    def cp_audience(self) -> str: ...


class LocalRoleAdapter:
    """Deterministic local role map; replace it at the harness boundary."""

    def __init__(self, keys: KeyBundle) -> None:
        self._keys = keys

    @property
    def trusted_surface_public_key(self) -> JWK:
        return self._keys.trusted_surface

    @property
    def agent_private_key(self) -> JWK:
        return self._keys.agent

    @property
    def mpp_private_key(self) -> JWK:
        return self._keys.mpp

    def merchant_private_key(self, merchant_id: str) -> JWK:
        return self._keys.merchants[merchant_id]

    def merchant_audience(self, merchant_id: str) -> str:
        return f"urn:minmandate:ap2:merchant:{merchant_id}"

    @property
    def cp_audience(self) -> str:
        return "urn:minmandate:ap2:cp"


class DeterministicToolToCheckoutAdapter:
    """Local fixture mapping; the production bridge supplies its own mapping."""

    def build_signed_checkout(
        self,
        call: PaidToolCall,
        approval: NeutralApproval,
        merchant_key: JWK,
    ) -> SignedCheckout:
        merchant = Merchant(
            id=call.quote.merchant.id,
            name=call.quote.merchant.name,
            website=call.quote.merchant.website,
        )
        totals = [
            Total(type="subtotal", amount=call.quote.amount_minor),
            Total(type="total", amount=call.quote.amount_minor),
        ]
        content_key = {
            "merchant": call.quote.merchant.id,
            "tool": call.tool_id,
            "title": call.title,
            "amount": call.quote.amount_minor,
            "currency": call.quote.currency,
            "nonce": call.quote.nonce,
            "arguments": call.arguments,
        }
        line = LineItem(
            id=_opaque_id("line", content_key),
            item=CheckoutItem(
                id=call.tool_id,
                title=call.title,
                price=call.quote.amount_minor,
            ),
            quantity=1,
            totals=totals,
        )
        checkout = Checkout(
            id=_opaque_id("checkout", content_key),
            merchant=merchant,
            line_items=[line],
            status=Status.ready_for_complete,
            currency=call.quote.currency,
            totals=totals,
            links=[
                Link(
                    type="privacy_policy",
                    url="https://local.invalid/privacy",
                    title="Synthetic evaluation fixture",
                )
            ],
            messages=None,
            expires_at=datetime.fromtimestamp(approval.expires_at, tz=UTC),
        )
        checkout_jwt = create_jwt(
            header={
                "alg": "ES256",
                "typ": "JWT",
                "kid": f"merchant-{call.quote.merchant.id}",
            },
            payload=checkout.model_dump(mode="json", exclude_none=True),
            private_key=merchant_key,
        )
        return SignedCheckout(
            checkout=checkout,
            checkout_jwt=checkout_jwt,
            checkout_hash=compute_sha256_b64url(checkout_jwt),
        )


class LocalRailAdapter:
    """Creates and verifies deterministic no-funds AP2 receipt artifacts."""

    def __init__(self, payment_instrument: PaymentInstrument | None = None) -> None:
        self.payment_instrument = payment_instrument or PaymentInstrument(
            id="local-no-funds-1",
            type="local_no_funds",
            description="Deterministic evaluation instrument; no funds move.",
        )
        self._receipts = ReceiptClient()

    def create_and_verify_receipts(
        self,
        *,
        call: PaidToolCall,
        payment_mandate: PaymentMandate,
        checkout_reference: str,
        payment_reference: str,
        merchant_key: JWK,
        mpp_key: JWK,
    ) -> ReceiptArtifacts:
        checkout_receipt = self._receipts.create_checkout_receipt(
            merchant=call.quote.merchant.id,
            reference=checkout_reference,
            order_id=_opaque_id(
                "order",
                {
                    "merchant": call.quote.merchant.id,
                    "amount": call.quote.amount_minor,
                    "currency": call.quote.currency,
                    "nonce": call.quote.nonce,
                },
            ),
        )
        payment_receipt = self._receipts.create_payment_receipt(
            payment_mandate_content=payment_mandate,
            reference=payment_reference,
        )
        checkout_receipt_jwt = create_jwt(
            header={
                "alg": "ES256",
                "typ": "JWT",
                "kid": f"merchant-{call.quote.merchant.id}",
            },
            payload=checkout_receipt.model_dump(mode="json", exclude_none=True),
            private_key=merchant_key,
        )
        payment_receipt_jwt = create_jwt(
            header={"alg": "ES256", "typ": "JWT", "kid": "eval-mpp-ap2-v0.2"},
            payload=payment_receipt.model_dump(mode="json", exclude_none=True),
            private_key=mpp_key,
        )
        verified = (
            self._receipts.verify_receipt(
                receipt_jwt=checkout_receipt_jwt,
                receipt_issuer_public_key=merchant_key,
                has_reference_in_store_cb=lambda reference: reference == checkout_reference,
                is_payment_receipt=False,
            ),
            self._receipts.verify_receipt(
                receipt_jwt=payment_receipt_jwt,
                receipt_issuer_public_key=mpp_key,
                has_reference_in_store_cb=lambda reference: reference == payment_reference,
                is_payment_receipt=True,
            ),
        )
        errors = tuple(
            str(result.get("message") or result.get("error"))
            for result in verified
            if result.get("verified") is not True
        )
        return ReceiptArtifacts(
            checkout_receipt_jwt=checkout_receipt_jwt,
            payment_receipt_jwt=payment_receipt_jwt,
            errors=errors,
        )
