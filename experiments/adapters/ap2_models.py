"""AP2 v0.2 schema snapshot used for local fixture validation.

Field names and literal VCT values mirror the generated Pydantic models at
google-agentic-commerce/AP2 commit b4587ac1d055888a73b4b21750973cffba961793.
Only the success-path object variants exercised by this artifact are included.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, PositiveInt


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Merchant(StrictModel):
    id: str
    name: str
    website: str | None = None


class Amount(StrictModel):
    amount: int
    currency: str


class PaymentInstrument(StrictModel):
    id: str
    type: str
    description: str | None = None


class AllowedMerchants(StrictModel):
    type: Literal["checkout.allowed_merchants"] = "checkout.allowed_merchants"
    allowed: list[Merchant]


class Item(StrictModel):
    id: str
    title: str


class LineItemRequirements(StrictModel):
    id: str
    acceptable_items: list[Item]
    quantity: PositiveInt


class LineItems(StrictModel):
    type: Literal["checkout.line_items"] = "checkout.line_items"
    items: list[LineItemRequirements] = Field(min_length=1)


class OpenCheckoutMandate(StrictModel):
    vct: Literal["mandate.checkout.open.1"] = "mandate.checkout.open.1"
    constraints: list[AllowedMerchants | LineItems]
    cnf: dict[str, Any]
    iat: int | None = None
    exp: int | None = None


class CheckoutMandate(StrictModel):
    vct: Literal["mandate.checkout.1"] = "mandate.checkout.1"
    checkout_jwt: str
    checkout_hash: str
    iat: int | None = None
    exp: int | None = None


class PaymentMandate(StrictModel):
    vct: Literal["mandate.payment.1"] = "mandate.payment.1"
    transaction_id: str
    payee: Merchant
    payment_amount: Amount
    payment_instrument: PaymentInstrument
    execution_date: str | None = None
    risk_data: dict[str, Any] | None = None
    iat: int | None = None
    exp: int | None = None


class CheckoutReceiptSuccess(StrictModel):
    status: Literal["Success"]
    iss: str
    iat: int
    reference: str
    error: None = None
    error_description: None = None
    order_id: str


class PaymentReceiptSuccess(StrictModel):
    status: Literal["Success"]
    iss: str
    iat: int
    reference: str
    error: None = None
    error_description: None = None
    payment_id: str
    psp_confirmation_id: str
    network_confirmation_id: str
