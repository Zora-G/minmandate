from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
import json
from threading import RLock
import time
from typing import Any, Callable

from ap2.sdk.checkout_mandate_chain import CheckoutMandateChain
from ap2.sdk.generated.checkout_mandate import CheckoutMandate
from ap2.sdk.generated.payment_mandate import PaymentMandate
from ap2.sdk.generated.types.amount import Amount
from ap2.sdk.generated.types.merchant import Merchant
from ap2.sdk.generated.types.payment_instrument import PaymentInstrument
from ap2.sdk.jwt_helper import verify_jwt
from ap2.sdk.mandate import MandateClient
from ap2.sdk.payment_mandate_chain import PaymentMandateChain
from ap2.sdk.utils import compute_sha256_b64url

from .adapters import (
    DeterministicToolToCheckoutAdapter,
    LocalRailAdapter,
    LocalRoleAdapter,
    RoleAdapter,
    ToolToCheckoutAdapter,
)

from .compiler import AP2Compiler, AP2MandatePair, AP2MandatePool
from .domain import AP2Profile, NeutralApproval, PaidToolCall
from .keys import KeyBundle
from .ledger import AP2UsageLedger
from .wire import AP2WireRecord


@dataclass(slots=True)
class AP2CallResult:
    accepted: bool
    outcome: str
    reason: str | None
    violations: list[str]
    pair_id: str | None
    timings_ms: dict[str, float] = field(default_factory=dict)
    wire: AP2WireRecord | None = None
    authorization_breadth: dict[str, Any] = field(default_factory=dict)

    def to_dict(self, include_tokens: bool = True) -> dict[str, Any]:
        out = {
            "accepted": self.accepted,
            "outcome": self.outcome,
            "reason": self.reason,
            "violations": self.violations,
            "pair_id": self.pair_id,
            "timings_ms": self.timings_ms,
            "authorization_breadth": self.authorization_breadth,
        }
        out["wire"] = self.wire.to_sanitized_dict(include_tokens) if self.wire else None
        return out


class AP2BaselineEngine:
    def __init__(
        self,
        approval: NeutralApproval,
        *,
        profile: AP2Profile = AP2Profile.NATIVE,
        keys: KeyBundle | None = None,
        payment_instrument: PaymentInstrument | None = None,
        tool_to_checkout_adapter: ToolToCheckoutAdapter | None = None,
        role_adapter: RoleAdapter | None = None,
        rail_adapter: LocalRailAdapter | None = None,
        disclosure_mode: str = "all",
        hash_mode: str = "sd_hash",
        now_fn: Callable[[], float] = time.time,
    ) -> None:
        # Keep the complete native AP2 engine initialization in the one-time
        # task setup bucket.  This conservatively includes local role-key
        # construction and avoids reducing the baseline's measured overhead.
        t = time.perf_counter_ns()
        self.approval = approval
        self.profile = profile
        merchant_ids = {tool.merchant.id for tool in approval.tools}
        if approval.allowed_merchants is not None:
            merchant_ids.update(merchant.id for merchant in approval.allowed_merchants)
        self.keys = keys or KeyBundle.generate(sorted(merchant_ids))
        if rail_adapter is not None and payment_instrument is not None:
            raise ValueError("provide payment_instrument through rail_adapter, not both")
        self.roles = role_adapter or LocalRoleAdapter(self.keys)
        self.tool_to_checkout = tool_to_checkout_adapter or DeterministicToolToCheckoutAdapter()
        self.rail = rail_adapter or LocalRailAdapter(payment_instrument)
        self.instrument = self.rail.payment_instrument
        self.disclosure_mode = disclosure_mode
        self.hash_mode = hash_mode
        self.now_fn = now_fn
        self.client = MandateClient()
        self.ledger = AP2UsageLedger()
        self._call_lock = RLock()
        self._call_cache: dict[tuple[str, str], tuple[str, AP2CallResult]] = {}
        compiler = AP2Compiler(profile, self.keys, self.instrument, now_fn=now_fn)
        self.pool = AP2MandatePool(compiler.issue(approval))
        self.task_authorization_setup_ms = self._ms(t)

    @staticmethod
    def _ms(start_ns: int) -> float:
        return (time.perf_counter_ns() - start_ns) / 1_000_000

    def _claims(
        self, pair: AP2MandatePair, call: PaidToolCall
    ) -> tuple[dict | None, dict | None]:
        if self.disclosure_mode == "all":
            return None, None
        if self.disclosure_mode == "minimal":
            raise ValueError(
                "minimal open-mandate disclosure is not supported by the "
                "official MandateClient.present API: its claims_to_disclose "
                "parameter selects the closed leaf, not the prior open token"
            )
        raise ValueError(
            f"unsupported AP2 disclosure mode: {self.disclosure_mode}"
        )
    @staticmethod
    def _call_fingerprint(call: PaidToolCall) -> str:
        return json.dumps(
            {
                "tool_id": call.tool_id,
                "arguments": call.arguments,
                "amount_minor": call.quote.amount_minor,
                "currency": call.quote.currency,
                "merchant_id": call.quote.merchant.id,
                "nonce": call.quote.nonce,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    def execute(self, call: PaidToolCall) -> AP2CallResult:
        cache_key = (call.workflow_id, call.call_id)
        fingerprint = self._call_fingerprint(call)
        with self._call_lock:
            cached = self._call_cache.get(cache_key)
            if cached is not None:
                cached_fingerprint, cached_result = cached
                if cached_fingerprint != fingerprint:
                    return AP2CallResult(
                        False,
                        "rejected",
                        "idempotency_conflict",
                        ["call_id replay changed authenticated call content"],
                        cached_result.pair_id,
                    )
                return replace(
                    cached_result,
                    outcome="idempotent_receipt",
                    timings_ms={},
                )
            result = self._execute(call)
            if result.accepted:
                self._call_cache[cache_key] = (fingerprint, result)
            return result

    def _execute(self, call: PaidToolCall) -> AP2CallResult:
        timings: dict[str, float] = {}
        # Selecting a matching issued mandate is condition-specific AP2
        # authorization processing.  Keep it distinct in raw traces while the
        # common Table 1 schema assigns it to evidence creation.
        t = time.perf_counter_ns()
        if call.quote.currency != self.approval.currency:
            timings["mandate_select"] = self._ms(t)
            return AP2CallResult(
                False,
                "rejected",
                "currency_mismatch",
                ["quote currency mismatch"],
                None,
                timings,
            )
        pair = self.pool.select(call)
        timings["mandate_select"] = self._ms(t)
        if pair is None:
            return AP2CallResult(
                False, "rejected", "no_applicable_open_mandate",
                ["no AP2 open mandate satisfies merchant/tool/amount/remaining context"], None,
                timings,
            )

        merchant_key = self.roles.merchant_private_key(call.quote.merchant.id)
        issuer_public = self.roles.trusted_surface_public_key
        checkout_claims, payment_claims = self._claims(pair, call)
        now = int(self.now_fn())
        # Merchant checkout and signature.
        t = time.perf_counter_ns()
        signed_checkout = self.tool_to_checkout.build_signed_checkout(
            call, self.approval, merchant_key
        )
        checkout_jwt = signed_checkout.checkout_jwt
        checkout_hash = signed_checkout.checkout_hash
        timings["merchant_checkout_sign"] = self._ms(t)

        # Agent closes the Checkout Mandate.
        t = time.perf_counter_ns()
        checkout_chain = self.client.present(
            holder_key=self.roles.agent_private_key,
            mandate_token=pair.open_checkout_token,
            payloads=[
                CheckoutMandate(
                    checkout_jwt=checkout_jwt,
                    checkout_hash=checkout_hash,
                    iat=now,
                    exp=self.approval.expires_at,
                )
            ],
            claims_to_disclose=checkout_claims,
            nonce=call.quote.nonce,
            aud=self.roles.merchant_audience(call.quote.merchant.id),
            hash_mode=self.hash_mode,
        )
        timings["agent_close_checkout"] = self._ms(t)

        # Merchant verifies its signed checkout and AP2 checkout chain.
        t = time.perf_counter_ns()
        try:
            verify_jwt(checkout_jwt, merchant_key)
            checkout_payloads = self.client.verify(
                token=checkout_chain,
                key_or_provider=lambda _token: issuer_public,
                expected_aud=self.roles.merchant_audience(call.quote.merchant.id),
                expected_nonce=call.quote.nonce,
                current_time=now,
            )
            checkout_parsed = CheckoutMandateChain.parse(checkout_payloads)
            checkout_violations = checkout_parsed.verify(
                expected_checkout_hash=checkout_hash,
                checkout_jwt=checkout_jwt,
            )
        except Exception as exc:  # official verifier failures are fail-closed
            timings["merchant_verify_checkout"] = self._ms(t)
            return AP2CallResult(
                False,
                "rejected",
                "checkout_verification_failed",
                [str(exc)],
                pair.pair_id,
                timings,
            )
        timings["merchant_verify_checkout"] = self._ms(t)
        if checkout_violations:
            return AP2CallResult(
                False,
                "rejected",
                "checkout_constraint_violation",
                checkout_violations,
                pair.pair_id,
                timings,
            )

        # Agent closes the Payment Mandate.
        t = time.perf_counter_ns()
        merchant = Merchant(
            id=call.quote.merchant.id,
            name=call.quote.merchant.name,
            website=call.quote.merchant.website,
        )
        payment_model = PaymentMandate(
            transaction_id=checkout_hash,
            payee=merchant,
            payment_amount=Amount(
                amount=call.quote.amount_minor,
                currency=call.quote.currency,
            ),
            payment_instrument=self.instrument,
            iat=now,
            exp=self.approval.expires_at,
        )
        payment_chain = self.client.present(
            holder_key=self.roles.agent_private_key,
            mandate_token=pair.open_payment_token,
            payloads=[payment_model],
            claims_to_disclose=payment_claims,
            nonce=call.quote.nonce,
            aud=self.roles.cp_audience,
            hash_mode=self.hash_mode,
        )
        timings["agent_close_payment"] = self._ms(t)

        # Atomic CP/MPP verification + AP2 recurrence/budget context update.
        t = time.perf_counter_ns()
        verified_payment_payloads: list[dict[str, Any]] = []

        def verify_with_context(context):
            nonlocal verified_payment_payloads
            try:
                verified_payment_payloads = self.client.verify(
                    token=payment_chain,
                    key_or_provider=lambda _token: issuer_public,
                    expected_aud=self.roles.cp_audience,
                    expected_nonce=call.quote.nonce,
                    current_time=now,
                )
                parsed = PaymentMandateChain.parse(verified_payment_payloads)
                return parsed.verify(
                    expected_transaction_id=checkout_hash,
                    expected_open_checkout_hash=pair.open_checkout_hash,
                    mandate_context=context,
                )
            except Exception as exc:
                return [f"payment verification failed: {exc}"]

        redemption = self.ledger.redeem(
            pair,
            transaction_id=checkout_hash,
            amount_minor=call.quote.amount_minor,
            verify_with_context=verify_with_context,
        )
        timings["cp_mpp_verify_and_consume"] = self._ms(t)
        if redemption.status == "rejected":
            return AP2CallResult(
                False,
                "rejected",
                "payment_constraint_violation",
                redemption.violations,
                pair.pair_id,
                timings,
            )

        # Receipts bind to the official closed leaf JWT references.  The local
        # rail's public API creates *and verifies* both receipts atomically, so
        # retain one raw timer instead of reporting a fictitious zero verify
        # phase.  The common Table 1 schema assigns the whole operation to
        # settlement_or_receipt_ms exactly once.
        t = time.perf_counter_ns()
        checkout_reference = compute_sha256_b64url(
            self.client.get_closed_mandate_jwt(checkout_chain)
        )
        payment_reference = compute_sha256_b64url(
            self.client.get_closed_mandate_jwt(payment_chain)
        )
        receipt_artifacts = self.rail.create_and_verify_receipts(
            call=call,
            payment_mandate=payment_model,
            checkout_reference=checkout_reference,
            payment_reference=payment_reference,
            merchant_key=merchant_key,
            mpp_key=self.roles.mpp_private_key,
        )
        timings["receipt_create_and_verify"] = self._ms(t)

        receipt_errors = list(receipt_artifacts.errors)
        if receipt_errors:
            return AP2CallResult(
                False,
                "rejected",
                "receipt_verification_failed",
                receipt_errors,
                pair.pair_id,
                timings,
            )

        # Effective open payloads are verifier outputs and support the field audit.
        effective_checkout = checkout_payloads[0]
        effective_payment = verified_payment_payloads[0]
        wire = AP2WireRecord(
            workflow_id=call.workflow_id,
            call_id=call.call_id,
            pair_id=pair.pair_id,
            open_checkout_token=pair.open_checkout_token,
            open_payment_token=pair.open_payment_token,
            checkout_chain=checkout_chain,
            payment_chain=payment_chain,
            checkout_jwt=checkout_jwt,
            checkout_receipt_jwt=receipt_artifacts.checkout_receipt_jwt,
            payment_receipt_jwt=receipt_artifacts.payment_receipt_jwt,
            effective_open_checkout=effective_checkout,
            effective_open_payment=effective_payment,
        )
        breadth = {
            "allowed_merchants": len(pair.allowed_merchant_ids),
            "allowed_tools": len(pair.allowed_tool_ids),
            "max_occurrences": pair.max_occurrences,
            "used_occurrences": pair.use_count,
            "budget_minor": pair.budget_minor,
            "spent_minor": pair.spent_minor,
            "per_call_max_minor": pair.per_call_max_minor,
        }
        return AP2CallResult(
            True,
            redemption.status,
            None,
            [],
            pair.pair_id,
            timings,
            wire,
            breadth,
        )


class AP2BaselineController:
    """Task-scoped controller exposing the official AP2 authorization path."""

    def __init__(self, *args, **kwargs) -> None:
        self.engine = AP2BaselineEngine(*args, **kwargs)

    def authorize_paid_call(self, call: PaidToolCall) -> AP2CallResult:
        return self.engine.execute(call)

    @property
    def approval(self) -> NeutralApproval:
        return self.engine.approval
