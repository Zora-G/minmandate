from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Any, Iterable


DENIAL_REASONS = {
    "invalid_request",
    "class_not_authorized",
    "merchant_not_authorized",
    "insufficient_slots",
    "insufficient_budget",
    "quote_exceeds_slot_capacity",
    "expired_mandate",
    "order_constraint_violation",
    "malformed_payment_projection",
    "proof_failure",
    "replay_or_duplicate_serial",
    "internal_error",
}


@dataclass(frozen=True, slots=True)
class SlotReservation:
    slot_index: int
    service_class: str
    merchant_id: str
    amount: int
    shared_reserve: bool = False


@dataclass(frozen=True, slots=True)
class StructuredDenial:
    schema_version: str
    reason_code: str
    requested_service_class: str
    requested_merchant: str
    remaining_slots_by_class: dict[str, int]
    remaining_shared_slots: int
    remaining_budget: int
    quoted_price: int
    budget_shortfall: int
    alternative_allowed_services: list[str]
    allowed_service_classes: list[str]
    allowed_merchants: list[str]
    expiry: int
    retryable: bool
    reauthorization_required: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class MandatePolicyState:
    """Fail-closed authorization state shared by Policy-only and MinMandate."""

    schema_version = "minmandate-planner-state-v1"
    denial_schema_version = "minmandate-structured-denial-v1"

    def __init__(
        self,
        slots: Iterable[dict[str, Any]],
        allowed_merchants: Iterable[str],
        budget: int,
        expiry: int,
        *,
        max_replans: int = 2,
        max_reauthorizations: int = 1,
        remaining_shared_slots: int = 0,
        allowed_order_constraints: list[str] | None = None,
    ) -> None:
        if budget < 0 or expiry < 0 or max_replans < 0 or max_reauthorizations < 0:
            raise ValueError("mandate limits must be non-negative")
        slot_rows = [dict(slot) for slot in slots]
        allowed_merchant_values = sorted({str(value) for value in allowed_merchants})
        expanded: list[tuple[int, str, str | None, bool, int]] = []
        for slot in slot_rows:
            service_class = str(slot["service_class"])
            merchant_value = slot.get("merchant_id")
            merchant_id = str(merchant_value) if merchant_value else None
            if merchant_id is None and len(allowed_merchant_values) == 1:
                merchant_id = allowed_merchant_values[0]
            capacity = int(slot["capacity"])
            if capacity <= 0:
                raise ValueError("slot capacity must be positive")
            for _ in range(capacity):
                expanded.append(
                    (
                        len(expanded),
                        service_class,
                        merchant_id,
                        str(slot.get("reserve_kind", "initial")) == "shared",
                        int(slot.get("max_amount", 2**63 - 1)),
                    )
                )
        if not expanded:
            raise ValueError("a mandate requires at least one spend slot")
        self._slots = expanded
        self._spent_slots: set[int] = set()
        self.allowed_service_classes = sorted(
            {service_class for _, service_class, _, _, _ in expanded}
        )
        self.allowed_merchants = allowed_merchant_values
        explicit_pairs = {
            (str(slot["service_class"]), str(slot["merchant_id"]))
            for slot in slot_rows
            if slot.get("merchant_id")
        }
        self._allowed_pairs = explicit_pairs or {
            (service_class, merchant_id)
            for service_class in self.allowed_service_classes
            for merchant_id in self.allowed_merchants
        }
        self.remaining_budget = int(budget)
        self.expiry = int(expiry)
        self.max_replans = int(max_replans)
        self.max_reauthorizations = int(max_reauthorizations)
        self.remaining_shared_slots = int(remaining_shared_slots)
        self.allowed_order_constraints = list(allowed_order_constraints or [])
        self.denials: list[StructuredDenial] = []
        self.reauthorizations = 0
        self.reauthorization_requests = 0
        self.reauthorization_approvals = 0
        self.reauthorization_rejections = 0
        self.accepted_calls = 0
        self.replan_succeeded = False

    def remaining_slots_by_class(self) -> dict[str, int]:
        counts = {service_class: 0 for service_class in self.allowed_service_classes}
        for slot_index, service_class, _merchant_id, shared, _max_amount in self._slots:
            if slot_index not in self._spent_slots and not shared:
                counts[service_class] += 1
        return counts

    def planner_state(self) -> dict[str, Any]:
        last_denial = self.denials[-1].to_dict() if self.denials else None
        return {
            "schema_version": self.schema_version,
            "allowed_service_classes": self.allowed_service_classes,
            "allowed_merchants": self.allowed_merchants,
            "remaining_slots_by_class": self.remaining_slots_by_class(),
            "remaining_shared_slots": self.remaining_shared_slots,
            "remaining_budget": self.remaining_budget,
            "quoted_price": None,
            "expiry": self.expiry,
            "allowed_order_constraints": self.allowed_order_constraints,
            "replan_attempts_remaining": max(0, self.max_replans - len(self.denials)),
            "reauthorization_available": self.reauthorization_requests < self.max_reauthorizations,
            "last_denial": last_denial,
        }

    def _deny(
        self,
        reason_code: str,
        service_class: str,
        merchant_id: str,
        *,
        reauthorization_required: bool,
        quoted_price: int,
    ) -> StructuredDenial:
        if reason_code not in DENIAL_REASONS:
            raise ValueError(f"unknown denial reason: {reason_code}")
        retryable = len(self.denials) < self.max_replans
        denial = StructuredDenial(
            schema_version=self.denial_schema_version,
            reason_code=reason_code,
            requested_service_class=service_class,
            requested_merchant=merchant_id,
            remaining_slots_by_class=self.remaining_slots_by_class(),
            remaining_shared_slots=self.remaining_shared_slots,
            remaining_budget=self.remaining_budget,
            quoted_price=quoted_price,
            budget_shortfall=max(0, quoted_price - self.remaining_budget),
            alternative_allowed_services=[
                candidate_class
                for candidate_class, remaining in self.remaining_slots_by_class().items()
                if remaining > 0 and candidate_class != service_class
            ],
            allowed_service_classes=self.allowed_service_classes,
            allowed_merchants=self.allowed_merchants,
            expiry=self.expiry,
            retryable=retryable,
            reauthorization_required=reauthorization_required,
        )
        self.denials.append(denial)
        return denial

    def check(
        self,
        service_class: str,
        merchant_id: str,
        amount: int,
        trusted_now: int,
    ) -> tuple[SlotReservation | None, StructuredDenial | None]:
        if not service_class or not merchant_id or amount <= 0:
            return None, self._deny(
                "invalid_request",
                service_class,
                merchant_id,
                reauthorization_required=False,
                quoted_price=amount,
            )
        if trusted_now > self.expiry:
            return None, self._deny(
                "expired_mandate", service_class, merchant_id, reauthorization_required=True,
                quoted_price=amount,
            )
        if service_class not in self.allowed_service_classes:
            return None, self._deny(
                "class_not_authorized", service_class, merchant_id, reauthorization_required=True,
                quoted_price=amount,
            )
        if merchant_id not in self.allowed_merchants or (
            service_class,
            merchant_id,
        ) not in self._allowed_pairs:
            return None, self._deny(
                "merchant_not_authorized", service_class, merchant_id, reauthorization_required=True,
                quoted_price=amount,
            )
        if amount > self.remaining_budget:
            return None, self._deny(
                "insufficient_budget", service_class, merchant_id, reauthorization_required=True,
                quoted_price=amount,
            )
        candidate = next(
            (
                (index, shared)
                for index, slot_class, _merchant_id, shared, max_amount in self._slots
                if slot_class == service_class
                and index not in self._spent_slots
                and (not shared or self.remaining_shared_slots > 0)
                and amount <= max_amount
            ),
            None,
        )
        if candidate is None:
            has_unspent_class_slot = any(
                slot_class == service_class
                and index not in self._spent_slots
                and (not shared or self.remaining_shared_slots > 0)
                for index, slot_class, _merchant_id, shared, _max_amount in self._slots
            )
            return None, self._deny(
                (
                    "quote_exceeds_slot_capacity"
                    if has_unspent_class_slot
                    else "insufficient_slots"
                ),
                service_class,
                merchant_id,
                reauthorization_required=True,
                quoted_price=amount,
            )
        slot_index, shared = candidate
        return SlotReservation(slot_index, service_class, merchant_id, amount, shared), None

    def commit(self, reservation: SlotReservation) -> None:
        if reservation.slot_index in self._spent_slots:
            raise RuntimeError("slot reservation was already committed")
        if reservation.amount > self.remaining_budget:
            raise RuntimeError("budget changed after policy reservation")
        self._spent_slots.add(reservation.slot_index)
        if reservation.shared_reserve:
            if self.remaining_shared_slots <= 0:
                raise RuntimeError("shared reserve was exhausted after policy reservation")
            self.remaining_shared_slots -= 1
        self.remaining_budget -= reservation.amount
        self.accepted_calls += 1
        if self.denials:
            self.replan_succeeded = True

    def request_reauthorization(
        self,
        denial: StructuredDenial,
        amount: int,
        approval_policy: str,
    ) -> dict[str, Any]:
        self.reauthorization_requests += 1
        pair = (denial.requested_service_class, denial.requested_merchant)
        capacity_only = (
            approval_policy == "approve_capacity_only"
            and denial.reason_code
            in {"insufficient_slots", "insufficient_budget", "quote_exceeds_slot_capacity"}
            and pair in self._allowed_pairs
        )
        approved = self.reauthorization_requests <= self.max_reauthorizations and capacity_only
        if not approved:
            self.reauthorization_rejections += 1
            return {
                "approved": False,
                "reason": "user_policy_rejected",
                "request_number": self.reauthorization_requests,
            }
        added_slots = 0
        added_budget = 0
        if denial.reason_code in {"insufficient_slots", "quote_exceeds_slot_capacity"}:
            self._slots.append(
                (
                    len(self._slots),
                    denial.requested_service_class,
                    denial.requested_merchant,
                    False,
                    denial.quoted_price,
                )
            )
            added_slots = 1
        if denial.reason_code == "insufficient_budget":
            self.remaining_budget += amount
            added_budget = amount
        self.reauthorizations += 1
        self.reauthorization_approvals += 1
        return {
            "approved": True,
            "request_number": self.reauthorization_requests,
            "added_slots": added_slots,
            "added_budget": added_budget,
            "added_classes": [],
            "added_merchants": [],
        }

    def remaining_crypto_slots(self) -> list[dict[str, Any]]:
        slots, _mapping = self.remaining_crypto_slots_with_mapping()
        return slots

    def remaining_crypto_slots_with_mapping(
        self,
    ) -> tuple[list[dict[str, Any]], dict[int, int]]:
        remaining: list[tuple[int, dict[str, Any]]] = []
        for index, service_class, merchant_id, shared, max_amount in self._slots:
            if index in self._spent_slots or (
                shared and self.remaining_shared_slots <= 0
            ):
                continue
            if not merchant_id:
                raise ValueError(
                    "cannot project a cryptographic slot without an exact merchant_id"
                )
            remaining.append(
                (
                    index,
                    {
                        "service_class": service_class,
                        "merchant_id": merchant_id,
                        "capacity": max_amount,
                    },
                )
            )
        return (
            [slot for _index, slot in remaining],
            {logical_index: credential_index for credential_index, (logical_index, _slot) in enumerate(remaining)},
        )

    def metrics(self) -> dict[str, Any]:
        return {
            "number_of_replans": len(self.denials),
            "structured_denial_count": len(self.denials),
            "denial_reason_sequence": [item.reason_code for item in self.denials],
            "whether_replan_succeeded": self.replan_succeeded,
            "reauthorization_requests": self.reauthorization_requests,
            "reauthorization_approvals": self.reauthorization_approvals,
            "reauthorization_rejections": self.reauthorization_rejections,
            "remaining_slots_by_class": self.remaining_slots_by_class(),
            "remaining_budget": self.remaining_budget,
            "accepted_paid_calls": self.accepted_calls,
            "unused_credential_slots": sum(
                index not in self._spent_slots
                for index, _service_class, _merchant_id, _shared, _max_amount in self._slots
            ),
        }


def apply_contingency_profile(
    authorizations: Iterable[dict[str, Any]], profile: str
) -> tuple[list[dict[str, Any]], int, dict[str, Any]]:
    base = [dict(row) for row in authorizations]
    classes = sorted({str(row["service_class"]) for row in base})
    merchants_by_class: dict[str, set[str]] = {}
    for row in base:
        merchant_id = row.get("merchant_id")
        if merchant_id:
            merchants_by_class.setdefault(str(row["service_class"]), set()).add(
                str(merchant_id)
            )

    def reserve_slot(service_class: str, capacity: int, reserve_kind: str) -> dict[str, Any]:
        row: dict[str, Any] = {
            "service_class": service_class,
            "capacity": capacity,
            "reserve_kind": reserve_kind,
        }
        merchants = merchants_by_class.get(service_class, set())
        if len(merchants) == 1:
            row["merchant_id"] = next(iter(merchants))
        return row

    initial_slots = sum(int(row["capacity"]) for row in base)
    reserve: list[dict[str, Any]] = []
    shared_slots = 0
    if profile == "none":
        pass
    elif profile == "plus_one_per_approved_class":
        reserve = [
            reserve_slot(service_class, 1, "class")
            for service_class in classes
        ]
    elif profile == "pooled_25_percent":
        shared_slots = int(math.ceil(0.25 * initial_slots)) if initial_slots else 0
        reserve = [
            reserve_slot(service_class, shared_slots, "shared")
            for service_class in classes
        ]
    else:
        raise ValueError(f"unknown contingency profile: {profile}")
    physical_reserve_slots = sum(int(row["capacity"]) for row in reserve)
    return (
        base + reserve,
        shared_slots,
        {
            "contingency_profile": profile,
            "initial_slots": initial_slots,
            "logical_reserve_slots": shared_slots
            if profile == "pooled_25_percent"
            else physical_reserve_slots,
            "physical_reserve_slots": physical_reserve_slots,
            "approved_classes": classes,
        },
    )
