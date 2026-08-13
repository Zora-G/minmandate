from __future__ import annotations

import math
from dataclasses import asdict, dataclass, replace
from typing import Any, Iterable

from experiments.benchmark.mandate_compiler import ApprovedSlot, UserApprovalArtifact
from experiments.common import canonical_json, sha256_bytes
from experiments.pricing import MarketTariff


DENIAL_REASONS = {
    "malformed_request",
    "class_not_authorized",
    "merchant_not_authorized",
    "single_quote_exceeds_initial_budget",
    "global_budget_exhausted",
    "applicable_class_capacity_exhausted",
    "denomination_composition_failure",
    "expired_mandate",
    "order_constraint_violation",
    "malformed_payment_projection",
    "proof_failure",
    "replay_or_duplicate_serial",
    "internal_error",
}

MERCHANT_POLICY_PREFIX = "policy:admitted:"


def admitted_merchant_scope(service_class: str) -> str:
    """Canonical merchant-neutral scope for any admitted merchant in a class."""

    if not service_class:
        raise ValueError("merchant policy scope requires a service class")
    return f"{MERCHANT_POLICY_PREFIX}{service_class}"


def merchant_scope_matches(scope: str, service_class: str, merchant_id: str) -> bool:
    """Return whether an exact or admitted-class scope covers a runtime merchant."""

    return scope == merchant_id or scope == admitted_merchant_scope(service_class)


@dataclass(frozen=True, slots=True)
class DenominationSlot:
    slot_index: int
    service_class: str
    merchant_id: str
    denomination: int
    funding_coverage: int
    reserve_kind: str
    expiry: int | None = None
    funding_eligible: bool = True


@dataclass(frozen=True, slots=True)
class SpendReservation:
    slot_indices: tuple[int, ...]
    slot_denominations: tuple[int, ...]
    selected_slot_capacity: int
    service_class: str
    merchant_id: str
    amount: int
    denomination_slack: int


@dataclass(frozen=True, slots=True)
class StructuredSpendDenial:
    schema_version: str
    reason_code: str
    requested_service_class: str
    requested_merchant: str
    quoted_price: int
    selected_slot_capacity: int
    remaining_slot_denominations: dict[str, list[int]]
    remaining_approved_budget: int
    funding_coverage_remaining: int
    budget_shortfall: int
    denomination_shortfall: int
    alternative_allowed_services: list[str]
    allowed_service_classes: list[str]
    allowed_merchants: list[str]
    expiry: int
    retryable: bool
    reauthorization_required: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SpendCapacityPlan:
    schema_version: str
    profile: str
    base_budget: int
    approved_budget: int
    funding_coverage: int
    joint_reserve_amount: int
    slots: tuple[DenominationSlot, ...]
    metadata: dict[str, Any]


@dataclass(frozen=True, slots=True)
class PendingAmendment:
    approval_artifact: UserApprovalArtifact
    delta: int
    new_slot: DenominationSlot


def affordability_preflight(
    *,
    plan: SpendCapacityPlan,
    suite: str,
    policy_tools: dict[str, Any],
    tariff: MarketTariff,
    scenario: str = "nominal",
) -> dict[str, Any]:
    """Check frozen nominal tool caps before mandate approval.

    This preflight does not expand the mandate. It reports the smallest joint
    shortfall and the user choices required when a nominal call is unaffordable.
    """

    pair_slots: dict[tuple[str, str], list[DenominationSlot]] = {}
    for slot in plan.slots:
        pair_slots.setdefault((slot.service_class, slot.merchant_id), []).append(slot)
    rows: list[dict[str, Any]] = []
    frozen_quotes = list(plan.metadata.get("required_call_quote_caps", []))
    if frozen_quotes:
        candidates = [
            (
                str(row["tool_name"]),
                (str(row["service_class"]), str(row["merchant_id"])),
                int(row["amount_nanos"]),
                "task_argument_projection",
            )
            for row in frozen_quotes
        ]
    else:
        multiplier = int(tariff.scenario_multipliers_milli.get(scenario, 1000))
        candidates = []
        for tool_name, rule in sorted(policy_tools.get(suite, {}).items()):
            if not bool(rule.get("paid")):
                continue
            nominal = int(
                tariff.tariff_for(suite, str(tool_name))["budget_nominal_nanos"]
            )
            candidates.append(
                (
                    str(tool_name),
                    (str(rule["service_class"]), str(rule["merchant_id"])),
                    max(1, math.ceil(nominal * multiplier / 1000)),
                    "nominal_fallback",
                )
            )
    for tool_name, pair, quoted_cap, projection_source in candidates:
        if pair not in pair_slots:
            continue
        selected = JointSpendCapacityState._select_subset(pair_slots[pair], quoted_cap)
        applicable_capacity = sum(slot.denomination for slot in pair_slots[pair])
        budget_shortfall = max(0, quoted_cap - plan.approved_budget)
        denomination_shortfall = max(0, quoted_cap - applicable_capacity)
        rows.append(
            {
                "tool_name": str(tool_name),
                "service_class": pair[0],
                "merchant_id": pair[1],
                "nominal_quote_cap": quoted_cap,
                "projection_source": projection_source,
                "selected_slot_capacity": sum(slot.denomination for slot in selected or ()),
                "budget_shortfall": budget_shortfall,
                "denomination_shortfall": denomination_shortfall,
                "affordable": bool(selected) and budget_shortfall == 0,
            }
        )
    minimum_shortfall = max(
        (max(row["budget_shortfall"], row["denomination_shortfall"]) for row in rows),
        default=0,
    )
    return {
        "schema_version": "minmandate-affordability-preflight-v2",
        "scenario": scenario,
        "passed": all(row["affordable"] for row in rows),
        "minimum_joint_shortfall": minimum_shortfall,
        "tools": rows,
        "user_options": [
            "approve_minimum_joint_increase",
            "choose_cheaper_service",
            "remove_service",
            "reject_mandate",
        ],
        "automatic_expansion": False,
    }


def _quarter_split(value: int) -> list[int]:
    if value <= 0:
        raise ValueError("denomination value must be positive")
    if value < 4:
        return [value]
    quarter = value // 4
    return [quarter, quarter, quarter, value - 3 * quarter]


def build_spend_capacity_plan(
    *,
    suite: str,
    authorizations: Iterable[dict[str, Any]],
    policy_tools: dict[str, Any],
    tariff: MarketTariff,
    profile: str,
) -> SpendCapacityPlan:
    rows = [dict(row) for row in authorizations]
    if profile not in {
        "same_budget_redenomination",
        "preapproved_joint_reserve_25_percent",
    }:
        raise ValueError(f"unknown joint spend-capacity profile: {profile}")
    if not rows:
        return SpendCapacityPlan(
            schema_version="minmandate-spend-capacity-plan-v1",
            profile=profile,
            base_budget=0,
            approved_budget=0,
            funding_coverage=0,
            joint_reserve_amount=0,
            slots=(),
            metadata={
                "spend_capacity_profile": profile,
                "base_budget": 0,
                "approved_budget": 0,
                "funding_coverage": 0,
                "joint_reserve_amount": 0,
                "initial_denomination_count": 0,
                "capacity_inflation": 0.0,
                "invocation_quota": None,
            },
        )
    base_entries: list[tuple[str, str, int]] = []
    required_call_quote_caps: list[dict[str, Any]] = []
    scope_totals: dict[tuple[str, str], int] = {}
    for row in rows:
        service_class = str(row["service_class"])
        merchant_id = str(row["merchant_id"])
        capacity = int(row["capacity"])
        if capacity <= 0:
            raise ValueError("authorization invocation estimate must be positive")
        frozen_quotes = row.get("quote_caps")
        if frozen_quotes is None:
            nominal = tariff.max_nominal_for_scope(
                suite, service_class, merchant_id, policy_tools
            )
            quote_rows = [
                {"tool_name": "scope_nominal_fallback", "amount_nanos": nominal}
                for _ in range(capacity)
            ]
        else:
            if not isinstance(frozen_quotes, list) or len(frozen_quotes) != capacity:
                raise ValueError(
                    "authorization quote_caps must contain one entry per paid call"
                )
            quote_rows = [dict(value) for value in frozen_quotes]
        for quote_row in quote_rows:
            quoted_cap = int(quote_row["amount_nanos"])
            if quoted_cap <= 0:
                raise ValueError("authorization quote cap must be positive")
            base_entries.append((service_class, merchant_id, quoted_cap))
            required_call_quote_caps.append(
                {
                    "tool_name": str(quote_row["tool_name"]),
                    "service_class": service_class,
                    "merchant_id": merchant_id,
                    "amount_nanos": quoted_cap,
                }
            )
        scope_totals[(service_class, merchant_id)] = (
            scope_totals.get((service_class, merchant_id), 0)
            + sum(int(value["amount_nanos"]) for value in quote_rows)
        )
    base_budget = sum(value for _cls, _merchant, value in base_entries)
    slot_specs: list[tuple[str, str, int, str]] = []
    for service_class, merchant_id, value in base_entries:
        slot_specs.extend(
            (service_class, merchant_id, denomination, "base_redenominated")
            for denomination in _quarter_split(value)
        )
    joint_reserve_amount = 0
    if profile == "same_budget_redenomination":
        pass
    elif profile == "preapproved_joint_reserve_25_percent":
        for (service_class, merchant_id), scope_total in sorted(scope_totals.items()):
            delta = max(1, math.ceil(scope_total * 0.25))
            joint_reserve_amount += delta
            slot_specs.extend(
                (service_class, merchant_id, denomination, "preapproved_joint_reserve")
                for denomination in _quarter_split(delta)
            )
    approved_budget = base_budget + joint_reserve_amount
    slots = tuple(
        DenominationSlot(
            slot_index=index,
            service_class=service_class,
            merchant_id=merchant_id,
            denomination=denomination,
            funding_coverage=denomination,
            reserve_kind=reserve_kind,
        )
        for index, (service_class, merchant_id, denomination, reserve_kind) in enumerate(slot_specs)
    )
    funding_coverage = sum(slot.funding_coverage for slot in slots)
    if sum(slot.denomination for slot in slots) != approved_budget:
        raise RuntimeError("denomination capacity does not equal approved budget")
    if funding_coverage != approved_budget:
        raise RuntimeError("funding coverage does not equal approved budget")
    return SpendCapacityPlan(
        schema_version="minmandate-spend-capacity-plan-v1",
        profile=profile,
        base_budget=base_budget,
        approved_budget=approved_budget,
        funding_coverage=funding_coverage,
        joint_reserve_amount=joint_reserve_amount,
        slots=slots,
        metadata={
            "spend_capacity_profile": profile,
            "base_budget": base_budget,
            "approved_budget": approved_budget,
            "funding_coverage": funding_coverage,
            "joint_reserve_amount": joint_reserve_amount,
            "initial_denomination_count": len(slots),
            "capacity_inflation": (
                joint_reserve_amount / base_budget if base_budget else 0.0
            ),
            "invocation_quota": None,
            "required_call_quote_caps": required_call_quote_caps,
        },
    )


class JointSpendCapacityState:
    """Joint policy state for budget, denominations, and funding coverage."""

    schema_version = "minmandate-planner-spend-state-v1"
    denial_schema_version = "minmandate-structured-spend-denial-v2"

    def __init__(
        self,
        plan: SpendCapacityPlan,
        approval_artifact: UserApprovalArtifact,
        *,
        max_replans: int = 2,
        allowed_order_constraints: list[str] | None = None,
    ) -> None:
        approval_artifact.validate()
        if max_replans < 0:
            raise ValueError("mandate limits must be non-negative")
        expected_slots = tuple(
            (slot.service_class, slot.merchant_id, slot.denomination)
            for slot in plan.slots
        )
        approved_slots = tuple(
            (slot.service_class, slot.merchant_id, slot.capacity)
            for slot in approval_artifact.slots
        )
        if expected_slots != approved_slots:
            raise ValueError("approval artifact does not bind the exact ordered plan slots")
        if (
            approval_artifact.base_budget != plan.base_budget
            or approval_artifact.reserve_budget != plan.joint_reserve_amount
            or approval_artifact.approved_budget != plan.approved_budget
            or approval_artifact.funding_coverage != plan.funding_coverage
        ):
            raise ValueError("approval artifact does not bind plan budget/reserve/funding")
        plan_classes = tuple(sorted({slot.service_class for slot in plan.slots}))
        plan_merchants = tuple(sorted({slot.merchant_id for slot in plan.slots}))
        if approval_artifact.allowed_service_classes != plan_classes:
            raise ValueError("approval service classes differ from the compiled plan")
        if approval_artifact.allowed_merchants != plan_merchants:
            raise ValueError("approval merchants differ from the compiled plan")
        eligible_indices = tuple(
            index for index, slot in enumerate(plan.slots) if slot.funding_coverage > 0
        )
        if approval_artifact.funding_eligible_slot_indices != eligible_indices:
            raise ValueError("approval funding eligibility differs from the compiled plan")
        self.profile = plan.profile
        self.base_budget = int(plan.base_budget)
        self.approved_budget = int(approval_artifact.approved_budget)
        self.initial_approved_budget = int(approval_artifact.approved_budget)
        self.total_funding_coverage = int(approval_artifact.funding_coverage)
        self.initial_funding_coverage = int(approval_artifact.funding_coverage)
        self.joint_reserve_amount = int(approval_artifact.reserve_budget)
        eligible_set = set(approval_artifact.funding_eligible_slot_indices)
        self._slots = [
            replace(
                slot,
                expiry=approval_artifact.slots[index].expiry,
                funding_eligible=index in eligible_set,
            )
            for index, slot in enumerate(plan.slots)
        ]
        self._spent_slots: set[int] = set()
        self.initial_approval_artifact = approval_artifact
        self.active_approval_artifact = approval_artifact
        self.approval_history = [approval_artifact]
        self.active_credential_id = approval_artifact.artifact_sha256
        self.retired_credential_ids: list[str] = []
        self.allowed_service_classes = list(approval_artifact.allowed_service_classes)
        self.allowed_merchants = list(approval_artifact.allowed_merchants)
        self._allowed_pairs = {(slot.service_class, slot.merchant_id) for slot in self._slots}
        self.remaining_budget = self.approved_budget
        self.actual_spend = 0
        self.burned_slot_capacity = 0
        self.denomination_slack_total = 0
        self.expiry = max((slot.expiry or 0 for slot in self._slots), default=0)
        self.max_replans = int(max_replans)
        self.max_reauthorizations = int(approval_artifact.amendment_limit)
        self.allowed_order_constraints = list(allowed_order_constraints or [])
        self.denials: list[StructuredSpendDenial] = []
        self.reauthorizations = 0
        self.reauthorization_requests = 0
        self.reauthorization_approvals = 0
        self.reauthorization_rejections = 0
        self.accepted_calls = 0
        self.replan_succeeded = False
        self.amendments: list[dict[str, Any]] = []
        self._assert_joint_invariant()

    def _assert_joint_invariant(self) -> None:
        total_denomination = sum(slot.denomination for slot in self._slots)
        total_funding = sum(
            slot.funding_coverage for slot in self._slots if slot.funding_eligible
        )
        if total_denomination != self.approved_budget:
            raise RuntimeError("approved budget and denomination capacity diverged")
        if total_funding != self.total_funding_coverage:
            raise RuntimeError("funding eligibility and funding coverage diverged")

    def _available_slots(
        self,
        service_class: str | None = None,
        merchant_id: str | None = None,
        *,
        trusted_now: int | None = None,
        require_funding: bool = False,
    ) -> list[DenominationSlot]:
        return [
            slot
            for slot in self._slots
            if slot.slot_index not in self._spent_slots
            and (service_class is None or slot.service_class == service_class)
            and (
                merchant_id is None
                or merchant_scope_matches(slot.merchant_id, slot.service_class, merchant_id)
            )
            and (trusted_now is None or (slot.expiry is not None and trusted_now <= slot.expiry))
            and (not require_funding or slot.funding_eligible)
        ]

    def remaining_slot_denominations(self) -> dict[str, list[int]]:
        values = {service_class: [] for service_class in self.allowed_service_classes}
        for slot in self._available_slots():
            values[slot.service_class].append(slot.denomination)
        return {key: sorted(items) for key, items in sorted(values.items())}

    def funding_coverage_remaining(self) -> int:
        return sum(
            slot.funding_coverage
            for slot in self._available_slots(require_funding=True)
        )

    def scope_available(self, service_class: str, merchant_id: str) -> bool:
        return bool(self._available_slots(service_class, merchant_id))

    def planner_state(self) -> dict[str, Any]:
        last_denial = self.denials[-1].to_dict() if self.denials else None
        return {
            "schema_version": self.schema_version,
            "allowed_service_classes": self.allowed_service_classes,
            "allowed_merchants": self.allowed_merchants,
            "remaining_slot_denominations": self.remaining_slot_denominations(),
            "remaining_approved_budget": self.remaining_budget,
            "funding_coverage_remaining": self.funding_coverage_remaining(),
            "quoted_price": None,
            "estimated_budget_after_call": None,
            "expiry": self.expiry,
            "allowed_order_constraints": self.allowed_order_constraints,
            "replan_attempts_remaining": max(0, self.max_replans - len(self.denials)),
            "reauthorization_available": self.reauthorization_requests < self.max_reauthorizations,
            "last_denial": last_denial,
        }

    @staticmethod
    def _select_subset(
        slots: list[DenominationSlot], amount: int
    ) -> tuple[DenominationSlot, ...] | None:
        states: dict[int, tuple[int, ...]] = {0: ()}
        by_index = {slot.slot_index: slot for slot in slots}
        for slot in sorted(slots, key=lambda item: item.slot_index):
            updates: dict[int, tuple[int, ...]] = {}
            for total, indices in list(states.items()):
                next_total = total + slot.denomination
                candidate = (*indices, slot.slot_index)
                existing = states.get(next_total) or updates.get(next_total)
                if existing is None or (len(candidate), candidate) < (len(existing), existing):
                    updates[next_total] = candidate
            states.update(updates)
        feasible = [
            (total - amount, len(indices), indices, total)
            for total, indices in states.items()
            if total >= amount and indices
        ]
        if not feasible:
            return None
        _slack, _count, indices, _total = min(feasible)
        return tuple(by_index[index] for index in indices)

    def preview_quote(
        self, service_class: str, merchant_id: str, amount: int
    ) -> dict[str, Any]:
        selected = self._select_subset(
            self._available_slots(service_class, merchant_id), amount
        )
        capacity = sum(slot.denomination for slot in selected or ())
        return {
            "quoted_price": amount,
            "selected_slot_capacity": capacity,
            "denomination_slack": max(0, capacity - amount),
            "estimated_budget_after_call": (
                self.remaining_budget - amount if amount <= self.remaining_budget else None
            ),
            "affordable": bool(selected) and amount <= self.remaining_budget,
        }

    def _alternative_services(self, requested_class: str) -> list[str]:
        return sorted(
            service_class
            for service_class in self.allowed_service_classes
            if service_class != requested_class
            and any(
                slot.service_class == service_class
                and slot.denomination <= self.remaining_budget
                for slot in self._available_slots()
            )
        )

    def _deny(
        self,
        reason_code: str,
        service_class: str,
        merchant_id: str,
        amount: int,
        selected_capacity: int,
        *,
        reauthorization_required: bool,
    ) -> StructuredSpendDenial:
        if reason_code not in DENIAL_REASONS:
            raise ValueError(f"unknown denial reason: {reason_code}")
        available_capacity = sum(
            slot.denomination for slot in self._available_slots(service_class, merchant_id)
        )
        denial = StructuredSpendDenial(
            schema_version=self.denial_schema_version,
            reason_code=reason_code,
            requested_service_class=service_class,
            requested_merchant=merchant_id,
            quoted_price=amount,
            selected_slot_capacity=selected_capacity,
            remaining_slot_denominations=self.remaining_slot_denominations(),
            remaining_approved_budget=self.remaining_budget,
            funding_coverage_remaining=self.funding_coverage_remaining(),
            budget_shortfall=max(0, amount - self.remaining_budget),
            denomination_shortfall=max(0, amount - available_capacity),
            alternative_allowed_services=self._alternative_services(service_class),
            allowed_service_classes=self.allowed_service_classes,
            allowed_merchants=self.allowed_merchants,
            expiry=self.expiry,
            retryable=len(self.denials) < self.max_replans,
            reauthorization_required=reauthorization_required,
        )
        self.denials.append(denial)
        return denial

    def check(
        self, service_class: str, merchant_id: str, amount: int, trusted_now: int
    ) -> tuple[SpendReservation | None, StructuredSpendDenial | None]:
        if not service_class or not merchant_id or amount <= 0:
            return None, self._deny(
                "malformed_request", service_class, merchant_id, amount, 0,
                reauthorization_required=False,
            )
        pair_slots = self._available_slots(service_class, merchant_id)
        live_pair_slots = self._available_slots(
            service_class, merchant_id, trusted_now=trusted_now
        )
        if pair_slots and not live_pair_slots:
            return None, self._deny(
                "expired_mandate", service_class, merchant_id, amount, 0,
                reauthorization_required=True,
            )
        if service_class not in self.allowed_service_classes:
            return None, self._deny(
                "class_not_authorized", service_class, merchant_id, amount, 0,
                reauthorization_required=True,
            )
        if not pair_slots:
            return None, self._deny(
                "merchant_not_authorized", service_class, merchant_id, amount, 0,
                reauthorization_required=True,
            )
        if amount > self.remaining_budget:
            reason = (
                "single_quote_exceeds_initial_budget"
                if amount > self.initial_approved_budget
                else "global_budget_exhausted"
            )
            return None, self._deny(
                reason, service_class, merchant_id, amount, 0,
                reauthorization_required=True,
            )
        funded_slots = self._available_slots(
            service_class,
            merchant_id,
            trusted_now=trusted_now,
            require_funding=True,
        )
        if amount > self.funding_coverage_remaining() or not funded_slots:
            return None, self._deny(
                "applicable_class_capacity_exhausted",
                service_class,
                merchant_id,
                amount,
                sum(slot.denomination for slot in funded_slots),
                reauthorization_required=True,
            )
        selected = self._select_subset(
            funded_slots, amount
        )
        if selected is None:
            available_capacity = sum(
                slot.denomination
                for slot in self._available_slots(service_class, merchant_id)
            )
            reason = (
                "applicable_class_capacity_exhausted"
                if available_capacity < amount
                else "denomination_composition_failure"
            )
            return None, self._deny(
                reason,
                service_class,
                merchant_id,
                amount,
                available_capacity,
                reauthorization_required=True,
            )
        denominations = tuple(slot.denomination for slot in selected)
        selected_capacity = sum(denominations)
        return (
            SpendReservation(
                slot_indices=tuple(slot.slot_index for slot in selected),
                slot_denominations=denominations,
                selected_slot_capacity=selected_capacity,
                service_class=service_class,
                merchant_id=merchant_id,
                amount=amount,
                denomination_slack=selected_capacity - amount,
            ),
            None,
        )

    def commit(self, reservation: SpendReservation) -> None:
        if any(index in self._spent_slots for index in reservation.slot_indices):
            raise RuntimeError("denomination slot was already committed")
        if reservation.amount > self.remaining_budget:
            raise RuntimeError("budget changed after spend reservation")
        self._spent_slots.update(reservation.slot_indices)
        self.remaining_budget -= reservation.amount
        self.actual_spend += reservation.amount
        self.burned_slot_capacity += reservation.selected_slot_capacity
        self.denomination_slack_total += reservation.denomination_slack
        self.accepted_calls += 1
        if self.denials:
            self.replan_succeeded = True

    def amendment_approval_parameters(
        self,
        denial: StructuredSpendDenial,
    ) -> dict[str, Any]:
        pair = (denial.requested_service_class, denial.requested_merchant)
        joint_capacity_reason = denial.reason_code in {
            "single_quote_exceeds_initial_budget",
            "global_budget_exhausted",
            "applicable_class_capacity_exhausted",
            "denomination_composition_failure",
        }
        if not joint_capacity_reason or pair not in self._allowed_pairs:
            raise ValueError("denial cannot be repaired without widening policy")
        delta = max(1, denial.budget_shortfall, denial.denomination_shortfall)
        remaining = self._available_slots()
        remaining_capacity = sum(slot.denomination for slot in remaining)
        remaining_funding = sum(
            slot.funding_coverage for slot in remaining if slot.funding_eligible
        )
        if remaining_capacity != remaining_funding:
            raise ValueError(
                "remaining credential capacity lacks exact independent funding coverage"
            )
        slots = [
            {
                "service_class": slot.service_class,
                "merchant_id": slot.merchant_id,
                "capacity": slot.denomination,
                "expiry": int(slot.expiry or self.expiry),
            }
            for slot in remaining
        ]
        slots.append(
            {
                "service_class": denial.requested_service_class,
                "merchant_id": denial.requested_merchant,
                "capacity": delta,
                "expiry": denial.expiry,
            }
        )
        eligible = [
            index for index, slot in enumerate(remaining) if slot.funding_eligible
        ]
        eligible.append(len(slots) - 1)
        return {
            "workflow_id": self.initial_approval_artifact.workflow_id,
            "slots": slots,
            "base_budget": remaining_capacity,
            "reserve_budget": delta,
            "approved_budget": remaining_capacity + delta,
            "allowed_service_classes": list(self.allowed_service_classes),
            "allowed_merchants": list(self.allowed_merchants),
            "funding_eligible_slot_indices": eligible,
            "funding_coverage": remaining_funding + delta,
            "amendment_limit": 0,
            "approval_kind": "amendment",
            "approval_sequence": 1,
            "parent_approval_sha256": self.active_credential_id,
        }

    def _rejected_amendment(self, reason: str, delta: int) -> dict[str, Any]:
        self.reauthorization_rejections += 1
        return {
            "approved": False,
            "reason": reason,
            "decision": "approval_not_present_or_invalid",
            "request_number": self.reauthorization_requests,
            "requested_delta_budget": delta,
            "requested_delta_denomination_slots": [delta] if delta else [],
            "requested_delta_funding_coverage": delta,
            "delta_budget": 0,
            "delta_denomination_slots": [],
            "delta_funding_coverage": 0,
            "approval_artifact_sha256": None,
        }

    def prepare_reauthorization(
        self,
        denial: StructuredSpendDenial,
        approval_artifact: UserApprovalArtifact | None,
    ) -> tuple[PendingAmendment | None, dict[str, Any]]:
        self.reauthorization_requests += 1
        delta = max(1, denial.budget_shortfall, denial.denomination_shortfall)
        if self.reauthorization_requests > self.max_reauthorizations or self.reauthorizations:
            return None, self._rejected_amendment("amendment_limit_exhausted", delta)
        if approval_artifact is None:
            return None, self._rejected_amendment("explicit_approval_artifact_required", delta)
        try:
            approval_artifact.validate()
            expected = self.amendment_approval_parameters(denial)
        except ValueError as exc:
            return None, self._rejected_amendment(f"invalid_amendment_approval: {exc}", delta)
        expected_slots = tuple(ApprovedSlot.from_value(slot) for slot in expected["slots"])
        exact = (
            approval_artifact.workflow_id == expected["workflow_id"]
            and approval_artifact.slots == expected_slots
            and approval_artifact.base_budget == expected["base_budget"]
            and approval_artifact.reserve_budget == expected["reserve_budget"]
            and approval_artifact.approved_budget == expected["approved_budget"]
            and approval_artifact.allowed_service_classes
            == tuple(expected["allowed_service_classes"])
            and approval_artifact.allowed_merchants == tuple(expected["allowed_merchants"])
            and approval_artifact.funding_eligible_slot_indices
            == tuple(expected["funding_eligible_slot_indices"])
            and approval_artifact.funding_coverage == expected["funding_coverage"]
            and approval_artifact.amendment_limit == 0
            and approval_artifact.approval_kind == "amendment"
            and approval_artifact.approval_sequence == 1
            and approval_artifact.parent_approval_sha256 == self.active_credential_id
            and approval_artifact.artifact_sha256 != self.active_credential_id
        )
        if not exact:
            return None, self._rejected_amendment("amendment_artifact_policy_mismatch", delta)
        next_index = max((slot.slot_index for slot in self._slots), default=-1) + 1
        slot = DenominationSlot(
            slot_index=next_index,
            service_class=denial.requested_service_class,
            merchant_id=denial.requested_merchant,
            denomination=delta,
            funding_coverage=delta,
            reserve_kind="explicit_joint_amendment",
            expiry=denial.expiry,
            funding_eligible=True,
        )
        pending = PendingAmendment(approval_artifact, delta, slot)
        return pending, {
            "approved": True,
            "activation_pending": True,
            "request_number": self.reauthorization_requests,
            "approval_artifact_sha256": approval_artifact.artifact_sha256,
        }

    def activate_reauthorization(self, pending: PendingAmendment) -> dict[str, Any]:
        artifact = pending.approval_artifact
        if artifact.parent_approval_sha256 != self.active_credential_id:
            raise RuntimeError("active credential changed before amendment activation")
        retired = self.active_credential_id
        self._slots.append(pending.new_slot)
        self.approved_budget += pending.delta
        self.remaining_budget += pending.delta
        self.total_funding_coverage += pending.delta
        self.active_approval_artifact = artifact
        self.approval_history.append(artifact)
        self.retired_credential_ids.append(retired)
        self.active_credential_id = artifact.artifact_sha256
        self.reauthorizations += 1
        self.reauthorization_approvals += 1
        self.max_reauthorizations = 0
        amendment = {
            "approved": True,
            "decision": "explicit_artifact_verified",
            "request_number": self.reauthorization_requests,
            "requested_delta_budget": pending.delta,
            "requested_delta_denomination_slots": [pending.delta],
            "requested_delta_funding_coverage": pending.delta,
            "delta_budget": pending.delta,
            "delta_denomination_slots": [pending.delta],
            "delta_funding_coverage": pending.delta,
            "applicable_service_classes": [pending.new_slot.service_class],
            "applicable_merchants": [pending.new_slot.merchant_id],
            "expiry_change": 0,
            "approval_artifact_sha256": artifact.artifact_sha256,
            "approval_evidence_class": artifact.evidence_class,
            "retired_credential_id": retired,
            "active_credential_id": self.active_credential_id,
        }
        self.amendments.append(amendment)
        self._assert_joint_invariant()
        return amendment

    def request_reauthorization(
        self,
        denial: StructuredSpendDenial,
        approval_artifact: UserApprovalArtifact | None,
    ) -> dict[str, Any]:
        pending, result = self.prepare_reauthorization(denial, approval_artifact)
        return self.activate_reauthorization(pending) if pending is not None else result

    def remaining_crypto_slots_with_mapping(
        self,
    ) -> tuple[list[dict[str, Any]], dict[int, int]]:
        remaining = self._available_slots()
        return (
            [
                {
                    "service_class": slot.service_class,
                    "merchant_id": slot.merchant_id,
                    "capacity": slot.denomination,
                    "expiry": int(slot.expiry or self.expiry),
                    "funding_eligible": slot.funding_eligible,
                }
                for slot in remaining
            ],
            {slot.slot_index: credential_index for credential_index, slot in enumerate(remaining)},
        )

    def canonical_transcript(
        self, replan_state: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        return {
            "schema_version": "minmandate-canonical-policy-transcript-v1",
            "approval_chain": [artifact.to_dict() for artifact in self.approval_history],
            "policy": {
                "allowed_service_classes": list(self.allowed_service_classes),
                "allowed_merchants": list(self.allowed_merchants),
                "allowed_pairs": [list(pair) for pair in sorted(self._allowed_pairs)],
                "base_budget": self.base_budget,
                "initial_reserve_budget": self.joint_reserve_amount,
                "initial_approved_budget": self.initial_approved_budget,
                "approved_budget": self.approved_budget,
                "remaining_budget": self.remaining_budget,
                "initial_funding_coverage": self.initial_funding_coverage,
                "total_funding_coverage": self.total_funding_coverage,
                "funding_coverage_remaining": self.funding_coverage_remaining(),
                "amendment_limit": self.initial_approval_artifact.amendment_limit,
            },
            "ordered_slots": [
                {
                    "slot_index": slot.slot_index,
                    "service_class": slot.service_class,
                    "merchant_id": slot.merchant_id,
                    "capacity": slot.denomination,
                    "expiry": slot.expiry,
                    "funding_eligible": slot.funding_eligible,
                    "funding_coverage": slot.funding_coverage,
                    "reserve_kind": slot.reserve_kind,
                    "state": "spent" if slot.slot_index in self._spent_slots else "remaining",
                }
                for slot in self._slots
            ],
            "denials": [denial.to_dict() for denial in self.denials],
            "replans": dict(replan_state or {}),
            "amendment_state": {
                "requests": self.reauthorization_requests,
                "approvals": self.reauthorization_approvals,
                "rejections": self.reauthorization_rejections,
                "amendments": list(self.amendments),
                "active_credential_id": self.active_credential_id,
                "retired_credential_ids": list(self.retired_credential_ids),
                "remaining": max(0, self.max_reauthorizations - self.reauthorizations),
            },
        }

    def transcript_sha256(self, replan_state: dict[str, Any] | None = None) -> str:
        return sha256_bytes(
            canonical_json(self.canonical_transcript(replan_state)).encode("utf-8")
        )

    def metrics(self) -> dict[str, Any]:
        remaining_denominations = self.remaining_slot_denominations()
        funding_remaining = self.funding_coverage_remaining()
        return {
            "number_of_replans": len(self.denials),
            "structured_denial_count": len(self.denials),
            "denial_reason_sequence": [item.reason_code for item in self.denials],
            "whether_replan_succeeded": self.replan_succeeded,
            "reauthorization_requests": self.reauthorization_requests,
            "reauthorization_approvals": self.reauthorization_approvals,
            "reauthorization_rejections": self.reauthorization_rejections,
            "amendments": self.amendments,
            "initial_approval_artifact_sha256": self.initial_approval_artifact.artifact_sha256,
            "active_approval_artifact_sha256": self.active_credential_id,
            "retired_credential_ids": self.retired_credential_ids,
            "canonical_policy_transcript_sha256": self.transcript_sha256(),
            "total_approved_budget": self.approved_budget,
            "initial_approved_budget": self.initial_approved_budget,
            "base_budget": self.base_budget,
            "actual_spend": self.actual_spend,
            "remaining_budget": self.remaining_budget,
            "initial_slot_denominations": [slot.denomination for slot in self._slots],
            "remaining_slot_denominations": remaining_denominations,
            "funding_coverage_initial": self.initial_funding_coverage,
            "funding_coverage_remaining": funding_remaining,
            "denomination_slack": self.denomination_slack_total,
            "burned_slot_capacity": self.burned_slot_capacity,
            "unused_authorized_capacity": min(self.remaining_budget, funding_remaining),
            "joint_reserve_amount": self.joint_reserve_amount,
            "capacity_inflation": (
                (self.approved_budget - self.base_budget) / self.base_budget
                if self.base_budget
                else 0.0
            ),
            "accepted_paid_calls": self.accepted_calls,
            "invocation_quota": None,
        }
