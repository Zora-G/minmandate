from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock
from typing import Callable

from ap2.sdk.constraints import MandateContext

from .compiler import AP2MandatePair


@dataclass(slots=True)
class RedemptionOutcome:
    status: str
    violations: list[str] = field(default_factory=list)
    idempotent: bool = False


class AP2UsageLedger:
    """Local atomic state for AP2 recurrence and budget constraints.

    This is not a new AP2 credential mechanism. It serializes the official
    MandateContext check and update so concurrent local calls cannot pass the
    same stale recurrence/budget state.
    """

    def __init__(self) -> None:
        self._lock = RLock()

    def redeem(
        self,
        pair: AP2MandatePair,
        transaction_id: str,
        amount_minor: int,
        verify_with_context: Callable[[MandateContext], list[str]],
    ) -> RedemptionOutcome:
        with self._lock:
            previous = pair.accepted_transactions.get(transaction_id)
            if previous is not None:
                if previous == amount_minor:
                    return RedemptionOutcome("idempotent_receipt", idempotent=True)
                return RedemptionOutcome(
                    "rejected", ["conflicting transaction_id reuse"]
                )

            context = MandateContext(
                total_amount=pair.spent_minor,
                total_uses=pair.use_count,
            )
            violations = verify_with_context(context)
            if violations:
                return RedemptionOutcome("rejected", violations)

            pair.accepted_transactions[transaction_id] = amount_minor
            pair.spent_minor += amount_minor
            pair.use_count += 1
            return RedemptionOutcome("fresh_accept")
