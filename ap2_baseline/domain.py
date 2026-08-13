from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any


class AP2Profile(StrEnum):
    NATIVE = "ap2_native"
    COMMON_POLICY = "ap2_common_policy"


@dataclass(frozen=True, slots=True)
class MerchantSpec:
    id: str
    name: str
    website: str | None = None

    def __post_init__(self) -> None:
        if not self.id or not self.name:
            raise ValueError("merchant id and name are required")


@dataclass(frozen=True, slots=True)
class ToolAuthorization:
    tool_id: str
    title: str
    service_class: str
    merchant: MerchantSpec
    max_calls: int
    per_call_max_minor: int
    allocated_budget_minor: int

    def __post_init__(self) -> None:
        if not self.tool_id or not self.title:
            raise ValueError("tool_id and title are required")
        if self.max_calls <= 0:
            raise ValueError("max_calls must be positive")
        if self.per_call_max_minor <= 0 or self.allocated_budget_minor <= 0:
            raise ValueError("amount limits must be positive")
        if self.allocated_budget_minor > self.max_calls * self.per_call_max_minor:
            # This is allowed economically but usually indicates a frozen-config bug.
            raise ValueError("allocated budget exceeds max_calls * per_call_max")


@dataclass(frozen=True, slots=True)
class NeutralApproval:
    task_id: str
    currency: str
    total_budget_minor: int
    expires_at: int
    tools: tuple[ToolAuthorization, ...]
    allowed_merchants: tuple[MerchantSpec, ...] | None = None

    def __post_init__(self) -> None:
        if not self.task_id:
            raise ValueError("task_id is required")
        if len(self.currency) != 3 or self.currency.upper() != self.currency:
            raise ValueError("currency must be an ISO-4217 alpha-3 code")
        if self.total_budget_minor <= 0:
            raise ValueError("total budget must be positive")
        if not self.tools:
            raise ValueError("at least one tool authorization is required")
        if self.allowed_merchants is not None and not self.allowed_merchants:
            raise ValueError("allowed_merchants cannot be empty when specified")
        if sum(t.allocated_budget_minor for t in self.tools) > self.total_budget_minor:
            raise ValueError("per-tool allocated budgets exceed total budget")

    @property
    def max_calls(self) -> int:
        return sum(t.max_calls for t in self.tools)

    @property
    def per_call_max_minor(self) -> int:
        return max(t.per_call_max_minor for t in self.tools)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Quote:
    amount_minor: int
    currency: str
    merchant: MerchantSpec
    nonce: str

    def __post_init__(self) -> None:
        if self.amount_minor <= 0:
            raise ValueError("quoted amount must be positive")
        if not self.nonce:
            raise ValueError("quote nonce is required")


@dataclass(frozen=True, slots=True)
class PaidToolCall:
    workflow_id: str
    call_id: str
    tool_id: str
    title: str
    service_class: str
    arguments: dict[str, Any]
    quote: Quote

    def __post_init__(self) -> None:
        if not self.workflow_id or not self.call_id or not self.tool_id:
            raise ValueError("workflow_id, call_id and tool_id are required")
