from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True, slots=True)
class PaymentContext:
    workflow_id: str
    base_task_id: str
    call_id: str
    call_index: int
    suite: str
    tool_name: str
    canonical_arguments: dict[str, Any]
    merchant_visible_descriptor: str
    service_class: str
    merchant_id: str
    amount: int
    trusted_now: int
    seed: int


@dataclass(slots=True)
class RoleView:
    role: str
    coalition: str
    value: dict[str, Any]
    schema_valid: bool
    schema_validation: str
    validation_errors: list[str]


@dataclass(slots=True)
class PaymentArtifact:
    protocol: str
    protocol_version: str
    accepted: bool
    error_code: str | None
    role_views: list[RoleView]
    timing_ms: dict[str, Any]


class PaymentAdapter(Protocol):
    protocol: str
    protocol_version: str

    def create(self, context: PaymentContext) -> PaymentArtifact: ...
