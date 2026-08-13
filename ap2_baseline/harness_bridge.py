from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .domain import AP2Profile, NeutralApproval, PaidToolCall
from .engine import AP2BaselineEngine, AP2CallResult


@dataclass(slots=True)
class HarnessDecision:
    accepted: bool
    reason: str | None
    result: AP2CallResult


class AP2BaselineController:
    """Thin bridge to the existing Native/Policy/Full experiment controller.

    Codex should adapt only the two conversion callbacks below to the current
    repository. Keep the AP2 engine independent of benchmark internals.
    """

    def __init__(
        self,
        approval_from_task: Callable[[Any], NeutralApproval],
        call_from_runner: Callable[[Any, Any], PaidToolCall],
        profile: AP2Profile = AP2Profile.NATIVE,
    ) -> None:
        self._approval_from_task = approval_from_task
        self._call_from_runner = call_from_runner
        self._profile = profile
        self._engines: dict[str, AP2BaselineEngine] = {}

    def issue_task(self, task_record: Any) -> AP2BaselineEngine:
        approval = self._approval_from_task(task_record)
        engine = AP2BaselineEngine(approval, profile=self._profile)
        self._engines[approval.task_id] = engine
        return engine

    def authorize_paid_call(
        self,
        task_id: str,
        planner_call: Any,
        frozen_quote: Any,
    ) -> HarnessDecision:
        engine = self._engines[task_id]
        call = self._call_from_runner(planner_call, frozen_quote)
        result = engine.execute(call)
        return HarnessDecision(result.accepted, result.reason, result)
