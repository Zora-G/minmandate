"""Benchmark-owned AP2 v0.2 bridge for the query-free Table 1 harness.

This module is the only AgentDojo-facing AP2 layer.  It compiles the frozen
protocol-neutral approval directly into the AP2 bundle and translates a
confirmed tariff quote into an official AP2 PaidToolCall.  It never consumes a
MinMandate wire object and it does not implement AP2 cryptography or receipts.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import importlib
import json
import os
from pathlib import Path
import time
from typing import Any, Mapping

from experiments.adapters.ap2_money import CanonicalMoney, nanos_to_ap2_minor_units
from experiments.adapters.ap2_commerce_adapter import AP2CommerceAdapter


def _opaque_id(prefix: str, value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"{prefix}-{hashlib.sha256(encoded.encode('utf-8')).hexdigest()[:32]}"


def _assert_conformant_sdk_path(module_file: Path) -> None:
    """Require the approved SDK copy when a cost-pilot launcher asks for it."""

    sdk_root = os.environ.get("MM_AP2_CONFORMANT_SDK_ROOT")
    manifest_sha256 = os.environ.get("MM_AP2_CONFORMANT_MANIFEST_SHA256")
    if sdk_root is None and manifest_sha256 is None:
        return
    if not sdk_root or not manifest_sha256:
        raise RuntimeError("incomplete AP2-v0.2-conformant launcher binding")
    expected_root = Path(sdk_root).resolve()
    try:
        module_file.resolve().relative_to(expected_root)
    except ValueError as error:
        raise RuntimeError(
            "AP2 cost pilot did not import the approved materialized SDK"
        ) from error
    manifest = (
        Path(__file__).resolve().parents[2]
        / "experiments/configs/ap2_v0_2_conformant_manifest.json"
    )
    observed = hashlib.sha256(manifest.read_bytes()).hexdigest()
    if observed != manifest_sha256:
        raise RuntimeError("AP2 cost pilot manifest hash differs from launcher binding")


@dataclass(frozen=True, slots=True)
class AP2ApprovalCompilation:
    approval: Any
    money_audit: tuple[dict[str, Any], ...]
    source_authorizations_sha256: str | None = None


def _ap2_types():
    # The approved cost-pilot launcher inserts the materialized SDK first.
    sdk_module = importlib.import_module("ap2.sdk")
    _assert_conformant_sdk_path(Path(str(sdk_module.__file__)))
    from ap2_baseline import AP2BaselineController, AP2Profile, MerchantSpec, NeutralApproval
    from ap2_baseline import ToolAuthorization

    return AP2BaselineController, AP2Profile, MerchantSpec, NeutralApproval, ToolAuthorization


def compile_protocol_neutral_approval(
    mandate_draft: Mapping[str, Any],
    *,
    merchant_metadata: Mapping[str, Mapping[str, Any]] | None = None,
    require_exact_economic_amounts: bool = False,
) -> AP2ApprovalCompilation:
    """Compile frozen quote caps, independently of MinMandate slots/wire.

    The draft must contain one quote cap for every approved paid occurrence. A
    missing cap is an error; no tariff fallback or silent amount conversion is
    permitted.
    """
    _, _, MerchantSpec, NeutralApproval, ToolAuthorization = _ap2_types()
    source_task_id = str(mandate_draft.get("base_task_id") or mandate_draft.get("workflow_id") or "")
    if not source_task_id:
        raise ValueError("AP2 neutral approval requires a frozen draft identity")
    currency = str(mandate_draft.get("currency") or "USD").upper()
    expiry = int(mandate_draft.get("expiry", -1))
    if expiry < 0:
        raise ValueError("AP2 neutral approval requires non-negative expiry")
    raw_authorizations = mandate_draft.get("authorizations")
    if not isinstance(raw_authorizations, list) or not raw_authorizations:
        raise ValueError("AP2 neutral approval requires frozen authorizations")
    metadata = merchant_metadata or {}
    grouped: dict[tuple[str, str, str], list[CanonicalMoney]] = {}
    audit: list[dict[str, Any]] = []
    for authorization in raw_authorizations:
        if not isinstance(authorization, Mapping):
            raise TypeError("invalid frozen authorization")
        service_class = str(authorization.get("service_class", ""))
        merchant_id = str(authorization.get("merchant_id", ""))
        capacity = int(authorization.get("capacity", 0))
        caps = authorization.get("quote_caps")
        if not service_class or not merchant_id or capacity <= 0:
            raise ValueError("authorization requires service class, merchant and positive capacity")
        if not isinstance(caps, list) or len(caps) != capacity:
            raise ValueError(
                f"authorization {service_class}/{merchant_id} quote_caps must have exactly {capacity} entries"
            )
        for cap in caps:
            if not isinstance(cap, Mapping) or not str(cap.get("tool_name", "")):
                raise ValueError("each AP2 authorization must name its paid tool")
            tool_name = str(cap["tool_name"])
            source_nanos = cap.get("amount_nanos")
            if not isinstance(source_nanos, int):
                raise ValueError("AP2 quote caps require integer amount_nanos")
            money = nanos_to_ap2_minor_units(source_nanos, currency)
            if require_exact_economic_amounts and money.rounding_delta_nanos != 0:
                raise ValueError(
                    "AP2 shared economic trace is not exactly representable in "
                    f"{currency} minor units: {source_nanos} nanos"
                )
            grouped.setdefault((service_class, merchant_id, tool_name), []).append(money)
            audit.append({
                "source_task_id": source_task_id,
                "service_class": service_class,
                "merchant_id": merchant_id,
                "tool_name": tool_name,
                **money.audit_row(),
            })
    if not grouped:
        raise ValueError("AP2 neutral approval has no paid quote caps")
    tools = []
    for (service_class, merchant_id, tool_name), values in sorted(grouped.items()):
        merchant_info = metadata.get(merchant_id, {})
        merchant = MerchantSpec(
            id=merchant_id,
            name=str(merchant_info.get("name") or merchant_id),
            website=(str(merchant_info["website"]) if merchant_info.get("website") else None),
        )
        tools.append(
            ToolAuthorization(
                tool_id=tool_name,
                title=tool_name,
                service_class=service_class,
                merchant=merchant,
                max_calls=len(values),
                per_call_max_minor=max(item.minor_units for item in values),
                allocated_budget_minor=sum(item.minor_units for item in values),
            )
        )
    # AP2's v0.2 model calls this field ``task_id``. The benchmark task
    # identity must never cross the verifier boundary, so use an opaque
    # approval identifier derived only from the frozen authorization object.
    approval_id = _opaque_id(
        "approval",
        {
            "currency": currency,
            "expiry": expiry,
            "allowed_merchants": sorted(
                str(value) for value in (mandate_draft.get("allowed_merchants") or [])
            ),
            "tools": [
                {
                    "tool_id": tool.tool_id,
                    "service_class": tool.service_class,
                    "merchant": tool.merchant.id,
                    "max_calls": tool.max_calls,
                    "per_call_max_minor": tool.per_call_max_minor,
                    "allocated_budget_minor": tool.allocated_budget_minor,
                }
                for tool in tools
            ],
        },
    )
    explicit_allowed = mandate_draft.get("allowed_merchants")
    allowed_merchants = None
    if explicit_allowed is not None:
        if not isinstance(explicit_allowed, list) or not explicit_allowed:
            raise ValueError("AP2 allowed_merchants must be a nonempty list")
        allowed_merchants = tuple(
            MerchantSpec(
                id=str(merchant_id),
                name=str(metadata.get(str(merchant_id), {}).get("name") or merchant_id),
                website=(
                    str(metadata[str(merchant_id)]["website"])
                    if metadata.get(str(merchant_id), {}).get("website")
                    else None
                ),
            )
            for merchant_id in sorted({str(value) for value in explicit_allowed})
        )
    approval = NeutralApproval(
        task_id=approval_id,
        currency=currency,
        total_budget_minor=sum(item.minor_units for values in grouped.values() for item in values),
        expires_at=expiry,
        tools=tuple(tools),
        allowed_merchants=allowed_merchants,
    )
    return AP2ApprovalCompilation(approval=approval, money_audit=tuple(audit))


@dataclass(frozen=True, slots=True)
class AP2AuthorizationDecision:
    accepted: bool
    reason: str | None
    violations: tuple[str, ...]
    outcome: str
    result: dict[str, Any]
    money_audit: dict[str, Any]


class AP2QueryFreeController:
    """Harness bridge around the official AP2BaselineController."""

    def __init__(
        self,
        mandate_draft: Mapping[str, Any],
        *,
        workflow_id: str,
        now_fn,
        profile: str = "ap2_native",
        merchant_metadata: Mapping[str, Mapping[str, Any]] | None = None,
        require_exact_economic_amounts: bool = False,
    ) -> None:
        AP2BaselineController, AP2Profile, _, _, _ = _ap2_types()
        compiled = compile_protocol_neutral_approval(
            mandate_draft,
            merchant_metadata=merchant_metadata,
            require_exact_economic_amounts=require_exact_economic_amounts,
        )
        self.compilation = compiled
        self.require_exact_economic_amounts = require_exact_economic_amounts
        self.source_workflow_id = workflow_id
        self.workflow_id = _opaque_id(
            "session", {"approval": compiled.approval.to_dict(), "profile": profile}
        )
        self.commerce = AP2CommerceAdapter(merchant_metadata=merchant_metadata)
        self._logical_now_fn = now_fn
        self._logical_start = int(now_fn())
        self._wall_start = int(time.time())
        logical_delta = compiled.approval.expires_at - self._logical_start
        if logical_delta < 0:
            raise ValueError("AP2 approval is already expired at the harness logical time")
        # AP2 v0.2's SDK uses its process clock internally for KB-SD-JWT iat.
        # Map the frozen benchmark logical expiry to the wall-clock epoch only
        # inside this adapter; preserve the original logical expiry in the audit.
        wire_approval = replace(
            compiled.approval, expires_at=self._wall_start + logical_delta
        )
        try:
            ap2_profile = AP2Profile(str(profile))
        except ValueError as exc:
            raise ValueError(f"unsupported AP2 profile: {profile}") from exc
        self.controller = AP2BaselineController(
            wire_approval,
            profile=ap2_profile,
            now_fn=lambda: self._wall_start + max(0, int(now_fn()) - self._logical_start),
            **self.commerce.engine_kwargs(),
        )
        # The official engine already measures this task-scoped work.  Expose
        # it once in the raw episode trace without changing AP2 execution.
        self._task_setup_ms = float(self.controller.engine.task_authorization_setup_ms)
        self._task_setup_reported = False

    def authorize_paid_call(
        self,
        *,
        call_id: str,
        tool_name: str,
        title: str,
        service_class: str,
        arguments: Mapping[str, Any],
        quote: Any,
        merchant_metadata: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> AP2AuthorizationDecision:
        _, _, MerchantSpec, _, _ = _ap2_types()
        merchant_id = str(quote.merchant_id)
        metadata = (merchant_metadata or {}).get(merchant_id, {})
        merchant = MerchantSpec(
            id=merchant_id,
            name=str(metadata.get("name") or merchant_id),
            website=(str(metadata["website"]) if metadata.get("website") else None),
        )
        from ap2_baseline import PaidToolCall, Quote

        money = nanos_to_ap2_minor_units(int(quote.amount_nanos), str(quote.currency))
        if self.require_exact_economic_amounts and money.rounding_delta_nanos != 0:
            raise ValueError(
                "AP2 shared runtime quote is not exactly representable in "
                f"{money.currency} minor units: {money.source_nanos} nanos"
            )
        opaque_call_id = _opaque_id(
            "call",
            {
                "tool": tool_name,
                "service_class": service_class,
                "arguments": dict(arguments),
                "quote_id": str(quote.quote_id),
                "amount_minor": money.minor_units,
                "merchant": merchant_id,
            },
        )
        call = PaidToolCall(
            workflow_id=self.workflow_id,
            call_id=opaque_call_id,
            tool_id=str(tool_name),
            title=str(title),
            service_class=str(service_class),
            arguments=dict(arguments),
            quote=Quote(
                amount_minor=money.minor_units,
                currency=money.currency,
                merchant=merchant,
                nonce=str(quote.quote_id),
            ),
        )
        result = self.controller.authorize_paid_call(call)
        result_dict = result.to_dict(include_tokens=True)
        timings = dict(result_dict.get("timings_ms") or {})
        timings["task_authorization_setup_ms"] = (
            0.0 if self._task_setup_reported else self._task_setup_ms
        )
        result_dict["timings_ms"] = timings
        self._task_setup_reported = True
        return AP2AuthorizationDecision(
            accepted=bool(result.accepted),
            reason=result.reason,
            violations=tuple(str(item) for item in result.violations),
            outcome=str(result.outcome),
            result=result_dict,
            money_audit={
                "call_id": str(call_id),
                "quote_id": str(quote.quote_id),
                "tool_name": str(tool_name),
                "approval_expires_at_logical": self.compilation.approval.expires_at,
                "approval_expires_at_wire": self.controller.approval.expires_at,
                **money.audit_row(),
            },
        )
