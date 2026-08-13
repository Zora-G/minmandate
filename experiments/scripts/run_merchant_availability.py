#!/usr/bin/env python3
"""Replay merchant-uncertainty conditions over paired workflow cohorts.

The initial approval contains the candidate merchant set. Recorded business
results and benchmark utility are attached to protocol-accepted paid traces.
"""

from __future__ import annotations

import argparse
import copy
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = (
    Path(os.environ["MINMANDATE_ROOT"])
    if "MINMANDATE_ROOT" in os.environ
    else Path(__file__).resolve().parents[2]
).resolve()
import sys
sys.path.insert(0, str(ROOT))

from experiments.adapters.base import PaymentContext
from experiments.adapters.minmandate_adapter import PersistentMinMandateClient
from experiments.common import canonical_json
from experiments.runtime.minmandate_contract import load_or_create_user_approval
from experiments.scripts.run_coverage_replay import _conformant_ap2
from experiments.common import read_jsonl
from experiments.spend_capacity import JointSpendCapacityState, build_spend_capacity_plan


OUTPUT = ROOT / "experiments/paper_official/merchant_uncertainty/offline_v3_96"
CONFIG = Path(
    os.environ.get(
        "MU_CONFIG",
        str(ROOT / "experiments/configs/merchant_uncertainty_offline_v2.json"),
    )
).resolve()
RUST_BINARY = Path(
    os.environ.get(
        "MINMANDATE_RUST_BINARY",
        str(ROOT / "artifact-rs/target/release/minmandate-rs"),
    )
).resolve()
POLICY_CONFIG = ROOT / "artifacts/merchant-uncertainty-v3-96/issuer_policy_config.json"
SCENARIOS = (
    "unknown_exact_merchant_within_set",
    "multiple_candidates",
    "runtime_substitution_within_set",
    "out_of_set_negative_control",
)
PROTOCOLS = ("ap2", "minmandate")
PLANNER_RUN_PREFIX = "offline-merchant-uncertainty-v3-96-r4-planner"


@dataclass(frozen=True, slots=True)
class FormalEpisode:
    planner: str
    run_id: str
    episode: dict[str, Any]
    calls: tuple[dict[str, Any], ...]
    ap2_rows: tuple[dict[str, Any], ...]
    draft: dict[str, Any]


def _sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text("".join(canonical_json(row) + "\n" for row in rows), encoding="utf-8")
    tmp.replace(path)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _workflow_id(item: Any) -> str:
    return str(item.episode["episode_id"]).rsplit(":", 1)[0]


def paid_calls(item: Any) -> list[dict[str, Any]]:
    return [row for row in item.calls if row.get("paid") is True]


def load_planner_rerun(protocol: str, planner: str, run_prefix: str) -> list[FormalEpisode]:
    condition = "ap2_native" if protocol == "ap2" else "minmandate"
    result: list[FormalEpisode] = []
    for run_dir in sorted(ROOT.glob(f"results/{run_prefix}-{planner}-*")):
        manifest_path = run_dir / "manifest.json"
        if not manifest_path.is_file():
            continue
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("status") != "raw_complete" or manifest.get("freeze_verified_at_raw_complete") is not True:
            continue
        calls_by_episode: dict[str, list[dict[str, Any]]] = {}
        for row in read_jsonl(run_dir / "tool_calls.jsonl"):
            calls_by_episode.setdefault(str(row["episode_id"]), []).append(row)
        ap2_by_episode: dict[str, list[dict[str, Any]]] = {}
        ap2_path = run_dir / "ap2_raw_calls.jsonl"
        if ap2_path.is_file():
            for row in read_jsonl(ap2_path):
                ap2_by_episode.setdefault(str(row["episode_id"]), []).append(row)
        drafts = {
            str(row["workflow_id"]): row
            for row in read_jsonl(run_dir / "mandate_drafts.jsonl")
        }
        for episode in read_jsonl(run_dir / "benchmark_episodes.jsonl"):
            episode_id = str(episode["episode_id"])
            if not episode_id.endswith(":" + condition):
                continue
            workflow = episode_id.rsplit(":", 1)[0]
            result.append(FormalEpisode(
                planner=planner,
                run_id=run_dir.name,
                episode=episode,
                calls=tuple(sorted(calls_by_episode.get(episode_id, []), key=lambda row: int(row["call_index"]))),
                ap2_rows=tuple(sorted(ap2_by_episode.get(episode_id, []), key=lambda row: int(row["call_index"]))),
                draft=drafts[workflow],
            ))
    identities = [str(item.episode["episode_id"]) for item in result]
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    expected = int(config["source"]["episodes_per_planner_condition"])
    if len(result) != expected or len(set(identities)) != expected:
        raise RuntimeError(
            f"planner rerun is not a complete {expected}-episode cohort: {protocol}/{planner} "
            f"rows={len(result)} unique={len(set(identities))}"
        )
    return sorted(result, key=lambda item: str(item.episode["episode_id"]))


def _candidate_catalog() -> dict[str, list[str]]:
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    return {
        str(tool): [str(value) for value in values]
        for tool, values in config["merchant_catalog"].items()
    }


def _candidate_for(item: Any, call: dict[str, Any], scenario: str, catalog: dict[str, list[str]]) -> str:
    candidates = catalog[str(call["tool_name"])]
    source = str(call["merchant_id"])
    if source not in candidates or len(candidates) < 2:
        raise ValueError(f"incomplete candidate set for {call['tool_name']}: {candidates}")
    digest = hashlib.sha256(
        f"{item.episode['base_task_id']}|{item.episode['seed']}|{call['tool_name']}|{call['call_index']}".encode()
    ).digest()
    if scenario == "multiple_candidates":
        return candidates[int.from_bytes(digest[:8], "big") % len(candidates)]
    if scenario == "unknown_exact_merchant_within_set":
        return candidates[int.from_bytes(digest[8:16], "big") % len(candidates)]
    if scenario == "runtime_substitution_within_set":
        alternatives = [value for value in candidates if value != source]
        return alternatives[int.from_bytes(digest[16:24], "big") % len(alternatives)]
    if scenario == "out_of_set_negative_control":
        return f"{source}-outside-approved-set"
    raise ValueError(scenario)


def _expand_authorizations(rows: list[dict[str, Any]], catalog: dict[str, list[str]]) -> list[dict[str, Any]]:
    expanded: list[dict[str, Any]] = []
    for row in rows:
        caps = list(row.get("quote_caps") or [])
        if not caps:
            raise ValueError("authorization has no quote caps")
        tools = sorted({str(cap["tool_name"]) for cap in caps})
        candidate_sets = {tuple(catalog[tool]) for tool in tools}
        if len(candidate_sets) != 1:
            raise ValueError(
                "authorization groups tools with different merchant candidate sets: "
                f"{tools}"
            )
        candidates = list(next(iter(candidate_sets)))
        for merchant in candidates:
            clone = copy.deepcopy(row)
            clone["merchant_id"] = merchant
            expanded.append(clone)
    return expanded


def _expanded_draft(item: Any, catalog: dict[str, list[str]]) -> dict[str, Any]:
    draft = copy.deepcopy(item.draft)
    draft["authorizations"] = _expand_authorizations(list(draft.get("authorizations") or []), catalog)
    draft["slots"] = _expand_authorizations(list(draft.get("slots") or []), catalog)
    candidate_factor = max(len(values) for values in catalog.values())
    draft["budget"] = int(draft["budget"]) * candidate_factor
    draft["allowed_merchants"] = sorted({str(row["merchant_id"]) for row in draft["authorizations"]})
    draft["offline_merchant_uncertainty"] = {
        "candidate_factor": candidate_factor,
        "reauthorization_allowed": False,
        "source_budget_nanos": int(item.draft["budget"]),
        "locked_budget_nanos": int(draft["budget"]),
    }
    return draft


def _base_row(item: Any, protocol: str, scenario: str, draft: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "minmandate-offline-merchant-uncertainty-episode-v3-96",
        "experiment_id": "offline-merchant-uncertainty-v3-96",
        "protocol": protocol,
        "planner": item.planner,
        "scenario": scenario,
        "source_run_id": item.run_id,
        "source_episode_id": str(item.episode["episode_id"]),
        "base_task_id": str(item.episode["base_task_id"]),
        "model_id": str(item.episode["model_id"]),
        "seed": int(item.episode["seed"]),
        "source_task_success": bool(item.episode["task_success"]),
        "initial_approval_formation_success": False,
        "approval_formation_failure": None,
        "candidate_set_size": 3,
        "initial_authorization_artifacts": 0,
        "initial_authorization_entries": 0,
        "initial_authorization_slots": 0,
        "initial_approval_artifact_bytes": 0,
        "initial_authorization_artifact_bytes": 0,
        "source_budget_nanos": int(item.draft["budget"]),
        "locked_budget_nanos": int(draft["budget"]),
        "budget_inflation_ratio": int(draft["budget"]) / int(item.draft["budget"]),
        "availability_rejections": 0,
        "merchant_authorization_rejections": 0,
        "offline_policy_replans": 0,
        "runtime_substitution_required": scenario == "runtime_substitution_within_set",
        "runtime_substitution_events": 0,
        "substitution_obligation_satisfied": scenario != "runtime_substitution_within_set",
        "user_reauthorization_requests": 0,
        "user_reauthorization_approvals": 0,
        "unauthorized_user_interactions": 0,
        "complete_paid_trace_authorized": False,
        "end_to_end_success": False,
        "paid_calls_in_source_trace": len(paid_calls(item)),
        "paid_calls_authorized": 0,
        "external_payment_requests": 0,
        "network_transactions": 0,
        "funds_moved": False,
        "call_authorization_trace": [],
    }


def _finalize(row: dict[str, Any]) -> dict[str, Any]:
    row["end_to_end_success"] = bool(
        row["initial_approval_formation_success"]
        and row["complete_paid_trace_authorized"]
        and row["source_task_success"]
        and row["substitution_obligation_satisfied"]
        and row["user_reauthorization_requests"] == 0
        and row["unauthorized_user_interactions"] == 0
    )
    row["record_sha256"] = _sha256(row)
    return row


def replay_ap2(item: Any, scenario: str, catalog: dict[str, list[str]]) -> dict[str, Any]:
    from experiments.adapters.ap2_baseline_adapter import AP2QueryFreeController

    draft = _expanded_draft(item, catalog)
    row = _base_row(item, "ap2", scenario, draft)
    metadata = {
        merchant: {"name": merchant, "website": f"https://{merchant}.local.invalid"}
        for values in catalog.values() for merchant in values
    }
    try:
        logical_now = 1
        controller = AP2QueryFreeController(
            draft,
            workflow_id=_workflow_id(item),
            profile="ap2_native",
            now_fn=lambda: logical_now,
            merchant_metadata=metadata,
            require_exact_economic_amounts=True,
        )
        row["initial_approval_formation_success"] = True
        pairs = controller.controller.engine.pool.pairs
        row["initial_authorization_artifacts"] = 2 * len(pairs)
        row["initial_authorization_entries"] = len(controller.compilation.approval.tools)
        row["initial_authorization_slots"] = sum(tool.max_calls for tool in controller.compilation.approval.tools)
        row["initial_approval_artifact_bytes"] = len(
            canonical_json(controller.compilation.approval.to_dict()).encode("utf-8")
        )
        row["initial_authorization_artifact_bytes"] = sum(
            len(pair.open_checkout_token.encode("utf-8"))
            + len(pair.open_payment_token.encode("utf-8"))
            for pair in pairs
        )
    except Exception as error:
        row["approval_formation_failure"] = f"{type(error).__name__}: {error}"
        return _finalize(row)

    complete = True
    for call in paid_calls(item):
        runtime_merchant = _candidate_for(item, call, scenario, catalog)
        source_merchant = str(call["merchant_id"])
        call_metadata = dict(metadata)
        call_metadata.setdefault(
            runtime_merchant,
            {
                "name": runtime_merchant,
                "website": f"https://{runtime_merchant}.local.invalid",
            },
        )
        replan = scenario == "runtime_substitution_within_set" and runtime_merchant != source_merchant
        if replan:
            row["availability_rejections"] += 1
            row["offline_policy_replans"] += 1
            row["runtime_substitution_events"] += 1
        logical_now = 1 + int(call["call_index"])
        quote = SimpleNamespace(
            amount_nanos=int(call["quoted_price_nanos"]),
            currency="USD",
            merchant_id=runtime_merchant,
            quote_id=_sha256([call["price_quote_id"], scenario, runtime_merchant]),
        )
        decision = controller.authorize_paid_call(
            call_id=_sha256([scenario, call["call_id"]]),
            tool_name=str(call["tool_name"]),
            title=str(call["tool_name"]),
            service_class=str(call["service_class"]),
            arguments=dict(call["canonical_tool_arguments"]),
            quote=quote,
            merchant_metadata=call_metadata,
        )
        accepted = bool(decision.accepted)
        if not accepted:
            row["merchant_authorization_rejections"] += 1
            complete = False
        else:
            row["paid_calls_authorized"] += 1
        row["call_authorization_trace"].append({
            "call_index": int(call["call_index"]),
            "tool_name": str(call["tool_name"]),
            "source_merchant_id": source_merchant,
            "runtime_merchant_id": runtime_merchant,
            "availability_rejection_before_selection": replan,
            "offline_policy_replan": replan,
            "accepted": accepted,
            "outcome": str(decision.outcome),
            "reason": decision.reason,
        })
        if not accepted:
            break
    paid_count = len(paid_calls(item))
    row["substitution_obligation_satisfied"] = bool(
        scenario != "runtime_substitution_within_set"
        or (paid_count > 0 and row["runtime_substitution_events"] == paid_count)
    )
    row["complete_paid_trace_authorized"] = bool(complete and row["paid_calls_authorized"] == paid_count)
    return _finalize(row)


def _mm_formation(item: Any, draft: dict[str, Any], scenario: str) -> tuple[Any, Any, list[dict[str, Any]], str]:
    replay_id = "merchant-v3-96-" + _sha256([item.episode["episode_id"], scenario])[:32]
    plan = build_spend_capacity_plan(
        suite=str(item.episode["suite"]),
        authorizations=list(draft["slots"]),
        policy_tools={},
        tariff=None,
        profile="same_budget_redenomination",
    )
    slots = [
        {
            "service_class": slot.service_class,
            "merchant_id": slot.merchant_id,
            "capacity": slot.denomination,
            "expiry": int(draft["expiry"]),
        }
        for slot in plan.slots
    ]
    approval = load_or_create_user_approval(
        mode="development",
        workflow_id=replay_id,
        slots=slots,
        base_budget=plan.base_budget,
        reserve_budget=plan.joint_reserve_amount,
        approved_budget=plan.approved_budget,
        allowed_service_classes=sorted({slot.service_class for slot in plan.slots}),
        allowed_merchants=sorted({slot.merchant_id for slot in plan.slots}),
        funding_eligible_slot_indices=[index for index, slot in enumerate(plan.slots) if slot.funding_coverage > 0],
        funding_coverage=plan.funding_coverage,
        amendment_limit=0,
    )
    return plan, approval, slots, replay_id


def replay_minmandate(client: PersistentMinMandateClient, item: Any, scenario: str, catalog: dict[str, list[str]]) -> dict[str, Any]:
    draft = _expanded_draft(item, catalog)
    row = _base_row(item, "minmandate", scenario, draft)
    try:
        plan, approval, slots, replay_id = _mm_formation(item, draft, scenario)
        state = JointSpendCapacityState(plan, approval, max_replans=2)
        begin = client.begin_workflow(
            replay_id,
            "offline merchant uncertainty candidate-set replay",
            slots,
            int(draft["expiry"]),
            approval_artifact=approval,
        )
        if begin.get("accepted") is not True:
            raise RuntimeError(f"begin_workflow rejected: {begin.get('error_code') or begin.get('status')}")
        row["initial_approval_formation_success"] = True
        row["initial_authorization_artifacts"] = 1
        row["initial_authorization_entries"] = len(slots)
        row["initial_authorization_slots"] = len(slots)
        row["initial_approval_artifact_bytes"] = len(
            canonical_json(approval.to_dict()).encode("utf-8")
        )
        row["initial_authorization_artifact_bytes"] = row["initial_approval_artifact_bytes"]
        row["locked_budget_nanos"] = int(plan.approved_budget)
        row["budget_inflation_ratio"] = int(plan.approved_budget) / int(item.draft["budget"])
    except Exception as error:
        row["approval_formation_failure"] = f"{type(error).__name__}: {error}"
        return _finalize(row)

    complete = True
    try:
        for call in paid_calls(item):
            runtime_merchant = _candidate_for(item, call, scenario, catalog)
            source_merchant = str(call["merchant_id"])
            replan = scenario == "runtime_substitution_within_set" and runtime_merchant != source_merchant
            if replan:
                row["availability_rejections"] += 1
                row["offline_policy_replans"] += 1
                row["runtime_substitution_events"] += 1
            reservation, denial = state.check(
                str(call["service_class"]), runtime_merchant,
                int(call["quoted_price_nanos"]), 1 + int(call["call_index"]),
            )
            accepted = denial is None
            response_status = None
            if accepted:
                context = PaymentContext(
                    workflow_id=replay_id,
                    base_task_id=str(item.episode["base_task_id"]),
                    call_id=_sha256([scenario, call["call_id"]]),
                    call_index=int(call["call_index"]),
                    suite=str(item.episode["suite"]),
                    tool_name=str(call["tool_name"]),
                    canonical_arguments=dict(call["canonical_tool_arguments"]),
                    merchant_visible_descriptor=canonical_json({"tool": call["tool_name"], "arguments": call["canonical_tool_arguments"]}),
                    service_class=str(call["service_class"]),
                    merchant_id=runtime_merchant,
                    amount=int(call["quoted_price_nanos"]),
                    trusted_now=1 + int(call["call_index"]),
                    seed=int(item.episode["seed"]),
                )
                response = client.invoke(context, list(reservation.slot_indices))
                accepted = response.get("accepted") is True
                response_status = response.get("status")
                if accepted:
                    state.commit(reservation)
            if not accepted:
                row["merchant_authorization_rejections"] += 1
                complete = False
            else:
                row["paid_calls_authorized"] += 1
            row["call_authorization_trace"].append({
                "call_index": int(call["call_index"]),
                "tool_name": str(call["tool_name"]),
                "source_merchant_id": source_merchant,
                "runtime_merchant_id": runtime_merchant,
                "availability_rejection_before_selection": replan,
                "offline_policy_replan": replan,
                "accepted": accepted,
                "outcome": response_status,
                "reason": denial.reason_code if denial is not None else None,
            })
            if not accepted:
                break
    finally:
        ended = client.end_workflow(replay_id)
        if ended.get("ok") is not True:
            raise RuntimeError(f"end_workflow failed for {replay_id}")
    paid_count = len(paid_calls(item))
    row["substitution_obligation_satisfied"] = bool(
        scenario != "runtime_substitution_within_set"
        or (paid_count > 0 and row["runtime_substitution_events"] == paid_count)
    )
    row["complete_paid_trace_authorized"] = bool(complete and row["paid_calls_authorized"] == paid_count)
    return _finalize(row)


def run_shard(protocol: str, planner: str, shard_index: int, shard_count: int, output: Path, planner_run_prefix: str) -> Path:
    if not 0 <= shard_index < shard_count:
        raise ValueError("shard index must be in [0, shard_count)")
    items = load_planner_rerun(protocol, planner, planner_run_prefix)
    items = [item for index, item in enumerate(items) if index % shard_count == shard_index]
    catalog = _candidate_catalog()
    rows: list[dict[str, Any]] = []
    if protocol == "ap2":
        with _conformant_ap2():
            for item in items:
                for scenario in SCENARIOS:
                    rows.append(replay_ap2(item, scenario, catalog))
    else:
        with PersistentMinMandateClient(RUST_BINARY, POLICY_CONFIG) as client:
            for item in items:
                for scenario in SCENARIOS:
                    rows.append(replay_minmandate(client, item, scenario, catalog))
    shard = output / "shards" / protocol / planner / f"part-{shard_index:02d}-of-{shard_count:02d}"
    result = shard / "episode_results.jsonl"
    _write_jsonl(result, rows)
    _write_json(shard / "manifest.json", {
        "schema_version": "minmandate-offline-merchant-uncertainty-shard-v3-96",
        "experiment_id": "offline-merchant-uncertainty-v3-96",
        "protocol": protocol,
        "planner": planner,
        "shard_index": shard_index,
        "shard_count": shard_count,
        "source_episodes": len(items),
        "planner_run_prefix": planner_run_prefix,
        "result_rows": len(rows),
        "result_sha256": hashlib.sha256(result.read_bytes()).hexdigest(),
        "scenarios": list(SCENARIOS),
        "max_reauthorizations": 0,
        "status": "complete",
    })
    return shard


def merge(output: Path, shard_count: int) -> None:
    rows: list[dict[str, Any]] = []
    manifests: list[dict[str, Any]] = []
    for protocol in PROTOCOLS:
        for planner in ("l8", "q14", "q32", "gpt_oss"):
            for index in range(shard_count):
                shard = output / "shards" / protocol / planner / f"part-{index:02d}-of-{shard_count:02d}"
                manifest = json.loads((shard / "manifest.json").read_text())
                result = shard / "episode_results.jsonl"
                if manifest["result_sha256"] != hashlib.sha256(result.read_bytes()).hexdigest():
                    raise RuntimeError(f"shard hash mismatch: {shard}")
                manifests.append(manifest)
                rows.extend(_read_jsonl(result))
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    source_workflows = (
        int(config["source"]["tasks_per_planner"])
        * len(config["source"]["seeds"])
        * len(config["source"]["planners"])
    )
    expected = source_workflows * len(PROTOCOLS) * len(SCENARIOS)
    identities = {(r["protocol"], r["source_episode_id"], r["scenario"]) for r in rows}
    if len(rows) != expected or len(identities) != expected:
        raise RuntimeError(f"incomplete cohort: rows={len(rows)} identities={len(identities)} expected={expected}")
    summary: dict[str, Any] = {}
    for protocol in PROTOCOLS:
        summary[protocol] = {}
        for planner in ("l8", "q14", "q32", "gpt_oss"):
            summary[protocol][planner] = {}
            for scenario in SCENARIOS:
                values = [r for r in rows if r["protocol"] == protocol and r["planner"] == planner and r["scenario"] == scenario]
                n = len(values)
                summary[protocol][planner][scenario] = {
                    "episodes": n,
                    "approval_formation_failures": sum(not r["initial_approval_formation_success"] for r in values),
                    "complete_paid_traces": sum(r["complete_paid_trace_authorized"] for r in values),
                    "end_to_end_successes": sum(r["end_to_end_success"] for r in values),
                    "end_to_end_success_rate_pct": 100 * sum(r["end_to_end_success"] for r in values) / n,
                    "episodes_with_offline_policy_replan": sum(r["offline_policy_replans"] > 0 for r in values),
                    "runtime_substitution_events": sum(r["runtime_substitution_events"] for r in values),
                    "substitution_obligation_failures": sum(not r["substitution_obligation_satisfied"] for r in values),
                    "merchant_authorization_rejected_episodes": sum(r["merchant_authorization_rejections"] > 0 for r in values),
                    "user_reauthorization_requests": sum(r["user_reauthorization_requests"] for r in values),
                    "unauthorized_user_interactions": sum(r["unauthorized_user_interactions"] for r in values),
                    "median_budget_inflation_ratio": sorted(r["budget_inflation_ratio"] for r in values)[n // 2],
                    "median_initial_authorization_slots": sorted(r["initial_authorization_slots"] for r in values)[n // 2],
                    "median_initial_authorization_entries": sorted(r["initial_authorization_entries"] for r in values)[n // 2],
                    "median_initial_approval_artifact_bytes": sorted(r["initial_approval_artifact_bytes"] for r in values)[n // 2],
                    "median_initial_authorization_artifact_bytes": sorted(r["initial_authorization_artifact_bytes"] for r in values)[n // 2],
                }

    planner_runs = []
    run_planners = {
        str(r["source_run_id"]): str(r["planner"])
        for r in rows
    }
    for run_id in sorted({str(r["source_run_id"]) for r in rows}):
        manifest_path = ROOT / "results" / run_id / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        planner_runs.append({
            "run_id": run_id,
            "planner": run_planners[run_id],
            "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            "status": manifest.get("status"),
            "freeze_verified_at_raw_complete": manifest.get("freeze_verified_at_raw_complete"),
            "active_config_sha256": manifest.get("active_config_sha256"),
            "semantic_config_sha256": manifest.get("semantic_config_sha256"),
            "source_snapshot_sha256": manifest.get("source_snapshot_sha256"),
        })
    paired_cohorts = True
    for planner in ("l8", "q14", "q32", "gpt_oss"):
        cohort_keys = {}
        for protocol in PROTOCOLS:
            cohort_keys[protocol] = {
                (r["base_task_id"], int(r["seed"]))
                for r in rows
                if r["protocol"] == protocol and r["planner"] == planner
            }
        paired_cohorts = paired_cohorts and cohort_keys["ap2"] == cohort_keys["minmandate"]

    single_source_snapshot_per_planner = all(
        len({m["source_snapshot_sha256"] for m in planner_runs if m["planner"] == planner}) == 1
        for planner in ("l8", "q14", "q32", "gpt_oss")
    )

    gates = {
        "complete_row_count": len(rows) == expected,
        "unique_identity_count": len(identities) == expected,
        "all_shards_complete": all(m["status"] == "complete" for m in manifests),
        "all_planner_runs_frozen_complete": all(
            m["status"] == "raw_complete" and bool(m["freeze_verified_at_raw_complete"])
            for m in planner_runs
        ),
        "paired_protocol_cohorts": paired_cohorts,
        "single_source_snapshot_per_planner": single_source_snapshot_per_planner,
        "no_user_reauthorization": all(r["user_reauthorization_requests"] == 0 and r["user_reauthorization_approvals"] == 0 for r in rows),
        "no_unauthorized_user_interaction": all(r["unauthorized_user_interactions"] == 0 for r in rows),
        "out_of_set_fails_closed": all(
            not r["complete_paid_trace_authorized"]
            for r in rows
            if r["scenario"] == "out_of_set_negative_control" and r["paid_calls_in_source_trace"] > 0
        ),
        "formation_outcomes_recorded": all(
            r["initial_approval_formation_success"] != bool(r["approval_formation_failure"])
            for r in rows
        ),
        "success_requires_formation_and_authorization": all(
            not r["end_to_end_success"]
            or (r["initial_approval_formation_success"] and r["complete_paid_trace_authorized"])
            for r in rows
        ),
        "runtime_substitution_cannot_be_bypassed": all(
            (
                r["paid_calls_in_source_trace"] > 0
                and r["runtime_substitution_events"] == r["paid_calls_in_source_trace"]
                and r["substitution_obligation_satisfied"]
            )
            or (
                r["paid_calls_in_source_trace"] == 0
                and not r["substitution_obligation_satisfied"]
                and not r["end_to_end_success"]
            )
            for r in rows
            if r["scenario"] == "runtime_substitution_within_set"
        ),
    }
    if not all(gates.values()):
        raise RuntimeError(f"merge gate failed: {gates}")
    _write_jsonl(output / "episode_results.jsonl", sorted(rows, key=lambda r: (r["protocol"], r["planner"], r["source_episode_id"], r["scenario"])))
    _write_json(output / "summary.json", summary)
    _write_json(output / "gates.json", gates)
    _write_json(output / "provenance.json", {
        "schema_version": "minmandate-offline-merchant-uncertainty-provenance-v3-96",
        "experiment_id": "offline-merchant-uncertainty-v3-96",
        "source_cohort": f"{source_workflows} paired workflows per protocol ({int(config['source']['episodes_per_planner_condition'])} per planner and protocol)",
        "measurement_boundary": "real payment authorization replay; recorded planner/business outcome inherited only after complete authorization",
        "candidate_information": "same frozen three-merchant catalog supplied to both protocols before initial approval",
        "reauthorization_policy": "disabled for both protocols; max_reauthorizations=0",
        "offline_policy_replan": "runtime availability selection within the initially approved candidate set; no approval widening",
        "supersedes": "experiments/paper_official/merchant_uncertainty/formal_v1 (invalid for E2E usability: synthetic reauthorization and hard-coded failures)",
        "scenario_pooling": False,
        "config": str(CONFIG),
        "config_sha256": hashlib.sha256(CONFIG.read_bytes()).hexdigest(),
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "planner_runs": planner_runs,
        "shards": manifests,
        "external_payment_requests": 0,
        "network_transactions": 0,
        "funds_moved": False,
    })


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol", choices=PROTOCOLS)
    parser.add_argument("--planner", choices=("l8", "q14", "q32", "gpt_oss"))
    parser.add_argument("--shard-index", type=int)
    parser.add_argument("--shard-count", type=int, default=4)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--planner-run-prefix", default=PLANNER_RUN_PREFIX)
    parser.add_argument("--merge", action="store_true")
    args = parser.parse_args()
    if args.merge:
        merge(args.output, args.shard_count)
        return
    if args.protocol is None or args.planner is None or args.shard_index is None:
        parser.error("run mode requires --protocol, --planner, and --shard-index")
    print(run_shard(args.protocol, args.planner, args.shard_index, args.shard_count, args.output, args.planner_run_prefix))


if __name__ == "__main__":
    main()
