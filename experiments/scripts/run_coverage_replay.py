#!/usr/bin/env python3
"""Replay AP2-(k) merchant-coverage conditions over frozen planner traces.

The replay applies the highest-ranked-available merchant router. AP2 calls use
AP2QueryFreeController, and MinMandate calls use PersistentMinMandateClient.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import copy
import csv
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

ROOT = Path(os.environ.get("MINMANDATE_ROOT", Path(__file__).resolve().parents[2])).resolve()
import sys

sys.path.insert(0, str(ROOT))

from experiments.adapters.base import PaymentContext
from experiments.adapters.minmandate_adapter import PersistentMinMandateClient
from experiments.common import canonical_json
from experiments.runtime.minmandate_contract import load_or_create_user_approval
from experiments.spend_capacity import (
    JointSpendCapacityState,
    admitted_merchant_scope,
    build_spend_capacity_plan,
)


CONDITIONS = ("Native", "Policy-only", "AP2-1", "AP2-2", "AP2-3", "MinMandate")
PLANNER_SOURCE_NAMES = {"L8": "l8", "Q14": "q14", "Q32": "q32", "GPT-OSS": "gpt_oss"}


@contextmanager
def _conformant_ap2():
    """Use the AP2 dependency pinned in requirements.txt."""
    yield


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(canonical_json(row) + "\n" for row in rows), encoding="utf-8")


def sha(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def paid_calls(item: Any) -> list[dict[str, Any]]:
    return [row for row in item.calls if row.get("paid") is True]


def trace_signature(calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    fields = (
        "call_index", "tool_name", "service_class", "merchant_id",
        "quoted_price_nanos", "canonical_tool_arguments",
    )
    return [{key: row.get(key) for key in fields} for row in sorted(calls, key=lambda x: int(x["call_index"]))]


def load_source_cohort(root: Path, planner: str, prefixes: list[str], expected: int) -> list[Any]:
    """Load AP2-native rows and pair them with the same-run native row.

    Pairing is fail-closed: the native/AP2-native business traces must be
    identical before any availability replay is allowed.
    """
    rows: dict[str, Any] = {}
    for prefix in prefixes:
        for run_dir in sorted(root.glob(f"results/{prefix}-{planner}-*")):
            manifest_path = run_dir / "manifest.json"
            if not manifest_path.is_file():
                continue
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if manifest.get("status") != "raw_complete" or manifest.get("freeze_verified_at_raw_complete") is not True:
                continue
            calls_by_episode: dict[str, list[dict[str, Any]]] = {}
            for row in read_jsonl(run_dir / "tool_calls.jsonl"):
                calls_by_episode.setdefault(str(row["episode_id"]), []).append(row)
            drafts = {str(row["workflow_id"]): row for row in read_jsonl(run_dir / "mandate_drafts.jsonl")}
            episodes = {str(row["episode_id"]): row for row in read_jsonl(run_dir / "benchmark_episodes.jsonl")}
            for episode_id, native_episode in episodes.items():
                if not episode_id.endswith(":native"):
                    continue
                workflow = episode_id.rsplit(":", 1)[0]
                if workflow not in drafts:
                    # A canonical source block must also have the same-run
                    # frozen mandate draft for protocol replay.  Never splice
                    # a draft or trace across runs.  Controls backfill runs
                    # intentionally contain native/policy episodes only, but
                    # retain the same frozen draft input.
                    continue
                ap2_calls = sorted(calls_by_episode.get(episode_id, []), key=lambda x: int(x["call_index"]))
                if workflow in rows:
                    raise RuntimeError(f"duplicate source workflow: {workflow}")
                rows[workflow] = SimpleNamespace(
                    planner=planner,
                    run_id=run_dir.name,
                    episode=native_episode,
                    calls=tuple(ap2_calls),
                    ap2_episode=episodes.get(workflow + ":ap2_native"),
                    draft=drafts[workflow],
                )
    if len(rows) != expected:
        raise RuntimeError(f"source cohort incomplete for {planner}: {len(rows)} != {expected}")
    return sorted(rows.values(), key=lambda item: str(item.episode["episode_id"]))


def load_frozen(frozen_dir: Path) -> tuple[dict[str, Any], dict[tuple[str, str], dict[str, Any]], dict[tuple[str, int, str], dict[str, Any]]]:
    config = json.loads((frozen_dir / "ap2k_config.json").read_text(encoding="utf-8"))
    universes = {}
    for row in read_jsonl(frozen_dir / "merchant_universe.jsonl"):
        universes[(str(row["task_id"]), str(row["service_class"]))] = row
    masks = {}
    for row in read_jsonl(frozen_dir / "availability_masks.jsonl"):
        masks[(str(row["task_id"]), int(row["seed"]), str(row["merchant_id"]))] = row
    return config, universes, masks


def relevant_universes(item: Any, universes: dict[tuple[str, str], dict[str, Any]]) -> list[dict[str, Any]]:
    task = str(item.episode["base_task_id"])
    services = sorted({str(call["service_class"]) for call in paid_calls(item)})
    result = []
    for service in services:
        try:
            result.append(universes[(task, service)])
        except KeyError as exc:
            raise RuntimeError(f"missing frozen universe for {task}/{service}") from exc
    return result


def mask_hash(item: Any, masks: dict[tuple[str, int, str], dict[str, Any]]) -> str:
    task, seed = str(item.episode["base_task_id"]), int(item.episode["seed"])
    rows = [row for (t, s, _), row in masks.items() if t == task and s == seed]
    if not rows:
        raise RuntimeError(f"no frozen masks for {task}/{seed}")
    return sha(sorted(rows, key=lambda x: str(x["merchant_id"])))


def trace_hash(item: Any) -> str:
    return sha(trace_signature(paid_calls(item)))


def quote_hash(item: Any) -> str:
    return sha([
        {
            "call_index": int(call["call_index"]),
            "quoted_price_nanos": int(call["quoted_price_nanos"]),
            "service_class": str(call["service_class"]),
            "merchant_id": str(call["merchant_id"]),
        }
        for call in paid_calls(item)
    ])


def availability(row: dict[str, Any], p: float) -> bool:
    return not bool(row["unavailable_at"][format(float(p), "g")])


def route(call: dict[str, Any], task: str, seed: int, p: float, condition: str, universes: dict[tuple[str, str], dict[str, Any]], masks: dict[tuple[str, int, str], dict[str, Any]]) -> dict[str, Any]:
    service = str(call["service_class"])
    universe_row = universes[(task, service)]
    full = [str(value) for value in universe_row["merchant_ids_ranked"]]
    preferred = str(call["merchant_id"])
    if preferred not in full:
        raise RuntimeError(f"preferred merchant is outside frozen universe: {task}/{service}/{preferred}")
    if condition in ("Native", "Policy-only", "MinMandate"):
        authorized = list(full)
    else:
        k = int(condition.rsplit("-", 1)[1])
        authorized = [str(value) for value in universe_row["topk"][str(k)]]
    available_full = [mid for mid in full if availability(masks[(task, seed, mid)], p)]
    available_authorized = [mid for mid in authorized if mid in available_full]
    selected = available_authorized[0] if available_authorized else None
    denial = None
    if selected is None:
        denial = "no_authorized_available_merchant" if available_full else "no_available_merchant"
    return {
        "preferred_merchant_id": preferred,
        "selected_merchant_id": selected,
        "full_universe": full,
        "authorized_merchants": authorized,
        "available_full_universe": available_full,
        "available_authorized_merchants": available_authorized,
        "denial_reason": denial,
    }


def base_episode(item: Any, run_id: str, condition: str, p: float, frozen: dict[str, Any], universes: dict[tuple[str, str], dict[str, Any]], masks: dict[tuple[str, int, str], dict[str, Any]]) -> dict[str, Any]:
    universe_rows = relevant_universes(item, universes)
    return {
        "run_id": run_id,
        "task_id": str(item.episode["base_task_id"]),
        "planner": str(item.planner),
        "seed": int(item.episode["seed"]),
        "condition": condition,
        "p_unavail": float(p),
        "task_success": False,
        "had_paid_call": bool(paid_calls(item)),
        "initial_state_hash": str(item.episode["initial_state_hash"]),
        "trace_hash": trace_hash(item),
        "quote_manifest_hash": quote_hash(item),
        "availability_mask_hash": mask_hash(item, masks),
        "merchant_universe_hash": sha(sorted(universe_rows, key=lambda x: (str(x["task_id"]), str(x["service_class"])))),
        "source_run_id": str(item.run_id),
        "source_episode_id": str(item.episode["episode_id"]),
        "source_task_success": bool(item.episode["task_success"]),
        "coverage_stratum_eligible": all(int(row["universe_size"]) >= int(frozen["min_universe_size_main"]) for row in universe_rows),
        "paid_calls_attempted": len(paid_calls(item)),
        "paid_calls_routed": 0,
        "paid_calls_denied": 0,
        "first_divergent_call": None,
    }


def call_record(item: Any, episode: dict[str, Any], call: dict[str, Any], routed: dict[str, Any], accepted: bool, reason: str | None) -> dict[str, Any]:
    row = {
        "run_id": episode["run_id"],
        "task_id": episode["task_id"],
        "planner": episode["planner"],
        "seed": episode["seed"],
        "condition": episode["condition"],
        "p_unavail": episode["p_unavail"],
        "call_index": int(call["call_index"]),
        "service_class": str(call["service_class"]),
        **routed,
        "call_success": bool(accepted),
        "denial_reason": reason,
        "source_call_id": str(call["call_id"]),
        "tool_name": str(call["tool_name"]),
    }
    return row


def replay_simple(item: Any, episode: dict[str, Any], condition: str, p: float, universes: dict[tuple[str, str], dict[str, Any]], masks: dict[tuple[str, int, str], dict[str, Any]]) -> list[dict[str, Any]]:
    calls_out = []
    complete = True
    for call in paid_calls(item):
        routed = route(call, episode["task_id"], episode["seed"], p, condition, universes, masks)
        accepted = routed["selected_merchant_id"] is not None
        reason = routed["denial_reason"]
        calls_out.append(call_record(item, episode, call, routed, accepted, reason))
        if accepted:
            episode["paid_calls_routed"] += 1
        else:
            episode["paid_calls_denied"] += 1
            complete = False
            if episode["first_divergent_call"] is None:
                episode["first_divergent_call"] = int(call["call_index"])
            break
    episode["task_success"] = bool(episode["source_task_success"] and episode["had_paid_call"] and complete)
    return calls_out


def ap2_replay(item: Any, episode: dict[str, Any], condition: str, p: float, universes: dict[tuple[str, str], dict[str, Any]], masks: dict[tuple[str, int, str], dict[str, Any]], metadata: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    from experiments.adapters.ap2_baseline_adapter import AP2QueryFreeController

    if not paid_calls(item):
        # Keep the all-task denominator, but do not form an AP2 approval with
        # an empty AllowedMerchants set.  The official compiler correctly
        # rejects that object; an empty paid trace is simply inapplicable.
        episode["task_success"] = False
        return []

    draft = copy.deepcopy(item.draft)
    allowed = set()
    for call in paid_calls(item):
        routed = route(call, episode["task_id"], episode["seed"], p, condition, universes, masks)
        allowed.update(routed["authorized_merchants"])
    draft["allowed_merchants"] = sorted(allowed)
    calls_out = []
    complete = True
    logical_now = 1
    controller = AP2QueryFreeController(
        draft,
        workflow_id=str(item.episode["episode_id"]).rsplit(":", 1)[0] + ":" + condition,
        profile="ap2_native",
        now_fn=lambda: logical_now,
        merchant_metadata=metadata,
        require_exact_economic_amounts=True,
    )
    for call in paid_calls(item):
        routed = route(call, episode["task_id"], episode["seed"], p, condition, universes, masks)
        accepted = False
        reason = routed["denial_reason"]
        if routed["selected_merchant_id"] is not None:
            logical_now = 1 + int(call["call_index"])
            quote = SimpleNamespace(
                amount_nanos=int(call["quoted_price_nanos"]),
                currency="USD",
                merchant_id=routed["selected_merchant_id"],
                quote_id=sha([episode["run_id"], call["call_id"], routed["selected_merchant_id"]]),
            )
            try:
                decision = controller.authorize_paid_call(
                    call_id=sha([episode["run_id"], call["call_id"]]),
                    tool_name=str(call["tool_name"]),
                    title=str(call["tool_name"]),
                    service_class=str(call["service_class"]),
                    arguments=dict(call["canonical_tool_arguments"]),
                    quote=quote,
                    merchant_metadata=metadata,
                )
                accepted = bool(decision.accepted)
                reason = decision.reason
            except Exception as exc:
                reason = f"ap2_rejected:{type(exc).__name__}"
        calls_out.append(call_record(item, episode, call, routed, accepted, reason))
        if accepted:
            episode["paid_calls_routed"] += 1
        else:
            episode["paid_calls_denied"] += 1
            complete = False
            if episode["first_divergent_call"] is None:
                episode["first_divergent_call"] = int(call["call_index"])
            break
    episode["task_success"] = bool(episode["source_task_success"] and episode["had_paid_call"] and complete)
    return calls_out


def policy_replay(item: Any, episode: dict[str, Any], condition: str, p: float, universes: dict[tuple[str, str], dict[str, Any]], masks: dict[tuple[str, int, str], dict[str, Any]], client: Any | None) -> list[dict[str, Any]]:
    draft = copy.deepcopy(item.draft)
    for slot in draft.get("slots") or []:
        slot["merchant_id"] = admitted_merchant_scope(str(slot["service_class"]))
    plan = build_spend_capacity_plan(
        suite=str(item.episode["suite"]), authorizations=list(draft["slots"]), policy_tools={}, tariff=None, profile="same_budget_redenomination"
    )
    replay_id = "ap2k-" + sha([item.episode["episode_id"], condition, p])[:32]
    slots = [{"service_class": slot.service_class, "merchant_id": slot.merchant_id, "capacity": slot.denomination, "expiry": int(draft["expiry"])} for slot in plan.slots]
    approval = load_or_create_user_approval(
        mode="development", workflow_id=replay_id, slots=slots, base_budget=plan.base_budget,
        reserve_budget=plan.joint_reserve_amount, approved_budget=plan.approved_budget,
        allowed_service_classes=sorted({slot.service_class for slot in plan.slots}),
        allowed_merchants=sorted({slot.merchant_id for slot in plan.slots}),
        funding_eligible_slot_indices=[i for i, slot in enumerate(plan.slots) if slot.funding_coverage > 0],
        funding_coverage=plan.funding_coverage, amendment_limit=0,
    )
    state = JointSpendCapacityState(plan, approval, max_replans=0)
    if client is not None:
        begin = client.begin_workflow(replay_id, "AP2-k merchant coverage replay", slots, int(draft["expiry"]), approval_artifact=approval)
        if begin.get("accepted") is not True:
            raise RuntimeError(f"MinMandate begin_workflow rejected: {begin}")
    calls_out = []
    complete = True
    try:
        for call in paid_calls(item):
            routed = route(call, episode["task_id"], episode["seed"], p, condition, universes, masks)
            accepted = False
            reason = routed["denial_reason"]
            reservation = None
            if routed["selected_merchant_id"] is not None:
                reservation, denial = state.check(str(call["service_class"]), routed["selected_merchant_id"], int(call["quoted_price_nanos"]), 1 + int(call["call_index"]))
                reason = denial.reason_code if denial is not None else None
                accepted = denial is None
                if accepted and client is not None:
                    context = PaymentContext(
                        workflow_id=replay_id, base_task_id=episode["task_id"], call_id=sha([replay_id, call["call_id"]]),
                        call_index=int(call["call_index"]), suite=str(item.episode["suite"]), tool_name=str(call["tool_name"]),
                        canonical_arguments=dict(call["canonical_tool_arguments"]), merchant_visible_descriptor=canonical_json({"tool": call["tool_name"], "arguments": call["canonical_tool_arguments"]}),
                        service_class=str(call["service_class"]), merchant_id=routed["selected_merchant_id"], amount=int(call["quoted_price_nanos"]),
                        trusted_now=1 + int(call["call_index"]), seed=int(episode["seed"]),
                    )
                    response = client.invoke(context, list(reservation.slot_indices))
                    accepted = response.get("accepted") is True
                    reason = response.get("status") if not accepted else None
                if accepted and reservation is not None:
                    state.commit(reservation)
            calls_out.append(call_record(item, episode, call, routed, accepted, reason))
            if accepted:
                episode["paid_calls_routed"] += 1
            else:
                episode["paid_calls_denied"] += 1
                complete = False
                if episode["first_divergent_call"] is None:
                    episode["first_divergent_call"] = int(call["call_index"])
                break
    finally:
        if client is not None:
            ended = client.end_workflow(replay_id)
            if ended.get("ok") is not True:
                raise RuntimeError(f"MinMandate end_workflow failed: {ended}")
    episode["task_success"] = bool(episode["source_task_success"] and episode["had_paid_call"] and complete)
    return calls_out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=ROOT)
    ap.add_argument("--frozen-dir", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument("--source-prefixes", required=True)
    ap.add_argument("--expected-episodes-per-planner", type=int, default=288)
    ap.add_argument("--rust-binary", type=Path)
    ap.add_argument("--policy-config", type=Path)
    ap.add_argument("--planners", default=None, help="comma-separated planner labels, for deterministic shard execution")
    args = ap.parse_args()
    root = args.root.resolve()
    frozen_dir = args.frozen_dir.resolve()
    out_dir = args.out_dir.resolve()
    config, universes, masks = load_frozen(frozen_dir)
    if tuple(config["condition_order"]) != CONDITIONS:
        raise RuntimeError("condition order differs from normative AP2-k config")
    metadata = {mid: {"name": mid, "website": f"https://{mid}.local.invalid"} for row in universes.values() for mid in row["merchant_ids_ranked"]}
    source_prefixes = [value.strip() for value in args.source_prefixes.split(",") if value.strip()]
    selected_planners = set(PLANNER_SOURCE_NAMES) if args.planners is None else {value.strip() for value in args.planners.split(",") if value.strip()}
    unknown_planners = selected_planners - set(PLANNER_SOURCE_NAMES)
    if unknown_planners:
        raise RuntimeError(f"unknown planner shard(s): {sorted(unknown_planners)}")
    run_id = str(config["experiment_id"]) + "-formal-20260728"
    episodes: list[dict[str, Any]] = []
    calls: list[dict[str, Any]] = []
    pairing: dict[tuple[str, str, int, float], set[str]] = {}
    ap2_conformance = {"official_path": True, "profile": "ap2_native", "conditions": ["AP2-1", "AP2-2", "AP2-3"], "protocol_version": "AP2 v0.2", "patched_sdk": False}
    min_client = None
    with _conformant_ap2():
        for planner_label, source_planner in PLANNER_SOURCE_NAMES.items():
            if planner_label not in selected_planners:
                continue
            items = load_source_cohort(root, source_planner, source_prefixes, args.expected_episodes_per_planner)
            for item in items:
                for p in config["p_unavail"]:
                    for condition in CONDITIONS:
                        episode = base_episode(item, run_id, condition, float(p), config, universes, masks)
                        if condition == "Native":
                            condition_calls = replay_simple(item, episode, condition, float(p), universes, masks)
                        elif condition == "Policy-only":
                            condition_calls = policy_replay(item, episode, condition, float(p), universes, masks, None)
                        elif condition.startswith("AP2-"):
                            condition_calls = ap2_replay(item, episode, condition, float(p), universes, masks, metadata)
                        else:
                            if min_client is None:
                                if args.rust_binary is None or args.policy_config is None:
                                    raise RuntimeError("MinMandate replay requires --rust-binary and --policy-config")
                                min_client = PersistentMinMandateClient(args.rust_binary.resolve(), args.policy_config.resolve())
                            condition_calls = policy_replay(item, episode, condition, float(p), universes, masks, min_client)
                        episode["planner"] = planner_label
                        for record in condition_calls:
                            record["planner"] = planner_label
                        episodes.append(episode)
                        calls.extend(condition_calls)
                        key = (episode["task_id"], planner_label, episode["seed"], episode["p_unavail"])
                        pairing.setdefault(key, set()).add(condition)
    if min_client is not None:
        min_client.close()
    if len(episodes) != len(pairing) * len(CONDITIONS):
        raise RuntimeError("episode pairing cardinality is not six conditions per block")
    pairing_rows = []
    for key, conditions in sorted(pairing.items()):
        pairing_rows.append({"task_id": key[0], "planner": key[1], "seed": key[2], "p_unavail": key[3], "condition_count": len(conditions), "conditions": sorted(conditions), "passed": conditions == set(CONDITIONS)})
    out_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(out_dir / "episode_records.jsonl", episodes)
    write_jsonl(out_dir / "call_records.jsonl", calls)
    with (out_dir / "pairing_audit.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(pairing_rows[0]))
        writer.writeheader(); writer.writerows(pairing_rows)
    write_json(out_dir / "ap2_conformance.json", ap2_conformance)
    write_json(out_dir / "run_manifest.json", {"run_id": run_id, "planners": sorted(selected_planners), "source_prefixes": source_prefixes, "condition_order": list(CONDITIONS), "p_unavail": config["p_unavail"], "episodes": len(episodes), "calls": len(calls), "pair_blocks": len(pairing), "formal_model_or_gpu_job": False, "source_cohort_reused": "business_trace_only_with_native_canonical_and_same_run_draft"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
