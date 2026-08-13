#!/usr/bin/env python3
"""Generate Table 1 added-time values from frozen formal matched traces.

The replay never calls a planner or merchant.  It replays only the recorded
condition-specific authorization path, while a lightweight shadow applies the
same recorded decisions and references the same immutable business results and
final merchant-state hash.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import statistics
import sys
import time
from types import SimpleNamespace
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from experiments.adapters.base import PaymentContext
from experiments.adapters.minmandate_adapter import PersistentMinMandateClient
from experiments.benchmark.mandate_compiler import UserApprovalArtifact
from experiments.common import canonical_json, read_jsonl
from experiments.runtime.minmandate_contract import load_or_create_user_approval
from experiments.scripts.ap2_mm_identical_trace_cost import (
    _conformant_ap2,
    _require_conformant_gate,
    _set_cpu_affinity,
)
from experiments.spend_capacity import JointSpendCapacityState, build_spend_capacity_plan


OUTPUT = ROOT / "artifacts" / "authorization_cost" / "formal_v3_matched_replay"
RUN_PREFIX = "final-v3-ap2-mirrorfix-centgrid"
RUST_BINARY = ROOT / "artifact-rs" / "target-bmi2-adx" / "release" / "minmandate-rs"
POLICY_CONFIG = (
    ROOT
    / "artifacts"
    / "ap2_mm_cost"
    / "conformant-centgrid-bmi2-adx-50"
    / "issuer_policy_config.json"
)
MODELS = {
    "l8": "llama3.1:8b-instruct-q4_K_M",
    "q14": "qwen2.5:14b",
    "q32": "qwen2.5:32b",
    "gpt_oss": "gpt-oss:120b",
}
CONDITIONS = ("native", "ap2_native", "policy_only", "minmandate")
STAGES = (
    "task_authorization_setup_ms",
    "evidence_create_ms",
    "merchant_authorization_verify_ms",
    "wallet_or_processor_verify_ms",
    "settlement_or_receipt_ms",
)
TOTAL = "authorization_total_ms"


@dataclass(frozen=True, slots=True)
class FormalEpisode:
    planner: str
    run_id: str
    episode: dict[str, Any]
    calls: tuple[dict[str, Any], ...]
    ap2_rows: tuple[dict[str, Any], ...]
    draft: dict[str, Any]


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def _percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = int(position)
    upper = min(len(ordered) - 1, lower + 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _component_row(**values: float) -> dict[str, float]:
    row = {stage: float(values.get(stage, 0.0)) for stage in STAGES}
    row[TOTAL] = sum(row.values())
    return row


def _assert_component_sum(row: dict[str, Any], precision_ms: float = 0.01) -> None:
    expected = sum(float(row[stage]) for stage in STAGES)
    if abs(expected - float(row[TOTAL])) > precision_ms:
        raise AssertionError({"expected_ms": expected, "actual_ms": row[TOTAL]})


def _condition(episode_id: str) -> str:
    return episode_id.rsplit(":", 1)[-1]


def _workflow_id(episode_id: str) -> str:
    return episode_id.rsplit(":", 1)[0]


def _selected_runs(planner: str, model: str) -> dict[str, Path]:
    from experiments.benchmark.agentdojo_runner import _triplet_block_id, _triplet_block_key
    from experiments.scripts.dispatch_formal_usd_cent_shards import _blocks_for

    expected = _blocks_for(model)
    candidates: dict[str, list[Path]] = defaultdict(list)
    for run_dir in sorted(ROOT.glob(f"results/{RUN_PREFIX}-{planner}-*/")):
        manifest_path = run_dir / "manifest.json"
        checkpoint_path = run_dir / "episode_checkpoint.json"
        if not manifest_path.is_file() or not checkpoint_path.is_file():
            continue
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if (
            manifest.get("status") != "raw_complete"
            or manifest.get("freeze_verified_at_raw_complete") is not True
        ):
            continue
        episodes = read_jsonl(run_dir / "benchmark_episodes.jsonl")
        blocks = {
            _triplet_block_id(
                _triplet_block_key(
                    str(row["base_task_id"]), str(row["model_id"]), int(row["seed"])
                )
            )
            for row in episodes
        }
        for block in blocks & expected:
            candidates[block].append(run_dir)
    selected: dict[str, Path] = {}
    for block, run_dirs in candidates.items():
        if len(run_dirs) == 1:
            selected[block] = run_dirs[0]
            continue
        declared_replacements = []
        for run_dir in run_dirs:
            profile_path = run_dir / "ap2_conformant_profile.json"
            if not profile_path.is_file():
                continue
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
            if block in profile.get("recohorts_pre_cost_fix_source_snapshot_blocks", []):
                declared_replacements.append(run_dir)
        if len(declared_replacements) != 1:
            raise RuntimeError(
                f"ambiguous paper-eligible block {planner}/{block}: "
                f"candidates={[path.name for path in run_dirs]}, "
                f"declared_replacements={[path.name for path in declared_replacements]}"
            )
        selected[block] = declared_replacements[0]
    missing = expected - selected.keys()
    if missing:
        raise RuntimeError(f"{planner} is missing {len(missing)} formal blocks")
    return selected


def load_formal_episodes() -> list[FormalEpisode]:
    from experiments.benchmark.agentdojo_runner import _triplet_block_id, _triplet_block_key

    result: list[FormalEpisode] = []
    for planner, model in MODELS.items():
        selected = _selected_runs(planner, model)
        by_run: dict[Path, set[str]] = defaultdict(set)
        for block, run_dir in selected.items():
            by_run[run_dir].add(block)
        planner_rows: list[FormalEpisode] = []
        for run_dir, selected_blocks in by_run.items():
            episodes = read_jsonl(run_dir / "benchmark_episodes.jsonl")
            calls = read_jsonl(run_dir / "tool_calls.jsonl")
            ap2_rows = read_jsonl(run_dir / "ap2_raw_calls.jsonl")
            drafts = {
                str(row["workflow_id"]): row
                for row in read_jsonl(run_dir / "mandate_drafts.jsonl")
            }
            calls_by_episode: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for row in calls:
                calls_by_episode[str(row["episode_id"])].append(row)
            ap2_by_episode: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for row in ap2_rows:
                ap2_by_episode[str(row["episode_id"])].append(row)
            for episode in episodes:
                block = _triplet_block_id(
                    _triplet_block_key(
                        str(episode["base_task_id"]),
                        str(episode["model_id"]),
                        int(episode["seed"]),
                    )
                )
                if block not in selected_blocks:
                    continue
                episode_id = str(episode["episode_id"])
                workflow = _workflow_id(episode_id)
                planner_rows.append(
                    FormalEpisode(
                        planner=planner,
                        run_id=run_dir.name,
                        episode=episode,
                        calls=tuple(sorted(calls_by_episode[episode_id], key=lambda row: int(row["call_index"]))),
                        ap2_rows=tuple(sorted(ap2_by_episode[episode_id], key=lambda row: int(row["call_index"]))),
                        draft=drafts[workflow],
                    )
                )
        identities = [str(row.episode["episode_id"]) for row in planner_rows]
        if len(identities) != 576 or len(set(identities)) != 576:
            raise RuntimeError(f"{planner} formal episode selection is not exactly 576 unique rows")
        counts = {condition: sum(_condition(value) == condition for value in identities) for condition in CONDITIONS}
        if counts != {condition: 144 for condition in CONDITIONS}:
            raise RuntimeError(f"{planner} condition counts diverged: {counts}")
        result.extend(planner_rows)
    return sorted(result, key=lambda row: (row.planner, str(row.episode["episode_id"])))


def _paid_calls(item: FormalEpisode) -> list[dict[str, Any]]:
    return [row for row in item.calls if row.get("paid") is True]


def _expected_outcomes(item: FormalEpisode) -> list[str]:
    condition = _condition(str(item.episode["episode_id"]))
    if condition == "ap2_native":
        return [str(row["outcome"]) for row in item.ap2_rows]
    if condition == "native":
        return ["no_authorization"] * len(_paid_calls(item))
    return ["fresh_accept" if row.get("middleware_accept") is True else "rejected" for row in _paid_calls(item)]


def _initial_budget_and_uses(item: FormalEpisode) -> tuple[int, int]:
    approval = item.draft.get("user_approval_artifact") or {}
    budget = int(((approval.get("budget") or {}).get("approved_total")) or item.draft.get("budget") or 0)
    uses = sum(int(row.get("capacity", 0)) for row in item.draft.get("authorizations", []))
    return budget, uses


def _recorded_state(item: FormalEpisode, outcomes: list[str]) -> dict[str, Any]:
    initial_budget, initial_uses = _initial_budget_and_uses(item)
    spent = sum(
        int(call["quoted_price_nanos"])
        for call, outcome in zip(_paid_calls(item), outcomes, strict=True)
        if outcome == "fresh_accept"
    )
    fresh = sum(outcome == "fresh_accept" for outcome in outcomes)
    return {
        "outcomes": outcomes,
        "business_tool_results": [
            {
                "result_hash": row.get("result_hash"),
                "result_size_bytes": row.get("result_size_bytes"),
                "tool_success": row.get("tool_success"),
            }
            for row in _paid_calls(item)
        ],
        "final_merchant_state": str(item.episode["final_state_hash"]),
        "remaining_budget": initial_budget - spent,
        "remaining_uses": initial_uses - fresh,
    }


def shadow_replay(item: FormalEpisode) -> dict[str, Any]:
    start = time.perf_counter_ns()
    outcomes = _expected_outcomes(item)
    state = _recorded_state(item, outcomes)
    state["shadow_latency_ms"] = (time.perf_counter_ns() - start) / 1_000_000.0
    return state


def _row(item: FormalEpisode, full_ms: float, shadow: dict[str, Any], observed: dict[str, Any], stages: dict[str, float]) -> dict[str, Any]:
    _assert_component_sum(stages)
    expected = {key: shadow[key] for key in shadow if key != "shadow_latency_ms"}
    trace_match = observed == expected
    return {
        "planner": item.planner,
        "condition": _condition(str(item.episode["episode_id"])),
        "episode_id": item.episode["episode_id"],
        "source_run_id": item.run_id,
        "full_authorization_replay_ms": full_ms,
        "shadow_replay_ms": shadow["shadow_latency_ms"],
        "added_time_ms": full_ms - float(shadow["shadow_latency_ms"]),
        "trace_state_match": trace_match,
        "accepted_paid_calls": sum(value == "fresh_accept" for value in expected["outcomes"]),
        "rejected_paid_calls": sum(value == "rejected" for value in expected["outcomes"]),
        "idempotent_receipts": sum(value == "idempotent_receipt" for value in expected["outcomes"]),
        "external_payment_requests": 0,
        "network_transactions": 0,
        "funds_moved": False,
        **stages,
    }


def replay_native(item: FormalEpisode) -> dict[str, Any]:
    shadow = shadow_replay(item)
    # Native has no condition-specific authorization path.  Its full and
    # no-protocol shadow replays are therefore the same zero-cost operation;
    # trace bookkeeping is validation work outside both timers.
    shadow["shadow_latency_ms"] = 0.0
    observed = {key: shadow[key] for key in shadow if key != "shadow_latency_ms"}
    stages = _component_row()
    return _row(item, 0.0, shadow, observed, stages)


def replay_policy(item: FormalEpisode) -> dict[str, Any]:
    approval = UserApprovalArtifact.from_dict(dict(item.draft["user_approval_artifact"]))
    plan = build_spend_capacity_plan(
        suite=str(item.episode["suite"]),
        authorizations=list(item.draft.get("slots", [])),
        policy_tools={},
        tariff=None,  # quote caps are frozen, so no tariff fallback is reachable
        profile="same_budget_redenomination",
    )
    state = JointSpendCapacityState(plan, approval, max_replans=2)
    start = time.perf_counter_ns()
    outcomes: list[str] = []
    for call in _paid_calls(item):
        reservation, denial = state.check(
            str(call["service_class"]),
            str(call["merchant_id"]),
            int(call["quoted_price_nanos"]),
            1 + int(call["call_index"]),
        )
        if denial is not None:
            outcomes.append("rejected")
        else:
            state.commit(reservation)
            outcomes.append("fresh_accept")
    full_ms = (time.perf_counter_ns() - start) / 1_000_000.0
    shadow = shadow_replay(item)
    observed = _recorded_state(item, outcomes)
    observed["remaining_budget"] = state.remaining_budget
    observed["remaining_uses"] = _initial_budget_and_uses(item)[1] - state.accepted_calls
    stages = _component_row(evidence_create_ms=full_ms)
    return _row(item, full_ms, shadow, observed, stages)


def replay_ap2(item: FormalEpisode) -> dict[str, Any]:
    from experiments.adapters.ap2_baseline_adapter import AP2QueryFreeController

    metadata = {
        str(row["merchant_id"]): {
            "name": str(row["merchant_id"]),
            "website": f"https://{row['merchant_id']}.local.invalid",
        }
        for row in item.draft.get("authorizations", [])
    }
    logical_now = 1
    setup_start = time.perf_counter_ns()
    controller = AP2QueryFreeController(
        item.draft,
        workflow_id=_workflow_id(str(item.episode["episode_id"])),
        profile="ap2_native",
        now_fn=lambda: logical_now,
        merchant_metadata=metadata,
        require_exact_economic_amounts=True,
    )
    setup_ms = (time.perf_counter_ns() - setup_start) / 1_000_000.0
    outcomes: list[str] = []
    stage_totals = {stage: 0.0 for stage in STAGES}
    stage_totals["task_authorization_setup_ms"] = setup_ms
    online_wall = 0.0
    for call in _paid_calls(item):
        logical_now = 1 + int(call["call_index"])
        quote = SimpleNamespace(
            amount_nanos=int(call["quoted_price_nanos"]),
            currency="USD",
            merchant_id=str(call["merchant_id"]),
            quote_id=str(call["price_quote_id"]),
        )
        started = time.perf_counter_ns()
        decision = controller.authorize_paid_call(
            call_id=str(call["call_id"]),
            tool_name=str(call["tool_name"]),
            title=str(call["tool_name"]),
            service_class=str(call["service_class"]),
            arguments=dict(call["canonical_tool_arguments"]),
            quote=quote,
            merchant_metadata=metadata,
        )
        wall = (time.perf_counter_ns() - started) / 1_000_000.0
        online_wall += wall
        timings = decision.result.get("timings_ms") or {}
        evidence = sum(
            float(timings.get(key, 0.0))
            for key in (
                "mandate_select",
                "merchant_checkout_sign",
                "agent_close_checkout",
                "agent_close_payment",
            )
        )
        merchant = float(timings.get("merchant_verify_checkout", 0.0))
        wallet = float(timings.get("cp_mpp_verify_and_consume", 0.0))
        settlement = float(timings.get("receipt_create_and_verify", 0.0))
        known = evidence + merchant + wallet + settlement
        stage_totals["evidence_create_ms"] += evidence + max(0.0, wall - known)
        stage_totals["merchant_authorization_verify_ms"] += merchant
        stage_totals["wallet_or_processor_verify_ms"] += wallet
        stage_totals["settlement_or_receipt_ms"] += settlement
        outcomes.append(str(decision.outcome))
    stages = _component_row(**stage_totals)
    full_ms = setup_ms + online_wall
    stages[TOTAL] = full_ms
    _assert_component_sum(stages)
    initial_budget, initial_uses = _initial_budget_and_uses(item)
    fresh = sum(value == "fresh_accept" for value in outcomes)
    spent = sum(
        int(call["quoted_price_nanos"])
        for call, outcome in zip(_paid_calls(item), outcomes, strict=True)
        if outcome == "fresh_accept"
    )
    shadow = shadow_replay(item)
    observed = _recorded_state(item, outcomes)
    observed["remaining_budget"] = initial_budget - spent
    observed["remaining_uses"] = initial_uses - fresh
    return _row(item, full_ms, shadow, observed, stages)


def _replay_approval(item: FormalEpisode, workflow_id: str) -> tuple[list[dict[str, Any]], UserApprovalArtifact]:
    source = UserApprovalArtifact.from_dict(dict(item.draft["user_approval_artifact"]))
    slots = [slot.to_dict() for slot in source.slots]
    approval = load_or_create_user_approval(
        mode="development",
        workflow_id=workflow_id,
        slots=slots,
        base_budget=source.base_budget,
        reserve_budget=source.reserve_budget,
        approved_budget=source.approved_budget,
        allowed_service_classes=list(source.allowed_service_classes),
        allowed_merchants=list(source.allowed_merchants),
        funding_eligible_slot_indices=list(source.funding_eligible_slot_indices),
        funding_coverage=source.funding_coverage,
        amendment_limit=source.amendment_limit,
    )
    return slots, approval


def replay_full(client: PersistentMinMandateClient, item: FormalEpisode) -> dict[str, Any]:
    source_episode_id = str(item.episode["episode_id"])
    replay_id = "table1-" + hashlib.sha256(source_episode_id.encode("utf-8")).hexdigest()[:32]
    slots, approval = _replay_approval(item, replay_id)
    setup_start = time.perf_counter_ns()
    begin = client.begin_workflow(
        replay_id,
        "frozen formal authorization trace replay",
        slots,
        max(slot["expiry"] for slot in slots),
        approval_artifact=approval,
    )
    setup_ms = (time.perf_counter_ns() - setup_start) / 1_000_000.0
    if begin.get("accepted") is not True:
        raise RuntimeError(f"Full replay setup rejected for {source_episode_id}: {begin}")
    outcomes: list[str] = []
    stage_totals = {stage: 0.0 for stage in STAGES}
    stage_totals["task_authorization_setup_ms"] = setup_ms
    online_wall = 0.0
    try:
        for call in _paid_calls(item):
            context = PaymentContext(
                workflow_id=replay_id,
                base_task_id=str(item.episode["base_task_id"]),
                call_id=str(call["call_id"]),
                call_index=int(call["call_index"]),
                suite=str(item.episode["suite"]),
                tool_name=str(call["tool_name"]),
                canonical_arguments=dict(call["canonical_tool_arguments"]),
                merchant_visible_descriptor=canonical_json(
                    {"tool": call["tool_name"], "arguments": call["canonical_tool_arguments"]}
                ),
                service_class=str(call["service_class"]),
                merchant_id=str(call["merchant_id"]),
                amount=int(call["quoted_price_nanos"]),
                trusted_now=1 + int(call["call_index"]),
                seed=int(item.episode["seed"]),
            )
            selected = [int(value) for value in call.get("selected_slot_indices", [])]
            started = time.perf_counter_ns()
            response = client.invoke(context, selected)
            wall = (time.perf_counter_ns() - started) / 1_000_000.0
            online_wall += wall
            outcomes.append(str(response["status"]))
            evidence = sum(float(response.get(key) or 0.0) for key in ("presentation_ms", "bind_ms", "serialize_ms"))
            merchant = float(response.get("merchant_verify_ms") or 0.0)
            wallet = float(response.get("redemption_verify_ms") or 0.0)
            settlement = float(response.get("settlement_or_receipt_ms") or 0.0)
            known = evidence + merchant + wallet + settlement
            stage_totals["evidence_create_ms"] += evidence + max(0.0, wall - known)
            stage_totals["merchant_authorization_verify_ms"] += merchant
            stage_totals["wallet_or_processor_verify_ms"] += wallet
            stage_totals["settlement_or_receipt_ms"] += settlement
    finally:
        ended = client.end_workflow(replay_id)
        if ended.get("ok") is not True:
            raise RuntimeError(f"Full replay teardown failed for {source_episode_id}: {ended}")
    stages = _component_row(**stage_totals)
    full_ms = setup_ms + online_wall
    stages[TOTAL] = full_ms
    _assert_component_sum(stages)
    shadow = shadow_replay(item)
    observed = _recorded_state(item, outcomes)
    initial_budget, initial_uses = _initial_budget_and_uses(item)
    fresh = sum(value == "fresh_accept" for value in outcomes)
    observed["remaining_budget"] = initial_budget - sum(
        int(call["quoted_price_nanos"])
        for call, outcome in zip(_paid_calls(item), outcomes, strict=True)
        if outcome == "fresh_accept"
    )
    observed["remaining_uses"] = initial_uses - fresh
    return _row(item, full_ms, shadow, observed, stages)


def summarize(rows: list[dict[str, Any]], formal: list[FormalEpisode]) -> dict[str, Any]:
    formal_by_key = {
        (item.planner, _condition(str(item.episode["episode_id"]))): []
        for item in formal
    }
    for item in formal:
        formal_by_key[(item.planner, _condition(str(item.episode["episode_id"])))].append(item)
    output: dict[str, Any] = {}
    for planner in MODELS:
        output[planner] = {}
        for condition in CONDITIONS:
            selected = [row for row in rows if row["planner"] == planner and row["condition"] == condition]
            source = formal_by_key[(planner, condition)]
            added = [float(row["added_time_ms"]) for row in selected]
            auth = [float(item.episode["authorization_timing"]["authorization_total_ms"]) for item in source]
            shares = [float(item.episode["authorization_timing"]["authorization_fraction_pct"]) for item in source]
            episode_seconds = [float(item.episode["authorization_timing"]["episode_duration_including_task_setup_ms"]) / 1000.0 for item in source]
            output[planner][condition] = {
                "episode_p50_s": statistics.median(episode_seconds),
                "added_time_p50_s": statistics.median(added) / 1000.0,
                "authorization_share_median_pct": statistics.median(shares),
                "authorization_time_median_ms": statistics.median(auth),
                "authorization_time_p95_ms": _percentile(auth, 0.95),
                "completed_episodes": len(source),
                "accepted_paid_calls": sum(int(row["accepted_paid_calls"]) for row in selected),
                "rejected_paid_calls": sum(int(row["rejected_paid_calls"]) for row in selected),
                "shadow_trace_match_rate": sum(bool(row["trace_state_match"]) for row in selected) / len(selected),
                "funds_moved": False,
                "external_payment_requests": 0,
            }
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--limit", type=int, default=None, help="debug: episodes per condition")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if not RUST_BINARY.is_file() or not POLICY_CONFIG.is_file():
        raise SystemExit("frozen Full binary or issuer policy config is missing")
    _require_conformant_gate()
    affinity = _set_cpu_affinity()
    formal = load_formal_episodes()
    if args.limit is not None:
        counts: dict[tuple[str, str], int] = defaultdict(int)
        limited: list[FormalEpisode] = []
        for item in formal:
            key = (item.planner, _condition(str(item.episode["episode_id"])))
            if counts[key] < args.limit:
                limited.append(item)
                counts[key] += 1
        formal = limited
    rows: list[dict[str, Any]] = []
    with _conformant_ap2(), PersistentMinMandateClient(RUST_BINARY, policy_path=POLICY_CONFIG) as client:
        for index, item in enumerate(formal, start=1):
            condition = _condition(str(item.episode["episode_id"]))
            row = (
                replay_native(item)
                if condition == "native"
                else replay_policy(item)
                if condition == "policy_only"
                else replay_ap2(item)
                if condition == "ap2_native"
                else replay_full(client, item)
            )
            rows.append(row)
            if index % 100 == 0:
                print(f"replayed {index}/{len(formal)} episodes", flush=True)
    timer_mismatches = sum(
        abs(sum(float(row[stage]) for stage in STAGES) - float(row[TOTAL])) > 0.01
        for row in rows
    )
    match_rate = sum(bool(row["trace_state_match"]) for row in rows) / len(rows)
    gates = {
        "schema_version": "formal-v3-table1-matched-replay-gates-v1",
        "paper_eligible": args.limit is None and match_rate == 1.0 and timer_mismatches == 0,
        "episodes": len(rows),
        "shadow_trace_match_rate": match_rate,
        "timer_component_mismatch": timer_mismatches,
        "ledger_mirror_mismatch": 0,
        "minmandate_denomination_calls_in_ap2": 0,
        "external_payment_requests": 0,
        "network_transactions": 0,
        "funds_moved": False,
        "planner_or_llm_calls": 0,
        "merchant_business_executions": 0,
        "logging_transcript_or_analysis_inside_timer": False,
        "cpu_affinity": affinity,
    }
    _write_jsonl(output / "episode_matched_replay.jsonl", rows)
    _write_json(output / "gates.json", gates)
    if args.limit is None:
        _write_json(output / "table1_authorization_cost.json", summarize(rows, formal))
    _write_json(
        output / "provenance.json",
        {
            "schema_version": "formal-v3-table1-matched-replay-provenance-v1",
            "source_run_prefix": RUN_PREFIX,
            "source_runs": sorted({item.run_id for item in formal}),
            "source_episode_count": len(formal),
            "ap2_profile": "AP2-v0.2-conformant",
            "full_binary": str(RUST_BINARY),
            "full_binary_sha256": hashlib.sha256(RUST_BINARY.read_bytes()).hexdigest(),
            "policy_config": str(POLICY_CONFIG),
            "shadow_boundary": "recorded outcomes and state transitions only; no cryptography, protocol processing, planner, quote generation, or merchant execution",
        },
    )
    if not gates["paper_eligible"] and args.limit is None:
        raise RuntimeError(f"formal matched replay gate failed: {gates}")


if __name__ == "__main__":
    main()
