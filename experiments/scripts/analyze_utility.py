#!/usr/bin/env python3
"""Complete the AP2-k output contract around the supplied metric script."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
from pathlib import Path
from typing import Any


EP_REQUIRED = (
    "run_id", "task_id", "planner", "seed", "condition", "p_unavail",
    "task_success", "had_paid_call", "initial_state_hash", "trace_hash",
    "quote_manifest_hash", "availability_mask_hash", "merchant_universe_hash",
)
CALL_REQUIRED = (
    "run_id", "task_id", "planner", "seed", "condition", "p_unavail",
    "call_index", "service_class", "preferred_merchant_id", "full_universe",
    "authorized_merchants", "available_full_universe", "available_authorized_merchants",
    "call_success", "denial_reason",
)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--raw-dir", type=Path, required=True)
    parser.add_argument("--frozen-dir", type=Path, required=True)
    parser.add_argument("--analysis-dir", type=Path, required=True)
    parser.add_argument("--gates-dir", type=Path, required=True)
    parser.add_argument("--pairing-gate", type=Path, required=True)
    parser.add_argument("--ap2-gate", type=Path, required=True)
    args = parser.parse_args()
    cfg = json.loads(args.config.read_text(encoding="utf-8"))
    episodes = read_jsonl(args.raw_dir / "episode_records.jsonl")
    calls = read_jsonl(args.raw_dir / "call_records.jsonl")
    conditions = list(cfg["condition_order"])
    p_grid = [float(value) for value in cfg["p_unavail"]]
    errors: list[str] = []
    ep_keys: set[tuple[Any, ...]] = set()
    for index, row in enumerate(episodes, 1):
        missing = [key for key in EP_REQUIRED if key not in row]
        if missing:
            errors.append(f"episode {index}: missing {missing}")
        if row.get("condition") not in conditions:
            errors.append(f"episode {index}: invalid condition")
        if float(row.get("p_unavail", -1)) not in p_grid:
            errors.append(f"episode {index}: invalid p_unavail")
        key = tuple(row.get(k) for k in ("task_id", "planner", "seed", "condition", "p_unavail"))
        if key in ep_keys:
            errors.append(f"duplicate episode key {key}")
        ep_keys.add(key)
    for index, row in enumerate(calls, 1):
        missing = [key for key in CALL_REQUIRED if key not in row]
        if missing:
            errors.append(f"call {index}: missing {missing}")
        if row.get("condition") not in conditions:
            errors.append(f"call {index}: invalid condition")
        for key in ("full_universe", "authorized_merchants", "available_full_universe", "available_authorized_merchants"):
            if key in row and len(row[key]) != len(set(row[key])):
                errors.append(f"call {index}: duplicate merchant in {key}")
    by_pair: collections.defaultdict[tuple[Any, ...], set[str]] = collections.defaultdict(set)
    hash_sets: collections.defaultdict[tuple[Any, ...], set[tuple[str, ...]]] = collections.defaultdict(set)
    for row in episodes:
        pair = tuple(row.get(k) for k in ("task_id", "planner", "seed", "p_unavail"))
        by_pair[pair].add(str(row.get("condition")))
        hash_sets[pair].add(tuple(str(row.get(k)) for k in ("initial_state_hash", "trace_hash", "quote_manifest_hash", "availability_mask_hash", "merchant_universe_hash")))
    for pair, observed in by_pair.items():
        if observed != set(conditions):
            errors.append(f"incomplete condition block {pair}: {sorted(observed)}")
        if len(hash_sets[pair]) != 1:
            errors.append(f"paired frozen hashes differ {pair}")
    observed_planners = {str(row.get("planner")) for row in episodes}
    missing_planners = [planner for planner in cfg["planners"] if planner not in observed_planners]
    if missing_planners:
        errors.append(f"missing configured planners: {missing_planners}")
    expected_blocks = {
        planner: len({(row["task_id"], row["seed"], float(row["p_unavail"])) for row in episodes if row.get("planner") == planner and row.get("condition") == conditions[0]})
        for planner in cfg["planners"]
    }
    if any(expected_blocks[planner] == 0 for planner in cfg["planners"]):
        errors.append("one or more configured planners has no paired blocks")

    schema_gate = {"schema_version": "ap2k-schema-validation-gate-v1", "passed": not errors, "episodes": len(episodes), "calls": len(calls), "errors": errors[:100]}
    write_json(args.gates_dir / "schema_validation.json", schema_gate)

    universe_rows = read_jsonl(args.frozen_dir / "merchant_universe.jsonl")
    size_counts = collections.Counter(int(row["universe_size"]) for row in universe_rows)
    eligible = [row for row in universe_rows if int(row["universe_size"]) >= int(cfg["min_universe_size_main"])]
    universe_stats = {
        "experiment_id": cfg["experiment_id"],
        "task_service_groups": len(universe_rows),
        "universe_size_counts": {str(k): v for k, v in sorted(size_counts.items())},
        "eligible_groups_ge_min": len(eligible),
        "deficient_groups_lt_min": len(universe_rows) - len(eligible),
        "min_universe_size_main": cfg["min_universe_size_main"],
        "strict_main_coverage_gate": bool(cfg.get("strict_main_coverage_gate", False)),
        "all_task_reporting_retained": True,
        "coverage_stratum_reporting": "universe_size_ge_min",
    }
    write_json(args.analysis_dir / "merchant_universe_statistics.json", universe_stats)

    strata_rows = []
    for stratum, predicate in (("all_task", lambda row: True), ("universe_size_ge_min", lambda row: bool(row.get("coverage_stratum_eligible")))):
        for planner in cfg["planners"]:
            for condition in conditions:
                for p in p_grid:
                    subset = [row for row in episodes if row.get("planner") == planner and row.get("condition") == condition and float(row.get("p_unavail")) == p and predicate(row)]
                    strata_rows.append({"stratum": stratum, "planner": planner, "condition": condition, "p_unavail": p, "success_numerator": sum(bool(row["task_success"]) for row in subset), "episode_denominator": len(subset), "paid_episode_denominator": sum(bool(row["had_paid_call"]) for row in subset)})
    (args.analysis_dir / "coverage_strata.csv").parent.mkdir(parents=True, exist_ok=True)
    import csv
    with (args.analysis_dir / "coverage_strata.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(strata_rows[0])); writer.writeheader(); writer.writerows(strata_rows)

    denom = collections.defaultdict(lambda: {"episodes": 0, "paid_episodes": 0, "successes": 0})
    for row in episodes:
        key = (row["planner"], row["condition"], float(row["p_unavail"]))
        denom[key]["episodes"] += 1; denom[key]["paid_episodes"] += int(bool(row["had_paid_call"])); denom[key]["successes"] += int(bool(row["task_success"]))
    write_json(args.analysis_dir / "raw_denominators.json", {"|".join(map(str, key)): value for key, value in sorted(denom.items(), key=lambda item: tuple(map(str, item[0])))})

    denial_counts = collections.Counter((row["planner"], row["condition"], float(row["p_unavail"]), row.get("denial_reason") or "accepted") for row in calls)
    denial_rows = [{"planner": key[0], "condition": key[1], "p_unavail": key[2], "denial_reason": key[3], "numerator_calls": value, "denominator_calls": sum(v for k, v in denial_counts.items() if k[:3] == key[:3])} for key, value in sorted(denial_counts.items(), key=lambda item: tuple(map(str, item[0])))]
    with (args.analysis_dir / "denial_attribution.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(denial_rows[0]) if denial_rows else ["planner", "condition", "p_unavail", "denial_reason", "numerator_calls", "denominator_calls"]); writer.writeheader(); writer.writerows(denial_rows)

    # Market-wide failure is deliberately condition-neutral: it is determined
    # from the full-universe Native replay, never from an AP2-k trace that may
    # have terminated earlier after an authorization-coverage denial.
    failure_p = float(cfg["availability_loss_to"])
    market_failed_pairs = {
        (row["task_id"], row["planner"], int(row["seed"]), float(row["p_unavail"]))
        for row in calls
        if row.get("condition") == "Native" and row.get("denial_reason") == "no_available_merchant"
    }
    coverage_failed_episodes = {
        (row["task_id"], row["planner"], int(row["seed"]), row["condition"], float(row["p_unavail"]))
        for row in calls
        if row.get("denial_reason") == "no_authorized_available_merchant"
        and bool(row.get("available_full_universe"))
        and not bool(row.get("available_authorized_merchants"))
    }
    market_rows = []
    decomposition_rows = []
    for planner in cfg["planners"]:
        for condition in conditions:
            paid = [
                row for row in episodes
                if row.get("planner") == planner
                and row.get("condition") == condition
                and float(row.get("p_unavail")) == failure_p
                and bool(row.get("had_paid_call"))
            ]
            market_numerator = sum(
                (row["task_id"], row["planner"], int(row["seed"]), float(row["p_unavail"])) in market_failed_pairs
                for row in paid
            )
            denominator = len(paid)
            coverage_numerator = sum(
                (row["task_id"], row["planner"], int(row["seed"]), row["condition"], float(row["p_unavail"])) in coverage_failed_episodes
                for row in paid
            )
            market_rows.append({
                "planner": planner,
                "condition": condition,
                "p_unavail": failure_p,
                "source_condition": "Native",
                "numerator": market_numerator,
                "denominator": denominator,
                "percent": (100.0 * market_numerator / denominator) if denominator else None,
            })
            decomposition_rows.append({
                "planner": planner,
                "condition": condition,
                "p_unavail": failure_p,
                "coverage_limited_numerator": coverage_numerator,
                "market_wide_numerator": market_numerator,
                "denominator": denominator,
                "coverage_limited_percent": (100.0 * coverage_numerator / denominator) if denominator else None,
                "market_wide_percent": (100.0 * market_numerator / denominator) if denominator else None,
                "market_wide_source_condition": "Native",
            })
    with (args.analysis_dir / "market_wide_failures.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(market_rows[0]) if market_rows else ["planner", "condition", "p_unavail", "source_condition", "numerator", "denominator", "percent"])
        writer.writeheader(); writer.writerows(market_rows)
    with (args.analysis_dir / "availability_failure_decomposition.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(decomposition_rows[0]) if decomposition_rows else ["planner", "condition", "p_unavail", "coverage_limited_numerator", "market_wide_numerator", "denominator", "coverage_limited_percent", "market_wide_percent", "market_wide_source_condition"])
        writer.writeheader(); writer.writerows(decomposition_rows)

    table_values_path = args.analysis_dir / "table1_values.json"
    table_values = json.loads(table_values_path.read_text(encoding="utf-8")) if table_values_path.is_file() else None
    table1_cells = []
    if table_values is not None:
        def display(value: float | None, *, signed: bool = False) -> str:
            if value is None:
                return "n/a"
            return f"{value:+.1f}" if signed else f"{value:.1f}"
        for planner, planner_values in table_values["planners"].items():
            for condition, values in planner_values.items():
                selector = {"planner": planner, "condition": condition}
                for p in p_grid:
                    cell = values["task_success"][format(p, "g")]
                    table1_cells.append({
                        "cell": f"task_success_p{format(p, 'g')}", "source_file": str(args.raw_dir / "episode_records.jsonl"),
                        "selector": {**selector, "p_unavail": p}, "numerator": cell["numerator"],
                        "denominator": cell["denominator"], "unrounded_value": cell["percent"],
                        "display_value": display(cell["percent"]),
                    })
                for label, key, signed in (("delta_vs_native_pp", "delta_vs_native", True), ("availability_loss_pp", "availability_loss", False)):
                    metric = values[key]
                    table1_cells.append({
                        "cell": label, "source_file": str(table_values_path), "selector": selector,
                        "numerator": None, "denominator": None, "unrounded_value": metric["percentage_points"],
                        "display_value": display(metric["percentage_points"], signed=signed),
                    })
                for label, key in (("fallback_success_percent", "fallback_success"), ("coverage_limited_failure_percent", "coverage_limited_failure")):
                    metric = values[key]
                    table1_cells.append({
                        "cell": label, "source_file": str(args.raw_dir / "episode_records.jsonl"), "selector": selector,
                        "numerator": metric["numerator"], "denominator": metric["denominator"],
                        "unrounded_value": metric["percent"], "display_value": display(metric["percent"]),
                    })
    provenance = {
        "experiment_id": cfg["experiment_id"],
        "canonical_trace": "same-run native business trace only; old AP2-native planner result not reused",
        "availability_assignment": "supplied freeze_inputs.py; no execution RNG",
        "ranking": cfg["ranking"],
        "condition_order": conditions,
        "p_unavail": p_grid,
        "formal_result_tuning_used": False,
        "inputs": {str(path): file_sha(path) for path in sorted([args.config, args.frozen_dir / "merchant_universe.jsonl", args.frozen_dir / "availability_masks.jsonl", args.frozen_dir / "SHA256SUMS"])},
        "table1_cells": table1_cells,
        "paper_table_failure_decomposition": {
            "p_unavail": failure_p,
            "coverage_limited_definition": "available_full_universe_nonempty_and_available_authorized_empty",
            "market_wide_definition": "no_available_merchant_on_condition_neutral_native_route",
            "rows": decomposition_rows,
        },
    }
    write_json(args.analysis_dir / "value_provenance.json", provenance)

    pairing = json.loads(args.pairing_gate.read_text(encoding="utf-8"))
    ap2 = json.loads(args.ap2_gate.read_text(encoding="utf-8"))
    package_root = args.gates_dir.parent
    required_paths = [
        *[args.frozen_dir / name for name in ("ap2k_config.json", "merchant_catalog_input.jsonl", "merchant_universe.jsonl", "availability_masks.jsonl", "merchant_universe_coverage.csv", "freeze_gate.json", "SHA256SUMS")],
        *[args.raw_dir / name for name in ("episode_records.jsonl", "call_records.jsonl", "pairing_audit.csv", "ap2_conformance.json", "run_manifest.json")],
        *[args.analysis_dir / name for name in ("table1_values.json", "table1_values.csv", "task_success_by_p.csv", "paired_transitions.csv", "fallback_denominators.csv", "coverage_limited_failures.csv", "market_wide_failures.csv", "availability_failure_decomposition.csv", "denial_attribution.csv", "merchant_universe_statistics.json", "coverage_strata.csv", "value_provenance.json")],
        *[package_root / "paper" / name for name in ("table1_ap2k.tex", "section_4_2_ap2k.tex")],
        *[args.gates_dir / name for name in ("schema_validation.json", "pairing_gate.json", "availability_gate.json", "ap2_gate.json")],
    ]
    missing_outputs = [str(path) for path in required_paths if not path.is_file()]
    expected_analysis = not missing_outputs
    package_gate = {
        "schema_version": "ap2k-package-gate-v1",
        "passed": bool(schema_gate["passed"] and pairing.get("passed") is True and ap2.get("cost_comparison_authorized") is True and expected_analysis),
        "schema_validation": schema_gate["passed"],
        "pairing_gate": pairing.get("passed") is True,
        "ap2_gate": ap2.get("cost_comparison_authorized") is True,
        "analysis_outputs_present": expected_analysis,
        "missing_required_outputs": missing_outputs,
        "configured_planners": cfg["planners"],
        "observed_planners": sorted(observed_planners),
        "paired_blocks_by_planner": expected_blocks,
        "model_or_gpu_job": False,
    }
    write_json(args.gates_dir / "package_gate.json", package_gate)
    return 0 if package_gate["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
