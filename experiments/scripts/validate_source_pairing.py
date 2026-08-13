#!/usr/bin/env python3
"""Pre-formal pairing gate for the frozen native/AP2 source cohort."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from run_coverage_replay import load_source_cohort, PLANNER_SOURCE_NAMES, paid_calls


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--source-prefixes", required=True)
    parser.add_argument("--expected", type=int, default=288)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    prefixes = [value.strip() for value in args.source_prefixes.split(",") if value.strip()]
    planners = {}
    errors = []
    for label, source_name in PLANNER_SOURCE_NAMES.items():
        try:
            items = load_source_cohort(root, source_name, prefixes, args.expected)
            task_ids = {str(item.episode["base_task_id"]) for item in items}
            paid_counts = [len(paid_calls(item)) for item in items]
            planners[label] = {
                "source_planner": source_name,
                "episodes": len(items),
                "unique_workflows": len({str(item.episode["episode_id"]) for item in items}),
                "unique_tasks": len(task_ids),
                "paid_call_denominator": sum(paid_counts),
                "canonical_native_trace_selected": True,
                "same_run_frozen_mandate_draft_available": True,
            }
        except Exception as exc:
            errors.append(f"{label}: {type(exc).__name__}: {exc}")
    result = {
        "schema_version": "ap2k-source-pairing-gate-v1",
        "passed": not errors and len(planners) == len(PLANNER_SOURCE_NAMES),
        "expected_episodes_per_planner": args.expected,
        "source_prefixes": prefixes,
        "planners": planners,
        "errors": errors,
        "model_or_gpu_job": False,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
