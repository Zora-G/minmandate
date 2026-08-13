#!/usr/bin/env python3
"""Compute task-cluster bootstrap intervals for AP2-k utility contrasts.

The AP2-k replay repeats seeds within a base task.  This analysis therefore
resamples base tasks (while retaining all of their seed-level paired outcomes)
instead of treating replay episodes as independent observations.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
from collections import defaultdict
from pathlib import Path


COMPARATORS = ("AP2-1", "AP2-2", "AP2-3")


def read_jsonl(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * q
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--episodes", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--p-unavail", type=float, default=0.5)
    parser.add_argument("--repetitions", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=20260729)
    args = parser.parse_args()

    rows = [
        row
        for row in read_jsonl(args.episodes)
        if float(row["p_unavail"]) == args.p_unavail
        and str(row["condition"]) in {"MinMandate", *COMPARATORS}
    ]
    paired: dict[tuple[str, str, int], dict[str, int]] = defaultdict(dict)
    for row in rows:
        key = (str(row["planner"]), str(row["task_id"]), int(row["seed"]))
        paired[key][str(row["condition"])] = int(bool(row["task_success"]))

    task_effects: dict[tuple[str, str], dict[str, list[float]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for (planner, task_id, _seed), outcome in paired.items():
        if "MinMandate" not in outcome:
            raise ValueError(f"missing MinMandate counterpart for {planner}/{task_id}")
        for comparator in COMPARATORS:
            if comparator not in outcome:
                raise ValueError(f"missing {comparator} counterpart for {planner}/{task_id}")
            task_effects[(planner, comparator)][task_id].append(
                float(outcome["MinMandate"] - outcome[comparator])
            )

    rng = random.Random(args.seed)
    output: list[dict[str, object]] = []
    for (planner, comparator), per_task in sorted(task_effects.items()):
        effects = [sum(values) / len(values) for _, values in sorted(per_task.items())]
        if not effects:
            raise ValueError(f"no paired effects for {planner}/{comparator}")
        bootstrap = [
            100.0 * sum(rng.choice(effects) for _ in effects) / len(effects)
            for _ in range(args.repetitions)
        ]
        output.append(
            {
                "planner": planner,
                "comparator": comparator,
                "p_unavail": args.p_unavail,
                "task_clusters": len(effects),
                "seed_repetitions_per_task": len(next(iter(per_task.values()))),
                "mean_delta_pp": 100.0 * sum(effects) / len(effects),
                "ci_low_pp": percentile(bootstrap, 0.025),
                "ci_high_pp": percentile(bootstrap, 0.975),
                "bootstrap_repetitions": args.repetitions,
                "bootstrap_seed": args.seed,
                "estimand": "MinMandate minus AP2-k task-success rate, paired by task and seed",
            }
        )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(output[0]))
        writer.writeheader()
        writer.writerows(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
