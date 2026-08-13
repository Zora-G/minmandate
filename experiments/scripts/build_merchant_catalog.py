#!/usr/bin/env python3
"""Build the pre-execution AP2-(k) merchant catalog input.

This adapter only reads the already-frozen source traces and the registered
public merchant catalog.  It never reads task success, evaluator output, or
formal replay results when assigning ranks.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


CATALOG_GROUPS = {
    "calendar": ("calendar",),
    "communication": ("mail", "slack"),
    "finance": ("banking",),
    "storage": ("drive",),
    "travel": (
        "travel-car",
        "travel-flight",
        "travel-hotel",
        "travel-restaurant",
        "travel-profile",
    ),
    "web": ("web",),
}


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def build_catalog(root: Path, source_prefixes: str, config: Path, base_catalog: Path | None = None) -> list[dict[str, Any]]:
    availability = read_json(config)
    if "merchant_catalog" in availability:
        merchant_catalog = availability["merchant_catalog"]
        merchants_by_class = {
            service_class: [str(value) for group in groups for value in merchant_catalog[group]]
            for service_class, groups in CATALOG_GROUPS.items()
        }
    elif base_catalog is not None:
        # The repository's predeclared catalog is the normative public input;
        # the AP2-k config intentionally contains protocol parameters only.
        # Reuse its fixed merchant lists and only add task/service keys found
        # in the canonical native source trace.
        base_rows = read_jsonl(base_catalog)
        merchants_by_class = {}
        for row in sorted(base_rows, key=lambda x: (str(x["service_class"]), int(x["approval_rank"]), str(x["merchant_id"]))):
            merchants_by_class.setdefault(str(row["service_class"]), []).append(str(row["merchant_id"]))
        for service_class in merchants_by_class:
            merchants_by_class[service_class] = list(dict.fromkeys(merchants_by_class[service_class]))
    else:
        raise RuntimeError("config has no merchant_catalog; --base-catalog is required")
    tasks_and_classes: set[tuple[str, str]] = set()
    for planner in ("l8", "q14", "q32", "gpt_oss"):
        for prefix in (value.strip() for value in source_prefixes.split(",") if value.strip()):
            for run_dir in sorted(root.glob(f"results/{prefix}-{planner}-*")):
                manifest = run_dir / "manifest.json"
                episodes_path = run_dir / "benchmark_episodes.jsonl"
                calls_path = run_dir / "tool_calls.jsonl"
                if not manifest.is_file() or not episodes_path.is_file() or not calls_path.is_file():
                    continue
                status = read_json(manifest)
                if status.get("status") != "raw_complete" or status.get("freeze_verified_at_raw_complete") is not True:
                    continue
                paid_by_episode: dict[str, set[str]] = {}
                for call in read_jsonl(calls_path):
                    if call.get("paid") is True:
                        paid_by_episode.setdefault(str(call["episode_id"]), set()).add(str(call["service_class"]))
                for episode in read_jsonl(episodes_path):
                    episode_id = str(episode["episode_id"])
                    # The canonical business trace is the frozen native lane.
                    # Controls-backfill runs intentionally do not contain an
                    # AP2-native episode, and AP2-native lanes can have a
                    # protocol-specific paid-call surface.  Catalog
                    # construction must therefore be driven by the same-run
                    # native trace used by the replay adapter, never by a
                    # formal result or a protocol lane.
                    if episode_id.endswith(":native"):
                        for service_class in paid_by_episode.get(episode_id, set()):
                            tasks_and_classes.add((str(episode["base_task_id"]), service_class))

    rows: list[dict[str, Any]] = []
    for task_id, service_class in sorted(tasks_and_classes):
        merchants = merchants_by_class.get(service_class)
        if not merchants:
            raise RuntimeError(f"no predeclared merchant catalog group for {service_class!r}")
        for rank, merchant_id in enumerate(merchants, start=1):
            rows.append(
                {
                    "task_id": task_id,
                    "service_class": service_class,
                    "merchant_id": merchant_id,
                    "admitted": True,
                    "approval_rank": rank,
                    "rank_source": "approval_time_preference",
                    "catalog_version": "merchant-catalog-v3-predeclared",
                }
            )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--source-prefixes", default=None)
    parser.add_argument("--base-catalog", type=Path, default=None)
    args = parser.parse_args()
    if not args.source_prefixes:
        raise SystemExit("--source-prefixes is required so catalog construction is registry-bound")
    prefixes = args.source_prefixes
    rows = build_catalog(args.root.resolve(), prefixes, args.config.resolve(), args.base_catalog.resolve() if args.base_catalog else None)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    print(json.dumps({"rows": len(rows), "output": str(args.out.resolve())}, indent=2))


if __name__ == "__main__":
    main()
