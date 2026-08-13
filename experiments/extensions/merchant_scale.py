#!/usr/bin/env python3
"""Run and merge normalized merchant-scale stress-test shards.

The design varies the merchant universe, AP2 top-k width, and independent
availability threshold. Shards use the packaged AP2 and MinMandate replay
functions.
"""

from __future__ import annotations

import argparse
import copy
import csv
import gzip
import hashlib
import json
import os
import platform
import random
import socket
import sys
from collections import Counter, defaultdict
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterable, Sequence


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

CONTRACT_PATH = Path(__file__).with_name("merchant_scale_contract.json")
DEFAULT_RESULT_ROOT = (
    ROOT
    / "experiments/extensions/results/MERCHANT_SCALE_STRESS"
)
RAW_EPISODES = ROOT / "inputs/merchant_availability/raw/episode_records.jsonl"
RAW_CALLS = ROOT / "inputs/merchant_availability/raw/call_records.jsonl"
ORIGINAL_CONFIG = (
    ROOT / "inputs/merchant_availability/frozen_inputs/ap2k_config.json"
)
ORIGINAL_UNIVERSES = (
    ROOT
    / "inputs/merchant_availability/frozen_inputs/merchant_universe.jsonl"
)
ORIGINAL_MASKS = (
    ROOT
    / "inputs/merchant_availability/frozen_inputs/availability_masks.jsonl"
)
PLANNER_SOURCE_NAMES = {"L8": "l8", "Q14": "q14", "Q32": "q32", "GPT-OSS": "gpt_oss"}


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def paid_calls(item: Any) -> list[dict[str, Any]]:
    return [row for row in item.calls if row.get("paid") is True]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(canonical_json(row) + "\n" for row in rows),
        encoding="utf-8",
    )


def write_csv(path: Path, rows: Sequence[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = sorted({key for row in rows for key in row}) if rows else ["empty"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_deterministic_gzip_jsonl(
    path: Path, rows: Sequence[dict[str, Any]]
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
            for row in rows:
                zipped.write((canonical_json(row) + "\n").encode("utf-8"))


def load_contract() -> dict[str, Any]:
    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    if contract.get("experiment_id") != "MERCHANT_SCALE_STRESS":
        raise RuntimeError("unexpected E6 contract experiment_id")
    return contract


def verify_required_inputs(root: Path, contract: dict[str, Any]) -> list[str]:
    required = [str(relative) for relative in contract["required_inputs"]]
    errors = []
    for relative in required:
        path = root / relative
        if not path.is_file():
            errors.append(f"missing required external input: {relative}")
    if errors:
        raise RuntimeError("E6 input check failed:\n" + "\n".join(errors))
    return required


def p_label(value: float) -> str:
    return format(float(value), "g")


def atomic_cell_id(cell: dict[str, Any]) -> str:
    fields = [
        str(cell["arm"]),
        f"u{int(cell['universe_size']):02d}",
        f"p{int(round(float(cell['p_unavail']) * 100)):02d}",
        str(cell["planner"]),
        f"s{int(cell['seed'])}",
    ]
    if cell["arm"] == "AP2":
        fields.insert(2, f"k{int(cell['k']):02d}")
    return "-".join(fields)


def atomic_cells(contract: dict[str, Any]) -> list[dict[str, Any]]:
    design = contract["design"]
    result: list[dict[str, Any]] = []
    for universe_size in design["merchant_universe_sizes"]:
        for k in design["ap2_k_by_universe_size"][str(universe_size)]:
            for probability in design["merchant_unavailability_probabilities"]:
                for planner in design["planners"]:
                    for seed in design["source_seeds"]:
                        cell = {
                            "arm": "AP2",
                            "universe_size": int(universe_size),
                            "k": int(k),
                            "p_unavail": float(probability),
                            "planner": str(planner),
                            "seed": int(seed),
                        }
                        cell["cell_id"] = atomic_cell_id(cell)
                        result.append(cell)
        for probability in design["merchant_unavailability_probabilities"]:
            for planner in design["planners"]:
                for seed in design["source_seeds"]:
                    cell = {
                        "arm": "MinMandate",
                        "universe_size": int(universe_size),
                        "k": None,
                        "p_unavail": float(probability),
                        "planner": str(planner),
                        "seed": int(seed),
                    }
                    cell["cell_id"] = atomic_cell_id(cell)
                    result.append(cell)
    result.sort(key=lambda row: str(row["cell_id"]))
    expected = int(contract["expected_cardinality"]["all_atomic_cells"])
    if len(result) != expected or len({row["cell_id"] for row in result}) != expected:
        raise RuntimeError(f"atomic cell cardinality mismatch: {len(result)} != {expected}")
    return result


def physical_shard(cell_id: str, shard_count: int) -> int:
    if shard_count <= 0:
        raise ValueError("shard_count must be positive")
    value = int.from_bytes(hashlib.sha256(cell_id.encode("utf-8")).digest()[:8], "big")
    return value % shard_count


def partition_cells(
    cells: Sequence[dict[str, Any]], shard_count: int
) -> dict[int, list[dict[str, Any]]]:
    result = {index: [] for index in range(shard_count)}
    for cell in cells:
        result[physical_shard(str(cell["cell_id"]), shard_count)].append(dict(cell))
    return result


def uniform_u64(salt: str, task_id: str, seed: int, merchant_id: str) -> float:
    material = "\x1f".join([salt, task_id, str(seed), merchant_id]).encode("utf-8")
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big") / float(1 << 64)


def load_preferred_map(path: Path = RAW_CALLS) -> dict[tuple[str, str], str]:
    preferred: dict[tuple[str, str], set[str]] = defaultdict(set)
    for row in read_jsonl(path):
        if str(row.get("condition")) != "Native" or float(row.get("p_unavail")) != 0.0:
            continue
        key = (str(row["task_id"]), str(row["service_class"]))
        preferred[key].add(str(row["preferred_merchant_id"]))
    ambiguous = {key: values for key, values in preferred.items() if len(values) != 1}
    if ambiguous:
        raise RuntimeError(f"source-preferred merchant is not unique: {ambiguous}")
    return {key: next(iter(values)) for key, values in preferred.items()}


def normalized_universes(
    original_rows: Sequence[dict[str, Any]],
    preferred: dict[tuple[str, str], str],
    universe_size: int,
    allowed_k: Sequence[int],
) -> dict[tuple[str, str], dict[str, Any]]:
    universes: dict[tuple[str, str], dict[str, Any]] = {}
    for original in original_rows:
        task_id = str(original["task_id"])
        service_class = str(original["service_class"])
        key = (task_id, service_class)
        source_preferred = preferred.get(key)
        original_ranked = [str(value) for value in original["merchant_ids_ranked"]]
        if source_preferred is None or source_preferred not in original_ranked:
            raise RuntimeError(f"missing source-preferred merchant for {key}")
        ranked = [source_preferred] + [
            merchant for merchant in original_ranked if merchant != source_preferred
        ]
        rank = len(ranked) + 1
        slug = "".join(ch if ch.isalnum() else "-" for ch in service_class).strip("-")
        while len(ranked) < universe_size:
            candidate = f"e6-{slug}-synthetic-{rank:02d}"
            rank += 1
            if candidate not in ranked:
                ranked.append(candidate)
        ranked = ranked[:universe_size]
        topk = {str(int(k)): ranked[: int(k)] for k in allowed_k if int(k) <= universe_size}
        row = {
            "task_id": task_id,
            "service_class": service_class,
            "merchant_ids_ranked": ranked,
            "universe_size": int(universe_size),
            "topk": topk,
            "source_preferred_merchant_id": source_preferred,
            "catalog_versions": sorted(
                set(str(value) for value in original.get("catalog_versions", []))
                | {"e6-normalized-synthetic-v1"}
            ),
            "rank_sources": ["source_preferred_first"]
            + ["frozen_approval_order"] * (min(len(original_ranked), universe_size) - 1)
            + ["deterministic_synthetic_extension"]
            * max(0, universe_size - len(original_ranked)),
        }
        row["universe_hash"] = sha256_json(row)
        universes[key] = row
    return universes


def original_u_values(path: Path = ORIGINAL_MASKS) -> dict[tuple[str, int, str], float]:
    return {
        (str(row["task_id"]), int(row["seed"]), str(row["merchant_id"])): float(row["u"])
        for row in read_jsonl(path)
    }


def normalized_masks(
    universes: dict[tuple[str, str], dict[str, Any]],
    seeds: Sequence[int],
    probabilities: Sequence[float],
    salt: str,
    original_u: dict[tuple[str, int, str], float],
) -> dict[tuple[str, int, str], dict[str, Any]]:
    merchants_by_task: dict[str, set[str]] = defaultdict(set)
    for (task_id, _), universe in universes.items():
        merchants_by_task[task_id].update(str(value) for value in universe["merchant_ids_ranked"])
    result: dict[tuple[str, int, str], dict[str, Any]] = {}
    for task_id in sorted(merchants_by_task):
        for seed in seeds:
            for merchant_id in sorted(merchants_by_task[task_id]):
                key = (task_id, int(seed), merchant_id)
                value = original_u.get(key)
                source = "frozen_mask_u"
                if value is None:
                    value = uniform_u64(salt, task_id, int(seed), merchant_id)
                    source = "e6_synthetic_hash_u"
                result[key] = {
                    "task_id": task_id,
                    "seed": int(seed),
                    "merchant_id": merchant_id,
                    "u": float(value),
                    "u_source": source,
                    "unavailable_at": {
                        p_label(probability): float(value) < float(probability)
                        for probability in probabilities
                    },
                }
    return result


def validate_normalized_design(
    by_size: dict[int, dict[tuple[str, str], dict[str, Any]]],
    masks_by_size: dict[int, dict[tuple[str, int, str], dict[str, Any]]],
    contract: dict[str, Any],
) -> None:
    sizes = [int(value) for value in contract["design"]["merchant_universe_sizes"]]
    probabilities = [
        float(value)
        for value in contract["design"]["merchant_unavailability_probabilities"]
    ]
    for universe_size in sizes:
        allowed_k = contract["design"]["ap2_k_by_universe_size"][str(universe_size)]
        for key, row in by_size[universe_size].items():
            full = list(row["merchant_ids_ranked"])
            if len(full) != universe_size or len(set(full)) != universe_size:
                raise RuntimeError(f"invalid exact normalized universe for {key}/U={universe_size}")
            if full[0] != row["source_preferred_merchant_id"]:
                raise RuntimeError(f"source-preferred merchant is not rank one for {key}")
            for k in allowed_k:
                if int(k) > universe_size or row["topk"][str(k)] != full[: int(k)]:
                    raise RuntimeError(f"invalid top-k prefix for {key}/U={universe_size}/k={k}")
        for key, row in masks_by_size[universe_size].items():
            flags = [bool(row["unavailable_at"][p_label(p)]) for p in probabilities]
            if any(flags[index] and not flags[index + 1] for index in range(len(flags) - 1)):
                raise RuntimeError(f"non-nested availability mask: {key}/U={universe_size}")
    for key in by_size[sizes[0]]:
        previous: list[str] = []
        for universe_size in sizes:
            current = list(by_size[universe_size][key]["merchant_ids_ranked"])
            if previous and current[: len(previous)] != previous:
                raise RuntimeError(f"merchant universes are not nested for {key}")
            previous = current


def build_normalized_inputs(
    contract: dict[str, Any],
) -> tuple[
    dict[int, dict[tuple[str, str], dict[str, Any]]],
    dict[int, dict[tuple[str, int, str], dict[str, Any]]],
    dict[str, Any],
]:
    original_config = json.loads(ORIGINAL_CONFIG.read_text(encoding="utf-8"))
    original_rows = read_jsonl(ORIGINAL_UNIVERSES)
    preferred = load_preferred_map()
    original_u = original_u_values()
    design = contract["design"]
    by_size = {}
    masks_by_size = {}
    for universe_size in design["merchant_universe_sizes"]:
        universe_size = int(universe_size)
        allowed_k = design["ap2_k_by_universe_size"][str(universe_size)]
        by_size[universe_size] = normalized_universes(
            original_rows, preferred, universe_size, allowed_k
        )
        masks_by_size[universe_size] = normalized_masks(
            by_size[universe_size],
            [int(value) for value in design["source_seeds"]],
            [float(value) for value in design["merchant_unavailability_probabilities"]],
            str(original_config["availability_salt"]),
            original_u,
        )
    validate_normalized_design(by_size, masks_by_size, contract)
    e6_config = {
        "experiment_id": contract["experiment_id"],
        "min_universe_size_main": min(int(value) for value in design["merchant_universe_sizes"]),
        "strict_main_coverage_gate": True,
    }
    return by_size, masks_by_size, e6_config


def modified_item_for_universe(item: Any, universe_size: int) -> Any:
    episode = copy.deepcopy(item.episode)
    original_id = str(episode["episode_id"])
    workflow = original_id.rsplit(":", 1)[0]
    episode["episode_id"] = f"{workflow}:E6-U{universe_size}:native"
    return SimpleNamespace(
        planner=item.planner,
        run_id=item.run_id,
        episode=episode,
        calls=item.calls,
        ap2_episode=item.ap2_episode,
        draft=item.draft,
    )


def authorization_descriptor(
    item: Any,
    arm: str,
    k: int | None,
    universes: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any]:
    services = sorted({str(call["service_class"]) for call in paid_calls(item)})
    if arm == "AP2":
        assert k is not None
        entries = sorted(
            {
                merchant
                for service in services
                for merchant in universes[(str(item.episode["base_task_id"]), service)]["topk"][str(k)]
            }
        )
        encoded = {"allowed_merchants": entries}
        scope_type = "enumerated_merchant_ids"
    else:
        entries = [f"policy:admitted:{service}" for service in services]
        encoded = {"merchant_selection_predicates": entries}
        scope_type = "service_class_admission_predicate"
    nonmerchant_draft = copy.deepcopy(item.draft)
    nonmerchant_draft.pop("allowed_merchants", None)
    return {
        "authorization_scope_type": scope_type,
        "authorization_entry_count": len(entries),
        "authorization_scope_canonical_bytes": len(canonical_json(encoded).encode("utf-8")),
        "nonmerchant_draft_sha256": sha256_json(nonmerchant_draft),
        "budget_scaled_with_k": False,
    }


def run_shard(args: argparse.Namespace) -> int:
    adapter_root = (args.adapter_root or args.root).resolve()
    # Load adapters from the selected source tree.
    sys.path.insert(0, str(adapter_root))
    from experiments.adapters.minmandate_adapter import PersistentMinMandateClient
    from experiments.scripts import run_coverage_replay as reference_replay

    contract = load_contract()
    if args.shard_count != int(contract["design"]["physical_shards"]):
        raise RuntimeError("E6 contract requires exactly 32 physical shards")
    if not 0 <= args.shard_index < args.shard_count:
        raise ValueError("shard_index is outside shard_count")
    root = args.root.resolve()
    source_root = (args.source_root or root).resolve()
    verify_required_inputs(root, contract)
    source_prefixes = str(args.source_prefixes)
    binary = args.rust_binary.resolve()
    policy = args.policy_config.resolve()

    cells = atomic_cells(contract)
    selected = partition_cells(cells, args.shard_count)[args.shard_index]
    part_dir = args.output_root.resolve() / "shards" / f"part-{args.shard_index:03d}-of-{args.shard_count:03d}"
    if part_dir.exists() and any(part_dir.iterdir()):
        raise RuntimeError(f"refusing to overwrite nonempty shard: {part_dir}")
    by_size, masks_by_size, e6_config = build_normalized_inputs(contract)
    source_prefix_list = [value.strip() for value in source_prefixes.split(",") if value.strip()]
    needed_planners = sorted({str(cell["planner"]) for cell in selected})
    items_by_planner: dict[str, list[Any]] = {}
    for planner in needed_planners:
        items_by_planner[planner] = reference_replay.load_source_cohort(
            source_root,
            PLANNER_SOURCE_NAMES[planner],
            source_prefix_list,
            int(args.expected_episodes_per_planner),
        )

    episodes: list[dict[str, Any]] = []
    calls: list[dict[str, Any]] = []
    min_client = None
    run_id = "e6-merchant-scale-stress-v1"
    try:
        if any(cell["arm"] == "MinMandate" for cell in selected):
            min_client = PersistentMinMandateClient(binary, policy)
        with reference_replay._conformant_ap2():
            for cell in selected:
                universe_size = int(cell["universe_size"])
                probability = float(cell["p_unavail"])
                planner = str(cell["planner"])
                seed = int(cell["seed"])
                condition = (
                    f"AP2-{int(cell['k'])}"
                    if cell["arm"] == "AP2"
                    else "MinMandate"
                )
                source_items = [
                    item
                    for item in items_by_planner[planner]
                    if int(item.episode["seed"]) == seed
                ]
                if len(source_items) != int(contract["design"]["base_tasks_per_planner_seed"]):
                    raise RuntimeError(f"incomplete source cell: {cell['cell_id']}")
                universes = by_size[universe_size]
                masks = masks_by_size[universe_size]
                metadata = {
                    merchant_id: {
                        "name": merchant_id,
                        "website": f"https://{merchant_id}.local.invalid",
                    }
                    for row in universes.values()
                    for merchant_id in row["merchant_ids_ranked"]
                }
                for source_item in source_items:
                    item = modified_item_for_universe(source_item, universe_size)
                    episode = reference_replay.base_episode(
                        item,
                        run_id,
                        condition,
                        probability,
                        e6_config,
                        universes,
                        masks,
                    )
                    if cell["arm"] == "AP2":
                        condition_calls = reference_replay.ap2_replay(
                            item,
                            episode,
                            condition,
                            probability,
                            universes,
                            masks,
                            metadata,
                        )
                    else:
                        condition_calls = reference_replay.policy_replay(
                            item,
                            episode,
                            condition,
                            probability,
                            universes,
                            masks,
                            min_client,
                        )
                    episode.update(
                        {
                            "schema_version": "minmandate-e6-episode-v1",
                            "experiment_id": contract["experiment_id"],
                            "cell_id": cell["cell_id"],
                            "arm": cell["arm"],
                            "universe_size": universe_size,
                            "k": cell["k"],
                            "coverage_ratio": (
                                float(cell["k"]) / universe_size
                                if cell["k"] is not None
                                else 1.0
                            ),
                            **authorization_descriptor(
                                item,
                                str(cell["arm"]),
                                int(cell["k"]) if cell["k"] is not None else None,
                                universes,
                            ),
                        }
                    )
                    episode["planner"] = planner
                    for record in condition_calls:
                        record.update(
                            {
                                "schema_version": "minmandate-e6-call-v1",
                                "experiment_id": contract["experiment_id"],
                                "cell_id": cell["cell_id"],
                                "arm": cell["arm"],
                                "universe_size": universe_size,
                                "k": cell["k"],
                                "planner": planner,
                            }
                        )
                    episodes.append(episode)
                    calls.extend(condition_calls)
    finally:
        if min_client is not None:
            min_client.close()

    episodes.sort(key=lambda row: (str(row["cell_id"]), str(row["task_id"])))
    calls.sort(
        key=lambda row: (
            str(row["cell_id"]),
            str(row["task_id"]),
            int(row["call_index"]),
            str(row["source_call_id"]),
        )
    )
    expected_episode_rows = len(selected) * int(contract["design"]["base_tasks_per_planner_seed"])
    if len(episodes) != expected_episode_rows:
        raise RuntimeError(f"shard episode count mismatch: {len(episodes)} != {expected_episode_rows}")
    part_dir.mkdir(parents=True, exist_ok=False)
    episode_path = part_dir / "episode_results.jsonl"
    call_path = part_dir / "call_results.jsonl"
    write_jsonl(episode_path, episodes)
    write_jsonl(call_path, calls)
    script_path = Path(__file__).resolve()
    manifest = {
        "schema_version": "minmandate-e6-shard-manifest-v1",
        "experiment_id": contract["experiment_id"],
        "status": "completed",
        "contract_sha256": sha256_file(CONTRACT_PATH),
        "runner_sha256": sha256_file(script_path),
        "binary_sha256": sha256_file(binary),
        "policy_sha256": sha256_file(policy),
        "source_prefixes": source_prefixes,
        "shard_index": args.shard_index,
        "shard_count": args.shard_count,
        "atomic_cell_ids": [str(cell["cell_id"]) for cell in selected],
        "counts": {
            "atomic_cells": len(selected),
            "episode_rows": len(episodes),
            "call_rows": len(calls),
        },
        "outputs": {
            episode_path.name: {
                "bytes": episode_path.stat().st_size,
                "sha256": sha256_file(episode_path),
            },
            call_path.name: {
                "bytes": call_path.stat().st_size,
                "sha256": sha256_file(call_path),
            },
        },
        "environment": {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "python": sys.version,
            "pid": os.getpid(),
        },
    }
    write_json(part_dir / "manifest.json", manifest)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


def percentile(values: Sequence[float], quantile: float) -> float:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return float("nan")
    position = (len(ordered) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def paired_contrast_rows(
    episodes: Sequence[dict[str, Any]], contract: dict[str, Any]
) -> list[dict[str, Any]]:
    mm = {
        (
            int(row["universe_size"]),
            float(row["p_unavail"]),
            str(row["planner"]),
            int(row["seed"]),
            str(row["task_id"]),
        ): int(bool(row["task_success"]))
        for row in episodes
        if row["arm"] == "MinMandate"
    }
    per_contrast_task: dict[tuple[int, int, float, str], dict[str, list[float]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for row in episodes:
        if row["arm"] != "AP2":
            continue
        counterpart = (
            int(row["universe_size"]),
            float(row["p_unavail"]),
            str(row["planner"]),
            int(row["seed"]),
            str(row["task_id"]),
        )
        if counterpart not in mm:
            raise RuntimeError(f"missing MinMandate counterpart: {counterpart}")
        key = (
            int(row["universe_size"]),
            int(row["k"]),
            float(row["p_unavail"]),
            str(row["planner"]),
        )
        per_contrast_task[key][str(row["task_id"])].append(
            float(mm[counterpart] - int(bool(row["task_success"])))
        )
    effects: list[tuple[tuple[int, int, float, str], list[float]]] = []
    for key, task_values in sorted(per_contrast_task.items()):
        if len(task_values) != int(contract["design"]["base_tasks_per_planner_seed"]):
            raise RuntimeError(f"contrast has incomplete task clusters: {key}")
        values = [sum(v) / len(v) for _, v in sorted(task_values.items())]
        effects.append((key, values))
    pooled: dict[tuple[int, int, float], dict[str, list[float]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for (universe_size, k, probability, _planner), values in effects:
        task_ids = sorted(per_contrast_task[(universe_size, k, probability, _planner)])
        for task_id, value in zip(task_ids, values):
            pooled[(universe_size, k, probability)][task_id].append(value)
    for (universe_size, k, probability), task_values in sorted(pooled.items()):
        values = [sum(v) / len(v) for _, v in sorted(task_values.items())]
        effects.append(((universe_size, k, probability, "ALL-4"), values))

    repetitions = int(contract["design"]["bootstrap_repetitions"])
    seed = int(contract["design"]["bootstrap_seed"])
    rows = []
    try:
        import numpy as np

        task_count = len(effects[0][1])
        rng = np.random.default_rng(seed)
        indices = rng.integers(0, task_count, size=(repetitions, task_count))
        counts = np.zeros((repetitions, task_count), dtype=np.int16)
        np.add.at(
            counts,
            (np.repeat(np.arange(repetitions), task_count), indices.reshape(-1)),
            1,
        )
        matrix = np.asarray([values for _, values in effects], dtype=float)
        bootstrap = (counts @ matrix.T) / float(task_count)
        lows = np.quantile(bootstrap, 0.025, axis=0)
        highs = np.quantile(bootstrap, 0.975, axis=0)
        for index, (key, values) in enumerate(effects):
            rows.append(
                {
                    "universe_size": key[0],
                    "k": key[1],
                    "coverage_ratio": key[1] / key[0],
                    "p_unavail": key[2],
                    "planner": key[3],
                    "task_clusters": len(values),
                    "mean_delta_pp": 100.0 * sum(values) / len(values),
                    "ci_low_pp": 100.0 * float(lows[index]),
                    "ci_high_pp": 100.0 * float(highs[index]),
                    "bootstrap_repetitions": repetitions,
                    "bootstrap_seed": seed,
                }
            )
    except ImportError:
        rng = random.Random(seed)
        for key, values in effects:
            estimates = [
                100.0 * sum(rng.choice(values) for _ in values) / len(values)
                for _ in range(repetitions)
            ]
            rows.append(
                {
                    "universe_size": key[0],
                    "k": key[1],
                    "coverage_ratio": key[1] / key[0],
                    "p_unavail": key[2],
                    "planner": key[3],
                    "task_clusters": len(values),
                    "mean_delta_pp": 100.0 * sum(values) / len(values),
                    "ci_low_pp": percentile(estimates, 0.025),
                    "ci_high_pp": percentile(estimates, 0.975),
                    "bootstrap_repetitions": repetitions,
                    "bootstrap_seed": seed,
                }
            )
    return rows


def summary_rows(
    episodes: Sequence[dict[str, Any]], calls: Sequence[dict[str, Any]]
) -> list[dict[str, Any]]:
    event_by_episode: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {
            "market_wide": False,
            "coverage_limited": False,
            "protocol_denial": False,
            "fallback_eligible": 0,
            "fallback_success": 0,
        }
    )
    for row in calls:
        key = (str(row["cell_id"]), str(row["task_id"]))
        available_full = list(row.get("available_full_universe") or [])
        available_authorized = list(row.get("available_authorized_merchants") or [])
        event_by_episode[key]["market_wide"] |= not bool(available_full)
        event_by_episode[key]["coverage_limited"] |= bool(available_full) and not bool(
            available_authorized
        )
        event_by_episode[key]["protocol_denial"] |= (
            bool(available_authorized) and not bool(row.get("call_success"))
        )
        preferred = str(row.get("preferred_merchant_id"))
        eligible = bool(available_full) and preferred not in available_full
        event_by_episode[key]["fallback_eligible"] += int(eligible)
        event_by_episode[key]["fallback_success"] += int(
            eligible and bool(row.get("call_success"))
        )
    groups: dict[tuple[str, int, Any, float, str], list[dict[str, Any]]] = defaultdict(list)
    for row in episodes:
        key = (
            str(row["arm"]),
            int(row["universe_size"]),
            row["k"],
            float(row["p_unavail"]),
            str(row["planner"]),
        )
        groups[key].append(row)
    output = []
    for key, rows in sorted(groups.items(), key=lambda item: tuple(map(str, item[0]))):
        paid = [row for row in rows if bool(row["had_paid_call"])]
        events = [event_by_episode[(str(row["cell_id"]), str(row["task_id"]))] for row in paid]
        fallback_denominator = sum(int(event["fallback_eligible"]) for event in events)
        output.append(
            {
                "arm": key[0],
                "universe_size": key[1],
                "k": key[2],
                "coverage_ratio": (float(key[2]) / key[1]) if key[2] is not None else 1.0,
                "p_unavail": key[3],
                "planner": key[4],
                "episode_denominator": len(rows),
                "task_success_rate": sum(bool(row["task_success"]) for row in rows) / len(rows),
                "paid_episode_denominator": len(paid),
                "market_wide_failure_rate": (
                    sum(bool(event["market_wide"]) for event in events) / len(events)
                    if events
                    else None
                ),
                "coverage_limited_failure_rate": (
                    sum(bool(event["coverage_limited"]) for event in events) / len(events)
                    if events
                    else None
                ),
                "protocol_denial_rate": (
                    sum(bool(event["protocol_denial"]) for event in events) / len(events)
                    if events
                    else None
                ),
                "fallback_success_rate": (
                    sum(int(event["fallback_success"]) for event in events)
                    / fallback_denominator
                    if fallback_denominator
                    else None
                ),
                "mean_authorization_entry_count": sum(
                    int(row["authorization_entry_count"]) for row in rows
                )
                / len(rows),
                "mean_authorization_scope_canonical_bytes": sum(
                    int(row["authorization_scope_canonical_bytes"]) for row in rows
                )
                / len(rows),
            }
        )
    return output


def validate_and_merge(args: argparse.Namespace) -> int:
    contract = load_contract()
    root = args.root.resolve()
    verify_required_inputs(root, contract)
    build_normalized_inputs(contract)
    cells = atomic_cells(contract)
    expected_by_part = partition_cells(cells, int(contract["design"]["physical_shards"]))
    expected_cell_ids = {str(cell["cell_id"]) for cell in cells}
    shards_root = args.shards_root.resolve()
    manifests = []
    episodes: list[dict[str, Any]] = []
    calls: list[dict[str, Any]] = []
    common_hashes = None
    for part_index in range(int(contract["design"]["physical_shards"])):
        part_dir = shards_root / f"part-{part_index:03d}-of-032"
        manifest_path = part_dir / "manifest.json"
        if not manifest_path.is_file():
            raise RuntimeError(f"missing shard manifest: {manifest_path}")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("status") != "completed" or manifest.get("shard_index") != part_index:
            raise RuntimeError(f"invalid shard manifest: {manifest_path}")
        if int(manifest.get("shard_count", -1)) != 32:
            raise RuntimeError(f"invalid shard_count in {manifest_path}")
        observed_ids = set(str(value) for value in manifest["atomic_cell_ids"])
        planned_ids = {str(cell["cell_id"]) for cell in expected_by_part[part_index]}
        if observed_ids != planned_ids:
            raise RuntimeError(f"atomic-cell mismatch in shard {part_index}")
        hash_tuple = (
            manifest["contract_sha256"],
            manifest["runner_sha256"],
            manifest["binary_sha256"],
            manifest["policy_sha256"],
            manifest["source_prefixes"],
        )
        if common_hashes is None:
            common_hashes = hash_tuple
        elif hash_tuple != common_hashes:
            raise RuntimeError("contract/script/runtime/source hashes differ across shards")
        for name in ("episode_results.jsonl", "call_results.jsonl"):
            path = part_dir / name
            if sha256_file(path) != manifest["outputs"][name]["sha256"]:
                raise RuntimeError(f"shard output hash mismatch: {path}")
        part_episodes = read_jsonl(part_dir / "episode_results.jsonl")
        part_calls = read_jsonl(part_dir / "call_results.jsonl")
        if len(part_episodes) != int(manifest["counts"]["episode_rows"]):
            raise RuntimeError(f"shard episode count mismatch: {part_index}")
        if len(part_calls) != int(manifest["counts"]["call_rows"]):
            raise RuntimeError(f"shard call count mismatch: {part_index}")
        manifests.append(manifest)
        episodes.extend(part_episodes)
        calls.extend(part_calls)
    if common_hashes is None:
        raise RuntimeError("no E6 shards were loaded")
    if common_hashes[0] != sha256_file(CONTRACT_PATH):
        raise RuntimeError("shards are bound to the wrong E6 contract")
    if common_hashes[1] != sha256_file(Path(__file__).resolve()):
        raise RuntimeError("current validator runner differs from the shard runner")
    observed_cell_ids = {str(row["cell_id"]) for row in episodes}
    if observed_cell_ids != expected_cell_ids:
        raise RuntimeError("merged atomic-cell union is incomplete or contains extras")
    episode_counts = Counter(str(row["cell_id"]) for row in episodes)
    expected_tasks = int(contract["design"]["base_tasks_per_planner_seed"])
    if any(episode_counts[cell_id] != expected_tasks for cell_id in expected_cell_ids):
        raise RuntimeError("one or more atomic cells does not contain exactly 96 tasks")
    if len(episodes) != int(contract["expected_cardinality"]["all_episode_rows"]):
        raise RuntimeError("merged episode cardinality differs from the E6 contract")
    episode_keys = [
        (
            str(row["cell_id"]),
            str(row["task_id"]),
        )
        for row in episodes
    ]
    if len(episode_keys) != len(set(episode_keys)):
        raise RuntimeError("duplicate merged episode primary key")
    call_keys = [
        (
            str(row["cell_id"]),
            str(row["task_id"]),
            int(row["call_index"]),
            str(row["source_call_id"]),
        )
        for row in calls
    ]
    if len(call_keys) != len(set(call_keys)):
        raise RuntimeError("duplicate merged call primary key")
    for row in calls:
        full = list(row["full_universe"])
        authorized = list(row["authorized_merchants"])
        if len(full) != int(row["universe_size"]):
            raise RuntimeError("call row has the wrong normalized universe size")
        if row["arm"] == "AP2":
            if authorized != full[: int(row["k"])]:
                raise RuntimeError("AP2 authorized merchants are not the registered top-k prefix")
        elif authorized != full:
            raise RuntimeError("MinMandate call does not use the full registered universe")
    availability_views: dict[
        tuple[int, float, str, int, str], set[tuple[tuple[str, ...], tuple[str, ...]]]
    ] = defaultdict(set)
    for row in calls:
        availability_views[
            (
                int(row["universe_size"]),
                float(row["p_unavail"]),
                str(row["task_id"]),
                int(row["seed"]),
                str(row["service_class"]),
            )
        ].add(
            (
                tuple(str(value) for value in row["full_universe"]),
                tuple(str(value) for value in row["available_full_universe"]),
            )
        )
    if any(len(values) != 1 for values in availability_views.values()):
        raise RuntimeError("availability realization differs across planners or arms")
    source_invariants: dict[tuple[int, float, str, int, str], set[tuple[str, ...]]] = defaultdict(set)
    draft_invariants: dict[tuple[int, float, str, int, str], set[str]] = defaultdict(set)
    for row in episodes:
        key = (
            int(row["universe_size"]),
            float(row["p_unavail"]),
            str(row["planner"]),
            int(row["seed"]),
            str(row["task_id"]),
        )
        source_invariants[key].add(
            (
                str(row["initial_state_hash"]),
                str(row["trace_hash"]),
                str(row["quote_manifest_hash"]),
            )
        )
        draft_invariants[key].add(str(row["nonmerchant_draft_sha256"]))
    if any(len(values) != 1 for values in source_invariants.values()):
        raise RuntimeError("source trace/quote/initial-state hashes differ across paired arms")
    if any(len(values) != 1 for values in draft_invariants.values()):
        raise RuntimeError("non-merchant draft changed with k or protocol arm")
    _ = paired_contrast_rows(episodes, {**contract, "design": {**contract["design"], "bootstrap_repetitions": 1}})

    episodes.sort(key=lambda row: (str(row["cell_id"]), str(row["task_id"])))
    calls.sort(
        key=lambda row: (
            str(row["cell_id"]),
            str(row["task_id"]),
            int(row["call_index"]),
            str(row["source_call_id"]),
        )
    )
    output_dir = args.output_dir.resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        raise RuntimeError(f"refusing to overwrite nonempty merge directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=False)
    episode_output = output_dir / "raw/episode_results.jsonl.gz"
    call_output = output_dir / "raw/call_results.jsonl.gz"
    write_deterministic_gzip_jsonl(episode_output, episodes)
    write_deterministic_gzip_jsonl(call_output, calls)
    summaries = summary_rows(episodes, calls)
    contrasts = paired_contrast_rows(episodes, contract)
    summary_path = output_dir / "analysis/summary.csv"
    contrast_path = output_dir / "analysis/paired_task_bootstrap.csv"
    write_csv(summary_path, summaries)
    write_csv(contrast_path, contrasts)
    manifest = {
        "schema_version": "minmandate-e6-merged-manifest-v1",
        "experiment_id": contract["experiment_id"],
        "status": "completed_and_validated",
        "contract_sha256": sha256_file(CONTRACT_PATH),
        "runner_sha256": sha256_file(Path(__file__).resolve()),
        "shards": len(manifests),
        "counts": {
            "atomic_cells": len(expected_cell_ids),
            "episode_rows": len(episodes),
            "call_rows": len(calls),
            "summary_rows": len(summaries),
            "contrast_rows": len(contrasts),
        },
        "gates": {
            "main_hash_gate": True,
            "all_shards_present": True,
            "atomic_cell_union_exact_and_disjoint": True,
            "task_cardinality_per_cell": True,
            "paired_minmandate_counterparts": True,
            "topk_prefix": True,
            "source_invariants": True,
            "nonmerchant_draft_invariant": True,
            "primary_key_uniqueness": True,
        },
        "outputs": {
            str(path.relative_to(output_dir)): {
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
            for path in (episode_output, call_output, summary_path, contrast_path)
        },
        "interpretation_boundary": contract["relationship_to_main"],
        "supplement_update_allowed": False,
    }
    write_json(output_dir / "manifest.json", manifest)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


def print_plan(args: argparse.Namespace) -> int:
    contract = load_contract()
    cells = atomic_cells(contract)
    partitions = partition_cells(cells, int(contract["design"]["physical_shards"]))
    plan = {
        "experiment_id": contract["experiment_id"],
        "contract_sha256": sha256_file(CONTRACT_PATH),
        "atomic_cells": len(cells),
        "expected_episode_rows": contract["expected_cardinality"]["all_episode_rows"],
        "physical_shards": {
            str(index): {
                "atomic_cells": len(partitions[index]),
                "expected_episode_rows": len(partitions[index])
                * int(contract["design"]["base_tasks_per_planner_seed"]),
                "first_cell_id": partitions[index][0]["cell_id"] if partitions[index] else None,
                "last_cell_id": partitions[index][-1]["cell_id"] if partitions[index] else None,
            }
            for index in partitions
        },
    }
    if args.output:
        write_json(args.output.resolve(), plan)
    print(json.dumps(plan, indent=2, sort_keys=True))
    return 0


def runtime_preflight(args: argparse.Namespace) -> int:
    from experiments.scripts import run_coverage_replay as reference_replay

    contract = load_contract()
    root = args.root.resolve()
    source_root = (args.source_root or root).resolve()
    required_inputs = verify_required_inputs(root, contract)
    source_prefixes = str(args.source_prefixes)
    binary = args.rust_binary.resolve()
    policy = args.policy_config.resolve()
    by_size, masks_by_size, _ = build_normalized_inputs(contract)
    source_prefix_list = [
        value.strip() for value in source_prefixes.split(",") if value.strip()
    ]
    source_counts = {}
    for planner, source_name in PLANNER_SOURCE_NAMES.items():
        items = reference_replay.load_source_cohort(
            source_root,
            source_name,
            source_prefix_list,
            int(args.expected_episodes_per_planner),
        )
        per_seed = Counter(int(item.episode["seed"]) for item in items)
        expected_per_seed = int(contract["design"]["base_tasks_per_planner_seed"])
        if per_seed != Counter(
            {
                int(seed): expected_per_seed
                for seed in contract["design"]["source_seeds"]
            }
        ):
            raise RuntimeError(f"incomplete source seed blocks for {planner}: {per_seed}")
        source_counts[planner] = {
            "episodes": len(items),
            "per_seed": {str(key): value for key, value in sorted(per_seed.items())},
        }
    cells = atomic_cells(contract)
    partitions = partition_cells(cells, int(contract["design"]["physical_shards"]))
    report = {
        "schema_version": "minmandate-e6-runtime-preflight-v1",
        "experiment_id": contract["experiment_id"],
        "passed": True,
        "contract_sha256": sha256_file(CONTRACT_PATH),
        "runner_sha256": sha256_file(Path(__file__).resolve()),
        "binary_sha256": sha256_file(binary),
        "policy_sha256": sha256_file(policy),
        "required_inputs": required_inputs,
        "source_prefixes": source_prefixes,
        "source_counts": source_counts,
        "normalized_universe_groups": {
            str(size): len(rows) for size, rows in sorted(by_size.items())
        },
        "normalized_mask_rows": {
            str(size): len(rows) for size, rows in sorted(masks_by_size.items())
        },
        "atomic_cells": len(cells),
        "physical_shard_cell_counts": {
            str(index): len(rows) for index, rows in partitions.items()
        },
        "protocol_execution_started": False,
    }
    if args.output:
        output = args.output.resolve()
        if output.exists():
            raise RuntimeError(f"refusing to overwrite preflight report: {output}")
        write_json(output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan", help="print the frozen atomic-cell/shard plan")
    plan.add_argument("--output", type=Path)
    plan.set_defaults(func=print_plan)
    preflight = sub.add_parser(
        "preflight",
        help="validate runtime, source cohorts, and merchant-scale inputs",
    )
    preflight.add_argument("--root", type=Path, default=ROOT)
    preflight.add_argument(
        "--source-root",
        type=Path,
        default=None,
        help="Root containing the registered source-run directories; defaults to --root.",
    )
    preflight.add_argument("--output", type=Path)
    preflight.add_argument("--source-prefixes", required=True)
    preflight.add_argument("--expected-episodes-per-planner", type=int, default=288)
    preflight.add_argument("--rust-binary", type=Path, required=True)
    preflight.add_argument("--policy-config", type=Path, required=True)
    preflight.set_defaults(func=runtime_preflight)
    run = sub.add_parser("run-shard", help="execute one physical shard")
    run.add_argument("--root", type=Path, default=ROOT)
    run.add_argument("--source-root", type=Path, default=None)
    run.add_argument("--adapter-root", type=Path, default=None)
    run.add_argument("--output-root", type=Path, default=DEFAULT_RESULT_ROOT)
    run.add_argument("--shard-index", type=int, required=True)
    run.add_argument("--shard-count", type=int, default=32)
    run.add_argument("--source-prefixes", required=True)
    run.add_argument("--expected-episodes-per-planner", type=int, default=288)
    run.add_argument("--rust-binary", type=Path, required=True)
    run.add_argument("--policy-config", type=Path, required=True)
    run.set_defaults(func=run_shard)
    merge = sub.add_parser("merge", help="validate and merge all shards")
    merge.add_argument("--root", type=Path, default=ROOT)
    merge.add_argument("--shards-root", type=Path, default=DEFAULT_RESULT_ROOT / "shards")
    merge.add_argument("--output-dir", type=Path, default=DEFAULT_RESULT_ROOT / "merged")
    merge.set_defaults(func=validate_and_merge)
    return result


def main() -> int:
    args = parser().parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
