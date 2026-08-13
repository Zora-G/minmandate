#!/usr/bin/env python3
"""Validate the frozen AP2-k availability mask without formal results."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def read_jsonl(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--frozen-dir", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    frozen = args.frozen_dir
    config = json.loads((frozen / "ap2k_config.json").read_text(encoding="utf-8"))
    masks = read_jsonl(frozen / "availability_masks.jsonl")
    expected = {}
    recomputed = 0
    errors = []
    for row in masks:
        key = (str(row["task_id"]), int(row["seed"]), str(row["merchant_id"]))
        if key in expected:
            errors.append(f"duplicate mask key {key}")
        expected[key] = row
        msg = "\x1f".join([str(config["availability_salt"]), key[0], str(key[1]), key[2]]).encode()
        u = int.from_bytes(hashlib.sha256(msg).digest()[:8], "big") / float(1 << 64)
        recomputed += int(abs(float(row["u"]) - u) <= 1e-15)
        if abs(float(row["u"]) - u) > 1e-15:
            errors.append(f"u mismatch {key}")
        for p in config["p_unavail"]:
            label = format(float(p), "g")
            if bool(row["unavailable_at"][label]) != (u < float(p)):
                errors.append(f"threshold mismatch {key}/{label}")

    nested = True
    for key, row in expected.items():
        vals = [bool(row["unavailable_at"][format(float(p), "g")]) for p in config["p_unavail"]]
        if any(vals[i] and not vals[i + 1] for i in range(len(vals) - 1)):
            nested = False
            errors.append(f"non-nested mask {key}")

    result = {
        "experiment_id": config["experiment_id"],
        "mask_rows": len(masks),
        "unique_mask_keys": len(expected),
        "recomputed_u_rows": recomputed,
        "shared_across_planners": bool(config["availability_shared_across_planners"]),
        "persistent_within_episode": bool(config["availability_persistent_within_episode"]),
        "nested": nested,
        "passed": not errors and nested,
        "errors": errors,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
