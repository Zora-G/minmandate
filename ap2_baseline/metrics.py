from __future__ import annotations

from collections import Counter, defaultdict
from statistics import median
from typing import Iterable


def paired_transitions(rows: Iterable[dict], left: str, right: str) -> dict[str, int]:
    index = defaultdict(dict)
    for row in rows:
        key = (row["task_id"], row["planner"], row["seed"])
        index[key][row["condition"]] = bool(row["success"])
    out = Counter()
    for values in index.values():
        if left not in values or right not in values:
            continue
        l, r = values[left], values[right]
        out[f"{'S' if l else 'F'}->{'S' if r else 'F'}"] += 1
    return dict(out)


def summarize_ap2_calls(rows: Iterable[dict]) -> dict:
    rows = list(rows)
    accepted = [r for r in rows if r.get("accepted")]
    denials = Counter(r.get("reason") for r in rows if not r.get("accepted"))
    total_wire = [r["wire"]["byte_sizes"]["total_transmitted"] for r in accepted if r.get("wire")]
    latency = [sum(r.get("timings_ms", {}).values()) for r in accepted]
    return {
        "calls": len(rows),
        "accepted": len(accepted),
        "accept_rate": len(accepted) / max(1, len(rows)),
        "denials": dict(denials),
        "median_total_wire_bytes": median(total_wire) if total_wire else None,
        "median_ap2_path_ms": median(latency) if latency else None,
    }
