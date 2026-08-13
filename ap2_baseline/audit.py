from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Iterable


def load_jsonl(path: str | Path) -> list[dict]:
    rows = []
    with Path(path).open() as fh:
        for line in fh:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def write_field_registry(rows: Iterable[dict], output: str | Path) -> None:
    fields = []
    for row in rows:
        for name, value in row["wire"]["stable_fields"].items():
            fields.append(
                {
                    "workflow_id": row["workflow_id"],
                    "call_id": row["call_id"],
                    "profile": row.get("condition", "AP2-v0.2"),
                    "observer": "merchant+payment-interface",
                    "field_path": name,
                    "value": value,
                    "nonempty": bool(value),
                }
            )
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(fields[0]) if fields else ["field_path"])
        writer.writeheader()
        writer.writerows(fields)


def exact_join_metrics(rows: list[dict], field_name: str) -> dict:
    """Compute exact join recall and candidate-set size for one concrete field.

    A query is eligible when it has at least one other call in the same workflow.
    Candidates are all other calls carrying the same non-empty field value.
    """
    by_value: dict[str, list[int]] = defaultdict(list)
    for i, row in enumerate(rows):
        value = row["wire"]["stable_fields"].get(field_name, "")
        if value:
            by_value[value].append(i)

    recalls = []
    candidate_sizes = []
    false_joins = 0
    for i, row in enumerate(rows):
        true_peers = {
            j for j, other in enumerate(rows)
            if j != i and other["workflow_id"] == row["workflow_id"]
        }
        if not true_peers:
            continue
        value = row["wire"]["stable_fields"].get(field_name, "")
        candidates = {j for j in by_value.get(value, []) if j != i} if value else set()
        recalls.append(int(bool(candidates & true_peers)))
        candidate_sizes.append(len(candidates))
        false_joins += sum(rows[j]["workflow_id"] != row["workflow_id"] for j in candidates)

    return {
        "field": field_name,
        "coverage": sum(bool(r["wire"]["stable_fields"].get(field_name, "")) for r in rows) / max(1, len(rows)),
        "exact_join_recall": sum(recalls) / max(1, len(recalls)),
        "mean_candidate_set": sum(candidate_sizes) / max(1, len(candidate_sizes)),
        "false_join_edges": false_joins,
        "eligible_queries": len(recalls),
    }
