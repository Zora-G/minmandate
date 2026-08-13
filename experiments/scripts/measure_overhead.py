#!/usr/bin/env python3
"""Measure the MinMandate JSONL transport codec on a fixed trace.

Byte counts cover the physical client--backend JSONL boundary and include the
newline-delimited JSON envelope.  Measurements span setup and paid calls;
startup ping and workflow teardown are excluded.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.adapters.base import PaymentContext
from experiments.adapters.minmandate_adapter import PersistentMinMandateClient
from experiments.runtime.minmandate_contract import load_or_create_user_approval


AMOUNT_NANOS = 10_000_000
CALL_COUNT = 4


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fieldnames = [
        "encoding",
        "repetition",
        "phase",
        "call_index",
        "operation",
        "direction",
        "payload_bytes",
        "transport_bytes",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _approval(workflow: str) -> Any:
    slots = [
        {
            "service_class": "service",
            "merchant_id": "merchant-a",
            "capacity": AMOUNT_NANOS,
            "expiry": 3600,
        }
        for _ in range(CALL_COUNT)
    ]
    return slots, load_or_create_user_approval(
        mode="development",
        workflow_id=workflow,
        slots=slots,
        base_budget=CALL_COUNT * AMOUNT_NANOS,
        reserve_budget=0,
        approved_budget=CALL_COUNT * AMOUNT_NANOS,
        allowed_service_classes=["service"],
        allowed_merchants=["merchant-a"],
        funding_eligible_slot_indices=list(range(CALL_COUNT)),
        funding_coverage=CALL_COUNT * AMOUNT_NANOS,
        amendment_limit=0,
    )


def _run_condition(
    binary: Path,
    *,
    compact_wire: bool,
    repetitions: int,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    encoding = "gzip-base64-v1" if compact_wire else "canonical-json"
    raw_rows: list[dict[str, Any]] = []
    setup_totals: list[dict[str, Any]] = []
    call_totals: list[dict[str, Any]] = []
    workflow_totals: list[dict[str, Any]] = []
    with PersistentMinMandateClient(
        binary,
        compact_wire=compact_wire,
        transport_wire_audit=True,
    ) as client:
        # Startup is explicitly outside the established overhead boundary.
        client.transport_wire_audit.clear()
        for repetition in range(1, repetitions + 1):
            start = len(client.transport_wire_audit)
            workflow = f"compact-transport-{encoding}-r{repetition}"
            slots, approval = _approval(workflow)
            begin = client.begin_workflow(
                workflow,
                "compact transport fixed trace",
                slots,
                3600,
                approval_artifact=approval,
            )
            if begin.get("accepted") is not True:
                raise RuntimeError(f"setup rejected under {encoding}: {begin}")
            for call_index in range(1, CALL_COUNT + 1):
                context = PaymentContext(
                    workflow,
                    "fixed-cost-trace",
                    f"paid-{call_index}",
                    call_index,
                    "controlled",
                    "service.alpha",
                    {"request": f"fixed-paid-call-{call_index}"},
                    "service.alpha",
                    "service",
                    "merchant-a",
                    AMOUNT_NANOS,
                    call_index + 1,
                    11,
                )
                response = client.invoke(context, call_index - 1)
                if response.get("accepted") is not True or response.get("status") != "fresh_accept":
                    raise RuntimeError(
                        f"paid call {call_index} rejected under {encoding}: {response}"
                    )
            end = client.end_workflow(workflow)
            if end.get("ok") is not True:
                raise RuntimeError(f"workflow teardown failed under {encoding}: {end}")

            audit = client.transport_wire_audit[start:]
            expected_operations = ["begin_workflow", *("invoke" for _ in range(CALL_COUNT)), "end_workflow"]
            operations = [entry["operation"] for entry in audit]
            if operations != expected_operations:
                raise RuntimeError(f"unexpected transport audit operations: {operations}")

            measured = audit[:-1]  # Exclude teardown from the established lifetime.
            totals = []
            for index, entry in enumerate(measured):
                phase = "task_setup" if index == 0 else "per_call"
                call_index = 0 if index == 0 else index
                total = int(entry["request_transport_bytes"]) + int(
                    entry["response_transport_bytes"]
                )
                totals.append(total)
                for direction in ("request", "response"):
                    raw_rows.append(
                        {
                            "encoding": encoding,
                            "repetition": repetition,
                            "phase": phase,
                            "call_index": call_index,
                            "operation": entry["operation"],
                            "direction": direction,
                            "payload_bytes": int(entry[f"{direction}_payload_bytes"]),
                            "transport_bytes": int(entry[f"{direction}_transport_bytes"]),
                        }
                    )
            setup_totals.append(
                {"encoding": encoding, "repetition": repetition, "bytes": totals[0]}
            )
            for call_index, total in enumerate(totals[1:], start=1):
                call_totals.append(
                    {
                        "encoding": encoding,
                        "repetition": repetition,
                        "call_index": call_index,
                        "bytes": total,
                    }
                )
            workflow_totals.append(
                {"encoding": encoding, "repetition": repetition, "bytes": sum(totals)}
            )
    return raw_rows, setup_totals, call_totals, workflow_totals


def _p50(rows: list[dict[str, Any]]) -> float:
    return float(statistics.median(float(row["bytes"]) for row in rows))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust-binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=100)
    args = parser.parse_args()
    if args.repetitions <= 0:
        raise SystemExit("--repetitions must be positive")
    binary = args.rust_binary.resolve()
    if not binary.is_file():
        raise SystemExit(f"missing Rust binary: {binary}")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)

    all_raw: list[dict[str, Any]] = []
    by_encoding: dict[str, tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]] = {}
    for compact_wire in (False, True):
        raw, setup, calls, workflow = _run_condition(
            binary, compact_wire=compact_wire, repetitions=args.repetitions
        )
        all_raw.extend(raw)
        by_encoding["gzip-base64-v1" if compact_wire else "canonical-json"] = (
            setup,
            calls,
            workflow,
        )
    canonical = by_encoding["canonical-json"]
    compressed = by_encoding["gzip-base64-v1"]
    metrics = {
        "task_setup": (canonical[0], compressed[0]),
        "per_paid_call": (canonical[1], compressed[1]),
        "four_call_workflow": (canonical[2], compressed[2]),
    }
    summary_metrics = {}
    for name, (baseline_rows, compressed_rows) in metrics.items():
        baseline = _p50(baseline_rows)
        optimized = _p50(compressed_rows)
        summary_metrics[name] = {
            "canonical_json_p50_bytes": baseline,
            "gzip_base64_v1_p50_bytes": optimized,
            "reduction_percent": (baseline - optimized) * 100.0 / baseline,
            "canonical_n": len(baseline_rows),
            "gzip_base64_v1_n": len(compressed_rows),
        }
    _write_csv(output / "transport_raw.csv", all_raw)
    _write_json(
        output / "transport_summary.json",
        {
            "schema_version": "minmandate-compact-transport-v1",
            "candidate_binary": str(binary),
            "call_count": CALL_COUNT,
            "repetitions": args.repetitions,
            "metric_boundary": "physical client-to-Rust-backend JSONL lines, including newline; startup ping and end_workflow excluded",
            "not_a_figure3_role_hop_replacement": True,
            "semantic_requirement": "each setup and paid call accepted as fresh_accept under both encodings",
            "metrics": summary_metrics,
        },
    )
    print(json.dumps({"output": str(output), "metrics": summary_metrics}, sort_keys=True))


if __name__ == "__main__":
    main()
