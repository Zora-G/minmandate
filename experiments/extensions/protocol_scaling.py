#!/usr/bin/env python3
"""Run auditable appendix-only scaling and component experiments (E7).

This wrapper invokes the real local Rust credential implementation.  It keeps
the three estimands separate: selected-slot scaling, credential-size scaling,
and component-specific negative controls.  It refuses to overwrite a result
directory so failed or adverse runs remain inspectable.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import platform
import subprocess
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
CRATE = ROOT / "rust_protocol"
DEFAULT_BINARY = CRATE / "target/release/minmandate-rs"
DEFAULT_OUTPUT = ROOT / "experiments/extensions/results/PROTOCOL_COMPONENT_SCALING"
SLOT_COUNTS = (1, 2, 4, 8)
CREDENTIAL_SIZES = (4, 8, 16, 32, 64)
VARIANTS = ("full", "one_call_binding", "serials", "bbs_only")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _percentile(values: Iterable[float], q: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("empty metric sample")
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * q
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def _summary(rows: list[dict[str, Any]], columns: tuple[str, ...]) -> dict[str, Any]:
    result: dict[str, Any] = {"n": len(rows)}
    for column in columns:
        values = [float(row[column]) for row in rows]
        result[column] = {"p50": _percentile(values, .5), "p95": _percentile(values, .95)}
    return result


def _run(binary: Path, output: Path, runs: int, slots: int, spend_slots: int, variant: str) -> list[dict[str, Any]]:
    output.mkdir(parents=True, exist_ok=False)
    command = [
        str(binary), "--runs", str(runs), "--slots", str(slots),
        "--spend-slots", str(spend_slots), "--experiment-variant", variant,
        "--skip-corruption-check", "--output-dir", str(output),
    ]
    completed = subprocess.run(command, cwd=CRATE, capture_output=True, text=True)
    (output / "runner.stdout.log").write_text(completed.stdout, encoding="utf-8")
    (output / "runner.stderr.log").write_text(completed.stderr, encoding="utf-8")
    if completed.returncode:
        raise RuntimeError(f"benchmark failed for {output.name}: {completed.stderr[-1200:]}")
    raw = json.loads((output / "latest-rust.json").read_text(encoding="utf-8"))
    rows = raw.get("rows")
    if not isinstance(rows, list) or len(rows) != runs:
        raise RuntimeError(f"unexpected row count for {output.name}")
    if any(row["slots"] != slots or row["spend_slots"] != spend_slots for row in rows):
        raise RuntimeError(f"configuration mismatch in {output.name}")
    if any(row["experiment_variant"] != variant for row in rows):
        raise RuntimeError(f"variant mismatch in {output.name}")
    return rows


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _f(value: float) -> str:
    return f"{value:.2f}"


def _latex_tables(output: Path, slots: list[dict[str, Any]], credentials: list[dict[str, Any]], ablations: list[dict[str, Any]]) -> None:
    slot_lines = [
        r"\begin{table*}[t]", r"\centering\small",
        r"\resizebox{\textwidth}{!}{%", r"\begin{tabular}{@{}rccccr@{}}", r"\toprule",
        r"$|S_i|$ & Derive (p50/p95 ms) & Merchant verify (p50/p95 ms) & Redemption (p50/p95 ms) & Service/spend bytes & Total bytes \\", r"\midrule",
    ]
    for row in slots:
        slot_lines.append(
            f"{row['selected_slots']} & {_f(row['presentation_ms']['p50'])}/{_f(row['presentation_ms']['p95'])} & "
            f"{_f(row['merchant_verify_ms']['p50'])}/{_f(row['merchant_verify_ms']['p95'])} & "
            f"{_f(row['redeem_valid_ms']['p50'])}/{_f(row['redeem_valid_ms']['p95'])} & "
            f"{int(row['merchant_proof_bytes']['p50'])}/{int(row['redemption_proof_bytes']['p50'])} & {int(row['redeem_request_bytes']['p50'])} " + r"\\")
    slot_lines += [r"\bottomrule", r"\end{tabular}", r"}", rf"\caption{{E7 selected-slot scaling (appendix-only local protocol boundary; $n={slots[0]['n']}$ per cell). Bytes are canonical serialized values.}}", r"\label{tab:e7-slot-scaling}", r"\end{table*}"]
    (output / "table_selected_slot_scaling.tex").write_text("\n".join(slot_lines) + "\n", encoding="utf-8")

    credential_lines = [
        r"\begin{table}[t]", r"\centering\small", r"\begin{tabular}{@{}rrrrr@{}}", r"\toprule",
        r"Slots & Credential bytes & Issue (p50/p95 ms) & Derive (p50/p95 ms) & Verify (p50/p95 ms) \\", r"\midrule",
    ]
    for row in credentials:
        credential_lines.append(
            f"{row['credential_slots']} & {int(row['credential_bytes']['p50'])} & "
            f"{_f(row['issue_ms']['p50'])}/{_f(row['issue_ms']['p95'])} & "
            f"{_f(row['presentation_ms']['p50'])}/{_f(row['presentation_ms']['p95'])} & "
            f"{_f(row['merchant_verify_ms']['p50'])}/{_f(row['merchant_verify_ms']['p95'])} " + r"\\")
    credential_lines += [r"\bottomrule", r"\end{tabular}", rf"\caption{{E7 credential-size scaling with one selected slot ($n={credentials[0]['n']}$ per cell).}}", r"\label{tab:e7-credential-scaling}", r"\end{table}"]
    (output / "table_credential_scaling.tex").write_text("\n".join(credential_lines) + "\n", encoding="utf-8")

    ablation_lines = [
        r"\begin{table}[t]", r"\centering\small", r"\begin{tabular}{@{}lccc@{}}", r"\toprule",
        r"Variant & Stable issuer exposed & Bind-tamper accepted & Replay fresh-accept \\", r"\midrule",
    ]
    labels = {"full": "Full", "one_call_binding": "No issuer hiding", "serials": "No binding", "bbs_only": "No serial freshness"}
    for row in ablations:
        ablation_lines.append(f"{labels[row['variant']]} & {row['stable_issuer_handle_disclosed_rate']:.3f} & {row['bind_tamper_accept_rate']:.3f} & {row['replay_fresh_accept_rate']:.3f} " + r"\\")
    ablation_lines += [r"\bottomrule", r"\end{tabular}", rf"\caption{{E7 component-specific ablations ($n={ablations[0]['n']}$ per variant). Each column tests the component named by its mechanism, not a common privacy metric.}}", r"\label{tab:e7-component-ablation}", r"\end{table}"]
    (output / "table_component_ablations.tex").write_text("\n".join(ablation_lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--runs", type=int, default=20)
    parser.add_argument("--resume", action="store_true", help="continue an interrupted run without overwriting completed cells")
    args = parser.parse_args()
    binary, output = args.binary.resolve(), args.output.resolve()
    if args.runs < 5:
        raise ValueError("--runs must be at least 5 to report p95")
    if not binary.is_file():
        raise FileNotFoundError(binary)
    if output.exists() and not args.resume:
        raise FileExistsError(f"refusing to overwrite {output}")
    if output.exists() and (output / "manifest.json").exists():
        raise FileExistsError(f"refusing to alter completed run {output}")
    output.mkdir(parents=True, exist_ok=True)
    raw = output / "raw"
    raw.mkdir(exist_ok=True)
    slot_rows: list[dict[str, Any]] = []
    credential_rows: list[dict[str, Any]] = []
    ablation_rows: list[dict[str, Any]] = []
    slot_metrics = ("presentation_ms", "merchant_verify_ms", "redeem_valid_ms", "merchant_proof_bytes", "redemption_proof_bytes", "redeem_request_bytes")
    credential_metrics = ("credential_bytes", "issue_ms", "presentation_ms", "merchant_verify_ms", "redeem_valid_ms")

    def run_or_load(name: str, slots: int, spend_slots: int, variant: str) -> list[dict[str, Any]]:
        cell = raw / name
        prior = cell / "latest-rust.json"
        if prior.is_file():
            loaded = json.loads(prior.read_text(encoding="utf-8")).get("rows")
            if isinstance(loaded, list) and len(loaded) == args.runs and all(
                row.get("slots") == slots and row.get("spend_slots") == spend_slots and row.get("experiment_variant") == variant
                for row in loaded
            ):
                return loaded
            raise RuntimeError(f"interrupted cell {name} is incomplete or inconsistent; it was preserved and not rerun")
        return _run(binary, cell, args.runs, slots, spend_slots, variant)

    for selected in SLOT_COUNTS:
        rows = run_or_load(f"selected_slots_{selected}", 8, selected, "full")
        item = _summary(rows, slot_metrics)
        item["selected_slots"] = selected
        slot_rows.append(item)
    for size in CREDENTIAL_SIZES:
        rows = run_or_load(f"credential_slots_{size}", size, 1, "full")
        item = _summary(rows, credential_metrics)
        item["credential_slots"] = size
        credential_rows.append(item)
    for variant in VARIANTS:
        rows = run_or_load(f"ablation_{variant}", 8, 1, variant)
        ablation_rows.append({
            "variant": variant, "n": len(rows),
            "stable_issuer_handle_disclosed_rate": sum(bool(x["stable_issuer_handle_disclosed"]) for x in rows) / len(rows),
            "bind_tamper_accept_rate": sum(bool(x["bad_bind_fresh_execution_authorized"]) for x in rows) / len(rows),
            "replay_fresh_accept_rate": sum(bool(x["replay_fresh_execution_authorized"]) for x in rows) / len(rows),
        })
    _write_csv(output / "selected_slot_scaling.csv", slot_rows)
    _write_csv(output / "credential_size_scaling.csv", credential_rows)
    _write_csv(output / "component_ablations.csv", ablation_rows)
    manifest = {
        "schema_version": "microbench-manifest-v2", "run_id": "PROTOCOL_COMPONENT_SCALING",
        "implementation": {"binary": str(binary), "binary_sha256": _sha256(binary), "crate_source": str(CRATE / "src"), "rust_source_sha256": _sha256(CRATE / "src/lib.rs")},
        "design": {"runs_per_cell": args.runs, "selected_slot_counts": SLOT_COUNTS, "credential_slot_counts": CREDENTIAL_SIZES, "variants": VARIANTS, "boundary": "local process, real BLS12-381/BBS operations; excludes LLM, network, live payment rails, and distributed state"},
        "environment": {"platform": platform.platform(), "python": platform.python_version(), "rustc": subprocess.run(["rustc", "--version"], capture_output=True, text=True, check=True).stdout.strip()},
        "outputs": {name: _sha256(output / name) for name in ("selected_slot_scaling.csv", "credential_size_scaling.csv", "component_ablations.csv")},
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _latex_tables(output, slot_rows, credential_rows, ablation_rows)
    print(json.dumps({"output": str(output), "slot_cells": len(slot_rows), "credential_cells": len(credential_rows), "ablation_cells": len(ablation_rows)}, sort_keys=True))


if __name__ == "__main__":
    main()
