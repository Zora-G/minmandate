#!/usr/bin/env python3
"""Render the paper-facing AP2-k table with failure attribution at primary p.

This repository adapter leaves the supplied metric and rendering scripts
unchanged.  It combines their frozen outputs with the condition-neutral
market-wide failure decomposition produced by complete_ap2k_analysis.py.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


PLANNER_ORDER = ("L8", "Q14", "Q32", "GPT-OSS")
CONDITION_ORDER = ("AP2-1", "AP2-2", "AP2-3", "Native", "Policy-only", "MinMandate")
DISPLAY_BLOCKS = (
    (r"AP2-\(k\) sensitivity", ("AP2-1", "AP2-2", "AP2-3")),
    ("Stack ablation", ("Native", "Policy-only", "MinMandate")),
)


def pk(value: float) -> str:
    return format(float(value), "g")


def fmt(value: float | None, signed: bool = False, bold: bool = False) -> str:
    if value is None:
        rendered = r"\textsc{n/a}"
    else:
        rendered = f"{value:+.1f}" if signed else f"{value:.1f}"
    return rf"\textbf{{{rendered}}}" if bold else rendered


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--values", type=Path, required=True)
    parser.add_argument("--failure-decomposition", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    values = json.loads(args.values.read_text(encoding="utf-8"))
    decompositions: dict[tuple[str, str], dict[str, str]] = {}
    with args.failure_decomposition.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            decompositions[(row["planner"], row["condition"])] = row

    planners = [planner for planner in PLANNER_ORDER if planner in values["planners"]]
    missing_planners = set(values["planners"]) - set(planners)
    if missing_planners:
        raise SystemExit(f"unrendered planners: {sorted(missing_planners)}")
    for planner in planners:
        missing_conditions = set(CONDITION_ORDER) - set(values["planners"][planner])
        if missing_conditions:
            raise SystemExit(f"{planner}: missing conditions {sorted(missing_conditions)}")

    lines = [
        r"\begin{table*}[t]",
        r"\centering",
        r"\caption{\textbf{End-to-end task utility under independent merchant unavailability.} Each admitted merchant is independently unavailable under a frozen, nested mask shared across conditions. AP2-\(k\) names the top \(k\) merchants at authorization time; MinMandate may select any merchant satisfying the frozen admission predicate. \(\Delta\) vs.\ Native is measured at \(p_{\mathrm{unavail}}=0.25\). The two failure columns decompose availability failures at \(p_{\mathrm{unavail}}=0.5\): coverage-limited failure counts paid-task episodes where an admitted merchant is available but no merchant named by the condition is available, whereas market-wide failure counts episodes where no merchant in the full admitted universe is available and is derived from the condition-neutral Native route. Fallback success uses the common set of episodes where the preferred merchant is unavailable but an alternative in the full admitted universe remains available. Bold numerals mark the complete AP2 protocol (AP2-3) within the AP2-\(k\) sensitivity block.}",
        r"\label{tab:task-utility-unavailability}",
        r"\footnotesize",
        r"\setlength{\tabcolsep}{2.8pt}",
        r"\renewcommand{\arraystretch}{1.12}",
        r"\newcolumntype{T}{>{\centering\arraybackslash}p{2.8em}}",
        r"\begin{tabular*}{\textwidth}{@{\extracolsep{\fill}}ll@{\hspace{0.7em}}l@{\hspace{0.35em}}TTTTcccc@{}}",
        r"\toprule",
        r"\multirow{2}{*}{\textbf{Planner}} & \multirow{2}{*}{\textbf{Block}} & \multirow{2}{*}{\textbf{Condition}} & \multicolumn{4}{c}{\textbf{Task success (\%) \(\uparrow\) under \boldmath\(p_{\mathrm{unavail}}\)}} & \multicolumn{4}{c@{}}{\textbf{Merchant adaptability}} \\",
        r"\cmidrule(lr){4-7}\cmidrule(lr){8-11}",
        r"& & & \(0\) & \(0.1\) & \(\mathbf{0.25}\) & \(0.5\) & \shortstack{\(\Delta\) vs.\\Native (pp) \(\uparrow\)} & \shortstack{Authorization\\fail. (pp) \(\downarrow\)} & \shortstack{Market\\fail. (pp) \(\downarrow\)} & \shortstack{Fallback\\succ. (\%) \(\uparrow\)} \\",
        r"\midrule",
    ]
    for planner_index, planner in enumerate(planners):
        for block_index, (block_label, block_conditions) in enumerate(DISPLAY_BLOCKS):
            for condition_index, condition in enumerate(block_conditions):
                cell = values["planners"][planner][condition]
                decomposition = decompositions.get((planner, condition))
                if decomposition is None:
                    raise SystemExit(f"missing failure decomposition for {planner}/{condition}")
                prefix = (
                    rf"\multirow{{6}}{{*}}{{{planner}}}"
                    if block_index == 0 and condition_index == 0
                    else ""
                )
                block = rf"\multirow{{3}}{{*}}{{{block_label}}}" if condition_index == 0 else ""
                name = rf"\textbf{{{condition}}}" if condition == "MinMandate" else condition
                highlight_complete_protocol = condition == "AP2-3"
                successes = [fmt(cell["task_success"][pk(p)]["percent"], bold=highlight_complete_protocol) for p in values["p_grid"]]
                fields = successes + [
                    fmt(cell["delta_vs_native"]["percentage_points"], signed=True, bold=highlight_complete_protocol),
                    fmt(float(decomposition["coverage_limited_percent"]) if decomposition["coverage_limited_percent"] else None, bold=highlight_complete_protocol),
                    fmt(float(decomposition["market_wide_percent"]) if decomposition["market_wide_percent"] else None, bold=highlight_complete_protocol),
                    fmt(cell["fallback_success"]["percent"], bold=highlight_complete_protocol),
                ]
                lines.append(" & ".join([prefix, block, name] + fields) + r" \\")
            if block_index == 0:
                lines.append(r"\cmidrule(lr){2-11}")
        if planner_index != len(planners) - 1:
            lines.append(r"\midrule")
    lines += [r"\bottomrule", r"\end{tabular*}", r"\end{table*}", ""]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(lines), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
