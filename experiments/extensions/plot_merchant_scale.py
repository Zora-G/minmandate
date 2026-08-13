#!/usr/bin/env python3
"""Render compact diagnostic panels accompanying supplementary Table 6."""

from __future__ import annotations

import csv
from pathlib import Path

import matplotlib as mpl

mpl.use("pdf")
import matplotlib.pyplot as plt
import numpy as np


ROOT = Path(__file__).resolve().parents[2]
SUMMARY = (
    ROOT
    / "experiments/extensions/results/MERCHANT_SCALE_STRESS"
    / "merged-attempt-003/analysis/summary.csv"
)
OUTPUT = ROOT / "paper/supplementary/figures/figure_e6_merchant_scale.pdf"

PLANNERS = ["L8", "Q14", "Q32", "GPT-OSS"]
UNIVERSE_SIZES = [3, 5, 10, 20]
COLORS = ["#0072B2", "#009E73", "#D55E00", "#CC79A7"]
MARKERS = ["o", "s", "^", "D"]


def read_rows() -> list[dict[str, str]]:
    with SUMMARY.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def task_success(
    rows: list[dict[str, str]],
    planner: str,
    universe_size: int,
    arm: str,
    k: int | None = None,
) -> float:
    matches = [
        row
        for row in rows
        if row["planner"] == planner
        and row["arm"] == arm
        and int(row["universe_size"]) == universe_size
        and float(row["p_unavail"]) == 0.5
        and (arm != "AP2" or int(row["k"]) == k)
    ]
    if len(matches) != 1:
        raise ValueError(
            f"Expected one row for planner={planner}, U={universe_size}, "
            f"arm={arm}, k={k}; found {len(matches)}"
        )
    return 100.0 * float(matches[0]["task_success_rate"])


def main() -> None:
    mpl.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": ["Times New Roman", "DejaVu Serif"],
            "pdf.fonttype": 42,
            "axes.linewidth": 0.65,
            "axes.labelsize": 10.95,
            "xtick.labelsize": 10.95,
            "ytick.labelsize": 10.95,
            "legend.fontsize": 10.95,
            "xtick.direction": "out",
            "ytick.direction": "out",
        }
    )
    rows = read_rows()
    fig, axes = plt.subplots(2, 1, figsize=(2.70, 4.13), constrained_layout=False)

    # Panel (a): absolute MinMandate task success as the admitted universe grows.
    for planner, color, marker in zip(PLANNERS, COLORS, MARKERS):
        values = [
            task_success(rows, planner, universe_size, "MinMandate")
            for universe_size in UNIVERSE_SIZES
        ]
        axes[0].plot(
            UNIVERSE_SIZES,
            values,
            color=color,
            marker=marker,
            markersize=4.2,
            linewidth=1.45,
            label=planner,
        )
    axes[0].set_ylabel("Task success (%)")
    axes[0].set_xlabel(r"Merchant-universe size $|U|$")
    axes[0].set_xticks(UNIVERSE_SIZES)
    axes[0].set_ylim(0, 100)
    axes[0].legend(
        frameon=False,
        ncol=2,
        loc="center left",
        bbox_to_anchor=(0.02, 0.43),
        handlelength=1.8,
        columnspacing=0.8,
        borderaxespad=0.15,
    )

    # Panel (b): planner-specific gain over restricted AP2-k at the largest U.
    x = np.arange(len(PLANNERS))
    width = 0.23
    bar_colors = ["#0072B2", "#E69F00", "#009E73"]
    hatches = ["", "//", ".."]
    for offset, k, color, hatch in zip([-width, 0.0, width], [1, 2, 3], bar_colors, hatches):
        gains = [
            task_success(rows, planner, 20, "MinMandate")
            - task_success(rows, planner, 20, "AP2", k=k)
            for planner in PLANNERS
        ]
        axes[1].bar(
            x + offset,
            gains,
            width,
            label=f"vs. AP2-{k}",
            color=color,
            edgecolor="black",
            linewidth=0.45,
            hatch=hatch,
        )
    axes[1].set_ylabel("Task-success gain (pp)")
    axes[1].set_xlabel(r"Planner at $|U|=20$")
    axes[1].set_xticks(x)
    axes[1].set_xticklabels(PLANNERS)
    axes[1].set_ylim(0, 65)
    axes[1].legend(
        frameon=False,
        ncol=1,
        loc="upper left",
        handlelength=1.8,
        borderaxespad=0.15,
    )

    for label, ax in zip(["(a)", "(b)"], axes):
        ax.text(
            -0.14,
            1.03,
            label,
            transform=ax.transAxes,
            fontsize=10.95,
            fontweight="bold",
            va="bottom",
        )
        ax.grid(axis="y", color="#D9E2E8", linewidth=0.4)
        ax.set_axisbelow(True)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.spines["left"].set_linewidth(0.65)
        ax.spines["bottom"].set_linewidth(0.65)
        ax.tick_params(axis="both", width=0.55, length=2.7)

    fig.subplots_adjust(left=0.30, right=0.99, bottom=0.12, top=0.96, hspace=0.50)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUTPUT)
    plt.close(fig)


if __name__ == "__main__":
    main()
