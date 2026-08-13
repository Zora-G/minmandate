#!/usr/bin/env python3
"""Render the appendix E7 selected-slot and credential-size scaling figure."""

from __future__ import annotations

import ast
import csv
from pathlib import Path

import matplotlib as mpl

mpl.use("pdf")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D


ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "experiments/extensions/results/PROTOCOL_COMPONENT_SCALING_attempt_003"
OUTPUT = ROOT / "paper/supplementary/figures/figure_e7_scalability.pdf"


def read_rows(path: Path) -> list[dict[str, object]]:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = []
        for row in csv.DictReader(handle):
            parsed: dict[str, object] = {key: value for key, value in row.items()}
            for key, value in list(parsed.items()):
                if key == "n" or key.endswith("slots"):
                    parsed[key] = int(value)  # type: ignore[arg-type]
                elif key.endswith("_ms") or key.endswith("_bytes"):
                    parsed[key] = ast.literal_eval(value)  # type: ignore[arg-type]
            rows.append(parsed)
        return rows


def series(rows: list[dict[str, object]], x_key: str, metric: str, scale: float = 1.0) -> tuple[list[int], list[float], list[float]]:
    ordered = sorted(rows, key=lambda row: int(row[x_key]))
    x = [int(row[x_key]) for row in ordered]
    p50 = [float(row[metric]["p50"]) * scale for row in ordered]  # type: ignore[index]
    p95 = [float(row[metric]["p95"]) * scale for row in ordered]  # type: ignore[index]
    return x, p50, p95


def draw_panel(
    ax: mpl.axes.Axes,
    rows: list[dict[str, object]],
    x_key: str,
    x_label: str,
    metrics: list[tuple[str, str, str]],
    scale: float = 1.0,
) -> None:
    for metric, label, color in metrics:
        x, p50, p95 = series(rows, x_key, metric, scale=scale)
        ax.plot(x, p50, marker="o", markersize=3.8, linewidth=1.45, color=color, label=label, zorder=3)
        ax.fill_between(x, p50, p95, color=color, alpha=0.13, linewidth=0, zorder=1)
    ax.set_xlabel(x_label)
    ax.set_xticks(sorted({int(row[x_key]) for row in rows}))
    ax.grid(axis="y", color="#D9E2E8", linewidth=0.45)
    ax.set_axisbelow(True)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_linewidth(0.65)
    ax.spines["bottom"].set_linewidth(0.65)
    ax.tick_params(axis="both", labelsize=11, width=0.55, length=3)
    ax.xaxis.label.set_size(11)


def main() -> None:
    mpl.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": ["Times New Roman", "DejaVu Serif"],
            "pdf.fonttype": 42,
            "axes.linewidth": 0.65,
            "xtick.direction": "out",
            "ytick.direction": "out",
        }
    )
    slot_rows = read_rows(RESULTS / "selected_slot_scaling.csv")
    credential_rows = read_rows(RESULTS / "credential_size_scaling.csv")
    colors = {
        "derive": "#0072B2",
        "verify": "#D55E00",
        "redeem": "#009E73",
        "issue": "#CC79A7",
    }

    fig, axes = plt.subplots(1, 4, figsize=(6.55, 2.30), constrained_layout=False)
    draw_panel(
        axes[0],
        slot_rows,
        "selected_slots",
        r"$|S_i|$",
        [
            ("presentation_ms", "derive/present", colors["derive"]),
            ("merchant_verify_ms", "merchant verify", colors["verify"]),
            ("redeem_valid_ms", "redeem", colors["redeem"]),
        ],
    )
    draw_panel(
        axes[1],
        credential_rows,
        "credential_slots",
        r"$n_{\mathrm{cred}}$",
        [
            ("issue_ms", "issue", colors["issue"]),
            ("presentation_ms", "derive/present", colors["derive"]),
            ("merchant_verify_ms", "merchant verify", colors["verify"]),
        ],
    )
    draw_panel(
        axes[2],
        slot_rows,
        "selected_slots",
        r"$|S_i|$",
        [
            ("merchant_proof_bytes", "service proof", colors["derive"]),
            ("redemption_proof_bytes", "redemption proof", colors["verify"]),
            ("redeem_request_bytes", "redemption request", colors["redeem"]),
        ],
        scale=1 / 1024,
    )
    draw_panel(
        axes[3],
        credential_rows,
        "credential_slots",
        r"$n_{\mathrm{cred}}$",
        [("credential_bytes", "credential", colors["issue"])],
        scale=1 / 1024,
    )
    axes[0].set_ylabel("Latency (ms)", fontsize=11)
    axes[2].set_ylabel("Size (KiB)", fontsize=11)
    axes[0].set_xticks([1, 4, 8])
    axes[1].set_xticks([4, 16, 64])
    axes[2].set_xticks([1, 4, 8])
    axes[3].set_xticks([4, 16, 64])
    for ax in axes:
        ax.set_ylim(bottom=0)
    panel_labels = ["(a)", "(b)", "(c)", "(d)"]
    for ax, label in zip(axes, panel_labels):
        ax.text(-0.12, 1.08, label, transform=ax.transAxes, fontsize=11, fontweight="bold", va="bottom")
    handles = [
        Line2D([0], [0], color=colors["derive"], marker="o", linewidth=1.45, markersize=3.8, label="derive / service proof"),
        Line2D([0], [0], color=colors["verify"], marker="o", linewidth=1.45, markersize=3.8, label="verify / redemption proof"),
        Line2D([0], [0], color=colors["redeem"], marker="o", linewidth=1.45, markersize=3.8, label="redeem / redemption request"),
        Line2D([0], [0], color=colors["issue"], marker="o", linewidth=1.45, markersize=3.8, label="issue / credential"),
    ]
    fig.legend(handles=handles, loc="upper center", ncol=2, frameon=False, fontsize=10.5, handlelength=1.8, columnspacing=1.0, bbox_to_anchor=(0.56, 1.075))
    fig.subplots_adjust(left=0.095, right=0.995, bottom=0.30, top=0.70, wspace=0.48)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUTPUT, bbox_inches="tight", pad_inches=0.035)
    plt.close(fig)


if __name__ == "__main__":
    main()
