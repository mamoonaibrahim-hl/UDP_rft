"""Week 4: summarise and plot S1, S2 and S3 results."""

import argparse
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parent.parent

CONFIG = [
    "scenario",
    "mode",
    "window",
    "file_size",
    "delay_ms",
    "loss_pct",
    "duplicate_pct",
    "corrupt_pct",
    "reorder_pct",
    "rate_mbps",
]

METRICS = [
    "completion_s",
    "goodput_mbps",
    "retransmissions",
    "retrans_ratio_pct",
    "probe_rtt_ms",
]

LABELS = {
    1: "Stop-and-wait (W=1)",
    32: "Go-Back-N (W=32)",
}

COLORS = {
    1: "#2563eb",
    32: "#d97706",
}

STANDARD_S1_SIZES = [0, 1, 1024, 1048576, 10485760]


def load_results(folder, scenario):
    path = folder / f"{scenario}.csv"
    data = pd.read_csv(path)

    required = CONFIG + METRICS + ["rep", "status", "hash_ok"]
    missing = sorted(set(required) - set(data.columns))

    if missing:
        raise ValueError(f"{path.name}: missing columns {missing}")

    if data.empty:
        raise ValueError(f"{path.name}: no results")

    numeric = [
        column
        for column in required
        if column not in ("scenario", "mode", "status", "hash_ok")
    ]

    for column in numeric:
        data[column] = pd.to_numeric(data[column], errors="raise")

    values = data[numeric].to_numpy(dtype=float)

    if not np.isfinite(values).all():
        raise ValueError(f"{path.name}: missing or non-finite numbers")

    if (values < 0).any():
        raise ValueError(f"{path.name}: negative measurement or setting")

    if (data["completion_s"] <= 0).any():
        raise ValueError(f"{path.name}: completion time must be positive")

    for column in ("window", "file_size", "rep"):
        if (data[column] % 1 != 0).any():
            raise ValueError(f"{path.name}: {column} must be an integer")

    if not data["window"].between(1, 256).all():
        raise ValueError(f"{path.name}: invalid window size")

    if (data["rep"] < 1).any():
        raise ValueError(f"{path.name}: repetition must start at 1")

    percentages = [
        "loss_pct",
        "duplicate_pct",
        "corrupt_pct",
        "reorder_pct",
        "retrans_ratio_pct",
    ]

    for column in percentages:
        if not data[column].between(0, 100).all():
            raise ValueError(f"{path.name}: invalid {column}")

    if not data["scenario"].astype(str).eq(scenario).all():
        raise ValueError(f"{path.name}: unexpected scenario")

    hash_ok = (
        data["hash_ok"]
        .astype(str)
        .str.strip()
        .str.lower()
        .eq("true")
    )

    status_ok = data["status"].astype(str).str.strip().eq("OK")

    if not (hash_ok & status_ok).all():
        bad = data.loc[
            ~(hash_ok & status_ok),
            ["mode", "window", "file_size", "rep", "status", "hash_ok"],
        ]
        raise ValueError(
            f"{path.name}: unsuccessful or unverified runs:\n"
            f"{bad.to_string(index=False)}"
        )

    if data.duplicated(CONFIG + ["rep"]).any():
        raise ValueError(f"{path.name}: duplicate configuration/repetition")

    expected_modes = data["window"].map(
        lambda window: "stop-and-wait" if window == 1 else "sliding"
    )

    if not data["mode"].eq(expected_modes).all():
        raise ValueError(f"{path.name}: mode and window do not agree")

    data["hash_ok"] = hash_ok

    print(f"{scenario.upper()}: {len(data)} verified runs")
    return data


def make_summary(data):
    grouped = data.groupby(CONFIG, dropna=False, sort=True)

    counts = grouped.size().rename("runs")
    stats = grouped[METRICS].agg(["mean", "std"])
    stats.columns = [
        f"{metric}_{stat}" for metric, stat in stats.columns
    ]

    summary = counts.to_frame().join(stats).reset_index()

    # Standard deviation stays blank for single-run configurations.
    return summary


def select_main_results(summary, scenario):
    clean_extras = (
        summary["duplicate_pct"].eq(0)
        & summary["corrupt_pct"].eq(0)
        & summary["reorder_pct"].eq(0)
        & summary["rate_mbps"].eq(0)
    )

    selected = summary.loc[
        clean_extras & summary["window"].isin([1, 32])
    ].copy()

    if scenario == "s1":
        selected = selected.loc[
            selected["delay_ms"].eq(0)
            & selected["loss_pct"].eq(0)
            & selected["file_size"].isin(STANDARD_S1_SIZES)
        ]
        expected_x = STANDARD_S1_SIZES
        x = "file_size"

    elif scenario == "s2":
        selected = selected.loc[
            selected["file_size"].eq(1048576)
            & selected["loss_pct"].eq(0)
        ]
        expected_x = [0, 25, 50, 100]
        x = "delay_ms"

    else:
        selected = selected.loc[
            selected["file_size"].eq(1048576)
            & selected["delay_ms"].eq(50)
        ]
        expected_x = [0, 1, 2, 5, 10]
        x = "loss_pct"

    for window in (1, 32):
        part = selected.loc[selected["window"].eq(window)]

        if (
            len(part) != len(expected_x)
            or set(part[x]) != set(expected_x)
        ):
            raise ValueError(
                f"{scenario.upper()}: incomplete or ambiguous "
                f"main configuration grid for W={window}"
            )

        if (part["runs"] < 3).any():
            raise ValueError(
                f"{scenario.upper()}: main plots require at least "
                f"three runs per configuration for W={window}"
            )

    return selected


def save_figure(fig, folder, name):
    fig.savefig(folder / f"{name}.png", dpi=200)
    fig.savefig(folder / f"{name}.pdf")
    plt.close(fig)
    print(f"Saved {name}.png and {name}.pdf")


def plot_s1(summary, folder):
    fig, ax = plt.subplots(figsize=(9, 5.5), layout="constrained")
    positions = np.arange(len(STANDARD_S1_SIZES))

    for window, offset in ((1, -0.06), (32, 0.06)):
        part = (
            summary.loc[summary["window"].eq(window)]
            .set_index("file_size")
            .loc[STANDARD_S1_SIZES]
        )

        # Points avoid implying a continuous file-size relationship.
        ax.errorbar(
            positions + offset,
            part["completion_s_mean"].to_numpy(),
            yerr=part["completion_s_std"].to_numpy(),
            fmt="o",
            capsize=4,
            color=COLORS[window],
            label=LABELS[window],
        )

    ax.set_xticks(
        positions,
        ["0 B", "1 B", "1 KiB", "1 MiB", "10 MiB"],
    )
    ax.set_yscale("log")
    ax.set_xlabel("File size (categorical spacing)")
    ax.set_ylabel("Completion time (seconds, log scale)")
    ax.set_title("S1: Completion time by file size")
    ax.grid(axis="y", alpha=0.25)
    ax.legend()
    fig.supxlabel(
        "Mean ± sample standard deviation; at least 3 runs per point.",
        fontsize=9,
    )

    save_figure(fig, folder, "s1_completion_by_size")


def plot_lines(summary, x, metric, title, xlabel, ylabel, name, folder):
    fig, ax = plt.subplots(figsize=(9, 5.5), layout="constrained")

    for window in (1, 32):
        part = summary.loc[
            summary["window"].eq(window)
        ].sort_values(x)

        ax.errorbar(
            part[x].to_numpy(),
            part[f"{metric}_mean"].to_numpy(),
            yerr=part[f"{metric}_std"].to_numpy(),
            marker="o",
            capsize=4,
            linewidth=1.8,
            color=COLORS[window],
            label=LABELS[window],
        )

    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_xticks(sorted(summary[x].unique()))
    if name == "s2_goodput_vs_delay":
     ax.set_yscale("log")
     ax.set_ylabel("Goodput (Mbps, log scale)")
    else:
     ax.set_ylim(bottom=0)
    ax.grid(alpha=0.25)
    ax.legend()

    fig.supxlabel(
        "Mean ± sample standard deviation; at least 3 runs per point.",
        fontsize=9,
    )

    save_figure(fig, folder, name)


def main():
    parser = argparse.ArgumentParser(
        description="Validate, summarise and plot S1-S3 results."
    )
    parser.add_argument(
        "--results",
        type=Path,
        default=ROOT / "results",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=ROOT / "results" / "plots",
    )
    args = parser.parse_args()

    datasets = {}
    summaries = {}
    main_results = {}

    # Validate every input before creating output files.
    for scenario in ("s1", "s2", "s3"):
        data = load_results(args.results, scenario)
        summary = make_summary(data)

        datasets[scenario] = data
        summaries[scenario] = summary
        main_results[scenario] = select_main_results(
            summary, scenario
        )

    args.out.mkdir(parents=True, exist_ok=True)

    plt.rcParams.update({
        "font.size": 11,
        "axes.spines.top": False,
        "axes.spines.right": False,
    })

    for scenario, summary in summaries.items():
        summary.to_csv(
            args.out / f"{scenario}_summary.csv",
            index=False,
        )

    # Include every S1 size in the correctness table,
    # including the two single-run 64 KiB configurations.
    correctness = (
        datasets["s1"]
        .groupby(CONFIG, dropna=False)
        .agg(
            runs=("hash_ok", "size"),
            matching_hashes=("hash_ok", "sum"),
        )
        .reset_index()
    )
    correctness["success_pct"] = (
        correctness["matching_hashes"]
        / correctness["runs"]
        * 100
    )
    correctness.to_csv(
        args.out / "s1_correctness.csv",
        index=False,
    )

    plot_s1(main_results["s1"], args.out)

    plot_lines(
        main_results["s2"],
        x="delay_ms",
        metric="goodput_mbps",
        title="S2: Goodput versus delay (1 MiB, 0% loss)",
        xlabel="Configured one-way delay (ms)",
        ylabel="Goodput (Mbps)",
        name="s2_goodput_vs_delay",
        folder=args.out,
    )

    plot_lines(
        main_results["s3"],
        x="loss_pct",
        metric="goodput_mbps",
        title="S3: Goodput versus loss (1 MiB, 50 ms one-way delay)",
        xlabel="Configured packet loss per direction (%)",
        ylabel="Goodput (Mbps)",
        name="s3_goodput_vs_loss",
        folder=args.out,
    )

    plot_lines(
        main_results["s3"],
        x="loss_pct",
        metric="retrans_ratio_pct",
        title="S3: Retransmissions versus loss (1 MiB, 50 ms delay)",
        xlabel="Configured packet loss per direction (%)",
        ylabel="DATA retransmission ratio (%)",
        name="s3_retransmissions_vs_loss",
        folder=args.out,
    )

    print(f"\nOutputs saved in: {args.out.resolve()}")
    print(
        "S1 non-standard sizes remain in the summary and "
        "correctness tables but are excluded from its main plot."
    )
    print(
        "Configured delay is used on the S2 axis. "
        "Measured RTT is retained in the summary CSVs."
    )


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError) as error:
        raise SystemExit(f"Cannot generate plots: {error}")