"""Statistical analysis and publication artifact generation."""

import csv
import statistics
from pathlib import Path
from typing import Dict, Iterable, List


def descriptive_statistics(values: Iterable[float]) -> Dict:
    """Return dissertation-ready descriptive statistics."""
    sample = [float(value) for value in values if value is not None]
    if not sample:
        return {
            "n": 0,
            "mean": None,
            "median": None,
            "standard_deviation": None,
            "minimum": None,
            "maximum": None,
        }

    return {
        "n": len(sample),
        "mean": round(statistics.fmean(sample), 4),
        "median": round(statistics.median(sample), 4),
        "standard_deviation": round(statistics.stdev(sample), 4)
        if len(sample) > 1
        else 0.0,
        "minimum": round(min(sample), 4),
        "maximum": round(max(sample), 4),
    }


def mann_whitney_analysis(
    treatment: Iterable[float],
    control: Iterable[float],
    metric: str,
    alpha: float = 0.05,
) -> Dict:
    """Run a two-sided Mann-Whitney U test and rank-biserial effect size."""
    treatment_values = [float(value) for value in treatment if value is not None]
    control_values = [float(value) for value in control if value is not None]
    if not treatment_values or not control_values:
        return {
            "metric": metric,
            "computed": False,
            "reason": "Both treatment and control samples are required.",
        }

    from scipy.stats import mannwhitneyu

    result = mannwhitneyu(
        treatment_values,
        control_values,
        alternative="two-sided",
        method="auto",
    )
    denominator = len(treatment_values) * len(control_values)
    rank_biserial = (2 * float(result.statistic) / denominator) - 1
    magnitude = "large" if abs(rank_biserial) >= 0.5 else (
        "medium" if abs(rank_biserial) >= 0.3 else (
            "small" if abs(rank_biserial) >= 0.1 else "negligible"
        )
    )

    return {
        "metric": metric,
        "computed": True,
        "alternative": "two-sided",
        "treatment_n": len(treatment_values),
        "control_n": len(control_values),
        "u_statistic": round(float(result.statistic), 4),
        "p_value": float(result.pvalue),
        "alpha": alpha,
        "statistically_significant": bool(result.pvalue < alpha),
        "rank_biserial_correlation": round(rank_biserial, 4),
        "effect_size_magnitude": magnitude,
    }


def export_trial_csv(results: Dict, destination: Path) -> str:
    """Export raw trial-level observations for independent verification."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "condition",
        "trial",
        "execution_time_ms",
        "detection_latency_ms",
        "completeness_percent",
        "total_alerts",
        "critical_alerts",
        "evidence_preserved",
    ]
    rows: List[Dict] = []

    for condition in ("stealth_trials", "noisy_trials"):
        for trial in results.get(condition, []):
            detection = trial.get("detection", {})
            rows.append(
                {
                    "condition": trial.get("mode"),
                    "trial": trial.get("trial"),
                    "execution_time_ms": round(
                        trial.get("agent_execution_time_seconds", 0) * 1000, 4
                    ),
                    "detection_latency_ms": detection.get(
                        "first_detection_latency_ms"
                    ),
                    "completeness_percent": detection.get(
                        "completeness_percent"
                    ),
                    "total_alerts": detection.get("total_alerts"),
                    "critical_alerts": detection.get("critical_alerts"),
                    "evidence_preserved": trial.get("evidence_preserved"),
                }
            )

    for trial in results.get("human_baseline_trials", []):
        rows.append(
            {
                "condition": "human_baseline",
                "trial": trial.get("trial"),
                "execution_time_ms": round(
                    trial.get("planned_duration_seconds", 0) * 1000, 4
                ),
            }
        )

    for trial in results.get("control_condition", {}).get("trials", []):
        rows.append(
            {
                "condition": "wazuh_periodic_fim_control",
                "trial": trial.get("trial"),
                "completeness_percent": trial.get("completeness_percent"),
                "total_alerts": trial.get("total_alerts"),
            }
        )

    with destination.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return str(destination)


def generate_charts(results: Dict, output_dir: Path) -> List[str]:
    """Generate PNG figures corresponding to the methodology metrics."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    output_dir.mkdir(parents=True, exist_ok=True)
    artifacts = []

    latency_groups = []
    latency_labels = []
    for key, label in (("stealth_trials", "Stealth"), ("noisy_trials", "Noisy")):
        values = [
            trial["detection"]["first_detection_latency_ms"]
            for trial in results.get(key, [])
            if trial["detection"].get("first_detection_latency_ms") is not None
        ]
        if values:
            latency_groups.append(values)
            latency_labels.append(label)
    if latency_groups:
        figure, axis = plt.subplots(figsize=(7, 4.5))
        try:
            axis.boxplot(latency_groups, tick_labels=latency_labels)
        except TypeError:
            # Matplotlib < 3.9 uses labels=
            axis.boxplot(latency_groups, labels=latency_labels)
        axis.set_title("AntiGravity Shield Detection Latency")
        axis.set_ylabel("Latency (milliseconds)")
        axis.grid(axis="y", alpha=0.25)
        path = output_dir / "detection_latency_boxplot.png"
        figure.tight_layout()
        figure.savefig(path, dpi=300)
        plt.close(figure)
        artifacts.append(str(path))

    control_values = [
        trial["completeness_percent"]
        for trial in results.get("control_condition", {}).get("trials", [])
    ]
    stealth_values = [
        trial["detection"]["completeness_percent"]
        for trial in results.get("stealth_trials", [])
    ]
    noisy_values = [
        trial["detection"]["completeness_percent"]
        for trial in results.get("noisy_trials", [])
    ]
    groups = [control_values, stealth_values, noisy_values]
    labels = ["Wazuh control", "Shield stealth", "Shield noisy"]
    if any(groups):
        means = [statistics.fmean(group) if group else 0 for group in groups]
        figure, axis = plt.subplots(figsize=(8, 4.5))
        axis.bar(labels, means, color=["#777777", "#1f6f8b", "#4aa96c"])
        axis.set_ylim(0, 105)
        axis.set_ylabel("Mean detection completeness (%)")
        axis.set_title("Detection Completeness by Condition")
        axis.grid(axis="y", alpha=0.25)
        path = output_dir / "detection_completeness_bar.png"
        figure.tight_layout()
        figure.savefig(path, dpi=300)
        plt.close(figure)
        artifacts.append(str(path))

    agent_times = [
        trial.get("agent_execution_time_seconds", 0) * 1000
        for trial in results.get("stealth_trials", [])
    ]
    human_times = [
        trial.get("planned_duration_seconds", 0) * 1000
        for trial in results.get("human_baseline_trials", [])
    ]
    if agent_times and human_times:
        figure, axis = plt.subplots(figsize=(7, 4.5))
        axis.bar(
            ["Autonomous agent", "Human baseline"],
            [statistics.median(agent_times), statistics.median(human_times)],
            color=["#b23a48", "#345995"],
        )
        axis.set_yscale("log")
        axis.set_ylabel("Median execution time (milliseconds, log scale)")
        axis.set_title("Agent and Human-Speed Execution Comparison")
        axis.grid(axis="y", alpha=0.25)
        path = output_dir / "execution_time_comparison.png"
        figure.tight_layout()
        figure.savefig(path, dpi=300)
        plt.close(figure)
        artifacts.append(str(path))

    return artifacts
