"""Tests for statistical analysis and research artifact export."""

import csv

from agshield.analysis import (
    descriptive_statistics,
    export_trial_csv,
    mann_whitney_analysis,
)


def test_descriptive_statistics_reports_required_metrics():
    result = descriptive_statistics([10, 20, 30])

    assert result == {
        "n": 3,
        "mean": 20.0,
        "median": 20.0,
        "standard_deviation": 10.0,
        "minimum": 10.0,
        "maximum": 30.0,
    }


def test_mann_whitney_reports_effect_size():
    result = mann_whitney_analysis(
        [100.0] * 30,
        [0.0] * 5,
        metric="detection_completeness_percent",
    )

    assert result["computed"] is True
    assert result["statistically_significant"] is True
    assert result["rank_biserial_correlation"] == 1.0
    assert result["effect_size_magnitude"] == "large"


def test_mann_whitney_requires_both_samples():
    result = mann_whitney_analysis([], [0], metric="completeness")

    assert result["computed"] is False


def test_trial_csv_contains_raw_conditions(tmp_path):
    results = {
        "stealth_trials": [
            {
                "trial": 1,
                "mode": "stealth",
                "agent_execution_time_seconds": 0.1,
                "evidence_preserved": True,
                "detection": {
                    "first_detection_latency_ms": 20,
                    "completeness_percent": 100,
                    "total_alerts": 4,
                    "critical_alerts": 2,
                },
            }
        ],
        "noisy_trials": [],
        "human_baseline_trials": [
            {"trial": 1, "planned_duration_seconds": 12.0}
        ],
        "control_condition": {
            "trials": [
                {"trial": 1, "completeness_percent": 0, "total_alerts": 0}
            ]
        },
    }
    destination = tmp_path / "trial_data.csv"

    export_trial_csv(results, destination)

    with destination.open(encoding="utf-8") as csv_file:
        rows = list(csv.DictReader(csv_file))
    assert [row["condition"] for row in rows] == [
        "stealth",
        "human_baseline",
        "wazuh_periodic_fim_control",
    ]
