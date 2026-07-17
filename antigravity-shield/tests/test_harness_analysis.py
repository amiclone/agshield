"""Correctness tests for experiment timing and control metadata."""

from agshield.test_harness import ExperimentHarness


def test_latency_uses_first_anti_forensic_action_not_process_launch(tmp_path):
    harness = ExperimentHarness(
        agent_dir=str(tmp_path),
        workspace_dir=str(tmp_path / "workspace"),
        reports_dir=str(tmp_path / "reports"),
    )
    shield_report = {
        "log_integrity": {"valid": True},
        "report_path": "report.json",
        "alerts": [
            {
                "severity": "CRITICAL",
                "event_type": "OPERATION_BURST",
                "detection_perf_time": 90.0,
                "details": {},
            },
            {
                "severity": "WARNING",
                "event_type": "FILE_DELETED",
                "detection_perf_time": 100.025,
                "details": {},
            },
        ],
    }
    agent_report = {
        "cleanup_start_perf_time": 100.0,
        "execution_time_seconds": 0.1,
    }

    result = harness._analyze_trial(
        1,
        "noisy",
        0,
        80.0,
        2.0,
        shield_report,
        agent_report,
    )

    assert result["detection"]["first_detection_latency_ms"] == 25.0
    assert result["detection"]["latency_origin"] == "first_anti_forensic_action"
    assert result["evidence_preserved"] is True


def test_historical_control_is_explicitly_labelled():
    control = ExperimentHarness._historical_control(5)

    assert control["design"] == "historical control"
    assert len(control["trials"]) == 5
    assert all(trial["total_alerts"] == 0 for trial in control["trials"])
    assert "undefined" in control["limitations"]
