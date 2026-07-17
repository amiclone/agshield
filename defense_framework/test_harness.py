"""
AntiGravity Shield — Head-to-Head Test Harness
===============================================
Runs the attack agent and defense shield simultaneously,
measuring detection latency, completeness, and false positive rate.

This produces the empirical data for the defense paper.
"""

import os
import sys
import time
import json
import shutil
import subprocess
import threading
from datetime import datetime

# Add paths
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "agent_package"))

from shield_controller import ShieldController


BOLD = "\033[1m"
RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"


class TestHarness:
    """
    Runs controlled experiments: attack agent vs defense shield.
    Measures detection performance across multiple trials.
    """

    def __init__(self, workspace_dir=None, reports_dir=None):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.agent_dir = os.path.join(self.base_dir, "..", "agent_package")
        self.workspace_dir = workspace_dir or os.path.join(self.base_dir, "test_workspace")
        self.reports_dir = reports_dir or os.path.join(self.base_dir, "reports")

        os.makedirs(self.reports_dir, exist_ok=True)

    def _setup_workspace(self):
        """Create a clean test workspace."""
        if os.path.exists(self.workspace_dir):
            shutil.rmtree(self.workspace_dir)
        os.makedirs(self.workspace_dir)

        # Copy agent scripts to workspace
        for filename in ["agent_controller.py", "timestomper.py", "data_wiper.py", "log_cleaner.py"]:
            src = os.path.join(self.agent_dir, filename)
            dst = os.path.join(self.workspace_dir, filename)
            if os.path.exists(src):
                shutil.copy2(src, dst)

    def _teardown_workspace(self):
        """Clean up the test workspace."""
        if os.path.exists(self.workspace_dir):
            shutil.rmtree(self.workspace_dir, ignore_errors=True)

    def run_trial(self, trial_num, mode="stealth", delay=0):
        """
        Run a single trial: start shield, then run attack, measure results.

        Args:
            trial_num: Trial number for reporting
            mode: "stealth" or "noisy"
            delay: Delay before agent cleanup (seconds)

        Returns:
            dict: Trial results
        """
        print(f"\n  {'─'*50}")
        print(f"  {BOLD}Trial {trial_num}{RESET} — Mode: {YELLOW}{mode.upper()}{RESET}")
        print(f"  {'─'*50}\n")

        # Setup clean workspace
        self._setup_workspace()

        # Start shield monitoring the workspace
        shield = ShieldController(
            watch_paths=[self.workspace_dir],
            reports_dir=self.reports_dir,
        )

        # Start shield (no canaries in test mode for cleaner results)
        shield.start(deploy_canaries=True, canary_count=2)

        # Give the monitor a moment to initialize inotify watches
        time.sleep(0.5)

        # Record attack start time
        attack_start_perf = time.perf_counter()
        attack_start_wall = time.time()

        # Run the attack agent in the workspace
        print(f"\n  {RED}{BOLD}[ATTACK]{RESET} Launching agent in {mode} mode...")

        agent_script = os.path.join(self.workspace_dir, "agent_controller.py")
        cmd = [sys.executable, agent_script]
        if mode == "noisy":
            cmd.append("--noisy")
        if delay > 0:
            cmd.extend(["--delay", str(delay)])

        try:
            result = subprocess.run(
                cmd,
                cwd=self.workspace_dir,
                capture_output=True,
                text=True,
                timeout=30,
            )
            agent_stdout = result.stdout
            agent_stderr = result.stderr
        except subprocess.TimeoutExpired:
            agent_stdout = "TIMEOUT"
            agent_stderr = "Agent timed out after 30s"

        attack_end_perf = time.perf_counter()
        attack_duration = attack_end_perf - attack_start_perf

        print(f"  {RED}[ATTACK]{RESET} Agent completed in {attack_duration:.4f}s")

        # Give time for inotify events from the cleanup phase to propagate
        time.sleep(2.0)

        # Stop shield and get report
        shield_report = shield.stop()

        # Parse agent's own report
        agent_report_path = os.path.join(self.workspace_dir, "operation_report.json")
        agent_report = {}
        if os.path.exists(agent_report_path):
            with open(agent_report_path, "r") as f:
                agent_report = json.load(f)

        # Analyze detection results
        trial_result = self._analyze_trial(
            trial_num, mode, delay,
            attack_start_wall, attack_duration,
            shield_report, agent_report
        )

        return trial_result

    def _analyze_trial(self, trial_num, mode, delay,
                       attack_start, attack_duration,
                       shield_report, agent_report):
        """Analyze a trial's results for detection metrics."""

        alerts = shield_report.get("alerts", [])

        # Classify detections
        detected_timestomp = any(
            a.get("event_type") in ("TIMESTAMP_RETRODATED", "CTIME_MTIME_DIVERGENCE", "TIMESTAMP_IMPOSSIBLE")
            for a in alerts
        )
        detected_wiper = any(
            a.get("event_type") in ("WIPER_SIGNATURE",) or
            (a.get("event_type") == "FILE_MODIFIED" and "overwrite" in a.get("details", {}).get("reason", "").lower()) or
            (a.get("event_type") == "FILE_MOVED" and "random" in a.get("details", {}).get("reason", "").lower())
            for a in alerts
        )
        detected_deletion = any(
            a.get("event_type") in ("FILE_DELETED", "MASS_DELETION", "EPHEMERAL_FILE")
            for a in alerts
        )
        detected_burst = any(
            a.get("event_type") == "OPERATION_BURST"
            for a in alerts
        )
        detected_canary = any(
            a.get("module") == "canary_deployer" or
            (a.get("details", {}).get("reason", "") and "CANARY" in a.get("details", {}).get("reason", ""))
            for a in alerts
        )

        # Calculate detection latencies
        critical_alerts = [a for a in alerts if a.get("severity") == "CRITICAL"]
        warning_alerts = [a for a in alerts if a.get("severity") == "WARNING"]

        first_detection_time = None
        if critical_alerts:
            first_detection_time = min(
                a.get("detection_wall_time", float("inf")) for a in critical_alerts
            )
        elif warning_alerts:
            first_detection_time = min(
                a.get("detection_wall_time", float("inf")) for a in warning_alerts
            )

        first_detection_latency = None
        if first_detection_time:
            first_detection_latency = first_detection_time - attack_start

        # Agent execution time from its own report
        agent_exec_time = agent_report.get("execution_time_seconds", attack_duration)

        # Detection completeness score
        if mode == "stealth":
            expected_detections = ["timestomp", "wipe", "deletion", "burst"]
            actual_detections = []
            if detected_timestomp:
                actual_detections.append("timestomp")
            if detected_wiper:
                actual_detections.append("wipe")
            if detected_deletion:
                actual_detections.append("deletion")
            if detected_burst:
                actual_detections.append("burst")
            completeness = len(actual_detections) / len(expected_detections) * 100
        else:
            # In noisy mode, we mainly expect deletion
            expected_detections = ["deletion"]
            actual_detections = []
            if detected_deletion:
                actual_detections.append("deletion")
            completeness = len(actual_detections) / len(expected_detections) * 100

        result = {
            "trial": trial_num,
            "mode": mode,
            "delay_seconds": delay,
            "agent_execution_time_seconds": agent_exec_time,
            "attack_total_duration_seconds": round(attack_duration, 4),
            "detection": {
                "total_alerts": len(alerts),
                "critical_alerts": len(critical_alerts),
                "warning_alerts": len(warning_alerts),
                "first_detection_latency_seconds": round(first_detection_latency, 4) if first_detection_latency else None,
                "first_detection_latency_ms": round(first_detection_latency * 1000, 2) if first_detection_latency else None,
                "detected_timestomp": detected_timestomp,
                "detected_wiper": detected_wiper,
                "detected_deletion": detected_deletion,
                "detected_burst": detected_burst,
                "detected_canary_tampering": detected_canary,
                "completeness_percent": completeness,
                "expected_detections": expected_detections,
                "actual_detections": actual_detections,
            },
            "shield_report_path": shield_report.get("report_path"),
        }

        # Print trial summary
        print(f"\n  {CYAN}{'─'*50}{RESET}")
        print(f"  {BOLD}Trial {trial_num} Results:{RESET}")
        print(f"    Agent execution time:      {agent_exec_time:.4f}s")
        print(f"    Total alerts fired:         {len(alerts)}")
        print(f"    Critical alerts:            {len(critical_alerts)}")
        if first_detection_latency:
            print(f"    First detection latency:    {first_detection_latency*1000:.2f}ms")
        print(f"    Detection completeness:     {completeness:.0f}%")
        print(f"    Detections: {', '.join(actual_detections) if actual_detections else 'NONE'}")
        print(f"  {CYAN}{'─'*50}{RESET}")

        return result

    def run_false_positive_test(self, duration=10):
        """
        Run the shield with NO attack for a period to measure false positive rate.

        Args:
            duration: How long to monitor without any attack (seconds)

        Returns:
            dict: False positive test results
        """
        print(f"\n  {'='*50}")
        print(f"  {BOLD}FALSE POSITIVE TEST{RESET} — {duration}s silent monitoring")
        print(f"  {'='*50}\n")

        self._setup_workspace()

        # Create some normal-looking files
        for i in range(5):
            with open(os.path.join(self.workspace_dir, f"normal_file_{i}.txt"), "w") as f:
                f.write(f"Normal file content {i}\n")

        # Use a fresh reports dir to avoid stale canary registries from attack trials
        fp_reports = os.path.join(self.reports_dir, "fp_test")
        if os.path.exists(fp_reports):
            shutil.rmtree(fp_reports)
        os.makedirs(fp_reports, exist_ok=True)

        shield = ShieldController(
            watch_paths=[self.workspace_dir],
            reports_dir=fp_reports,
        )
        shield.start(deploy_canaries=False)

        # Wait silently
        print(f"  Monitoring for {duration}s with no attack...")
        time.sleep(duration)

        shield_report = shield.stop()

        # Count unexpected alerts (exclude initial baseline/setup events)
        alerts = shield_report.get("alerts", [])
        false_positives = [a for a in alerts if a.get("severity") in ("WARNING", "CRITICAL")]

        result = {
            "test": "false_positive",
            "duration_seconds": duration,
            "total_alerts": len(alerts),
            "false_positives": len(false_positives),
            "false_positive_rate": len(false_positives) / max(duration, 1),
        }

        status = f"{GREEN}PASS{RESET}" if len(false_positives) == 0 else f"{RED}FAIL{RESET}"
        print(f"\n  False positive test: {status}")
        print(f"  Unexpected alerts: {len(false_positives)}")

        return result

    def run_experiment(self, stealth_trials=5, noisy_trials=3, fp_duration=10):
        """
        Run a complete experiment suite.

        Args:
            stealth_trials: Number of stealth mode trials
            noisy_trials: Number of noisy mode trials
            fp_duration: Duration of false positive test

        Returns:
            dict: Complete experiment results
        """
        experiment_start = time.time()

        print(f"\n{'='*60}")
        print(f"  🔬 {BOLD}ANTIGRAVITY SHIELD — EXPERIMENTAL EVALUATION{RESET}")
        print(f"{'='*60}")
        print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Stealth trials: {stealth_trials}")
        print(f"  Noisy trials:   {noisy_trials}")
        print(f"  FP test:        {fp_duration}s")
        print(f"{'='*60}")

        results = {
            "experiment_date": datetime.now().isoformat(),
            "stealth_trials": [],
            "noisy_trials": [],
            "false_positive_test": None,
        }

        # Stealth mode trials
        for i in range(1, stealth_trials + 1):
            trial = self.run_trial(i, mode="stealth")
            results["stealth_trials"].append(trial)
            time.sleep(1)  # Brief pause between trials

        # Noisy mode trials
        for i in range(1, noisy_trials + 1):
            trial = self.run_trial(i, mode="noisy")
            results["noisy_trials"].append(trial)
            time.sleep(1)

        # False positive test
        results["false_positive_test"] = self.run_false_positive_test(fp_duration)

        # Aggregate statistics
        results["summary"] = self._compute_summary(results)

        # Save experiment results
        results_path = os.path.join(self.reports_dir, f"experiment_{int(experiment_start)}.json")
        with open(results_path, "w") as f:
            json.dump(results, f, indent=2, default=str)

        # Print final summary
        self._print_summary(results)

        print(f"\n  📄 Full results saved to: {results_path}")

        # Cleanup
        self._teardown_workspace()

        return results

    def _compute_summary(self, results):
        """Compute aggregate statistics across all trials."""
        stealth = results["stealth_trials"]
        noisy = results["noisy_trials"]

        def avg(lst):
            return sum(lst) / len(lst) if lst else 0

        stealth_exec_times = [t["agent_execution_time_seconds"] for t in stealth]
        stealth_latencies = [
            t["detection"]["first_detection_latency_ms"]
            for t in stealth if t["detection"]["first_detection_latency_ms"] is not None
        ]
        stealth_completeness = [t["detection"]["completeness_percent"] for t in stealth]

        noisy_latencies = [
            t["detection"]["first_detection_latency_ms"]
            for t in noisy if t["detection"]["first_detection_latency_ms"] is not None
        ]

        summary = {
            "stealth_mode": {
                "trials": len(stealth),
                "avg_agent_execution_ms": round(avg(stealth_exec_times) * 1000, 2),
                "avg_detection_latency_ms": round(avg(stealth_latencies), 2) if stealth_latencies else None,
                "min_detection_latency_ms": round(min(stealth_latencies), 2) if stealth_latencies else None,
                "max_detection_latency_ms": round(max(stealth_latencies), 2) if stealth_latencies else None,
                "avg_completeness_percent": round(avg(stealth_completeness), 1),
                "detection_rate_timestomp": sum(1 for t in stealth if t["detection"]["detected_timestomp"]) / len(stealth) * 100 if stealth else 0,
                "detection_rate_wiper": sum(1 for t in stealth if t["detection"]["detected_wiper"]) / len(stealth) * 100 if stealth else 0,
                "detection_rate_deletion": sum(1 for t in stealth if t["detection"]["detected_deletion"]) / len(stealth) * 100 if stealth else 0,
                "detection_rate_burst": sum(1 for t in stealth if t["detection"]["detected_burst"]) / len(stealth) * 100 if stealth else 0,
            },
            "noisy_mode": {
                "trials": len(noisy),
                "avg_detection_latency_ms": round(avg(noisy_latencies), 2) if noisy_latencies else None,
                "detection_rate": sum(1 for t in noisy if t["detection"]["completeness_percent"] > 0) / len(noisy) * 100 if noisy else 0,
            },
            "false_positive_rate": results["false_positive_test"]["false_positive_rate"] if results["false_positive_test"] else None,
        }

        return summary

    def _print_summary(self, results):
        """Print a formatted summary table."""
        summary = results["summary"]
        stealth = summary["stealth_mode"]
        noisy = summary["noisy_mode"]
        fp = results["false_positive_test"]

        print(f"\n{'='*60}")
        print(f"  📊 {BOLD}EXPERIMENT SUMMARY{RESET}")
        print(f"{'='*60}")

        print(f"\n  {BOLD}Stealth Mode (Agent with Anti-Forensics){RESET}")
        print(f"  {'─'*45}")
        print(f"  Trials:                    {stealth['trials']}")
        print(f"  Avg agent execution:       {stealth['avg_agent_execution_ms']:.2f}ms")
        if stealth['avg_detection_latency_ms']:
            print(f"  Avg detection latency:     {stealth['avg_detection_latency_ms']:.2f}ms")
            print(f"  Min detection latency:     {stealth['min_detection_latency_ms']:.2f}ms")
            print(f"  Max detection latency:     {stealth['max_detection_latency_ms']:.2f}ms")
        print(f"  Avg completeness:          {stealth['avg_completeness_percent']:.0f}%")
        print(f"  Timestomp detection rate:  {stealth['detection_rate_timestomp']:.0f}%")
        print(f"  Wiper detection rate:      {stealth['detection_rate_wiper']:.0f}%")
        print(f"  Deletion detection rate:   {stealth['detection_rate_deletion']:.0f}%")
        print(f"  Burst detection rate:      {stealth['detection_rate_burst']:.0f}%")

        print(f"\n  {BOLD}Noisy Mode (Agent without Anti-Forensics){RESET}")
        print(f"  {'─'*45}")
        print(f"  Trials:                    {noisy['trials']}")
        if noisy['avg_detection_latency_ms']:
            print(f"  Avg detection latency:     {noisy['avg_detection_latency_ms']:.2f}ms")
        print(f"  Detection rate:            {noisy['detection_rate']:.0f}%")

        print(f"\n  {BOLD}False Positive Test{RESET}")
        print(f"  {'─'*45}")
        if fp:
            print(f"  Duration:                  {fp['duration_seconds']}s")
            print(f"  False positives:           {fp['false_positives']}")
            status = f"{GREEN}ZERO{RESET}" if fp['false_positives'] == 0 else f"{RED}{fp['false_positives']}{RESET}"
            print(f"  Rate:                      {status}")

        # Key finding
        if stealth['avg_detection_latency_ms'] and stealth['avg_agent_execution_ms']:
            print(f"\n  {BOLD}🔑 KEY FINDING:{RESET}")
            if stealth['avg_detection_latency_ms'] < stealth['avg_agent_execution_ms']:
                print(f"  Shield detected the agent FASTER than the agent could complete!")
                print(f"  Detection: {stealth['avg_detection_latency_ms']:.0f}ms vs Agent: {stealth['avg_agent_execution_ms']:.0f}ms")
            else:
                print(f"  Shield detected the agent within {stealth['avg_detection_latency_ms']:.0f}ms")
                print(f"  (vs Wazuh FIM which detected NOTHING in stealth mode)")

        print(f"\n{'='*60}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AntiGravity Shield — Test Harness")
    parser.add_argument("--stealth-trials", type=int, default=5,
                        help="Number of stealth mode trials (default: 5)")
    parser.add_argument("--noisy-trials", type=int, default=3,
                        help="Number of noisy mode trials (default: 3)")
    parser.add_argument("--fp-duration", type=int, default=10,
                        help="False positive test duration in seconds (default: 10)")
    parser.add_argument("--single", choices=["stealth", "noisy"],
                        help="Run a single trial instead of full experiment")

    args = parser.parse_args()

    harness = TestHarness()

    if args.single:
        result = harness.run_trial(1, mode=args.single)
        print(json.dumps(result, indent=2, default=str))
    else:
        harness.run_experiment(
            stealth_trials=args.stealth_trials,
            noisy_trials=args.noisy_trials,
            fp_duration=args.fp_duration,
        )
