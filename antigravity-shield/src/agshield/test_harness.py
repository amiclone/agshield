"""
AntiGravity Shield — Test Harness
==================================
Runs the attack agent and defense shield simultaneously,
measuring detection latency, completeness, and false positive rate.

This produces the empirical data for the defense paper.
"""

import os
import sys
import time
import json
import shutil
import subprocess  # nosec B404 - used only to launch the controlled experimental agent
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from agshield import __version__
from agshield.analysis import (
    descriptive_statistics,
    export_trial_csv,
    generate_charts,
    mann_whitney_analysis,
)
from agshield.config import Config
from agshield.detection.engine import DetectionEngine
from agshield.human_baseline import run_human_baseline
from agshield.utils.platform import get_default_data_dir


BOLD = "\033[1m"
RESET = "\033[0m"
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"


class ExperimentHarness:
    """
    Runs controlled experiments: attack agent vs defense shield.
    Measures detection performance across multiple trials.
    """

    def __init__(
        self,
        workspace_dir: Optional[str] = None,
        reports_dir: Optional[str] = None,
        agent_dir: Optional[str] = None,
    ):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        # Look for agent_package in multiple locations:
        # 1. Bundled in the executable (PyInstaller sets sys._MEIPASS)
        # 2. Relative to the source tree
        # 3. System installation path
        # 4. User-specified AGENT_PACKAGE_PATH env var
        self.agent_dir = os.path.abspath(agent_dir) if agent_dir else None

        # Check for bundled agent (PyInstaller)
        if hasattr(sys, '_MEIPASS'):
            bundled = os.path.join(sys._MEIPASS, 'agent_package')
            if os.path.exists(bundled):
                self.agent_dir = bundled

        # Check env var
        if not self.agent_dir:
            env_path = os.environ.get('AGSHIELD_AGENT_PATH')
            if env_path and os.path.exists(env_path):
                self.agent_dir = env_path

        # Check system install paths
        if not self.agent_dir:
            # User-local install path
            user_path = os.path.expanduser('~/.local/share/agshield/agent_package')
            candidates = [
                user_path,
                '/usr/local/share/agshield/agent_package',
                '/usr/share/agshield/agent_package',
                '/opt/agshield/agent_package',
            ]
            # Also check Windows-specific paths
            import sys as _sys
            if _sys.platform == 'win32':
                appdata = os.environ.get('APPDATA')
                if appdata:
                    candidates.append(os.path.join(appdata, 'antigravity', 'agent_package'))
                candidates.append('C:\\Program Files\\antigravity-shield\\agent_package')
                candidates.append('C:\\ProgramData\\antigravity\\agent_package')

            for path in candidates:
                if os.path.exists(path):
                    self.agent_dir = path
                    break

        # Check relative to project tree
        if not self.agent_dir:
            candidates = [
                os.path.join(self.base_dir, "..", "..", "..", "agent_package"),
                os.path.join(self.base_dir, "..", "agent_package"),
                os.path.join(os.path.dirname(self.base_dir), "..", "agent_package"),
            ]
            for path in candidates:
                if os.path.exists(path):
                    self.agent_dir = path
                    break

        default_workspace = Path(tempfile.gettempdir()) / "agshield-experiment"
        default_reports = get_default_data_dir() / "experiments"
        self.workspace_dir = os.path.abspath(workspace_dir or str(default_workspace))
        self.reports_dir = os.path.abspath(reports_dir or str(default_reports))
        self._active_experiment_dir: Optional[str] = None

        os.makedirs(self.reports_dir, exist_ok=True)

    def _setup_workspace(self) -> None:
        """Create a clean test workspace."""
        if not self.agent_dir:
            raise FileNotFoundError(
                "agent_package not found. Please either:\n"
                "Provide the controlled agent separately with --agent-path or "
                "the AGSHIELD_AGENT_PATH environment variable. The defensive "
                "package intentionally does not distribute the offensive agent."
            )

        if os.path.exists(self.workspace_dir):
            shutil.rmtree(self.workspace_dir)
        os.makedirs(self.workspace_dir)

        # Copy agent scripts to workspace
        required_files = [
            "agent_controller.py",
            "timestomper.py",
            "data_wiper.py",
            "log_cleaner.py",
        ]
        missing = [
            filename
            for filename in required_files
            if not os.path.isfile(os.path.join(self.agent_dir, filename))
        ]
        if missing:
            raise FileNotFoundError(
                f"Agent package is incomplete; missing: {', '.join(missing)}"
            )

        for filename in required_files:
            src = os.path.join(self.agent_dir, filename)
            dst = os.path.join(self.workspace_dir, filename)
            shutil.copy2(src, dst)

    def _python_executable(self) -> str:
        """Resolve Python for the separately supplied experimental agent."""
        if not getattr(sys, "frozen", False):
            return sys.executable
        executable = shutil.which("python3") or shutil.which("python")
        if not executable:
            raise RuntimeError(
                "Experiment mode requires Python for the external controlled agent. "
                "The Shield monitoring executable itself remains standalone."
            )
        return executable

    def _trial_reports_dir(self, condition: str, trial_num: int) -> str:
        """Return an isolated report directory to prevent cross-trial state."""
        root = self._active_experiment_dir or self.reports_dir
        path = os.path.join(root, "trials", f"{condition}_{trial_num:03d}")
        if os.path.exists(path):
            shutil.rmtree(path)
        os.makedirs(path, exist_ok=True)
        return path

    def _teardown_workspace(self) -> None:
        """Clean up the test workspace."""
        if os.path.exists(self.workspace_dir):
            shutil.rmtree(self.workspace_dir, ignore_errors=True)

    def run_trial(self, trial_num: int, mode: str = "stealth", delay: float = 0) -> Dict:
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

        trial_reports_dir = self._trial_reports_dir(mode, trial_num)

        # Create a temporary config for this isolated trial
        config = Config()
        config._config.setdefault("general", {})
        config._config["general"]["watch_paths"] = [self.workspace_dir]
        config._config["general"]["reports_dir"] = trial_reports_dir
        config._config["general"]["database_path"] = os.path.join(
            trial_reports_dir, "baseline.db"
        )
        config._config["general"]["log_file"] = os.path.join(
            trial_reports_dir, "shield.log"
        )

        # Start shield monitoring the workspace
        shield = DetectionEngine(config)

        # Start shield (no canaries in test mode for cleaner results)
        shield.start(deploy_canaries=True, canary_count=2)

        # Give the monitor a moment to initialize inotify watches
        time.sleep(0.5)

        # Record process timing. Detection latency is recalculated from the
        # agent's instrumented cleanup boundary, not from process launch.
        attack_start_perf = time.perf_counter()

        # Run the attack agent in the workspace
        print(f"\n  {RED}{BOLD}[ATTACK]{RESET} Launching agent in {mode} mode...")

        agent_script = os.path.join(self.workspace_dir, "agent_controller.py")

        cmd = [self._python_executable(), agent_script]
        if mode == "noisy":
            cmd.append("--noisy")
        if delay > 0:
            cmd.extend(["--delay", str(delay)])

        try:
            # shell=False and an absolute Python path keep this controlled and explicit.
            result = subprocess.run(  # nosec B603
                cmd,
                cwd=self.workspace_dir,
                capture_output=True,
                text=True,
                timeout=30,
                shell=False,
            )
            agent_stdout = result.stdout
            agent_stderr = result.stderr
            if result.returncode != 0:
                raise RuntimeError(
                    f"Agent exited with code {result.returncode}: "
                    f"{agent_stderr.strip() or agent_stdout.strip()}"
                )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("Agent timed out after 30 seconds") from exc

        attack_end_perf = time.perf_counter()
        attack_duration = attack_end_perf - attack_start_perf

        print(f"  {RED}[ATTACK]{RESET} Agent completed in {attack_duration:.4f}s")

        # Parse the agent report before stopping the Shield. The instrumented
        # monotonic timestamp identifies the first anti-forensic action.
        agent_report_path = os.path.join(self.workspace_dir, "operation_report.json")
        if not os.path.exists(agent_report_path):
            raise RuntimeError("Agent completed without producing operation_report.json")
        with open(agent_report_path, "r", encoding="utf-8") as report_file:
            agent_report = json.load(report_file)

        # Give time for inotify events from the cleanup phase to propagate
        time.sleep(2.0)

        # Stop shield and get report
        shield_report = shield.stop()

        # Analyze detection results
        trial_result = self._analyze_trial(
            trial_num,
            mode,
            delay,
            attack_start_perf,
            attack_duration,
            shield_report,
            agent_report,
        )

        return trial_result

    def _analyze_trial(self, trial_num: int, mode: str, delay: float,
                       attack_start_perf: float, attack_duration: float,
                       shield_report: Dict, agent_report: Dict) -> Dict:
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

        # Calculate latency from the first anti-forensic action. Older agents
        # without instrumentation fall back to process launch and are marked.
        critical_alerts = [a for a in alerts if a.get("severity") == "CRITICAL"]
        warning_alerts = [a for a in alerts if a.get("severity") == "WARNING"]
        cleanup_start_perf = agent_report.get(
            "cleanup_start_perf_time", attack_start_perf
        )
        latency_origin = (
            "first_anti_forensic_action"
            if "cleanup_start_perf_time" in agent_report
            else "process_launch_fallback"
        )
        qualifying_alerts = [
            alert
            for alert in alerts
            if alert.get("severity") in ("WARNING", "CRITICAL")
            and alert.get("detection_perf_time", float("inf")) >= cleanup_start_perf
        ]
        first_detection_latency = None
        if qualifying_alerts:
            first_detection_perf = min(
                alert["detection_perf_time"] for alert in qualifying_alerts
            )
            first_detection_latency = first_detection_perf - cleanup_start_perf

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
                "first_detection_latency_seconds": round(first_detection_latency, 4)
                if first_detection_latency is not None
                else None,
                "first_detection_latency_ms": round(first_detection_latency * 1000, 2)
                if first_detection_latency is not None
                else None,
                "latency_origin": latency_origin,
                "detected_timestomp": detected_timestomp,
                "detected_wiper": detected_wiper,
                "detected_deletion": detected_deletion,
                "detected_burst": detected_burst,
                "detected_canary_tampering": detected_canary,
                "completeness_percent": completeness,
                "expected_detections": expected_detections,
                "actual_detections": actual_detections,
            },
            "evidence_preserved": bool(
                shield_report.get("log_integrity", {}).get("valid", False)
            ),
            "shield_report_path": shield_report.get("report_path"),
        }

        # Print trial summary
        print(f"\n  {CYAN}{'─'*50}{RESET}")
        print(f"  {BOLD}Trial {trial_num} Results:{RESET}")
        print(f"    Agent execution time:      {agent_exec_time:.4f}s")
        print(f"    Total alerts fired:         {len(alerts)}")
        print(f"    Critical alerts:            {len(critical_alerts)}")
        if first_detection_latency is not None:
            print(f"    First detection latency:    {first_detection_latency*1000:.2f}ms")
        print(f"    Detection completeness:     {completeness:.0f}%")
        print(f"    Detections: {', '.join(actual_detections) if actual_detections else 'NONE'}")
        print(f"  {CYAN}{'─'*50}{RESET}")

        return result

    def run_false_positive_test(self, duration: int = 10) -> Dict:
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
        root = self._active_experiment_dir or self.reports_dir
        fp_reports = os.path.join(root, "false_positive_test")
        if os.path.exists(fp_reports):
            shutil.rmtree(fp_reports)
        os.makedirs(fp_reports, exist_ok=True)

        # Create a temporary config for this trial
        config = Config()
        config._config.setdefault("general", {})
        config._config["general"]["watch_paths"] = [self.workspace_dir]
        config._config["general"]["reports_dir"] = fp_reports
        config._config["general"]["database_path"] = os.path.join(fp_reports, "baseline.db")
        config._config["general"]["log_file"] = os.path.join(
            fp_reports, "shield.log"
        )

        shield = DetectionEngine(config)
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

    def run_canary_test(self) -> Dict:
        """Modify one deployed canary and measure high-confidence detection."""
        print(f"\n  {'='*50}")
        print(f"  {BOLD}CANARY EFFECTIVENESS TEST{RESET}")
        print(f"  {'='*50}\n")
        self._setup_workspace()

        root = self._active_experiment_dir or self.reports_dir
        reports_dir = os.path.join(root, "canary_test")
        if os.path.exists(reports_dir):
            shutil.rmtree(reports_dir)
        os.makedirs(reports_dir, exist_ok=True)

        config = Config()
        config._config.setdefault("general", {})
        config._config["general"].update(
            {
                "watch_paths": [self.workspace_dir],
                "reports_dir": reports_dir,
                "database_path": os.path.join(reports_dir, "baseline.db"),
                "log_file": os.path.join(reports_dir, "shield.log"),
            }
        )
        shield = DetectionEngine(config)
        shield.start(deploy_canaries=True, canary_count=1)
        time.sleep(0.5)

        registry = shield.canary_deployer.get_registry()
        if not registry:
            shield.stop()
            raise RuntimeError("Canary deployment failed; effectiveness test aborted")
        canary_path = next(iter(registry))
        interaction_started = time.perf_counter()
        with open(canary_path, "a", encoding="utf-8") as canary_file:
            canary_file.write("\nCONTROLLED_CANARY_INTERACTION\n")
        time.sleep(0.5)
        report = shield.stop()

        canary_alerts = [
            alert
            for alert in report.get("alerts", [])
            if "CANARY" in alert.get("details", {}).get("reason", "")
            or alert.get("event_type", "").startswith("CANARY_")
        ]
        after_interaction = [
            alert
            for alert in canary_alerts
            if alert.get("detection_perf_time", 0) >= interaction_started
        ]
        latency_ms = None
        if after_interaction:
            latency_ms = round(
                (
                    min(alert["detection_perf_time"] for alert in after_interaction)
                    - interaction_started
                )
                * 1000,
                2,
            )

        result = {
            "detected": bool(after_interaction),
            "alert_count": len(after_interaction),
            "detection_latency_ms": latency_ms,
            "canary_filename": os.path.basename(canary_path),
            "report_path": report.get("report_path"),
        }
        print(
            f"  Canary detection: {'PASS' if result['detected'] else 'FAIL'}"
            + (f" ({latency_ms:.2f}ms)" if latency_ms is not None else "")
        )
        return result

    @staticmethod
    def _historical_control(trials: int) -> Dict:
        """Represent the observed zero-alert Wazuh control from prior work."""
        return {
            "source": "Orji et al. (2026) prior Wazuh periodic-FIM experiment",
            "design": "historical control",
            "limitations": (
                "Control observations are historical rather than concurrently "
                "randomised. Detection latency is undefined because no alerts fired."
            ),
            "trials": [
                {
                    "trial": trial,
                    "total_alerts": 0,
                    "completeness_percent": 0.0,
                    "detection_latency_ms": None,
                }
                for trial in range(1, trials + 1)
            ],
        }

    def run_experiment(
        self,
        stealth_trials: int = 30,
        noisy_trials: int = 3,
        human_trials: int = 1,
        control_trials: int = 5,
        fp_duration: int = 10,
        human_seed: int = 2026,
    ) -> Dict:
        """
        Run a complete experiment suite.

        Args:
            stealth_trials: Number of stealth mode trials
            noisy_trials: Number of noisy mode trials
            human_trials: Number of qualitative human-speed baseline trials
            control_trials: Historical zero-alert Wazuh observations
            fp_duration: Duration of false positive test

        Returns:
            dict: Complete experiment results
        """
        experiment_start = time.time()
        experiment_id = datetime.now().strftime("%Y%m%dT%H%M%S")
        self._active_experiment_dir = os.path.join(
            self.reports_dir, f"experiment_{experiment_id}"
        )
        os.makedirs(self._active_experiment_dir, exist_ok=True)

        print(f"\n{'='*60}")
        print(f"  🔬 {BOLD}ANTIGRAVITY SHIELD v{__version__} — EXPERIMENTAL EVALUATION{RESET}")
        print(f"{'='*60}")
        print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Stealth trials: {stealth_trials}")
        print(f"  Noisy trials:   {noisy_trials}")
        print(f"  Human trials:   {human_trials}")
        print(f"  Control trials: {control_trials} (historical)")
        print(f"  FP test:        {fp_duration}s")
        print(f"{'='*60}")

        results = {
            "experiment_date": datetime.now().isoformat(),
            "shield_version": __version__,
            "stealth_trials": [],
            "noisy_trials": [],
            "human_baseline_trials": [],
            "control_condition": self._historical_control(control_trials),
            "canary_test": None,
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

        # Human-speed baseline is qualitative context, not an attack condition.
        for i in range(1, human_trials + 1):
            print(f"\n  [HUMAN BASELINE] Trial {i}/{human_trials}")
            results["human_baseline_trials"].append(
                run_human_baseline(i, seed=human_seed + i - 1)
            )

        # Dedicated canary interaction directly evaluates RQ3.
        results["canary_test"] = self.run_canary_test()

        # False positive test
        results["false_positive_test"] = self.run_false_positive_test(fp_duration)

        # Aggregate statistics
        results["summary"] = self._compute_summary(results)
        results["statistical_analysis"] = self._compute_statistical_analysis(results)

        artifacts_dir = Path(self._active_experiment_dir) / "figures"
        results["artifacts"] = {
            "trial_csv": export_trial_csv(
                results, Path(self._active_experiment_dir) / "trial_data.csv"
            ),
            "figures": generate_charts(results, artifacts_dir),
        }

        # Save experiment results
        results_path = os.path.join(self._active_experiment_dir, "experiment_results.json")
        with open(results_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)

        # Print final summary
        self._print_summary(results)

        print(f"\n  📄 Full results saved to: {results_path}")
        print(f"  📊 Figures saved to: {artifacts_dir}")

        # Cleanup
        self._teardown_workspace()
        self._active_experiment_dir = None

        return results

    @staticmethod
    def _compute_statistical_analysis(results: Dict) -> Dict:
        """Compute the inferential tests specified in the methodology."""
        treatment_completeness = [
            trial["detection"]["completeness_percent"]
            for trial in results["stealth_trials"]
        ]
        control_completeness = [
            trial["completeness_percent"]
            for trial in results["control_condition"]["trials"]
        ]
        return {
            "primary_test": mann_whitney_analysis(
                treatment_completeness,
                control_completeness,
                metric="detection_completeness_percent",
            ),
            "latency_comparison": {
                "computed": False,
                "reason": (
                    "Control latency is right-censored/undefined because Wazuh "
                    "generated no alerts. Assigning an artificial latency would "
                    "bias the comparison."
                ),
            },
        }

    def _compute_summary(self, results: Dict) -> Dict:
        """Compute aggregate statistics across all trials."""
        stealth = results["stealth_trials"]
        noisy = results["noisy_trials"]

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
        noisy_completeness = [t["detection"]["completeness_percent"] for t in noisy]
        human_durations_ms = [
            trial["planned_duration_seconds"] * 1000
            for trial in results["human_baseline_trials"]
        ]

        summary = {
            "stealth_mode": {
                "trials": len(stealth),
                "agent_execution_ms": descriptive_statistics(
                    [value * 1000 for value in stealth_exec_times]
                ),
                "detection_latency_ms": descriptive_statistics(stealth_latencies),
                "detection_completeness_percent": descriptive_statistics(
                    stealth_completeness
                ),
                "avg_agent_execution_ms": round(
                    descriptive_statistics(
                        [value * 1000 for value in stealth_exec_times]
                    )["mean"] or 0,
                    2,
                ),
                "avg_detection_latency_ms": round(
                    descriptive_statistics(stealth_latencies)["mean"], 2
                )
                if stealth_latencies
                else None,
                "min_detection_latency_ms": round(min(stealth_latencies), 2) if stealth_latencies else None,
                "max_detection_latency_ms": round(max(stealth_latencies), 2) if stealth_latencies else None,
                "avg_completeness_percent": round(
                    descriptive_statistics(stealth_completeness)["mean"] or 0, 1
                ),
                "detection_rate_timestomp": sum(1 for t in stealth if t["detection"]["detected_timestomp"]) / len(stealth) * 100 if stealth else 0,
                "detection_rate_wiper": sum(1 for t in stealth if t["detection"]["detected_wiper"]) / len(stealth) * 100 if stealth else 0,
                "detection_rate_deletion": sum(1 for t in stealth if t["detection"]["detected_deletion"]) / len(stealth) * 100 if stealth else 0,
                "detection_rate_burst": sum(1 for t in stealth if t["detection"]["detected_burst"]) / len(stealth) * 100 if stealth else 0,
                "evidence_preservation_rate": sum(
                    1 for t in stealth if t["evidence_preserved"]
                )
                / len(stealth)
                * 100
                if stealth
                else 0,
            },
            "noisy_mode": {
                "trials": len(noisy),
                "detection_latency_ms": descriptive_statistics(noisy_latencies),
                "detection_completeness_percent": descriptive_statistics(
                    noisy_completeness
                ),
                "avg_detection_latency_ms": round(
                    descriptive_statistics(noisy_latencies)["mean"], 2
                )
                if noisy_latencies
                else None,
                "detection_rate": sum(1 for t in noisy if t["detection"]["completeness_percent"] > 0) / len(noisy) * 100 if noisy else 0,
            },
            "human_baseline": {
                "trials": len(human_durations_ms),
                "execution_time_ms": descriptive_statistics(human_durations_ms),
            },
            "canary_test": results["canary_test"],
            "false_positive_rate": results["false_positive_test"]["false_positive_rate"] if results["false_positive_test"] else None,
        }

        return summary

    def _print_summary(self, results: Dict) -> None:
        """Print a formatted summary table."""
        summary = results["summary"]
        stealth = summary["stealth_mode"]
        noisy = summary["noisy_mode"]
        human = summary["human_baseline"]
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

        print(f"\n  {BOLD}Human-Speed Baseline (Qualitative){RESET}")
        print(f"  {'─'*45}")
        print(f"  Trials:                    {human['trials']}")
        if human["execution_time_ms"]["median"] is not None:
            print(
                "  Median modelled duration: "
                f"{human['execution_time_ms']['median']:.2f}ms"
            )

        canary = results.get("canary_test") or {}
        print(f"\n  {BOLD}Canary Effectiveness Test{RESET}")
        print(f"  {'─'*45}")
        print(f"  Detected:                  {canary.get('detected', False)}")
        if canary.get("detection_latency_ms") is not None:
            print(
                f"  Detection latency:         {canary['detection_latency_ms']:.2f}ms"
            )

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

        primary_test = results.get("statistical_analysis", {}).get(
            "primary_test", {}
        )
        if primary_test.get("computed"):
            print(f"\n  {BOLD}Inferential Analysis{RESET}")
            print(f"  {'─'*45}")
            print(f"  Mann-Whitney U:            {primary_test['u_statistic']:.4f}")
            print(f"  p-value:                   {primary_test['p_value']:.6g}")
            print(
                "  Rank-biserial r:           "
                f"{primary_test['rank_biserial_correlation']:.4f} "
                f"({primary_test['effect_size_magnitude']})"
            )
            print(
                "  Significant (p < 0.05):    "
                f"{primary_test['statistically_significant']}"
            )

        print(f"\n{'='*60}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AntiGravity Shield — Test Harness")
    parser.add_argument("--stealth-trials", type=int, default=30,
                        help="Number of stealth mode trials (default: 30)")
    parser.add_argument("--noisy-trials", type=int, default=3,
                        help="Number of noisy mode trials (default: 3)")
    parser.add_argument("--human-trials", type=int, default=1,
                        help="Human baseline trials (default: 1)")
    parser.add_argument("--control-trials", type=int, default=5,
                        help="Historical Wazuh control observations (default: 5)")
    parser.add_argument("--fp-duration", type=int, default=10,
                        help="False positive test duration in seconds (default: 10)")
    parser.add_argument("--human-seed", type=int, default=2026,
                        help="Human baseline random seed (default: 2026)")
    parser.add_argument("--agent-path",
                        help="Path to the separately supplied controlled agent")
    parser.add_argument("--reports-dir",
                        help="Persistent experiment output directory")
    parser.add_argument("--single", choices=["stealth", "noisy"],
                        help="Run a single trial instead of full experiment")

    args = parser.parse_args()

    harness = ExperimentHarness(agent_dir=args.agent_path, reports_dir=args.reports_dir)

    if args.single:
        result = harness.run_trial(1, mode=args.single)
        print(json.dumps(result, indent=2, default=str))
    else:
        harness.run_experiment(
            stealth_trials=args.stealth_trials,
            noisy_trials=args.noisy_trials,
            human_trials=args.human_trials,
            control_trials=args.control_trials,
            fp_duration=args.fp_duration,
            human_seed=args.human_seed,
        )
