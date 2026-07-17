"""
AntiGravity Shield — Central Detection Engine
==============================================
Orchestrates all detection modules in parallel and provides
unified alert aggregation, severity classification, and reporting.

This is the main entry point for the detection framework.
"""

import os
import sys
import time
import json
import signal
import threading
import logging
from datetime import datetime
from collections import defaultdict
from typing import Callable, Dict, List, Optional

from agshield.config import Config
from agshield.monitor.kernel_monitor import KernelMonitor
from agshield.monitor.process_tracker import ProcessTracker
from agshield.monitor.realtime import RealtimeMonitor
from agshield.monitor.canary import CanaryDeployer
from agshield.monitor.timestamp import TimestampValidator
from agshield.monitor.logprotector import LogProtector
from agshield.monitor.behavior import BehavioralDetector
from agshield.detection.rules import RuleEngine
from agshield.integration.wazuh import WazuhIntegration

logger = logging.getLogger("antigravity.engine")


# Severity icons for console output (ASCII-safe for Windows cp1252)
SEVERITY_ICONS = {
    "INFO": "[i]",
    "WARNING": "[!]",
    "CRITICAL": "[!!!]",
}

SEVERITY_COLORS = {
    "INFO": "\033[94m",       # Blue
    "WARNING": "\033[93m",    # Yellow
    "CRITICAL": "\033[91m",   # Red
}
RESET_COLOR = "\033[0m"
BOLD = "\033[1m"


def _safe_print(msg: str) -> None:
    """Print with fallback encoding for Windows consoles."""
    try:
        print(msg)
    except UnicodeEncodeError:
        print(msg.encode("ascii", errors="replace").decode("ascii"))


class DetectionEngine:
    """
    Central detection orchestrator.
    Starts all detection modules, receives alerts via a thread-safe queue,
    and generates structured reports.
    """

    def __init__(self, config: Optional[Config] = None, config_path: Optional[str] = None):
        self.config = config or Config(config_path)
        self.watch_paths = self.config.watch_paths
        self.reports_dir = self.config.reports_dir
        os.makedirs(self.reports_dir, exist_ok=True)

        # Alert storage
        self.alerts: List[dict] = []
        self.alert_lock = threading.RLock()

        # Timing
        self.start_time = None
        self.start_perf = None

        # Initialize modules
        db_path = self.config.database_path
        registry_path = os.path.join(self.reports_dir, "canary_registry.json")
        log_path = self.config.log_file
        chain_path = os.path.join(self.reports_dir, "hash_chain.json")

        # Behavioral config
        beh_config = self.config.get_section("behavioral_detector")
        ts_config = self.config.get_section("timestamp_validator")

        self.canary_deployer = CanaryDeployer(registry_path=registry_path)
        self.timestamp_validator = TimestampValidator(
            alert_callback=self._on_alert,
            retro_date_threshold_days=ts_config.get("retro_date_threshold_days", 365),
            future_threshold_seconds=ts_config.get("future_threshold_seconds", 300),
            sibling_deviation_days=ts_config.get("sibling_deviation_days", 180),
            ctime_mtime_drift_seconds=ts_config.get("ctime_mtime_drift_seconds", 60),
        )
        self.log_protector = LogProtector(log_path=log_path, chain_path=chain_path)
        self.behavioral_detector = BehavioralDetector(
            alert_callback=self._on_alert,
            burst_window_seconds=beh_config.get("burst_window_seconds", 1.0),
            burst_threshold_ops=beh_config.get("burst_threshold_ops", 4),
            ephemeral_threshold_seconds=beh_config.get("ephemeral_threshold_seconds", 5.0),
            wiper_sequence_window=beh_config.get("wiper_sequence_window", 2.0),
            rapid_deletion_threshold=beh_config.get("rapid_deletion_threshold", 3),
        )

        # Process tracker for PID attribution
        self.process_tracker = ProcessTracker(cache_ttl=5.0)

        # Rule engine for configurable detection rules
        self.rule_engine = RuleEngine(alert_callback=self._on_alert)

        # Wazuh integration
        wazuh_config = self.config.get_section("wazuh_integration")
        if wazuh_config.get("enabled", False):
            self.wazuh = WazuhIntegration(
                api_url=wazuh_config.get("api_url", "https://localhost:55000"),
                api_user=wazuh_config.get("api_user", "wazuh-wui"),
                api_password=wazuh_config.get("api_password", ""),
                api_verify_ssl=wazuh_config.get("api_verify_ssl", False),
                socket_path=wazuh_config.get("socket_path", "/var/ossec/queue/sockets/queue"),
                alert_prefix=wazuh_config.get("alert_prefix", "antigravity"),
            )
        else:
            self.wazuh = None

        # Kernel monitor (primary) and realtime monitor (fallback)
        self.kernel_monitor = None
        self.realtime_monitor = None
        self._db_path = db_path
        self._running = False
        self._monitor_backend = "unknown"

    def _on_alert(self, alert: dict) -> None:
        """
        Central alert handler. Called by all modules.
        Thread-safe: multiple modules fire alerts from different threads.
        """
        with self.alert_lock:
            # Add detection latency if we have a start time
            if self.start_perf:
                alert["detection_latency_ms"] = round(
                    (alert.get("detection_perf_time", time.perf_counter()) - self.start_perf) * 1000, 2
                )

            # Process attribution — enrich with PID info if available
            pid = alert.get("pid") or alert.get("details", {}).get("pid")
            if pid and pid > 0:
                self.process_tracker.enrich_alert(alert, pid)

            # Monitor backend tag
            alert["monitor_backend"] = self._monitor_backend

            self.alerts.append(alert)

            # Log to immutable chain
            self.log_protector.log_event(alert)

            # Console output
            self._print_alert(alert)

            # Feed to behavioral detector (from kernel or realtime monitor)
            if alert.get("module") in ("realtime_monitor", "kernel_monitor"):
                self.behavioral_detector.process_event(alert)

                # Also check timestamps on created/modified files
                if alert["event_type"] in ("FILE_CREATED", "FILE_MODIFIED", "FILE_ATTRIB_CHANGED"):
                    filepath = alert.get("path", "")
                    if os.path.exists(filepath):
                        self.timestamp_validator.validate_file(filepath)

            # Feed to rule engine
            self.rule_engine.evaluate(alert)

            # Send to Wazuh if integration is enabled
            if self.wazuh:
                self.wazuh.send_alert(alert)

    def _print_alert(self, alert: dict) -> None:
        """Pretty-print an alert to the console."""
        severity = alert.get("severity", "INFO")
        icon = SEVERITY_ICONS.get(severity, "  ")
        color = SEVERITY_COLORS.get(severity, "")

        ts = datetime.fromtimestamp(
            alert.get("detection_wall_time", time.time())
        ).strftime("%H:%M:%S.%f")[:-3]

        module = alert.get("module", "unknown")
        event_type = alert.get("event_type", "UNKNOWN")
        path = alert.get("path", "")

        # Shorten path for display
        display_path = os.path.basename(path) if path else ""

        latency = alert.get("detection_latency_ms", "")
        latency_str = f" ({latency}ms)" if latency else ""

        _safe_print(
            f"  {icon} {color}[{ts}] [{severity}]{RESET_COLOR} "
            f"{BOLD}{event_type}{RESET_COLOR} "
            f"-> {display_path}{latency_str}"
        )

        reason = alert.get("details", {}).get("reason", "")
        if reason and severity in ("WARNING", "CRITICAL"):
            # Wrap long reasons
            if len(reason) > 100:
                reason = reason[:100] + "..."
            _safe_print(f"       -> {reason}")

    def start(self, deploy_canaries: bool = True, canary_count: int = 3) -> "DetectionEngine":
        """
        Start the full detection stack.

        Args:
            deploy_canaries: Whether to deploy honeypot files
            canary_count: Number of canary files per watched directory
        """
        self.start_time = time.time()
        self.start_perf = time.perf_counter()

        _safe_print(f"\n{'='*60}")
        _safe_print(f"  [SHIELD] {BOLD}ANTIGRAVITY SHIELD -- Enterprise Defense Framework{RESET_COLOR}")
        _safe_print(f"{'='*60}")
        _safe_print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        _safe_print(f"  Monitoring: {', '.join(self.watch_paths)}")
        _safe_print(f"{'='*60}\n")

        # Step 1: Deploy canary files
        canary_registry = {}
        if deploy_canaries:
            _safe_print(f"  [{BOLD}PHASE 1{RESET_COLOR}] Deploying canary tripwires...")
            for path in self.watch_paths:
                deployed = self.canary_deployer.deploy_canaries(path, count=canary_count)
                canary_registry.update(deployed)
            _safe_print(f"  Total canaries deployed: {len(canary_registry)}\n")

        # Step 2: Initialize kernel-level monitor (with watchdog fallback)
        _safe_print(f"  [{BOLD}PHASE 2{RESET_COLOR}] Starting kernel-level file monitor...")
        rt_config = self.config.get_section("realtime_monitor")
        self.kernel_monitor = KernelMonitor(
            watch_paths=self.watch_paths,
            alert_callback=self._on_alert,
            canary_registry=canary_registry,
            db_path=self._db_path,
            ignore_patterns=rt_config.get("ignore_patterns"),
            suspicious_extensions=rt_config.get("suspicious_extensions"),
        )
        self._monitor_backend = self.kernel_monitor.start()
        self.kernel_monitor.scan_baseline()

        if self.kernel_monitor.using_kernel:
            _safe_print(f"  [*] Backend: KERNEL (fanotify) -- sub-millisecond detection")
        else:
            _safe_print(f"  [*] Backend: USER-SPACE (watchdog) -- fallback mode")
        _safe_print("")

        # Step 3: Initial timestamp scan
        _safe_print(f"  [{BOLD}PHASE 3{RESET_COLOR}] Scanning for existing timestamp anomalies...")
        anomaly_count = 0
        for path in self.watch_paths:
            if os.path.isdir(path):
                alerts = self.timestamp_validator.validate_directory(path)
                anomaly_count += len(alerts)
        if anomaly_count == 0:
            _safe_print("  [OK] No pre-existing timestamp anomalies found.\n")
        else:
            _safe_print(f"  [!] Found {anomaly_count} pre-existing anomaly(ies).\n")

        # Step 4: Set up external log monitoring
        _safe_print(f"  [{BOLD}PHASE 4{RESET_COLOR}] Initializing log protection...")
        log_config = self.config.get_section("log_protector")
        external_logs = log_config.get("external_logs", [])
        # Expand ~ in paths
        external_logs = [os.path.expanduser(p) for p in external_logs]
        # Filter to existing files
        external_logs = [p for p in external_logs if os.path.exists(p)]
        if external_logs:
            self.log_protector.monitor_external_logs(external_logs)
            _safe_print(f"  Monitoring {len(external_logs)} external log file(s)")
        _safe_print(f"  Hash-chained audit log: {self.log_protector.log_path}\n")

        self._running = True

        _safe_print(f"  {'='*56}")
        _safe_print(f"  [SHIELD] {BOLD}SHIELD ACTIVE -- Monitoring for threats...{RESET_COLOR}")
        _safe_print(f"  {'='*56}\n")

        return self

    def stop(self) -> dict:
        """Stop all detection modules and generate final report."""
        if not self._running:
            return {}

        self._running = False

        # Stop kernel/realtime monitor (in a thread with timeout to avoid hangs)
        if self.kernel_monitor:
            stop_thread = threading.Thread(target=self.kernel_monitor.stop, daemon=True)
            stop_thread.start()
            stop_thread.join(timeout=3)

        # Final canary verification
        canary_alerts = self.canary_deployer.verify_canaries()
        for alert in canary_alerts:
            self._on_alert(alert)

        # External log check
        log_alerts = self.log_protector.check_external_logs()
        for alert in log_alerts:
            self._on_alert(alert)

        # Verify log integrity
        integrity = self.log_protector.verify_integrity()

        # Generate report
        report = self._generate_report(integrity)

        end_time = time.time()
        duration = end_time - self.start_time

        _safe_print(f"\n  {'='*56}")
        _safe_print(f"  [SHIELD] {BOLD}SHIELD DEACTIVATED{RESET_COLOR}")
        _safe_print(f"  {'='*56}")
        _safe_print(f"  Duration: {duration:.2f}s")
        _safe_print(f"  Total alerts: {len(self.alerts)}")

        # Summary by severity
        by_severity = defaultdict(int)
        for a in self.alerts:
            by_severity[a.get("severity", "INFO")] += 1
        for sev in ["CRITICAL", "WARNING", "INFO"]:
            if by_severity[sev]:
                _safe_print(f"    {SEVERITY_ICONS.get(sev, '')} {sev}: {by_severity[sev]}")

        integrity_str = "VERIFIED" if integrity['valid'] else "COMPROMISED"
        _safe_print(f"  Log integrity: {integrity_str}")
        _safe_print(f"  Report saved: {report['report_path']}")
        _safe_print(f"  {'='*56}\n")

        return report

    def _generate_report(self, integrity: dict) -> dict:
        """Generate a structured JSON detection report."""
        end_time = time.time()

        report = {
            "framework": "AntiGravity Shield",
            "version": "2.0.0",
            "monitor_backend": self._monitor_backend,
            "start_time": self.start_time,
            "end_time": end_time,
            "duration_seconds": round(end_time - self.start_time, 4),
            "watched_paths": self.watch_paths,
            "summary": {
                "total_alerts": len(self.alerts),
                "by_severity": {},
                "by_module": {},
                "by_event_type": {},
            },
            "log_integrity": integrity,
            "behavioral_stats": self.behavioral_detector.get_stats(),
            "process_tracker_stats": self.process_tracker.get_stats(),
            "kernel_events": self.kernel_monitor.event_count if self.kernel_monitor else 0,
            "canary_status": {
                "deployed": len(self.canary_deployer.get_registry()),
                "final_verification": "passed" if not any(
                    a.get("module") == "canary_deployer" for a in self.alerts
                ) else "FAILED",
            },
            "alerts": self.alerts,
        }

        # Aggregate summaries
        for alert in self.alerts:
            sev = alert.get("severity", "INFO")
            mod = alert.get("module", "unknown")
            evt = alert.get("event_type", "UNKNOWN")

            report["summary"]["by_severity"][sev] = report["summary"]["by_severity"].get(sev, 0) + 1
            report["summary"]["by_module"][mod] = report["summary"]["by_module"].get(mod, 0) + 1
            report["summary"]["by_event_type"][evt] = report["summary"]["by_event_type"].get(evt, 0) + 1

        # Save report
        report_filename = f"shield_report_{int(self.start_time)}.json"
        report_path = os.path.join(self.reports_dir, report_filename)
        report["report_path"] = report_path

        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)

        return report

    def get_alerts(self) -> List[dict]:
        """Return a copy of all alerts."""
        with self.alert_lock:
            return list(self.alerts)

    def wait(self) -> None:
        """Block until interrupted (Ctrl+C)."""
        try:
            while self._running:
                # Periodic canary verification (every 10 seconds)
                time.sleep(10)
                if self._running:
                    canary_alerts = self.canary_deployer.verify_canaries()
                    for alert in canary_alerts:
                        self._on_alert(alert)

                    log_alerts = self.log_protector.check_external_logs()
                    for alert in log_alerts:
                        self._on_alert(alert)

        except KeyboardInterrupt:
            print("\n\n  [SHIELD] Shutting down...")
            self.stop()
