"""
AntiGravity Shield — Central Controller
========================================
Orchestrates all defense modules in parallel and provides
unified alert aggregation, severity classification, and reporting.

This is the main entry point for the defense framework.
"""

import os
import sys
import time
import json
import signal
import threading
from datetime import datetime
from collections import defaultdict

# Add parent directory to path so we can import defense modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from realtime_monitor import RealtimeMonitor
from canary_deployer import CanaryDeployer
from timestamp_validator import TimestampValidator
from log_protector import LogProtector
from behavioral_detector import BehavioralDetector


# Severity icons for console output
SEVERITY_ICONS = {
    "INFO": "ℹ️ ",
    "WARNING": "⚠️ ",
    "CRITICAL": "🚨",
}

SEVERITY_COLORS = {
    "INFO": "\033[94m",       # Blue
    "WARNING": "\033[93m",    # Yellow
    "CRITICAL": "\033[91m",   # Red
}
RESET_COLOR = "\033[0m"
BOLD = "\033[1m"


class ShieldController:
    """
    Central defense orchestrator.
    Starts all defense modules, receives alerts via a thread-safe queue,
    and generates structured reports.
    """

    def __init__(self, watch_paths, reports_dir="reports"):
        self.watch_paths = watch_paths if isinstance(watch_paths, list) else [watch_paths]
        self.reports_dir = reports_dir
        os.makedirs(reports_dir, exist_ok=True)

        # Alert storage
        self.alerts = []
        self.alert_lock = threading.RLock()  # RLock: prevents deadlock if log writes trigger re-entry

        # Timing
        self.start_time = None
        self.start_perf = None

        # Initialize modules
        db_path = os.path.join(reports_dir, "baseline.db")
        registry_path = os.path.join(reports_dir, "canary_registry.json")
        log_path = os.path.join(reports_dir, "shield_audit.log")
        chain_path = os.path.join(reports_dir, "hash_chain.json")

        self.canary_deployer = CanaryDeployer(registry_path=registry_path)
        self.timestamp_validator = TimestampValidator(alert_callback=self._on_alert)
        self.log_protector = LogProtector(log_path=log_path, chain_path=chain_path)
        self.behavioral_detector = BehavioralDetector(alert_callback=self._on_alert)

        # Realtime monitor gets initialized after canaries are deployed
        self.realtime_monitor = None
        self._db_path = db_path
        self._running = False

    def _on_alert(self, alert):
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

            self.alerts.append(alert)

            # Log to immutable chain
            self.log_protector.log_event(alert)

            # Console output
            self._print_alert(alert)

            # Feed to behavioral detector (if the alert is from the realtime monitor)
            if alert.get("module") == "realtime_monitor":
                self.behavioral_detector.process_event(alert)

                # Also check timestamps on created/modified files
                if alert["event_type"] in ("FILE_CREATED", "FILE_MODIFIED"):
                    filepath = alert.get("path", "")
                    if os.path.exists(filepath):
                        self.timestamp_validator.validate_file(filepath)

    def _print_alert(self, alert):
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

        print(
            f"  {icon} {color}[{ts}] [{severity}]{RESET_COLOR} "
            f"{BOLD}{event_type}{RESET_COLOR} "
            f"→ {display_path}{latency_str}"
        )

        reason = alert.get("details", {}).get("reason", "")
        if reason and severity in ("WARNING", "CRITICAL"):
            # Wrap long reasons
            if len(reason) > 100:
                reason = reason[:100] + "..."
            print(f"       ↳ {reason}")

    def start(self, deploy_canaries=True, canary_count=3):
        """
        Start the full defense stack.

        Args:
            deploy_canaries: Whether to deploy honeypot files
            canary_count: Number of canary files per watched directory
        """
        self.start_time = time.time()
        self.start_perf = time.perf_counter()

        print(f"\n{'='*60}")
        print(f"  🛡️  {BOLD}ANTIGRAVITY SHIELD — Enterprise Defense Framework{RESET_COLOR}")
        print(f"{'='*60}")
        print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Monitoring: {', '.join(self.watch_paths)}")
        print(f"{'='*60}\n")

        # Step 1: Deploy canary files
        canary_registry = {}
        if deploy_canaries:
            print(f"  [{BOLD}PHASE 1{RESET_COLOR}] Deploying canary tripwires...")
            for path in self.watch_paths:
                deployed = self.canary_deployer.deploy_canaries(path, count=canary_count)
                canary_registry.update(deployed)
            print(f"  Total canaries deployed: {len(canary_registry)}\n")

        # Step 2: Initialize real-time monitor with canary awareness
        print(f"  [{BOLD}PHASE 2{RESET_COLOR}] Starting real-time file monitor...")
        self.realtime_monitor = RealtimeMonitor(
            self.watch_paths,
            self._on_alert,
            canary_registry=canary_registry,
            db_path=self._db_path,
        )
        self.realtime_monitor.scan_baseline()
        self.realtime_monitor.start()
        print()

        # Step 3: Initial timestamp scan
        print(f"  [{BOLD}PHASE 3{RESET_COLOR}] Scanning for existing timestamp anomalies...")
        anomaly_count = 0
        for path in self.watch_paths:
            if os.path.isdir(path):
                alerts = self.timestamp_validator.validate_directory(path)
                anomaly_count += len(alerts)
        if anomaly_count == 0:
            print("  ✅ No pre-existing timestamp anomalies found.\n")
        else:
            print(f"  ⚠️  Found {anomaly_count} pre-existing anomaly(ies).\n")

        # Step 4: Set up external log monitoring
        print(f"  [{BOLD}PHASE 4{RESET_COLOR}] Initializing log protection...")
        external_logs = []
        bash_history = os.path.expanduser("~/.bash_history")
        if os.path.exists(bash_history):
            external_logs.append(bash_history)
        for log_path in ["/var/log/auth.log", "/var/log/syslog"]:
            if os.path.exists(log_path):
                external_logs.append(log_path)
        if external_logs:
            self.log_protector.monitor_external_logs(external_logs)
            print(f"  Monitoring {len(external_logs)} external log file(s)")
        print(f"  Hash-chained audit log: {self.log_protector.log_path}\n")

        self._running = True

        print(f"  {'='*56}")
        print(f"  🛡️  {BOLD}SHIELD ACTIVE — Monitoring for threats...{RESET_COLOR}")
        print(f"  {'='*56}\n")

        return self

    def stop(self):
        """Stop all defense modules and generate final report."""
        if not self._running:
            return

        self._running = False

        # Stop realtime monitor (in a thread with timeout to avoid inotify hangs)
        if self.realtime_monitor:
            stop_thread = threading.Thread(target=self.realtime_monitor.stop, daemon=True)
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

        print(f"\n  {'='*56}")
        print(f"  🛡️  {BOLD}SHIELD DEACTIVATED{RESET_COLOR}")
        print(f"  {'='*56}")
        print(f"  Duration: {duration:.2f}s")
        print(f"  Total alerts: {len(self.alerts)}")

        # Summary by severity
        by_severity = defaultdict(int)
        for a in self.alerts:
            by_severity[a.get("severity", "INFO")] += 1
        for sev in ["CRITICAL", "WARNING", "INFO"]:
            if by_severity[sev]:
                print(f"    {SEVERITY_ICONS.get(sev, '')} {sev}: {by_severity[sev]}")

        print(f"  Log integrity: {'✅ VERIFIED' if integrity['valid'] else '🚨 COMPROMISED'}")
        print(f"  Report saved: {report['report_path']}")
        print(f"  {'='*56}\n")

        return report

    def _generate_report(self, integrity):
        """Generate a structured JSON defense report."""
        end_time = time.time()

        report = {
            "framework": "AntiGravity Shield",
            "version": "1.0.0",
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

    def get_alerts(self):
        """Return a copy of all alerts."""
        with self.alert_lock:
            return list(self.alerts)

    def wait(self):
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


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AntiGravity Shield — Enterprise Defense Framework")
    parser.add_argument("--watch", nargs="+", default=["."],
                        help="Directories to monitor (default: current directory)")
    parser.add_argument("--no-canaries", action="store_true",
                        help="Disable canary file deployment")
    parser.add_argument("--canary-count", type=int, default=3,
                        help="Number of canary files per directory (default: 3)")

    args = parser.parse_args()

    shield = ShieldController(
        watch_paths=args.watch,
        reports_dir=os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports"),
    )

    shield.start(
        deploy_canaries=not args.no_canaries,
        canary_count=args.canary_count,
    )

    shield.wait()
