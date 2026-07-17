"""
AntiGravity Shield v2.0 -- System-Wide Terminal Monitor
========================================================
Monitors the ENTIRE Windows file system in real-time using
ReadDirectoryChangesW (kernel-level API on Windows).

Detects:
  - File creation, modification, deletion, renaming
  - Timestomping (os.utime backdating)
  - Secure wiping (same-size overwrite -> rename -> delete)
  - Mass deletion / operation bursts
  - Ephemeral files (created + deleted in < 5s)
  - Event log tampering (wevtutil)
  - Suspicious executables

Usage (on Windows):
    python shield_monitor.py
    python shield_monitor.py --paths "C:\\Users" "C:\\ProgramData"
    python shield_monitor.py --all-drives
"""
import sys
import os
import time
import json
import signal
import argparse
import threading
from datetime import datetime
from collections import defaultdict

# ── Resolve source path ──
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
for src_dir in [
    os.path.join(SCRIPT_DIR, "antigravity-shield", "src"),
    os.path.join(os.path.expanduser("~"), "antigravity-shield", "src"),
    os.path.join(SCRIPT_DIR, "src"),
]:
    if os.path.exists(src_dir):
        sys.path.insert(0, src_dir)
        break

from agshield.detection.engine import DetectionEngine
from agshield.config import Config


# ── ANSI colors (Windows 10+ supports them) ──
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
PURPLE = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

SEVERITY_STYLE = {
    "CRITICAL": f"{RED}{BOLD}",
    "WARNING": f"{YELLOW}",
    "INFO": f"{BLUE}",
}

# ── Noise filter: skip these paths to avoid drowning in Windows system chatter ──
SYSTEM_NOISE_PATTERNS = [
    # Windows internals
    "\\AppData\\Local\\Temp\\",
    "\\AppData\\Local\\Microsoft\\",
    "\\AppData\\Local\\Google\\Chrome\\",
    "\\AppData\\Local\\Mozilla\\",
    "\\AppData\\Roaming\\Microsoft\\",
    "\\Windows\\Prefetch\\",
    "\\Windows\\Temp\\",
    "\\Windows\\SoftwareDistribution\\",
    "\\Windows\\Logs\\",
    "\\Windows\\ServiceProfiles\\",
    "\\Windows\\System32\\config\\",
    "\\Windows\\System32\\sru\\",
    "\\Windows\\System32\\wdi\\",
    "\\Windows\\System32\\LogFiles\\",
    "\\Windows\\System32\\catroot2\\",
    "\\Windows\\System32\\Tasks\\Microsoft\\",
    "\\Windows\\System32\\winevt\\Logs\\Microsoft-",  # Skip MS telemetry logs but keep Security/System
    "\\$Recycle.Bin\\",
    "\\System Volume Information\\",
    "\\ProgramData\\Microsoft\\Windows\\",
    "\\ProgramData\\Package Cache\\",
    "\\ProgramData\\USOShared\\",
    # Dev noise
    "__pycache__",
    ".pyc",
    ".pyo",
    ".swp",
    ".tmp",
    "~$",
    ".lock",
    "ntuser.dat",
    "UsrClass.dat",
    ".db-journal",
    # Shield's own files (avoid feedback loop)
    "baseline.db",
    "hash_chain.json",
    "shield.log",
    "canary_registry.json",
    "shield_report_",
    "shield_output",
    "shield_realtest",
]

# ── HIGH-VALUE targets that we always want to monitor ──
HIGH_VALUE_PATHS = [
    # Windows Event Logs (the main attack target)
    "\\Windows\\System32\\winevt\\Logs\\Security.evtx",
    "\\Windows\\System32\\winevt\\Logs\\System.evtx",
    "\\Windows\\System32\\winevt\\Logs\\Application.evtx",
    # Registry hives
    "\\Windows\\System32\\config\\SAM",
    "\\Windows\\System32\\config\\SECURITY",
    "\\Windows\\System32\\config\\SYSTEM",
    # User areas
    "\\Users\\",
    "\\ProgramData\\",
]


def is_noise(path):
    """Check if a path is system noise we should suppress."""
    path_upper = path.upper()
    for pattern in SYSTEM_NOISE_PATTERNS:
        if pattern.upper() in path_upper:
            # But never suppress high-value targets
            for hv in HIGH_VALUE_PATHS:
                if hv.upper() in path_upper:
                    return False
            return True
    return False


def safe_print(msg):
    """Print with encoding safety for Windows console."""
    try:
        print(msg, flush=True)
    except UnicodeEncodeError:
        print(msg.encode("ascii", errors="replace").decode("ascii"), flush=True)


def get_windows_drives():
    """Get all available drive letters on Windows."""
    drives = []
    if sys.platform == "win32":
        import ctypes
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            if bitmask & (1 << i):
                drive = chr(65 + i) + ":\\"
                drives.append(drive)
    else:
        drives = ["C:\\"]
    return drives


class SystemWideShield:
    """
    System-wide file system monitor with terminal interface.
    Uses the full AntiGravity Shield detection engine.
    """

    def __init__(self, watch_paths, output_dir=None, quiet=False):
        self.watch_paths = watch_paths
        self.quiet = quiet  # Suppress INFO-level alerts
        self.output_dir = output_dir or os.path.join(
            os.path.expanduser("~"), "Desktop", "shield_output"
        )
        os.makedirs(self.output_dir, exist_ok=True)
        self.reports_dir = os.path.join(self.output_dir, "reports")
        os.makedirs(self.reports_dir, exist_ok=True)

        self.engine = None
        self.running = False
        self.start_time = 0
        self.alert_counts = defaultdict(int)
        self.alert_lock = threading.Lock()
        self.events_per_second = 0
        self._recent_events = []

    def start(self):
        """Start system-wide monitoring."""
        # Enable ANSI colors on Windows
        if sys.platform == "win32":
            os.system("")  # Enables ANSI escape codes on Win10+

        self._print_banner()

        # Configure engine
        config = Config()
        config._config.setdefault("general", {})
        config._config["general"]["watch_paths"] = self.watch_paths
        config._config["general"]["reports_dir"] = self.reports_dir
        config._config["general"]["database_path"] = os.path.join(self.output_dir, "baseline.db")
        config._config["general"]["log_file"] = os.path.join(self.output_dir, "shield.log")

        # Tune behavioral detector for system-wide monitoring
        config._config.setdefault("behavioral_detector", {})
        config._config["behavioral_detector"]["burst_threshold_ops"] = 10  # Higher threshold for system-wide
        config._config["behavioral_detector"]["rapid_deletion_threshold"] = 5

        # Create engine
        self.engine = DetectionEngine(config)

        # Wrap alert handler to add our filtering + display
        original_on_alert = self.engine._on_alert

        # Shield's own output directory — suppress completely to avoid feedback loop
        shield_output_dir = os.path.normpath(self.output_dir).lower()

        def filtered_alert(alert):
            """Filter noise and display real threats."""
            path = alert.get("path", "")

            # ALWAYS suppress alerts from the shield's own output directory
            # (baseline.db, shield.log, hash_chain.json, etc.) — these are
            # generated by our own engine and create a feedback loop
            if path and os.path.normpath(path).lower().startswith(shield_output_dir):
                return

            # Skip system noise for INFO-level only
            if is_noise(path) and alert.get("severity") == "INFO":
                return

            # Call real engine handler (with console print suppressed)
            original_on_alert(alert)

            # Display in our clean terminal format
            self._display_alert(alert)

        self.engine._on_alert = filtered_alert
        self.engine.behavioral_detector.alert_callback = filtered_alert
        self.engine.timestamp_validator.alert_callback = filtered_alert
        self.engine.rule_engine.alert_callback = filtered_alert

        # ── FAST START: Skip slow baseline hash scan ──
        # For system-wide monitoring, hashing every file would take minutes.
        # Instead, we directly start the watchdog monitor (which uses Windows
        # ReadDirectoryChangesW — a kernel-level API) and detect events in
        # real-time WITHOUT needing a baseline.
        safe_print(f"\n  {DIM}Initializing detection engine (fast-start mode)...{RESET}")

        self.engine.start_time = time.time()
        self.engine.start_perf = time.perf_counter()

        # Start kernel/watchdog monitor directly (NO baseline scan)
        from agshield.monitor.kernel_monitor import KernelMonitor
        rt_config = config.get_section("realtime_monitor")
        self.engine.kernel_monitor = KernelMonitor(
            watch_paths=self.watch_paths,
            alert_callback=filtered_alert,  # Use our filtered callback directly
            canary_registry={},
            db_path=os.path.join(self.output_dir, "baseline.db"),
            ignore_patterns=rt_config.get("ignore_patterns"),
            suspicious_extensions=rt_config.get("suspicious_extensions"),
            skip_baseline=True,  # Skip slow hash scan for fast start
        )
        self.engine._monitor_backend = self.engine.kernel_monitor.start()
        # Skip scan_baseline() — this is what makes it fast
        self.engine._running = True

        # Suppress engine's own console output to avoid duplicate lines
        # (we display alerts through our own _display_alert method)
        self.engine._print_alert = lambda alert: None

        self.running = True
        self.start_time = time.time()

        backend = self.engine._monitor_backend.upper()
        safe_print(f"  {GREEN}Engine started: {backend} backend{RESET}")
        safe_print(f"  {DIM}Monitoring {len(self.watch_paths)} path(s):{RESET}")
        for p in self.watch_paths:
            safe_print(f"    {CYAN}{p}{RESET}")
        safe_print(f"\n  {GREEN}{BOLD}SHIELD ACTIVE -- System-wide real-time monitoring{RESET}")
        safe_print(f"  {DIM}Press Ctrl+C to stop and generate report{RESET}")
        safe_print(f"  {'=' * 70}\n")

        # Start stats printer thread
        stats_thread = threading.Thread(target=self._stats_loop, daemon=True)
        stats_thread.start()

        # Block until Ctrl+C
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

        self._shutdown()

    def _display_alert(self, alert):
        """Display an alert in the terminal."""
        severity = alert.get("severity", "INFO")

        # In quiet mode, skip INFO
        if self.quiet and severity == "INFO":
            with self.alert_lock:
                self.alert_counts[severity] += 1
            return

        event_type = alert.get("event_type", "UNKNOWN")
        path = alert.get("path", "")
        ts = alert.get("detection_wall_time", time.time())
        pid = alert.get("pid", alert.get("details", {}).get("pid", ""))
        reason = alert.get("details", {}).get("reason", "")
        module = alert.get("module", "")
        latency = alert.get("detection_latency_ms", "")

        # Track counts
        with self.alert_lock:
            self.alert_counts[severity] += 1
            self._recent_events.append(time.time())
            # Keep only last 10 seconds
            cutoff = time.time() - 10
            self._recent_events = [t for t in self._recent_events if t > cutoff]

        try:
            time_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]
        except Exception:
            time_str = "??:??:??"

        style = SEVERITY_STYLE.get(severity, "")
        lat_str = f" {DIM}({latency}ms){RESET}" if latency else ""

        # Shorten path for display (keep last 2 components)
        display_path = path
        if len(path) > 60:
            parts = path.replace("/", "\\").split("\\")
            if len(parts) > 3:
                display_path = "...\\" + "\\".join(parts[-3:])

        # Main alert line
        pid_str = f" {PURPLE}PID:{pid}{RESET}" if pid else ""
        line = (
            f"  {style}[{severity:8s}]{RESET} "
            f"{DIM}[{time_str}]{RESET} "
            f"{WHITE}{BOLD}{event_type:22s}{RESET} "
            f"{CYAN}{display_path}{RESET}"
            f"{pid_str}{lat_str}"
        )
        safe_print(line)

        # Reason line for CRITICAL/WARNING
        if reason and severity in ("CRITICAL", "WARNING"):
            short_reason = reason[:130] + "..." if len(reason) > 130 else reason
            safe_print(f"           {DIM}>> {short_reason}{RESET}")

    def _stats_loop(self):
        """Print stats summary every 30 seconds."""
        while self.running:
            time.sleep(30)
            if not self.running:
                break
            with self.alert_lock:
                total = sum(self.alert_counts.values())
                crit = self.alert_counts.get("CRITICAL", 0)
                warn = self.alert_counts.get("WARNING", 0)
                info = self.alert_counts.get("INFO", 0)
                eps = len(self._recent_events) / 10.0

            elapsed = int(time.time() - self.start_time)
            mins, secs = divmod(elapsed, 60)

            safe_print(
                f"\n  {DIM}--- [{mins:02d}:{secs:02d}] "
                f"Total:{total} | "
                f"{RED}CRIT:{crit}{RESET}{DIM} | "
                f"{YELLOW}WARN:{warn}{RESET}{DIM} | "
                f"{BLUE}INFO:{info}{RESET}{DIM} | "
                f"Events/sec:{eps:.1f} ---{RESET}\n"
            )

    def _shutdown(self):
        """Stop monitoring and generate report."""
        safe_print(f"\n\n  {YELLOW}Stopping shield...{RESET}")
        self.running = False

        if self.engine:
            report = self.engine.stop()
            summary = report.get("summary", {})
            duration = report.get("duration_seconds", 0)

            safe_print(f"\n  {'=' * 70}")
            safe_print(f"  {GREEN}{BOLD}ANTIGRAVITY SHIELD -- SESSION REPORT{RESET}")
            safe_print(f"  {'=' * 70}")
            safe_print(f"  Duration:       {duration:.1f}s")
            safe_print(f"  Backend:        {report.get('monitor_backend', 'unknown').upper()}")
            safe_print(f"  Paths Monitored: {len(self.watch_paths)}")
            safe_print(f"")
            safe_print(f"  {BOLD}Alert Summary:{RESET}")

            by_sev = summary.get("by_severity", {})
            for sev in ["CRITICAL", "WARNING", "INFO"]:
                count = by_sev.get(sev, 0)
                style = SEVERITY_STYLE.get(sev, "")
                safe_print(f"    {style}{sev:10s}: {count}{RESET}")

            total = summary.get("total_alerts", 0)
            safe_print(f"    {'─' * 20}")
            safe_print(f"    {BOLD}TOTAL:      {total}{RESET}")

            safe_print(f"\n  {BOLD}Event Types:{RESET}")
            by_evt = summary.get("by_event_type", {})
            for evt, cnt in sorted(by_evt.items(), key=lambda x: -x[1]):
                safe_print(f"    {evt:28s}: {cnt}")

            integrity = report.get("log_integrity", {})
            status = f"{GREEN}VERIFIED{RESET}" if integrity.get("valid") else f"{RED}COMPROMISED{RESET}"
            safe_print(f"\n  Log Integrity:  {status}")
            safe_print(f"  Report:         {report.get('report_path', 'N/A')}")
            safe_print(f"  {'=' * 70}\n")

    def _print_banner(self):
        safe_print(f"""
  {GREEN}{BOLD}
     _    _   _ _____ ___  ____ ____      ___     _____ _______   __
    / \\  | \\ | |_   _|_ _|/ ___|  _ \\    / \\ \\   / /_ _|_   _\\ \\ / /
   / _ \\ |  \\| | | |  | || |  _| |_) |  / _ \\ \\ / / | |  | |  \\ V /
  / ___ \\| |\\  | | |  | || |_| |  _ <  / ___ \\ V /  | |  | |   | |
 /_/   \\_\\_| \\_| |_| |___|\\____|_| \\_\\/_/   \\_\\_/  |___| |_|   |_|
                                                                      
  {CYAN}S H I E L D   v2.0{RESET}
  {DIM}Enterprise Anti-Forensic Defense Framework{RESET}
  {DIM}System-Wide Real-Time File System Monitor{RESET}
  {DIM}MSc Cyber Security Dissertation Project{RESET}
  {'=' * 70}
""")


def main():
    parser = argparse.ArgumentParser(
        description="AntiGravity Shield v2.0 -- System-Wide Monitor"
    )
    parser.add_argument(
        "--paths", nargs="+",
        help="Specific paths to monitor (default: key system areas)"
    )
    parser.add_argument(
        "--all-drives", action="store_true",
        help="Monitor ALL drive roots (C:\\, D:\\, etc.)"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output directory for reports and logs"
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress INFO-level alerts (show only WARNING/CRITICAL)"
    )
    args = parser.parse_args()

    if args.paths:
        watch_paths = args.paths
    elif args.all_drives:
        watch_paths = get_windows_drives()
    else:
        # Default: monitor key user and system areas
        home = os.path.expanduser("~")
        watch_paths = [
            home,                                           # All of user's home directory
            os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "winevt", "Logs"),  # Event logs
        ]
        # Add Desktop explicitly (common attack target)
        desktop = os.path.join(home, "Desktop")
        if os.path.exists(desktop) and desktop not in watch_paths:
            pass  # Already covered by home

        # Add ProgramData if it exists
        progdata = os.environ.get("ProgramData", "C:\\ProgramData")
        if os.path.exists(progdata):
            watch_paths.append(progdata)

        # Filter to existing paths only
        watch_paths = [p for p in watch_paths if os.path.exists(p)]

    if not watch_paths:
        print("ERROR: No valid paths to monitor.", file=sys.stderr)
        sys.exit(1)

    shield = SystemWideShield(
        watch_paths=watch_paths,
        output_dir=args.output,
        quiet=args.quiet,
    )
    shield.start()


if __name__ == "__main__":
    main()
