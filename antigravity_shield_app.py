"""
AntiGravity Shield v2.0 -- Desktop Application
================================================
Real-time anti-forensic detection with a live GUI.
Connects to the REAL detection engine and monitors the
ACTUAL file system using watchdog (ReadDirectoryChangesW on Windows).

Usage:
    python antigravity_shield_app.py
"""
import sys
import os
import time
import json
import traceback
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from datetime import datetime

# ── Resolve source path ──
# Works whether the script is in the project root or on the VM
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
POSSIBLE_SRC_DIRS = [
    os.path.join(SCRIPT_DIR, "antigravity-shield", "src"),
    os.path.join(os.path.expanduser("~"), "antigravity-shield", "src"),
    os.path.join(SCRIPT_DIR, "src"),
]
for src_dir in POSSIBLE_SRC_DIRS:
    if os.path.exists(src_dir):
        sys.path.insert(0, src_dir)
        break

# Also ensure config can be found
CONFIG_DIR = None
for base in [SCRIPT_DIR, os.path.join(os.path.expanduser("~"), "antigravity-shield")]:
    cfg = os.path.join(base, "config", "default.yaml")
    if os.path.exists(cfg):
        CONFIG_DIR = os.path.join(base, "config")
        break

from agshield.detection.engine import DetectionEngine
from agshield.config import Config


class ShieldApp:
    """AntiGravity Shield Desktop Application with REAL detection engine."""

    VERSION = "2.0.0"

    # Dark theme colors
    BG_DARK = "#0d1117"
    BG_PANEL = "#161b22"
    BG_HEADER = "#1a2332"
    FG_TEXT = "#c9d1d9"
    FG_DIM = "#6e7681"
    GREEN = "#00ff88"
    RED = "#ff4444"
    YELLOW = "#ffaa00"
    BLUE = "#58a6ff"
    PURPLE = "#bc8cff"

    SEVERITY_COLORS = {
        "CRITICAL": "#ff4444",
        "WARNING": "#ffaa00",
        "INFO": "#58a6ff",
    }

    def __init__(self):
        self.engine = None
        self.running = False
        self.alert_count = 0
        self.critical_count = 0
        self.warning_count = 0
        self.info_count = 0
        self.start_time = 0
        self.alert_queue = []
        self.alert_lock = threading.Lock()
        self.error_log = []

        self._build_window()

    def _build_window(self):
        """Build the main application window."""
        self.root = tk.Tk()
        self.root.title("AntiGravity Shield v2.0 -- Enterprise Defense Framework")
        self.root.geometry("1100x750")
        self.root.minsize(900, 550)
        self.root.configure(bg=self.BG_DARK)

        # Try to set icon (won't crash if missing)
        try:
            self.root.iconbitmap(default="")
        except Exception:
            pass

        # ── Header ──
        header = tk.Frame(self.root, bg=self.BG_HEADER, height=60)
        header.pack(fill=tk.X)
        header.pack_propagate(False)

        title_frame = tk.Frame(header, bg=self.BG_HEADER)
        title_frame.pack(side=tk.LEFT, padx=20, pady=10)

        tk.Label(
            title_frame, text="ANTIGRAVITY SHIELD",
            font=("Consolas", 18, "bold"), fg=self.GREEN, bg=self.BG_HEADER
        ).pack(side=tk.LEFT)
        tk.Label(
            title_frame, text=f"  v{self.VERSION}",
            font=("Consolas", 12), fg=self.FG_DIM, bg=self.BG_HEADER
        ).pack(side=tk.LEFT, padx=(5, 0))

        # Status indicator
        status_frame = tk.Frame(header, bg=self.BG_HEADER)
        status_frame.pack(side=tk.RIGHT, padx=20, pady=10)

        self.status_dot = tk.Canvas(
            status_frame, width=12, height=12, bg=self.BG_HEADER,
            highlightthickness=0
        )
        self.status_dot.pack(side=tk.LEFT, padx=(0, 8))
        self.dot_id = self.status_dot.create_oval(2, 2, 10, 10, fill="#555555")

        self.status_label = tk.Label(
            status_frame, text="INACTIVE",
            font=("Consolas", 11, "bold"), fg="#555555", bg=self.BG_HEADER
        )
        self.status_label.pack(side=tk.LEFT)

        # ── Controls Bar ──
        controls = tk.Frame(self.root, bg=self.BG_PANEL, height=50)
        controls.pack(fill=tk.X, padx=0, pady=(1, 0))
        controls.pack_propagate(False)

        btn_frame = tk.Frame(controls, bg=self.BG_PANEL)
        btn_frame.pack(side=tk.LEFT, padx=15, pady=8)

        self.start_btn = tk.Button(
            btn_frame, text="  START SHIELD  ",
            font=("Consolas", 10, "bold"),
            fg="#000000", bg=self.GREEN, activebackground="#00cc66",
            relief=tk.FLAT, cursor="hand2",
            command=self._start_shield
        )
        self.start_btn.pack(side=tk.LEFT, padx=(0, 8))

        self.stop_btn = tk.Button(
            btn_frame, text="  STOP  ",
            font=("Consolas", 10, "bold"),
            fg="#ffffff", bg="#555555", activebackground="#333333",
            relief=tk.FLAT, cursor="hand2",
            command=self._stop_shield, state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 8))

        # Watch path
        path_frame = tk.Frame(controls, bg=self.BG_PANEL)
        path_frame.pack(side=tk.LEFT, padx=10, pady=8, fill=tk.X, expand=True)

        tk.Label(
            path_frame, text="Watch Path:",
            font=("Consolas", 9), fg=self.FG_DIM, bg=self.BG_PANEL
        ).pack(side=tk.LEFT)

        default_path = os.path.join(
            os.path.expanduser("~"), "Desktop", "evidence_workspace"
        )
        self.path_var = tk.StringVar(value=default_path)
        self.path_entry = tk.Entry(
            path_frame, textvariable=self.path_var,
            font=("Consolas", 9), fg=self.FG_TEXT, bg=self.BG_DARK,
            insertbackground=self.FG_TEXT, relief=tk.FLAT, width=50
        )
        self.path_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        browse_btn = tk.Button(
            path_frame, text="...",
            font=("Consolas", 9), fg=self.FG_TEXT, bg=self.BG_DARK,
            relief=tk.FLAT, cursor="hand2",
            command=self._browse_path
        )
        browse_btn.pack(side=tk.LEFT)

        # Uptime
        self.uptime_label = tk.Label(
            controls, text="",
            font=("Consolas", 9), fg=self.FG_DIM, bg=self.BG_PANEL
        )
        self.uptime_label.pack(side=tk.RIGHT, padx=15)

        # ── Stats Bar ──
        stats = tk.Frame(self.root, bg=self.BG_DARK, height=80)
        stats.pack(fill=tk.X, padx=10, pady=8)

        self.stat_widgets = {}
        for name, label, color in [
            ("total", "TOTAL ALERTS", self.GREEN),
            ("critical", "CRITICAL", self.RED),
            ("warning", "WARNING", self.YELLOW),
            ("info", "INFO", self.BLUE),
            ("backend", "BACKEND", self.PURPLE),
        ]:
            frame = tk.Frame(stats, bg=self.BG_PANEL, padx=20, pady=8)
            frame.pack(side=tk.LEFT, padx=4, fill=tk.Y)

            val_text = "0" if name != "backend" else "--"
            val = tk.Label(
                frame, text=val_text,
                font=("Consolas", 22, "bold"), fg=color, bg=self.BG_PANEL
            )
            val.pack()
            lbl = tk.Label(
                frame, text=label,
                font=("Consolas", 8), fg=self.FG_DIM, bg=self.BG_PANEL
            )
            lbl.pack()
            self.stat_widgets[name] = val

        # ── Alert Log ──
        log_header = tk.Frame(self.root, bg=self.BG_DARK)
        log_header.pack(fill=tk.X, padx=10, pady=(5, 0))
        tk.Label(
            log_header, text="LIVE ALERT FEED",
            font=("Consolas", 10, "bold"), fg=self.FG_DIM, bg=self.BG_DARK
        ).pack(side=tk.LEFT)

        self.clear_btn = tk.Button(
            log_header, text="Clear",
            font=("Consolas", 8), fg=self.FG_DIM, bg=self.BG_PANEL,
            relief=tk.FLAT, cursor="hand2",
            command=self._clear_log
        )
        self.clear_btn.pack(side=tk.RIGHT)

        self.log_text = scrolledtext.ScrolledText(
            self.root,
            font=("Consolas", 9),
            bg=self.BG_DARK, fg=self.FG_TEXT,
            insertbackground=self.FG_TEXT,
            relief=tk.FLAT, wrap=tk.WORD,
            state=tk.DISABLED,
            padx=10, pady=5
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=(2, 5))

        # Configure text tags for colors
        self.log_text.tag_configure("CRITICAL", foreground=self.RED)
        self.log_text.tag_configure("WARNING", foreground=self.YELLOW)
        self.log_text.tag_configure("INFO", foreground=self.BLUE)
        self.log_text.tag_configure("header", foreground=self.GREEN)
        self.log_text.tag_configure("dim", foreground=self.FG_DIM)
        self.log_text.tag_configure("process", foreground=self.PURPLE)
        self.log_text.tag_configure("error", foreground="#ff6666")

        # ── Footer ──
        footer = tk.Frame(self.root, bg=self.BG_PANEL, height=25)
        footer.pack(fill=tk.X, side=tk.BOTTOM)
        footer.pack_propagate(False)
        tk.Label(
            footer,
            text="AntiGravity Shield v2.0 | Kernel-Level Defense Framework | MSc Cyber Security Dissertation",
            font=("Consolas", 8), fg=self.FG_DIM, bg=self.BG_PANEL
        ).pack(side=tk.LEFT, padx=10)

        # Start periodic UI updates
        self.root.after(200, self._update_ui)

        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _browse_path(self):
        path = filedialog.askdirectory(title="Select Directory to Monitor")
        if path:
            self.path_var.set(path)

    def _log(self, text, tag=None):
        """Append text to the log widget (thread-safe via queue)."""
        with self.alert_lock:
            self.alert_queue.append((text, tag))

    def _start_shield(self):
        """Start the shield in a background thread."""
        watch_path = self.path_var.get().strip()
        if not watch_path:
            messagebox.showwarning("Warning", "Please specify a watch path.")
            return

        os.makedirs(watch_path, exist_ok=True)
        reports_dir = os.path.join(watch_path, "reports")
        os.makedirs(reports_dir, exist_ok=True)

        # Seed some evidence files if empty
        for name, content in [
            ("financial_report.txt", "CONFIDENTIAL: Q2 Financial Data 2026"),
            ("employee_data.csv", "name,role,salary\nJohn Doe,CEO,250000\nJane Smith,CTO,220000"),
            ("access_log.txt", "2026-07-16 10:00 LOGIN admin from 10.0.0.1\n2026-07-16 10:05 QUERY database"),
            ("audit_trail.log", "AUDIT: System startup complete\nAUDIT: Monitoring enabled"),
        ]:
            fpath = os.path.join(watch_path, name)
            if not os.path.exists(fpath):
                with open(fpath, "w") as f:
                    f.write(content)

        self.start_btn.configure(state=tk.DISABLED, bg="#333333")
        self.stop_btn.configure(state=tk.NORMAL, bg=self.RED)
        self.path_entry.configure(state=tk.DISABLED)

        self._log("=" * 60 + "\n", "header")
        self._log("  ANTIGRAVITY SHIELD v2.0 STARTING...\n", "header")
        self._log("=" * 60 + "\n", "header")
        self._log(f"  Watch Path: {watch_path}\n", "dim")
        self._log(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n", "dim")

        def start_engine():
            try:
                config = Config()
                config._config.setdefault("general", {})
                config._config["general"]["watch_paths"] = [watch_path]
                config._config["general"]["reports_dir"] = reports_dir
                config._config["general"]["database_path"] = os.path.join(watch_path, "baseline.db")
                config._config["general"]["log_file"] = os.path.join(watch_path, "shield.log")

                self.engine = DetectionEngine(config)

                # ── CRITICAL: Monkey-patch the engine's _on_alert to ALSO
                # ── feed alerts into the GUI queue. The engine's internal
                # ── _on_alert does all the real work (logging, behavioral
                # ── analysis, etc). We wrap it to ALSO call _handle_alert.
                original_on_alert = self.engine._on_alert

                def gui_aware_alert(alert):
                    """Wraps the real _on_alert — feeds alerts to GUI too."""
                    # Call the REAL engine alert handler first
                    original_on_alert(alert)
                    # Then feed a copy to the GUI
                    try:
                        self._handle_alert(dict(alert))
                    except Exception:
                        pass  # Never let GUI crash the engine

                # Replace the callback on the engine AND all sub-modules
                self.engine._on_alert = gui_aware_alert

                # Also patch the callbacks on sub-modules that were set
                # during __init__ (they captured the OLD _on_alert reference)
                self.engine.behavioral_detector.alert_callback = gui_aware_alert
                self.engine.timestamp_validator.alert_callback = gui_aware_alert
                self.engine.rule_engine.alert_callback = gui_aware_alert

                # Start the engine
                self.engine.start(deploy_canaries=True, canary_count=2)
                self.running = True
                self.start_time = time.time()

                backend = self.engine._monitor_backend.upper()
                self._log(f"  Backend: {backend}\n", "header")
                self._log(f"  Monitoring: {watch_path}\n", "dim")
                self._log("  SHIELD ACTIVE -- Real-time monitoring started\n", "header")
                self._log("  Waiting for file system events...\n\n", "dim")

            except Exception as e:
                tb = traceback.format_exc()
                self._log(f"\n  ERROR starting engine:\n", "error")
                self._log(f"  {str(e)}\n", "error")
                self._log(f"  {tb}\n", "dim")
                self.running = False
                # Re-enable start button on main thread
                self.root.after(0, self._reset_ui)

        threading.Thread(target=start_engine, daemon=True).start()

    def _handle_alert(self, alert):
        """Process an alert from the engine and update GUI state."""
        severity = alert.get("severity", "INFO")
        event_type = alert.get("event_type", "UNKNOWN")
        path = alert.get("path", "")
        ts = alert.get("detection_wall_time", time.time())
        pid = alert.get("pid", alert.get("details", {}).get("pid", ""))
        reason = alert.get("details", {}).get("reason", "")
        module = alert.get("module", "")

        if os.sep in str(path):
            path = os.path.basename(path)

        try:
            time_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]
        except Exception:
            time_str = "??:??:??"

        latency = alert.get("detection_latency_ms", "")
        lat_str = f" ({latency}ms)" if latency else ""

        # Update counters
        with self.alert_lock:
            self.alert_count += 1
            if severity == "CRITICAL":
                self.critical_count += 1
            elif severity == "WARNING":
                self.warning_count += 1
            else:
                self.info_count += 1

        # Format log line with module tag
        mod_tag = f"[{module}]" if module else ""
        line = f"  [{time_str}] [{severity:8s}] {event_type:22s} -> {path}{lat_str}"
        if pid:
            line += f"  (PID:{pid})"
        line += "\n"
        self._log(line, severity)

        if reason and severity in ("CRITICAL", "WARNING"):
            short_reason = reason[:120] + "..." if len(reason) > 120 else reason
            self._log(f"       >> {short_reason}\n", "dim")

    def _stop_shield(self):
        """Stop the shield."""
        if not self.running:
            return

        self._log("\n  STOPPING SHIELD...\n", "header")
        self.running = False

        def stop_engine():
            try:
                if self.engine:
                    report = self.engine.stop()
                    summary = report.get("summary", {})
                    self._log("\n" + "=" * 60 + "\n", "header")
                    self._log("  SHIELD DEACTIVATED\n", "header")
                    self._log("=" * 60 + "\n", "header")
                    self._log(f"  Total Alerts:  {summary.get('total_alerts', 0)}\n")
                    by_sev = summary.get("by_severity", {})
                    for sev_name in ["CRITICAL", "WARNING", "INFO"]:
                        count = by_sev.get(sev_name, 0)
                        if count:
                            self._log(f"    {sev_name}: {count}\n", sev_name)
                    by_evt = summary.get("by_event_type", {})
                    if by_evt:
                        self._log(f"  Event Types:\n", "dim")
                        for evt, cnt in sorted(by_evt.items(), key=lambda x: -x[1]):
                            self._log(f"    {evt}: {cnt}\n", "dim")
                    integrity = report.get("log_integrity", {})
                    status = "VERIFIED" if integrity.get("valid") else "FAILED"
                    self._log(f"  Log Integrity: {status}\n")
                    self._log(f"  Report:        {report.get('report_path', 'N/A')}\n\n")
            except Exception as e:
                self._log(f"  Error stopping: {e}\n", "error")

            self.root.after(0, self._reset_ui)

        threading.Thread(target=stop_engine, daemon=True).start()

    def _reset_ui(self):
        """Reset UI to stopped state."""
        self.start_btn.configure(state=tk.NORMAL, bg=self.GREEN)
        self.stop_btn.configure(state=tk.DISABLED, bg="#555555")
        self.path_entry.configure(state=tk.NORMAL)
        self.status_dot.itemconfig(self.dot_id, fill="#555555")
        self.status_label.configure(text="INACTIVE", fg="#555555")

    def _clear_log(self):
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state=tk.DISABLED)
        with self.alert_lock:
            self.alert_count = 0
            self.critical_count = 0
            self.warning_count = 0
            self.info_count = 0

    def _update_ui(self):
        """Periodic UI update (runs on main thread)."""
        # Process queued log entries
        with self.alert_lock:
            entries = list(self.alert_queue)
            self.alert_queue.clear()

        if entries:
            self.log_text.configure(state=tk.NORMAL)
            for text, tag in entries:
                # Sanitize for Windows console encoding
                safe_text = text.encode("ascii", errors="replace").decode("ascii")
                if tag:
                    self.log_text.insert(tk.END, safe_text, tag)
                else:
                    self.log_text.insert(tk.END, safe_text)
            self.log_text.see(tk.END)
            self.log_text.configure(state=tk.DISABLED)

        # Update stats
        with self.alert_lock:
            total = self.alert_count
            crit = self.critical_count
            warn = self.warning_count
            info = self.info_count

        self.stat_widgets["total"].configure(text=str(total))
        self.stat_widgets["critical"].configure(text=str(crit))
        self.stat_widgets["warning"].configure(text=str(warn))
        self.stat_widgets["info"].configure(text=str(info))

        # Update status indicator
        if self.running:
            self.status_dot.itemconfig(self.dot_id, fill=self.GREEN)
            self.status_label.configure(text="ACTIVE", fg=self.GREEN)
            if self.engine:
                try:
                    self.stat_widgets["backend"].configure(
                        text=self.engine._monitor_backend.upper()
                    )
                except Exception:
                    pass
            # Uptime
            if self.start_time:
                elapsed = int(time.time() - self.start_time)
                mins, secs = divmod(elapsed, 60)
                hrs, mins = divmod(mins, 60)
                if hrs > 0:
                    self.uptime_label.configure(text=f"Uptime: {hrs:02d}:{mins:02d}:{secs:02d}")
                else:
                    self.uptime_label.configure(text=f"Uptime: {mins:02d}:{secs:02d}")

        self.root.after(200, self._update_ui)

    def _on_close(self):
        """Handle window close."""
        if self.running:
            if messagebox.askyesno("Confirm", "Shield is running. Stop and exit?"):
                self.running = False
                if self.engine:
                    try:
                        self.engine.stop()
                    except Exception:
                        pass
                self.root.destroy()
        else:
            self.root.destroy()

    def run(self):
        """Start the application."""
        self.root.mainloop()


if __name__ == "__main__":
    app = ShieldApp()
    app.run()
