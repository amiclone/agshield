"""
AntiGravity Shield v2.0 - MONITOR ONLY
========================================
Self-contained real-time file system monitor.
Just watches the system and reports any suspicious activity.
Does NOT run any attacks - that's YOUR job.

Run: python shield_watch.py
"""
import os
import sys
import time
import hashlib
import string
import threading
from datetime import datetime
from collections import defaultdict

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    print("[!] Installing watchdog...")
    os.system(f"{sys.executable} -m pip install watchdog -q")
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler

if sys.platform == "win32":
    os.system("")

# Colors
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
P = "\033[95m"; C = "\033[96m"; W = "\033[97m"
BOLD = "\033[1m"; DIM = "\033[2m"; X = "\033[0m"


def sp(msg):
    try:
        print(msg, flush=True)
    except UnicodeEncodeError:
        print(msg.encode("ascii", errors="replace").decode("ascii"), flush=True)


class ShieldDetector(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.start_time = time.time()
        self.alerts = []
        self.lock = threading.Lock()
        self.file_hashes = {}
        self.file_birth = {}
        self.counts = defaultdict(int)
        self.ops_window = []  # timestamps for burst detection
        self.ignore = ["__pycache__", ".pyc", "ntuser.dat",
                       "UsrClass.dat", "thumbcache", ".tmp", "~$",
                       "shield_watch", "shield_experiment_report"]
        self.error_count = 0

    def on_error(self, event):
        """Handle watchdog errors gracefully — skip, don't crash."""
        self.error_count += 1
        # Silently skip permission errors and other OS issues

    def _is_ignored(self, path):
        low = path.lower()
        return any(p.lower() in low for p in self.ignore)

    def _ts(self):
        return datetime.now().strftime("%H:%M:%S.%f")[:-3]

    def _check_burst(self, path):
        """Detect abnormal operation bursts."""
        now = time.time()
        with self.lock:
            self.ops_window.append(now)
            self.ops_window = [t for t in self.ops_window if now - t < 2.0]
            if len(self.ops_window) >= 8:
                count = len(self.ops_window)
                self.ops_window.clear()
                self._alert("CRITICAL", "OPERATION_BURST", "multiple files",
                    f"{count} file operations in 2s window. "
                    f"Normal user activity is <1 op/sec. "
                    f"This is characteristic of automated anti-forensic tools.")

    def _alert(self, severity, event_type, path, reason=""):
        if self._is_ignored(path):
            return
        with self.lock:
            self.counts[severity] += 1
            self.counts["TOTAL"] += 1
            self.alerts.append({
                "time": self._ts(), "severity": severity,
                "event_type": event_type, "path": path, "reason": reason,
            })

        if severity == "CRITICAL":
            sev_c = f"{R}{BOLD}"; icon = "[!!!]"
        elif severity == "WARNING":
            sev_c = Y; icon = "[!] "
        else:
            sev_c = B; icon = "[i] "

        display = path
        if len(path) > 65:
            parts = path.replace("/", "\\").split("\\")
            if len(parts) > 3:
                display = "...\\" + "\\".join(parts[-3:])

        sp(f"  {sev_c}{icon} [{self._ts()}] {event_type:24s}{X} {C}{display}{X}")
        if reason:
            short = reason[:140] + "..." if len(reason) > 140 else reason
            sp(f"        {DIM}>> {short}{X}")

    def on_created(self, event):
        try:
            if event.is_directory:
                return
            path = event.src_path
            self.file_birth[path] = time.time()
            try:
                with open(path, "rb") as f:
                    h = hashlib.sha256(f.read()).hexdigest()
                self.file_hashes[path] = (h, os.path.getsize(path))
            except Exception:
                pass

            _, ext = os.path.splitext(path)
            if ext.lower() in (".exe", ".bat", ".ps1", ".vbs", ".cmd", ".dll"):
                self._alert("WARNING", "SUSPICIOUS_FILE_CREATED", path,
                            f"Executable/script created: {os.path.basename(path)}")
            else:
                self._alert("WARNING", "FILE_CREATED", path,
                            f"New file: {os.path.basename(path)}")
            self._check_burst(path)
        except Exception:
            pass  # Skip errors, don't crash

    def on_modified(self, event):
        try:
            if event.is_directory:
                return
            path = event.src_path

            # Wipe detection
            if path in self.file_hashes:
                try:
                    old_hash, old_size = self.file_hashes[path]
                    new_size = os.path.getsize(path)
                    with open(path, "rb") as f:
                        new_hash = hashlib.sha256(f.read()).hexdigest()
                    if new_hash != old_hash and new_size == old_size and old_size > 0:
                        self._alert("CRITICAL", "WIPE_DETECTED", path,
                            f"Same-size content replacement! "
                            f"Old hash: {old_hash[:12]}... New: {new_hash[:12]}... "
                            f"Signature of secure overwrite/wiping.")
                        self.file_hashes[path] = (new_hash, new_size)
                        self._check_burst(path)
                        return
                    self.file_hashes[path] = (new_hash, new_size)
                except Exception:
                    pass

            # Timestomp detection
            try:
                mtime = os.path.getmtime(path)
                ctime = os.path.getctime(path)
                now = time.time()
                mtime_age = (now - mtime) / 86400
                ctime_age = (now - ctime) / 86400
                if mtime_age > 30 and ctime_age < 1:
                    mt = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
                    ct = datetime.fromtimestamp(ctime).strftime("%Y-%m-%d %H:%M:%S")
                    self._alert("CRITICAL", "TIMESTOMPING_DETECTED", path,
                        f"mtime={mt} ({mtime_age:.0f} days old) but "
                        f"ctime={ct} ({ctime_age:.1f} days old). "
                        f"DEFINITIVE timestomping indicator!")
                    self._check_burst(path)
                    return
            except Exception:
                pass

            self._alert("INFO", "FILE_MODIFIED", path, "File content changed")
            self._check_burst(path)
        except Exception:
            pass  # Skip errors, don't crash

    def on_deleted(self, event):
        try:
            if event.is_directory:
                return
            path = event.src_path
            if path in self.file_birth:
                lifetime = time.time() - self.file_birth[path]
                if lifetime < 5.0:
                    self._alert("CRITICAL", "EPHEMERAL_FILE", path,
                        f"Created and deleted in {lifetime:.2f}s! "
                        f"Indicates malware staging or anti-forensic cleanup.")
                    del self.file_birth[path]
                    self._check_burst(path)
                    return
                del self.file_birth[path]
            self._alert("WARNING", "FILE_DELETED", path,
                         f"File deleted: {os.path.basename(path)}")
            self._check_burst(path)
        except Exception:
            pass

    def on_moved(self, event):
        try:
            if event.is_directory:
                return
            dst_name = os.path.basename(event.dest_path)
            _, ext = os.path.splitext(dst_name)
            if not ext and len(dst_name) > 8 and all(
                    c in string.ascii_letters + string.digits for c in dst_name):
                self._alert("CRITICAL", "WIPER_RENAME", event.src_path,
                    f"Renamed to random string '{dst_name}' -- "
                    f"wiper/secure-delete pattern!")
            else:
                self._alert("WARNING", "FILE_RENAMED", event.src_path,
                    f"Renamed: {os.path.basename(event.src_path)} -> {dst_name}")
            self._check_burst(event.src_path)
        except Exception:
            pass


def get_watch_dirs(home):
    """
    Get individual subdirectories under home to watch.
    Each gets its OWN observer so if one crashes, others survive.
    """
    # Priority targets
    priority = ["Desktop", "Documents", "Downloads",
                "Pictures", "Videos", "Music", ".ssh"]
    dirs = []
    for name in priority:
        p = os.path.join(home, name)
        if os.path.isdir(p):
            dirs.append(p)

    # Also watch top-level files in home (non-recursive)
    dirs.append(home)  # will be scheduled non-recursive
    return dirs


def main():
    home = os.path.expanduser("~")
    watch_dirs = get_watch_dirs(home)

    sp(f"""
  {G}{BOLD}
     _    _   _ _____ ___  ____ ____      ___     _____ _______   __
    / \\  | \\ | |_   _|_ _|/ ___|  _ \\    / \\ \\   / /_ _|_   _\\ \\ / /
   / _ \\ |  \\| | | |  | || |  _| |_) |  / _ \\ \\ / / | |  | |  \\ V /
  / ___ \\| |\\  | | |  | || |_| |  _ <  / ___ \\ V /  | |  | |   | |
 /_/   \\_\\_| \\_| |_| |___|\\____|_| \\_\\/_/   \\_\\_/  |___| |_|   |_|
  {C}S H I E L D   v2.0{X}
  {DIM}Enterprise Anti-Forensic Defense Framework{X}
  {DIM}System-Wide Real-Time File System Monitor{X}
  {'='*60}
{X}""")

    sp(f"  {G}[SHIELD]{X} Backend:  {C}WATCHDOG (ReadDirectoryChangesW){X}")
    sp(f"  {G}[SHIELD]{X} Platform: {C}{sys.platform} / Python {sys.version.split()[0]}{X}")
    sp(f"  {G}[SHIELD]{X} Host:     {C}{os.environ.get('COMPUTERNAME', 'unknown')}{X}")
    sp(f"  {G}[SHIELD]{X} Time:     {C}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{X}")
    sp(f"  {G}[SHIELD]{X} Watching ({len(watch_dirs)} zones):")
    for wp in watch_dirs:
        sp(f"    {C}{wp}{X}")
    sp(f"")

    detector = ShieldDetector()

    # ── Start one observer per directory (fault isolation) ──
    observers = {}
    for d in watch_dirs:
        try:
            obs = Observer()
            recursive = (d != home)  # home itself is non-recursive
            obs.schedule(detector, d, recursive=recursive)
            obs.start()
            observers[d] = obs
            label = "recursive" if recursive else "top-level only"
            sp(f"  {G}[OK]{X} {os.path.basename(d) or d} ({label})")
        except Exception as e:
            sp(f"  {Y}[SKIP]{X} {d} -- {e}")

    sp(f"")
    sp(f"  {G}{BOLD}SHIELD ACTIVE -- {len(observers)} monitors running{X}")
    sp(f"  {DIM}  Create, delete, or modify any file to see real-time alerts.{X}")
    sp(f"  {DIM}  Press Ctrl+C to stop and see the report.{X}")
    sp(f"  {'='*60}")
    sp(f"")

    last_heartbeat = time.time()
    heartbeat_interval = 30

    try:
        while True:
            time.sleep(5)

            now = time.time()

            # ── Health check: restart any dead observers ──
            for d, obs in list(observers.items()):
                if not obs.is_alive():
                    sp(f"  {Y}[SHIELD] Restarting observer for {os.path.basename(d)}...{X}")
                    try:
                        obs.stop()
                    except Exception:
                        pass
                    try:
                        new_obs = Observer()
                        recursive = (d != home)
                        new_obs.schedule(detector, d, recursive=recursive)
                        new_obs.start()
                        observers[d] = new_obs
                        sp(f"  {G}[SHIELD] Restarted OK{X}")
                    except Exception:
                        del observers[d]

            # ── Heartbeat ──
            if now - last_heartbeat >= heartbeat_interval:
                last_heartbeat = now
                elapsed = int(now - detector.start_time)
                m, s = divmod(elapsed, 60)
                with detector.lock:
                    t = detector.counts.get("TOTAL", 0)
                    c = detector.counts.get("CRITICAL", 0)
                    w = detector.counts.get("WARNING", 0)
                    i = detector.counts.get("INFO", 0)
                alive = sum(1 for o in observers.values() if o.is_alive())
                sp(f"  {DIM}[{m:02d}:{s:02d}] SHIELD ALIVE | "
                   f"Total:{t} | {R}CRIT:{c}{X}{DIM} | "
                   f"{Y}WARN:{w}{X}{DIM} | {B}INFO:{i}{X}{DIM} | "
                   f"{alive}/{len(observers)} monitors up{X}")

    except KeyboardInterrupt:
        pass

    sp(f"\n  {Y}Stopping...{X}")
    for obs in observers.values():
        try:
            obs.stop()
            obs.join(timeout=3)
        except Exception:
            pass

    # Report
    sp(f"\n  {'='*60}")
    sp(f"  {G}{BOLD}SHIELD SESSION REPORT{X}")
    sp(f"  {'='*60}")
    with detector.lock:
        sp(f"    {R}CRITICAL : {detector.counts.get('CRITICAL', 0)}{X}")
        sp(f"    {Y}WARNING  : {detector.counts.get('WARNING', 0)}{X}")
        sp(f"    {B}INFO     : {detector.counts.get('INFO', 0)}{X}")
        sp(f"    {W}{BOLD}TOTAL    : {detector.counts.get('TOTAL', 0)}{X}")
    sp(f"")

    evt_counts = defaultdict(int)
    for a in detector.alerts:
        evt_counts[a["event_type"]] += 1
    sp(f"  {BOLD}Events:{X}")
    for evt, cnt in sorted(evt_counts.items(), key=lambda x: -x[1]):
        sp(f"    {evt:28s}: {cnt}")

    crits = [a for a in detector.alerts if a["severity"] == "CRITICAL"]
    if crits:
        sp(f"\n  {BOLD}Critical Findings:{X}")
        for a in crits:
            sp(f"    {R}[!!!]{X} {a['event_type']:24s} {C}{os.path.basename(a['path'])}{X}")

    import json
    rpath = os.path.join(home, "Desktop", "shield_experiment_report.json")
    with open(rpath, "w") as f:
        json.dump({"alerts": detector.alerts, "counts": dict(detector.counts),
                    "events": dict(evt_counts)}, f, indent=2, default=str)
    sp(f"\n  {G}Report: {rpath}{X}")
    sp(f"  {'='*60}\n")
    input("  Press Enter to exit...")


if __name__ == "__main__":
    main()

