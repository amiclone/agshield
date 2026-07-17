"""
AntiGravity Shield v2.0 - LIVE DEMO
====================================
Self-contained. No external dependencies except watchdog + psutil.
Monitors the ENTIRE user directory and detects real attacks.

This script:
  1) Starts real-time file system monitoring (ReadDirectoryChangesW)
  2) After 3 seconds, launches a REAL attack sequence
  3) Shows every detection with full file paths and timestamps
  4) Generates a final report

Run: python shield_live_demo.py
"""
import os
import sys
import time
import hashlib
import random
import string
import threading
from datetime import datetime
from collections import defaultdict

# ── Ensure watchdog + psutil are available ──
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    print("[!] Installing watchdog...")
    os.system(f"{sys.executable} -m pip install watchdog -q")
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler

try:
    import psutil
except ImportError:
    print("[!] Installing psutil...")
    os.system(f"{sys.executable} -m pip install psutil -q")
    import psutil

# ── Enable ANSI colors on Windows ──
if sys.platform == "win32":
    os.system("")

# ── Colors ──
R = "\033[91m"    # Red
G = "\033[92m"    # Green
Y = "\033[93m"    # Yellow
B = "\033[94m"    # Blue
P = "\033[95m"    # Purple
C = "\033[96m"    # Cyan
W = "\033[97m"    # White
BOLD = "\033[1m"
DIM = "\033[2m"
X = "\033[0m"     # Reset


def sp(msg):
    """Safe print for Windows console."""
    try:
        print(msg, flush=True)
    except UnicodeEncodeError:
        print(msg.encode("ascii", errors="replace").decode("ascii"), flush=True)


class ShieldDetector(FileSystemEventHandler):
    """
    Real-time file system event detector.
    Uses Windows ReadDirectoryChangesW via watchdog.
    """

    def __init__(self, watch_dir):
        super().__init__()
        self.watch_dir = os.path.normpath(watch_dir)
        self.start_time = time.time()
        self.alerts = []
        self.lock = threading.Lock()
        self.file_hashes = {}      # path -> (hash, size, mtime) for wipe detection
        self.file_birth = {}       # path -> creation_time for ephemeral detection
        self.counts = defaultdict(int)

        # Noise: ignore our own report file and common Windows temp churn
        self.ignore = [
            "shield_live_demo",
            "__pycache__",
            ".pyc",
            "ntuser.dat",
            "UsrClass.dat",
            "thumbcache",
            ".tmp",
            "~$",
        ]

    def _is_ignored(self, path):
        low = path.lower()
        for pat in self.ignore:
            if pat.lower() in low:
                return True
        return False

    def _ts(self):
        return datetime.now().strftime("%H:%M:%S.%f")[:-3]

    def _latency(self):
        return f"{(time.time() - self.start_time)*1000:.0f}ms"

    def _alert(self, severity, event_type, path, reason=""):
        """Record and display an alert."""
        if self._is_ignored(path):
            return

        with self.lock:
            self.counts[severity] += 1
            self.counts["TOTAL"] += 1
            alert = {
                "time": self._ts(),
                "severity": severity,
                "event_type": event_type,
                "path": path,
                "reason": reason,
            }
            self.alerts.append(alert)

        # Color based on severity
        if severity == "CRITICAL":
            sev_c = f"{R}{BOLD}"
            icon = "[!!!]"
        elif severity == "WARNING":
            sev_c = Y
            icon = "[!] "
        else:
            sev_c = B
            icon = "[i] "

        # Shorten path
        display = path
        if len(path) > 65:
            parts = path.replace("/", "\\").split("\\")
            if len(parts) > 3:
                display = "...\\" + "\\".join(parts[-3:])

        sp(f"  {sev_c}{icon} [{self._ts()}] {event_type:24s}{X} {C}{display}{X}")
        if reason:
            short = reason[:140] + "..." if len(reason) > 140 else reason
            sp(f"        {DIM}>> {short}{X}")

    # ── Watchdog event handlers ──

    def on_created(self, event):
        if event.is_directory:
            return
        path = event.src_path

        # Track file birth time
        self.file_birth[path] = time.time()

        # Record initial hash for wipe detection
        try:
            with open(path, "rb") as f:
                h = hashlib.sha256(f.read()).hexdigest()
            sz = os.path.getsize(path)
            self.file_hashes[path] = (h, sz, os.path.getmtime(path))
        except Exception:
            pass

        # Check for suspicious extensions
        _, ext = os.path.splitext(path)
        if ext.lower() in (".exe", ".bat", ".ps1", ".vbs", ".cmd", ".dll"):
            self._alert("WARNING", "SUSPICIOUS_FILE_CREATED", path,
                        f"Executable/script created: {os.path.basename(path)}")
        else:
            self._alert("WARNING", "FILE_CREATED", path,
                        f"New file: {os.path.basename(path)}")

    def on_modified(self, event):
        if event.is_directory:
            return
        path = event.src_path

        # ── Wipe detection: same-size content replacement ──
        if path in self.file_hashes:
            try:
                old_hash, old_size, _ = self.file_hashes[path]
                new_size = os.path.getsize(path)
                with open(path, "rb") as f:
                    new_hash = hashlib.sha256(f.read()).hexdigest()

                if new_hash != old_hash and new_size == old_size and old_size > 0:
                    self._alert("CRITICAL", "WIPE_DETECTED", path,
                                f"Same-size content replacement! Old hash: {old_hash[:12]}... New hash: {new_hash[:12]}... "
                                f"This is a signature of secure overwrite/wiping.")
                    self.file_hashes[path] = (new_hash, new_size, os.path.getmtime(path))
                    return

                self.file_hashes[path] = (new_hash, new_size, os.path.getmtime(path))
            except Exception:
                pass

        # ── Timestomp detection: mtime vs current time ──
        try:
            mtime = os.path.getmtime(path)
            ctime = os.path.getctime(path)
            now = time.time()
            mtime_age_days = (now - mtime) / 86400
            ctime_age_days = (now - ctime) / 86400

            if mtime_age_days > 30 and ctime_age_days < 1:
                mtime_str = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
                ctime_str = datetime.fromtimestamp(ctime).strftime("%Y-%m-%d %H:%M:%S")
                self._alert("CRITICAL", "TIMESTOMPING_DETECTED", path,
                            f"mtime={mtime_str} ({mtime_age_days:.0f} days old) but "
                            f"ctime={ctime_str} ({ctime_age_days:.1f} days old). "
                            f"DEFINITIVE timestomping indicator!")
                return
        except Exception:
            pass

        self._alert("INFO", "FILE_MODIFIED", path, "File content changed")

    def on_deleted(self, event):
        if event.is_directory:
            return
        path = event.src_path

        # ── Ephemeral file detection ──
        if path in self.file_birth:
            lifetime = time.time() - self.file_birth[path]
            if lifetime < 5.0:
                self._alert("CRITICAL", "EPHEMERAL_FILE", path,
                            f"File created and deleted in {lifetime:.2f}s! "
                            f"Indicates malware staging or anti-forensic cleanup.")
                del self.file_birth[path]
                return
            del self.file_birth[path]

        self._alert("WARNING", "FILE_DELETED", path,
                     f"File deleted: {os.path.basename(path)}")

    def on_moved(self, event):
        if event.is_directory:
            return
        src = event.src_path
        dst = event.dest_path

        # ── Rename to random string = wiper behavior ──
        dst_name = os.path.basename(dst)
        _, ext = os.path.splitext(dst_name)
        if not ext and len(dst_name) > 8 and all(c in string.ascii_letters + string.digits for c in dst_name):
            self._alert("CRITICAL", "WIPER_RENAME", src,
                        f"Renamed to random string '{dst_name}' -- this is a wiper/secure-delete pattern!")
        else:
            self._alert("WARNING", "FILE_RENAMED", src,
                        f"Renamed: {os.path.basename(src)} -> {os.path.basename(dst)}")


def run_attack(target_dir):
    """
    Execute a REAL anti-forensic attack sequence.
    This creates, modifies, timestomps, wipes, and deletes REAL files.
    """
    sp(f"\n  {R}{BOLD}{'='*60}{X}")
    sp(f"  {R}{BOLD}  ATTACK SEQUENCE STARTING IN TARGET DIRECTORY{X}")
    sp(f"  {R}{BOLD}  {target_dir}{X}")
    sp(f"  {R}{BOLD}{'='*60}{X}\n")

    attack_dir = os.path.join(target_dir, "evidence_data")
    os.makedirs(attack_dir, exist_ok=True)
    time.sleep(1)

    # ── Phase 1: Drop evidence files ──
    sp(f"  {Y}[ATTACKER] Phase 1: Creating evidence files...{X}")
    files_created = []
    evidence = {
        "financial_records.xlsx": "CONFIDENTIAL: Q2 Revenue $4.2M, Expenses $3.1M, Net Profit $1.1M",
        "employee_ssn.csv": "Name,SSN,Salary\nJohn Doe,123-45-6789,$95000\nJane Smith,987-65-4321,$120000",
        "server_access.log": "2026-07-16 14:22:01 LOGIN root@10.0.0.5 SSH\n2026-07-16 14:23:15 QUERY SELECT * FROM users\n2026-07-16 14:24:00 EXFIL data.tar.gz -> 185.220.101.1",
        "malware_payload.exe": "MZ" + "\x00" * 50 + "This is a simulated PE executable payload",
        "credentials.txt": "admin:P@ssw0rd123!\nroot:toor\ndb_user:s3cur3_p@ss",
    }
    for fname, content in evidence.items():
        fpath = os.path.join(attack_dir, fname)
        with open(fpath, "w") as f:
            f.write(content)
        files_created.append(fpath)
        time.sleep(0.3)

    sp(f"  {Y}[ATTACKER] Created {len(files_created)} evidence files{X}")
    time.sleep(1)

    # ── Phase 2: Timestomping ──
    sp(f"  {Y}[ATTACKER] Phase 2: Timestomping malware_payload.exe...{X}")
    mal_path = os.path.join(attack_dir, "malware_payload.exe")
    # Backdate to January 2024 (makes it look like an old system file)
    fake_time = datetime(2024, 1, 15, 8, 30, 0).timestamp()
    os.utime(mal_path, (fake_time, fake_time))
    time.sleep(1)

    sp(f"  {Y}[ATTACKER] Phase 3: Timestomping credentials.txt...{X}")
    cred_path = os.path.join(attack_dir, "credentials.txt")
    fake_time2 = datetime(2023, 6, 1, 12, 0, 0).timestamp()
    os.utime(cred_path, (fake_time2, fake_time2))
    time.sleep(1)

    # ── Phase 3: Secure wipe (overwrite with same-size random data) ──
    sp(f"  {Y}[ATTACKER] Phase 4: Secure wiping financial_records.xlsx...{X}")
    fin_path = os.path.join(attack_dir, "financial_records.xlsx")
    if os.path.exists(fin_path):
        sz = os.path.getsize(fin_path)
        for pass_num in range(3):
            with open(fin_path, "wb") as f:
                f.write(os.urandom(sz))
            sp(f"  {DIM}[ATTACKER] Wipe pass {pass_num+1}/3 complete{X}")
            time.sleep(0.5)

        # Rename to random string (wiper pattern)
        random_name = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
        renamed_path = os.path.join(attack_dir, random_name)
        os.rename(fin_path, renamed_path)
        time.sleep(0.3)

        # Delete the renamed file
        os.remove(renamed_path)
        sp(f"  {Y}[ATTACKER] financial_records.xlsx securely destroyed{X}")
    time.sleep(1)

    # ── Phase 4: Secure wipe of SSN data ──
    sp(f"  {Y}[ATTACKER] Phase 5: Wiping employee_ssn.csv...{X}")
    ssn_path = os.path.join(attack_dir, "employee_ssn.csv")
    if os.path.exists(ssn_path):
        sz = os.path.getsize(ssn_path)
        for pass_num in range(3):
            with open(ssn_path, "wb") as f:
                f.write(os.urandom(sz))
            time.sleep(0.3)
        random_name2 = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
        renamed2 = os.path.join(attack_dir, random_name2)
        os.rename(ssn_path, renamed2)
        time.sleep(0.2)
        os.remove(renamed2)
        sp(f"  {Y}[ATTACKER] employee_ssn.csv securely destroyed{X}")
    time.sleep(1)

    # ── Phase 5: Rapid file creation + deletion (staging pattern) ──
    sp(f"  {Y}[ATTACKER] Phase 6: Rapid staging/cleanup (ephemeral files)...{X}")
    for i in range(5):
        tmp = os.path.join(attack_dir, f"exfil_stage_{i}.tmp")
        with open(tmp, "w") as f:
            f.write(f"exfiltration payload chunk {i} " * 50)
        time.sleep(0.1)
        os.remove(tmp)
        time.sleep(0.1)
    sp(f"  {Y}[ATTACKER] Staging files cleaned up{X}")
    time.sleep(1)

    # ── Phase 6: Log tampering simulation ──
    sp(f"  {Y}[ATTACKER] Phase 7: Tampering with access log...{X}")
    log_path = os.path.join(attack_dir, "server_access.log")
    if os.path.exists(log_path):
        with open(log_path, "w") as f:
            f.write("")  # Truncate to zero
        time.sleep(0.5)
        os.remove(log_path)
    sp(f"  {Y}[ATTACKER] Access log destroyed{X}")
    time.sleep(1)

    # ── Phase 7: Clean remaining evidence ──
    sp(f"  {Y}[ATTACKER] Phase 8: Final cleanup - deleting remaining files...{X}")
    for f in os.listdir(attack_dir):
        fpath = os.path.join(attack_dir, f)
        if os.path.isfile(fpath):
            os.remove(fpath)
            time.sleep(0.2)

    try:
        os.rmdir(attack_dir)
    except Exception:
        pass

    sp(f"\n  {R}{BOLD}  ATTACK SEQUENCE COMPLETE{X}")
    sp(f"  {DIM}  All evidence has been destroyed by the attacker.{X}\n")


def main():
    home = os.path.expanduser("~")
    desktop = os.path.join(home, "Desktop")
    target_dir = os.path.join(desktop, "shield_experiment")
    os.makedirs(target_dir, exist_ok=True)

    sp(f"""
  {G}{BOLD}
     _    _   _ _____ ___  ____ ____      ___     _____ _______   __
    / \\  | \\ | |_   _|_ _|/ ___|  _ \\    / \\ \\   / /_ _|_   _\\ \\ / /
   / _ \\ |  \\| | | |  | || |  _| |_) |  / _ \\ \\ / / | |  | |  \\ V /
  / ___ \\| |\\  | | |  | || |_| |  _ <  / ___ \\ V /  | |  | |   | |
 /_/   \\_\\_| \\_| |_| |___|\\____|_| \\_\\/_/   \\_\\_/  |___| |_|   |_|
  {C}S H I E L D   v2.0  --  LIVE EXPERIMENT{X}
  {DIM}Enterprise Anti-Forensic Defense Framework{X}
  {DIM}MSc Cyber Security Dissertation - Real-Time Detection Demo{X}
  {'='*60}
{X}""")

    sp(f"  {G}[SHIELD]{X} Target directory: {C}{target_dir}{X}")
    sp(f"  {G}[SHIELD]{X} Backend: {C}WATCHDOG (ReadDirectoryChangesW){X}")
    sp(f"  {G}[SHIELD]{X} Platform: {C}{sys.platform} / Python {sys.version.split()[0]}{X}")
    sp(f"  {G}[SHIELD]{X} Time: {C}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{X}")
    sp(f"  {G}[SHIELD]{X} Hostname: {C}{os.environ.get('COMPUTERNAME', 'unknown')}{X}")
    sp(f"")
    sp(f"  {G}[SHIELD]{X} Starting real-time file system monitor...")

    # ── Start watchdog observer ──
    detector = ShieldDetector(target_dir)
    observer = Observer()
    observer.schedule(detector, target_dir, recursive=True)
    observer.start()

    sp(f"  {G}[SHIELD]{X} {G}{BOLD}MONITOR ACTIVE{X} -- watching {C}{target_dir}{X}")
    sp(f"")
    sp(f"  {DIM}{'='*60}{X}")
    sp(f"  {DIM}  DETECTION LOG (real-time alerts from file system events){X}")
    sp(f"  {DIM}{'='*60}{X}")
    sp(f"")

    # Give watchdog 2 seconds to fully initialize
    time.sleep(2)

    # ── Run the attack in a background thread ──
    attack_thread = threading.Thread(target=run_attack, args=(target_dir,))
    attack_thread.start()
    attack_thread.join()

    # Wait for final events to propagate
    sp(f"\n  {G}[SHIELD]{X} Waiting for final event propagation...")
    time.sleep(3)

    # ── Stop and report ──
    observer.stop()
    observer.join()

    sp(f"\n  {'='*60}")
    sp(f"  {G}{BOLD}ANTIGRAVITY SHIELD -- EXPERIMENT REPORT{X}")
    sp(f"  {'='*60}")
    sp(f"")
    sp(f"  {BOLD}Detection Summary:{X}")
    sp(f"    {R}CRITICAL : {detector.counts.get('CRITICAL', 0)}{X}")
    sp(f"    {Y}WARNING  : {detector.counts.get('WARNING', 0)}{X}")
    sp(f"    {B}INFO     : {detector.counts.get('INFO', 0)}{X}")
    sp(f"    {W}{'─'*25}{X}")
    sp(f"    {W}{BOLD}TOTAL    : {detector.counts.get('TOTAL', 0)}{X}")
    sp(f"")

    # Count by event type
    event_counts = defaultdict(int)
    for a in detector.alerts:
        event_counts[a["event_type"]] += 1

    sp(f"  {BOLD}Events Detected:{X}")
    for evt, cnt in sorted(event_counts.items(), key=lambda x: -x[1]):
        color = R if "WIPE" in evt or "TIMESTOMP" in evt or "EPHEMERAL" in evt else Y
        sp(f"    {color}{evt:28s}: {cnt}{X}")

    sp(f"")
    sp(f"  {BOLD}Key Findings:{X}")
    critical_events = [a for a in detector.alerts if a["severity"] == "CRITICAL"]
    for a in critical_events:
        sp(f"    {R}[!!!]{X} {a['event_type']:24s} {C}{os.path.basename(a['path'])}{X}")
        if a["reason"]:
            sp(f"          {DIM}{a['reason'][:100]}{X}")

    # Save JSON report
    import json
    report_path = os.path.join(desktop, "shield_experiment_report.json")
    report = {
        "timestamp": datetime.now().isoformat(),
        "platform": sys.platform,
        "hostname": os.environ.get("COMPUTERNAME", "unknown"),
        "target_dir": target_dir,
        "total_alerts": detector.counts.get("TOTAL", 0),
        "by_severity": dict(detector.counts),
        "by_event_type": dict(event_counts),
        "alerts": detector.alerts,
    }
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    sp(f"\n  {G}Report saved: {report_path}{X}")
    sp(f"  {'='*60}")
    sp(f"  {G}{BOLD}EXPERIMENT COMPLETE{X}")
    sp(f"  {'='*60}")
    sp(f"")
    input("  Press Enter to exit...")


if __name__ == "__main__":
    main()
