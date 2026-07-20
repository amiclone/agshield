"""
AntiGravity Shield v3.0 — AI-Powered Anti-Forensic Defense
============================================================
Layers: Process Attribution | Attack Chain Correlation |
        AI Anomaly Engine | Human-in-the-Loop Response |
        SIEM Integration | Forensic Timeline | Canary |
        Metadata Scanner (hybrid event+poll)
"""
import os, sys, time, math, hashlib, string, shutil, json, threading, socket, logging
from datetime import datetime
from collections import defaultdict, deque

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    os.system(f"{sys.executable} -m pip install watchdog -q")
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

if sys.platform == "win32":
    os.system("")

R="\033[91m";G="\033[92m";Y="\033[93m";B="\033[94m"
P="\033[95m";C="\033[96m";W="\033[97m"
BOLD="\033[1m";DIM="\033[2m";X="\033[0m"

def sp(msg):
    try: print(msg, flush=True)
    except: print(msg.encode("ascii","replace").decode("ascii"), flush=True)

# ═══════════════════════════════════════════════════════════
# LAYER 1: Process Attribution
# ═══════════════════════════════════════════════════════════
class ProcessTracker:
    SUSPICIOUS = {"python","python3","python.exe","python3.exe","perl",
        "powershell","powershell.exe","cmd.exe","wscript","cscript",
        "bash","sh","node","ruby","mshta","pwsh","pwsh.exe"}

    def __init__(self):
        self._cache = {}
        self._lock = threading.Lock()

    def get_for_path(self, path):
        """Find which process has a handle on this file path."""
        if not HAS_PSUTIL:
            return {"pid": 0, "name": "unknown", "cmdline": "", "user": ""}
        try:
            # Check recent processes that touched files
            for proc in psutil.process_iter(['pid','name','cmdline','username']):
                try:
                    pinfo = proc.info
                    if pinfo['cmdline']:
                        cmdline = " ".join(pinfo['cmdline'])
                        if path in cmdline or os.path.basename(path) in cmdline:
                            return {
                                "pid": pinfo['pid'], "name": pinfo['name'] or "unknown",
                                "cmdline": cmdline[:200], "user": pinfo['username'] or "",
                            }
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception:
            pass
        return {"pid": 0, "name": "unknown", "cmdline": "", "user": ""}

    def is_suspicious(self, name):
        return name.lower() in self.SUSPICIOUS

# ═══════════════════════════════════════════════════════════
# LAYER 2: AI Anomaly Engine (Rolling Statistics)
# ═══════════════════════════════════════════════════════════
class AnomalyEngine:
    def __init__(self, alert_cb=None, learn_secs=60):
        self.alert_cb = alert_cb
        self.learn_secs = learn_secs
        self.start = time.time()
        self._times = deque(maxlen=5000)
        self._sev = deque(maxlen=200)
        self._rate_n = 0; self._rate_mean = 0.0; self._rate_m2 = 0.0
        self._sev_n = 0; self._sev_mean = 0.0; self._sev_m2 = 0.0
        self._last = time.time()
        self.anomalies = 0
        self.learned = False

    def feed(self, event):
        now = time.time()
        self._times.append(now)
        self._sev.append(1.0 if event.get("severity") == "CRITICAL" else 0.0)
        if now - self._last >= 5.0:
            self._last = now
            self._check(now)

    def _welford_add(self, which, val):
        if which == "rate":
            self._rate_n += 1
            d = val - self._rate_mean
            self._rate_mean += d / self._rate_n
            self._rate_m2 += d * (val - self._rate_mean)
        else:
            self._sev_n += 1
            d = val - self._sev_mean
            self._sev_mean += d / self._sev_n
            self._sev_m2 += d * (val - self._sev_mean)

    def _std(self, which):
        n, m2 = (self._rate_n, self._rate_m2) if which == "rate" else (self._sev_n, self._sev_m2)
        return math.sqrt(m2 / n) if n > 2 else 0

    def _check(self, now):
        cutoff = now - 60.0
        rate = sum(1 for t in self._times if t > cutoff)
        self._welford_add("rate", float(rate))
        if self._sev:
            cr = sum(self._sev) / len(self._sev)
            self._welford_add("sev", cr)
        if now - self.start < self.learn_secs:
            return
        if not self.learned and self._rate_n >= 5:
            self.learned = True
        if not self.learned:
            return
        # Rate anomaly
        std = self._std("rate")
        if std > 0 and rate > 10:
            z = abs(rate - self._rate_mean) / std
            if z > 2.5:
                self.anomalies += 1
                if self.alert_cb:
                    self.alert_cb("CRITICAL", "AI_RATE_ANOMALY", "system-wide",
                        f"File ops rate ({rate}/min) is {z:.1f}σ above baseline "
                        f"(mean={self._rate_mean:.0f}/min). Automated activity detected.")

    def summary(self):
        return {"learned": self.learned, "rate_mean": round(self._rate_mean,1),
                "rate_std": round(self._std("rate"),1), "anomalies": self.anomalies}

# ═══════════════════════════════════════════════════════════
# LAYER 3: Attack Chain Correlator
# ═══════════════════════════════════════════════════════════
PHASE_MAP = {"FILE_CREATED":"CREATE","SUSPICIOUS_FILE_CREATED":"CREATE",
    "FILE_MODIFIED":"MODIFY","WIPE_DETECTED":"WIPE",
    "TIMESTOMPING_DETECTED":"TIMESTOMP","WIPER_RENAME":"RENAME_RANDOM",
    "FILE_DELETED":"DELETE","FILE_RENAMED":"RENAME","EPHEMERAL_FILE":"EPHEMERAL"}

PATTERNS = {
    "EVIDENCE_DESTRUCTION": (["CREATE","MODIFY","WIPE","RENAME_RANDOM","DELETE"], 3),
    "TIMESTOMP_CAMPAIGN": (["CREATE","MODIFY","TIMESTOMP"], 2),
    "DATA_STAGING": (["CREATE","MODIFY","DELETE"], 3),
}

class ChainCorrelator:
    def __init__(self, window=30.0, alert_cb=None):
        self.window = window
        self.alert_cb = alert_cb
        self._events = []
        self._phases = []
        self._last_time = 0
        self._alerted = set()
        self._lock = threading.Lock()
        self.chains_detected = 0

    def feed(self, event):
        now = time.time()
        with self._lock:
            if self._last_time and now - self._last_time > self.window:
                self._events.clear(); self._phases.clear()
                self._alerted.clear()
            self._last_time = now
            self._events.append(event)
            phase = PHASE_MAP.get(event.get("event_type",""), "OTHER")
            self._phases.append(phase)
            self._classify()

    def _classify(self):
        for name, (required, min_match) in PATTERNS.items():
            if name in self._alerted:
                continue
            matched = 0; idx = 0
            for p in self._phases:
                if idx < len(required) and p == required[idx]:
                    matched += 1; idx += 1
            if matched >= min_match:
                self._alerted.add(name)
                self.chains_detected += 1
                n = len(self._events)
                if self.alert_cb:
                    self.alert_cb("CRITICAL", f"ATTACK_CHAIN_{name}",
                        f"{len(set(e.get('path','') for e in self._events))} files",
                        f"Multi-phase attack detected: {name} ({n} events, "
                        f"{matched}/{len(required)} phases matched)")

# ═══════════════════════════════════════════════════════════
# LAYER 4: Response Engine (Human-in-the-Loop)
# ═══════════════════════════════════════════════════════════
class ResponseEngine:
    def __init__(self):
        home = os.path.expanduser("~")
        self.vault_dir = os.path.join(home, "Desktop", "shield_evidence_vault")
        os.makedirs(self.vault_dir, exist_ok=True)
        self.preserved = []
        self.pending = []
        self.history = []
        self._lock = threading.Lock()
        self._next_id = 1

    def on_critical(self, event_type, path, pid=0, proc_name=""):
        # Auto-preserve evidence
        if event_type in ("WIPE_DETECTED","TIMESTOMPING_DETECTED","WIPER_RENAME"):
            vp = self._preserve(path, event_type)
            if vp:
                sp(f"  {G}[VAULT]{X} Preserved: {C}{os.path.basename(path)}{X}")
        # Recommend action (human must approve)
        if pid and proc_name and event_type in ("WIPE_DETECTED","WIPER_RENAME"):
            aid = self._next_id; self._next_id += 1
            action = {"id": aid, "type": "KILL_PROCESS", "pid": pid,
                       "proc": proc_name, "reason": event_type, "path": path}
            with self._lock:
                self.pending.append(action)
            sp(f"")
            sp(f"  {R}{BOLD}╔════════════════════════════════════════════════╗{X}")
            sp(f"  {R}{BOLD}║  RECOMMENDED ACTION — HUMAN APPROVAL REQUIRED  ║{X}")
            sp(f"  {R}{BOLD}╠════════════════════════════════════════════════╣{X}")
            sp(f"  {R}{BOLD}║{X}  Kill: {Y}{proc_name} (PID {pid}){X}")
            sp(f"  {R}{BOLD}║{X}  Why:  {W}{event_type} on {os.path.basename(path)}{X}")
            sp(f"  {R}{BOLD}║{X}  {G}Type: approve {aid}  |  deny {aid}{X}")
            sp(f"  {R}{BOLD}╚════════════════════════════════════════════════╝{X}")
            sp(f"")

    def handle_cmd(self, cmd):
        parts = cmd.strip().lower().split()
        if len(parts) != 2 or parts[0] not in ("approve","deny"):
            return False
        try: aid = int(parts[1])
        except: return False
        with self._lock:
            act = next((a for a in self.pending if a["id"] == aid), None)
            if not act:
                sp(f"  {Y}Action #{aid} not found{X}"); return True
            self.pending.remove(act)
            if parts[0] == "approve" and HAS_PSUTIL:
                try:
                    psutil.Process(act["pid"]).terminate()
                    sp(f"  {R}[KILLED]{X} {act['proc']} (PID {act['pid']})")
                except Exception as e:
                    sp(f"  {Y}[FAIL]{X} {e}")
            else:
                sp(f"  {Y}[DENIED]{X} Action #{aid}")
            self.history.append(act)
        return True

    def _preserve(self, path, reason):
        try:
            if not os.path.exists(path) or os.path.getsize(path) > 50*1024*1024:
                return None
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            dst = os.path.join(self.vault_dir, f"{ts}_{os.path.basename(path)}")
            shutil.copy2(path, dst)
            h = hashlib.sha256(open(dst,"rb").read()).hexdigest()
            self.preserved.append({"src":path,"dst":dst,"hash":h,"time":ts})
            return dst
        except: return None

# ═══════════════════════════════════════════════════════════
# LAYER 5a: SIEM Integration (Syslog CEF)
# ═══════════════════════════════════════════════════════════
class SIEMConnector:
    """Forwards alerts to SIEM via syslog (CEF format) or file."""
    SEV_MAP = {"CRITICAL":10,"WARNING":5,"INFO":1}

    def __init__(self, syslog_host=None, syslog_port=514, log_file=None):
        self.host = syslog_host
        self.port = syslog_port
        self.sock = None
        home = os.path.expanduser("~")
        self.log_file = log_file or os.path.join(home,"Desktop","shield_siem.log")
        self.sent = 0
        if self.host:
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            except: pass

    def forward(self, event):
        """Convert event to CEF and send to syslog + local file."""
        sev = self.SEV_MAP.get(event.get("severity","INFO"), 1)
        etype = event.get("event_type","UNKNOWN")
        path = event.get("path","").replace("\\","\\\\")
        reason = event.get("reason","").replace("|","_")[:200]
        pid = event.get("pid",0)
        proc = event.get("process","unknown")
        ts = event.get("time", datetime.now().strftime("%H:%M:%S"))
        cef = (f"CEF:0|AntiGravity|Shield|3.0|{etype}|{etype}|{sev}|"
               f"filePath={path} reason={reason} pid={pid} process={proc} "
               f"rt={ts}")
        # Send via UDP syslog if configured
        if self.sock and self.host:
            try:
                self.sock.sendto(cef.encode("utf-8"), (self.host, self.port))
            except: pass
        # Always write to local log file
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(f"{datetime.now().isoformat()} {cef}\n")
        except: pass
        self.sent += 1

# ═══════════════════════════════════════════════════════════
# LAYER 5b: Forensic Timeline (Hash Chain Integrity)
# ═══════════════════════════════════════════════════════════
class ForensicTimeline:
    """Tamper-proof forensic event timeline with hash chain."""
    def __init__(self):
        home = os.path.expanduser("~")
        self.timeline_file = os.path.join(home,"Desktop","shield_forensic_timeline.jsonl")
        self.chain_hash = hashlib.sha256(b"ANTIGRAVITY_GENESIS").hexdigest()
        self.entries = 0

    def record(self, event):
        """Add event to timeline with chain hash for tamper detection."""
        entry = {
            "seq": self.entries,
            "timestamp": datetime.now().isoformat(),
            "event_type": event.get("event_type",""),
            "severity": event.get("severity",""),
            "path": event.get("path",""),
            "reason": event.get("reason",""),
            "pid": event.get("pid",0),
            "process": event.get("process",""),
            "prev_hash": self.chain_hash,
        }
        # Chain: hash of previous hash + current entry
        entry_str = json.dumps(entry, sort_keys=True)
        self.chain_hash = hashlib.sha256(
            (self.chain_hash + entry_str).encode()
        ).hexdigest()
        entry["chain_hash"] = self.chain_hash
        try:
            with open(self.timeline_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except: pass
        self.entries += 1

    def verify_integrity(self):
        """Verify the hash chain hasn't been tampered with."""
        try:
            chain = hashlib.sha256(b"ANTIGRAVITY_GENESIS").hexdigest()
            with open(self.timeline_file, "r") as f:
                for i, line in enumerate(f):
                    entry = json.loads(line)
                    if entry.get("prev_hash") != chain:
                        return False, f"Chain broken at entry {i}"
                    check = dict(entry)
                    del check["chain_hash"]
                    entry_str = json.dumps(check, sort_keys=True)
                    chain = hashlib.sha256((chain+entry_str).encode()).hexdigest()
                    if entry.get("chain_hash") != chain:
                        return False, f"Hash mismatch at entry {i}"
            return True, f"All {i+1} entries verified"
        except Exception as e:
            return False, str(e)

# ═══════════════════════════════════════════════════════════
# LAYER 7: Canary Deployer (Deception-Based Detection)
# ═══════════════════════════════════════════════════════════
CANARY_TEMPLATES = [
    {"name": "passwords_backup.txt", "content": "# Password Vault Export\n# Generated: 2024-03-15\nadmin:P@ssw0rd123!\nroot:Tr0ub4dor&3\n"},
    {"name": "ssh_private_key.bak", "content": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAE\nCANARY_FILE_DO_NOT_USE\n-----END OPENSSH PRIVATE KEY-----\n"},
    {"name": "financial_report_Q4_CONFIDENTIAL.csv", "content": "Date,Account,Amount\n2024-01-15,Corporate,1250000.00\n2024-02-01,Reserve,890000.50\n"},
    {"name": "database_credentials.conf", "content": "[production]\nhost=10.0.1.50\nuser=prod_admin\npassword=xK9mL2vQ7nR4\n"},
    {"name": ".aws_credentials_old", "content": "[default]\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI\n"},
]

class CanaryDeployer:
    """Deploys honeypot files. Any interaction = zero-false-positive intrusion."""
    def __init__(self, registry_path=None):
        home = os.path.expanduser("~")
        self.registry_path = registry_path or os.path.join(home, "Desktop", "canary_registry.json")
        self.registry = {}  # {filepath: {sha256, deployed_at}}
        self._load()

    def _load(self):
        if os.path.exists(self.registry_path):
            try:
                with open(self.registry_path, "r") as f: self.registry = json.load(f)
            except: self.registry = {}

    def _save(self):
        try:
            with open(self.registry_path, "w") as f: json.dump(self.registry, f, indent=2)
        except: pass

    def deploy(self, target_dir, count=3):
        """Deploy canary files into target_dir. Returns list of deployed paths."""
        import random as _rnd
        if not os.path.isdir(target_dir): return []
        templates = _rnd.sample(CANARY_TEMPLATES, min(count, len(CANARY_TEMPLATES)))
        deployed = []
        for t in templates:
            fp = os.path.join(target_dir, t["name"])
            if os.path.exists(fp) and fp not in self.registry: continue
            try:
                with open(fp, "w") as f: f.write(t["content"])
                sha = hashlib.sha256(t["content"].encode()).hexdigest()
                self.registry[fp] = {"sha256": sha, "deployed_at": time.time(), "name": t["name"]}
                deployed.append(fp)
                sp(f"  {G}[CANARY]{X} Deployed: {C}{t['name']}{X}")
            except: pass
        self._save()
        return deployed

    def verify(self):
        """Check all canaries. Returns list of alert dicts."""
        alerts = []
        for fp, meta in list(self.registry.items()):
            if not os.path.exists(fp):
                alerts.append({"type": "CANARY_MISSING", "path": fp, "name": meta["name"]})
                continue
            try:
                with open(fp, "r") as f: content = f.read()
                sha = hashlib.sha256(content.encode()).hexdigest()
                if sha != meta["sha256"]:
                    alerts.append({"type": "CANARY_TAMPERED", "path": fp, "name": meta["name"],
                                   "original": meta["sha256"][:12], "current": sha[:12]})
            except:
                alerts.append({"type": "CANARY_UNREADABLE", "path": fp, "name": meta["name"]})
        return alerts

    def is_canary(self, path):
        """Check if a path is a registered canary file."""
        return path in self.registry

    def cleanup(self):
        for fp in list(self.registry.keys()):
            try:
                if os.path.exists(fp): os.remove(fp)
            except: pass
        self.registry = {}; self._save()

# ═══════════════════════════════════════════════════════════
# LAYER 8: High-Frequency Metadata Scanner
# ═══════════════════════════════════════════════════════════
class MetadataScanner(threading.Thread):
    """
    Polls all files in watched dirs at 200ms intervals.
    Catches what watchdog misses: timestomping (os.utime),
    same-size wipes, canary deletions, and silent renames.
    """
    def __init__(self, watch_dirs, alert_cb, canary=None, interval=0.2):
        super().__init__(daemon=True)
        self.watch_dirs = watch_dirs
        self.alert_cb = alert_cb  # function(severity, event_type, path, reason)
        self.canary = canary
        self.interval = interval
        self._stop_event = threading.Event()
        self._baseline = {}  # {filepath: {mtime, ctime, size, hash}}
        self._lock = threading.Lock()

    def stop(self):
        self._stop_event.set()

    def _hash_file(self, path):
        try:
            with open(path, "rb") as f: return hashlib.sha256(f.read(65536)).hexdigest()
        except: return None

    def _scan_dir(self, d):
        """Walk directory and return {path: {mtime, ctime, size, hash}}."""
        snapshot = {}
        try:
            for root, dirs, files in os.walk(d):
                for fn in files:
                    fp = os.path.join(root, fn)
                    try:
                        st = os.stat(fp)
                        snapshot[fp] = {
                            "mtime": st.st_mtime,
                            "ctime": st.st_ctime,
                            "size": st.st_size,
                            "hash": self._hash_file(fp),
                            "name": fn,
                        }
                    except: pass
        except: pass
        return snapshot

    def build_baseline(self):
        """Take initial snapshot of all watched directories."""
        for d in self.watch_dirs:
            snap = self._scan_dir(d)
            with self._lock:
                self._baseline.update(snap)

    def run(self):
        while not self._stop_event.is_set():
            self._stop_event.wait(self.interval)
            if self._stop_event.is_set(): break
            try:
                self._check_cycle()
            except: pass

    def _check_cycle(self):
        """One scan cycle: compare current state to baseline."""
        current = {}
        for d in self.watch_dirs:
            current.update(self._scan_dir(d))

        with self._lock:
            # Collect disappeared files and new files for move detection
            disappeared = {}  # {hash: (path, old_meta)}
            appeared = {}     # {hash: (path, new_meta)}

            for fp, old in list(self._baseline.items()):
                if fp not in current and old.get("hash"):
                    disappeared[old["hash"]] = (fp, old)

            for fp, new in current.items():
                if fp not in self._baseline and new.get("hash"):
                    appeared[new["hash"]] = (fp, new)

            # Detect MOVES: same hash disappeared from A, appeared at B
            moved_srcs = set()
            moved_dsts = set()
            for h in disappeared:
                if h in appeared:
                    src_path, src_meta = disappeared[h]
                    dst_path, dst_meta = appeared[h]
                    self.alert_cb("WARNING", "FILE_MOVED", src_path,
                        f"Moved: {src_meta['name']} -> {os.path.basename(dst_path)}")
                    moved_srcs.add(src_path)
                    moved_dsts.add(dst_path)

            # Now handle remaining disappeared files (not moves)
            for fp, old in list(self._baseline.items()):
                if fp not in current and fp not in moved_srcs:
                    if self.canary and self.canary.is_canary(fp):
                        self.alert_cb("CRITICAL", "CANARY_MISSING", fp,
                            f"Canary file DELETED: {old['name']}")
                    else:
                        age = time.time() - old.get("ctime", 0)
                        if age < 10:
                            self.alert_cb("CRITICAL", "EPHEMERAL_FILE", fp,
                                f"File disappeared within {age:.1f}s")
                        else:
                            self.alert_cb("WARNING", "FILE_DELETED", fp,
                                f"Deleted: {old['name']}")

            # Check existing files for changes (timestomping, wipes, canary tamper)
            for fp in self._baseline:
                if fp in current and fp not in moved_srcs:
                    old = self._baseline[fp]
                    new = current[fp]

                    # Timestomping: mtime moved backwards significantly
                    if old["mtime"] - new["mtime"] > 86400 * 30:
                        self.alert_cb("CRITICAL", "TIMESTOMPING_DETECTED", fp,
                            f"mtime jumped backwards by {(old['mtime']-new['mtime'])/86400:.0f} days")

                    # mtime vs ctime divergence
                    now = time.time()
                    mtime_age = (now - new["mtime"]) / 86400
                    ctime_age = (now - new["ctime"]) / 86400
                    if mtime_age > 30 and ctime_age < 1 and old.get("_ts_flagged") != True:
                        self.alert_cb("CRITICAL", "TIMESTOMPING_DETECTED", fp,
                            f"mtime={mtime_age:.0f}d old but ctime={ctime_age:.1f}d old")
                        new["_ts_flagged"] = True

                    # Same-size wipe
                    if (new["hash"] and old["hash"] and
                        new["hash"] != old["hash"] and
                        new["size"] == old["size"] and new["size"] > 0):
                        self.alert_cb("CRITICAL", "WIPE_DETECTED", fp,
                            f"Same-size overwrite: {old['hash'][:12]}->{new['hash'][:12]}")

                    # Canary tampered
                    if self.canary and self.canary.is_canary(fp):
                        if new["hash"] and old["hash"] and new["hash"] != old["hash"]:
                            self.alert_cb("CRITICAL", "CANARY_TAMPERED", fp,
                                f"Canary modified: {old['name']}")

            # Check for new files with suspicious names (exclude moves)
            for fp, new in current.items():
                if fp not in self._baseline and fp not in moved_dsts:
                    fn = new["name"]
                    _, ext = os.path.splitext(fn)
                    if (not ext and len(fn) > 8 and
                        all(c in string.ascii_letters + string.digits for c in fn)):
                        self.alert_cb("CRITICAL", "WIPER_RENAME", fp,
                            f"Suspicious random filename: {fn}")

            # Update baseline to current state
            self._baseline = current


# ═══════════════════════════════════════════════════════════
# Windows Service Support
# ═══════════════════════════════════════════════════════════
def install_service():
    """Install the shield as a Windows scheduled task (auto-start)."""
    script = os.path.abspath(__file__)
    python = sys.executable
    task_name = "AntiGravityShield"
    bat_path = os.path.join(os.path.dirname(script), "shield_service.bat")
    with open(bat_path, "w") as f:
        f.write(f'@echo off\n"{python}" "{script}"\n')
    cmd = f'schtasks /create /tn "{task_name}" /tr "{bat_path}" /sc onlogon /rl highest /f'
    sp(f"  {G}[SERVICE]{X} Installing as scheduled task...")
    ret = os.system(cmd)
    if ret == 0:
        sp(f"  {G}[SERVICE]{X} Installed: {task_name} (runs on logon)")
        sp(f"  {G}[SERVICE]{X} Wrapper: {bat_path}")
    else:
        sp(f"  {Y}[SERVICE]{X} Failed. Try running CMD as Administrator first.")

def uninstall_service():
    task_name = "AntiGravityShield"
    os.system(f'schtasks /delete /tn "{task_name}" /f')
    sp(f"  {Y}[SERVICE]{X} Removed: {task_name}")

# ═══════════════════════════════════════════════════════════
# CORE: File System Detector
# ═══════════════════════════════════════════════════════════
class ShieldDetector(FileSystemEventHandler):
    def __init__(self, correlator, anomaly, response, tracker, siem=None, timeline=None, canary=None):
        super().__init__()
        self.start_time = time.time()
        self.alerts = []; self.lock = threading.Lock()
        self.file_hashes = {}; self.file_birth = {}
        self.counts = defaultdict(int)
        self.ops_window = []
        self.correlator = correlator
        self.anomaly = anomaly
        self.response = response
        self.tracker = tracker
        self.siem = siem
        self.timeline = timeline
        self.canary = canary
        self.ignore = ["__pycache__",".pyc","ntuser.dat","UsrClass.dat",
            "thumbcache",".tmp","~$","shield_v3","shield_experiment",
            "shield_evidence_vault","shield_siem","shield_forensic",
            "canary_registry.json"]

    def _ign(self, p):
        lo = p.lower()
        return any(x.lower() in lo for x in self.ignore)

    def _ts(self):
        return datetime.now().strftime("%H:%M:%S.%f")[:-3]

    def _alert(self, sev, etype, path, reason="", pid=0, proc=""):
        if self._ign(path): return
        evt = {"time":self._ts(),"severity":sev,"event_type":etype,
               "path":path,"reason":reason,"pid":pid,"process":proc}
        with self.lock:
            self.counts[sev] += 1; self.counts["TOTAL"] += 1
            self.alerts.append(evt)
        # Display
        if sev=="CRITICAL": sc=f"{R}{BOLD}"; ic="[!!!]"
        elif sev=="WARNING": sc=Y; ic="[!] "
        else: sc=B; ic="[i] "
        dp = path
        if len(path) > 60:
            pp = path.replace("/","\\").split("\\")
            if len(pp)>3: dp = "...\\"+  "\\".join(pp[-3:])
        proc_tag = f" {DIM}[{proc} PID:{pid}]{X}" if proc and proc != "unknown" else ""
        sp(f"  {sc}{ic} [{self._ts()}] {etype:24s}{X} {C}{dp}{X}{proc_tag}")
        if reason:
            sp(f"        {DIM}>> {reason[:140]}{X}")
        # Feed to ALL layers
        self.correlator.feed(evt)
        self.anomaly.feed(evt)
        if self.siem: self.siem.forward(evt)
        if self.timeline: self.timeline.record(evt)
        if sev == "CRITICAL":
            self.response.on_critical(etype, path, pid, proc)

    def _get_proc(self, path):
        info = self.tracker.get_for_path(path)
        return info.get("pid",0), info.get("name","unknown")

    def on_created(self, event):
        try:
            p = event.src_path
            if event.is_directory:
                self._alert("WARNING","DIR_CREATED",p,
                    f"New directory: {os.path.basename(p)}"); return
            self.file_birth[p] = time.time()
            try:
                with open(p,"rb") as f: h=hashlib.sha256(f.read()).hexdigest()
                self.file_hashes[p] = (h, os.path.getsize(p))
            except: pass
            pid, proc = self._get_proc(p)
            _, ext = os.path.splitext(p)
            if ext.lower() in (".exe",".bat",".ps1",".vbs",".cmd",".dll"):
                self._alert("WARNING","SUSPICIOUS_FILE_CREATED",p,
                    f"Executable created: {os.path.basename(p)}",pid,proc)
            else:
                self._alert("WARNING","FILE_CREATED",p,
                    f"New file: {os.path.basename(p)}",pid,proc)
        except: pass

    def on_modified(self, event):
        try:
            if event.is_directory: return
            p = event.src_path; pid, proc = self._get_proc(p)
            # Canary tampering check
            if self.canary and self.canary.is_canary(p):
                self._alert("CRITICAL","CANARY_TAMPERED",p,
                    f"Honeypot file MODIFIED: {os.path.basename(p)} — intrusion confirmed!",pid,proc)
                return
            if p in self.file_hashes:
                try:
                    oh, os_ = self.file_hashes[p]
                    ns = os.path.getsize(p)
                    with open(p,"rb") as f: nh=hashlib.sha256(f.read()).hexdigest()
                    if nh!=oh and ns==os_ and os_>0:
                        self._alert("CRITICAL","WIPE_DETECTED",p,
                            f"Same-size overwrite! Old:{oh[:12]} New:{nh[:12]}",pid,proc)
                        self.file_hashes[p]=(nh,ns); return
                    self.file_hashes[p]=(nh,ns)
                except: pass
            try:
                mt=os.path.getmtime(p); ct=os.path.getctime(p); now=time.time()
                ma=(now-mt)/86400; ca=(now-ct)/86400
                if ma>30 and ca<1:
                    mts=datetime.fromtimestamp(mt).strftime("%Y-%m-%d %H:%M:%S")
                    cts=datetime.fromtimestamp(ct).strftime("%Y-%m-%d %H:%M:%S")
                    self._alert("CRITICAL","TIMESTOMPING_DETECTED",p,
                        f"mtime={mts} ({ma:.0f}d old) ctime={cts} ({ca:.1f}d old)",pid,proc)
                    return
            except: pass
            self._alert("INFO","FILE_MODIFIED",p,"Content changed",pid,proc)
        except: pass

    def on_deleted(self, event):
        try:
            p = event.src_path
            if event.is_directory:
                self._alert("WARNING","DIR_DELETED",p,
                    f"Directory removed: {os.path.basename(p)}"); return
            # Canary deletion check
            if self.canary and self.canary.is_canary(p):
                self._alert("CRITICAL","CANARY_MISSING",p,
                    f"Honeypot file DELETED: {os.path.basename(p)} — intrusion confirmed!")
                return
            if p in self.file_birth:
                lt = time.time()-self.file_birth[p]
                if lt < 5.0:
                    self._alert("CRITICAL","EPHEMERAL_FILE",p,
                        f"Created+deleted in {lt:.2f}s — staging/cleanup"); return
                del self.file_birth[p]
            self._alert("WARNING","FILE_DELETED",p,f"Deleted: {os.path.basename(p)}")
        except: pass

    def on_moved(self, event):
        try:
            dn = os.path.basename(event.dest_path)
            if event.is_directory:
                self._alert("WARNING","DIR_RENAMED",event.src_path,
                    f"{os.path.basename(event.src_path)} -> {dn}"); return
            _, ext=os.path.splitext(dn)
            pid, proc = self._get_proc(event.src_path)
            if not ext and len(dn)>8 and all(c in string.ascii_letters+string.digits for c in dn):
                self._alert("CRITICAL","WIPER_RENAME",event.src_path,
                    f"Renamed to random '{dn}' — wiper pattern!",pid,proc)
            else:
                self._alert("WARNING","FILE_RENAMED",event.src_path,
                    f"{os.path.basename(event.src_path)} -> {dn}",pid,proc)
        except: pass

    def on_error(self, event):
        pass  # Skip errors, don't crash

# ═══════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════
def get_watch_dirs(home):
    dirs = []
    for n in ["Desktop","Documents","Downloads","Pictures","Videos","Music",".ssh"]:
        p = os.path.join(home, n)
        if os.path.isdir(p): dirs.append(p)
    dirs.append(home)
    return dirs

def main():
    home = os.path.expanduser("~")
    watch_dirs = get_watch_dirs(home)

    # Initialize AI layers
    def chain_alert(sev, etype, path, reason):
        sp(f"  {P}{BOLD}[CHAIN]{X} {R}{etype}{X}: {reason}")
    def anomaly_alert(sev, etype, path, reason):
        sp(f"  {P}{BOLD}[AI]{X} {R}{etype}{X}: {reason}")

    correlator = ChainCorrelator(window=30.0, alert_cb=chain_alert)
    anomaly = AnomalyEngine(alert_cb=anomaly_alert, learn_secs=60)
    response = ResponseEngine()
    tracker = ProcessTracker()
    siem = SIEMConnector()
    timeline = ForensicTimeline()
    canary = CanaryDeployer()

    sp(f"""
  {G}{BOLD}
     _    _   _ _____ ___  ____ ____      ___     _____ _______   __
    / \\  | \\ | |_   _|_ _|/ ___|  _ \\    / \\ \\   / /_ _|_   _\\ \\ / /
   / _ \\ |  \\| | | |  | || |  _| |_) |  / _ \\ \\ / / | |  | |  \\ V /
  / ___ \\| |\\  | | |  | || |_| |  _ <  / ___ \\ V /  | |  | |   | |
 /_/   \\_\\_| \\_| |_| |___|\\____|_| \\_\\/_/   \\_\\_/  |___| |_|   |_|
  {C}S H I E L D   v3.0   —   AI-POWERED{X}
  {DIM}Enterprise Anti-Forensic Defense Framework{X}
  {'='*60}
{X}""")
    sp(f"  {G}[SHIELD]{X} Platform: {C}{sys.platform} / Python {sys.version.split()[0]}{X}")
    sp(f"  {G}[SHIELD]{X} Host:     {C}{os.environ.get('COMPUTERNAME','unknown')}{X}")
    sp(f"  {G}[SHIELD]{X} Time:     {C}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{X}")
    sp(f"  {G}[SHIELD]{X} psutil:   {C}{'YES' if HAS_PSUTIL else 'NO'}{X}")
    sp(f"  {G}[SHIELD]{X} Zones:    {C}{len(watch_dirs)}{X}")
    for wp in watch_dirs:
        sp(f"    {C}{wp}{X}")
    sp(f"")
    sp(f"  {BOLD}AI Layers Active:{X}")
    sp(f"    {G}✓{X} Process Attribution (WHO is doing this)")
    sp(f"    {G}✓{X} Attack Chain Correlation (CONNECT events into campaigns)")
    sp(f"    {G}✓{X} AI Anomaly Engine (LEARN normal, detect abnormal)")
    sp(f"    {G}✓{X} Response Engine (RECOMMEND actions, human approves)")
    sp(f"    {G}✓{X} SIEM Connector (CEF syslog format)")
    sp(f"    {G}✓{X} Forensic Timeline (hash-chain tamper-proof)")
    sp(f"    {G}✓{X} Canary Deployer (honeypot deception tripwires)")
    sp(f"  {DIM}  Evidence vault: {response.vault_dir}{X}")
    sp(f"  {DIM}  SIEM log: {siem.log_file}{X}")
    sp(f"  {DIM}  Timeline: {timeline.timeline_file}{X}")
    sp(f"")

    # Deploy canaries to Desktop
    desktop = os.path.join(home, "Desktop")
    if os.path.isdir(desktop):
        canary.deploy(desktop, count=3)
    sp(f"")

    detector = ShieldDetector(correlator, anomaly, response, tracker, siem, timeline, canary)
    observers = {}
    for d in watch_dirs:
        try:
            obs = Observer()
            rec = (d != home)
            obs.schedule(detector, d, recursive=rec)
            obs.start()
            observers[d] = obs
        except Exception as e:
            sp(f"  {Y}[SKIP]{X} {d}: {e}")

    sp(f"  {G}{BOLD}SHIELD v3.0 ACTIVE — {len(observers)} monitors running{X}")
    sp(f"  {DIM}  Ctrl+C to stop | Type 'approve/deny <id>' for response actions{X}")
    sp(f"  {'='*60}\n")

    last_hb = time.time()
    try:
        while True:
            time.sleep(5)
            now = time.time()
            # Health check
            for d, obs in list(observers.items()):
                if not obs.is_alive():
                    try: obs.stop()
                    except: pass
                    try:
                        new = Observer()
                        new.schedule(detector, d, recursive=(d!=home))
                        new.start(); observers[d] = new
                    except: del observers[d]
            # Heartbeat
            if now - last_hb >= 30:
                last_hb = now
                el = int(now - detector.start_time); m,s = divmod(el,60)
                with detector.lock:
                    t=detector.counts.get("TOTAL",0)
                    c=detector.counts.get("CRITICAL",0)
                ai = anomaly.summary()
                ch = correlator.chains_detected
                alive = sum(1 for o in observers.values() if o.is_alive())
                sp(f"  {DIM}[{m:02d}:{s:02d}] ALIVE | "
                   f"Events:{t} | {R}CRIT:{c}{X}{DIM} | "
                   f"Chains:{ch} | AI:{'learned' if ai['learned'] else 'learning'} | "
                   f"{alive}/{len(observers)} monitors{X}")
                # Periodic canary verification
                cv = canary.verify()
                for ca in cv:
                    pid, proc = 0, ""
                    detector._alert("CRITICAL", ca["type"], ca["path"],
                        f"Honeypot '{ca['name']}' {ca['type'].split('_')[1].lower()}!")
    except KeyboardInterrupt:
        pass

    sp(f"\n  {Y}Stopping...{X}")
    for obs in observers.values():
        try: obs.stop(); obs.join(timeout=3)
        except: pass

    # ── Final Report ──
    sp(f"\n  {'='*60}")
    sp(f"  {G}{BOLD}SHIELD v3.0 SESSION REPORT{X}")
    sp(f"  {'='*60}")
    with detector.lock:
        sp(f"    {R}CRITICAL : {detector.counts.get('CRITICAL',0)}{X}")
        sp(f"    {Y}WARNING  : {detector.counts.get('WARNING',0)}{X}")
        sp(f"    {B}INFO     : {detector.counts.get('INFO',0)}{X}")
        sp(f"    {W}{BOLD}TOTAL    : {detector.counts.get('TOTAL',0)}{X}")
    sp(f"\n  {BOLD}AI Summary:{X}")
    ai = anomaly.summary()
    sp(f"    Baseline: {'Learned' if ai['learned'] else 'Still learning'}")
    sp(f"    Normal rate: {ai['rate_mean']}/min (σ={ai['rate_std']})")
    sp(f"    AI anomalies: {ai['anomalies']}")
    sp(f"    Attack chains: {correlator.chains_detected}")
    sp(f"    Evidence preserved: {len(response.preserved)}")
    # Final canary check
    final_canary = canary.verify()
    canary_ok = len(final_canary) == 0
    sp(f"    Canary files: {'ALL INTACT' if canary_ok else f'{len(final_canary)} COMPROMISED'}")
    sp(f"\n  {BOLD}Events:{X}")
    ec = defaultdict(int)
    for a in detector.alerts: ec[a["event_type"]] += 1
    for e,c in sorted(ec.items(), key=lambda x:-x[1]):
        sp(f"    {e:28s}: {c}")
    crits = [a for a in detector.alerts if a["severity"]=="CRITICAL"]
    if crits:
        sp(f"\n  {BOLD}Critical Findings:{X}")
        for a in crits[:20]:
            proc = f" [{a['process']}]" if a.get('process','') not in ('','unknown') else ''
            sp(f"    {R}[!!!]{X} {a['event_type']:24s} {C}{os.path.basename(a['path'])}{X}{proc}")

    rpath = os.path.join(home, "Desktop", "shield_v3_report.json")
    with open(rpath, "w") as f:
        json.dump({"alerts":detector.alerts,"counts":dict(detector.counts),
            "events":dict(ec),"ai":ai,"chains":correlator.chains_detected,
            "evidence":response.preserved,
            "canary":{"deployed":len(canary.registry),"compromised":len(final_canary),
                      "status":"INTACT" if canary_ok else "COMPROMISED"}}, f, indent=2, default=str)
    sp(f"\n  {G}Report: {rpath}{X}")
    sp(f"  {'='*60}\n")
    input("  Press Enter to exit...")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "--install":
            install_service(); sys.exit(0)
        elif sys.argv[1] == "--uninstall":
            uninstall_service(); sys.exit(0)
    main()
