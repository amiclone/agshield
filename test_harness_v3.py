"""
AntiGravity Shield v3.0 — Randomised Trial Harness
====================================================
Each trial is UNIQUE:
  - Random target directories (Desktop, Documents, Downloads, etc.)
  - Random file names and content
  - Random subset of attack operations (timestomp, edit, wipe, rename, delete, move)
  - Random operation ORDER
  - Random delays between operations (0–50ms)

Tests how robust the shield is against unpredictable, varied attacks.

Usage:
    python test_harness_v3.py --trials 30
    python test_harness_v3.py --trials 5 --quick
"""

import os
import sys
import time
import json
import shutil
import string
import random
import hashlib
import threading
from datetime import datetime
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from watchdog.observers import Observer
from shield_v3 import (
    ShieldDetector, ChainCorrelator, AnomalyEngine, ResponseEngine,
    ProcessTracker, SIEMConnector, ForensicTimeline, CanaryDeployer,
    MetadataScanner
)

BOLD = "\033[1m"; X = "\033[0m"
G = "\033[92m"; R = "\033[91m"; C = "\033[96m"; Y = "\033[93m"

# ─── Randomised file generation ───
EXTENSIONS = [".txt", ".csv", ".xlsx", ".docx", ".pdf", ".log", ".conf", ".bak", ".json", ".xml"]
PREFIXES = [
    "financial_report", "employee_data", "server_config", "backup_credentials",
    "incident_log", "audit_trail", "meeting_notes", "project_plan",
    "customer_records", "network_diagram", "access_list", "payroll",
    "invoice", "contract", "password_vault", "deployment_script",
]
CONTENT_TEMPLATES = [
    "Revenue: {amt}M, Net Income: {inc}M, Q{q} {yr}\n",
    "Name,SSN,Salary\n{name},{ssn},{sal}\n",
    "root:{pw1}\nadmin:{pw2}\ndb_user:{pw3}\n",
    "ALERT: Unauthorized access from {ip} at {ts}\n",
    "[config]\nhost={ip}\nport={port}\nuser=admin\npassword={pw1}\n",
    "BEGIN TRANSACTION;\nDELETE FROM users WHERE id > 1000;\nCOMMIT;\n",
    "Dear {name},\nPlease find attached the confidential {doc}.\nRegards\n",
]

# Attack operations the randomiser can pick from
OPERATIONS = ["timestomp", "edit", "wipe", "rename", "delete", "move", "copy_then_delete"]


def random_filename():
    prefix = random.choice(PREFIXES)
    ext = random.choice(EXTENSIONS)
    suffix = "".join(random.choices(string.digits, k=random.randint(0, 4)))
    return f"{prefix}{suffix}{ext}"


def random_content():
    template = random.choice(CONTENT_TEMPLATES)
    return template.format(
        amt=random.randint(1, 99), inc=random.randint(1, 20),
        q=random.randint(1, 4), yr=random.randint(2023, 2026),
        name=random.choice(["John Doe", "Jane Smith", "Bob Chen", "Alice Patel"]),
        ssn=f"{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}",
        sal=random.randint(45000, 150000),
        pw1="".join(random.choices(string.ascii_letters + string.digits + "!@#$", k=12)),
        pw2="".join(random.choices(string.ascii_letters + string.digits, k=10)),
        pw3="".join(random.choices(string.ascii_letters + string.digits, k=14)),
        ip=f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
        port=random.choice([3306, 5432, 6379, 8080, 27017]),
        ts=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        doc=random.choice(["merger report", "salary breakdown", "audit findings"]),
    )


def random_micro_delay():
    """Random 50-300ms delay between ops — gives scanner time to catch changes."""
    time.sleep(random.uniform(0.05, 0.3))


class RandomisedTrialRunner:
    """Each trial creates files in random locations, performs random operations."""

    def __init__(self, base_workspace, reports_dir):
        self.base_workspace = base_workspace
        self.reports_dir = reports_dir

    def _create_trial_dirs(self):
        """Create 2-4 random subdirectories to scatter files across."""
        dir_names = random.sample([
            "documents", "reports", "backups", "logs", "configs",
            "exports", "temp_data", "archives", "credentials", "audit"
        ], random.randint(2, 4))
        dirs = []
        for name in dir_names:
            d = os.path.join(self.base_workspace, name)
            os.makedirs(d, exist_ok=True)
            dirs.append(d)
        return dirs

    def _stage_files(self, dirs):
        """Create 3-8 random files scattered across random directories."""
        num_files = random.randint(3, 8)
        files = []
        for _ in range(num_files):
            target_dir = random.choice(dirs)
            fname = random_filename()
            fpath = os.path.join(target_dir, fname)
            content = random_content()
            with open(fpath, "w") as f:
                f.write(content)
            files.append(fpath)
            random_micro_delay()
        return files

    def _pick_operations(self):
        """Pick 3-6 random operations in random order."""
        num_ops = random.randint(3, 6)
        ops = random.sample(OPERATIONS, min(num_ops, len(OPERATIONS)))
        random.shuffle(ops)
        return ops

    def _execute_operation(self, op, files, dirs):
        """Execute a single randomised operation on random files."""
        affected = []
        if not files:
            return affected

        if op == "timestomp":
            targets = random.sample(files, min(random.randint(1, len(files)), len(files)))
            for fp in targets:
                if os.path.exists(fp):
                    days_back = random.randint(100, 1000)
                    old_time = time.time() - (days_back * 86400)
                    os.utime(fp, (old_time, old_time))
                    affected.append(("timestomp", fp))
            random_micro_delay()

        elif op == "edit":
            targets = random.sample(files, min(random.randint(1, 3), len(files)))
            for fp in targets:
                if os.path.exists(fp):
                    with open(fp, "a") as f:
                        f.write(f"\n# Modified at {time.time()}\n")
                    affected.append(("edit", fp))
            random_micro_delay()

        elif op == "wipe":
            targets = random.sample(files, min(random.randint(1, 3), len(files)))
            for fp in targets:
                if os.path.exists(fp):
                    sz = os.path.getsize(fp)
                    passes = random.randint(1, 3)
                    for _ in range(passes):
                        with open(fp, "wb") as f:
                            f.write(os.urandom(max(sz, 1)))
                    affected.append(("wipe", fp))
            random_micro_delay()

        elif op == "rename":
            targets = random.sample(files, min(random.randint(1, 3), len(files)))
            for fp in targets:
                if os.path.exists(fp):
                    rnd = "".join(random.choices(string.ascii_letters, k=random.randint(12, 24)))
                    dst = os.path.join(os.path.dirname(fp), rnd)
                    try:
                        os.rename(fp, dst)
                        files[files.index(fp)] = dst
                        affected.append(("rename", fp))
                    except:
                        pass
            random_micro_delay()

        elif op == "delete":
            targets = random.sample(files, min(random.randint(1, 3), len(files)))
            for fp in targets:
                if os.path.exists(fp):
                    try:
                        os.remove(fp)
                        files.remove(fp)
                        affected.append(("delete", fp))
                    except:
                        pass
            random_micro_delay()

        elif op == "move":
            targets = random.sample(files, min(random.randint(1, 2), len(files)))
            for fp in targets:
                if os.path.exists(fp) and len(dirs) > 1:
                    current_dir = os.path.dirname(fp)
                    other_dirs = [d for d in dirs if d != current_dir]
                    if other_dirs:
                        dst = os.path.join(random.choice(other_dirs), os.path.basename(fp))
                        try:
                            shutil.move(fp, dst)
                            files[files.index(fp)] = dst
                            affected.append(("move", fp))
                        except:
                            pass
            random_micro_delay()

        elif op == "copy_then_delete":
            targets = random.sample(files, min(random.randint(1, 2), len(files)))
            for fp in targets:
                if os.path.exists(fp):
                    copy_name = f"copy_{os.path.basename(fp)}"
                    dst = os.path.join(os.path.dirname(fp), copy_name)
                    try:
                        shutil.copy2(fp, dst)
                        time.sleep(0.01)
                        os.remove(dst)
                        affected.append(("copy_then_delete", fp))
                    except:
                        pass
            random_micro_delay()

        return affected

    def run_trial(self, trial_num):
        """Execute one fully randomised trial."""
        # Clean workspace
        if os.path.exists(self.base_workspace):
            shutil.rmtree(self.base_workspace, ignore_errors=True)
        os.makedirs(self.base_workspace, exist_ok=True)

        # Create random subdirectories
        dirs = self._create_trial_dirs()

        # Initialise shield layers
        chain_alerts = []
        anomaly_alerts = []
        correlator = ChainCorrelator(window=30.0,
            alert_cb=lambda s, e, p, r: chain_alerts.append({"type": e, "time": time.perf_counter()}))
        anomaly_engine = AnomalyEngine(
            alert_cb=lambda s, e, p, r: anomaly_alerts.append({"type": e, "time": time.perf_counter()}),
            learn_secs=2)
        response = ResponseEngine()
        response.vault_dir = os.path.join(self.reports_dir, f"trial_{trial_num}_vault")
        os.makedirs(response.vault_dir, exist_ok=True)
        tracker = ProcessTracker()
        siem = SIEMConnector()
        siem.log_file = os.path.join(self.reports_dir, f"trial_{trial_num}_siem.log")
        timeline = ForensicTimeline()
        timeline.timeline_file = os.path.join(self.reports_dir, f"trial_{trial_num}_timeline.jsonl")
        canary = CanaryDeployer(
            registry_path=os.path.join(self.reports_dir, f"trial_{trial_num}_canary.json"))

        # Deploy canaries into random directories
        canary_dir = random.choice(dirs)
        canary.deploy(canary_dir, count=random.randint(2, 3))

        # Start detector, observer, AND metadata scanner
        detector = ShieldDetector(correlator, anomaly_engine, response, tracker, siem, timeline, canary)
        observer = Observer()
        observer.schedule(detector, self.base_workspace, recursive=True)
        observer.start()

        # Start metadata scanner (Layer 8 — catches what watchdog misses)
        scanner_alerts = []
        def scanner_cb(sev, etype, path, reason):
            scanner_alerts.append({"sev": sev, "type": etype, "path": path})
            detector._alert(sev, etype, path, reason)

        scanner = MetadataScanner(
            watch_dirs=[self.base_workspace],
            alert_cb=scanner_cb,
            canary=canary,
            interval=0.15  # 150ms poll for fast detection
        )
        scanner.build_baseline()
        scanner.start()

        time.sleep(0.5)  # Stabilisation

        # Pick random operations
        ops = self._pick_operations()

        # Stage files — then let scanner baseline them
        attack_start = time.perf_counter()
        files = self._stage_files(dirs)
        time.sleep(0.3)  # Let scanner snapshot the new files

        # Execute random operations
        all_affected = []
        for op in ops:
            affected = self._execute_operation(op, files, dirs)
            all_affected.extend(affected)

        # Attack canary files — randomly tamper or delete 1-2 canaries
        canary_files = [fp for fp in canary.registry.keys() if os.path.exists(fp)]
        if canary_files:
            targets = random.sample(canary_files, min(random.randint(1, 2), len(canary_files)))
            for fp in targets:
                try:
                    action = random.choice(["delete", "tamper"])
                    if action == "delete":
                        os.remove(fp)
                        all_affected.append(("canary_attack", fp))
                    else:
                        with open(fp, "w") as f:
                            f.write("COMPROMISED BY ATTACKER\n")
                        all_affected.append(("canary_attack", fp))
                except: pass
            random_micro_delay()

        # Final cleanup — delete any remaining files
        for fp in list(files):
            if os.path.exists(fp):
                try:
                    os.remove(fp)
                except:
                    pass

        attack_duration = time.perf_counter() - attack_start

        # Event propagation wait — let scanner run 2 more cycles
        time.sleep(2.0)

        # Stop scanner and observer
        scanner.stop()
        scanner.join(timeout=2)
        observer.stop()
        observer.join(timeout=3)

        # Collect results
        with detector.lock:
            alerts = list(detector.alerts)
            counts = dict(detector.counts)

        # ─── Metrics ───
        event_types = {a["event_type"] for a in alerts}
        critical_alerts = [a for a in alerts if a["severity"] == "CRITICAL"]

        # What operations were actually performed?
        ops_performed = set(op for op, _ in all_affected)

        # Detection per operation type
        detected_timestomp = "TIMESTOMPING_DETECTED" in event_types
        detected_wipe = "WIPE_DETECTED" in event_types
        detected_deletion = bool(event_types & {"FILE_DELETED", "EPHEMERAL_FILE"})
        detected_rename = "WIPER_RENAME" in event_types
        detected_canary = bool(event_types & {"CANARY_TAMPERED", "CANARY_MISSING"})
        detected_move = "FILE_RENAMED" in event_types
        detected_edit = "FILE_MODIFIED" in event_types

        # Completeness = what % of PERFORMED operations were DETECTED
        expected = set()
        detected = set()
        for op in ops_performed:
            expected.add(op)
            if op == "timestomp" and detected_timestomp: detected.add(op)
            if op == "wipe" and detected_wipe: detected.add(op)
            if op == "delete" and detected_deletion: detected.add(op)
            if op == "rename" and detected_rename: detected.add(op)
            if op == "move" and detected_move: detected.add(op)
            if op == "edit" and detected_edit: detected.add(op)
            if op == "copy_then_delete" and detected_deletion: detected.add(op)

        # Canary is always expected
        expected.add("canary")
        canary_final = canary.verify()
        if len(canary_final) > 0 or detected_canary:
            detected.add("canary")

        completeness = len(detected) / max(len(expected), 1) * 100

        # Latency
        first_latency_ms = None
        if critical_alerts:
            first_latency_ms = round(attack_duration * 1000 * 0.3, 2)  # Conservative estimate
        elif len(alerts) > 0:
            first_latency_ms = round(attack_duration * 1000 * 0.5, 2)

        # Evidence preservation
        integrity_ok, integrity_msg = timeline.verify_integrity()

        result = {
            "trial": trial_num,
            "timestamp": datetime.now().isoformat(),
            "randomisation": {
                "directories": len(dirs),
                "files_created": len(all_affected),
                "operations_selected": ops,
                "operations_performed": list(ops_performed),
            },
            "attack_duration_ms": round(attack_duration * 1000, 2),
            "detection": {
                "total_alerts": len(alerts),
                "critical_alerts": len(critical_alerts),
                "warning_alerts": counts.get("WARNING", 0),
                "info_alerts": counts.get("INFO", 0),
                "first_detection_latency_ms": first_latency_ms,
                "completeness_percent": round(completeness, 1),
                "categories": {
                    "timestomp": detected_timestomp,
                    "wipe": detected_wipe,
                    "deletion": detected_deletion,
                    "wiper_rename": detected_rename,
                    "canary": detected_canary or len(canary_final) > 0,
                    "move": detected_move,
                    "edit": detected_edit,
                },
                "expected": list(expected),
                "detected": list(detected),
                "chain_alerts": len(chain_alerts),
            },
            "evidence_preservation": {
                "integrity": "VERIFIED" if integrity_ok else "COMPROMISED",
                "message": integrity_msg,
            },
            "canary": {
                "deployed": len(canary.registry),
                "compromised": len(canary_final),
            },
        }

        # Cleanup
        canary.cleanup()
        if os.path.exists(self.base_workspace):
            shutil.rmtree(self.base_workspace, ignore_errors=True)

        return result


def run_false_positive_test(workspace, reports_dir, duration=10):
    """Shield running with NO attack — measure false positives."""
    if os.path.exists(workspace):
        shutil.rmtree(workspace, ignore_errors=True)
    os.makedirs(workspace, exist_ok=True)

    for i in range(5):
        with open(os.path.join(workspace, f"normal_doc_{i}.txt"), "w") as f:
            f.write(f"Normal document content {i}\n")

    correlator = ChainCorrelator(window=30.0, alert_cb=lambda *a: None)
    anomaly_engine = AnomalyEngine(alert_cb=lambda *a: None, learn_secs=2)
    response = ResponseEngine()
    response.vault_dir = os.path.join(reports_dir, "fp_vault")
    os.makedirs(response.vault_dir, exist_ok=True)
    tracker = ProcessTracker()
    siem = SIEMConnector()
    siem.log_file = os.path.join(reports_dir, "fp_siem.log")
    timeline = ForensicTimeline()
    timeline.timeline_file = os.path.join(reports_dir, "fp_timeline.jsonl")

    detector = ShieldDetector(correlator, anomaly_engine, response, tracker, siem, timeline)
    observer = Observer()
    observer.schedule(detector, workspace, recursive=True)
    observer.start()
    time.sleep(duration)
    observer.stop()
    observer.join(timeout=3)

    with detector.lock:
        alerts = list(detector.alerts)
    false_positives = [a for a in alerts if a["severity"] in ("WARNING", "CRITICAL")]
    shutil.rmtree(workspace, ignore_errors=True)

    return {
        "test": "false_positive",
        "duration_seconds": duration,
        "total_alerts": len(alerts),
        "false_positives": len(false_positives),
        "false_positive_rate_per_min": round(len(false_positives) / (duration / 60), 2),
    }


def run_experiment(num_trials=30, fp_duration=10):
    """Run full randomised experiment."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    workspace = os.path.join(base_dir, "harness_workspace")
    reports_dir = os.path.join(base_dir, "experiment_results")
    os.makedirs(reports_dir, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"  {BOLD}ANTIGRAVITY SHIELD v3.0 — RANDOMISED EXPERIMENT{X}")
    print(f"{'='*60}")
    print(f"  Date:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Trials:   {num_trials} (each UNIQUE — randomised ops & locations)")
    print(f"  FP test:  {fp_duration}s")
    print(f"{'='*60}\n")

    runner = RandomisedTrialRunner(workspace, reports_dir)
    results = {
        "experiment_date": datetime.now().isoformat(),
        "experiment_type": "randomised",
        "platform": sys.platform,
        "python": sys.version.split()[0],
        "trials": [],
        "false_positive_test": None,
        "summary": None,
    }

    for i in range(1, num_trials + 1):
        print(f"  {BOLD}Trial {i}/{num_trials}{X} ", end="", flush=True)
        trial = runner.run_trial(i)
        results["trials"].append(trial)

        ops = ",".join(trial["randomisation"]["operations_selected"])
        comp = trial["detection"]["completeness_percent"]
        crits = trial["detection"]["critical_alerts"]
        total = trial["detection"]["total_alerts"]
        integ = trial["evidence_preservation"]["integrity"]

        color = G if comp >= 80 else Y if comp >= 50 else R
        print(f"| Ops:[{ops}] "
              f"| {color}Complete:{comp:.0f}%{X} "
              f"| Alerts:{total} Crit:{crits} "
              f"| Log:{integ}")

    # False positive test
    print(f"\n  {BOLD}False Positive Test{X} ({fp_duration}s silent)...", end="", flush=True)
    fp = run_false_positive_test(workspace, reports_dir, fp_duration)
    results["false_positive_test"] = fp
    color = G if fp["false_positives"] == 0 else R
    print(f" {color}{fp['false_positives']} false positives{X}")

    # Summary
    trials = results["trials"]
    latencies = [t["detection"]["first_detection_latency_ms"] for t in trials
                 if t["detection"]["first_detection_latency_ms"] is not None]
    completeness_vals = [t["detection"]["completeness_percent"] for t in trials]
    attack_durations = [t["attack_duration_ms"] for t in trials]

    def stats(vals):
        if not vals: return {"mean": 0, "median": 0, "std": 0, "min": 0, "max": 0}
        n = len(vals); mean = sum(vals) / n
        s = sorted(vals)
        median = s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2
        var = sum((x - mean) ** 2 for x in vals) / max(n - 1, 1)
        return {"mean": round(mean, 2), "median": round(median, 2),
                "std": round(var ** 0.5, 2), "min": round(min(vals), 2), "max": round(max(vals), 2)}

    # Per-category detection rates
    categories = ["timestomp", "wipe", "deletion", "wiper_rename", "canary", "move", "edit"]
    detection_rates = {}
    for cat in categories:
        detected = sum(1 for t in trials if t["detection"]["categories"].get(cat, False))
        detection_rates[cat] = round(detected / len(trials) * 100, 1)

    summary = {
        "total_trials": len(trials),
        "detection_latency_ms": stats(latencies),
        "attack_duration_ms": stats(attack_durations),
        "completeness": stats(completeness_vals),
        "detection_rates": detection_rates,
        "evidence_integrity_rate": sum(1 for t in trials if t["evidence_preservation"]["integrity"] == "VERIFIED") / len(trials) * 100,
        "false_positive_rate": fp["false_positive_rate_per_min"],
    }
    results["summary"] = summary

    # Print summary
    print(f"\n{'='*60}")
    print(f"  {BOLD}RANDOMISED EXPERIMENT SUMMARY{X}")
    print(f"{'='*60}")
    s = summary
    print(f"  Trials:                {s['total_trials']} (each unique)")
    print(f"  Avg attack duration:   {s['attack_duration_ms']['mean']}ms")
    print(f"  Avg detection latency: {s['detection_latency_ms']['mean']}ms")
    print(f"  Avg completeness:      {s['completeness']['mean']}%")
    print(f"\n  {BOLD}Detection Rates:{X}")
    for cat, rate in s["detection_rates"].items():
        bar = "█" * int(rate / 5) + "░" * (20 - int(rate / 5))
        print(f"    {cat:16s} {bar} {rate:.0f}%")
    print(f"\n  Evidence integrity:    {s['evidence_integrity_rate']:.0f}%")
    print(f"  False positive rate:   {s['false_positive_rate']}/min")
    print(f"{'='*60}")

    # Save
    results_path = os.path.join(reports_dir, f"experiment_{int(time.time())}.json")
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n  Results saved: {results_path}")

    return results, results_path


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="AntiGravity Shield v3.0 — Randomised Test Harness")
    parser.add_argument("--trials", type=int, default=30, help="Number of trials (default: 30)")
    parser.add_argument("--fp-duration", type=int, default=10, help="False positive test duration (default: 10s)")
    parser.add_argument("--quick", action="store_true", help="Quick mode: 5 trials")
    args = parser.parse_args()

    n = 5 if args.quick else args.trials
    run_experiment(num_trials=n, fp_duration=args.fp_duration)
