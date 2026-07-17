"""
AntiGravity Shield v2.0 — Windows VM Integration Test
=====================================================
Runs the shield on the Windows VM, simulates an attack,
and verifies detection.
"""
import sys
import os
import time
import json
import threading
import random
import string

# Shield source
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "antigravity-shield", "src"))

from agshield.detection.engine import DetectionEngine
from agshield.config import Config

WATCH_DIR = os.path.join(os.path.expanduser("~"), "Desktop", "evidence_workspace")


def simulate_attack(watch_dir):
    """Simulate the anti-forensics attack against the evidence workspace."""
    time.sleep(3)
    print("\n" + "=" * 50)
    print("  ATTACK PHASE STARTING")
    print("=" * 50)

    # Phase 1: Create evidence file
    evidence = os.path.join(watch_dir, "stolen_data.txt")
    with open(evidence, "w") as f:
        f.write("CONFIDENTIAL: Quarterly financial data")
    print(f"  [1] Created evidence file: stolen_data.txt")
    time.sleep(0.5)

    # Phase 2: Drop payload with suspicious extension
    dropper = os.path.join(watch_dir, "payload.exe")
    with open(dropper, "w") as f:
        f.write("MZ_FAKE_PE_HEADER_CONTENT")
    print(f"  [2] Dropped payload: payload.exe")
    time.sleep(0.5)

    # Phase 3: Timestomp the payload to Jan 2000
    os.utime(dropper, (946684800, 946684800))
    print(f"  [3] Timestomped payload.exe to Jan 2000")
    time.sleep(0.5)

    # Phase 4: Overwrite evidence (wiper behavior)
    original_size = os.path.getsize(evidence)
    with open(evidence, "w") as f:
        f.write("X" * original_size)
    print(f"  [4] Wiped evidence file (overwrite with Xs)")
    time.sleep(0.3)

    # Phase 5: Rename to random name
    random_name = "".join(random.choices(string.ascii_lowercase, k=8))
    renamed = os.path.join(watch_dir, random_name)
    os.rename(evidence, renamed)
    print(f"  [5] Renamed evidence to: {random_name}")
    time.sleep(0.3)

    # Phase 6: Delete both files
    os.remove(renamed)
    os.remove(dropper)
    print(f"  [6] Deleted all files")

    print("=" * 50)
    print("  ATTACK COMPLETE")
    print("=" * 50)


def main():
    print("=" * 60)
    print("  AntiGravity Shield v2.0 — Windows VM Test")
    print("=" * 60)
    print(f"  Watch directory: {WATCH_DIR}")
    print()

    # Ensure watch directory exists
    os.makedirs(WATCH_DIR, exist_ok=True)
    reports_dir = os.path.join(WATCH_DIR, "reports")
    os.makedirs(reports_dir, exist_ok=True)

    # Configure shield
    config = Config()
    config._config.setdefault("general", {})
    config._config["general"]["watch_paths"] = [WATCH_DIR]
    config._config["general"]["reports_dir"] = reports_dir
    config._config["general"]["database_path"] = os.path.join(WATCH_DIR, "baseline.db")
    config._config["general"]["log_file"] = os.path.join(WATCH_DIR, "shield.log")

    # Start shield
    engine = DetectionEngine(config)
    engine.start(deploy_canaries=True, canary_count=2)

    # Run attack in background
    attack_thread = threading.Thread(target=simulate_attack, args=(WATCH_DIR,))
    attack_thread.start()
    attack_thread.join()

    # Wait for event propagation
    time.sleep(3)

    # Stop and get report
    report = engine.stop()

    # Print results
    print()
    print("=" * 60)
    print("  TEST RESULTS")
    print("=" * 60)
    summary = report.get("summary", {})
    print(f"  Version:         {report.get('version', '?')}")
    print(f"  Monitor Backend: {report.get('monitor_backend', '?')}")
    print(f"  Duration:        {report.get('duration_seconds', 0):.2f}s")
    print(f"  Total Alerts:    {summary.get('total_alerts', 0)}")
    print(f"  By Severity:     {summary.get('by_severity', {})}")
    print(f"  By Module:       {summary.get('by_module', {})}")
    print(f"  Log Integrity:   {'VERIFIED' if report.get('log_integrity', {}).get('valid') else 'FAILED'}")
    print()

    # Save report
    report_path = os.path.join(reports_dir, f"test_report_{int(time.time())}.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"  Report saved: {report_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
