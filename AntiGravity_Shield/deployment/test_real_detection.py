"""
Quick test: Does the shield detect REAL file operations on Windows?
Outputs results to a JSON file we can retrieve.
"""
import sys
import os
import time
import json

# Add source path
sys.path.insert(0, os.path.join(os.path.expanduser("~"), "antigravity-shield", "src"))

from agshield.detection.engine import DetectionEngine
from agshield.config import Config

watch_dir = os.path.join(os.path.expanduser("~"), "Desktop", "shield_realtest")
os.makedirs(watch_dir, exist_ok=True)
reports_dir = os.path.join(watch_dir, "reports")
os.makedirs(reports_dir, exist_ok=True)

# Configure
config = Config()
config._config.setdefault("general", {})
config._config["general"]["watch_paths"] = [watch_dir]
config._config["general"]["reports_dir"] = reports_dir
config._config["general"]["database_path"] = os.path.join(watch_dir, "baseline.db")
config._config["general"]["log_file"] = os.path.join(watch_dir, "shield.log")

# Start engine
engine = DetectionEngine(config)
engine.start(deploy_canaries=False)
backend = engine._monitor_backend
print(f"STARTED - backend: {backend}")

# Let watchdog settle
time.sleep(2)

# ── REAL ATTACK SIMULATION ──
results = {"backend": backend, "events": []}

# 1. Create a file
print("[1] Creating file...")
test_file = os.path.join(watch_dir, "secret_document.txt")
with open(test_file, "w") as f:
    f.write("TOP SECRET: This is classified information that must be destroyed")
time.sleep(1)

# 2. Modify with same-size content (wiper signature)
print("[2] Overwriting file (wiper pattern)...")
with open(test_file, "w") as f:
    content = "x" * 64
    f.write(content)
time.sleep(1)

# 3. Rename to random name (wiper pattern)
print("[3] Renaming to random name...")
renamed = os.path.join(watch_dir, "a8f3b2c1d9e4f7a0")
os.rename(test_file, renamed)
time.sleep(1)

# 4. Delete
print("[4] Deleting file...")
os.remove(renamed)
time.sleep(1)

# 5. Timestomping
print("[5] Timestomping test...")
ts_file = os.path.join(watch_dir, "evidence_log.txt")
with open(ts_file, "w") as f:
    f.write("Evidence: Login from 10.0.0.5 at 14:30 UTC")
time.sleep(0.5)
# Backdate to year 2000
os.utime(ts_file, (946684800, 946684800))
time.sleep(1)

# 6. Mass creation + deletion
print("[6] Mass create/delete (burst)...")
for i in range(10):
    tmp = os.path.join(watch_dir, f"tempfile_{i}.tmp")
    with open(tmp, "w") as f:
        f.write(f"temp data {i}")
time.sleep(0.5)
for i in range(10):
    tmp = os.path.join(watch_dir, f"tempfile_{i}.tmp")
    if os.path.exists(tmp):
        os.remove(tmp)
time.sleep(2)

# Stop and collect
print("[7] Stopping engine...")
report = engine.stop()

summary = report.get("summary", {})
alerts = report.get("alerts", [])

output = {
    "backend": backend,
    "total_alerts": summary.get("total_alerts", 0),
    "by_severity": summary.get("by_severity", {}),
    "by_event_type": summary.get("by_event_type", {}),
    "by_module": summary.get("by_module", {}),
    "sample_alerts": [],
}

# Include first 15 alerts as samples
for a in alerts[:15]:
    output["sample_alerts"].append({
        "event_type": a.get("event_type"),
        "path": os.path.basename(a.get("path", "")),
        "severity": a.get("severity"),
        "module": a.get("module"),
        "reason": a.get("details", {}).get("reason", ""),
    })

# Write results
result_path = os.path.join(os.path.expanduser("~"), "shield_test_results.json")
with open(result_path, "w") as f:
    json.dump(output, f, indent=2, default=str)

print(f"\nRESULTS: {summary.get('total_alerts', 0)} alerts detected")
print(f"Saved to: {result_path}")
