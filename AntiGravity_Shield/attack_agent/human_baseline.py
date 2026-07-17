import time
import os
import json
import random

# Simulating the same imports/actions as agent_controller.py
try:
    import timestomper
    import data_wiper
    import log_cleaner
except ImportError:
    pass

REPORT_FILE = "human_baseline_report.json"
EVIDENCE_FILE = "stolen_plans.txt"
DROPPER_FILE = "malware_dropper.exe"

def simulate_typing(command, min_time=1.5, max_time=4.0):
    """
    Simulates a human typing a command and waiting for it to execute.
    Humans have latency observing output, thinking, and typing.
    """
    delay = random.uniform(min_time, max_time)
    print(f"[HUMAN] Typing: `{command}`...")
    time.sleep(delay)

def run_human_baseline():
    print("=== Anti-Forensics: Human Operator Baseline ===")
    
    # 0. Setup dummy files (assuming they exist from activity)
    if not os.path.exists(EVIDENCE_FILE):
        with open(EVIDENCE_FILE, "w") as f: f.write("dummy")
    if not os.path.exists(DROPPER_FILE):
        with open(DROPPER_FILE, "w") as f: f.write("dummy")

    report = {"actions": []}
    
    # Start Timer
    start_time = time.perf_counter()
    
    # 1. Timestomp
    simulate_typing(f"touch -r /bin/bash {DROPPER_FILE}", 2.0, 5.0)
    print(f"[HUMAN] Verified timestamps on {DROPPER_FILE}")
    report["actions"].append({"tool": "manual_timestomp", "time_taken": time.perf_counter() - start_time})
    
    # 2. Wipe
    step_start = time.perf_counter()
    simulate_typing(f"shred -u -z -n 3 {EVIDENCE_FILE}", 3.0, 6.0)
    print(f"[HUMAN] Shredded {EVIDENCE_FILE}")
    report["actions"].append({"tool": "manual_shred", "time_taken": time.perf_counter() - step_start})
    
    # 3. Clean Logs
    step_start = time.perf_counter()
    simulate_typing("cat /dev/null > /var/log/auth.log", 2.0, 4.0)
    simulate_typing("systemctl stop splunk", 2.0, 5.0)
    simulate_typing("history -c", 1.0, 2.0)
    print("[HUMAN] Cleared logs and history")
    report["actions"].append({"tool": "manual_log_clean", "time_taken": time.perf_counter() - step_start})
    
    # End Timer
    total_time = time.perf_counter() - start_time
    report["execution_time_seconds"] = round(total_time, 4)
    report["mode"] = "human_baseline"
    
    print(f"\n[!] Human Operator completed cleanup in {total_time:.4f} seconds.")
    
    # Write report
    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=4)
        
    print(f"[+] Human baseline report saved to {REPORT_FILE}")

if __name__ == "__main__":
    run_human_baseline()
