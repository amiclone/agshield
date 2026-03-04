import os
import time
import json
import platform
import timestomper
import data_wiper
import log_cleaner

REPORT_FILE = "operation_report.json"
EVIDENCE_FILE = "stolen_plans.txt"
DROPPER_FILE = "malware_dropper.exe"
EVIDENCE_FILE = "stolen_plans.txt"

def generate_activity():
    """Creates some dummy files to simulate 'activity'."""
    print("[*] Agent Active. Simulating malicious activity...")
    
    # Create a "sensitive" file
    with open(EVIDENCE_FILE, "w") as f:
        f.write("CONFIDENTIAL DATA: Target IP List...\n")
        f.write("192.168.1.100\n192.168.1.101\n")
    print(f"[+] Created evidence: {EVIDENCE_FILE}")
    
    # Create the "dropper"
    with open(DROPPER_FILE, "w") as f:
        f.write("binary content simulation")
    print(f"[+] Dropped payload: {DROPPER_FILE}")
    
    time.sleep(2) # Wait a bit to have some real time difference

def run_cleanup():
    """Performs the Anti-Forensics."""
    report = {"actions": []}
    
    print("\n[*] INITIATING CLEANUP PHASE...")
    
    import sys
    mode = "stealth"
    delay = 0
    
    # Simple argument parsing
    if "--noisy" in sys.argv:
        mode = "noisy"
        print("[!] RUNNING IN NOISY MODE (No Stealth)")
        
    for i, arg in enumerate(sys.argv):
        if arg == "--delay" and i + 1 < len(sys.argv):
            try:
                delay = float(sys.argv[i+1])
            except ValueError:
                pass

    if delay > 0:
        print(f"[*] Waiting {delay} seconds before cleanup phase (simulating delayed forensics response)...")
        time.sleep(delay)
        
    # Start high-precision timer for the actual cleanup actions
    start_time = time.perf_counter()

    # 1. Timestomp
    if mode == "stealth":
        print(f"[*] Timestomping {DROPPER_FILE} to look like a system file...")
        if timestomper.stomp_file(DROPPER_FILE):
            report["actions"].append({"tool": "timestomper", "target": DROPPER_FILE, "status": "success", "technique": "Backdating"})
        else:
            report["actions"].append({"tool": "timestomper", "target": DROPPER_FILE, "status": "failed"})
    else:
        print(f"[!] NOISY: Skipping Timestomp on {DROPPER_FILE} (Leaving evidence fresh)")
        report["actions"].append({"tool": "timestomper", "status": "skipped_noisy"})

    # 2. Wipe
    if mode == "stealth":
        print(f"[*] Wiping {EVIDENCE_FILE}...")
        if data_wiper.secure_wipe(EVIDENCE_FILE, passes=3):
            report["actions"].append({"tool": "wiper", "target": EVIDENCE_FILE, "status": "success", "technique": "Overwriting+Renaming"})
        else:
            report["actions"].append({"tool": "wiper", "target": EVIDENCE_FILE, "status": "failed"})
    else:
        print(f"[!] NOISY: Standard deletion of {EVIDENCE_FILE} (Recoverable & Detected)")
        try:
            os.remove(EVIDENCE_FILE)
            report["actions"].append({"tool": "standard_delete", "target": EVIDENCE_FILE, "status": "success"})
        except Exception as e:
            print(f"[-] Delete failed: {e}")

    # 3. Clean Logs
    if mode == "stealth":
        print(f"[*] Cleaning Tracks...")
        log_cleaner.clean_logs()
        report["actions"].append({"tool": "log_cleaner", "status": "attempted"})
    else:
        print(f"[!] NOISY: Skipping Log Cleaning (Traces left intact)")
        report["actions"].append({"tool": "log_cleaner", "status": "skipped_noisy"})
    
    # Stop timer
    end_time = time.perf_counter()
    execution_time = end_time - start_time
    report["execution_time_seconds"] = round(execution_time, 4)
    report["delay_seconds"] = delay
    report["mode"] = mode
    
    print(f"[*] Cleanup Phase completed in {execution_time:.4f} seconds.")
    
    # Write report
    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=4)
    print(f"\n[+] Operation Complete. Report saved to {REPORT_FILE}")

if __name__ == "__main__":
    generate_activity()
    run_cleanup()
