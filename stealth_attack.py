"""Stealth Attack Agent — runs silently at machine speed"""
import os, time, string, random

home = os.path.expanduser("~")
stage = os.path.join(home, "Desktop", "ops_data")

print("[STEALTH] Phase 1: Creating staging directory...")
os.makedirs(stage, exist_ok=True)
files = {
    "financial_report_Q4.xlsx": "Revenue: 12.4M, Net Income: 3.2M, Confidential",
    "employee_records.csv": "Name,SSN,Salary\nJohn Doe,123-45-6789,95000",
    "server_credentials.txt": "root:Pr0d_S3rv3r2026\nadmin:B4ckd00r99",
    "incident_log.txt": "ALERT: Unauthorized access from 185.220.101.34",
}
for name, data in files.items():
    with open(os.path.join(stage, name), "w") as f:
        f.write(data)
    print(f"  [+] Created {name}")

print("[STEALTH] Phase 2: Timestomping all files...")
for name in files:
    fp = os.path.join(stage, name)
    days_back = random.randint(200, 800)
    old_time = time.time() - (days_back * 86400)
    os.utime(fp, (old_time, old_time))
    print(f"  [+] Backdated {name} by {days_back} days")

print("[STEALTH] Phase 3: Secure wiping (3-pass overwrite)...")
for name in files:
    fp = os.path.join(stage, name)
    sz = os.path.getsize(fp)
    for p in range(3):
        with open(fp, "wb") as f:
            f.write(os.urandom(sz))
    print(f"  [+] Wiped {name} ({sz} bytes, 3 passes)")

print("[STEALTH] Phase 4: Wiper renames...")
renamed = []
for name in os.listdir(stage):
    fp = os.path.join(stage, name)
    if os.path.isfile(fp):
        rnd = "".join(random.choices(string.ascii_letters, k=20))
        dst = os.path.join(stage, rnd)
        os.rename(fp, dst)
        renamed.append(dst)
        print(f"  [+] {name} -> {rnd}")

print("[STEALTH] Phase 5: Destroying all evidence...")
for fp in renamed:
    os.remove(fp)
    print(f"  [-] Deleted {os.path.basename(fp)}")
os.rmdir(stage)

print("\n[STEALTH] Attack complete. All evidence destroyed.")

