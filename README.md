# AntiGravity Shield v3.0 — AI-Powered Anti-Forensic Defense Framework

> Enterprise-grade, real-time kernel-level monitoring with AI-powered threat detection, attack chain correlation, and human-in-the-loop response.

## Quick Install (Windows)

### Prerequisites
- **Python 3.10+** — [Download](https://www.python.org/downloads/) (check "Add to PATH" during install)

### Option 1: One-Click Install
```
git clone https://github.com/amiclone/agshield.git
cd agshield
install.bat
```
Double-click `install.bat` — it installs dependencies, copies the shield, and creates Desktop launchers.

### Option 2: Manual Install
```bash
git clone https://github.com/amiclone/agshield.git
cd agshield
pip install -r requirements.txt
python shield_v3.py
```

### Auto-Start on Boot
```bash
python shield_v3.py --install     # Register as scheduled task
python shield_v3.py --uninstall   # Remove scheduled task
```

---

## What It Does

AntiGravity Shield monitors your file system in real-time and detects anti-forensic attacks using 6 AI layers:

| Layer | Feature | How |
|---|---|---|
| **1. Process Attribution** | Identifies WHO performed each operation | PID + process name via psutil |
| **2. AI Anomaly Engine** | Learns normal behavior, flags anomalies | Welford's rolling statistics + z-score |
| **3. Attack Chain Correlation** | Connects isolated events into campaigns | Temporal sequence matching (30s window) |
| **4. Response Engine** | Recommends actions, human approves | `approve/deny` CLI + evidence auto-vault |
| **5. SIEM + Timeline** | Exports alerts for Splunk/ELK | CEF syslog + hash-chained JSONL |
| **6. Windows Service** | Runs on system startup | Scheduled task auto-registration |

## Detection Capabilities

| Threat | Detection Method | Severity |
|---|---|---|
| **Timestomping** | mtime >30 days old, ctime <1 day | 🔴 CRITICAL |
| **Secure Wiping** | Same-size content overwrite (hash changed) | 🔴 CRITICAL |
| **Ephemeral Files** | Created and deleted within 5 seconds | 🔴 CRITICAL |
| **Wiper Renames** | Renamed to random alphanumeric string | 🔴 CRITICAL |
| **Executable Drops** | .exe/.bat/.ps1/.vbs/.dll created | 🟡 WARNING |
| **File/Dir Operations** | All create/modify/delete/rename events | 🟡 WARNING / 🔵 INFO |

## Output Files

After running, the shield creates these on your Desktop:

| File | Purpose |
|---|---|
| `shield_siem.log` | SIEM-compatible CEF format alerts |
| `shield_forensic_timeline.jsonl` | Tamper-proof hash-chained event log |
| `shield_evidence_vault/` | Auto-preserved copies of attacked files |
| `shield_v3_report.json` | Session summary (generated on exit) |

## Project Structure

```
agshield/
├── shield_v3.py              ★ Main shield (deploy this)
├── stealth_attack.py           Attack demo (5-phase stealth)
├── install.bat                 One-click Windows installer
├── requirements.txt            Python dependencies
│
├── AntiGravity_Shield/         Organized project files
│   ├── shield/                 All shield versions
│   ├── attack_agent/           Offensive AI agent modules
│   ├── defense_modules/        Defense framework components
│   ├── deployment/             Deployment & test scripts
│   ├── evidence/               Experiment results
│   ├── screenshots/            Documentation images
│   ├── dissertation/           Academic chapters
│   └── docs/                   Research papers & guides
│
├── agent_package/              Attack agent source
├── defense_framework/          Defense module source
├── antigravity-shield/         Package source (pip installable)
└── dissertation/               Academic writing
```

## Running the Attack Demo

With the shield running on one terminal:
```bash
python stealth_attack.py
```

This executes a 5-phase attack at machine speed:
1. **Staging** — Creates 4 sensitive files
2. **Timestomping** — Backdates all files 200-800 days
3. **Secure Wipe** — 3-pass random overwrite
4. **Wiper Rename** — Renames to 20-char random strings
5. **Mass Delete** — Destroys all evidence

The shield catches every phase in real-time.

## License

Academic research project — MSc Cybersecurity dissertation.
