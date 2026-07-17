# AntiGravity Shield v3.0 — AI-Powered Anti-Forensic Defense Framework

## Project Structure

```
AntiGravity_Shield/
├── shield/                    # Core Shield (deploy to Windows VM)
│   ├── shield_v3.py           # ★ MAIN — AI-powered monitor (all 6 layers)
│   ├── shield_live_demo.py    # Self-contained attack + detection demo
│   ├── shield_watch.py        # v2 monitor (legacy, stable)
│   ├── shield_monitor.py      # v1 monitor (original prototype)
│   ├── shield_dashboard.py    # GUI dashboard (optional)
│   └── Start_Shield.vbs       # Windows launcher script
│
├── attack_agent/              # Offensive AI Agent (the attacker)
│   ├── agent_controller.py    # Orchestrates all attack modules
│   ├── timestomper.py         # Timestamp manipulation module
│   ├── data_wiper.py          # Secure file wiping module
│   ├── log_cleaner.py         # Log tampering module
│   └── human_baseline.py      # Human-speed baseline comparison
│
├── defense_modules/           # Defense Framework Components
│   ├── shield_controller.py   # Orchestration controller
│   ├── test_harness.py        # Empirical test harness (metrics)
│   ├── behavioral_detector.py # Behavioral analysis engine
│   ├── canary_deployer.py     # Canary file deployment
│   ├── log_protector.py       # Log integrity protection
│   ├── realtime_monitor.py    # Real-time monitoring base
│   └── timestamp_validator.py # Timestamp validation engine
│
├── deployment/                # Deployment & Testing
│   ├── deploy_shield.py       # Automated VM deployment
│   ├── remote_deployer.py     # SSH remote deployment
│   ├── test_shield_windows.py # Windows integration tests
│   ├── test_real_detection.py # Detection validation tests
│   └── requirements.txt       # Python dependencies
│
├── evidence/                  # Experimental Evidence
│   ├── agent_experiment_report.md
│   ├── victim_report_evidence.json
│   ├── victim_report_noisy.json
│   └── victim_report_stealth.json
│
├── screenshots/               # Screenshots for documentation
│
├── dissertation/              # Academic Writing
│   ├── 00_Front_Matter.md
│   ├── Chapter_1_Introduction.md
│   ├── Chapter_2_Literature_Review.md
│   ├── Chapter_3_Methodology.md
│   ├── convert_to_docx.py
│   └── *.docx (compiled versions)
│
└── docs/                      # Reference Documents
    ├── Research_Proposal.md
    ├── report_guide.md
    ├── report_role_1_attacker.md
    ├── report_role_2_engineer.md
    ├── report_role_3_analyst.md
    └── *.pdf (papers & reviews)
```

## Quick Start

### On Windows VM:
```bash
# Deploy shield
scp shield/shield_v3.py vboxuser@VM_IP:C:\Users\vboxuser\shield_v3.py

# Run shield
python shield_v3.py

# Install as auto-start service
python shield_v3.py --install

# Uninstall service
python shield_v3.py --uninstall
```

### Run Demo (shield + attack):
```bash
python shield/shield_live_demo.py
```

## Shield v3.0 Features
1. **Process Attribution** — WHO did it (PID + process name)
2. **Attack Chain Correlation** — CONNECT events into campaigns
3. **AI Anomaly Engine** — LEARN normal behavior, detect abnormal
4. **Response Engine** — RECOMMEND actions, human approves
5. **SIEM Connector** — CEF syslog format for Splunk/ELK
6. **Forensic Timeline** — Hash-chain tamper-proof evidence
7. **Windows Service** — Auto-start on logon

## Output Files (on VM Desktop)
- `shield_siem.log` — SIEM-compatible alert log
- `shield_forensic_timeline.jsonl` — Tamper-proof forensic timeline
- `shield_evidence_vault/` — Auto-preserved evidence files
- `shield_v3_report.json` — Session summary report
