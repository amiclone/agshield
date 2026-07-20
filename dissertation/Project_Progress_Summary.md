# AntiGravity Shield — Project Progress Summary

## 1. Completed Work

### 1.1 Dissertation Chapters Written

| Chapter | Title | Status |
|---------|-------|--------|
| Front Matter | Title, Abstract, Declaration | Complete |
| Chapter 1 | Introduction | Complete |
| Chapter 2 | Literature Review | Complete |
| Chapter 3 | Methodology | Complete |
| Chapter 4 | Design and Implementation | Complete |

### 1.2 Attack Agent (Offensive Artefact)

- **stealth_attack.py** — Five-phase machine-speed anti-forensic attack agent executing at under 100 milliseconds: evidence staging, timestomping, secure three-pass wiping, wiper rename obfuscation, and evidence destruction.
- **human_baseline.py** — Human-speed simulation with realistic command typing delays (1.5 to 6.0 seconds per action) for qualitative comparison.
- Validated in the AISS 2026 accepted paper with an average execution time of 370 milliseconds across five trials.

### 1.3 AntiGravity Shield v3.0 (Defensive Artefact — Seven Layers)

**Layer 1 — Process Attribution:** Real-time identification of which process triggered each file system event using the psutil library. Includes a curated list of suspicious process names for immediate flagging.

**Layer 2 — Attack Chain Correlation:** Temporal grouping of related events within a 30-second sliding window. Detects three patterns: full anti-forensic chains, stage-and-destroy sequences, and wipe-then-delete sequences.

**Layer 3 — AI Anomaly Engine:** Statistical baseline learning using Welford's online algorithm. Detects operation bursts exceeding 2.5 standard deviations from the learned normal event rate.

**Layer 4 — Human-in-the-Loop Response Engine:** Requires explicit human approval before any destructive countermeasure is executed. All critical events are automatically preserved in an evidence vault regardless of operator response.

**Layer 5 — SIEM Integration:** Generates all alerts in Common Event Format (CEF) for ingestion by enterprise SIEM platforms including Splunk, QRadar, ArcSight, and Wazuh.

**Layer 6 — Forensic Timeline:** Maintains a tamper-evident, hash-chained audit log using SHA-256. Any modification to historical entries invalidates the chain from the point of tampering onwards.

**Layer 7 — Canary Deployer:** Plants realistic honeypot files (passwords, SSH keys, credentials) into monitored directories. Any interaction with these files is a zero-false-positive intrusion indicator.

### 1.4 Core Detection Capabilities

- Same-size overwrite detection (secure wipe signature) — WIPE_DETECTED
- Modification time and creation time divergence (timestomping) — TIMESTOMPING_DETECTED
- Files created and deleted within 5 seconds (staging operations) — EPHEMERAL_FILE
- Random alphanumeric rename patterns (wiper malware signature) — WIPER_RENAME
- Canary file tampering or deletion — CANARY_TAMPERED and CANARY_MISSING
- Directory creation, deletion, and rename tracking

### 1.5 Experimental Infrastructure

- **test_harness_v3.py** — Automated trial runner executing the full experimental workflow: workspace creation, shield initialisation, canary deployment, stabilisation pause, attack execution, event propagation pause, data collection, and teardown.
- **analyze_results.py** — Statistical analysis module implementing the Mann-Whitney U test in pure Python, rank-biserial correlation effect size, descriptive statistics, and automated generation of dissertation-ready results tables.
- Four quantitative metrics collected per trial: detection latency in milliseconds, detection completeness as a percentage, false-positive rate, and evidence preservation status.
- False positive test: 10-second silent monitoring with no adversarial input.

### 1.6 Deployment and Packaging

- **install.bat** — One-click Windows installer managing dependencies and launcher creation.
- Windows scheduled task registration for automatic service start on user logon.
- Repository published to GitHub at github.com/amiclone/agshield.
- Automated markdown-to-docx converter for all dissertation chapters.

### 1.7 AISS 2026 Reviewer Feedback Addressed

**Reviewer 1 (Accept):** Requested more systematic inferential statistics with multiple trials. Addressed by the automated test harness producing 30 or more trials and the Mann-Whitney U statistical analysis module.

**Reviewer 2 (Strong Accept):** Requested elaboration on broader architectural and operational implications. Addressed by the seven-layer integrated defence framework with SIEM integration and enterprise deployment support.

**Reviewer 3 (Weak Accept):** Requested human baseline comparison, broader experimental scope, and additional SIEM platform evaluation. Addressed by the human baseline simulation script, canary deployer module, and CEF-based SIEM integration supporting multiple platforms.

## 2. Remaining Work

### Step 1 — Run the 30-Trial Experiment on the Windows VM

Execute the automated test harness on the Windows virtual machine to produce the empirical data required for Chapter 5. The experiment must run on Windows because the ReadDirectoryChangesW kernel API provides the event-driven monitoring required for full detection coverage, particularly for timestomping detection which is not triggered by Linux inotify.

Commands to execute on the Windows VM:

- python test_harness_v3.py --trials 30
- python analyze_results.py

### Step 2 — Write Chapter 5: Results and Analysis

Present the 30-trial quantitative data including detection latency statistics (mean, median, standard deviation), detection completeness by attack category, Mann-Whitney U test results with p-value and effect size, the comparison table between the Shield and default periodic FIM, false positive test results, and evidence preservation verification.

### Step 3 — Write Chapter 6: Discussion

Interpret the experimental results against each of the four research questions. Confirm or reject the hypothesis. Compare results with existing literature. Discuss limitations and implications for enterprise security practice.

### Step 4 — Write Chapter 7: Conclusions and Future Work

Summarise the research contributions. Revisit each of the five objectives. Identify directions for future work including evaluation on additional SIEM platforms, machine-learning-based detection, and network-level anti-forensics.

### Step 5 — Write Chapter 8: Legal, Social, Ethical and Professional Issues

Reflect on dual-use research ethics, responsible disclosure principles, GDPR considerations, and professional responsibilities in offensive security research.

### Step 6 — Final Assembly and Submission

Merge all chapters into a single document. Consolidate the references list. Add appendices containing code listings and raw experimental data. Proofread and submit by the deadline of 18th August 2026.
