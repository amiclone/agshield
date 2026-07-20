# Chapter 4: Design and Implementation

This chapter presents the architectural design and implementation of the two primary artefacts developed in this research: the Anti-Gravity autonomous attack agent and the AntiGravity Shield countermeasure framework. The chapter begins with an overview of the experimental environment, then describes the attack agent — which serves as the controlled, repeatable threat input — before detailing each of the seven coordinated modules that comprise the defence framework. The test harness used for automated experimental evaluation is described in the final section.

## 4.1 Experimental Environment

All experiments are conducted within an isolated virtualised environment to ensure full experimental control and eliminate risk to live systems.

**Host System:** Ubuntu Linux workstation serving as the development and orchestration platform. The host manages the virtual machine lifecycle, deploys artefacts via SSH, and collects experimental data.

**Target System:** Windows 11 virtual machine running under KVM/QEMU, provisioned with Python 3.12.2. The Windows platform was selected because it reflects the dominant enterprise desktop environment and provides the `ReadDirectoryChangesW` kernel API — a synchronous, event-driven file system monitoring interface that underpins the real-time detection capability of the Shield framework.

**Dependencies:** The framework requires only two external Python packages — `watchdog` (for cross-platform file system event monitoring via kernel APIs) and `psutil` (for process enumeration and attribution). Both are installed automatically by the deployment script if not already present.

**Isolation:** The virtual machine operates on an isolated virtual network with no connectivity to the host network or the internet during experimental trials. This ensures that experimental measurements are not contaminated by external network activity and that the offensive agent poses no risk to production systems.

## 4.2 The Anti-Gravity Attack Agent

The Anti-Gravity autonomous agent, originally developed and validated in the prior AI-SS 2026 study (Orji et al., 2026), serves as the controlled threat input for all experimental trials. The agent executes a five-phase anti-forensic operation at machine speed, with zero inter-phase delays, representing the worst-case scenario for defensive monitoring systems.

### 4.2.1 Attack Phases

The agent's operational sequence proceeds as follows:

**Phase 1 — Evidence Staging:** The agent creates a staging directory and populates it with four files containing simulated sensitive data (financial records, employee data, server credentials, and incident logs). These files represent the types of forensic artefacts that an adversary would seek to destroy.

**Phase 2 — Timestomping:** Each file's `mtime` (modification time) and `atime` (access time) are set to a randomised date between 200 and 800 days in the past using the `os.utime()` system call. This technique, known as timestomping (Carvey, 2014), is designed to make recently created or modified files appear aged, undermining timeline-based forensic analysis.

**Phase 3 — Secure Wiping:** Each file undergoes a three-pass cryptographic overwrite using `os.urandom()`. Each pass writes a quantity of random bytes equal to the original file size, ensuring that the original content cannot be recovered through standard forensic carving techniques (Garfinkel and Shelat, 2003). Critically, the file size remains unchanged after wiping — a signature that the Shield framework is designed to detect.

**Phase 4 — Wiper Rename:** Each file is renamed to a random 20-character alphabetic string with no file extension. This obfuscation technique disrupts filename-based forensic correlation and is characteristic of automated wiper malware (Kroll, 2025).

**Phase 5 — Evidence Destruction:** All renamed files are permanently deleted using `os.remove()`, and the staging directory is removed. At the conclusion of this phase, no trace of the original files remains on the file system.

The entire five-phase sequence completes in under 100 milliseconds on the target system, well within the TOCTOU Time Gap identified in the prior study.

### 4.2.2 Design Rationale

The agent is deliberately designed to be minimal and self-contained — a single Python script with no external dependencies — to ensure that its execution characteristics are deterministic and reproducible across trials. The zero-delay execution model represents the operational ceiling of autonomous anti-forensic capability: if the defence framework can detect this agent, it can detect any slower variant.

## 4.3 The AntiGravity Shield Framework

The AntiGravity Shield is an integrated countermeasure framework comprising seven coordinated modules, each addressing a distinct aspect of the detection and evidence preservation challenge. The framework is implemented as a single self-contained Python script (`shield_v3.py`, 799 lines) to simplify deployment and eliminate dependency conflicts in enterprise environments.

The architectural design follows the defence-in-depth principle: no single module is relied upon exclusively. Each module contributes independent detection signals, and the combination of signals provides both high detection completeness and low false-positive rates. Figure 4.1 illustrates the modular architecture.

**Table 4.1:** AntiGravity Shield v3.0 — Module Summary.

| Layer | Module | Function | Detection Output |
|-------|--------|----------|-----------------|
| 1 | Process Attribution | Identifies which process triggered each file system event | PID, process name |
| 2 | Attack Chain Correlation | Groups temporally related events into attack campaigns | `ATTACK_CHAIN_DETECTED` |
| 3 | AI Anomaly Engine | Learns baseline activity rates; detects statistical anomalies | `ANOMALY_BURST` |
| 4 | Human-in-the-Loop Response | Requires human approval before destructive countermeasures | Approve/Deny prompts |
| 5 | SIEM Integration | Forwards all events in Common Event Format (CEF) | CEF syslog entries |
| 6 | Forensic Timeline | Maintains a tamper-evident, hash-chained audit log | `VERIFIED` / `COMPROMISED` |
| 7 | Canary Deployer | Plants honeypot tripwire files; any interaction is an intrusion indicator | `CANARY_TAMPERED` / `CANARY_MISSING` |

### 4.3.1 Layer 1: Process Attribution

The Process Attribution module addresses a fundamental limitation of traditional FIM systems: they report *what* changed but not *who* changed it. Without process-level attribution, security analysts cannot distinguish between legitimate system processes (e.g., Windows Update modifying system files) and malicious actors.

The module leverages the `psutil` library to enumerate all running processes and identify which process holds an open file handle matching the path of a detected file system event. A curated list of suspicious process names — including script interpreters (`python.exe`, `powershell.exe`, `bash`), script hosts (`wscript`, `cscript`), and known living-off-the-land binaries (`mshta`) — enables immediate flagging of events attributed to high-risk processes.

Process information is cached with a configurable time-to-live to minimise the performance overhead of repeated process table scans during burst activity.

### 4.3.2 Layer 2: Attack Chain Correlation

Individual file system events — a file creation here, a modification there — are often insufficient to diagnose an attack in progress. The Attack Chain Correlator aggregates temporally proximate events into coherent attack campaigns using a sliding time window (default: 30 seconds).

The module maintains a deque of recent events and applies three pattern-matching rules:

1. **Full Anti-Forensic Chain:** Detection of timestomping, wiping, and deletion events affecting the same directory within the time window triggers an `ATTACK_CHAIN_DETECTED` alert with CRITICAL severity.
2. **Stage-and-Destroy Pattern:** File creation followed by deletion within the window — characteristic of staging operations — triggers a `STAGE_AND_DESTROY` alert.
3. **Wipe-and-Delete Sequence:** Secure wiping followed by file deletion — the signature cleanup phase of anti-forensic operations — triggers a `WIPE_THEN_DELETE` alert.

These correlation rules are derived directly from the operational patterns observed in the prior AI-SS 2026 study and represent the behavioural fingerprint of autonomous anti-forensic agents.

### 4.3.3 Layer 3: AI Anomaly Engine

The AI Anomaly Engine provides a statistical baseline against which abnormal file system activity is evaluated. Unlike signature-based detection, which requires prior knowledge of specific attack patterns, the anomaly engine can detect novel threats by identifying deviations from learned normality.

The engine operates in two phases:

**Learning Phase (default: 60 seconds):** During the initial learning window, the engine observes all file system events and computes a running estimate of the mean event rate (events per minute) and its standard deviation using **Welford's online algorithm** (Welford, 1962). This algorithm is numerically stable for streaming data and requires only constant memory — O(1) — making it suitable for continuous operation on resource-constrained systems.

**Detection Phase:** Once the baseline is established, each new event is evaluated against the learned distribution. If the instantaneous event rate exceeds the mean by more than 2.5 standard deviations (a z-score threshold), an `ANOMALY_BURST` alert is generated. This threshold was selected to balance sensitivity against false-positive risk: a z-score of 2.5 corresponds to a probability of approximately 0.62% under a normal distribution, meaning that fewer than 1 in 160 normal activity windows would trigger a false alarm.

### 4.3.4 Layer 4: Human-in-the-Loop Response Engine

A core design principle of the AntiGravity Shield is that **no autonomous destructive action is taken without explicit human authorisation**. This principle reflects the responsible AI design philosophy advocated by Shneiderman (2022) and addresses a legitimate concern in automated security systems: the risk of false-positive-driven damage, where an overzealous automated response causes more harm than the attack it attempts to mitigate.

When a CRITICAL-severity event is detected, the Response Engine generates a recommended action — for example, quarantining a suspicious process or isolating a file — and presents it to the operator via an interactive command-line prompt. The operator must explicitly type `approve` or `deny` before any action is executed. This human-in-the-loop architecture ensures that the framework enhances human decision-making rather than replacing it.

All critical events, regardless of the operator's response, are automatically preserved in an evidence vault — a dedicated directory where copies of affected files are stored with timestamped filenames. This ensures that forensic evidence is captured even if the operator chooses not to act immediately.

### 4.3.5 Layer 5: SIEM Integration (CEF)

Enterprise security operations centres (SOCs) typically aggregate alerts from multiple sources into a centralised SIEM platform. To support integration with existing enterprise infrastructure, the Shield generates all alerts in **Common Event Format (CEF)** — the de facto standard for SIEM log ingestion supported by platforms including Splunk, QRadar, ArcSight, and Wazuh (ArcSight, 2017).

Each CEF log entry includes: the event timestamp, severity level (mapped to the CEF 0–10 severity scale), event type, affected file path, process attribution data, and a human-readable description. Log entries are written to a dedicated file (`shield_siem.log`) on the user's Desktop, which can be configured as a log source in any CEF-compatible SIEM platform.

This integration layer ensures that the Shield does not operate in isolation but feeds its detection signals into the broader enterprise security monitoring ecosystem.

### 4.3.6 Layer 6: Forensic Timeline (Hash-Chained)

The Forensic Timeline module addresses the evidence preservation requirement identified in Research Question 4. Traditional log files are vulnerable to tampering — an attacker who gains access to the monitoring system could modify or delete log entries to conceal their activity. The Shield mitigates this risk through a **hash-chained audit log** inspired by blockchain-style integrity verification.

Each log entry is serialised as a JSON object and appended to a JSONL (JSON Lines) file. Before appending, the entry is augmented with a `chain_hash` field computed as:

```
chain_hash = SHA-256(previous_chain_hash + serialised_entry)
```

The first entry uses a genesis hash of `"0" * 64`. This construction ensures that any modification to a historical entry — insertion, deletion, or alteration — invalidates the chain from the point of tampering onwards. The `verify_integrity()` method recomputes the chain from the genesis entry and reports `VERIFIED` if all hashes match or `COMPROMISED` if any discrepancy is detected.

This mechanism provides forensic analysts with cryptographic assurance that the audit trail has not been tampered with, even if the attacker subsequently gains administrative access to the monitoring system.

### 4.3.7 Layer 7: Canary Deployer (Deception-Based Detection)

The Canary Deployer implements a deception-based detection strategy designed to achieve **zero false positives by construction**. The module deploys honeypot files — realistic-looking decoys with names such as `passwords_backup.txt`, `ssh_private_key.bak`, and `database_credentials.conf` — into monitored directories. These files are designed to attract attackers: their filenames suggest high-value targets that an adversary would prioritise for exfiltration or destruction.

Each deployed canary file is registered with its SHA-256 hash in a persistent registry. The Shield monitors these files through two mechanisms:

1. **Real-time detection:** The `ShieldDetector` event handler checks every file modification and deletion event against the canary registry. If a canary file is modified, a `CANARY_TAMPERED` alert is generated at CRITICAL severity. If a canary file is deleted, a `CANARY_MISSING` alert is generated.
2. **Periodic verification:** Every 30 seconds during the heartbeat cycle, the Canary Deployer re-verifies all registered canaries by recomputing their SHA-256 hashes and checking for missing files.

The zero-false-positive property arises from the fact that legitimate users have no reason to interact with canary files. Any access — read, modify, or delete — is, by definition, unauthorised and constitutes an intrusion indicator. This property makes canary-based detection particularly valuable for environments where false-positive fatigue is a significant operational concern.

## 4.4 Core File System Detector

The `ShieldDetector` class is the central event handler that receives all file system notifications from the operating system kernel. It extends the `watchdog` library's `FileSystemEventHandler` and implements handlers for four event types:

**`on_created`:** Records the file creation timestamp in a birth registry and computes an initial SHA-256 hash. Executable files (`.exe`, `.bat`, `.ps1`, `.vbs`, `.cmd`, `.dll`) trigger WARNING-severity alerts.

**`on_modified`:** Implements two critical detection checks:
- **Same-size overwrite detection (wipe detection):** If a file's hash has changed but its size is identical to the previously recorded size, a `WIPE_DETECTED` alert is generated at CRITICAL severity. This pattern — content change without size change — is the characteristic signature of a secure wipe operation.
- **Timestamp anomaly detection (timestomping):** If a file's modification time is more than 30 days in the past while its creation time is less than 1 day old, a `TIMESTOMPING_DETECTED` alert is generated. This divergence between `mtime` and `ctime` is physically impossible under normal file system operations and constitutes strong evidence of timestamp manipulation.

**`on_deleted`:** Checks the birth registry to compute the file's lifespan. If a file was created and deleted within 5 seconds, an `EPHEMERAL_FILE` alert is generated at CRITICAL severity — this pattern is characteristic of staging-and-cleanup operations used by attack agents.

**`on_moved`:** Detects wiper-style renames by checking whether the destination filename is a long, random alphanumeric string with no file extension — the signature rename pattern used by automated wiper malware.

All detected events are forwarded to every active layer: Process Attribution, Chain Correlator, Anomaly Engine, SIEM Connector, Forensic Timeline, and the Canary registry check. This fan-out architecture ensures that each layer receives complete visibility of all file system activity.

## 4.5 Automated Test Harness

The automated test harness (`test_harness_v3.py`) orchestrates the complete experimental workflow described in Chapter 3, Section 3.4.1. The harness is designed to run unattended, executing a specified number of trials and producing structured JSON output suitable for statistical analysis.

### 4.5.1 Trial Workflow

Each trial follows an identical seven-step procedure:

1. **Workspace creation:** A clean, isolated directory (`harness_workspace/`) is created. Any residual data from previous trials is deleted.
2. **Module initialisation:** All seven Shield modules are instantiated with trial-specific configuration — separate log files, canary registries, and evidence vaults per trial to prevent cross-contamination.
3. **Canary deployment:** Three canary files are deployed into the workspace.
4. **Observer start and stabilisation:** The `watchdog` Observer is started and a 500-millisecond pause allows the kernel monitoring subsystem to fully initialise.
5. **Attack execution:** The five-phase attack is executed inline (not as a subprocess), ensuring precise `time.perf_counter()` timing of the attack duration.
6. **Event propagation pause:** A 2.0-second pause allows all kernel-buffered events to propagate through the detection pipeline.
7. **Data collection:** The Observer is stopped, alerts are collected, and all four quantitative metrics (latency, completeness, false-positive rate, evidence preservation) are computed.

### 4.5.2 False Positive Test

A dedicated false-positive test creates a workspace containing five benign files, starts the Shield with all modules active (excluding canaries), monitors for 10 seconds with no adversarial input, and counts any WARNING or CRITICAL alerts generated. The expected outcome is zero false positives.

## 4.6 Statistical Analysis Module

The statistical analysis module (`analyze_results.py`) loads the JSON output from the test harness and performs the inferential analyses described in Chapter 3, Section 3.5.

The module implements the **Mann-Whitney U test** in pure Python (no external statistical library required), using the normal approximation for the U statistic z-score and the Abramowitz and Stegun (1964) approximation for the standard normal cumulative distribution function. Effect size is computed as the **rank-biserial correlation** r = 1 − (2U / n₁n₂).

The control condition — default periodic FIM — is modelled as a vector of detection latencies equal to 43,200,000 milliseconds (12 hours, the default Wazuh `syscheck` interval) with 0% detection completeness. This representation is justified by the empirical finding from the prior study that periodic FIM detected zero anti-forensic operations across all trials.

The module produces two outputs:
1. **`dissertation_results.md`:** A pre-formatted markdown document containing all tables, descriptive statistics, Mann-Whitney U results, and comparison tables, suitable for direct incorporation into Chapter 5.
2. **`statistical_analysis.json`:** A structured JSON file containing all computed statistics for programmatic access and verification.

## 4.7 Chapter Summary

This chapter has presented the design and implementation of the AntiGravity Shield v3.0 countermeasure framework and its supporting experimental infrastructure. The framework comprises seven coordinated modules — process attribution, attack chain correlation, AI anomaly detection, human-in-the-loop response, SIEM integration, hash-chained forensic logging, and canary-based deception — each providing an independent detection signal. The automated test harness and statistical analysis module together form a complete experimental pipeline capable of executing 30+ trials and producing publication-ready inferential statistics. The following chapter presents the quantitative results of the experimental evaluation.

---

## References (Chapter 4)

Abramowitz, M. and Stegun, I.A. (1964) *Handbook of Mathematical Functions with Formulas, Graphs, and Mathematical Tables*. Washington, DC: National Bureau of Standards.

ArcSight (2017) *Common Event Format (CEF) Implementation Standard*. Rev. 25. Micro Focus.

Carvey, H. (2014) *Windows Forensic Analysis Toolkit*. 4th edn. Elsevier/Syngress.

Garfinkel, S.L. and Shelat, A. (2003) 'Remembrance of Data Passed: A Study of Disk Sanitization Practices', *IEEE Security and Privacy*, 1(1), pp. 17–27.

Kroll, A. (2025) *Breaking Time: Methods, Artifacts, and Forensic Detection of Timestomping on FAT32, Ext3, and Ext4 File Systems*. SANS Institute Information Security Reading Room.

Orji, E.C., Adenihun, A., Ojuolape-Oria, I., Ofeimun, O., Adeboye, O. and Akinseye, S. (2026) 'Exploring Agentic AI in Anti-Forensics: Simulation of Evasion Tactics in Digital Investigations', in *Proceedings of the 1st International Workshop on AI Safety and Security (AI-SS 2026)*, held in conjunction with the 21st European Dependable Computing Conference (EDCC 2026). Canterbury, UK, 7 April. IEEE CPS.

Shneiderman, B. (2022) *Human-Centered AI*. Oxford: Oxford University Press.

Welford, B.P. (1962) 'Note on a Method for Calculating Corrected Sums of Squares and Products', *Technometrics*, 4(3), pp. 419–420.
