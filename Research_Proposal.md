# Research Proposal

**Title:** Exploring Agentic AI in Anti-Forensics: Countermeasures Against Autonomous Evidence Tampering in Enterprise Monitoring Systems

**Student:** Emmanuel Chukwudinma Orji

**Programme:** MSc Cyber Security

**Supervisor:** Dr. Olayinka Adeboye

**Date:** 1st June 2026

---

## 1. Introduction

Organisations across all sectors depend on digital evidence to investigate security breaches, attribute malicious activity, and satisfy regulatory requirements. The integrity of this evidence — log files, file system metadata, timestamps, and audit trails — underpins the entire discipline of digital forensics and is a critical assumption of enterprise security monitoring. However, the emergence of agentic artificial intelligence (AI), defined as autonomous systems capable of planning and executing multi-stage operations without continuous human oversight (Acharya, Kuppan and Divya, 2025), now threatens to undermine this assumption fundamentally.

**Motivation:** In a prior study that I submitted to the 1st International Workshop on AI Safety and Security (AI-SS 2026) (Orji et al., 2026), I demonstrated that an autonomous AI agent can execute a complete anti-forensic operation — destroying evidence, manipulating timestamps, and sanitising logs — in under 300 milliseconds. This finding is deeply concerning for forensic practitioners: agentic AI, for all its transformative potential across industries, can equally be weaponised to undermine the very evidence that investigators depend upon. Yet despite this growing threat, there remain remarkably few tools or frameworks designed to counter the damage that autonomous AI agents can inflict on digital forensic processes. The gap between the offensive capabilities of agentic AI and the defensive tools available to forensic experts is widening rapidly. It was this realisation — that the tools to fight back simply do not yet exist — that motivated me, having first researched the extent to which agentic AI can evade traditional forensic monitoring, to shift my focus toward building practical countermeasures. This dissertation therefore represents a direct response: the design and evaluation of mitigation tools intended to help forensic experts and security teams detect and defend against the very threats that my prior study exposed.

**Problem Statement:** Enterprise Security Information and Event Management (SIEM) systems, including industry-standard platforms such as Wazuh, predominantly implement File Integrity Monitoring (FIM) through periodic polling — checking file system states at fixed intervals. This architectural design introduces a Time-of-Check to Time-of-Use (TOCTOU) vulnerability, creating a temporal blind spot exploitable by high-speed autonomous adversaries. While the exploitability of this vulnerability has been empirically demonstrated, no published study has systematically designed and evaluated defensive countermeasures capable of detecting and mitigating autonomous anti-forensic activity at machine speed.

**Approach:** This research proposes the design, implementation, and empirical evaluation of an integrated countermeasure framework that replaces periodic polling with event-driven, real-time monitoring combined with behavioural analysis, canary-based deception, and tamper-proof logging. The framework is evaluated against the validated autonomous Anti-Gravity agent within a controlled experimental environment, measuring detection latency, completeness, and false-positive rates.

---

## 2. Aim and Objectives

**Aim:** To design and empirically evaluate an integrated countermeasure framework capable of detecting and mitigating autonomous AI-driven anti-forensic operations that evade standard enterprise monitoring configurations.

**Objectives:**

1. To conduct a critical review of existing literature on anti-forensic techniques, TOCTOU vulnerabilities, and agentic AI in offensive security, identifying at least one clearly defined gap in current defensive capabilities, to be completed by the end of Week 2 (1st June 2026).

2. To design and implement an integrated countermeasure framework comprising five modules — real-time event-driven monitoring, behavioural anomaly detection, timestamp validation, canary-based deception, and log integrity protection — with all modules functionally tested by the end of Week 4 (15th June 2026).

3. To evaluate the countermeasure framework against a validated autonomous anti-forensic agent across a minimum of 30 controlled experimental trials, collecting quantitative measurements of detection latency (in milliseconds), detection completeness (percentage of attack stages detected), false-positive rate, and evidence preservation, to be completed by the end of Week 8 (13th July 2026).

4. To statistically compare the detection performance of the countermeasure framework against default enterprise SIEM configurations (periodic FIM) using inferential statistical tests (Mann-Whitney U) at the p < 0.05 significance level, with analysis completed by the end of Week 10 (27th July 2026).

5. To produce evidence-based recommendations for enterprise security configurations, derived directly from the experimental results, and present findings within the completed dissertation by the submission deadline of 18th August 2026.

---

## 3. Literature Review

### 3.1 Anti-Forensic Techniques

The foundational literature on anti-forensics is established by Garfinkel (2007), who categorised anti-forensic techniques into three principal classes: evidence destruction, evidence hiding, and elimination of evidence sources. Subsequent research has documented specific techniques in detail. Timestomping — the manipulation of file metadata structures such as the Master File Table (MFT) and inode attributes — allows attackers to conceal the true timeline of file activity, complicating forensic reconstruction (Carvey, 2014; Kroll, 2025). Secure data deletion, in which file contents are overwritten with random data prior to unlinking, prevents forensic recovery using standard carving tools (Garfinkel and Shelat, 2003). While these techniques are well documented individually, their automated, agentic execution at machine speed remains insufficiently examined in the literature.

### 3.2 Vulnerabilities in Periodic Monitoring Architectures

Enterprise SIEM platforms, including Wazuh, typically implement File Integrity Monitoring using a periodic auditing model in which file system states are compared at fixed intervals against historical baselines (Wazuh Documentation Team, 2024). This architectural choice introduces a temporal blind spot characterised as a TOCTOU vulnerability: malicious activity that occurs and is fully remediated between scans remains invisible to the monitoring system (Wei and Pu, 2005). While continuous or event-driven monitoring models offer improved detection accuracy, they impose significant computational and storage overheads, leading many organisations to retain periodic configurations (Chuvakin, Schmidt and Phillips, 2013).

### 3.3 Agentic AI in Offensive Security

The emergence of agentic AI in offensive contexts has been documented by Challita and Parrend (2025), who describe autonomous frameworks capable of executing multi-stage attack chains, and by Fang et al. (2024), who demonstrate the automation of complex cyber operations using AI. Acharya, Kuppan and Divya (2025) provide a comprehensive survey of agentic AI architectures, highlighting their capacity for autonomous decision-making and adaptive task execution. The operational distinction between manual and agentic anti-forensic activity is significant: manual attacks are limited by human reaction time and leave residual artefacts, whereas agentic systems complete entire anti-forensic workflows within sub-second timeframes.

### 3.4 Research Gap

While the exploitability of the TOCTOU Time Gap has been empirically demonstrated, the literature lacks a corresponding evaluation of defensive countermeasures against machine-speed anti-forensic agents. No published study has systematically assessed an integrated real-time detection architecture against autonomous anti-forensic operations within enterprise environments. This research directly addresses this gap by shifting the focus from attack demonstration to the design and empirical evaluation of countermeasures.

---

## 4. Distinction from Prior Work

It is important to clarify how this dissertation differs from the author's prior accepted paper (Orji et al., 2026). The two studies address complementary but distinct research questions:

| Aspect | Prior Paper (Orji et al., 2026) | This Dissertation |
|--------|------------------------|-------------------|
| **Focus** | Offensive — demonstrating the attack | Defensive — designing and evaluating countermeasures |
| **Research Question** | *Can* an autonomous agent evade enterprise FIM? | *How* do we detect and mitigate such agents? |
| **Contribution** | Identified the TOCTOU Time Gap vulnerability | Proposes and validates a framework to close it |
| **Artefact** | Anti-Gravity attack agent | AntiGravity Shield defence framework |
| **Evaluation** | Single-condition (attack vs default SIEM) | Comparative (default SIEM vs integrated countermeasures) |
| **Statistical Rigour** | Descriptive (reviewer-noted limitation) | Inferential (Mann-Whitney U, 30+ trials) |
| **Scope** | Attack-only | Attack + Defence + Human-baseline comparison |

The prior paper established the *problem*; this dissertation proposes and evaluates the *solution*. The dissertation also directly addresses the three recommendations made by the AI-SS 2026 reviewers: broader experimental scope, human-baseline comparisons, and inferential statistical analysis.

---

## 5. Research Questions

The proposed research is guided by the following questions:

**RQ1:** To what extent can real-time, event-driven monitoring detect autonomous anti-forensic operations that completely evade periodic File Integrity Monitoring?

**RQ2:** Can behavioural analysis techniques identify patterns characteristic of agentic anti-forensic execution — such as operation bursts and rapid file lifecycle events — and distinguish them from legitimate system activity?

**RQ3:** How effective are canary-based deception mechanisms at detecting and attributing autonomous anti-forensic operations?

**RQ4:** What is the detection latency, detection completeness, and false-positive rate of an integrated countermeasure framework compared to default enterprise SIEM configurations when subjected to autonomous anti-forensic attack?

**Hypothesis:** An integrated countermeasure framework combining kernel-level real-time monitoring, behavioural anomaly detection, timestamp validation, canary-based deception, and log integrity protection will achieve statistically significant improvements in detection rate and forensic evidence preservation compared to standard periodic FIM configurations.

---

## 6. Methodology

### 6.1 Research Approach

This research adopts the **Design Science Research Methodology (DSRM)** (Peffers et al., 2007), a widely accepted framework for information systems research that involves the creation and evaluation of IT artefacts to solve identified problems. The DSRM process is followed through six stages:

1. **Problem Identification:** The TOCTOU Time Gap vulnerability in enterprise periodic FIM, established by the prior study.
2. **Objectives Definition:** Design countermeasures that achieve real-time detection with measurable latency, completeness, and false-positive metrics (see Section 2).
3. **Design and Development:** Construction of the AntiGravity Shield countermeasure framework (see Section 6.3).
4. **Demonstration:** Deployment of the framework within a controlled simulation environment against a validated autonomous threat.
5. **Evaluation:** Quantitative comparative evaluation using inferential statistical methods (see Section 6.4).
6. **Communication:** Dissemination through this dissertation and potential follow-on publication.

### 6.2 Experimental Design

The study follows a two-condition comparative experimental design:

- **Control Condition:** Enterprise monitoring using default periodic FIM configuration (Wazuh SIEM with standard 12-hour scan intervals), representing current industry-standard practice.
- **Treatment Condition:** The proposed integrated countermeasure framework, designated "AntiGravity Shield," incorporating five coordinated detection modules operating in real-time.

The existing Anti-Gravity autonomous agent, developed and validated in the prior study, serves as the controlled, repeatable threat input. Both stealth mode (full anti-forensics) and noisy mode (standard operations without anti-forensics) are evaluated to isolate the effect of anti-forensic techniques on detection outcomes.

### 6.3 Countermeasure Framework Architecture

The AntiGravity Shield countermeasure framework comprises five coordinated modules:

1. **Real-Time File Monitor:** Replaces periodic polling with kernel-event-driven monitoring using Linux inotify, capturing every file system event at the moment it occurs. A SQLite-backed baseline database enables hash-based change detection.

2. **Timestamp Validator:** Detects metadata anomalies indicative of timestomping, including modification timestamps predating directory creation, timestamps set to implausible dates, and divergence between ctime and mtime fields.

3. **Behavioural Pattern Detector:** Analyses file system event streams using a sliding window to detect operation bursts, secure wiper signatures (the modify–rename–delete sequence), ephemeral file patterns, and rapid mass deletion.

4. **Canary Deployer:** Deploys honeypot files within monitored directories; any access, modification, or deletion constitutes a high-confidence indicator of intrusion.

5. **Log Protector:** Implements write-ahead, hash-chained logging to preserve audit trail integrity, enabling tamper detection.

### 6.4 Data Collection and Analysis

Each experimental condition is evaluated across a minimum of 30 independent trials. An automated test harness manages the full experimental workflow. A dedicated false-positive baseline test monitors a quiescent workspace with no attack activity.

The following metrics are collected per trial:

- **Detection Latency:** Time from the first anti-forensic action to alert generation (milliseconds)
- **Detection Completeness:** Percentage of attack stages successfully detected
- **False Positive Rate:** Alerts generated during normal system operation per unit time
- **Evidence Preservation:** Forensic artefacts recoverable post-attack

Inferential statistical tests (Mann-Whitney U for non-parametric distributions) are applied to determine statistical significance at the p < 0.05 level. Human-baseline timing comparisons provide qualitative context.

### 6.5 Ethical Considerations

All experiments are conducted within isolated virtual environments with no connection to production systems, live networks, or real user data. The anti-forensic agent operates exclusively on simulated files within sandboxed workspaces. No personal or sensitive data is involved. A formal risk assessment has been completed in accordance with university requirements.

---

## 7. Expected Results

It is anticipated that the integrated countermeasure framework will demonstrate:

- **Near-complete detection coverage** across all three anti-forensic stages, significantly outperforming the zero-detection outcome observed under default periodic FIM.
- **Sub-second detection latency** through event-driven kernel monitoring, effectively closing the TOCTOU Time Gap.
- **Low false-positive rates** due to behavioural thresholds calibrated to distinguish automated machine-speed operations from normal user activity.
- **Enhanced forensic evidence preservation** through hash-chained immutable logging and canary-based attribution.

The research will contribute empirical evidence to support recommendations for enterprise security configurations against agentic AI-driven threats and advance the academic understanding of the offensive–defensive balance in the context of autonomous AI systems.

---

## 8. Timescale

*Project duration: 13 weeks (18th May 2026 – 18th August 2026)*

| Phase | Activity | Weeks | Dates |
|-------|----------|-------|-------|
| **1** | Literature review and methodology refinement | 1 – 2 | 18 May – 1 Jun |
| **2** | Countermeasure framework completion and integration testing | 2 – 4 | 25 May – 15 Jun |
| **3** | Experimental environment setup and pilot trials | 4 – 5 | 15 Jun – 22 Jun |
| **4** | Primary data collection (30+ trials per condition) | 5 – 8 | 22 Jun – 13 Jul |
| **5** | Statistical analysis, results interpretation, and visualisation | 8 – 10 | 13 Jul – 27 Jul |
| **6** | Dissertation writing (chapters drafted iteratively alongside Phases 2–5) | 3 – 12 | 8 Jun – 10 Aug |
| **7** | Review, revisions, and final submission | 11 – 13 | 3 Aug – 18 Aug |

*Note: Phases overlap deliberately to maximise the limited timeframe. The countermeasure framework is substantially developed from the prior study, enabling an accelerated start to experimentation.*

---

## 9. References

Acharya, D.B., Kuppan, K. and Divya, B. (2025) 'Agentic AI: Autonomous Intelligence for Complex Goals – A Comprehensive Survey', *IEEE Access*.

Carvey, H. (2014) *Windows Forensic Analysis Toolkit*. 4th edn. Elsevier/Syngress.

Challita, B. and Parrend, P. (2025) 'RedTeamLLM: An Agentic AI Framework for Offensive Security', *arXiv preprint*, arXiv:2505.06913.

Chuvakin, A., Schmidt, K. and Phillips, C. (2013) *Logging and Log Management: The Authoritative Guide to Understanding the Concepts Surrounding Logging and Log Management*. Syngress.

Fang, R., Bindu, R., Gupta, A. and Kang, D. (2024) 'LLM Agents Can Autonomously Exploit One-Day Vulnerabilities', *arXiv preprint*, arXiv:2404.08144.

Garfinkel, S.L. (2007) 'Anti-Forensics and the Digital Investigator', in *Proceedings of the 5th Australian Digital Forensics Conference*. Perth, Western Australia.

Garfinkel, S.L. and Shelat, A. (2003) 'Remembrance of Data Passed: A Study of Disk Sanitization Practices', *IEEE Security and Privacy*, 1(1), pp. 17–27.

Juneja, A. (2025) 'Rx-Int: A Kernel Engine for Real-Time Detection and Analysis of In-Memory Threats', *arXiv preprint*, arXiv:2508.03879.

Kroll, A. (2025) *Breaking Time: Methods, Artifacts, and Forensic Detection of Timestomping on FAT32, Ext3, and Ext4 File Systems*. SANS Institute Information Security Reading Room.

Orji, E.C., Adenihun, A., Ojuolape-Oria, I., Ofeimun, O., Adeboye, O. and Akinseye, S. (2026) 'Exploring Agentic AI in Anti-Forensics: Simulation of Evasion Tactics in Digital Investigations', in *Proceedings of the 1st International Workshop on AI Safety and Security (AI-SS 2026)*, held in conjunction with the 21st European Dependable Computing Conference (EDCC 2026). Canterbury, UK, 7 April. IEEE CPS.

Peffers, K., Tuunanen, T., Rothenberger, M.A. and Chatterjee, S. (2007) 'A Design Science Research Methodology for Information Systems Research', *Journal of Management Information Systems*, 24(3), pp. 45–77.

Shannon, C.E. (1949) 'Communication in the Presence of Noise', *Proceedings of the IRE*, 37(1), pp. 10–21.

Wazuh Documentation Team (2024) *File Integrity Monitoring: How It Works*. Available at: https://documentation.wazuh.com (Accessed: 15 January 2026).

Wei, J. and Pu, C. (2005) 'TOCTTOU Vulnerabilities in Unix-Style File Systems: An Anatomical Study', in *FAST*, vol. 5, pp. 12–12.
