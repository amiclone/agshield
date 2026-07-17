# Chapter 1: Introduction

## 1.1 Background and Context

The integrity of digital evidence is the foundational pillar upon which modern cybersecurity incident response, forensic investigation, and regulatory compliance are built. Organisations across every sector — from financial services and healthcare to critical national infrastructure — depend upon the trustworthiness of log files, file system metadata, timestamps, and audit trails to reconstruct security incidents, attribute malicious activity, and satisfy legal and regulatory obligations (Casey, 2011; NIST, 2006). When this evidence can no longer be trusted, the entire chain of accountability that underpins enterprise security collapses.

Anti-forensic techniques — methods deliberately designed to undermine the digital forensic process — have been documented in the academic literature for nearly two decades. Garfinkel (2007) established the foundational taxonomy, categorising anti-forensic methods into three principal classes: evidence destruction, evidence hiding, and elimination of evidence sources. Subsequent research has examined specific techniques in considerable depth, including timestomping — the manipulation of file metadata structures to conceal the true timeline of malicious activity (Carvey, 2014; Kroll, 2025) — and secure data deletion, in which file contents are overwritten prior to unlinking, defeating standard forensic recovery tools (Garfinkel and Shelat, 2003).

Historically, these techniques have been the province of skilled human adversaries operating at human speed. Defenders have, in turn, developed monitoring tools — most notably Security Information and Event Management (SIEM) platforms with integrated File Integrity Monitoring (FIM) — that are architecturally calibrated to detect human-speed intrusions. The implicit assumption underpinning these architectures is that attackers operate within human temporal constraints: that evidence will persist long enough between monitoring cycles for changes to be detected.

The emergence of agentic artificial intelligence — autonomous systems capable of planning, reasoning, and executing multi-stage operations without continuous human oversight (Acharya, Kuppan and Divya, 2025) — now challenges this assumption fundamentally. Agentic AI systems do not operate at human speed; they execute at machine speed, completing complex operational workflows within sub-second timeframes. When such systems are directed toward anti-forensic objectives, they introduce a class of threat for which existing enterprise monitoring architectures were never designed.

## 1.2 Problem Statement

Enterprise SIEM platforms, including the widely deployed open-source platform Wazuh, predominantly implement File Integrity Monitoring through a periodic polling architecture. Under this model, file system states are compared against stored baselines at fixed intervals — typically ranging from 12 hours in default configurations to as little as 5 seconds in performance-intensive custom deployments (Wazuh Documentation Team, 2024). This architectural design introduces a well-characterised vulnerability: the Time-of-Check to Time-of-Use (TOCTOU) race condition (Wei and Pu, 2005). Any malicious activity that occurs and is fully remediated between consecutive polling cycles remains invisible to the monitoring system, creating a temporal blind spot — a "Time Gap" — that can be exploited by sufficiently fast adversaries.

In a prior empirical study submitted to the 1st International Workshop on AI Safety and Security (AI-SS 2026) (Orji et al., 2026), the author demonstrated that this vulnerability is not merely theoretical. An autonomous AI agent — designated "Anti-Gravity" — was designed and deployed to execute a complete anti-forensic operation comprising evidence timestomping, secure multi-pass data wiping, and system log sanitisation. Across five controlled trials against a Splunk-monitored Windows environment with a 5-second polling interval, the agent completed all three anti-forensic stages in an average of 370 milliseconds — more than an order of magnitude faster than the shortest feasible monitoring cycle. The SIEM registered zero alerts during any stealth-mode trial. The digital evidence was destroyed before the monitoring system had any opportunity to observe it.

This finding exposes a structural weakness in the dominant enterprise monitoring paradigm: periodic polling architectures are fundamentally incapable of detecting machine-speed anti-forensic operations. Yet despite the severity of this vulnerability, a systematic search of the literature reveals no published study that has designed, implemented, and empirically evaluated defensive countermeasures capable of detecting and mitigating autonomous anti-forensic activity at machine speed. The gap between offensive capability and defensive tooling is widening, and no commensurate response exists in the academic or practitioner literature.

## 1.3 Motivation

The motivation for this research is both academic and practical. From an academic perspective, the literature on anti-forensics has been predominantly offence-oriented, cataloguing techniques and demonstrating their feasibility, while the complementary question — how do we defend against these techniques when they are automated and executed autonomously — has received comparatively little attention. This imbalance is particularly acute in the context of agentic AI, where the offensive capabilities documented by Challita and Parrend (2025) and Fang et al. (2024) have no published defensive counterpart specifically addressing anti-forensic automation.

From a practical perspective, the implications of the prior AI-SS 2026 study (Orji et al., 2026) are immediate and actionable. Organisations that rely on periodic FIM configurations — which represents the vast majority of enterprise deployments, given the computational and storage overheads associated with continuous monitoring (Chuvakin, Schmidt and Phillips, 2013) — are structurally vulnerable to the class of attack demonstrated. Security practitioners require evidence-based guidance on what countermeasures are effective, how they should be configured, and what performance characteristics they can expect.

This dissertation is therefore motivated by a direct and urgent need: to shift the research focus from attack demonstration to defence construction and evaluation, providing the forensic and security communities with empirically validated tools and recommendations for countering agentic AI-driven anti-forensic threats.

## 1.4 Aim and Objectives

**Aim:** To design and empirically evaluate an integrated countermeasure framework capable of detecting and mitigating autonomous AI-driven anti-forensic operations that evade standard enterprise monitoring configurations.

The research aim is operationalised through five SMART objectives:

**Objective 1:** To conduct a critical review of existing literature on anti-forensic techniques, TOCTOU vulnerabilities, and agentic AI in offensive security, identifying at least one clearly defined gap in current defensive capabilities, to be completed by the end of Week 2 (1st June 2026).

**Objective 2:** To design and implement an integrated countermeasure framework comprising five coordinated modules — real-time event-driven monitoring, behavioural anomaly detection, timestamp validation, canary-based deception, and log integrity protection — with all modules functionally tested by the end of Week 4 (15th June 2026).

**Objective 3:** To evaluate the countermeasure framework against a validated autonomous anti-forensic agent across a minimum of 30 controlled experimental trials, collecting quantitative measurements of detection latency (in milliseconds), detection completeness (percentage of attack stages detected), false-positive rate, and evidence preservation, to be completed by the end of Week 8 (13th July 2026).

**Objective 4:** To statistically compare the detection performance of the countermeasure framework against default enterprise SIEM configurations (periodic FIM) using inferential statistical tests (Mann-Whitney U) at the p < 0.05 significance level, with analysis completed by the end of Week 10 (27th July 2026).

**Objective 5:** To produce evidence-based recommendations for enterprise security configurations, derived directly from the experimental results, and present findings within the completed dissertation by the submission deadline of 18th August 2026.

## 1.5 Research Questions and Hypothesis

The proposed research is guided by the following questions:

**RQ1:** To what extent can real-time, event-driven monitoring detect autonomous anti-forensic operations that completely evade periodic File Integrity Monitoring?

**RQ2:** Can behavioural analysis techniques identify patterns characteristic of agentic anti-forensic execution — such as operation bursts and rapid file lifecycle events — and distinguish them from legitimate system activity?

**RQ3:** How effective are canary-based deception mechanisms at detecting and attributing autonomous anti-forensic operations?

**RQ4:** What is the detection latency, detection completeness, and false-positive rate of an integrated countermeasure framework compared to default enterprise SIEM configurations when subjected to autonomous anti-forensic attack?

**Hypothesis:** An integrated countermeasure framework combining kernel-level real-time monitoring, behavioural anomaly detection, timestamp validation, canary-based deception, and log integrity protection will achieve statistically significant improvements in detection rate and forensic evidence preservation compared to standard periodic FIM configurations (p < 0.05, Mann-Whitney U test).

## 1.6 Distinction from Prior Work

It is essential to clarify the relationship between this dissertation and the author's prior accepted paper (Orji et al., 2026), as the two studies address complementary but distinct research questions. Table 1.1 summarises the key distinctions.

**Table 1.1:** Comparison of prior work and this dissertation.

| Aspect | Prior Paper (Orji et al., 2026) | This Dissertation |
|--------|------------------------|-------------------|
| **Focus** | Offensive — demonstrating the attack | Defensive — designing and evaluating countermeasures |
| **Research Question** | *Can* an autonomous agent evade enterprise FIM? | *How* do we detect and mitigate such agents? |
| **Contribution** | Identified the TOCTOU Time Gap vulnerability | Proposes and validates a framework to close it |
| **Artefact** | Anti-Gravity attack agent | AntiGravity Shield defence framework |
| **Evaluation** | Single-condition (attack vs default SIEM) | Comparative (default SIEM vs integrated countermeasures) |
| **Statistical Rigour** | Descriptive (reviewer-noted limitation) | Inferential (Mann-Whitney U, 30+ trials) |
| **Scope** | Attack-only | Attack + Defence + Human-baseline comparison |

The prior paper established the *problem*; this dissertation proposes and evaluates the *solution*. The dissertation also directly addresses the three methodological recommendations made by the AI-SS 2026 peer reviewers: broader experimental scope, human-baseline comparisons, and inferential statistical analysis.

## 1.7 Scope and Limitations

This research focuses specifically on anti-forensic operations targeting file system artefacts — file creation, modification, deletion, and metadata manipulation — within a Linux-based enterprise environment. The scope includes:

- **In scope:** File-level anti-forensic operations (timestomping, secure wiping, log sanitisation); countermeasures operating at the file system and application layers; quantitative performance evaluation using controlled experimental methods.
- **Out of scope:** Network-level anti-forensics; memory-only attacks; hardware-based evidence destruction; Windows-specific NTFS artefact manipulation (the attack agent was originally validated on Windows but the defence framework operates on Linux); machine-learning-based detection models (the behavioural detection module uses rule-based heuristics).

These boundaries are deliberately drawn to maintain experimental control and ensure the research remains achievable within the 13-week project timeline. The limitations are acknowledged and discussed as avenues for future work in Chapter 7.

## 1.8 Dissertation Structure

The remainder of this dissertation is organised as follows:

**Chapter 2: Literature Review** provides a systematic examination of anti-forensic techniques, enterprise monitoring architectures, TOCTOU vulnerabilities, agentic AI in offensive security, and existing defensive countermeasures, culminating in the identification of the research gap this work addresses.

**Chapter 3: Methodology** presents the research methodology, including the justification for the Design Science Research Methodology (DSRM), the experimental design, data collection procedures, statistical analysis plan, and ethical considerations.

**Chapter 4: Design and Implementation** describes the architecture and implementation of both the Anti-Gravity attack agent and the AntiGravity Shield countermeasure framework, including the test harness used for automated experimental evaluation.

**Chapter 5: Results and Analysis** presents the quantitative results of the experimental evaluation across all conditions, including statistical analysis and visualisation of key performance metrics.

**Chapter 6: Discussion** interprets the experimental findings in the context of the research questions, evaluates the hypothesis, compares the results with existing literature, reflects on the novelty and limitations of the work, and discusses implications for enterprise security practice.

**Chapter 7: Conclusions and Future Work** summarises the contributions, revisits the research objectives, and identifies directions for future research.

**Chapter 8: Legal, Social, Ethical and Professional Issues** reflects on the ethical dimensions of dual-use security research, the legal framework governing the experimental approach, and the professional responsibilities of the researcher.

---

## References (Chapter 1)

Acharya, D.B., Kuppan, K. and Divya, B. (2025) 'Agentic AI: Autonomous Intelligence for Complex Goals — A Comprehensive Survey', *IEEE Access*.

Carvey, H. (2014) *Windows Forensic Analysis Toolkit*. 4th edn. Elsevier/Syngress.

Casey, E. (2011) *Digital Evidence and Computer Crime: Forensic Science, Computers, and the Internet*. 3rd edn. Academic Press.

Challita, B. and Parrend, P. (2025) 'RedTeamLLM: An Agentic AI Framework for Offensive Security', *arXiv preprint*, arXiv:2505.06913.

Chuvakin, A., Schmidt, K. and Phillips, C. (2013) *Logging and Log Management: The Authoritative Guide to Understanding the Concepts Surrounding Logging and Log Management*. Waltham, MA: Elsevier/Syngress.

Fang, R., Bindu, R., Gupta, A. and Kang, D. (2024) 'LLM Agents can Autonomously Exploit One-Day Vulnerabilities', *arXiv preprint*, arXiv:2404.08144.

Garfinkel, S.L. (2007) 'Anti-Forensics and the Digital Investigator', in *Proceedings of the 5th Australian Digital Forensics Conference*. Perth, Western Australia.

Garfinkel, S.L. and Shelat, A. (2003) 'Remembrance of Data Passed: A Study of Disk Sanitization Practices', *IEEE Security and Privacy*, 1(1), pp. 17–27.

Kroll, A. (2025) *Breaking Time: Methods, Artifacts, and Forensic Detection of Timestomping on FAT32, Ext3, and Ext4 File Systems*. SANS Institute Information Security Reading Room.

NIST (2006) *Guide to Integrating Forensic Techniques into Incident Response* (SP 800-86). National Institute of Standards and Technology.

Orji, E.C., Adenihun, A., Ojuolape-Oria, I., Ofeimun, O., Adeboye, O. and Akinseye, S. (2026) 'Exploring Agentic AI in Anti-Forensics: Simulation of Evasion Tactics in Digital Investigations', in *Proceedings of the 1st International Workshop on AI Safety and Security (AI-SS 2026)*, held in conjunction with the 21st European Dependable Computing Conference (EDCC 2026). Canterbury, UK, 7 April. IEEE CPS.

Wazuh Documentation Team (2024) *File Integrity Monitoring: How It Works*. Available at: https://documentation.wazuh.com (Accessed: 15 January 2026).

Wei, J. and Pu, C. (2005) 'TOCTTOU Vulnerabilities in Unix-Style File Systems: An Anatomical Study', in *FAST*, vol. 5, pp. 12–12.
