# Chapter 2: Literature Review

This chapter provides a systematic examination of the academic and practitioner literature relevant to this research. It is structured thematically, progressing from the foundational concepts of anti-forensic techniques and enterprise monitoring architectures, through the emerging threat of agentic AI in offensive security, to the defensive countermeasures that form the basis of the proposed framework. The chapter concludes by synthesising the literature to identify the specific research gap this dissertation addresses.

## 2.1 Anti-Forensic Techniques

### 2.1.1 Taxonomy of Anti-Forensics

The academic study of anti-forensics — techniques deliberately designed to obstruct or mislead the digital forensic process — has its origins in the work of Garfinkel (2007), who established the foundational taxonomy comprising three principal classes: evidence destruction, evidence hiding, and elimination of evidence sources. This classification has since been refined and extended by subsequent researchers. Rogers (2006) proposed a more granular categorisation distinguishing data hiding, artefact wiping, trail obfuscation, and attacks against the forensic tools themselves. More recently, Conlan, Baggili and Breitinger (2016) conducted a systematic review of anti-forensic techniques, noting that the increasing sophistication of adversary tradecraft requires continually updated taxonomies.

A 2024 systematic literature review by González Arias et al. (2024) provides the most comprehensive contemporary classification, analysing anti-forensic methods across desktop, mobile, cloud, and IoT environments. The authors emphasise that modern anti-forensic toolkits increasingly combine multiple techniques — timestamp manipulation, secure deletion, and log sanitisation — into coordinated workflows, a finding directly relevant to the agentic automation investigated in this dissertation.

### 2.1.2 Timestomping

Timestomping refers to the deliberate modification of file system metadata — specifically the Modified, Accessed, Created, and Entry Modified (MACE) timestamps — to conceal the true chronology of file activity (MITRE, 2024). The technique is catalogued as T1070.006 in the MITRE ATT&CK framework under the "Indicator Removal" tactic, reflecting its classification as a defence evasion method.

Carvey (2014) provides detailed analysis of timestamp manipulation within NTFS file systems, demonstrating how the `SetFileTime` Windows API can be used to alter `$STANDARD_INFORMATION` timestamps while leaving forensic traces in the `$FILE_NAME` attribute and the `$UsnJrnl` change journal. Kroll (2025) extends this analysis to Linux file systems (Ext3, Ext4, and FAT32), documenting how `utimensat()` system calls can modify both `mtime` and `atime` fields while the `ctime` (change time) field is automatically updated by the kernel, providing a potential detection vector. This divergence between `ctime` and `mtime` — where a file's content modification time predates its metadata change time — is a key heuristic exploited by the Timestamp Validator module in this dissertation's countermeasure framework.

### 2.1.3 Secure Data Deletion and Log Manipulation

Garfinkel and Shelat (2003), in their seminal study "Remembrance of Data Passed", demonstrated that standard file deletion merely removes directory entries, leaving recoverable data on the storage medium. Secure deletion techniques address this by overwriting file contents prior to unlinking. The United States Department of Defense standard DoD 5220.22-M specifies a three-pass overwrite protocol — random data, the complement, and a further random pass — as a minimum for sanitisation (NIST, 2014).

Log manipulation represents the third pillar of anti-forensic operations. System and application logs constitute critical evidence sources for forensic timeline reconstruction. Attackers may truncate, overwrite, or selectively edit log files to remove traces of their activity (Kent and Souppaya, 2006). In enterprise environments, log integrity is particularly vulnerable when monitoring agents lack real-time protection mechanisms, as log files can be modified or deleted in the interval between writing and collection by the SIEM (Chuvakin, Schmidt and Phillips, 2013).

## 2.2 Enterprise Monitoring Architectures

### 2.2.1 SIEM Systems and File Integrity Monitoring

Security Information and Event Management (SIEM) platforms serve as the central nervous system of enterprise security operations, aggregating, correlating, and alerting on security-relevant events from across the IT estate (Chuvakin, Schmidt and Phillips, 2013). A core capability of modern SIEM deployments is File Integrity Monitoring, which detects unauthorised changes to critical system files, application binaries, and configuration data.

The dominant open-source SIEM platform, Wazuh, implements FIM through a periodic auditing model. The Wazuh documentation describes this process explicitly: the FIM module "runs periodic scans... comparing the current checksums of monitored files against previously stored values" (Wazuh Documentation Team, 2024). Default configurations specify scan intervals of 12 hours (`syscheck` frequency of 43200 seconds), although administrators may configure shorter intervals at the cost of increased computational overhead.

Commercial SIEM platforms follow similar architectural patterns. Splunk's Universal Forwarder uses configurable `checkpointInterval` settings for log collection, while IBM QRadar and Microsoft Sentinel employ periodic baseline comparison models. Chuvakin, Schmidt and Phillips (2013) observe that despite the theoretical superiority of continuous monitoring, the majority of enterprise deployments retain periodic configurations to manage resource consumption — a pragmatic trade-off that introduces the vulnerability exploited in this research.

### 2.2.2 Polling versus Event-Driven Models

The distinction between periodic polling and event-driven monitoring architectures is fundamental to this research. In a polling model, the monitoring system initiates checks at defined intervals; any activity that occurs entirely between polls is invisible. In an event-driven model, the operating system kernel notifies the monitoring application of file system events in real-time.

On Linux systems, the `inotify` kernel subsystem provides this event-driven capability. Introduced in kernel version 2.6.13, `inotify` uses a callback mechanism to notify user-space applications immediately when specified events — creation, modification, deletion, attribute changes — occur on monitored files or directories (Love, 2005). Unlike polling, which consumes CPU resources proportional to the number of monitored files, `inotify` imposes negligible overhead during idle periods, firing only when events actually occur.

However, `inotify` has documented limitations relevant to security applications: it does not natively support recursive directory monitoring (requiring explicit watches on each subdirectory), is subject to system-wide limits on the number of active watches, and does not inherently provide process identification for the entity responsible for the event (Kerrisk, 2010). These limitations inform the architectural decisions made in the countermeasure framework described in Chapter 4.

## 2.3 TOCTOU Vulnerabilities in Security Monitoring

The Time-of-Check to Time-of-Use (TOCTOU) race condition is a well-characterised class of vulnerability in which a program validates a condition and then acts upon it, but the underlying state changes between the validation and the action (Bishop and Dilger, 1996). Wei and Pu (2005) provide the foundational anatomical study of TOCTOU vulnerabilities in Unix-style file systems, demonstrating how the non-atomic nature of check-then-use sequences can be exploited by concurrent processes.

While the original TOCTOU literature focuses on privilege escalation through symbolic link attacks, this research identifies a structural analogy in enterprise monitoring architectures: periodic FIM represents a "check" operation, and the next polling cycle represents the subsequent "use" of the same state information. Any activity that occurs and completes between these two events exists in a temporal blind spot. The critical distinction is one of scale: traditional TOCTOU exploitation requires microsecond-level race windows, whereas the monitoring TOCTOU gap spans seconds to hours, making exploitation trivially achievable for any sufficiently fast adversary.

Tsafrir, Hertz and Wagner (2008) demonstrated that even small race windows can be reliably exploited with high probability through repeated attempts. In the monitoring context, the "race" is won on every attempt because the gap between polling cycles vastly exceeds the time required for a machine-speed anti-forensic operation — a finding empirically confirmed by the author's prior study (Orji et al., 2026), where the autonomous agent completed all anti-forensic stages in 370 milliseconds against a 5-second polling interval.

## 2.4 Agentic AI in Offensive Cyber Security

### 2.4.1 Autonomous Agent Architectures

The emergence of agentic AI — autonomous systems that perceive their environment, reason about their goals, and execute multi-step action plans without continuous human direction — represents a paradigm shift in both constructive and adversarial applications of artificial intelligence (Acharya, Kuppan and Divya, 2025). Unlike traditional automation scripts, which follow predefined execution paths, agentic systems can adapt their behaviour based on environmental feedback, making them fundamentally more capable and unpredictable.

Fang et al. (2024) demonstrated that large language model (LLM) agents can autonomously exploit real-world vulnerabilities when provided with CVE descriptions, achieving success rates that underscore the offensive potential of the technology. Their work establishes that the barrier to autonomous cyber operations has been substantially lowered by the availability of general-purpose reasoning models.

### 2.4.2 AI-Driven Attack Frameworks

Challita and Parrend (2025) present RedTeamLLM, an agentic framework for offensive security that implements the "Observe, Plan, Act" loop, enabling autonomous reconnaissance, exploitation, and post-exploitation activities. Fang et al. (2024) similarly demonstrate the automation of multi-stage cyber operations using AI, documenting how autonomous agents can chain together individual attack techniques into complete operational workflows.

The ARTEMIS study (Lin et al., 2025) provides empirical evidence that autonomous AI agents can be competitive with certified human penetration testers: in a comparative evaluation on an operational enterprise network of approximately 8,000 hosts, the ARTEMIS multi-agent framework achieved second place overall, finding nine valid vulnerabilities with an 82% valid submission rate and outperforming nine out of ten OSCP-certified professionals, whilst offering significant cost savings at $18 per hour versus $60 per hour for human testers. Kaloudi and Li (2020), in their analysis of the AI-based cyber threat landscape, discuss how AI-driven malware can adapt its behaviour to evade detection — a capability that, when applied to anti-forensic operations, creates the class of threat this dissertation addresses.

The operational distinction between manual and agentic anti-forensic activity is critical. Manual attacks are constrained by human reaction time (typically hundreds of milliseconds per individual operation), leave residual artefacts during the decision-making process, and are detectable by monitoring systems calibrated for human-speed activity. Agentic systems, by contrast, execute entire anti-forensic workflows within sub-second timeframes, operating within the temporal blind spots of periodic monitoring architectures.

## 2.5 Defensive Countermeasures

### 2.5.1 Real-Time Monitoring Approaches

The shift from periodic to event-driven monitoring has been advocated by multiple researchers and practitioner bodies. The Center for Internet Security (CIS) recommends real-time FIM for critical system files (CIS, 2023), and industry analyses by CrowdStrike (2024) and Cimcor (2024) document the growing recognition that polling-based FIM creates unacceptable detection gaps in modern threat environments.

Juneja (2025) presents Rx-Int, a kernel-level engine for real-time detection and analysis of in-memory threats, demonstrating the feasibility of kernel-event-driven detection architectures that operate at machine speed. The work validates the architectural principle underpinning this dissertation's Real-Time File Monitor module: that kernel-level event notification can achieve detection latencies orders of magnitude lower than periodic polling.

### 2.5.2 Deception-Based Defence

Deception technology, particularly the deployment of honeypot or "canary" files, has gained substantial academic attention as a detection mechanism. Spitzner (2003) established the conceptual foundations of honeypot-based intrusion detection, while more recent work has focused specifically on ransomware detection through canary file monitoring. Moore (2016) demonstrated that strategically placed decoy files serve as high-fidelity tripwires: any access, modification, or deletion constitutes a strong indicator of malicious activity, as legitimate processes have no reason to interact with these files.

Al-Rimy, Maarof and Shaid (2018) provide a systematic review of ransomware countermeasures, identifying canary-based detection as particularly effective due to its low false-positive rate — a characteristic that distinguishes it from heuristic and behavioural methods. Research by Genç, Lenzini and Ryan (2018) further demonstrates that canary files can reduce the Mean Time to Detect (MTTD) to near-zero, providing an early-warning layer that complements signature-based and behavioural detection methods.

### 2.5.3 Behavioural Anomaly Detection

Behavioural anomaly detection for file system activity has evolved from simple threshold-based alerting to sophisticated pattern recognition. Garcia-Teodoro et al. (2009) provide a foundational survey of anomaly-based network intrusion detection, establishing the principle that deviations from established behavioural baselines can indicate malicious activity. This principle extends naturally to file system monitoring, where the temporal characteristics of operations — their frequency, sequencing, and velocity — carry diagnostic significance.

In the context of anti-forensic operations, behavioural patterns are particularly distinctive. The sequence of "modify, rename, delete" that characterises secure file wiping, the burst of rapid operations that accompanies automated execution, and the creation and immediate destruction of ephemeral files all produce behavioural signatures that differ markedly from normal user or system activity. The behavioural detection module in this dissertation exploits these temporal patterns using a sliding-window analysis approach, representing a rule-based alternative to the machine-learning-intensive methods documented in the recent literature.

### 2.5.4 Tamper-Proof Logging

The integrity of audit logs is a prerequisite for forensic trustworthiness. If an attacker can modify or delete logs after the fact, the entire evidentiary record is compromised. Hash-chained logging — where each log entry includes the cryptographic hash of the previous entry, creating a mathematical dependency chain — provides a tamper-evident audit trail (Schneier and Kelsey, 1999). Any modification to a historical entry invalidates all subsequent hashes, making tampering detectable.

Blockchain-based logging frameworks have been proposed as an evolution of hash-chained approaches, anchoring cryptographic proofs to distributed ledgers for non-repudiation (Ali et al., 2022). However, the performance overhead of blockchain-based systems makes them impractical for the sub-second detection requirements of this research. The Log Protector module in this dissertation therefore implements a lightweight hash-chain approach, providing tamper evidence without the latency penalties associated with distributed consensus mechanisms.

## 2.6 Research Gap and Contribution

The literature reviewed in this chapter reveals a clear and exploitable asymmetry: the offensive capabilities of agentic AI in anti-forensic contexts have been documented and empirically demonstrated, but no published study has systematically designed, implemented, and evaluated an integrated defensive countermeasure framework against these threats.

Specifically, the literature gap exists at the intersection of three domains:

1. **Anti-forensic automation:** While individual anti-forensic techniques are well documented (Garfinkel, 2007; Carvey, 2014; Kroll, 2025), their autonomous, coordinated execution by agentic AI systems is addressed only by the author's prior study (Orji et al., 2026).

2. **Monitoring architecture vulnerability:** The TOCTOU vulnerability in periodic FIM is structurally analogous to the classic race condition (Wei and Pu, 2005), yet no study has proposed countermeasures specifically designed to close this temporal blind spot against machine-speed adversaries.

3. **Integrated defensive frameworks:** While individual countermeasure techniques — real-time monitoring, deception, behavioural analysis, tamper-proof logging — exist in isolation in the literature, no published work has combined these into a single integrated framework and evaluated it empirically against an autonomous anti-forensic agent.

This dissertation directly addresses this gap by designing, implementing, and evaluating the AntiGravity Shield — an integrated countermeasure framework comprising five coordinated modules — against a validated autonomous anti-forensic agent within a controlled experimental environment.

## 2.7 Chapter Summary

This chapter has reviewed the literature across six thematic areas: anti-forensic techniques, enterprise monitoring architectures, TOCTOU vulnerabilities, agentic AI in offensive security, defensive countermeasures, and the identified research gap. The review demonstrates that while offensive capabilities have advanced to machine speed through agentic AI, defensive tools remain calibrated for human-speed threats. The following chapter presents the research methodology adopted to address this imbalance.

---

## References (Chapter 2)

Acharya, D.B., Kuppan, K. and Divya, B. (2025) 'Agentic AI: Autonomous Intelligence for Complex Goals — A Comprehensive Survey', *IEEE Access*.

Al-Rimy, B.A.S., Maarof, M.A. and Shaid, S.Z.M. (2018) 'Ransomware Threat Success Factors, Taxonomy, and Countermeasures: A Survey and Research Directions', *Computers and Security*, 74, pp. 144–166.

Ali, A., Khan, A., Ahmed, M. and Jeon, G. (2022) 'BCALS: Blockchain-Based Secure Log Management System for Cloud Computing', *Transactions on Emerging Telecommunications Technologies*, 33(4), e4272. doi:10.1002/ett.4272.

Bishop, M. and Dilger, M. (1996) 'Checking for Race Conditions in File Accesses', *Computing Systems*, 9(2), pp. 131–152.

Carvey, H. (2014) *Windows Forensic Analysis Toolkit*. 4th edn. Elsevier/Syngress.

Challita, B. and Parrend, P. (2025) 'RedTeamLLM: An Agentic AI Framework for Offensive Security', *arXiv preprint*, arXiv:2505.06913.

Chuvakin, A., Schmidt, K. and Phillips, C. (2013) *Logging and Log Management: The Authoritative Guide to Understanding the Concepts Surrounding Logging and Log Management*. Syngress.

Cimcor (2024) *The Hidden Risk of Polling-Based File Integrity Monitoring*. Available at: https://www.cimcor.com (Accessed: 20 May 2026).

CIS (2023) *CIS Controls v8: Implementation Group 3*. Center for Internet Security.

Conlan, K., Baggili, I. and Breitinger, F. (2016) 'Anti-Forensics: Furthering Digital Forensic Science through a New Extended, Granular Taxonomy', *Digital Investigation*, 18, pp. S66–S75.

CrowdStrike (2024) *File Integrity Monitoring: Why Real-Time Matters*. Available at: https://www.crowdstrike.com (Accessed: 20 May 2026).

Fang, R., Bindu, R., Gupta, A. and Kang, D. (2024) 'LLM Agents Can Autonomously Exploit One-Day Vulnerabilities', *arXiv preprint*, arXiv:2404.08144.

Garcia-Teodoro, P., Diaz-Verdejo, J., Maciá-Fernández, G. and Vázquez, E. (2009) 'Anomaly-Based Network Intrusion Detection: Techniques, Systems and Challenges', *Computers and Security*, 28(1–2), pp. 18–28.

Garfinkel, S.L. (2007) 'Anti-Forensics and the Digital Investigator', in *Proceedings of the 5th Australian Digital Forensics Conference*. Perth, Western Australia.

Garfinkel, S.L. and Shelat, A. (2003) 'Remembrance of Data Passed: A Study of Disk Sanitization Practices', *IEEE Security and Privacy*, 1(1), pp. 17–27.

Genç, Z.A., Lenzini, G. and Ryan, P.Y. (2018) 'No Random, No Ransom: A Key to Stop Cryptographic Ransomware', in *Proceedings of the 15th International Conference on Detection of Intrusions and Malware, and Vulnerability Assessment (DIMVA)*. Springer, pp. 234–255.

González Arias, R., Bermejo Higuera, J., Rainer Granados, J.J. and Sicilia Montalvo, J.A. (2024) 'Systematic Review: Anti-Forensic Computer Techniques', *Applied Sciences*, 14(12), 5302. doi:10.3390/app14125302.

Juneja, A. (2025) 'Rx-Int: A Kernel Engine for Real-Time Detection and Analysis of In-Memory Threats', *arXiv preprint*, arXiv:2508.03879.

Kaloudi, N. and Li, J. (2020) 'The AI-Based Cyber Threat Landscape: A Survey', *ACM Computing Surveys*, 53(1), pp. 1–34.

Kent, K. and Souppaya, M. (2006) *Guide to Computer Security Log Management* (SP 800-92). National Institute of Standards and Technology.

Kerrisk, M. (2010) *The Linux Programming Interface*. San Francisco: No Starch Press.

Kroll, A. (2025) *Breaking Time: Methods, Artifacts, and Forensic Detection of Timestomping on FAT32, Ext3, and Ext4 File Systems*. SANS Institute Information Security Reading Room.

Lin, J.W., Jones, E.K., Jasper, D.J., Ho, E.J., Wu, A., Yang, A.T., Perry, N., Zou, A., Fredrikson, M., Kolter, J.Z., Liang, P., Boneh, D. and Ho, D.E. (2025) 'Comparing AI Agents to Cybersecurity Professionals in Real-World Penetration Testing', *arXiv preprint*, arXiv:2512.09882.

Love, R. (2005) *Linux Kernel Development*. 2nd edn. Indianapolis: Novell Press.

MITRE (2024) *T1070.006 — Indicator Removal: Timestomp*. MITRE ATT&CK. Available at: https://attack.mitre.org/techniques/T1070/006/ (Accessed: 15 May 2026).

Moore, C. (2016) 'Detecting Ransomware with Honeypot Techniques', in *Proceedings of the IEEE Conference on Cybersecurity and Cyberforensics (CCC)*. IEEE, pp. 77–81.

NIST (2014) *Guidelines for Media Sanitization* (SP 800-88 Rev. 1). National Institute of Standards and Technology.

Orji, E.C., Adenihun, A., Ojuolape-Oria, I., Ofeimun, O., Adeboye, O. and Akinseye, S. (2026) 'Exploring Agentic AI in Anti-Forensics: Simulation of Evasion Tactics in Digital Investigations', in *Proceedings of the 1st International Workshop on AI Safety and Security (AI-SS 2026)*, held in conjunction with the 21st European Dependable Computing Conference (EDCC 2026). Canterbury, UK, 7 April. IEEE CPS.

Rogers, M. (2006) 'Anti-Forensics', in *Proceedings of the Annual Conference of the Digital Forensics Research Workshop (DFRWS)*. Lafayette, Indiana.

Schneier, B. and Kelsey, J. (1999) 'Secure Audit Logs to Support Computer Forensics', *ACM Transactions on Information and System Security*, 2(2), pp. 159–176.

Spitzner, L. (2003) *Honeypots: Tracking Hackers*. Boston: Addison-Wesley.

Tsafrir, D., Hertz, T. and Wagner, D. (2008) 'Portably Solving File TOCTTOU Races with Hardness Amplification', in *Proceedings of the USENIX Conference on File and Storage Technologies (FAST)*. San Jose, CA, pp. 189–206.

Wazuh Documentation Team (2024) *File Integrity Monitoring: How It Works*. Available at: https://documentation.wazuh.com (Accessed: 15 January 2026).

Wei, J. and Pu, C. (2005) 'TOCTTOU Vulnerabilities in Unix-Style File Systems: An Anatomical Study', in *FAST*, vol. 5, pp. 12–12.
