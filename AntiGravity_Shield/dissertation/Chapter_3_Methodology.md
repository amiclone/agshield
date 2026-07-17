# Chapter 3: Methodology

This chapter presents the research methodology adopted for this dissertation, including the philosophical underpinning, the selected research framework, the experimental design, data collection procedures, statistical analysis plan, and ethical considerations. Each methodological decision is justified with reference to the academic literature and the specific requirements of the research questions.

## 3.1 Research Philosophy and Approach

This research adopts a positivist philosophical stance, seeking to establish objective, measurable facts about the performance of defensive countermeasures against autonomous anti-forensic operations. The positivist approach is appropriate because the research questions demand quantitative answers — detection latencies measured in milliseconds, detection completeness expressed as percentages, and false-positive rates validated through statistical hypothesis testing (Saunders, Lewis and Thornhill, 2019). The research is deductive: a hypothesis is formulated from the literature and prior empirical findings, an artefact is constructed to test it, and experimental data are collected to confirm or refute it.

The overall research approach is applied rather than purely theoretical. The dissertation does not seek to develop new theory; rather, it designs, builds, and empirically evaluates a practical artefact — the AntiGravity Shield countermeasure framework — intended to solve an identified real-world problem. This applied orientation aligns with the Design Science Research Methodology described in the following section.

## 3.2 Design Science Research Methodology (DSRM)

### 3.2.1 Justification for DSRM

This research adopts the **Design Science Research Methodology (DSRM)** as formalised by Peffers et al. (2007). DSRM is a widely accepted framework for information systems and computer science research that involves the creation and rigorous evaluation of IT artefacts — such as software tools, frameworks, or models — to address identified problems. It is distinguished from purely empirical or interpretivist methodologies by its emphasis on building and evaluating, making it the natural choice for research whose primary contribution is a functional software framework.

Hevner et al. (2004) establish the foundational principles of design science in information systems, arguing that design-science research must produce a "viable artefact in the form of a construct, a model, a method, or an instantiation" and must be rigorously evaluated against its stated objectives. This dissertation satisfies both requirements: the artefact is the AntiGravity Shield framework (a software instantiation), and the evaluation is conducted through controlled experimental trials with quantitative performance metrics.

The alternative methodology considered was a purely experimental approach without the DSRM framing. However, this was rejected because the research involves both the construction and the evaluation of a novel artefact — activities that DSRM explicitly accommodates within a single coherent framework. A purely experimental approach would lack the structured design rationale that DSRM provides.

### 3.2.2 Application of DSRM Phases

The six phases of the DSRM process model are applied to this research as follows:

**Phase 1 — Problem Identification and Motivation:** The TOCTOU Time Gap vulnerability in enterprise periodic FIM was identified and empirically demonstrated in the author's prior study (Orji et al., 2026). The autonomous Anti-Gravity agent completed all anti-forensic operations in an average of 370 milliseconds, while the SIEM — configured with a 5-second polling interval — registered zero alerts. This phase is complete and provides the empirical foundation for the current work.

**Phase 2 — Definition of Objectives:** The objectives of the countermeasure framework are defined quantitatively: achieve sub-second detection latency, detect a minimum of 75% of attack stages, maintain a false-positive rate of zero during quiescent operation, and preserve forensic evidence through tamper-evident logging. These objectives derive directly from the research questions (Chapter 1, Section 1.5).

**Phase 3 — Design and Development:** The AntiGravity Shield framework was designed as an integrated system comprising five coordinated modules: a real-time file monitor, a timestamp validator, a behavioural pattern detector, a canary deployer, and a log protector. The architectural rationale and implementation details are presented in Chapter 4.

**Phase 4 — Demonstration:** The framework is deployed within a controlled experimental environment and subjected to attack by the validated Anti-Gravity autonomous agent. The test harness automates the full experimental workflow, ensuring repeatable, consistent trial execution.

**Phase 5 — Evaluation:** Quantitative performance data are collected across a minimum of 30 independent trials per condition and analysed using inferential statistical methods (Section 3.5). This phase addresses the AI-SS 2026 reviewers' recommendation for greater statistical rigour.

**Phase 6 — Communication:** Findings are disseminated through this dissertation and may inform a follow-on publication extending the AI-SS 2026 work.

## 3.3 Experimental Design

### 3.3.1 Two-Condition Comparative Design

The study employs a two-condition comparative experimental design to evaluate the effectiveness of the proposed countermeasure framework relative to the current industry-standard baseline:

- **Control Condition:** Enterprise monitoring using default periodic File Integrity Monitoring. Under this condition, the Wazuh SIEM is configured with the default `syscheck` frequency of 43,200 seconds (12 hours), representing the standard deployment configuration documented by the Wazuh Documentation Team (2024). As established in the prior study, the autonomous agent completes all anti-forensic operations within sub-second timeframes, rendering periodic FIM entirely ineffective — the expected detection rate is 0%.

- **Treatment Condition:** The proposed AntiGravity Shield countermeasure framework, incorporating all five coordinated detection modules operating in real-time. The framework replaces periodic polling with kernel-event-driven monitoring (Linux `inotify`) and augments detection with behavioural analysis, timestamp validation, canary-based deception, and hash-chained log protection.

The existing Anti-Gravity autonomous agent, developed and validated in the prior study (Orji et al., 2026), serves as the controlled, repeatable threat input across both conditions. This ensures that the independent variable — the monitoring architecture — is the only factor that differs between conditions.

### 3.3.2 Attack Modes

To isolate the specific effect of anti-forensic techniques on detection outcomes, the agent is evaluated in two operational modes:

- **Stealth Mode:** The agent executes all three anti-forensic stages — timestomping, secure multi-pass wiping with rename obfuscation, and log sanitisation — representing the full offensive capability.
- **Noisy Mode:** The agent performs standard file operations (creation and deletion) without invoking anti-forensic modules, representing a conventional attack without evasion.

Comparing detection performance across these modes enables the research to determine whether the countermeasure framework's advantages are attributable to its architectural design (event-driven monitoring) or specifically to its anti-forensic detection capabilities (behavioural analysis, timestamp validation).

### 3.3.3 Sample Size Justification

A minimum of 30 independent trials per primary condition (stealth mode) is specified. This threshold is selected for two reasons. First, it exceeds the minimum sample size commonly recommended for the application of the Central Limit Theorem, ensuring that the sampling distribution of the mean approximates normality regardless of the underlying data distribution (Field, 2018). Second, it directly addresses the methodological limitation noted by the AI-SS 2026 peer reviewers, who recommended a larger sample size to strengthen inferential claims. Additional trials are conducted in noisy mode (minimum 3) and for the false-positive baseline (minimum 1 extended monitoring session of 10+ seconds).

### 3.3.4 Human Baseline Comparison

A human baseline protocol simulates the same three anti-forensic operations — timestomping, secure file deletion, and log clearing — performed manually by a human operator. The protocol models realistic human latencies: typing commands (1.5–6.0 seconds per command), observing output, and sequencing actions. This comparison provides qualitative context for the experimental results, illustrating the magnitude of the speed differential between autonomous and human-speed anti-forensic operations. While not a formal experimental condition, the human baseline strengthens the discussion of why periodic monitoring fails: if even a human operator can complete anti-forensic tasks within a single polling interval, the vulnerability is not specific to AI but is structural.

## 3.4 Data Collection Methods

### 3.4.1 Automated Test Harness

An automated test harness (`test_harness.py`) manages the complete experimental workflow for each trial, eliminating human variability in experimental execution. The harness performs the following sequence:

1. **Workspace Preparation:** A clean, isolated test workspace is created, and the attack agent scripts are copied into it.
2. **Shield Activation:** The AntiGravity Shield is initialised with all five modules active, monitoring the workspace directory. Canary files are deployed and the `inotify` real-time monitor begins watching for file system events.
3. **Stabilisation Pause:** A 500-millisecond pause allows the monitoring infrastructure to fully initialise before the attack begins.
4. **Attack Execution:** The Anti-Gravity agent is launched as a subprocess within the monitored workspace. High-precision timestamps (`time.perf_counter()`) record the attack start and end times.
5. **Event Propagation Pause:** A 2.0-second pause after the agent completes allows all `inotify` kernel events to propagate through the detection pipeline.
6. **Shield Deactivation and Report Generation:** The Shield is stopped, triggering final canary verification, external log integrity checks, and the generation of a structured JSON report containing all alerts, timing data, and aggregate statistics.
7. **Result Analysis:** The harness programmatically classifies detections by type (timestomp, wiper signature, deletion, operation burst, canary tampering) and computes detection completeness, latency, and alert counts.

This automated approach ensures that every trial follows an identical procedure, supporting the internal validity of the experiment.

### 3.4.2 Quantitative Metrics

Four quantitative metrics are collected per trial:

**Detection Latency** is defined as the elapsed time, in milliseconds, between the first anti-forensic action performed by the agent and the generation of the first alert by the Shield. This is measured using Python's `time.perf_counter()`, which provides monotonic, sub-microsecond resolution timing unaffected by system clock adjustments.

**Detection Completeness** is defined as the percentage of expected attack stages successfully detected. In stealth mode, four detection categories are expected: timestomping detection, wiper signature detection, file deletion detection, and operation burst detection. A completeness score of 100% indicates that all four categories were triggered during the trial.

**False Positive Rate** is defined as the number of WARNING or CRITICAL alerts generated per unit time during a period of quiescent operation with no attack activity. A dedicated false-positive test monitors a workspace containing normal files for a minimum of 10 seconds with no adversarial input. A rate of zero false positives is the target.

**Evidence Preservation** is assessed through the log integrity verification mechanism. After each trial, the hash-chained audit log is verified: if the chain is intact, the forensic record of the attack is preserved even if the attacker attempted to sanitise logs within the monitored workspace. A binary outcome (VERIFIED or COMPROMISED) is recorded.

## 3.5 Statistical Analysis Plan

The primary statistical analysis compares the detection performance of the AntiGravity Shield (treatment) against the default periodic FIM (control) using the **Mann-Whitney U test** (Mann and Whitney, 1947). This non-parametric test is selected for the following reasons:

1. **No normality assumption:** Detection latency data are unlikely to follow a normal distribution, as sub-second timing measurements are typically right-skewed. The Mann-Whitney U test does not require normally distributed data, making it robust for this context (Field, 2018).
2. **Ordinal comparison:** The test determines whether values from one distribution tend to be larger (or smaller) than values from another, which directly addresses the research question of whether the Shield achieves statistically superior detection performance.
3. **Small-to-moderate sample sizes:** The test performs well with sample sizes of 30, the minimum specified for this study.

The significance level is set at p < 0.05, following the convention for social science and information systems research. If the null hypothesis (no difference between conditions) is rejected at this threshold, the alternative hypothesis — that the integrated countermeasure framework achieves significantly superior detection performance — is accepted.

Effect size is reported using the **rank-biserial correlation** (r), providing a standardised measure of the magnitude of the difference between conditions, independent of sample size. Effect sizes are interpreted using Cohen's (1988) conventions for correlation coefficients: small (r ≈ 0.1), medium (r ≈ 0.3), and large (r ≈ 0.5).

Descriptive statistics — mean, median, standard deviation, minimum, and maximum — are reported for all quantitative metrics. Results are visualised using box plots and bar charts to facilitate comparison across conditions.

## 3.6 Threats to Validity

The following threats to validity are acknowledged:

**Internal Validity:** The controlled experimental environment ensures that the independent variable (monitoring architecture) is the primary factor affecting detection outcomes. However, the use of a single attack agent with a fixed operational profile may not capture the full range of adversarial behaviour. The automated test harness mitigates experimenter bias by ensuring consistent trial execution.

**External Validity:** All experiments are conducted within an isolated simulation environment rather than a live enterprise network. The detection latencies and completeness rates observed may not generalise directly to production environments with higher system loads, network latency, and more complex file system activity. This limitation is acknowledged and discussed as a direction for future work.

**Construct Validity:** The four quantitative metrics — latency, completeness, false-positive rate, and evidence preservation — are selected to provide a comprehensive assessment of detection performance. However, they do not capture all dimensions of defensive effectiveness, such as the quality of forensic attribution or the usability of alert information for incident responders.

## 3.7 Ethical Considerations

All experiments are conducted within isolated virtual environments with no connection to production systems, live networks, or real user data. The anti-forensic agent operates exclusively on simulated files within sandboxed workspaces created by the test harness and destroyed after each trial. No personal, sensitive, or third-party data is involved at any stage.

The research involves the development and use of offensive security tools (the Anti-Gravity agent). To mitigate the ethical risks associated with dual-use research, the agent is designed to operate only within the controlled experimental environment and is not distributed publicly. The agent's capabilities are documented transparently in both the prior publication (Orji et al., 2026) and this dissertation, consistent with the principle of responsible disclosure in security research (Rescorla, 2005).

A formal risk assessment has been completed in accordance with University of Salford requirements. The risk assessment identifies no significant risks to participants, data subjects, or third parties, as the research involves no human participants and no access to live systems.

## 3.8 Chapter Summary

This chapter has presented the research methodology adopted for this dissertation. The Design Science Research Methodology provides the overarching framework, guiding the research through problem identification, artefact design, and empirical evaluation. The two-condition comparative experimental design, automated test harness, and Mann-Whitney U statistical analysis plan collectively ensure that the evaluation is rigorous, repeatable, and capable of supporting the inferential claims required to answer the research questions. The following chapter describes the design and implementation of the artefacts under evaluation.

---

## References (Chapter 3)

Cohen, J. (1988) *Statistical Power Analysis for the Behavioral Sciences*. 2nd edn. Hillsdale, NJ: Lawrence Erlbaum Associates.

Field, A. (2018) *Discovering Statistics Using IBM SPSS Statistics*. 5th edn. London: SAGE Publications.

Hevner, A.R., March, S.T., Park, J. and Ram, S. (2004) 'Design Science in Information Systems Research', *MIS Quarterly*, 28(1), pp. 75–105.

Mann, H.B. and Whitney, D.R. (1947) 'On a Test of Whether One of Two Random Variables is Stochastically Larger than the Other', *The Annals of Mathematical Statistics*, 18(1), pp. 50–60.

Orji, E.C., Adenihun, A., Ojuolape-Oria, I., Ofeimun, O., Adeboye, O. and Akinseye, S. (2026) 'Exploring Agentic AI in Anti-Forensics: Simulation of Evasion Tactics in Digital Investigations', in *Proceedings of the 1st International Workshop on AI Safety and Security (AI-SS 2026)*, held in conjunction with the 21st European Dependable Computing Conference (EDCC 2026). Canterbury, UK, 7 April. IEEE CPS.

Peffers, K., Tuunanen, T., Rothenberger, M.A. and Chatterjee, S. (2007) 'A Design Science Research Methodology for Information Systems Research', *Journal of Management Information Systems*, 24(3), pp. 45–77.

Rescorla, E. (2005) 'Is Finding Security Holes a Good Idea?', *IEEE Security and Privacy*, 3(1), pp. 14–19.

Saunders, M., Lewis, P. and Thornhill, A. (2019) *Research Methods for Business Students*. 8th edn. Harlow: Pearson Education.

Wazuh Documentation Team (2024) *File Integrity Monitoring: How It Works*. Available at: https://documentation.wazuh.com (Accessed: 15 January 2026).
