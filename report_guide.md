# Anti-Forensics Optimization & Report Guide

This document is designed to help you structure your school report and presentation. It highlights the evidence you generated and provides academic references to back up your "Research" section.

## 1. Project Evidence (What you achieved)

You successfully created and deployed an **Autonomous AI Agent** that performs Anti-Forensics. Here is the evidence you should include in your slides/report:

### A. The "Stealth" Run
*   **Goal**: Prove the agent can operate without detection.
*   **Evidence**:
    *   **Screenshot**: The `remote_deployer.py` output showing "Agent execution finished".
    *   **Artifact**: The `victim_report_evidence.json` file.
    *   **Wazuh Dashboard**: A screenshot showing **NO CRITICAL ALERTS** during the attack time.
    *   **Key Finding**: "The AI Agent exploited the FIM polling interval (Time Gap) to modify and delete files faster than the monitoring system could detect."

### B. The "Noisy" Run (Comparison)
*   **Goal**: Show what happens *without* your anti-forensics code.
*   **Evidence**:
    *   **Artifact**: The `victim_report_noisy.json` file.
    *   **Wazuh Dashboard**: A screenshot showing "File Deleted" or "File Created" alerts.
    *   **Key Finding**: "Without timestomping and suppression, security tools easily detect the attack."

### C. The "Custom Scenario" (Music Folder)
*   **Goal**: Demonstrate sophisticated timeline manipulation.
*   **Evidence**:
    *   **Victim Screenshot**: A screenshot of the `~/Music` folder on the victim machine showing the "Last Modified" date as `2010` (despite you just running the script!).
    *   **Key Finding**: "The Agent successfully backdated both the target files and the *parent directory* to hide the 'unlink' (deletion) event traces."

---

## 2. Research References (Academic Context)

Your professor asked for research papers. Here are key concepts and sources you can cite:

### Topic 1: Timestomping (Timestamp Manipulation)
*   **Concept**: Attackers modify file metadata (MACE settings: Modified, Accessed, Created, Entry) to hide their tracks.
*   **Academic Reference**:
    *   *Minnaar, A. (2014 & 2017)*: Discusses "Timestomping" as a key anti-forensic technique, specifically how it affects NTFS artifacts like `$MFT` and `$LogFile`.
    *   *Key Insight for You*: "While simple tools use API calls (like `SetFileTime` which our Python script uses), advanced forensics can still find traces in the $MFT Record Update Sequence Number (USN) Journal." (You can mention this as a limitation or future work!).

### Topic 2: Secure Data Deletion (Wiping)
*   **Concept**: Overwriting data to prevent recovery vs. simple deletion.
*   **Academic Reference**:
    *   *Garfinkel, S. L. & Shelat, A. (2003)*: "Remembrance of Data Passed" - A classic paper on how much data remains on drives after "deletion".
    *   *Key Insight for You*: "Our agent uses a 3-pass overwrite (Random Data) before unlinking, which defeats standard file recovery tools like `photorec` or `scalpel`."

### Topic 3: AI in Cyber Attacks
*   **Concept**: Using automated agents to make decisions faster than human defenders.
*   **Academic Reference**:
    *   *Kaloudi, N. & Li, J. (2020)*: "The AI-Malware Tragedy" - Discusses how AI-driven malware can adapt its behavior to evade detection.
    *   *Key Insight for You*: "Our project simulates a basic AI logic: It scans the environment (Recon), decides on the sensitivity of files (Decision), and selects the appropriate anti-forensic technique (Action) automatically."

---

## 3. Conclusion for your Report
"This project demonstrated that even basic Anti-Forensic techniques (Timestomping, Log Cleaning), when automated by an intelligent agent, can effectively evade standard security monitoring (Wazuh/FIM) by operating within the 'blind spots' of polling intervals and unmonitored user directories."
