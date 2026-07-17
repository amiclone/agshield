# Role 1: The Red Team (Attacker) Report
**Role**: Malware Developer & Offensive Operator
**Focus**: Tool Development, Anti-Forensics Logic, and Deployment

## 1. Introduction: The "Stealth Agent" Concept
For this project, my role was to design and execute a sophisticated "AI-Driven" attack agent capable of operating behind enemy lines (on a compromised Linux Victim) while actively evading detection. Unlike standard malware which leaves obvious traces (deleted files, modified logs), our goal was **Anti-Forensics**: the systematic destruction and manipulation of evidence to make the attack invisible to standard monitoring tools like File Integrity Monitoring (FIM).

We focused on three core techniques:
1.  **Timestomping**: Manipulating file metadata (Create/Modify/Access times) to blend in with legitimate system files.
2.  **Secure Wiping**: Overwriting data before deletion to prevent forensic recovery.
3.  **Log Suppression**: Cleaning bash history and traces to blind incident responders.

## 2. Tool Development (The Toolkit)
I developed a modular Python-based toolkit (`agent_package`) to handle these tasks autonomously.

### 2.1 The Time Manipulation Engine (`timestomper.py`)
Standard attackers use tools like `touch` which are easily logged. I wrote a custom script using Python's low-level `os.utime` function to precisely modify access and modification timestamps.

**Key Code snippet:**
```python
def stomp_file(filepath, new_time_str):
    """
    Converts a string like '2010-01-01' to epoch time and applies it
    to Atime (Access) and Mtime (Modify) of the target file.
    """
    target_time = time.mktime(datetime.strptime(new_time_str, "%Y-%m-%d %H:%M:%S").timetuple())
    os.utime(filepath, (target_time, target_time))
```
This allowed us to "backdate" our malware artifacts to the year 2010, effectively processing them outside the "Recent Changes" window of many security scanners.

### 2.2 The Secure Wiper (`data_wiper.py`)
Simply deleting a file (`rm file`) leaves the data on the disk. I implemented a secure wiper that performs a 3-pass overwrite before unlinking the file.
1.  **Pass 1-3**: Overwrite file content with random bytes (`os.urandom`).
2.  **Obfuscation**: Rename the file to a random string (e.g., `a8f92.tmp`) to scramble the filename entry in the Master File Table (MFT).
3.  **Deletion**: Finally call `os.remove()`.

### 2.3 The Logic Engine (`agent_controller.py`)
This is the "AI" brain. It accepts a `--noisy` flag to toggle between behavior modes:
*   **Stealth Mode (Default)**: Executes Timestomp -> Wipe -> Log Clean.
*   **Noisy Mode**: Executes standard `os.remove` (simulating a sloppy attacker) to generate a control baseline for our detection team.

## 3. Deployment & Execution
To simulate a real-world lateral movement scenario, we did not run the script locally. Instead, I built a `remote_deployer.py` script on our Command & Control (C2) host (Ubuntu).

### 3.1 The Attack Chain
1.  **Transport**: The deployer connects via **SSH** (Port 22) to the Victim (Kali Linux) using compromised credentials (`kali:kali`).
2.  **Staging**: It creates a temporary workspace (`/home/kali/agent_deployment_...`).
3.  **Execution**: It runs the Python agent and waits for the JSON report.
4.  **Exfiltration**: The `operation_report.json` is downloaded back to the C2 server for analysis.

### 3.2 Evidence of Execution
We performed multiple successful runs. Below is the evidence of the "Mass Deletion" scenario, where the agent targeted the `~/Music` directory, backdated every file, and then deleted them.

![Mass Deletion Evidence](/home/amiclone/.gemini/antigravity/brain/cae3cbc1-8426-420a-afbb-bff44da9f89a/uploaded_image_4_1765448057700.png)
*Figure 1: Terminal output from the C2 server showing the Agent successfully connecting, navigating to the Music folder, backdating files to 2010 ("Successfully timestomped"), and then deleting them.*

We also verified the "Noisy" vs "Stealth" modes. In the Stealth run (shown below), the agent completed its task and self-reported the "Success" status of its anti-forensic modules.

![Attack Complete](/home/amiclone/.gemini/antigravity/brain/cae3cbc1-8426-420a-afbb-bff44da9f89a/uploaded_image_0_1765448057700.png)
*Figure 2: Successful completion of the remote attack deployment.*

## 4. Conclusion (Red Team)
The tools developed successfully demonstrated that **automation speed** is a critical vulnerability in defense. By performing creation, modification, and deletion operations within milliseconds (as shown in our logs), we observed that standard periodic scanners failed to flag the activity in real-time. This confirms the hypothesis that high-speed Anti-Forensics can beat scheduled polling monitoring.
