# Role 2: The Security Engineer (Blue Team - Builder) Report
**Role**: Infrastructure Architect & Integrity Engineer
**Focus**: System Hardening, Network Setup, and Monitoring Implementation

## 1. Environment Architecture
To create a realistic simulation of a corporate environment under attack, I designed a virtualized testbed using Oracle VirtualBox. The infrastructure consisted of two primary nodes:

1.  **The Attacker Node (C2 Server)**: A remote system (Ubuntu Host) simulating the external adversary or a compromised machine initiating lateral movement.
2.  **The Victim Node (Target Endpoint)**: A Kali Linux Virtual Machine simulating a workstation or server with sensitive data.

### 1.1 Network Configuration
A critical challenge was ensuring the Attacker could reach the Victim (SSH Port 22) while maintaining a realistic network profile.
*   **Initial Attempt (NAT)**: The default NAT network isolated the VM, preventing inbound connections.
*   **Solution (Bridged Adapter)**: I reconfigured the VM to use a "Bridged Adapter," assigning it an IP address (`192.168.0.81`) on the same physical LAN as the Attacker. This mirrored a real-world scenario where two machines are on the same corporate subnet.

## 2. Monitoring Stack Implementation
I deployed a "Defense-in-Depth" monitoring strategy using three distinct layers of observability.

### 2.1 Layer 1: Wazuh (File Integrity Monitoring)
Wazuh is our primary HIDS (Host-based Intrusion Detection System).
*   **Installation**: I installed the Wazuh Agent on the Kali Linux endpoint.
    ```bash
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
    echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
    apt-get update && apt-get install wazuh-agent
    ```
*   **Configuration**: While the default configuration monitors `/etc`, I explicitly modified `/var/ossec/etc/ossec.conf` to add the custom monitoring scope for our simulation. I added a `<syscheck>` block to monitor the user's home directory and specific high-value targets like generic text files, setting the `frequency` to its default (which proved to be a vulnerability later).

### 2.2 Layer 2: Sysmon for Linux (Process Monitoring)
To track malicious process execution (like the Python script itself), I installed Microsoft's Sysmon for Linux.
*   **Deployment**:
    ```bash
    wget -q https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb
    dpkg -i packages-microsoft-prod.deb
    apt-get update && apt-get install sysmonforlinux
    ```
*   **Rule Tuning**: I configured `sysmonconfig.xml` to log Event ID 11 (FileCreate) and Event ID 1 (ProcessCreate). This was intended to catch the dropper (`malware_dropper.exe`) being placed on disk.

### 2.3 Layer 3: Kernel Auditing (Auditd)
Recognizing that user-mode tools can be bypassed, I enabled the Linux Audit Daemon (`auditd`) for kernel-level visibility.
*   **Rule Definition**: I created a specific watch rule to monitor the `kali` user's directory for any *write* or *attribute change* (timestomping) events.
    ```bash
    sudo auditctl -w /home/kali -p wa -k anti_forensics_watch
    ```
    *   `-w /home/kali`: Watch this path recursively.
    *   `-p wa`: Flag **W**rites (creation/deletion) and **A**ttribute changes (timestamp manipulation).
    *   `-k`: Tag logs with a specific key for easy searching.

## 3. Conclusion (Security Engineer)
The infrastructure was successfully verified. The Bridged Network allowed seamless SSH attacks, and the monitoring stack was fully active. However, as the Engineer, I noted that while `auditd` provides real-time logs, the centralized Wazuh FIM has a polling delay (latency) that might be exploited by rapid attacks. This architectural limitation was documented and passed to the Forensic Analyst for investigation.
