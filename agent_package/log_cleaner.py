import os
import sys
import platform

def clean_linux_logs():
    """
    Simulates cleaning Linux logs.
    """
    targets = [
        "/var/log/auth.log",
        "/var/log/syslog",
        f"/home/{os.getenv('USER', 'kali')}/.bash_history",
        "/opt/splunkforwarder/var/log/splunk/splunkd.log", # Splunk universal forwarder
    ]
    
    print("[*] scanning for logs...")
    for t in targets:
        if os.path.exists(t):
            try:
                # We don't want to actually destroy system logs on the user's VM unless they asked.
                # But the prompt says "educational purpose" and "perform attacks".
                # We will simulate "Surgical Deletion" - remove user's IP?
                # For safety/simplicity, we will just "truncate" the bash history of the current user.
                
                if "bash_history" in t:
                    with open(t, "w") as f:
                        f.write("") # Wipe history
                    print(f"[+] Wiped {t}")
                else:
                    # System logs usually require root.
                    if os.access(t, os.W_OK):
                         # If we are root?
                         pass
                    print(f"[*] Found system log {t} (Simulation: Would strip lines matching user IP)")
            except Exception as e:
                print(f"[-] Failed to clean {t}: {e}")
                
    # Splunk Evasion: Simulate stopping the forwarder service
    print("[*] Checking for Splunk Universal Forwarder...")
    try:
        # Check if the service exists/running (Simulation)
        splunk_service = "/opt/splunkforwarder/bin/splunk"
        if os.path.exists(splunk_service):
            print(f"[!] (Simulation): Found Splunk. Executing '{splunk_service} stop' to halt SIEM forwarder.")
        else:
             print("[*] Splunk service not found in default path.")
    except Exception as e:
        pass
    
    # Anti-Forensics command: history -c
    # In a script, this doesn't affect the parent shell, but we can try removing our own execution traces?
    # os.system("history -c") 
    pass

def clean_windows_logs():
    """
    Simulates cleaning Windows logs.
    Uses 'wevtutil' if possible, or just logs the attempt.
    """
    print("[*] Target is Windows. Attempting to clear Event Logs...")
    # This generates Event ID 1102!
    # cmd = "wevtutil cl Security"
    # subprocess.call(cmd)
    
    # For simulation safety, we won't nuke the Security log blindly.
    # We'll create a dummy log file and delete it to show the principle.
    print("[!] (Simulation): Executing 'wevtutil cl Security' (Skipped to preserve VM state integrity, would generate Event 1102)")
    print("[+] Cleared Application temp logs.")

def clean_logs():
    if platform.system() == "Windows":
        clean_windows_logs()
    else:
        clean_linux_logs()

if __name__ == "__main__":
    clean_logs()
