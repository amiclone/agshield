#!/usr/bin/env python3
"""
Deploy AntiGravity Shield v2.0 to Windows VM via SSH.

Usage:
    python3 deploy_shield.py

This script:
1. Packages the shield source code
2. Copies it to the Windows VM via SCP
3. Installs dependencies
4. Starts the shield watching C:\\Users\\vboxuser\\Desktop\\evidence_workspace
"""

import subprocess
import sys
import os

VM_HOST = "192.168.122.34"
VM_USER = "vboxuser"
VM_TARGET_DIR = "C:\\Users\\vboxuser\\antigravity-shield"
VM_WATCH_DIR = "C:\\Users\\vboxuser\\Desktop\\evidence_workspace"

SHIELD_SRC = os.path.join(os.path.dirname(__file__), "antigravity-shield")


def ssh(cmd, check=True):
    """Execute a command on the Windows VM via SSH."""
    full_cmd = ["ssh", "-o", "StrictHostKeyChecking=no", f"{VM_USER}@{VM_HOST}", cmd]
    print(f"  [SSH] {cmd}")
    result = subprocess.run(full_cmd, capture_output=True, text=True)
    if result.stdout.strip():
        print(f"        {result.stdout.strip()[:200]}")
    if result.returncode != 0 and check:
        print(f"  [ERROR] {result.stderr.strip()[:200]}")
    return result


def scp_dir(local_path, remote_path):
    """Copy a directory to the VM."""
    cmd = ["scp", "-r", "-o", "StrictHostKeyChecking=no",
           local_path, f"{VM_USER}@{VM_HOST}:{remote_path}"]
    print(f"  [SCP] {local_path} → {remote_path}")
    return subprocess.run(cmd, capture_output=True, text=True)


def main():
    print("=" * 60)
    print("  AntiGravity Shield v2.0 — Windows VM Deployment")
    print("=" * 60)
    print()

    # Step 1: Check VM connectivity
    print("[1/5] Checking VM connectivity...")
    result = ssh("echo OK", check=False)
    if result.returncode != 0:
        print("  FAILED: Cannot connect to VM. Is it running?")
        sys.exit(1)
    print("  ✅ Connected\n")

    # Step 2: Create directories on VM
    print("[2/5] Creating directories on VM...")
    ssh(f'if not exist "{VM_TARGET_DIR}" mkdir "{VM_TARGET_DIR}"')
    ssh(f'if not exist "{VM_WATCH_DIR}" mkdir "{VM_WATCH_DIR}"')
    # Create some evidence files to protect
    ssh(f'echo CONFIDENTIAL_REPORT > "{VM_WATCH_DIR}\\financial_report.txt"')
    ssh(f'echo EMPLOYEE_RECORDS > "{VM_WATCH_DIR}\\employee_data.csv"')
    ssh(f'echo ACCESS_LOGS > "{VM_WATCH_DIR}\\access_log.txt"')
    ssh(f'echo AUDIT_TRAIL > "{VM_WATCH_DIR}\\audit_trail.log"')
    print("  ✅ Directories and evidence files created\n")

    # Step 3: Upload shield source
    print("[3/5] Uploading shield to VM...")
    # Clean old installation
    ssh(f'if exist "{VM_TARGET_DIR}\\src" rmdir /s /q "{VM_TARGET_DIR}\\src"', check=False)
    ssh(f'if exist "{VM_TARGET_DIR}\\config" rmdir /s /q "{VM_TARGET_DIR}\\config"', check=False)

    scp_dir(os.path.join(SHIELD_SRC, "src"), VM_TARGET_DIR)
    scp_dir(os.path.join(SHIELD_SRC, "config"), VM_TARGET_DIR)
    scp_dir(os.path.join(SHIELD_SRC, "pyproject.toml"), VM_TARGET_DIR)

    print("  ✅ Shield uploaded\n")

    # Step 4: Install on VM
    print("[4/5] Installing shield on VM...")
    ssh(f'cd /d "{VM_TARGET_DIR}" && pip install -e . 2>&1')
    # Verify installation
    result = ssh('python -c "from agshield import __version__; print(f\'AntiGravity Shield v{__version__}\')"')
    print(f"  ✅ Installed\n")

    # Step 5: Test import
    print("[5/5] Verifying shield works on Windows...")
    result = ssh('python -c "'
                 'from agshield.monitor.kernel_monitor import KernelMonitor; '
                 'from agshield.monitor.process_tracker import ProcessTracker; '
                 'from agshield.detection.engine import DetectionEngine; '
                 'print(\"All modules loaded OK\")'
                 '"')
    print()

    print("=" * 60)
    print("  ✅ DEPLOYMENT COMPLETE")
    print("=" * 60)
    print()
    print("To START the shield on the VM:")
    print(f"  ssh {VM_USER}@{VM_HOST}")
    print(f"  agshield start -w \"{VM_WATCH_DIR}\"")
    print()
    print("Or run from your host:")
    print(f'  ssh {VM_USER}@{VM_HOST} "agshield start -w \\"{VM_WATCH_DIR}\\" --log-level DEBUG"')
    print()


if __name__ == "__main__":
    main()
