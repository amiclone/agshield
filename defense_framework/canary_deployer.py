"""
AntiGravity Shield — Module 2: Canary File Deployer
====================================================
Plants honeypot/tripwire files in monitored directories.
Any interaction with these files is a zero-false-positive intrusion indicator.

Counters: All unauthorized file access, deletion, or modification
"""

import os
import time
import json
import hashlib
import random
import string


# Realistic-looking canary filenames designed to attract attackers
CANARY_TEMPLATES = [
    {"name": "passwords_backup.txt", "content": "# Password Vault Export\n# Generated: 2024-03-15\n\nadmin:P@ssw0rd123!\nroot:Tr0ub4dor&3\ndb_user:MySQL_Pr0d_2024\n"},
    {"name": "ssh_private_key.bak", "content": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAE\nCANARY_FILE_DO_NOT_USE_THIS_IS_FAKE\nnm9uZQAAAAAAAAEAAAAzAAAAC3NzaC1lZDI1\n-----END OPENSSH PRIVATE KEY-----\n"},
    {"name": "financial_report_Q4_CONFIDENTIAL.csv", "content": "Date,Account,Amount,Status\n2024-01-15,Corporate Account,1250000.00,Cleared\n2024-01-22,Reserve Fund,890000.50,Pending\n2024-02-01,Exec Bonus Pool,450000.00,Approved\n"},
    {"name": "database_credentials.conf", "content": "[production]\nhost = 10.0.1.50\nport = 5432\nuser = prod_admin\npassword = xK9#mL2$vQ7@nR4\ndatabase = customer_records\n"},
    {"name": ".aws_credentials_old", "content": "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nregion = us-east-1\n"},
    {"name": "employee_ssn_list.xlsx.bak", "content": "CANARY FILE - This is a decoy placed by security monitoring.\nAny access to this file indicates unauthorized activity.\n"},
    {"name": "vpn_config_backup.ovpn", "content": "client\ndev tun\nproto udp\nremote vpn.internal.corp 1194\nresolv-retry infinite\nnobind\nca ca.crt\ncert client.crt\nkey client.key\n# CANARY - NOT A REAL CONFIG\n"},
    {"name": "bitcoin_wallet.dat.bak", "content": "CANARY DECOY - wallet simulation\naddress: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\nbalance: 0.00000000\n"},
]


class CanaryDeployer:
    """
    Deploys and manages canary (honeypot) files across monitored directories.
    """

    def __init__(self, registry_path="reports/canary_registry.json"):
        self.registry_path = registry_path
        self.registry = {}  # {filepath: {sha256, deployed_at, template_name}}
        self._load_registry()

    def _load_registry(self):
        """Load existing canary registry from disk."""
        if os.path.exists(self.registry_path):
            try:
                with open(self.registry_path, "r") as f:
                    self.registry = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.registry = {}

    def _save_registry(self):
        """Persist the canary registry to disk."""
        os.makedirs(os.path.dirname(self.registry_path), exist_ok=True)
        with open(self.registry_path, "w") as f:
            json.dump(self.registry, f, indent=2)

    @staticmethod
    def _hash_content(content):
        """SHA-256 hash of string content."""
        return hashlib.sha256(content.encode()).hexdigest()

    def deploy_canaries(self, target_dir, count=3):
        """
        Deploy canary files into a target directory.

        Args:
            target_dir: Directory to plant canary files in
            count: Number of canary files to deploy (max = len(CANARY_TEMPLATES))

        Returns:
            dict: Registry of deployed canary files {filepath: metadata}
        """
        if not os.path.exists(target_dir):
            print(f"  [SHIELD] ⚠  Target directory does not exist: {target_dir}")
            return {}

        # Select random templates
        templates = random.sample(CANARY_TEMPLATES, min(count, len(CANARY_TEMPLATES)))
        deployed = {}

        for template in templates:
            filepath = os.path.join(target_dir, template["name"])

            # Don't overwrite real files
            if os.path.exists(filepath) and filepath not in self.registry:
                print(f"  [SHIELD] ⚠  Skipping {template['name']} — real file exists")
                continue

            try:
                with open(filepath, "w") as f:
                    f.write(template["content"])

                sha = self._hash_content(template["content"])
                metadata = {
                    "sha256": sha,
                    "deployed_at": time.time(),
                    "template_name": template["name"],
                    "size": len(template["content"]),
                }

                self.registry[filepath] = metadata
                deployed[filepath] = metadata
                print(f"  [SHIELD] 🍯 Deployed canary: {template['name']}")

            except (OSError, IOError) as e:
                print(f"  [SHIELD] ✗  Failed to deploy {template['name']}: {e}")

        self._save_registry()
        return deployed

    def verify_canaries(self):
        """
        Check the integrity of all deployed canary files.

        Returns:
            list: List of alert dicts for any tampered/missing canaries
        """
        alerts = []

        for filepath, metadata in list(self.registry.items()):
            if not os.path.exists(filepath):
                alerts.append({
                    "module": "canary_deployer",
                    "event_type": "CANARY_MISSING",
                    "path": filepath,
                    "detection_wall_time": time.time(),
                    "detection_perf_time": time.perf_counter(),
                    "severity": "CRITICAL",
                    "details": {
                        "reason": f"Canary file DELETED: {os.path.basename(filepath)}",
                        "deployed_at": metadata["deployed_at"],
                        "original_sha256": metadata["sha256"],
                    },
                })
                continue

            # Check hash
            try:
                with open(filepath, "r") as f:
                    current_content = f.read()
                current_sha = self._hash_content(current_content)

                if current_sha != metadata["sha256"]:
                    alerts.append({
                        "module": "canary_deployer",
                        "event_type": "CANARY_TAMPERED",
                        "path": filepath,
                        "detection_wall_time": time.time(),
                        "detection_perf_time": time.perf_counter(),
                        "severity": "CRITICAL",
                        "details": {
                            "reason": f"Canary file MODIFIED: {os.path.basename(filepath)}",
                            "original_sha256": metadata["sha256"],
                            "current_sha256": current_sha,
                        },
                    })
            except (OSError, IOError):
                alerts.append({
                    "module": "canary_deployer",
                    "event_type": "CANARY_UNREADABLE",
                    "path": filepath,
                    "detection_wall_time": time.time(),
                    "detection_perf_time": time.perf_counter(),
                    "severity": "CRITICAL",
                    "details": {
                        "reason": f"Canary file unreadable: {os.path.basename(filepath)}",
                    },
                })

        return alerts

    def get_registry(self):
        """Return a copy of the canary file registry for use by other modules."""
        return dict(self.registry)

    def cleanup(self):
        """Remove all deployed canary files (for test teardown)."""
        for filepath in list(self.registry.keys()):
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
                    print(f"  [SHIELD] 🧹 Removed canary: {os.path.basename(filepath)}")
            except OSError:
                pass
        self.registry = {}
        self._save_registry()


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"[SHIELD] Deploying canary files to: {target}")

    deployer = CanaryDeployer()
    deployer.deploy_canaries(target, count=3)

    print(f"\n[SHIELD] Verifying canaries...")
    alerts = deployer.verify_canaries()
    if alerts:
        for a in alerts:
            print(f"  🚨 {a['event_type']}: {a['path']}")
    else:
        print("  ✅ All canary files intact.")
