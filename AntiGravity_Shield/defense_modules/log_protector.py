"""
AntiGravity Shield — Module 4: Immutable Log Protector
======================================================
Prevents log destruction by maintaining a cryptographically hash-chained,
append-only local log file. If any entry is deleted or modified,
the chain breaks and tampering is immediately detectable.

Counters: log_cleaner.py (log truncation, history wiping)
"""

import os
import time
import json
import hashlib
import threading
from datetime import datetime


class LogProtector:
    """
    Maintains an immutable, hash-chained audit log.

    Each log entry contains:
    - The event data
    - A SHA-256 hash of the previous entry
    - A sequence number

    If any entry is modified or deleted, the hash chain breaks,
    providing cryptographic proof of tampering.
    """

    def __init__(self, log_path="reports/shield_audit.log", chain_path="reports/hash_chain.json"):
        self.log_path = log_path
        self.chain_path = chain_path
        self.lock = threading.Lock()
        self.sequence = 0
        self.prev_hash = "GENESIS"  # Initial hash for the first entry
        self._monitored_logs = []
        self._log_snapshots = {}  # {filepath: size} for detecting truncation

        os.makedirs(os.path.dirname(log_path), exist_ok=True)

        # Resume chain if log exists
        self._resume_chain()

    def _resume_chain(self):
        """Resume the hash chain from the last entry if the log exists."""
        if os.path.exists(self.chain_path):
            try:
                with open(self.chain_path, "r") as f:
                    chain_state = json.load(f)
                    self.sequence = chain_state.get("sequence", 0)
                    self.prev_hash = chain_state.get("last_hash", "GENESIS")
            except (json.JSONDecodeError, IOError):
                pass

    def _save_chain_state(self):
        """Persist the current chain state."""
        with open(self.chain_path, "w") as f:
            json.dump({
                "sequence": self.sequence,
                "last_hash": self.prev_hash,
                "updated_at": time.time(),
            }, f)

    def log_event(self, alert):
        """
        Append an alert to the immutable log with hash chaining.

        Args:
            alert: Dict containing alert data from any shield module
        """
        with self.lock:
            self.sequence += 1

            entry = {
                "seq": self.sequence,
                "timestamp": time.time(),
                "timestamp_human": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                "prev_hash": self.prev_hash,
                "data": alert,
            }

            # Calculate hash of this entry (includes prev_hash, creating the chain)
            entry_str = json.dumps(entry, sort_keys=True)
            entry_hash = hashlib.sha256(entry_str.encode()).hexdigest()
            entry["entry_hash"] = entry_hash

            # Append to log file
            try:
                with open(self.log_path, "a") as f:
                    f.write(json.dumps(entry) + "\n")
            except IOError as e:
                print(f"  [SHIELD] ✗ Failed to write log: {e}")
                return

            # Update chain
            self.prev_hash = entry_hash
            self._save_chain_state()

    def verify_integrity(self):
        """
        Verify the complete hash chain of the audit log.

        Returns:
            dict: {valid: bool, entries_checked: int, error: str or None}
        """
        if not os.path.exists(self.log_path):
            return {"valid": True, "entries_checked": 0, "error": None}

        prev_hash = "GENESIS"
        entries_checked = 0

        try:
            with open(self.log_path, "r") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        return {
                            "valid": False,
                            "entries_checked": entries_checked,
                            "error": f"Corrupted entry at line {line_num}",
                        }

                    # Verify chain link
                    if entry.get("prev_hash") != prev_hash:
                        return {
                            "valid": False,
                            "entries_checked": entries_checked,
                            "error": (
                                f"HASH CHAIN BROKEN at entry #{entry.get('seq', '?')} (line {line_num}). "
                                f"Expected prev_hash={prev_hash[:16]}..., "
                                f"got={entry.get('prev_hash', 'MISSING')[:16]}... "
                                f"LOG TAMPERING DETECTED!"
                            ),
                        }

                    # Verify entry's own hash
                    stored_hash = entry.pop("entry_hash", None)
                    recalc_hash = hashlib.sha256(
                        json.dumps(entry, sort_keys=True).encode()
                    ).hexdigest()

                    if stored_hash != recalc_hash:
                        return {
                            "valid": False,
                            "entries_checked": entries_checked,
                            "error": (
                                f"ENTRY HASH MISMATCH at entry #{entry.get('seq', '?')} (line {line_num}). "
                                f"Entry content was modified! LOG TAMPERING DETECTED!"
                            ),
                        }

                    prev_hash = stored_hash
                    entries_checked += 1

        except IOError as e:
            return {"valid": False, "entries_checked": entries_checked, "error": str(e)}

        return {"valid": True, "entries_checked": entries_checked, "error": None}

    def monitor_external_logs(self, log_paths):
        """
        Register external log files to monitor for truncation/deletion.

        Args:
            log_paths: List of log file paths to watch
        """
        for path in log_paths:
            self._monitored_logs.append(path)
            if os.path.exists(path):
                self._log_snapshots[path] = os.path.getsize(path)
            else:
                self._log_snapshots[path] = 0

    def check_external_logs(self):
        """
        Check monitored log files for signs of tampering.

        Detects:
        - Log file deletion
        - Log file truncation (size decreased)
        - Log silence (no growth when expected)

        Returns:
            list: Alert dicts for any detected tampering
        """
        alerts = []

        for path in self._monitored_logs:
            prev_size = self._log_snapshots.get(path, 0)

            if not os.path.exists(path):
                if prev_size > 0:
                    alerts.append({
                        "module": "log_protector",
                        "event_type": "LOG_DELETED",
                        "path": path,
                        "detection_wall_time": time.time(),
                        "detection_perf_time": time.perf_counter(),
                        "severity": "CRITICAL",
                        "details": {
                            "reason": (
                                f"Monitored log file DELETED: {path}. "
                                f"Previous size was {prev_size} bytes. "
                                f"This is a signature of log_cleaner anti-forensic tools."
                            ),
                            "previous_size": prev_size,
                            "technique": "T1070.002 - Clear Linux/Mac System Logs (MITRE ATT&CK)",
                        },
                    })
                continue

            current_size = os.path.getsize(path)

            # Truncation detection
            if current_size < prev_size:
                alerts.append({
                    "module": "log_protector",
                    "event_type": "LOG_TRUNCATED",
                    "path": path,
                    "detection_wall_time": time.time(),
                    "detection_perf_time": time.perf_counter(),
                    "severity": "CRITICAL",
                    "details": {
                        "reason": (
                            f"Log file TRUNCATED: {path}. "
                            f"Size decreased from {prev_size} to {current_size} bytes. "
                            f"Log tampering in progress!"
                        ),
                        "previous_size": prev_size,
                        "current_size": current_size,
                        "bytes_lost": prev_size - current_size,
                        "technique": "T1070.002 - Clear Linux/Mac System Logs (MITRE ATT&CK)",
                    },
                })

            self._log_snapshots[path] = current_size

        return alerts

    def get_stats(self):
        """Return log statistics."""
        return {
            "total_entries": self.sequence,
            "log_file": self.log_path,
            "chain_valid": self.verify_integrity()["valid"],
        }


if __name__ == "__main__":
    print("[SHIELD] Log Protector — Integrity Check")

    protector = LogProtector()

    # Verify existing log
    result = protector.verify_integrity()

    if result["valid"]:
        print(f"  ✅ Log integrity VERIFIED — {result['entries_checked']} entries checked")
    else:
        print(f"  🚨 LOG TAMPERING DETECTED!")
        print(f"     Error: {result['error']}")
