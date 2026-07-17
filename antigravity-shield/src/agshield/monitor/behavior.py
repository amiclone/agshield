"""
AntiGravity Shield — Behavioral Pattern Detector
=================================================
Detects abnormal burst patterns that distinguish automated
anti-forensic agents from normal user activity.

Uses a sliding window to track file operations per second and
identifies the create→overwrite→rename→delete sequence that
is the signature of data wiping tools.
"""

import time
import threading
import logging
from collections import deque
from typing import Callable, Optional

logger = logging.getLogger("antigravity.monitor.behavior")


class BehavioralDetector:
    """
    Stateful behavioral analysis engine.
    Maintains a sliding window of file system events and detects
    patterns indicative of automated anti-forensic tools.
    """

    def __init__(self, alert_callback: Optional[Callable] = None,
                 burst_window_seconds: float = 1.0,
                 burst_threshold_ops: int = 4,
                 ephemeral_threshold_seconds: float = 5.0,
                 wiper_sequence_window: float = 2.0,
                 rapid_deletion_threshold: int = 3):
        self.alert_callback = alert_callback
        self.lock = threading.Lock()

        # Thresholds
        self.burst_window_seconds = burst_window_seconds
        self.burst_threshold_ops = burst_threshold_ops
        self.ephemeral_threshold_seconds = ephemeral_threshold_seconds
        self.wiper_sequence_window = wiper_sequence_window
        self.rapid_deletion_threshold = rapid_deletion_threshold

        # Sliding window of all events: deque of (timestamp, event_type, path)
        self.event_window = deque()

        # Track file lifecycles: {filepath: {"created_at": float, "events": [...]}}
        self.file_lifecycles = {}

        # Track per-file event sequences for wiper detection
        self.file_sequences = {}

        # Statistics
        self.stats = {
            "total_events": 0,
            "burst_alerts": 0,
            "wiper_alerts": 0,
            "ephemeral_alerts": 0,
            "mass_deletion_alerts": 0,
            "process_burst_alerts": 0,
            "ssh_attack_alerts": 0,
        }

        # Per-process event tracking: {pid: deque of (timestamp, event_type, path)}
        self.process_events = {}

    def process_event(self, alert: dict):
        """Process an incoming file system event from the realtime monitor."""
        event_type = alert.get("event_type", "UNKNOWN")
        filepath = alert.get("path", "")
        event_time = alert.get("detection_wall_time", time.time())

        with self.lock:
            self.stats["total_events"] += 1

            # Add to sliding window
            self.event_window.append((event_time, event_type, filepath))

            # Prune old events from window
            cutoff = event_time - self.burst_window_seconds * 3
            while self.event_window and self.event_window[0][0] < cutoff:
                self.event_window.popleft()

            # Track file lifecycle
            self._track_lifecycle(filepath, event_type, event_time)

            # Track per-file sequences
            self._track_sequence(filepath, event_type, event_time)

        # Rule 1: Burst Detection
        self._check_burst(event_time)

        # Rule 2: Wiper Signature Detection
        if event_type == "FILE_DELETED":
            self._check_wiper_signature(filepath, event_time)

        # Rule 3: Ephemeral File Detection
        if event_type == "FILE_DELETED":
            self._check_ephemeral(filepath, event_time)

        # Rule 4: Rapid Sequential Deletion
        if event_type == "FILE_DELETED":
            self._check_rapid_deletion(event_time)

        # Rule 5: Per-process burst detection (kernel monitor provides PID)
        pid = alert.get("pid") or alert.get("details", {}).get("pid")
        if pid and pid > 0:
            self._check_process_burst(pid, event_type, filepath, event_time)

        # Rule 6: SSH-originated attack detection
        ssh_originated = alert.get("details", {}).get("ssh_originated", False)
        if not ssh_originated:
            proc_info = alert.get("details", {}).get("process", {})
            ssh_originated = proc_info.get("ssh_originated", False)
        if ssh_originated and event_type in ("FILE_DELETED", "FILE_MODIFIED", "FILE_MOVED"):
            self._check_ssh_attack(alert, event_time)

    def _track_lifecycle(self, filepath, event_type, event_time):
        """Track when files are created and their subsequent events."""
        if event_type == "FILE_CREATED":
            self.file_lifecycles[filepath] = {
                "created_at": event_time,
                "events": [(event_time, "CREATED")],
            }
        elif filepath in self.file_lifecycles:
            self.file_lifecycles[filepath]["events"].append((event_time, event_type))

    def _track_sequence(self, filepath, event_type, event_time):
        """Track event sequences per file for pattern matching."""
        if filepath not in self.file_sequences:
            self.file_sequences[filepath] = deque(maxlen=10)
        self.file_sequences[filepath].append((event_time, event_type))

    def _check_burst(self, current_time):
        """Rule 1: Detect abnormal burst of file operations."""
        with self.lock:
            window_start = current_time - self.burst_window_seconds
            recent_ops = sum(1 for t, _, _ in self.event_window if t >= window_start)

        if recent_ops >= self.burst_threshold_ops:
            with self.lock:
                window_start = current_time - self.burst_window_seconds
                burst_events = [
                    (t, et, p) for t, et, p in self.event_window if t >= window_start
                ]

            alert = {
                "module": "behavioral_detector",
                "event_type": "OPERATION_BURST",
                "path": "multiple",
                "detection_wall_time": time.time(),
                "detection_perf_time": time.perf_counter(),
                "severity": "CRITICAL",
                "details": {
                    "reason": (
                        f"Abnormal burst: {recent_ops} file operations in "
                        f"{self.burst_window_seconds}s window. "
                        f"Normal user activity averages <1 op/sec. "
                        f"This is characteristic of automated anti-forensic tools."
                    ),
                    "operations_in_window": recent_ops,
                    "window_seconds": self.burst_window_seconds,
                    "events": [
                        {"time": t, "type": et, "file": p}
                        for t, et, p in burst_events[-8:]
                    ],
                    "technique": "Automated Anti-Forensic Agent Detection",
                },
            }

            self.stats["burst_alerts"] += 1
            if self.alert_callback:
                self.alert_callback(alert)

    def _check_wiper_signature(self, filepath, event_time):
        """Rule 2: Detect the overwrite→rename→delete sequence."""
        with self.lock:
            window_start = event_time - self.wiper_sequence_window
            recent = [
                (t, et, p) for t, et, p in self.event_window
                if t >= window_start
            ]

        has_modify = any(et == "FILE_MODIFIED" for _, et, _ in recent)
        has_move = any(et == "FILE_MOVED" for _, et, _ in recent)
        has_delete = any(et == "FILE_DELETED" for _, et, _ in recent)

        if has_modify and has_move and has_delete:
            alert = {
                "module": "behavioral_detector",
                "event_type": "WIPER_SIGNATURE",
                "path": filepath,
                "detection_wall_time": time.time(),
                "detection_perf_time": time.perf_counter(),
                "severity": "CRITICAL",
                "details": {
                    "reason": (
                        f"SECURE WIPER DETECTED: Modify→Rename→Delete sequence "
                        f"completed within {self.wiper_sequence_window}s. "
                        f"This is the exact signature of anti-forensic data wiping tools "
                        f"that overwrite content before deletion to prevent recovery."
                    ),
                    "sequence": [
                        {"type": et, "file": p, "time": t}
                        for t, et, p in recent
                    ],
                    "technique": "T1485 - Data Destruction (MITRE ATT&CK)",
                },
            }

            self.stats["wiper_alerts"] += 1
            if self.alert_callback:
                self.alert_callback(alert)

    def _check_ephemeral(self, filepath, event_time):
        """Rule 3: Detect files that were created and deleted very quickly."""
        lifecycle = self.file_lifecycles.get(filepath)
        if not lifecycle:
            return

        created_at = lifecycle["created_at"]
        lifespan = event_time - created_at

        if lifespan < self.ephemeral_threshold_seconds:
            alert = {
                "module": "behavioral_detector",
                "event_type": "EPHEMERAL_FILE",
                "path": filepath,
                "detection_wall_time": time.time(),
                "detection_perf_time": time.perf_counter(),
                "severity": "WARNING",
                "details": {
                    "reason": (
                        f"Ephemeral file: existed for only {lifespan:.3f}s. "
                        f"Files created and immediately destroyed are indicators "
                        f"of malware staging, data exfiltration, or evidence cleanup."
                    ),
                    "lifespan_seconds": round(lifespan, 4),
                    "event_count": len(lifecycle["events"]),
                },
            }

            self.stats["ephemeral_alerts"] += 1
            if self.alert_callback:
                self.alert_callback(alert)

        # Clean up lifecycle tracking
        if filepath in self.file_lifecycles:
            del self.file_lifecycles[filepath]

    def _check_rapid_deletion(self, current_time):
        """Rule 4: Detect multiple files being deleted in rapid succession."""
        with self.lock:
            window_start = current_time - self.burst_window_seconds
            recent_deletions = [
                (t, p) for t, et, p in self.event_window
                if t >= window_start and et == "FILE_DELETED"
            ]

        if len(recent_deletions) >= self.rapid_deletion_threshold:
            alert = {
                "module": "behavioral_detector",
                "event_type": "MASS_DELETION",
                "path": "multiple",
                "detection_wall_time": time.time(),
                "detection_perf_time": time.perf_counter(),
                "severity": "CRITICAL",
                "details": {
                    "reason": (
                        f"{len(recent_deletions)} files deleted within {self.burst_window_seconds}s. "
                        f"Mass automated deletion detected."
                    ),
                    "deletion_count": len(recent_deletions),
                    "deleted_files": [p for _, p in recent_deletions],
                    "technique": "T1070.004 - File Deletion (MITRE ATT&CK)",
                },
            }

            self.stats["mass_deletion_alerts"] += 1
            if self.alert_callback:
                self.alert_callback(alert)

    def get_stats(self) -> dict:
        """Return detection statistics."""
        with self.lock:
            return dict(self.stats)

    def _check_process_burst(self, pid: int, event_type: str,
                             filepath: str, event_time: float) -> None:
        """Rule 5: Detect a single process performing many file ops rapidly."""
        with self.lock:
            if pid not in self.process_events:
                self.process_events[pid] = deque(maxlen=50)
            self.process_events[pid].append((event_time, event_type, filepath))

            # Prune old entries
            cutoff = event_time - self.burst_window_seconds * 2
            while (self.process_events[pid] and
                   self.process_events[pid][0][0] < cutoff):
                self.process_events[pid].popleft()

            window_start = event_time - self.burst_window_seconds
            recent = [
                (t, et, p) for t, et, p in self.process_events[pid]
                if t >= window_start
            ]

        threshold = max(3, self.burst_threshold_ops - 1)
        if len(recent) >= threshold:
            alert = {
                "module": "behavioral_detector",
                "event_type": "PROCESS_BURST",
                "path": "multiple",
                "pid": pid,
                "detection_wall_time": time.time(),
                "detection_perf_time": time.perf_counter(),
                "severity": "CRITICAL",
                "details": {
                    "reason": (
                        f"Single process (PID {pid}) performed "
                        f"{len(recent)} file operations in "
                        f"{self.burst_window_seconds}s. "
                        f"Automated anti-forensic agent signature."
                    ),
                    "pid": pid,
                    "operations_in_window": len(recent),
                    "events": [
                        {"time": t, "type": et, "file": p}
                        for t, et, p in recent[-6:]
                    ],
                    "technique": "Automated Anti-Forensic Agent (Single-PID)",
                },
            }
            self.stats["process_burst_alerts"] += 1
            if self.alert_callback:
                self.alert_callback(alert)

    def _check_ssh_attack(self, source_alert: dict,
                          event_time: float) -> None:
        """Rule 6: Flag destructive file operations from SSH sessions."""
        event_type = source_alert.get("event_type", "")
        filepath = source_alert.get("path", "")
        pid = source_alert.get("pid", 0)

        alert = {
            "module": "behavioral_detector",
            "event_type": "SSH_ATTACK_INDICATOR",
            "path": filepath,
            "pid": pid,
            "detection_wall_time": time.time(),
            "detection_perf_time": time.perf_counter(),
            "severity": "CRITICAL",
            "details": {
                "reason": (
                    f"Destructive file operation ({event_type}) on "
                    f"{os.path.basename(filepath)} originated from SSH "
                    f"session (PID {pid}). Remote attacker activity detected."
                ),
                "original_event": event_type,
                "technique": "T1021.004 - Remote Services: SSH (MITRE ATT&CK)",
            },
        }
        self.stats["ssh_attack_alerts"] += 1
        if self.alert_callback:
            self.alert_callback(alert)
