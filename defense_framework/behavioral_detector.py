"""
AntiGravity Shield — Module 5: Behavioral Pattern Detector
===========================================================
Detects the abnormal burst pattern that distinguishes automated
anti-forensic agents from normal user activity.

Uses a sliding window to track file operations per second and
identifies the specific create→overwrite→rename→delete sequence
that is the signature of data wiping tools.

Counters: agent_controller.py full attack chain (timestomp → wipe → delete in <400ms)
"""

import time
import threading
from collections import deque
from datetime import datetime


# Detection thresholds
BURST_WINDOW_SECONDS = 1.0       # Sliding window size
BURST_THRESHOLD_OPS = 4          # Operations per window to trigger alert
EPHEMERAL_THRESHOLD_SECS = 5.0   # File created and deleted within this time
WIPER_SEQUENCE_WINDOW = 2.0      # Time window to detect overwrite→rename→delete


class BehavioralDetector:
    """
    Stateful behavioral analysis engine.
    Maintains a sliding window of file system events and detects
    patterns indicative of automated anti-forensic tools.
    """

    def __init__(self, alert_callback=None):
        self.alert_callback = alert_callback
        self.lock = threading.Lock()

        # Sliding window of all events: deque of (timestamp, event_type, path)
        self.event_window = deque()

        # Track file lifecycles: {filepath: {"created_at": float, "events": [...]}}
        self.file_lifecycles = {}

        # Track per-file event sequences for wiper detection
        # {filepath: [(timestamp, event_type), ...]}
        self.file_sequences = {}

        # Statistics
        self.stats = {
            "total_events": 0,
            "burst_alerts": 0,
            "wiper_alerts": 0,
            "ephemeral_alerts": 0,
        }

    def process_event(self, alert):
        """
        Process an incoming file system event from the realtime monitor.
        Runs behavioral analysis rules against the event stream.

        Args:
            alert: Alert dict from realtime_monitor
        """
        event_type = alert.get("event_type", "UNKNOWN")
        filepath = alert.get("path", "")
        event_time = alert.get("detection_wall_time", time.time())

        with self.lock:
            self.stats["total_events"] += 1

            # Add to sliding window
            self.event_window.append((event_time, event_type, filepath))

            # Prune old events from window
            cutoff = event_time - BURST_WINDOW_SECONDS * 3  # Keep 3x window for sequence analysis
            while self.event_window and self.event_window[0][0] < cutoff:
                self.event_window.popleft()

            # Track file lifecycle
            self._track_lifecycle(filepath, event_type, event_time)

            # Track per-file sequences
            self._track_sequence(filepath, event_type, event_time)

        # ─── Rule 1: Burst Detection ───
        self._check_burst(event_time)

        # ─── Rule 2: Wiper Signature Detection ───
        if event_type == "FILE_DELETED":
            self._check_wiper_signature(filepath, event_time)

        # ─── Rule 3: Ephemeral File Detection ───
        if event_type == "FILE_DELETED":
            self._check_ephemeral(filepath, event_time)

        # ─── Rule 4: Rapid Sequential Deletion ───
        if event_type == "FILE_DELETED":
            self._check_rapid_deletion(event_time)

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
            self.file_sequences[filepath] = deque(maxlen=10)  # Keep last 10 events per file
        self.file_sequences[filepath].append((event_time, event_type))

    def _check_burst(self, current_time):
        """
        Rule 1: Detect abnormal burst of file operations.
        Normal users don't generate >4 file events per second.
        Automated tools do.
        """
        with self.lock:
            window_start = current_time - BURST_WINDOW_SECONDS
            recent_ops = sum(1 for t, _, _ in self.event_window if t >= window_start)

        if recent_ops >= BURST_THRESHOLD_OPS:
            # Collect the burst details
            with self.lock:
                window_start = current_time - BURST_WINDOW_SECONDS
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
                        f"{BURST_WINDOW_SECONDS}s window. "
                        f"Normal user activity averages <1 op/sec. "
                        f"This is characteristic of automated anti-forensic tools."
                    ),
                    "operations_in_window": recent_ops,
                    "window_seconds": BURST_WINDOW_SECONDS,
                    "events": [
                        {"time": t, "type": et, "file": p}
                        for t, et, p in burst_events[-8:]  # Last 8 events
                    ],
                    "technique": "Automated Anti-Forensic Agent Detection",
                },
            }

            self.stats["burst_alerts"] += 1
            if self.alert_callback:
                self.alert_callback(alert)

    def _check_wiper_signature(self, filepath, event_time):
        """
        Rule 2: Detect the overwrite→rename→delete sequence.
        This is the exact behavioral signature of data_wiper.py:
        1. Open file, overwrite with random bytes (MODIFIED event)
        2. Rename to random string (MOVED event)
        3. Delete (DELETED event)
        """
        # For moved files, check original path
        # We need to check if there was a recent MODIFY then MOVE for any path
        # that now resolves to this deletion

        with self.lock:
            window_start = event_time - WIPER_SEQUENCE_WINDOW

            # Look for the sequence in recent events
            recent = [
                (t, et, p) for t, et, p in self.event_window
                if t >= window_start
            ]

        # Check for MODIFIED → MOVED → DELETED pattern within the window
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
                        f"completed within {WIPER_SEQUENCE_WINDOW}s. "
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
        """
        Rule 3: Detect files that were created and deleted very quickly.
        Legitimate files persist. Attacker tools create, use, and destroy evidence.
        """
        lifecycle = self.file_lifecycles.get(filepath)
        if not lifecycle:
            return

        created_at = lifecycle["created_at"]
        lifespan = event_time - created_at

        if lifespan < EPHEMERAL_THRESHOLD_SECS:
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
        """
        Rule 4: Detect multiple files being deleted in rapid succession.
        Mass deletion in <1 second indicates automated cleanup.
        """
        with self.lock:
            window_start = current_time - BURST_WINDOW_SECONDS
            recent_deletions = [
                (t, p) for t, et, p in self.event_window
                if t >= window_start and et == "FILE_DELETED"
            ]

        if len(recent_deletions) >= 3:
            alert = {
                "module": "behavioral_detector",
                "event_type": "MASS_DELETION",
                "path": "multiple",
                "detection_wall_time": time.time(),
                "detection_perf_time": time.perf_counter(),
                "severity": "CRITICAL",
                "details": {
                    "reason": (
                        f"{len(recent_deletions)} files deleted within {BURST_WINDOW_SECONDS}s. "
                        f"Mass automated deletion detected."
                    ),
                    "deletion_count": len(recent_deletions),
                    "deleted_files": [p for _, p in recent_deletions],
                    "technique": "T1070.004 - File Deletion (MITRE ATT&CK)",
                },
            }

            if self.alert_callback:
                self.alert_callback(alert)

    def get_stats(self):
        """Return detection statistics."""
        with self.lock:
            return dict(self.stats)


if __name__ == "__main__":
    print("[SHIELD] Behavioral Detector — standalone mode")
    print("  This module is designed to be driven by realtime_monitor events.")
    print("  Use shield_controller.py to run the full defense stack.")
