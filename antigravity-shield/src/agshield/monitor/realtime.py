"""
AntiGravity Shield — Real-Time File Monitor
============================================
Kernel-event-driven file system monitoring using Linux inotify.
Replaces periodic polling FIM with sub-millisecond event detection.
"""

import os
import time
import hashlib
import sqlite3
import threading
import logging
from datetime import datetime
from typing import Callable, Dict, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logger = logging.getLogger("antigravity.monitor.realtime")


class FileBaseline:
    """SQLite-backed file state database for change detection."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        with self.lock:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS file_states (
                    filepath TEXT PRIMARY KEY,
                    sha256 TEXT,
                    size INTEGER,
                    mtime REAL,
                    atime REAL,
                    ctime REAL,
                    first_seen REAL,
                    last_updated REAL
                )
            """)
            self.conn.commit()

    def record_file(self, filepath: str) -> Optional[Dict]:
        """Record or update a file's current state."""
        try:
            stat = os.stat(filepath)
            sha = self._hash_file(filepath)
            now = time.time()

            with self.lock:
                existing = self.conn.execute(
                    "SELECT first_seen FROM file_states WHERE filepath = ?",
                    (filepath,)
                ).fetchone()

                first_seen = existing[0] if existing else now

                self.conn.execute("""
                    INSERT OR REPLACE INTO file_states
                    (filepath, sha256, size, mtime, atime, ctime, first_seen, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (filepath, sha, stat.st_size, stat.st_mtime,
                      stat.st_atime, stat.st_ctime, first_seen, now))
                self.conn.commit()

            return {
                "sha256": sha,
                "size": stat.st_size,
                "mtime": stat.st_mtime,
                "ctime": stat.st_ctime,
                "first_seen": first_seen,
            }
        except (OSError, IOError) as e:
            logger.debug(f"Cannot record file {filepath}: {e}")
            return None

    def get_file_state(self, filepath: str) -> Optional[Dict]:
        """Retrieve the last known state of a file."""
        with self.lock:
            row = self.conn.execute(
                "SELECT sha256, size, mtime, atime, ctime, first_seen FROM file_states WHERE filepath = ?",
                (filepath,)
            ).fetchone()
        if row:
            return {
                "sha256": row[0], "size": row[1], "mtime": row[2],
                "atime": row[3], "ctime": row[4], "first_seen": row[5],
            }
        return None

    def remove_file(self, filepath: str):
        """Remove a file from the baseline."""
        with self.lock:
            self.conn.execute("DELETE FROM file_states WHERE filepath = ?", (filepath,))
            self.conn.commit()

    @staticmethod
    def _hash_file(filepath: str, block_size: int = 65536) -> Optional[str]:
        """Calculate SHA-256 hash of a file."""
        sha = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                while True:
                    data = f.read(block_size)
                    if not data:
                        break
                    sha.update(data)
            return sha.hexdigest()
        except (OSError, IOError):
            return None

    def close(self):
        self.conn.close()


class RealtimeFileHandler(FileSystemEventHandler):
    """Handles inotify filesystem events in real-time."""

    def __init__(self, baseline: FileBaseline, alert_callback: Callable,
                 canary_registry: Optional[Dict] = None,
                 ignore_patterns: Optional[list] = None,
                 suspicious_extensions: Optional[list] = None):
        super().__init__()
        self.baseline = baseline
        self.alert_callback = alert_callback
        self.canary_registry = canary_registry or {}
        self.ignore_patterns = ignore_patterns or ["__pycache__", "*.pyc", "*.swp", "*.tmp"]
        self.suspicious_extensions = suspicious_extensions or [".exe", ".bat", ".ps1", ".sh"]

    def _is_noise(self, path: str) -> bool:
        """Filter out noisy/irrelevant events."""
        for pattern in self.ignore_patterns:
            if pattern in path or path.endswith(pattern.lstrip("*")):
                return True
        return False

    def _make_alert(self, event_type: str, path: str, severity: str = "INFO",
                    details: Optional[Dict] = None) -> Dict:
        """Construct a standardized alert dict."""
        alert = {
            "module": "realtime_monitor",
            "event_type": event_type,
            "path": path,
            "detection_wall_time": time.time(),
            "detection_perf_time": time.perf_counter(),
            "severity": severity,
            "details": details or {},
        }
        self.alert_callback(alert)
        return alert

    def on_created(self, event):
        if event.is_directory or self._is_noise(event.src_path):
            return

        state = self.baseline.record_file(event.src_path)

        severity = "INFO"
        extra_details = {}

        # Check suspicious extensions
        _, ext = os.path.splitext(event.src_path)
        if ext in self.suspicious_extensions:
            severity = "WARNING"
            extra_details["reason"] = "Suspicious executable created"

        # Canary check
        if event.src_path in self.canary_registry:
            severity = "CRITICAL"
            extra_details["reason"] = "CANARY FILE RECREATED — possible attacker activity"

        if state:
            extra_details["sha256"] = state["sha256"]
            extra_details["size"] = state["size"]

        self._make_alert("FILE_CREATED", event.src_path, severity, extra_details)

    def on_deleted(self, event):
        if event.is_directory or self._is_noise(event.src_path):
            return

        last_state = self.baseline.get_file_state(event.src_path)
        self.baseline.remove_file(event.src_path)

        severity = "WARNING"
        extra_details = {}

        if last_state:
            lifespan = time.time() - last_state["first_seen"]
            extra_details["file_lifespan_seconds"] = round(lifespan, 4)

            if lifespan < 5.0:
                severity = "CRITICAL"
                extra_details["reason"] = (
                    f"Ephemeral file — created and deleted within {lifespan:.3f}s. "
                    "Indicates automated cleanup or anti-forensic wiping."
                )

        # Canary check
        if event.src_path in self.canary_registry:
            severity = "CRITICAL"
            extra_details["reason"] = "CANARY FILE DELETED — active intrusion detected!"

        self._make_alert("FILE_DELETED", event.src_path, severity, extra_details)

    def on_modified(self, event):
        if event.is_directory or self._is_noise(event.src_path):
            return

        old_state = self.baseline.get_file_state(event.src_path)
        new_state = self.baseline.record_file(event.src_path)

        severity = "INFO"
        extra_details = {}

        if old_state and new_state:
            if old_state["sha256"] != new_state["sha256"]:
                severity = "WARNING"
                extra_details["reason"] = "File content changed"
                extra_details["old_sha256"] = old_state["sha256"]
                extra_details["new_sha256"] = new_state["sha256"]

            # Detect overwrite pattern (wiper signature)
            if old_state["size"] == new_state["size"] and old_state["sha256"] != new_state["sha256"]:
                severity = "CRITICAL"
                extra_details["reason"] = (
                    "Same-size content replacement detected — "
                    "signature of secure overwrite/wiping tool"
                )

        # Canary check
        if event.src_path in self.canary_registry:
            severity = "CRITICAL"
            extra_details["reason"] = "CANARY FILE MODIFIED — active intrusion detected!"

        self._make_alert("FILE_MODIFIED", event.src_path, severity, extra_details)

    def on_moved(self, event):
        if event.is_directory or self._is_noise(event.src_path):
            return

        self.baseline.remove_file(event.src_path)
        self.baseline.record_file(event.dest_path)

        severity = "WARNING"
        extra_details = {
            "dest_path": event.dest_path,
            "reason": f"File renamed: {os.path.basename(event.src_path)} → {os.path.basename(event.dest_path)}",
        }

        # Check for obfuscation rename (random name = wiper behavior)
        dest_name = os.path.basename(event.dest_path)
        if len(dest_name) >= 8 and not os.path.splitext(dest_name)[1]:
            severity = "CRITICAL"
            extra_details["reason"] = (
                f"File renamed to random string ({os.path.basename(event.src_path)} → {dest_name}). "
                "Signature of anti-forensic secure wiper."
            )

        # Canary moved
        if event.src_path in self.canary_registry:
            severity = "CRITICAL"
            extra_details["reason"] = "CANARY FILE MOVED — active intrusion detected!"

        self._make_alert("FILE_MOVED", event.src_path, severity, extra_details)


class RealtimeMonitor:
    """
    Main monitor class. Wraps watchdog Observer with baseline tracking.
    """

    def __init__(self, watch_paths, alert_callback, canary_registry=None,
                 db_path="baseline.db", ignore_patterns=None,
                 suspicious_extensions=None):
        self.watch_paths = watch_paths if isinstance(watch_paths, list) else [watch_paths]
        self.baseline = FileBaseline(db_path)
        self.handler = RealtimeFileHandler(
            self.baseline, alert_callback, canary_registry,
            ignore_patterns, suspicious_extensions,
        )
        self.observer = Observer()
        self.observer.daemon = True
        self._running = False

    def start(self):
        """Start real-time monitoring on all configured paths."""
        for path in self.watch_paths:
            if os.path.exists(path):
                self.observer.schedule(self.handler, path, recursive=True)
                logger.info(f"Watching: {path}")
            else:
                logger.warning(f"Path does not exist, skipping: {path}")

        self.observer.start()
        self._running = True

    def stop(self):
        """Stop all monitoring."""
        if self._running:
            self._running = False
            self.observer.unschedule_all()
            self.observer.stop()
            # Force-close inotify fd to unblock kernel read()
            try:
                for emitter in list(self.observer.emitters):
                    if hasattr(emitter, '_inotify') and hasattr(emitter._inotify, '_inotify_fd'):
                        try:
                            os.close(emitter._inotify._inotify_fd)
                        except OSError as exc:
                            logger.debug("Ignoring inotify close error: %s", exc)
            except Exception as exc:
                logger.debug("Ignoring observer shutdown error: %s", exc)
            self.observer.join(timeout=3)
            try:
                self.baseline.close()
            except Exception as exc:
                logger.debug("Ignoring baseline close error: %s", exc)

    def scan_baseline(self):
        """Perform an initial baseline scan of all watched directories."""
        count = 0
        for path in self.watch_paths:
            if not os.path.exists(path):
                continue
            for root, dirs, files in os.walk(path):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    self.baseline.record_file(filepath)
                    count += 1
        logger.info(f"Baseline recorded: {count} files")
        return count
