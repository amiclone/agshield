"""
AntiGravity Shield — Module 1: Real-Time File Monitor
=====================================================
Replaces polling-based FIM (Wazuh) with kernel-event-driven monitoring
using Linux inotify via the watchdog library.

Counters: TOCTOU "Time Gap" vulnerability
"""

import os
import time
import hashlib
import json
import sqlite3
import threading
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class FileBaseline:
    """
    SQLite-backed file state database.
    Stores known-good file hashes, timestamps, and metadata
    for comparison when events occur.
    """

    def __init__(self, db_path="reports/baseline.db"):
        self.db_path = db_path
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

    def record_file(self, filepath):
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
        except (OSError, IOError):
            return None

    def get_file_state(self, filepath):
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

    def remove_file(self, filepath):
        """Remove a file from the baseline (it was deleted)."""
        with self.lock:
            self.conn.execute("DELETE FROM file_states WHERE filepath = ?", (filepath,))
            self.conn.commit()

    @staticmethod
    def _hash_file(filepath, block_size=65536):
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
    """
    Handles inotify filesystem events in real-time.
    Every event is timestamped and dispatched to the alert callback.
    """

    def __init__(self, baseline, alert_callback, canary_registry=None):
        super().__init__()
        self.baseline = baseline
        self.alert_callback = alert_callback
        self.canary_registry = canary_registry or {}

    def _is_noise(self, path):
        """Filter out Python bytecache and other noisy events."""
        return "__pycache__" in path or path.endswith(".pyc")

    def on_created(self, event):
        if event.is_directory or self._is_noise(event.src_path):
            return
        detection_time = time.perf_counter()
        wall_time = time.time()

        # Record new file in baseline
        state = self.baseline.record_file(event.src_path)

        alert = {
            "module": "realtime_monitor",
            "event_type": "FILE_CREATED",
            "path": event.src_path,
            "detection_wall_time": wall_time,
            "detection_perf_time": detection_time,
            "severity": "INFO",
            "details": {},
        }

        # Check if it's a suspicious file type
        if event.src_path.endswith((".exe", ".bat", ".ps1", ".sh")):
            alert["severity"] = "WARNING"
            alert["details"]["reason"] = "Suspicious executable created"

        if state:
            alert["details"]["sha256"] = state["sha256"]
            alert["details"]["size"] = state["size"]

        # Canary check
        if event.src_path in self.canary_registry:
            alert["severity"] = "CRITICAL"
            alert["details"]["reason"] = "CANARY FILE RECREATED — possible attacker activity"

        self.alert_callback(alert)

    def on_deleted(self, event):
        if event.is_directory or self._is_noise(event.src_path):
            return
        detection_time = time.perf_counter()
        wall_time = time.time()

        # Get last known state before we remove it
        last_state = self.baseline.get_file_state(event.src_path)
        self.baseline.remove_file(event.src_path)

        alert = {
            "module": "realtime_monitor",
            "event_type": "FILE_DELETED",
            "path": event.src_path,
            "detection_wall_time": wall_time,
            "detection_perf_time": detection_time,
            "severity": "WARNING",
            "details": {},
        }

        if last_state:
            # How long did the file exist?
            lifespan = wall_time - last_state["first_seen"]
            alert["details"]["file_lifespan_seconds"] = round(lifespan, 4)

            if lifespan < 5.0:
                alert["severity"] = "CRITICAL"
                alert["details"]["reason"] = (
                    f"Ephemeral file — created and deleted within {lifespan:.3f}s. "
                    "Indicates automated cleanup or anti-forensic wiping."
                )

        # Canary check
        if event.src_path in self.canary_registry:
            alert["severity"] = "CRITICAL"
            alert["details"]["reason"] = "CANARY FILE DELETED — active intrusion detected!"

        self.alert_callback(alert)

    def on_modified(self, event):
        if event.is_directory or self._is_noise(event.src_path):
            return
        detection_time = time.perf_counter()
        wall_time = time.time()

        old_state = self.baseline.get_file_state(event.src_path)
        new_state = self.baseline.record_file(event.src_path)

        alert = {
            "module": "realtime_monitor",
            "event_type": "FILE_MODIFIED",
            "path": event.src_path,
            "detection_wall_time": wall_time,
            "detection_perf_time": detection_time,
            "severity": "INFO",
            "details": {},
        }

        if old_state and new_state:
            if old_state["sha256"] != new_state["sha256"]:
                alert["severity"] = "WARNING"
                alert["details"]["reason"] = "File content changed"
                alert["details"]["old_sha256"] = old_state["sha256"]
                alert["details"]["new_sha256"] = new_state["sha256"]

            # Detect overwrite pattern (wiper signature)
            if old_state["size"] == new_state["size"] and old_state["sha256"] != new_state["sha256"]:
                alert["severity"] = "CRITICAL"
                alert["details"]["reason"] = (
                    "Same-size content replacement detected — "
                    "signature of secure overwrite/wiping tool"
                )

        # Canary check
        if event.src_path in self.canary_registry:
            alert["severity"] = "CRITICAL"
            alert["details"]["reason"] = "CANARY FILE MODIFIED — active intrusion detected!"

        self.alert_callback(alert)

    def on_moved(self, event):
        if event.is_directory or self._is_noise(event.src_path):
            return
        detection_time = time.perf_counter()
        wall_time = time.time()

        # Update baseline: remove old path, record new path
        self.baseline.remove_file(event.src_path)
        self.baseline.record_file(event.dest_path)

        alert = {
            "module": "realtime_monitor",
            "event_type": "FILE_MOVED",
            "path": event.src_path,
            "dest_path": event.dest_path,
            "detection_wall_time": wall_time,
            "detection_perf_time": detection_time,
            "severity": "WARNING",
            "details": {
                "reason": f"File renamed: {os.path.basename(event.src_path)} → {os.path.basename(event.dest_path)}",
            },
        }

        # Check for obfuscation rename (random name = wiper behavior)
        src_name = os.path.basename(event.src_path)
        dest_name = os.path.basename(event.dest_path)
        if len(dest_name) >= 8 and not os.path.splitext(dest_name)[1]:
            alert["severity"] = "CRITICAL"
            alert["details"]["reason"] = (
                f"File renamed to random string ({src_name} → {dest_name}). "
                "Signature of anti-forensic secure wiper."
            )

        # Canary moved
        if event.src_path in self.canary_registry:
            alert["severity"] = "CRITICAL"
            alert["details"]["reason"] = "CANARY FILE MOVED — active intrusion detected!"

        self.alert_callback(alert)


class RealtimeMonitor:
    """
    Main monitor class. Wraps watchdog Observer with baseline tracking.
    """

    def __init__(self, watch_paths, alert_callback, canary_registry=None, db_path="reports/baseline.db"):
        self.watch_paths = watch_paths if isinstance(watch_paths, list) else [watch_paths]
        self.baseline = FileBaseline(db_path)
        self.handler = RealtimeFileHandler(self.baseline, alert_callback, canary_registry)
        self.observer = Observer()
        self.observer.daemon = True  # Ensure observer thread won't block exit
        self._running = False

    def start(self):
        """Start real-time monitoring on all configured paths."""
        for path in self.watch_paths:
            if os.path.exists(path):
                self.observer.schedule(self.handler, path, recursive=True)
                print(f"  [SHIELD] 👁  Watching: {path}")
            else:
                print(f"  [SHIELD] ⚠  Path does not exist, skipping: {path}")

        self.observer.start()
        self._running = True

    def stop(self):
        """Stop all monitoring."""
        if self._running:
            self._running = False
            self.observer.unschedule_all()
            self.observer.stop()
            # Force-close the inotify file descriptor to unblock the kernel read()
            # This is necessary because observer.stop() only sets a flag,
            # but the inotify reader thread is blocked on os.read(fd, ...)
            try:
                for emitter in list(self.observer.emitters):
                    if hasattr(emitter, '_inotify') and hasattr(emitter._inotify, '_inotify_fd'):
                        import os as _os
                        try:
                            _os.close(emitter._inotify._inotify_fd)
                        except OSError:
                            pass
            except Exception:
                pass
            self.observer.join(timeout=3)
            try:
                self.baseline.close()
            except Exception:
                pass

    def scan_baseline(self):
        """
        Perform an initial baseline scan of all watched directories.
        Records the current state of every existing file.
        """
        count = 0
        for path in self.watch_paths:
            if not os.path.exists(path):
                continue
            for root, dirs, files in os.walk(path):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    self.baseline.record_file(filepath)
                    count += 1
        print(f"  [SHIELD] 📋 Baseline recorded: {count} files")
        return count


if __name__ == "__main__":
    import sys

    def print_alert(alert):
        severity = alert["severity"]
        icon = {"INFO": "ℹ️ ", "WARNING": "⚠️ ", "CRITICAL": "🚨"}
        ts = datetime.fromtimestamp(alert["detection_wall_time"]).strftime("%H:%M:%S.%f")[:-3]
        print(f"  {icon.get(severity, '  ')} [{ts}] [{severity}] {alert['event_type']}: {alert['path']}")
        if alert.get("details", {}).get("reason"):
            print(f"       ↳ {alert['details']['reason']}")

    watch_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"[SHIELD] Starting Real-Time Monitor on: {watch_dir}")

    monitor = RealtimeMonitor(watch_dir, print_alert)
    monitor.scan_baseline()
    monitor.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()
        print("\n[SHIELD] Monitor stopped.")
