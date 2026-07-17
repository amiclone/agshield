"""
AntiGravity Shield — Process Attribution Tracker
==================================================
Enriches kernel file system events with full process context:
PID, process name, command line, parent process, and SSH session detection.

This module answers the critical question: "WHO is modifying these files?"
which the original watchdog-based monitor could not answer.
"""

import os
import sys
import time
import logging
import threading
from typing import Dict, List, Optional, Tuple

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

logger = logging.getLogger("antigravity.monitor.process_tracker")

IS_WINDOWS = sys.platform == "win32"


class ProcessInfo:
    """Cached process information."""

    __slots__ = (
        "pid", "name", "cmdline", "ppid", "parent_name",
        "user", "ssh_originated", "timestamp",
    )

    def __init__(self, pid: int):
        self.pid = pid
        self.name = "unknown"
        self.cmdline = ""
        self.ppid = 0
        self.parent_name = ""
        self.user = ""
        self.ssh_originated = False
        self.timestamp = time.time()

    def to_dict(self) -> Dict:
        return {
            "pid": self.pid,
            "process_name": self.name,
            "cmdline": self.cmdline,
            "ppid": self.ppid,
            "parent_process": self.parent_name,
            "user": self.user,
            "ssh_originated": self.ssh_originated,
        }


class ProcessTracker:
    """
    Tracks and enriches process information for file system events.

    Uses /proc filesystem on Linux for zero-overhead process resolution.
    Maintains a short-lived cache to avoid repeated /proc lookups for
    the same PID during burst events.
    """

    # Process names that indicate an SSH session origin
    SSH_INDICATORS = {"sshd", "sshd.exe", "ssh", "dropbear"}

    # Process names that are suspicious in security context
    SUSPICIOUS_PROCESSES = {
        "python", "python3", "python.exe", "python3.exe",
        "python3.12", "python3.11", "python3.10",
        "perl", "perl.exe", "ruby", "ruby.exe",
        "node", "node.exe", "bash", "bash.exe", "sh",
        "zsh", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
        "cmd.exe", "wscript", "wscript.exe",
        "cscript", "cscript.exe", "mshta", "mshta.exe",
    }

    def __init__(self, cache_ttl: float = 5.0):
        """
        Args:
            cache_ttl: How long to cache process info (seconds).
        """
        self.cache_ttl = cache_ttl
        self._cache: Dict[int, ProcessInfo] = {}
        self._lock = threading.Lock()

    def get_process_info(self, pid: int) -> ProcessInfo:
        """
        Get process information for a PID.
        Results are cached for cache_ttl seconds.
        """
        with self._lock:
            cached = self._cache.get(pid)
            if cached and (time.time() - cached.timestamp) < self.cache_ttl:
                return cached

        info = self._resolve_process(pid)

        with self._lock:
            self._cache[pid] = info
            # Prune old entries
            cutoff = time.time() - self.cache_ttl * 3
            expired = [
                k for k, v in self._cache.items()
                if v.timestamp < cutoff
            ]
            for k in expired:
                del self._cache[k]

        return info

    def _resolve_process(self, pid: int) -> ProcessInfo:
        """Resolve process details cross-platform."""
        info = ProcessInfo(pid)

        if IS_WINDOWS or not os.path.exists(f"/proc/{pid}"):
            # Windows or /proc unavailable — use psutil
            return self._resolve_via_psutil(info)

        # Linux — use /proc for zero-overhead resolution
        try:
            with open(f"/proc/{pid}/comm", "r") as f:
                info.name = f.read().strip()
        except (OSError, IOError):
            pass

        try:
            with open(f"/proc/{pid}/cmdline", "r") as f:
                info.cmdline = f.read().replace("\x00", " ").strip()
        except (OSError, IOError):
            pass

        try:
            with open(f"/proc/{pid}/status", "r") as f:
                for line in f:
                    if line.startswith("Uid:"):
                        uid = int(line.split()[1])
                        info.user = self._uid_to_name(uid)
                    elif line.startswith("PPid:"):
                        info.ppid = int(line.split()[1])
        except (OSError, IOError, ValueError, IndexError):
            pass

        if info.ppid > 0:
            try:
                with open(f"/proc/{info.ppid}/comm", "r") as f:
                    info.parent_name = f.read().strip()
            except (OSError, IOError):
                pass

        info.ssh_originated = self._check_ssh_ancestry(pid)
        return info

    def _resolve_via_psutil(self, info: ProcessInfo) -> ProcessInfo:
        """Resolve process details using psutil (cross-platform)."""
        if not HAS_PSUTIL:
            return info
        try:
            proc = psutil.Process(info.pid)
            info.name = proc.name()
            try:
                info.cmdline = " ".join(proc.cmdline())
            except (psutil.AccessDenied, psutil.ZombieProcess):
                info.cmdline = ""
            try:
                info.user = proc.username()
            except (psutil.AccessDenied, psutil.ZombieProcess):
                info.user = ""
            info.ppid = proc.ppid()
            if info.ppid > 0:
                try:
                    parent = psutil.Process(info.ppid)
                    info.parent_name = parent.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            info.ssh_originated = self._check_ssh_ancestry(info.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return info

    def _check_ssh_ancestry(self, pid: int, max_depth: int = 8) -> bool:
        """Check if a process has an SSH daemon in its ancestry (cross-platform)."""
        if IS_WINDOWS or not os.path.exists("/proc"):
            return self._check_ssh_ancestry_psutil(pid, max_depth)

        # Linux fast path via /proc
        current_pid = pid
        for _ in range(max_depth):
            if current_pid <= 1:
                return False
            try:
                with open(f"/proc/{current_pid}/comm", "r") as f:
                    name = f.read().strip()
                if name in self.SSH_INDICATORS:
                    return True
                with open(f"/proc/{current_pid}/status", "r") as f:
                    for line in f:
                        if line.startswith("PPid:"):
                            current_pid = int(line.split()[1])
                            break
                    else:
                        return False
            except (OSError, IOError, ValueError):
                return False
        return False

    def _check_ssh_ancestry_psutil(self, pid: int, max_depth: int = 8) -> bool:
        """Check SSH ancestry using psutil (works on Windows)."""
        if not HAS_PSUTIL:
            return False
        current_pid = pid
        for _ in range(max_depth):
            if current_pid <= 1 or current_pid == 0:
                return False
            try:
                proc = psutil.Process(current_pid)
                name = proc.name().lower()
                if name in self.SSH_INDICATORS:
                    return True
                current_pid = proc.ppid()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return False
        return False

    def is_suspicious_process(self, info: ProcessInfo) -> Tuple[bool, str]:
        """
        Determine if a process is suspicious based on its attributes.

        Returns:
            (is_suspicious, reason)
        """
        reasons = []

        # Scripting interpreter running file operations
        if info.name in self.SUSPICIOUS_PROCESSES:
            reasons.append(
                f"Process '{info.name}' is a scripting interpreter "
                f"performing file system operations"
            )

        # SSH-originated file modification
        if info.ssh_originated:
            reasons.append(
                f"File operation originated from SSH session "
                f"(ancestor: sshd)"
            )

        # Agent-like command line patterns
        if info.cmdline:
            agent_indicators = [
                "agent_controller", "data_wiper", "log_cleaner",
                "timestomper", "cleanup", "wipe", "stomp",
                "anti_forensic", "antiforensic",
            ]
            cmdline_lower = info.cmdline.lower()
            for indicator in agent_indicators:
                if indicator in cmdline_lower:
                    reasons.append(
                        f"Command line contains anti-forensic indicator: "
                        f"'{indicator}'"
                    )
                    break

        return (len(reasons) > 0, "; ".join(reasons))

    def enrich_alert(self, alert: Dict, pid: int) -> Dict:
        """Add process attribution to an existing alert dict."""
        info = self.get_process_info(pid)
        alert.setdefault("details", {})
        alert["details"]["process"] = info.to_dict()

        is_suspicious, reason = self.is_suspicious_process(info)
        if is_suspicious:
            alert["details"]["process_suspicious"] = True
            alert["details"]["process_suspicion_reason"] = reason
            # Escalate severity
            if alert.get("severity") == "INFO":
                alert["severity"] = "WARNING"
            elif alert.get("severity") == "WARNING" and info.ssh_originated:
                alert["severity"] = "CRITICAL"

        return alert

    @staticmethod
    def _uid_to_name(uid: int) -> str:
        """Convert UID to username."""
        try:
            import pwd
            return pwd.getpwuid(uid).pw_name
        except (ImportError, KeyError):
            return str(uid)

    def get_stats(self) -> Dict:
        """Return tracker statistics."""
        with self._lock:
            return {
                "cached_processes": len(self._cache),
                "cache_ttl": self.cache_ttl,
            }
