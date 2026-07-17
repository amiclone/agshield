"""
AntiGravity Shield — Kernel-Level File System Monitor
======================================================
True kernel-level monitoring using Linux fanotify(7) via ctypes.
Provides sub-millisecond event detection with process attribution (PID).

This replaces the user-space watchdog-based monitor as the primary
event source, closing the TOCTOU Time Gap identified in the dissertation.

Fallback: If fanotify is unavailable (non-root, container, or Windows),
gracefully falls back to the existing watchdog-based RealtimeMonitor.

References:
    - fanotify(7) man page
    - Linux kernel 2.6.37+ (FAN_MARK_FILESYSTEM requires 4.20+)
    - MITRE ATT&CK T1070 — Indicator Removal
"""

import os
import sys
import struct
import time
import ctypes
import ctypes.util
import threading
import logging
import errno
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("antigravity.monitor.kernel")

# ─── Linux fanotify constants (from <linux/fanotify.h>) ───
FAN_ACCESS = 0x00000001
FAN_MODIFY = 0x00000002
FAN_ATTRIB = 0x00000004          # Attribute change — catches timestomping!
FAN_CLOSE_WRITE = 0x00000008
FAN_CLOSE_NOWRITE = 0x00000010
FAN_OPEN = 0x00000020
FAN_MOVED_FROM = 0x00000040
FAN_MOVED_TO = 0x00000080
FAN_CREATE = 0x00000100
FAN_DELETE = 0x00000200
FAN_DELETE_SELF = 0x00000400
FAN_MOVE_SELF = 0x00000800
FAN_ONDIR = 0x40000000
FAN_EVENT_ON_CHILD = 0x08000000

# fanotify_init flags
FAN_CLOEXEC = 0x00000001
FAN_NONBLOCK = 0x00000002
FAN_CLASS_NOTIF = 0x00000000
FAN_CLASS_CONTENT = 0x00000004
FAN_CLASS_PRE_CONTENT = 0x00000008
FAN_UNLIMITED_QUEUE = 0x00000010
FAN_UNLIMITED_MARKS = 0x00000020
FAN_REPORT_FID = 0x00000200
FAN_REPORT_DIR_FID = 0x00000400
FAN_REPORT_NAME = 0x00000800
FAN_REPORT_DFID_NAME = FAN_REPORT_DIR_FID | FAN_REPORT_NAME

# fanotify_mark flags
FAN_MARK_ADD = 0x00000001
FAN_MARK_REMOVE = 0x00000002
FAN_MARK_FILESYSTEM = 0x00000100

# fanotify event metadata structure size
FANOTIFY_METADATA_SIZE = 24  # sizeof(struct fanotify_event_metadata)

# Event mask for anti-forensic detection
ANTI_FORENSIC_EVENTS = (
    FAN_CREATE | FAN_DELETE | FAN_MODIFY |
    FAN_MOVED_FROM | FAN_MOVED_TO | FAN_ATTRIB |
    FAN_CLOSE_WRITE | FAN_ONDIR | FAN_EVENT_ON_CHILD
)

# Map fanotify masks to human-readable event types
EVENT_TYPE_MAP = {
    FAN_CREATE: "FILE_CREATED",
    FAN_DELETE: "FILE_DELETED",
    FAN_MODIFY: "FILE_MODIFIED",
    FAN_ATTRIB: "FILE_ATTRIB_CHANGED",
    FAN_MOVED_FROM: "FILE_MOVED_FROM",
    FAN_MOVED_TO: "FILE_MOVED_TO",
    FAN_CLOSE_WRITE: "FILE_CLOSE_WRITE",
}


def _fanotify_available() -> bool:
    """Check if fanotify is available on this system."""
    if sys.platform != "linux":
        return False
    # Check for root/CAP_SYS_ADMIN
    try:
        if os.geteuid() != 0:
            logger.debug("fanotify requires root privileges")
            return False
    except AttributeError:
        return False
    # Check kernel support
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        fd = libc.syscall(300, FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_NONBLOCK, 0)
        if fd < 0:
            return False
        os.close(fd)
        return True
    except Exception:
        return False


class KernelEvent:
    """Represents a single kernel-level file system event."""

    __slots__ = ("event_type", "path", "pid", "timestamp", "perf_time", "mask")

    def __init__(self, event_type: str, path: str, pid: int,
                 timestamp: float, perf_time: float, mask: int):
        self.event_type = event_type
        self.path = path
        self.pid = pid
        self.timestamp = timestamp
        self.perf_time = perf_time
        self.mask = mask

    def to_alert(self, severity: str = "INFO",
                 details: Optional[Dict] = None) -> Dict:
        """Convert to a standard shield alert dict."""
        alert = {
            "module": "kernel_monitor",
            "event_type": self.event_type,
            "path": self.path,
            "pid": self.pid,
            "detection_wall_time": self.timestamp,
            "detection_perf_time": self.perf_time,
            "severity": severity,
            "details": details or {},
        }
        return alert


class FanotifyMonitor:
    """
    Linux fanotify-based kernel monitor.

    Uses fanotify(7) system calls via ctypes for direct kernel event
    delivery with process attribution (PID). This is the same API
    used by enterprise EDR products and ClamAV.
    """

    def __init__(self, watch_paths: List[str],
                 alert_callback: Optional[Callable] = None,
                 canary_registry: Optional[Dict] = None,
                 ignore_patterns: Optional[List[str]] = None,
                 suspicious_extensions: Optional[List[str]] = None):
        self.watch_paths = watch_paths
        self.alert_callback = alert_callback
        self.canary_registry = canary_registry or {}
        self.ignore_patterns = ignore_patterns or [
            "__pycache__", "*.pyc", "*.swp", "*.tmp", ".git"
        ]
        self.suspicious_extensions = suspicious_extensions or [
            ".exe", ".bat", ".ps1", ".sh", ".dll", ".so"
        ]
        self._fan_fd = -1
        self._running = False
        self._thread = None
        self._libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        self._event_count = 0

    def start(self) -> bool:
        """Initialize fanotify and start monitoring."""
        # fanotify_init(flags, event_f_flags)
        # syscall 300 = fanotify_init on x86_64
        self._fan_fd = self._libc.syscall(
            300,
            FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_NONBLOCK,
            os.O_RDONLY | os.O_LARGEFILE
        )

        if self._fan_fd < 0:
            err = ctypes.get_errno()
            logger.error(f"fanotify_init failed: errno={err} ({os.strerror(err)})")
            return False

        logger.info(f"fanotify initialized (fd={self._fan_fd})")

        # Mark directories for monitoring
        # syscall 301 = fanotify_mark on x86_64
        for path in self.watch_paths:
            if not os.path.exists(path):
                logger.warning(f"Path does not exist, skipping: {path}")
                continue

            dirfd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            result = self._libc.syscall(
                301,  # fanotify_mark
                self._fan_fd,
                FAN_MARK_ADD,
                ANTI_FORENSIC_EVENTS,
                dirfd,
                None  # NULL path = use dirfd
            )

            if result < 0:
                err = ctypes.get_errno()
                logger.warning(
                    f"fanotify_mark failed for {path}: "
                    f"errno={err} ({os.strerror(err)})"
                )
                # Try without FAN_ATTRIB (older kernels)
                result = self._libc.syscall(
                    301, self._fan_fd, FAN_MARK_ADD,
                    ANTI_FORENSIC_EVENTS & ~FAN_ATTRIB,
                    dirfd, None
                )
                if result < 0:
                    logger.error(f"fanotify_mark retry failed for {path}")
                else:
                    logger.info(f"Watching (no ATTRIB): {path}")
            else:
                logger.info(f"Watching (kernel): {path}")

            os.close(dirfd)

        # Start reader thread
        self._running = True
        self._thread = threading.Thread(
            target=self._read_events, name="fanotify-reader", daemon=True
        )
        self._thread.start()
        return True

    def _read_events(self) -> None:
        """Read and dispatch fanotify events from the kernel."""
        buf_size = 4096
        buf = ctypes.create_string_buffer(buf_size)

        while self._running:
            try:
                nbytes = os.read(self._fan_fd, buf_size)
            except BlockingIOError:
                time.sleep(0.001)  # 1ms poll for non-blocking
                continue
            except OSError as e:
                if e.errno == errno.EAGAIN:
                    time.sleep(0.001)
                    continue
                if not self._running:
                    break
                logger.error(f"fanotify read error: {e}")
                break

            if not nbytes:
                time.sleep(0.001)
                continue

            self._parse_events(nbytes)

    def _parse_events(self, data: bytes) -> None:
        """Parse raw fanotify event metadata from kernel buffer."""
        offset = 0
        now = time.time()
        perf_now = time.perf_counter()

        while offset + FANOTIFY_METADATA_SIZE <= len(data):
            # struct fanotify_event_metadata {
            #   __u32 event_len;
            #   __u8  vers;
            #   __u8  reserved;
            #   __u16 metadata_len;
            #   __aligned_u64 mask;
            #   __s32 fd;
            #   __s32 pid;
            # }
            event_len, vers, reserved, meta_len, mask, fd, pid = struct.unpack_from(
                "=IBBHQII", data, offset
            )

            if event_len < FANOTIFY_METADATA_SIZE:
                break

            # Resolve file path from fd
            filepath = ""
            if fd >= 0:
                try:
                    filepath = os.readlink(f"/proc/self/fd/{fd}")
                except OSError:
                    filepath = f"<fd:{fd}>"
                finally:
                    try:
                        os.close(fd)
                    except OSError:
                        pass

            # Skip noise
            if not self._is_noise(filepath):
                self._dispatch_event(mask, filepath, pid, now, perf_now)

            offset += event_len

    def _is_noise(self, path: str) -> bool:
        """Filter out noisy/irrelevant events."""
        if not path:
            return True
        for pattern in self.ignore_patterns:
            if pattern.startswith("*"):
                if path.endswith(pattern.lstrip("*")):
                    return True
            elif pattern in path:
                return True
        return False

    def _dispatch_event(self, mask: int, filepath: str, pid: int,
                        timestamp: float, perf_time: float) -> None:
        """Convert kernel event to alert and dispatch."""
        self._event_count += 1

        # Map mask to event type(s)
        for flag, event_type in EVENT_TYPE_MAP.items():
            if mask & flag:
                event = KernelEvent(
                    event_type=event_type,
                    path=filepath,
                    pid=pid,
                    timestamp=timestamp,
                    perf_time=perf_time,
                    mask=mask,
                )
                self._process_event(event)

    def _process_event(self, event: KernelEvent) -> None:
        """Process a kernel event and fire alerts."""
        severity = "INFO"
        details: Dict = {"pid": event.pid, "source": "kernel_fanotify"}

        # Resolve process name
        try:
            with open(f"/proc/{event.pid}/comm", "r") as f:
                details["process_name"] = f.read().strip()
        except (OSError, IOError):
            details["process_name"] = "unknown"

        # Resolve process cmdline
        try:
            with open(f"/proc/{event.pid}/cmdline", "r") as f:
                cmdline = f.read().replace("\x00", " ").strip()
                if cmdline:
                    details["process_cmdline"] = cmdline
        except (OSError, IOError):
            pass

        # Check for SSH-originated activity
        try:
            with open(f"/proc/{event.pid}/status", "r") as f:
                for line in f:
                    if line.startswith("PPid:"):
                        ppid = int(line.split(":")[1].strip())
                        details["parent_pid"] = ppid
                        try:
                            with open(f"/proc/{ppid}/comm", "r") as pf:
                                parent_name = pf.read().strip()
                                details["parent_process"] = parent_name
                                if parent_name in ("sshd", "ssh"):
                                    details["ssh_originated"] = True
                                    severity = "WARNING"
                        except (OSError, IOError):
                            pass
                        break
        except (OSError, IOError):
            pass

        # Attribute change = potential timestomping
        if event.event_type == "FILE_ATTRIB_CHANGED":
            severity = "WARNING"
            details["reason"] = (
                "File attributes/timestamps changed — potential timestomping. "
                "This event is only visible via kernel-level monitoring."
            )
            details["technique"] = "T1070.006 - Timestomp (MITRE ATT&CK)"

        # Suspicious extensions
        _, ext = os.path.splitext(event.path)
        if ext in self.suspicious_extensions:
            if severity == "INFO":
                severity = "WARNING"
            details["reason"] = details.get("reason", "") + (
                f" Suspicious extension: {ext}"
            )

        # Canary check
        if event.path in self.canary_registry:
            severity = "CRITICAL"
            details["reason"] = (
                f"CANARY FILE {event.event_type.split('_', 1)[1]} "
                f"by PID {event.pid} ({details.get('process_name', '?')}) — "
                f"active intrusion detected!"
            )

        alert = event.to_alert(severity=severity, details=details)

        if self.alert_callback:
            self.alert_callback(alert)

    def stop(self) -> None:
        """Stop the fanotify monitor."""
        self._running = False
        if self._fan_fd >= 0:
            try:
                os.close(self._fan_fd)
            except OSError:
                pass
            self._fan_fd = -1
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        logger.info(
            f"Kernel monitor stopped. Events processed: {self._event_count}"
        )

    @property
    def event_count(self) -> int:
        return self._event_count


class KernelMonitor:
    """
    Unified kernel-level monitor with automatic fallback.

    Attempts to use fanotify (Linux) for true kernel-level monitoring.
    Falls back to watchdog-based RealtimeMonitor if kernel APIs are
    unavailable.
    """

    def __init__(self, watch_paths: List[str],
                 alert_callback: Optional[Callable] = None,
                 canary_registry: Optional[Dict] = None,
                 db_path: str = "baseline.db",
                 ignore_patterns: Optional[List[str]] = None,
                 suspicious_extensions: Optional[List[str]] = None,
                 skip_baseline: bool = False):
        self.watch_paths = (
            watch_paths if isinstance(watch_paths, list) else [watch_paths]
        )
        self.alert_callback = alert_callback
        self.canary_registry = canary_registry or {}
        self.db_path = db_path
        self.ignore_patterns = ignore_patterns
        self.suspicious_extensions = suspicious_extensions
        self.skip_baseline = skip_baseline

        self._kernel_monitor = None
        self._fallback_monitor = None
        self._using_kernel = False

    def start(self) -> str:
        """
        Start monitoring. Returns the backend name ('fanotify' or 'watchdog').
        """
        if _fanotify_available():
            logger.info("fanotify available — using kernel-level monitoring")
            self._kernel_monitor = FanotifyMonitor(
                watch_paths=self.watch_paths,
                alert_callback=self.alert_callback,
                canary_registry=self.canary_registry,
                ignore_patterns=self.ignore_patterns,
                suspicious_extensions=self.suspicious_extensions,
            )
            if self._kernel_monitor.start():
                self._using_kernel = True
                return "fanotify"
            else:
                logger.warning(
                    "fanotify init failed — falling back to watchdog"
                )

        # Fallback to watchdog-based monitor
        logger.info("Using watchdog-based monitoring (user-space fallback)")
        from agshield.monitor.realtime import RealtimeMonitor
        self._fallback_monitor = RealtimeMonitor(
            watch_paths=self.watch_paths,
            alert_callback=self.alert_callback,
            canary_registry=self.canary_registry,
            db_path=self.db_path,
            ignore_patterns=self.ignore_patterns,
            suspicious_extensions=self.suspicious_extensions,
        )
        if not self.skip_baseline:
            self._fallback_monitor.scan_baseline()
        self._fallback_monitor.start()
        self._using_kernel = False
        return "watchdog"

    def stop(self) -> None:
        """Stop the active monitor."""
        if self._kernel_monitor:
            self._kernel_monitor.stop()
        if self._fallback_monitor:
            self._fallback_monitor.stop()

    def scan_baseline(self) -> int:
        """Perform baseline scan (only for watchdog fallback)."""
        if self._fallback_monitor:
            return self._fallback_monitor.scan_baseline()
        return 0

    @property
    def using_kernel(self) -> bool:
        """Whether kernel-level monitoring is active."""
        return self._using_kernel

    @property
    def backend_name(self) -> str:
        return "fanotify" if self._using_kernel else "watchdog"

    @property
    def event_count(self) -> int:
        if self._kernel_monitor:
            return self._kernel_monitor.event_count
        return 0
