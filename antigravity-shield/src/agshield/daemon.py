"""
AntiGravity Shield — Daemon Module
===================================
Manages the shield as a background daemon process.
Cross-platform: works on Linux (fork-based daemon) and Windows (service-like).
"""

import os
import sys
import signal
import time
import logging
from typing import Optional

from agshield.config import Config
from agshield.detection.engine import DetectionEngine
from agshield.utils.platform import get_default_run_dir, is_windows

logger = logging.getLogger("antigravity.daemon")

DEFAULT_PID_FILE = str(get_default_run_dir() / "shield.pid")


class ShieldDaemon:
    """
    Manages the AntiGravity Shield as a background daemon.
    """

    def __init__(self, config: Optional[Config] = None, config_path: Optional[str] = None):
        self.config = config or Config(config_path)
        self.pid_file = self.config.get("daemon.pid_file", DEFAULT_PID_FILE)
        self.engine = None

    def start(self, foreground: bool = False) -> None:
        """
        Start the shield daemon.

        Args:
            foreground: If True, run in foreground (for debugging)
        """
        if not foreground and not is_windows():
            # Daemonize via fork (Unix only)
            self._daemonize()

        self.engine = DetectionEngine(self.config)

        # Handle signals
        def handle_signal(signum, frame):
            logger.info(f"Received signal {signum}, shutting down...")
            self.stop()
            sys.exit(0)

        if not is_windows():
            signal.signal(signal.SIGINT, handle_signal)
            signal.signal(signal.SIGTERM, handle_signal)
            signal.signal(signal.SIGHUP, self._reload_config)
        else:
            # Windows: only SIGINT/SIGTERM available in Python
            signal.signal(signal.SIGINT, handle_signal)
            signal.signal(signal.SIGTERM, handle_signal)

        self.engine.start()
        self.engine.wait()

    def stop(self) -> None:
        """Stop the shield daemon."""
        if self.engine:
            self.engine.stop()

        # Remove PID file
        if os.path.exists(self.pid_file):
            try:
                os.remove(self.pid_file)
            except OSError:
                pass

    def status(self) -> Optional[int]:
        """
        Check if the daemon is running.

        Returns:
            int: PID if running, None otherwise
        """
        if not os.path.exists(self.pid_file):
            return None

        try:
            with open(self.pid_file, "r") as f:
                pid = int(f.read().strip())

            # Check if process is actually running
            if is_windows():
                # On Windows, we can use psutil or check if the file is locked
                import psutil
                if psutil.pid_exists(pid):
                    return pid
            else:
                os.kill(pid, 0)
                return pid
        except (ValueError, ProcessLookupError, PermissionError, ImportError):
            return None

        return None

    def _daemonize(self) -> None:
        """Fork to background and become a daemon (Unix only)."""
        # First fork
        pid = os.fork()
        if pid > 0:
            # Parent exits
            print(f"Daemon started with PID {pid}")
            self._write_pid(pid)
            sys.exit(0)

        # Decouple from parent environment
        os.setsid()
        os.umask(0)

        # Second fork
        pid = os.fork()
        if pid > 0:
            sys.exit(0)

        # Redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        devnull = open(os.devnull, "r")
        os.dup2(devnull.fileno(), sys.stdin.fileno())

        self._write_pid(os.getpid())

    def _write_pid(self, pid: int) -> None:
        """Write the current PID to the PID file."""
        from pathlib import Path
        Path(self.pid_file).parent.mkdir(parents=True, exist_ok=True)
        with open(self.pid_file, "w") as f:
            f.write(str(pid))

    def _reload_config(self, signum, frame) -> None:
        """Reload configuration on SIGHUP."""
        logger.info("Reloading configuration...")
        # Re-read config file
        self.config._load()
        logger.info("Configuration reloaded successfully")
