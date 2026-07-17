"""
AntiGravity Shield — Platform Utilities
========================================
Cross-platform abstractions for OS-specific behavior.
Handles differences between Linux, macOS, and Windows.
"""

import os
import sys
import platform
import tempfile
from pathlib import Path
from typing import Optional


def get_os() -> str:
    """Get the operating system name."""
    return platform.system().lower()  # 'linux', 'windows', 'darwin'


def is_linux() -> bool:
    """Check if running on Linux."""
    return get_os() == "linux"


def is_windows() -> bool:
    """Check if running on Windows."""
    return get_os() == "windows"


def is_macos() -> bool:
    """Check if running on macOS."""
    return get_os() == "darwin"


def get_default_data_dir() -> Path:
    """Get the platform-appropriate data directory."""
    if is_windows():
        # Windows: %APPDATA%\antigravity or C:\ProgramData\antigravity
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "antigravity"
        return Path("C:/ProgramData/antigravity")
    else:
        # Unix/Linux/macOS: /var/lib/antigravity or ~/.local/share/antigravity
        if os.geteuid() == 0 if hasattr(os, 'geteuid') else False:
            return Path("/var/lib/antigravity")
        return Path.home() / ".local" / "share" / "antigravity"


def get_default_log_dir() -> Path:
    """Get the platform-appropriate log directory."""
    if is_windows():
        return Path("C:/ProgramData/antigravity/logs")
    else:
        if os.geteuid() == 0 if hasattr(os, 'geteuid') else False:
            return Path("/var/log/antigravity")
        return Path.home() / ".local" / "share" / "antigravity" / "logs"


def get_default_run_dir() -> Path:
    """Get the platform-appropriate runtime directory."""
    if is_windows():
        return Path("C:/ProgramData/antigravity/run")
    else:
        if os.geteuid() == 0 if hasattr(os, 'geteuid') else False:
            return Path("/var/run/antigravity")
        return Path(tempfile.gettempdir()) / "antigravity"


def get_default_config_dir() -> Path:
    """Get the platform-appropriate config directory."""
    if is_windows():
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "antigravity"
        return Path("C:/ProgramData/antigravity")
    else:
        return Path("/etc/antigravity")


def get_system_logs() -> list:
    """Get platform-appropriate system log paths."""
    if is_linux():
        return [
            "/var/log/auth.log",
            "/var/log/syslog",
            "/var/log/messages",
            "/var/log/secure",
            "/var/log/kern.log",
        ]
    elif is_macos():
        return [
            "/var/log/system.log",
            "/var/log/auth.log",
            "/var/log/install.log",
        ]
    elif is_windows():
        # Windows doesn't have traditional text logs in the same way
        # Event logs are accessed via PowerShell or wevtutil
        return []
    return []


def get_user_history_paths() -> list:
    """Get platform-appropriate user history file paths."""
    home = Path.home()
    if is_linux() or is_macos():
        return [
            str(home / ".bash_history"),
            str(home / ".zsh_history"),
            str(home / ".python_history"),
        ]
    elif is_windows():
        # Windows doesn't have bash history, but has PSReadLine history
        appdata = os.environ.get("APPDATA")
        if appdata:
            return [
                str(Path(appdata) / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt"),
            ]
        return []
    return []


def get_default_external_logs() -> list:
    """Get default external logs to monitor."""
    logs = get_system_logs() + get_user_history_paths()
    # Filter to existing files
    return [p for p in logs if os.path.exists(p)]


def set_file_mtime(filepath: str, timestamp: float) -> bool:
    """
    Set the modification time of a file cross-platform.

    Returns:
        bool: True if successful
    """
    try:
        os.utime(filepath, (timestamp, timestamp))
        return True
    except (OSError, AttributeError):
        return False


def get_inode_change_time(filepath: str) -> Optional[float]:
    """
    Cross-platform equivalent of ctime (inode change time on Linux).

    On Linux/Mac: returns st_ctime
    On Windows: returns st_ctime (which is creation time, not change time)

    Note: On Windows, there's no true inode change time. We approximate
    using file modification time + the last metadata change.
    """
    try:
        stat = os.stat(filepath)
        if is_windows():
            # On Windows, st_ctime is creation time, not change time
            # We use the max of mtime and file's parent directory mtime
            parent_dir = os.path.dirname(filepath)
            parent_mtime = os.stat(parent_dir).st_mtime if os.path.exists(parent_dir) else 0
            return max(stat.st_mtime, parent_mtime)
        else:
            return stat.st_ctime
    except OSError:
        return None


def create_symlink_safe(src: str, dst: str) -> bool:
    """
    Create a symlink cross-platform. Falls back to copy on Windows
    if symlink creation fails (requires admin privileges on Windows).
    """
    try:
        if is_windows():
            # Try symlink first (requires admin or developer mode)
            try:
                os.symlink(src, dst)
                return True
            except OSError:
                # Fall back to copy
                import shutil
                shutil.copy2(src, dst)
                return True
        else:
            os.symlink(src, dst)
            return True
    except OSError:
        return False


def has_inotify() -> bool:
    """Check if the platform supports inotify (Linux)."""
    if not is_linux():
        return False
    try:
        # Check if /proc/sys/fs/inotify exists
        return os.path.exists("/proc/sys/fs/inotify/max_user_watches")
    except Exception:
        return False


def get_executable_name() -> str:
    """Get the platform-appropriate executable name."""
    if is_windows():
        return "agshield.exe"
    return "agshield"


def get_install_path() -> Path:
    """Get the installation path for the executable."""
    if is_windows():
        return Path("C:/Program Files/antigravity-shield")
    else:
        return Path("/usr/local/bin")


def ensure_directory(path: Path) -> Path:
    """Ensure a directory exists, creating it if necessary."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def has_fanotify() -> bool:
    """
    Check if the platform supports fanotify (Linux kernel 2.6.37+).
    Requires root/CAP_SYS_ADMIN privilege.
    """
    if not is_linux():
        return False
    if not has_admin_privileges():
        return False
    try:
        import ctypes
        import ctypes.util
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        # fanotify_init syscall = 300 on x86_64
        fd = libc.syscall(300, 0x00000001, 0)  # FAN_CLOEXEC, O_RDONLY
        if fd < 0:
            return False
        os.close(fd)
        return True
    except Exception:
        return False


def has_admin_privileges() -> bool:
    """Check if the current process has admin/root privileges."""
    if is_windows():
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0 if hasattr(os, 'geteuid') else False


def get_process_info(pid: int) -> Optional[dict]:
    """
    Get basic process information cross-platform.

    Returns:
        dict with keys: name, cmdline, ppid, user (or None if unavailable)
    """
    if is_linux() or is_macos():
        info = {}
        try:
            with open(f"/proc/{pid}/comm", "r") as f:
                info["name"] = f.read().strip()
        except (OSError, IOError):
            info["name"] = "unknown"

        try:
            with open(f"/proc/{pid}/cmdline", "r") as f:
                info["cmdline"] = f.read().replace("\x00", " ").strip()
        except (OSError, IOError):
            info["cmdline"] = ""

        try:
            with open(f"/proc/{pid}/status", "r") as f:
                for line in f:
                    if line.startswith("PPid:"):
                        info["ppid"] = int(line.split()[1])
                    elif line.startswith("Uid:"):
                        uid = int(line.split()[1])
                        try:
                            import pwd
                            info["user"] = pwd.getpwuid(uid).pw_name
                        except (ImportError, KeyError):
                            info["user"] = str(uid)
        except (OSError, IOError):
            pass

        return info if info.get("name") != "unknown" else None

    elif is_windows():
        try:
            import psutil
            proc = psutil.Process(pid)
            return {
                "name": proc.name(),
                "cmdline": " ".join(proc.cmdline()),
                "ppid": proc.ppid(),
                "user": proc.username(),
            }
        except Exception:
            return None

    return None
