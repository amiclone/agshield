import os
import sys
import time
import datetime
import random
import platform
import subprocess

def get_platform():
    return platform.system()

def str_to_timestamp(date_str):
    """Converts YYYY-MM-DD HH:MM:SS to float timestamp."""
    try:
        return time.mktime(datetime.datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S").timetuple())
    except ValueError:
        return None

def set_linux_timestamps(filepath, atime, mtime):
    """Sets Access and Modify time on Linux using os.utime."""
    try:
        os.utime(filepath, (atime, mtime))
        print(f"[+] Successfully timestomped (Linux/Unix) {filepath}")
        return True
    except Exception as e:
        print(f"[-] Failed to timestomp {filepath}: {e}")
        return False

def set_windows_timestamps(filepath, ctime, atime, mtime):
    """Sets Creation, Access, and Modify time on Windows using WinAPI."""
    try:
        from ctypes import windll, Structure, byref, wintypes
        
        # Define FileTime structure if necessary, or use libraries if available.
        # For simplicity in this "malware", we might try a simpler approach if ctypes is complex,
        # but ctypes is standard.
        
        # Actually, Python's os.utime ONLY handles atime/mtime.
        # To handle Creation Time (ctime) on Windows, we need SetFileTime.
        
        # For this educational agent, sticking to os.utime is often enough for "Modified" timestamps
        # which users see most. But let's try to be advanced.
        
        # Simplified: Just do atime/mtime first.
        os.utime(filepath, (atime, mtime))
        
        # If we want to change CreationTime, we can try using powershell if ctypes fails or is too verbose for this snippet.
        # Powershell attempt:
        # $(Get-Item path).CreationTime = 'date'
        
        ctime_str = datetime.datetime.fromtimestamp(ctime).strftime('%Y-%m-%d %H:%M:%S')
        cmd = ["powershell", f"(Get-Item '{filepath}').CreationTime = '{ctime_str}'"]
        subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        print(f"[+] Successfully timestomped (Windows) {filepath}")
        return True
    except Exception as e:
        print(f"[-] Windows timestomp partial failure: {e}")
        return False

def stomp_file(filepath, target_date_str=None):
    """
    Changes the timestamps of a file to:
    1. A specific target_date_str (if provided).
    2. OR a random date in the past (if None).
    """
    if not os.path.exists(filepath):
        print(f"[-] File not found: {filepath}")
        return False

    if target_date_str:
        ts = str_to_timestamp(target_date_str)
    else:
        # Random date between 1 and 3 years ago
        days_ago = random.randint(365, 365*3)
        ts = time.time() - (days_ago * 86400)
    
    if not ts:
        print("[-] Invalid date format.")
        return False

    plat = get_platform()
    if plat == "Windows":
        return set_windows_timestamps(filepath, ts, ts, ts)
    else:
        return set_linux_timestamps(filepath, ts, ts)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python timestomper.py <file_path> [YYYY-MM-DD HH:MM:SS]")
        sys.exit(1)
    
    target_file = sys.argv[1]
    date_str = sys.argv[2] if len(sys.argv) > 2 else None
    stomp_file(target_file, date_str)
