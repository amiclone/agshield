"""
AntiGravity Shield — Timestamp Anomaly Detector
================================================
Detects timestomping by identifying temporal anomalies that are
mathematically impossible under normal file system operation.

Cross-platform support:
- Linux: Uses ctime (inode change time) which can't be spoofed by os.utime
- Windows: Approximates ctime using file mtime + parent directory mtime
"""

import os
import time
import logging
from datetime import datetime
from typing import Callable, Dict, List, Optional

from agshield.utils.platform import get_inode_change_time, is_windows

logger = logging.getLogger("antigravity.monitor.timestamp")


class TimestampValidator:
    """
    Analyzes file timestamps to detect manipulation (timestomping).
    Uses multiple heuristic rules that catch different evasion techniques.
    """

    def __init__(self, alert_callback: Optional[Callable] = None,
                 retro_date_threshold_days: int = 365,
                 future_threshold_seconds: int = 300,
                 sibling_deviation_days: int = 180,
                 ctime_mtime_drift_seconds: int = 60):
        self.alert_callback = alert_callback
        self.retro_date_threshold_days = retro_date_threshold_days
        self.future_threshold_seconds = future_threshold_seconds
        self.sibling_deviation_days = sibling_deviation_days
        self.ctime_mtime_drift_seconds = ctime_mtime_drift_seconds

    def validate_file(self, filepath: str) -> List[dict]:
        """Run all timestamp validation checks on a single file."""
        alerts = []

        if not os.path.exists(filepath):
            return alerts

        try:
            stat = os.stat(filepath)
        except OSError:
            return alerts

        now = time.time()
        mtime = stat.st_mtime
        atime = stat.st_atime
        # Use cross-platform ctime equivalent (on Linux: inode change time)
        ctime = stat.st_ctime if not is_windows() else get_inode_change_time(filepath) or stat.st_ctime

        # Rule 1: Retro-Dating Detection
        age_days = (now - mtime) / 86400
        ctime_age_days = (now - ctime) / 86400

        if age_days > self.retro_date_threshold_days and ctime_age_days < 1:
            mtime_str = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
            ctime_str = datetime.fromtimestamp(ctime).strftime("%Y-%m-%d %H:%M:%S")
            alerts.append(self._make_alert(
                filepath,
                "TIMESTAMP_RETRODATED",
                "CRITICAL",
                (
                    f"File mtime ({mtime_str}) is {age_days:.0f} days old, "
                    f"but ctime ({ctime_str}) is {ctime_age_days:.1f} days old. "
                    f"This is a definitive indicator of TIMESTOMPING — "
                    f"os.utime() changes mtime but cannot change ctime on Linux."
                ),
                {
                    "mtime": mtime, "ctime": ctime,
                    "mtime_human": mtime_str, "ctime_human": ctime_str,
                    "age_days": round(age_days, 1),
                    "ctime_age_days": round(ctime_age_days, 1),
                    "technique": "T1070.006 - Timestomp (MITRE ATT&CK)"
                }
            ))

        # Rule 2: ctime/mtime Mismatch Detection
        if abs(mtime - ctime) > self.retro_date_threshold_days * 86400:
            alerts.append(self._make_alert(
                filepath,
                "CTIME_MTIME_DIVERGENCE",
                "CRITICAL",
                (
                    f"Massive divergence between mtime and ctime "
                    f"({abs(mtime - ctime) / 86400:.0f} days apart). "
                    f"On Linux, this is physically impossible without timestamp manipulation."
                ),
                {
                    "mtime": mtime, "ctime": ctime,
                    "divergence_days": round(abs(mtime - ctime) / 86400, 1),
                }
            ))

        # Rule 3: Future Timestamp Detection
        if mtime > now + self.future_threshold_seconds:
            alerts.append(self._make_alert(
                filepath,
                "TIMESTAMP_FUTURE",
                "WARNING",
                (
                    f"File mtime is {(mtime - now) / 60:.1f} minutes in the future. "
                    f"Possible clock manipulation or timestomping attempt."
                ),
                {"mtime": mtime, "seconds_ahead": round(mtime - now, 1)}
            ))

        # Rule 4: Temporal Impossibility
        epoch_2000 = datetime(2000, 1, 1).timestamp()
        if mtime < epoch_2000 and ctime > epoch_2000:
            alerts.append(self._make_alert(
                filepath,
                "TIMESTAMP_IMPOSSIBLE",
                "CRITICAL",
                (
                    f"File claims modification date before year 2000 "
                    f"({datetime.fromtimestamp(mtime).strftime('%Y-%m-%d')}) "
                    f"but inode was changed recently. Timestomping confirmed."
                ),
                {"mtime": mtime, "ctime": ctime}
            ))

        # Fire alerts
        if self.alert_callback:
            for alert in alerts:
                self.alert_callback(alert)

        return alerts

    def validate_directory(self, dirpath: str) -> List[dict]:
        """Validate all files in a directory and perform sibling comparison."""
        all_alerts = []

        if not os.path.isdir(dirpath):
            return all_alerts

        # Collect all file timestamps in the directory
        sibling_mtimes = []
        files = []

        try:
            for entry in os.scandir(dirpath):
                if entry.is_file():
                    files.append(entry.path)
                    try:
                        sibling_mtimes.append(entry.stat().st_mtime)
                    except OSError:
                        pass
        except OSError:
            return all_alerts

        # Validate each file individually
        for filepath in files:
            alerts = self.validate_file(filepath)
            all_alerts.extend(alerts)

        # Rule 5: Sibling Inconsistency
        if len(sibling_mtimes) >= 3:
            avg_mtime = sum(sibling_mtimes) / len(sibling_mtimes)
            threshold = self.sibling_deviation_days * 86400

            for filepath in files:
                try:
                    stat = os.stat(filepath)
                    deviation = abs(stat.st_mtime - avg_mtime)
                    if deviation > threshold:
                        dev_days = deviation / 86400
                        all_alerts.append(self._make_alert(
                            filepath,
                            "TIMESTAMP_SIBLING_OUTLIER",
                            "WARNING",
                            (
                                f"File timestamp deviates {dev_days:.0f} days from "
                                f"directory average. Potential selective timestomping."
                            ),
                            {
                                "file_mtime": stat.st_mtime,
                                "directory_avg_mtime": avg_mtime,
                                "deviation_days": round(dev_days, 1),
                            }
                        ))
                except OSError:
                    pass

        return all_alerts

    def validate_realtime_attrib(self, filepath: str, pid: int = 0) -> List[dict]:
        """
        Real-time validation triggered by kernel FAN_ATTRIB events.

        When the kernel reports an attribute change, this method immediately
        checks for timestomping signatures. This is faster than post-hoc
        scanning because we know the exact moment the change happened.

        Args:
            filepath: Path to the file whose attributes changed
            pid: PID of the process that made the change (from kernel monitor)
        """
        alerts = self.validate_file(filepath)

        # If we detected timestomping AND have a PID, enrich the alert
        for alert in alerts:
            if pid > 0:
                alert["details"]["detected_via"] = "kernel_attrib_event"
                alert["details"]["modifier_pid"] = pid
                alert["details"]["reason"] = (
                    f"[REAL-TIME KERNEL DETECTION] {alert['details']['reason']}"
                )

        return alerts

    def _make_alert(self, filepath: str, event_type: str, severity: str,
                    reason: str, extra_details: Optional[Dict] = None) -> dict:
        """Construct a standardized alert dict."""
        alert = {
            "module": "timestamp_validator",
            "event_type": event_type,
            "path": filepath,
            "detection_wall_time": time.time(),
            "detection_perf_time": time.perf_counter(),
            "severity": severity,
            "details": {
                "reason": reason,
            },
        }
        if extra_details:
            alert["details"].update(extra_details)
        return alert
