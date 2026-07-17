"""
AntiGravity Shield — Module 3: Timestamp Anomaly Detector
==========================================================
Detects timestomping by identifying temporal anomalies that are
mathematically impossible under normal file system operation.

Counters: timestomper.py (MACE timestamp manipulation)
"""

import os
import time
from datetime import datetime, timedelta


# Detection thresholds
RETRO_DATE_THRESHOLD_DAYS = 365       # Flag if mtime is >1 year in the past
FUTURE_THRESHOLD_SECONDS = 300        # Flag if mtime is >5 minutes in the future
SIBLING_DEVIATION_DAYS = 180          # Flag if file differs >6 months from siblings
CTIME_MTIME_DRIFT_SECONDS = 60       # On creation, ctime and mtime should be close


class TimestampValidator:
    """
    Analyzes file timestamps to detect manipulation (timestomping).
    Uses multiple heuristic rules that catch different evasion techniques.
    """

    def __init__(self, alert_callback=None):
        self.alert_callback = alert_callback

    def validate_file(self, filepath):
        """
        Run all timestamp validation checks on a single file.

        Returns:
            list: List of alert dicts for any anomalies found
        """
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
        ctime = stat.st_ctime  # On Linux: inode change time (cannot be spoofed by user)

        # ─── Rule 1: Retro-Dating Detection ───
        # If mtime is set far in the past but ctime is recent,
        # the timestamps were manually manipulated.
        age_days = (now - mtime) / 86400
        ctime_age_days = (now - ctime) / 86400

        if age_days > RETRO_DATE_THRESHOLD_DAYS and ctime_age_days < 1:
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

        # ─── Rule 2: ctime/mtime Mismatch Detection ───
        # On Linux, ctime is updated whenever mtime changes (including via os.utime).
        # BUT ctime reflects WHEN the change happened, not what it was set to.
        # So if mtime = 2010 but ctime = today, timestomping occurred.
        if abs(mtime - ctime) > RETRO_DATE_THRESHOLD_DAYS * 86400:
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

        # ─── Rule 3: Future Timestamp Detection ───
        # Files with timestamps in the future are suspicious
        if mtime > now + FUTURE_THRESHOLD_SECONDS:
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

        # ─── Rule 4: Temporal Impossibility ───
        # mtime is before the epoch of common OS installations (before 2000)
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

    def validate_directory(self, dirpath):
        """
        Validate all files in a directory and also perform
        sibling comparison (Rule 5).

        Returns:
            list: All alerts from all files
        """
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

        # ─── Rule 5: Sibling Inconsistency ───
        # If one file's mtime is radically different from all siblings
        if len(sibling_mtimes) >= 3:
            avg_mtime = sum(sibling_mtimes) / len(sibling_mtimes)
            threshold = SIBLING_DEVIATION_DAYS * 86400

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

        # Fire sibling alerts
        if self.alert_callback:
            for alert in all_alerts:
                if alert not in [a for a in all_alerts if a.get("_fired")]:
                    alert["_fired"] = True

        return all_alerts

    def validate_on_event(self, filepath):
        """
        Called by the realtime monitor when a file event occurs.
        Performs timestamp validation on the affected file.

        Returns:
            list: Alerts generated
        """
        return self.validate_file(filepath)

    def _make_alert(self, filepath, event_type, severity, reason, extra_details=None):
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


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "."

    def print_alert(alert):
        sev = alert["severity"]
        icon = {"INFO": "ℹ️ ", "WARNING": "⚠️ ", "CRITICAL": "🚨"}
        print(f"  {icon.get(sev, '  ')} [{sev}] {alert['event_type']}")
        print(f"       File: {alert['path']}")
        print(f"       ↳ {alert['details']['reason']}")

    print(f"[SHIELD] Scanning timestamps in: {target}")
    validator = TimestampValidator(alert_callback=print_alert)

    if os.path.isdir(target):
        alerts = validator.validate_directory(target)
    else:
        alerts = validator.validate_file(target)

    if not alerts:
        print("  ✅ No timestamp anomalies detected.")
    else:
        print(f"\n  Found {len(alerts)} anomaly(ies).")
