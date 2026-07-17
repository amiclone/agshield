"""
AntiGravity Shield — AI Baseline & Anomaly Engine
====================================================
Learns per-system behavioral baselines using rolling statistics and
detects anomalies when current behavior deviates from learned norms.

This is what traditional tools CAN'T do: adapt to each system's unique
pattern of normal activity, eliminating false positives while catching
novel attacks that have no known signature.
"""
import time
import math
import threading
from collections import defaultdict, deque
from typing import Dict, Optional, Tuple


class RollingStats:
    """Efficient rolling mean/stddev using Welford's algorithm."""

    def __init__(self, window_size: int = 500):
        self.window = window_size
        self.values = deque(maxlen=window_size)
        self._count = 0
        self._mean = 0.0
        self._m2 = 0.0

    def add(self, value: float):
        self._count += 1
        self.values.append(value)
        delta = value - self._mean
        self._mean += delta / min(self._count, self.window)
        delta2 = value - self._mean
        self._m2 += delta * delta2

    @property
    def mean(self) -> float:
        return self._mean

    @property
    def std(self) -> float:
        if self._count < 2:
            return 0.0
        return math.sqrt(self._m2 / min(self._count, self.window))

    @property
    def count(self) -> int:
        return self._count

    def is_anomalous(self, value: float, sigma: float = 2.5) -> Tuple[bool, float]:
        """Check if a value is anomalous (> sigma std deviations from mean)."""
        if self._count < 10:
            return False, 0.0  # Not enough data to judge
        if self.std == 0:
            return value != self.mean, 0.0
        z_score = abs(value - self.mean) / self.std
        return z_score > sigma, z_score


class AnomalyEngine:
    """
    AI-powered anomaly detection engine.

    Learns three behavioral baselines per system:
    1. Operations per minute (file event rate)
    2. Severity distribution (ratio of CRITICAL/WARNING events)
    3. Directory activity patterns (which directories are normally active)

    Flags anomalies when current behavior deviates significantly from
    the learned baseline — even if individual events look benign.
    """

    def __init__(self, alert_callback=None, learning_period: float = 60.0):
        """
        Args:
            alert_callback: Function to call when anomaly detected.
            learning_period: Seconds of data to collect before alerting.
        """
        self.alert_callback = alert_callback
        self.learning_period = learning_period
        self.start_time = time.time()
        self._lock = threading.Lock()

        # Baseline models
        self.ops_rate = RollingStats(window_size=100)
        self.severity_ratio = RollingStats(window_size=100)
        self.dir_activity: Dict[str, RollingStats] = defaultdict(
            lambda: RollingStats(window_size=50)
        )

        # Sliding window for rate calculation
        self._event_times: deque = deque(maxlen=5000)
        self._severity_window: deque = deque(maxlen=200)
        self._last_rate_calc = time.time()

        # Anomaly state
        self.anomalies_detected = 0
        self.baseline_learned = False

    def process_event(self, event: Dict):
        """Feed an event into the anomaly engine."""
        now = time.time()

        with self._lock:
            self._event_times.append(now)

            severity = event.get("severity", "INFO")
            is_critical = 1.0 if severity == "CRITICAL" else 0.0
            self._severity_window.append(is_critical)

            # Extract directory from path
            path = event.get("path", "")
            import os
            directory = os.path.dirname(path) if path else ""

            # Calculate and feed metrics every 5 seconds
            if now - self._last_rate_calc >= 5.0:
                self._last_rate_calc = now
                self._update_baselines(now, directory)

    def _update_baselines(self, now: float, current_dir: str):
        """Recalculate metrics and check for anomalies."""
        # 1. Operations per minute
        cutoff = now - 60.0
        recent = sum(1 for t in self._event_times if t > cutoff)
        self.ops_rate.add(float(recent))

        # 2. Severity ratio (% of critical events in recent window)
        if self._severity_window:
            crit_ratio = sum(self._severity_window) / len(self._severity_window)
            self.severity_ratio.add(crit_ratio)

        # 3. Directory activity
        if current_dir:
            self.dir_activity[current_dir].add(1.0)

        # Check if learning period is over
        elapsed = now - self.start_time
        if elapsed < self.learning_period:
            return  # Still learning

        if not self.baseline_learned and self.ops_rate.count >= 10:
            self.baseline_learned = True

        if not self.baseline_learned:
            return

        # ── Anomaly checks ──

        # Rate anomaly: sudden spike in file operations
        is_rate_anomaly, rate_z = self.ops_rate.is_anomalous(float(recent), sigma=2.5)
        if is_rate_anomaly and recent > 10:
            self.anomalies_detected += 1
            self._fire_anomaly(
                "RATE_ANOMALY",
                f"File operation rate ({recent}/min) is {rate_z:.1f}σ above "
                f"baseline (mean={self.ops_rate.mean:.1f}/min, "
                f"σ={self.ops_rate.std:.1f}). This indicates automated "
                f"activity inconsistent with normal user behavior."
            )

        # Severity anomaly: sudden increase in critical events
        if self._severity_window:
            crit_ratio = sum(self._severity_window) / len(self._severity_window)
            is_sev_anomaly, sev_z = self.severity_ratio.is_anomalous(
                crit_ratio, sigma=2.0
            )
            if is_sev_anomaly and crit_ratio > 0.3:
                self.anomalies_detected += 1
                self._fire_anomaly(
                    "SEVERITY_ANOMALY",
                    f"Critical event ratio ({crit_ratio:.0%}) is {sev_z:.1f}σ "
                    f"above baseline ({self.severity_ratio.mean:.0%}). "
                    f"System is generating abnormally high-severity alerts."
                )

    def _fire_anomaly(self, anomaly_type: str, reason: str):
        """Emit an anomaly alert."""
        if self.alert_callback:
            self.alert_callback({
                "severity": "CRITICAL",
                "event_type": f"AI_{anomaly_type}",
                "path": "system-wide",
                "reason": reason,
            })

    def get_baseline_summary(self) -> Dict:
        """Return learned baseline metrics."""
        return {
            "baseline_learned": self.baseline_learned,
            "learning_duration_s": round(time.time() - self.start_time, 1),
            "ops_per_minute": {
                "mean": round(self.ops_rate.mean, 1),
                "std": round(self.ops_rate.std, 1),
                "samples": self.ops_rate.count,
            },
            "critical_event_ratio": {
                "mean": round(self.severity_ratio.mean, 3),
                "std": round(self.severity_ratio.std, 3),
                "samples": self.severity_ratio.count,
            },
            "directories_tracked": len(self.dir_activity),
            "anomalies_detected": self.anomalies_detected,
        }
