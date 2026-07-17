"""
Tests for the timestamp validator module.
"""

import os
import tempfile
import time
import unittest

from agshield.monitor.timestamp import TimestampValidator


class TestTimestampValidator(unittest.TestCase):
    """Test the TimestampValidator for timestomping detection."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _create_alerts_received(self):
        alerts = []

        def callback(alert):
            alerts.append(alert)

        return alerts, callback

    def test_normal_file_no_alerts(self):
        """A recently-created file generates no timestamp alerts."""
        alerts_received, cb = self._create_alerts_received()
        validator = TimestampValidator(alert_callback=cb)

        filepath = os.path.join(self.tmpdir, "normal.txt")
        with open(filepath, "w") as f:
            f.write("normal content")

        alerts = validator.validate_file(filepath)
        self.assertEqual(len(alerts), 0)

    def test_timestomping_detected(self):
        """A file backdated by 2 years is detected as timestomped."""
        alerts_received, cb = self._create_alerts_received()
        validator = TimestampValidator(alert_callback=cb)

        filepath = os.path.join(self.tmpdir, "timestomped.txt")
        with open(filepath, "w") as f:
            f.write("content")

        # Backdate to 2 years ago
        two_years_ago = time.time() - (365 * 2 * 86400)
        os.utime(filepath, (two_years_ago, two_years_ago))

        validator.validate_file(filepath)
        # Should have generated TIMESTAMP_RETRODATED alert
        self.assertTrue(
            any(a["event_type"] == "TIMESTAMP_RETRODATED" for a in alerts_received)
        )

    def test_alerts_to_callback(self):
        """Alerts are sent to the callback function."""
        alerts_received, cb = self._create_alerts_received()
        validator = TimestampValidator(alert_callback=cb)

        filepath = os.path.join(self.tmpdir, "new.txt")
        with open(filepath, "w") as f:
            f.write("content")

        future_time = time.time() + 3600  # 1 hour in the future
        os.utime(filepath, (future_time, future_time))

        validator.validate_file(filepath)
        self.assertTrue(len(alerts_received) > 0)


if __name__ == "__main__":
    unittest.main()
