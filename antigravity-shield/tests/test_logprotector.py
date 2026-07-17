"""
Tests for the log protector module.
"""

import os
import tempfile
import unittest

from agshield.monitor.logprotector import LogProtector


class TestLogProtector(unittest.TestCase):
    """Test the LogProtector hash-chain integrity."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.log_path = os.path.join(self.tmpdir, "shield_audit.log")
        self.chain_path = os.path.join(self.tmpdir, "hash_chain.json")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_empty_log_valid(self):
        """Empty log integrity check returns valid."""
        lp = LogProtector(log_path=self.log_path, chain_path=self.chain_path)
        result = lp.verify_integrity()
        self.assertTrue(result["valid"])
        self.assertEqual(result["entries_checked"], 0)

    def test_single_entry_valid(self):
        """A single log entry can be written and verified."""
        lp = LogProtector(log_path=self.log_path, chain_path=self.chain_path)
        lp.log_event({"event_type": "TEST", "severity": "INFO"})
        result = lp.verify_integrity()
        self.assertTrue(result["valid"])
        self.assertEqual(result["entries_checked"], 1)

    def test_chain_breaks_on_tampering(self):
        """Modifying a log entry breaks the hash chain."""
        lp = LogProtector(log_path=self.log_path, chain_path=self.chain_path)
        lp.log_event({"event_type": "TEST", "severity": "INFO", "x": 1})
        lp.log_event({"event_type": "TEST", "severity": "INFO", "x": 2})
        lp.log_event({"event_type": "TEST", "severity": "INFO", "x": 3})

        # Verify integrity before tampering
        result = lp.verify_integrity()
        self.assertTrue(result["valid"])

        # Tamper with the middle entry
        with open(self.log_path, "r") as f:
            lines = f.readlines()
        import json
        entry = json.loads(lines[1])
        entry["data"]["x"] = 999  # Tamper!
        lines[1] = json.dumps(entry) + "\n"
        with open(self.log_path, "w") as f:
            f.writelines(lines)

        # Verify integrity after tampering — should FAIL
        lp2 = LogProtector(log_path=self.log_path, chain_path=self.chain_path)
        result = lp2.verify_integrity()
        self.assertFalse(result["valid"])
        self.assertIn("LOG TAMPERING", result["error"])

    def test_entry_deletion_detected(self):
        """Deleting a log entry breaks the chain."""
        lp = LogProtector(log_path=self.log_path, chain_path=self.chain_path)
        lp.log_event({"event_type": "TEST", "x": 1})
        lp.log_event({"event_type": "TEST", "x": 2})
        lp.log_event({"event_type": "TEST", "x": 3})

        # Verify before deletion
        self.assertTrue(lp.verify_integrity()["valid"])

        # Delete middle entry — should break the chain
        with open(self.log_path, "r") as f:
            lines = f.readlines()
        # Remove the second entry
        with open(self.log_path, "w") as f:
            f.writelines([lines[0], lines[2]])

        lp2 = LogProtector(log_path=self.log_path, chain_path=self.chain_path)
        result = lp2.verify_integrity()
        self.assertFalse(result["valid"])


if __name__ == "__main__":
    unittest.main()
