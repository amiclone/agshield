"""
Tests for the configuration manager.
"""

import os
import tempfile
import unittest
import warnings
from unittest.mock import patch

from agshield.config import Config


class TestConfig(unittest.TestCase):
    """Test suite for Config class."""

    def setUp(self):
        # Create a temporary default config
        self.tmpdir = tempfile.mkdtemp()
        self.default_path = os.path.join(self.tmpdir, "default.yaml")
        with open(self.default_path, "w") as f:
            f.write("""
general:
  watch_paths:
    - /tmp
  log_level: INFO
""")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_default_config_loads(self):
        """Config class can load default YAML safely."""
        from pathlib import Path
        from agshield import config as cfg_module
        cfg_module.DEFAULT_CONFIG_PATH = Path(self.default_path)
        cfg = Config()
        self.assertIn("general", cfg._config)
        self.assertEqual(cfg.watch_paths, ["/tmp"])

    def test_safe_yaml_load(self):
        """Config uses yaml.safe_load to prevent code execution."""
        from pathlib import Path
        import yaml
        from agshield import config as cfg_module

        # Write a malicious YAML that uses !!python/object/apply
        # yaml.safe_load should REJECT this with a ConstructorError
        malicious_yaml = """
general:
  watch_paths:
    - !!python/object/apply:os.system ["echo pwned > /tmp/pwned"]
"""
        # safe_load should raise ConstructorError on this malicious YAML
        with self.assertRaises(yaml.constructor.ConstructorError):
            yaml.safe_load(malicious_yaml)

        # The file should not have been created (nobody tried to execute)
        self.assertFalse(os.path.exists("/tmp/pwned"))

    def test_sensitive_values_masked(self):
        """Sensitive config values are masked when displayed."""
        from pathlib import Path
        from agshield import config as cfg_module
        cfg_module.DEFAULT_CONFIG_PATH = Path(self.default_path)
        cfg = Config()
        cfg._config["wazuh_integration"] = {
            "api_user": "admin",
            "api_password": "secret123",
            "enable": True,
        }

        sanitized = cfg.get_sanitized_config()
        self.assertEqual(sanitized["wazuh_integration"]["api_password"], "****")
        self.assertEqual(sanitized["wazuh_integration"]["api_user"], "admin")
        self.assertEqual(sanitized["wazuh_integration"]["enable"], True)

    def test_command_injection_chars_in_paths_warn(self):
        """Command injection characters in paths trigger warnings."""
        from pathlib import Path
        from agshield import config as cfg_module
        cfg_module.DEFAULT_CONFIG_PATH = Path(self.default_path)
        cfg = Config()
        cfg._config["general"]["watch_paths"] = ["/tmp; rm -rf /"]

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            cfg._validate()
            self.assertTrue(any("Suspicious character" in str(warning.message) for warning in w))

    def test_dot_notation_get(self):
        """Dot notation config access works."""
        from pathlib import Path
        from agshield import config as cfg_module
        cfg_module.DEFAULT_CONFIG_PATH = Path(self.default_path)
        cfg = Config()
        self.assertEqual(cfg.get("general.log_level"), "INFO")
        self.assertEqual(cfg.get("general.nonexistent", "default"), "default")


class TestDeepMerge(unittest.TestCase):
    """Test suite for dict deep merge."""

    def test_simple_merge(self):
        base = {"a": 1, "b": 2}
        override = {"b": 99, "c": 3}
        merged = Config._deep_merge(base, override)
        self.assertEqual(merged, {"a": 1, "b": 99, "c": 3})

    def test_nested_merge(self):
        base = {"general": {"watch_paths": ["/tmp"], "log_level": "INFO"}}
        override = {"general": {"log_level": "DEBUG"}}
        merged = Config._deep_merge(base, override)
        self.assertEqual(merged["general"]["log_level"], "DEBUG")
        self.assertEqual(merged["general"]["watch_paths"], ["/tmp"])


if __name__ == "__main__":
    unittest.main()
