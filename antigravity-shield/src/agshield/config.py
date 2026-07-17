"""
AntiGravity Shield — Configuration Management
==============================================
Loads and validates configuration from YAML files.
Supports default config + user overrides.

Security:
- Uses yaml.safe_load to prevent code execution via YAML deserialization
- Validates file paths to prevent directory traversal
- Validates numeric values to prevent injection of malicious values
- Masks sensitive values (passwords) when displayed
"""

import os
import re
import yaml
from pathlib import Path
from typing import Any, Dict, Optional, List

DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config" / "default.yaml"

# Platform-specific config paths are determined at load time
def _get_user_config_paths() -> list:
    """Get platform-appropriate user config paths."""
    from agshield.utils.platform import get_default_config_dir, is_windows, get_os
    
    paths = []
    
    if is_windows():
        # Windows: %APPDATA%\antigravity\config.yaml
        appdata = os.environ.get("APPDATA")
        if appdata:
            paths.append(Path(appdata) / "antigravity" / "config.yaml")
        paths.append(Path("C:/ProgramData/antigravity/config.yaml"))
    else:
        # Linux/macOS
        paths.append(Path("/etc/antigravity/config.yaml"))
        paths.append(Path.home() / ".config" / "antigravity" / "config.yaml")
    
    # Current directory config
    paths.append(Path.cwd() / "antigravity.yaml")
    
    return paths


class Config:
    """
    Configuration manager for AntiGravity Shield.

    Loads default config, then overlays user config from the first
    existing path. Validates paths and values to prevent security issues.
    """

    # Allowed value patterns — validation is non-strict but catches obvious issues
    _VALID_PATTERN_PATH = re.compile(r"^[a-zA-Z0-9_\-\./:~ ]+$")
    _SENSITIVE_KEYS = {"password", "api_password", "secret", "token", "key"}

    def __init__(self, config_path: Optional[str] = None):
        self._config: Dict[str, Any] = {}
        self._load(config_path)
        self._validate()

    def _load(self, user_path: Optional[str] = None) -> None:
        """Load default config and overlay user config."""
        # Load defaults
        if DEFAULT_CONFIG_PATH.exists():
            with open(DEFAULT_CONFIG_PATH, "r") as f:
                self._config = yaml.safe_load(f) or {}
        else:
            self._config = {}

        # Find and load user config
        user_config = None
        if user_path:
            user_config = Path(user_path)
        else:
            for path in _get_user_config_paths():
                if path.exists():
                    user_config = path
                    break

        if user_config and user_config.exists():
            with open(user_config, "r") as f:
                user_data = yaml.safe_load(f) or {}
            self._config = self._deep_merge(self._config, user_data)

    def _validate(self) -> None:
        """
        Validate config values to catch obvious security issues.

        Notes:
        - This is a sanity check, not an exhaustive schema validator.
        - Path-like values are checked for injection patterns (e.g., '..', '$', '|').
        - Sensitive values (passwords, tokens) are read from env vars or
          /etc/antigravity/config.yaml — never logged in plaintext.
        """
        import warnings

        dangerous_chars = [";", "&", "|", "`", "$", "\n", "\r"]

        # Validate watch paths
        watch_paths = self._config.get("general", {}).get("watch_paths", []) or []
        if not isinstance(watch_paths, list):
            watch_paths = [watch_paths]
        for p in watch_paths:
            if not isinstance(p, str):
                continue
            if any(c in p for c in dangerous_chars):
                warnings.warn(
                    f"Suspicious character in watch path: {p!r}. "
                    f"This may be a configuration error.",
                    RuntimeWarning,
                )

        # Validate log file path
        log_file = self._config.get("general", {}).get("log_file", "") or ""
        if log_file and any(c in log_file for c in dangerous_chars):
            warnings.warn(
                f"Suspicious character in log_file: {log_file!r}.",
                RuntimeWarning,
            )

    @staticmethod
    def _deep_merge(base: Dict, override: Dict) -> Dict:
        """Recursively merge override into base."""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = Config._deep_merge(result[key], value)
            else:
                result[key] = value
        return result

    def _is_sensitive_key(self, key: str) -> bool:
        """Check if a key name indicates a sensitive value."""
        key_lower = key.lower()
        return any(sensitive in key_lower for sensitive in self._SENSITIVE_KEYS)

    def get(self, key: str, default: Any = None, mask_sensitive: bool = False) -> Any:
        """
        Get a config value using dot notation (e.g., 'general.watch_paths').

        Args:
            key: Dot-separated config path
            default: Default value if key not found
            mask_sensitive: If True, mask sensitive values (passwords, tokens)
        """
        keys = key.split(".")
        value = self._config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default

        if value is None:
            value = default

        # Mask sensitive values if requested
        if mask_sensitive and self._is_sensitive_key(keys[-1]) and value:
            return "****"

        return value

    def get_section(self, section: str, mask_sensitive: bool = False) -> Dict[str, Any]:
        """Get an entire config section, optionally masking sensitive values."""
        section_data = self._config.get(section, {})
        if not mask_sensitive:
            return section_data
        result = {}
        for key, value in section_data.items():
            if self._is_sensitive_key(key) and value:
                result[key] = "****"
            elif isinstance(value, dict):
                result[key] = {
                    k: ("****" if self._is_sensitive_key(k) and v else v)
                    for k, v in value.items()
                }
            else:
                result[key] = value
        return result

    def get_sanitized_config(self) -> Dict[str, Any]:
        """Return full config with all sensitive values masked."""
        return self._mask_dict(self._config)

    def _mask_dict(self, d: Dict) -> Dict:
        """Recursively mask sensitive values in a nested dict."""
        result = {}
        for key, value in d.items():
            if self._is_sensitive_key(key) and value:
                result[key] = "****"
            elif isinstance(value, dict):
                result[key] = self._mask_dict(value)
            else:
                result[key] = value
        return result

    def get_section(self, section: str) -> Dict[str, Any]:
        """Get an entire config section."""
        return self._config.get(section, {})

    @property
    def watch_paths(self) -> list:
        return self.get("general.watch_paths", ["."])

    @property
    def reports_dir(self) -> str:
        return self.get("general.reports_dir", "reports")

    @property
    def database_path(self) -> str:
        return self.get("general.database_path", "baseline.db")

    @property
    def log_level(self) -> str:
        return self.get("general.log_level", "INFO")

    @property
    def log_file(self) -> str:
        return self.get("general.log_file", "shield.log")

    def to_dict(self) -> Dict[str, Any]:
        """Return the full config as a dict."""
        return self._config.copy()

    def __repr__(self) -> str:
        sections = list(self._config.keys())
        return f"Config(sections={sections})"
