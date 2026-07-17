"""
AntiGravity Shield — Wazuh Integration
=======================================
Integrates AntiGravity Shield with Wazuh SIEM.

Sends alerts to Wazuh via:
1. Wazuh API (for remote management)
2. Local socket (for agent mode)
3. Custom log file (for Wazuh log monitoring)

This allows Wazuh to receive real-time anti-forensic detection alerts
from the Shield, complementing its periodic FIM with event-driven detection.
"""

import os
import json
import time
import logging
import socket
from typing import Optional

logger = logging.getLogger("antigravity.integration.wazuh")


class WazuhIntegration:
    """
    Sends AntiGravity Shield alerts to Wazuh SIEM.

    Supports both API-based and socket-based integration.
    """

    def __init__(self, api_url: str = "https://localhost:55000",
                 api_user: Optional[str] = None,
                 api_password: Optional[str] = None,
                 api_verify_ssl: bool = True,
                 socket_path: str = "/var/ossec/queue/sockets/queue",
                 alert_prefix: str = "antigravity"):
        # Prefer environment variables over config file values for credentials
        self.api_url = api_url
        self.api_user = api_user or os.environ.get("AGSHIELD_WAZUH_USER", "")
        self.api_password = api_password or os.environ.get("AGSHIELD_WAZUH_PASSWORD", "")
        self.api_verify_ssl = api_verify_ssl
        self.socket_path = socket_path
        self.alert_prefix = alert_prefix
        self._api_token = None
        self._socket = None

        # Warn if no credentials are configured
        if self.api_url and not (self.api_user and self.api_password):
            logger.debug(
                "Wazuh API credentials not configured. "
                "Set AGSHIELD_WAZUH_USER and AGSHIELD_WAZUH_PASSWORD environment variables "
                "or api_user/api_password in the config file."
            )

    def send_alert(self, alert: dict) -> bool:
        """
        Send an alert to Wazuh.

        Tries socket first (faster, local), then API (remote).

        Args:
            alert: Alert dict from any shield module

        Returns:
            bool: True if alert was sent successfully
        """
        # Try socket first (local agent mode)
        if self.socket_path and os.path.exists(self.socket_path):
            return self._send_via_socket(alert)

        # Try API (remote manager mode)
        if self.api_url:
            return self._send_via_api(alert)

        logger.warning("No Wazuh integration method available")
        return False

    def _send_via_socket(self, alert: dict) -> bool:
        """Send alert to Wazuh via local socket."""
        try:
            if not self._socket:
                self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

            # Format alert for Wazuh
            wazuh_alert = self._format_wazuh_alert(alert)
            message = f"1:{self.alert_prefix}:{json.dumps(wazuh_alert)}"

            self._socket.sendto(message.encode(), self.socket_path)
            logger.debug(f"Alert sent via socket: {alert.get('event_type')}")
            return True

        except (OSError, IOError) as e:
            logger.error(f"Failed to send alert via socket: {e}")
            self._socket = None
            return False

    def _send_via_api(self, alert: dict) -> bool:
        """Send alert to Wazuh via REST API."""
        try:
            import requests

            # Get API token if needed
            if not self._api_token:
                self._api_token = self._get_api_token()
                if not self._api_token:
                    return False

            # Format alert for Wazuh
            wazuh_alert = self._format_wazuh_alert(alert)

            # Send to Wazuh API
            headers = {
                "Authorization": f"Bearer {self._api_token}",
                "Content-Type": "application/json",
            }

            response = requests.post(
                f"{self.api_url}/active-response",
                headers=headers,
                json=wazuh_alert,
                verify=self.api_verify_ssl,
                timeout=10,
            )

            if response.status_code == 200:
                logger.debug(f"Alert sent via API: {alert.get('event_type')}")
                return True
            else:
                logger.error(f"API returned {response.status_code}: {response.text}")
                return False

        except ImportError:
            logger.error("requests library not available for Wazuh API integration")
            return False
        except Exception as e:
            logger.error(f"Failed to send alert via API: {e}")
            self._api_token = None  # Force re-auth on next attempt
            return False

    def _get_api_token(self) -> Optional[str]:
        """Get authentication token from Wazuh API."""
        try:
            import requests

            response = requests.post(
                f"{self.api_url}/security/user/authenticate",
                auth=(self.api_user, self.api_password),
                verify=self.api_verify_ssl,
                timeout=10,
            )

            if response.status_code == 200:
                token = response.json().get("data", {}).get("token")
                return token
            else:
                logger.error(f"API auth failed: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Failed to get API token: {e}")
            return None

    def _format_wazuh_alert(self, alert: dict) -> dict:
        """Format an alert for Wazuh consumption."""
        severity = alert.get("severity", "INFO")

        # Map severity to Wazuh level
        level_map = {
            "INFO": 1,
            "WARNING": 5,
            "CRITICAL": 10,
        }
        level = level_map.get(severity, 1)

        return {
            "integration": self.alert_prefix,
            "alert_id": f"{self.alert_prefix}-{int(time.time()*1000)}",
            "description": alert.get("details", {}).get("reason", "Anti-forensic activity detected"),
            "level": level,
            "rule": {
                "id": 100000 + hash(alert.get("event_type", "")) % 10000,
                "description": f"AntiGravity Shield: {alert.get('event_type', 'UNKNOWN')}",
                "level": level,
            },
            "agent": {
                "id": "000",
                "name": socket.gethostname(),
            },
            "manager": {
                "name": socket.gethostname(),
            },
            "data": {
                "module": alert.get("module", "unknown"),
                "event_type": alert.get("event_type", "UNKNOWN"),
                "path": alert.get("path", ""),
                "detection_latency_ms": alert.get("detection_latency_ms"),
                "details": alert.get("details", {}),
            },
            "timestamp": alert.get("detection_wall_time", time.time()),
        }

    def close(self) -> None:
        """Clean up resources."""
        if self._socket:
            try:
                self._socket.close()
            except Exception as e:
                logger.debug(f"Socket close failed (non-critical): {e}")
            self._socket = None
