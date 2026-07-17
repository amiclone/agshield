"""
AntiGravity Shield — Integration Module
========================================
Integrations with external systems (Wazuh, SIEM, etc.)
"""

from agshield.integration.wazuh import WazuhIntegration

__all__ = ["WazuhIntegration"]
