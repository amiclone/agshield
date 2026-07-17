"""
AntiGravity Shield
==================
Real-time AI anti-forensic detection and mitigation framework.

Detects and mitigates autonomous AI-driven anti-forensic operations
that evade traditional periodic File Integrity Monitoring (FIM).

v2.0: Kernel-level monitoring via fanotify with process attribution.

Author: Emmanuel Chukwudinma Orji
Version: 2.0.0
"""

__version__ = "2.0.0"
__author__ = "Emmanuel Chukwudinma Orji"
__email__ = "emmanuel.orji@example.com"

from agshield.config import Config
from agshield.daemon import ShieldDaemon
from agshield.detection.engine import DetectionEngine
from agshield.monitor.realtime import RealtimeMonitor
from agshield.monitor.kernel_monitor import KernelMonitor
from agshield.monitor.process_tracker import ProcessTracker
from agshield.integration.wazuh import WazuhIntegration

__all__ = [
    "Config",
    "ShieldDaemon",
    "DetectionEngine",
    "RealtimeMonitor",
    "KernelMonitor",
    "ProcessTracker",
    "WazuhIntegration",
]
