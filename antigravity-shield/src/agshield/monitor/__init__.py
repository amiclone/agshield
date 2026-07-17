"""
AntiGravity Shield — Monitor Module
====================================
Kernel-level and user-space file system monitoring with
process attribution for real-time anti-forensic detection.

v2.0: Added KernelMonitor (fanotify) and ProcessTracker.
"""

from agshield.monitor.realtime import RealtimeMonitor
from agshield.monitor.kernel_monitor import KernelMonitor
from agshield.monitor.process_tracker import ProcessTracker
from agshield.monitor.canary import CanaryDeployer
from agshield.monitor.timestamp import TimestampValidator
from agshield.monitor.logprotector import LogProtector
from agshield.monitor.behavior import BehavioralDetector

__all__ = [
    "RealtimeMonitor",
    "KernelMonitor",
    "ProcessTracker",
    "CanaryDeployer",
    "TimestampValidator",
    "LogProtector",
    "BehavioralDetector",
]
