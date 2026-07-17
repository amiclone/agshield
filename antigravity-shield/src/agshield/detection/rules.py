"""
AntiGravity Shield — Detection Rules Engine
============================================
Configurable rule-based detection system.
Allows defining custom detection rules that evaluate alerts
and trigger additional actions or escalate severity.
"""

import time
import logging
from typing import Callable, Dict, List, Optional

logger = logging.getLogger("antigravity.detection.rules")


class DetectionRule:
    """
    A single detection rule that evaluates alerts and can trigger actions.
    """

    def __init__(self, name: str, condition: Callable[[dict], bool],
                 action: Optional[Callable[[dict], None]] = None,
                 severity: str = "INFO", description: str = ""):
        self.name = name
        self.condition = condition
        self.action = action
        self.severity = severity
        self.description = description
        self.trigger_count = 0

    def evaluate(self, alert: dict) -> bool:
        """Evaluate the rule against an alert."""
        if self.condition(alert):
            self.trigger_count += 1
            if self.action:
                self.action(alert)
            return True
        return False


class RuleEngine:
    """
    Manages a collection of detection rules and evaluates them
    against incoming alerts.
    """

    def __init__(self, alert_callback: Optional[Callable] = None):
        self.alert_callback = alert_callback
        self.rules: List[DetectionRule] = []
        self._setup_default_rules()

    def _setup_default_rules(self) -> None:
        """Set up the default detection rules for anti-forensic activity."""

        # Rule: Detect rapid file creation + deletion (evidence staging)
        self.add_rule(DetectionRule(
            name="evidence_staging",
            condition=lambda a: (
                a.get("event_type") == "FILE_CREATED"
                and a.get("details", {}).get("size", 0) > 100
            ),
            action=self._escalate_if_suspicious,
            severity="WARNING",
            description="Detects creation of potentially staged evidence files",
        ))

        # Rule: Detect executable creation in unusual locations
        self.add_rule(DetectionRule(
            name="suspicious_executable",
            condition=lambda a: (
                a.get("event_type") == "FILE_CREATED"
                and a.get("path", "").endswith((".exe", ".bat", ".ps1", ".sh"))
            ),
            action=None,
            severity="WARNING",
            description="Detects creation of executable files",
        ))

        # Rule: Detect mass file operations (automated tool signature)
        self.add_rule(DetectionRule(
            name="mass_operation",
            condition=lambda a: (
                a.get("event_type") in ("FILE_DELETED", "FILE_MOVED")
                and a.get("path", "") == "multiple"
            ),
            action=None,
            severity="CRITICAL",
            description="Detects mass file operations indicative of automated tools",
        ))

    def add_rule(self, rule: DetectionRule) -> None:
        """Add a custom detection rule."""
        self.rules.append(rule)
        logger.info(f"Added detection rule: {rule.name}")

    def evaluate(self, alert: dict) -> List[DetectionRule]:
        """Evaluate all rules against an alert."""
        triggered = []
        for rule in self.rules:
            if rule.evaluate(alert):
                triggered.append(rule)
                logger.debug(f"Rule '{rule.name}' triggered for alert {alert.get('event_type')}")

        # Escalate if multiple rules fire
        if len(triggered) >= 2 and self.alert_callback:
            alert_copy = alert.copy()
            alert_copy["severity"] = "CRITICAL"
            alert_copy["details"]["escalation_reason"] = (
                f"Multiple rules triggered: {', '.join(r.name for r in triggered)}"
            )
            self.alert_callback(alert_copy)

        return triggered

    def _escalate_if_suspicious(self, alert: dict) -> None:
        """Escalate alert severity if suspicious patterns are detected."""
        if alert.get("severity") == "INFO":
            alert["severity"] = "WARNING"
            alert["details"]["escalated_by"] = "rule_engine"

    def get_stats(self) -> Dict:
        """Return rule trigger statistics."""
        return {
            "total_rules": len(self.rules),
            "rule_stats": {
                rule.name: rule.trigger_count for rule in self.rules
            },
        }
