"""
AntiGravity Shield — Attack Chain Correlator
==============================================
Groups individual file system events into coherent "incidents" and
detects multi-phase attack patterns (staging → timestomping → wiping → cleanup).

This is what separates an AI-powered tool from a traditional rule-based monitor:
individual events may be benign, but the SEQUENCE reveals malicious intent.
"""
import time
import threading
from collections import defaultdict
from typing import Dict, List, Optional


# Known attack phase signatures (ordered sequences)
ATTACK_PATTERNS = {
    "EVIDENCE_DESTRUCTION": {
        "phases": ["CREATE", "MODIFY", "WIPE", "RENAME_RANDOM", "DELETE"],
        "min_match": 3,
        "description": "Coordinated evidence destruction: files created, overwritten, renamed to random strings, then deleted",
    },
    "TIMESTOMP_CAMPAIGN": {
        "phases": ["CREATE", "MODIFY", "TIMESTOMP"],
        "min_match": 2,
        "description": "Timestamp manipulation campaign: files created/modified then backdated to evade timeline analysis",
    },
    "DATA_EXFILTRATION": {
        "phases": ["CREATE", "MODIFY", "DELETE"],
        "min_match": 3,
        "description": "Rapid file staging and cleanup: data staged then destroyed, consistent with exfiltration",
    },
    "LOG_TAMPERING": {
        "phases": ["MODIFY", "DELETE"],
        "min_match": 2,
        "description": "Log file tampering: log files modified (truncated) then deleted to erase audit trail",
    },
}

# Map event_type strings to phase labels
EVENT_TO_PHASE = {
    "FILE_CREATED": "CREATE",
    "SUSPICIOUS_FILE_CREATED": "CREATE",
    "FILE_MODIFIED": "MODIFY",
    "WIPE_DETECTED": "WIPE",
    "TIMESTOMPING_DETECTED": "TIMESTOMP",
    "WIPER_RENAME": "RENAME_RANDOM",
    "FILE_DELETED": "DELETE",
    "FILE_RENAMED": "RENAME",
    "EPHEMERAL_FILE": "EPHEMERAL",
    "OPERATION_BURST": "BURST",
}


class Incident:
    """A group of related events forming a potential attack."""

    def __init__(self, incident_id: int):
        self.id = incident_id
        self.events: List[Dict] = []
        self.start_time: float = 0
        self.end_time: float = 0
        self.phases_seen: List[str] = []
        self.files_involved: set = set()
        self.processes_involved: set = set()
        self.matched_pattern: Optional[str] = None
        self.threat_score: int = 0
        self.classified: bool = False

    def add_event(self, event: Dict):
        now = time.time()
        if not self.events:
            self.start_time = now
        self.end_time = now
        self.events.append(event)

        phase = EVENT_TO_PHASE.get(event.get("event_type", ""), "UNKNOWN")
        self.phases_seen.append(phase)

        path = event.get("path", "")
        if path:
            self.files_involved.add(path)

        pid = event.get("pid", "")
        if pid:
            self.processes_involved.add(str(pid))

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time if self.end_time else 0

    @property
    def severity_counts(self) -> Dict[str, int]:
        counts = defaultdict(int)
        for e in self.events:
            counts[e.get("severity", "INFO")] += 1
        return dict(counts)

    def to_dict(self) -> Dict:
        return {
            "incident_id": self.id,
            "event_count": len(self.events),
            "duration_seconds": round(self.duration, 2),
            "files_involved": len(self.files_involved),
            "processes_involved": list(self.processes_involved),
            "phases": self.phases_seen,
            "matched_pattern": self.matched_pattern,
            "threat_score": self.threat_score,
            "severity_breakdown": self.severity_counts,
        }


class ChainCorrelator:
    """
    Groups file events into incidents and classifies attack chains.

    Events within `window_seconds` of each other are grouped.
    Each group is then checked against known attack patterns.
    """

    def __init__(self, window_seconds: float = 30.0, alert_callback=None):
        self.window = window_seconds
        self.alert_callback = alert_callback
        self._lock = threading.Lock()
        self._current_incident: Optional[Incident] = None
        self._incidents: List[Incident] = []
        self._next_id = 1

    def process_event(self, event: Dict):
        """Feed an event into the correlator."""
        with self._lock:
            now = time.time()

            # Start new incident if none active or window expired
            if (self._current_incident is None or
                    now - self._current_incident.end_time > self.window):
                # Classify and store the old incident
                if self._current_incident and not self._current_incident.classified:
                    self._classify_incident(self._current_incident)
                # Start new
                self._current_incident = Incident(self._next_id)
                self._next_id += 1

            self._current_incident.add_event(event)

            # Re-classify on every event (live updates)
            self._classify_incident(self._current_incident)

    def _classify_incident(self, incident: Incident):
        """Check incident against known attack patterns and score it."""
        phases = incident.phases_seen
        best_match = None
        best_score = 0

        for pattern_name, pattern in ATTACK_PATTERNS.items():
            required = pattern["phases"]
            min_match = pattern["min_match"]

            # Count how many required phases are present (in order)
            matched = 0
            phase_idx = 0
            for p in phases:
                if phase_idx < len(required) and p == required[phase_idx]:
                    matched += 1
                    phase_idx += 1

            if matched >= min_match:
                score = int((matched / len(required)) * 100)
                if score > best_score:
                    best_score = score
                    best_match = pattern_name

        # Base threat score from severity
        sev_scores = {"CRITICAL": 30, "WARNING": 10, "INFO": 2}
        threat = sum(sev_scores.get(e.get("severity", "INFO"), 0)
                     for e in incident.events)

        # Bonus for pattern match
        if best_match:
            threat += best_score

        # Bonus for speed (faster = more automated = more suspicious)
        if incident.duration > 0 and len(incident.events) > 3:
            ops_per_sec = len(incident.events) / incident.duration
            if ops_per_sec > 2:
                threat += int(ops_per_sec * 10)

        # Bonus for multiple files
        if len(incident.files_involved) > 5:
            threat += 20

        incident.matched_pattern = best_match
        incident.threat_score = min(threat, 100)  # Cap at 100
        incident.classified = True

        # Fire alert if this is a new high-threat incident
        if best_match and self.alert_callback and threat >= 50:
            pattern_desc = ATTACK_PATTERNS[best_match]["description"]
            self.alert_callback({
                "severity": "CRITICAL",
                "event_type": f"ATTACK_CHAIN_{best_match}",
                "path": f"{len(incident.files_involved)} files",
                "reason": (
                    f"Attack chain detected: {best_match} "
                    f"(threat score: {threat}/100, "
                    f"{len(incident.events)} events in {incident.duration:.1f}s). "
                    f"{pattern_desc}"
                ),
            })

    def get_incidents(self) -> List[Dict]:
        """Return all incidents as dicts."""
        with self._lock:
            # Classify current if pending
            if self._current_incident and not self._current_incident.classified:
                self._classify_incident(self._current_incident)
            all_incidents = self._incidents.copy()
            if self._current_incident:
                all_incidents.append(self._current_incident)
            return [i.to_dict() for i in all_incidents]

    def get_summary(self) -> Dict:
        """Return a summary of all incidents."""
        incidents = self.get_incidents()
        return {
            "total_incidents": len(incidents),
            "attack_chains_detected": sum(
                1 for i in incidents if i["matched_pattern"]),
            "highest_threat_score": max(
                (i["threat_score"] for i in incidents), default=0),
            "patterns_found": list(set(
                i["matched_pattern"] for i in incidents
                if i["matched_pattern"])),
        }
