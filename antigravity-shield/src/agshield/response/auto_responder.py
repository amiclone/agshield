"""
AntiGravity Shield — Autonomous Response Engine (Human-in-the-Loop)
=====================================================================
Recommends response actions for detected threats and prompts the human
operator to approve or deny. NEVER auto-kills processes.

Design principle: AI detects at machine speed, human decides at human speed.
The shield preserves evidence immediately (no approval needed) but
destructive actions (kill process, quarantine) REQUIRE human approval.
"""
import os
import sys
import time
import shutil
import hashlib
import threading
import json
from datetime import datetime
from typing import Dict, List, Optional, Callable

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


# ANSI colors
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
P = "\033[95m"; C = "\033[96m"; W = "\033[97m"
BOLD = "\033[1m"; DIM = "\033[2m"; X = "\033[0m"


class ResponseAction:
    """A recommended response action awaiting human approval."""

    def __init__(self, action_type: str, target: str, reason: str,
                 severity: str, pid: Optional[int] = None,
                 process_name: str = ""):
        self.id = int(time.time() * 1000) % 100000
        self.action_type = action_type  # KILL_PROCESS, QUARANTINE, SNAPSHOT
        self.target = target
        self.reason = reason
        self.severity = severity
        self.pid = pid
        self.process_name = process_name
        self.timestamp = datetime.now()
        self.status = "PENDING"  # PENDING, APPROVED, DENIED, EXPIRED, AUTO
        self.result = ""

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "action": self.action_type,
            "target": self.target,
            "reason": self.reason,
            "severity": self.severity,
            "pid": self.pid,
            "process": self.process_name,
            "status": self.status,
            "time": self.timestamp.strftime("%H:%M:%S"),
        }


class EvidenceVault:
    """
    Preserves file snapshots before they are destroyed.
    This runs AUTOMATICALLY — no human approval needed for preservation.
    """

    def __init__(self, vault_dir: Optional[str] = None):
        if vault_dir is None:
            home = os.path.expanduser("~")
            vault_dir = os.path.join(home, "Desktop", "shield_evidence_vault")
        self.vault_dir = vault_dir
        os.makedirs(vault_dir, exist_ok=True)
        self.preserved: List[Dict] = []
        self._lock = threading.Lock()

    def preserve_file(self, src_path: str, reason: str) -> Optional[str]:
        """Copy a file to the evidence vault before it's destroyed."""
        try:
            if not os.path.exists(src_path):
                return None
            if os.path.getsize(src_path) > 50 * 1024 * 1024:  # Skip >50MB
                return None

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            basename = os.path.basename(src_path)
            vault_name = f"{timestamp}_{basename}"
            vault_path = os.path.join(self.vault_dir, vault_name)

            shutil.copy2(src_path, vault_path)

            # Hash the preserved copy
            with open(vault_path, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            record = {
                "original_path": src_path,
                "vault_path": vault_path,
                "hash_sha256": file_hash,
                "preserved_at": timestamp,
                "reason": reason,
                "size_bytes": os.path.getsize(vault_path),
            }

            with self._lock:
                self.preserved.append(record)

            return vault_path
        except Exception:
            return None

    def get_preserved(self) -> List[Dict]:
        with self._lock:
            return self.preserved.copy()


class ResponseEngine:
    """
    Human-in-the-loop response engine.

    When a CRITICAL threat is detected:
    1. AUTOMATICALLY preserves the file (evidence vault)
    2. RECOMMENDS an action (kill process, quarantine file)
    3. PROMPTS the human operator to approve or deny
    4. Executes ONLY if human approves

    This design ensures AI speed for detection + human judgment for response.
    """

    def __init__(self, print_fn=None):
        self.vault = EvidenceVault()
        self.print_fn = print_fn or print
        self._lock = threading.Lock()
        self.pending_actions: List[ResponseAction] = []
        self.action_history: List[ResponseAction] = []
        self.auto_preserve = True  # Always auto-preserve evidence

    def _sp(self, msg):
        try:
            self.print_fn(msg)
        except Exception:
            pass

    def on_critical_event(self, event: Dict):
        """Called when a CRITICAL event is detected. Decides response."""
        event_type = event.get("event_type", "")
        path = event.get("path", "")
        pid = event.get("pid")
        process_name = event.get("process_name", "")

        # ── AUTO: Preserve evidence (no approval needed) ──
        if self.auto_preserve and event_type in (
            "WIPE_DETECTED", "TIMESTOMPING_DETECTED", "WIPER_RENAME",
            "ATTACK_CHAIN_EVIDENCE_DESTRUCTION"
        ):
            vault_path = self.vault.preserve_file(path, event_type)
            if vault_path:
                self._sp(
                    f"  {G}[VAULT]{X} Evidence preserved: "
                    f"{C}{os.path.basename(path)}{X} → {DIM}{vault_path}{X}"
                )

        # ── RECOMMEND: Actions requiring human approval ──
        if event_type in ("WIPE_DETECTED", "WIPER_RENAME",
                          "ATTACK_CHAIN_EVIDENCE_DESTRUCTION"):
            if pid and HAS_PSUTIL:
                action = ResponseAction(
                    action_type="KILL_PROCESS",
                    target=f"PID {pid} ({process_name})",
                    reason=f"Process is performing {event_type} on {os.path.basename(path)}",
                    severity="CRITICAL",
                    pid=pid,
                    process_name=process_name,
                )
                self._recommend_action(action)

        if event_type == "TIMESTOMPING_DETECTED":
            action = ResponseAction(
                action_type="QUARANTINE",
                target=path,
                reason=f"File has been timestomped — evidence of anti-forensic manipulation",
                severity="CRITICAL",
            )
            self._recommend_action(action)

    def _recommend_action(self, action: ResponseAction):
        """Display a recommendation to the human operator."""
        with self._lock:
            self.pending_actions.append(action)

        self._sp(f"")
        self._sp(f"  {R}{BOLD}╔══════════════════════════════════════════════════╗{X}")
        self._sp(f"  {R}{BOLD}║  RESPONSE RECOMMENDATION — HUMAN APPROVAL NEEDED ║{X}")
        self._sp(f"  {R}{BOLD}╠══════════════════════════════════════════════════╣{X}")
        self._sp(f"  {R}{BOLD}║{X}  Action:  {Y}{action.action_type}{X}")
        self._sp(f"  {R}{BOLD}║{X}  Target:  {C}{action.target}{X}")
        self._sp(f"  {R}{BOLD}║{X}  Reason:  {W}{action.reason}{X}")
        self._sp(f"  {R}{BOLD}║{X}  ID:      {DIM}#{action.id}{X}")
        self._sp(f"  {R}{BOLD}╠══════════════════════════════════════════════════╣{X}")
        self._sp(f"  {R}{BOLD}║{X}  {G}Type 'approve {action.id}' or 'deny {action.id}'{X}")
        self._sp(f"  {R}{BOLD}╚══════════════════════════════════════════════════╝{X}")
        self._sp(f"")

    def handle_command(self, command: str) -> bool:
        """Process a human command (approve/deny). Returns True if handled."""
        parts = command.strip().lower().split()
        if len(parts) != 2:
            return False
        verb, action_id_str = parts
        if verb not in ("approve", "deny"):
            return False
        try:
            action_id = int(action_id_str)
        except ValueError:
            return False

        with self._lock:
            action = None
            for a in self.pending_actions:
                if a.id == action_id:
                    action = a
                    break
            if not action:
                self._sp(f"  {Y}Action #{action_id} not found{X}")
                return True

            if verb == "approve":
                action.status = "APPROVED"
                self._execute_action(action)
            else:
                action.status = "DENIED"
                self._sp(f"  {Y}[DENIED]{X} Action #{action_id} denied by operator")

            self.pending_actions.remove(action)
            self.action_history.append(action)
        return True

    def _execute_action(self, action: ResponseAction):
        """Execute an approved action."""
        if action.action_type == "KILL_PROCESS" and action.pid and HAS_PSUTIL:
            try:
                proc = psutil.Process(action.pid)
                proc_name = proc.name()
                proc.terminate()
                action.result = f"Process {proc_name} (PID {action.pid}) terminated"
                self._sp(
                    f"  {R}[KILL]{X} {action.result}"
                )
            except Exception as e:
                action.result = f"Failed: {e}"
                self._sp(f"  {Y}[FAIL]{X} Could not kill PID {action.pid}: {e}")

        elif action.action_type == "QUARANTINE":
            vault_path = self.vault.preserve_file(action.target, "QUARANTINED")
            if vault_path:
                action.result = f"Quarantined to {vault_path}"
                self._sp(
                    f"  {G}[QUARANTINE]{X} {os.path.basename(action.target)} "
                    f"→ evidence vault"
                )
            else:
                action.result = "File no longer exists or too large"
                self._sp(f"  {Y}[FAIL]{X} Could not quarantine: file unavailable")

    def get_summary(self) -> Dict:
        """Return response engine summary."""
        return {
            "evidence_preserved": len(self.vault.preserved),
            "actions_pending": len(self.pending_actions),
            "actions_approved": sum(
                1 for a in self.action_history if a.status == "APPROVED"),
            "actions_denied": sum(
                1 for a in self.action_history if a.status == "DENIED"),
            "vault_dir": self.vault.vault_dir,
        }
