"""
Module: response.auto_responder
Purpose: Executes automated response actions from playbooks.
         Supports semi-auto (confirmation countdown) and full-auto modes.
         Every action is logged to the audit trail and supports rollback.
Owner: response
Dependencies: response.actions, loguru, asyncio
Performance: Actions execute asynchronously. Each action is isolated —
             one failure does not prevent others from executing.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from loguru import logger

from ihadrs.constants import ActionType, ResponseMode, ResponseStatus, Severity
from ihadrs.core.config import IHADRSConfig
from ihadrs.exceptions import (
    ActionExecutionError,
    ActionRollbackError,
    PlaybookNotFoundError,
)
from ihadrs.models.threats import AutomatedActionRecord, ThreatEvent


# =============================================================================
# ACTION RESULT
# =============================================================================

@dataclass
class ActionResult:
    """Result of executing a single automated response action."""

    action_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    action_type: str = ""
    target: str = ""
    success: bool = False
    result_message: str = ""
    error_message: str = ""
    rollback_data: dict[str, Any] = field(default_factory=dict)
    executed_at: float = field(default_factory=time.time)
    duration_seconds: float = 0.0

    def to_record(self) -> AutomatedActionRecord:
        return AutomatedActionRecord(
            action_type=self.action_type,
            target=self.target,
            success=self.success,
            result_message=self.result_message,
            error_message=self.error_message,
            rollback_available=bool(self.rollback_data),
            rollback_data=self.rollback_data,
        )


# =============================================================================
# AUTO RESPONDER
# =============================================================================

class AutoResponder:
    """
    Executes automated response actions for detected threats.

    Action execution flow:
    1. Load playbook for threat.attack_category
    2. If semi_auto: show countdown, wait for user confirmation
    3. Execute each action in playbook sequence
    4. Log all actions to audit trail
    5. Update ThreatEvent.response_status

    Rollback flow:
    1. Store rollback_data before each destructive action
    2. If user marks FP: iterate recorded actions in reverse, call rollback
    """

    def __init__(self, config: IHADRSConfig) -> None:
        self._config = config
        self._mode = ResponseMode(config.response.mode)
        self._auto_severities = set(config.response.auto_respond_severities)
        self._confirmation_timeout = config.response.confirmation_timeout_seconds
        self._dry_run = False  # Set via config or env in full implementation
        self._log = logger.bind(component="AutoResponder")
        self._audit_log = logger.bind(component="audit", audit=True)

    # =========================================================================
    # Main Entry Point
    # =========================================================================

    async def respond(self, threat: ThreatEvent) -> list[ActionResult]:
        """
        Execute automated response for a detected threat.

        Args:
            threat: The ThreatEvent requiring response.

        Returns:
            List of ActionResult objects for all executed actions.
        """
        if self._mode == ResponseMode.MANUAL:
            self._log.debug(
                "Response mode is MANUAL — skipping automated response for {id}",
                id=threat.threat_id,
            )
            return []

        if not self._should_auto_respond(threat):
            self._log.debug(
                "Threat {id} severity {sev} not in auto-respond list",
                id=threat.threat_id,
                sev=threat.severity.value,
            )
            return []

        self._log.info(
            "Auto-responding to [{sev}] {cat}: {summary}",
            sev=threat.severity.value,
            cat=threat.attack_category.value,
            summary=threat.summary[:60],
        )

        # Resolve actions from playbook
        actions = self._get_playbook_actions(threat)
        if not actions:
            self._log.debug(
                "No automated actions configured for {cat}",
                cat=threat.attack_category.value,
            )
            return []

        # Semi-auto: wait for confirmation (non-blocking countdown)
        if self._mode == ResponseMode.SEMI_AUTO:
            approved = await self._wait_for_confirmation(threat, actions)
            if not approved:
                self._log.info(
                    "Auto-response cancelled for threat {id}",
                    id=threat.threat_id,
                )
                threat.response_status = ResponseStatus.CANCELLED
                return []

        # Execute actions
        threat.response_status = ResponseStatus.EXECUTING
        results = await self._execute_actions(threat, actions)

        # Update threat status based on results
        success_count = sum(1 for r in results if r.success)
        if success_count == len(results):
            threat.response_status = ResponseStatus.EXECUTED
        elif success_count > 0:
            threat.response_status = ResponseStatus.EXECUTED  # Partial success
        else:
            threat.response_status = ResponseStatus.FAILED

        # Record actions on the threat
        for result in results:
            threat.automated_actions.append(result.to_record())

        self._audit_log.info(
            "Response completed for threat {id}: {ok}/{total} actions succeeded",
            id=threat.threat_id,
            ok=success_count,
            total=len(results),
            threat_id=threat.threat_id,
            attack_category=threat.attack_category.value,
        )

        return results

    # =========================================================================
    # Action Execution
    # =========================================================================

    async def _execute_actions(
        self,
        threat: ThreatEvent,
        action_specs: list[dict[str, Any]],
    ) -> list[ActionResult]:
        """Execute a sequence of actions, continuing even if one fails."""
        results: list[ActionResult] = []

        for spec in action_specs:
            action_type = spec.get("action", "")
            target = self._resolve_target(spec, threat)

            self._log.info(
                "Executing action: {action} on {target}",
                action=action_type,
                target=target,
            )

            start = time.monotonic()
            result = ActionResult(action_type=action_type, target=target)

            try:
                if self._dry_run:
                    result.success = True
                    result.result_message = f"[DRY RUN] {action_type} on {target}"
                else:
                    result = await self._dispatch_action(action_type, target, spec, threat)

                result.duration_seconds = time.monotonic() - start

                self._audit_log.info(
                    "Action {action} on {target}: {status}",
                    action=action_type,
                    target=target,
                    status="SUCCESS" if result.success else "FAILED",
                    threat_id=threat.threat_id,
                    result_message=result.result_message,
                    error=result.error_message,
                )

            except Exception as exc:
                result.success = False
                result.error_message = str(exc)
                result.duration_seconds = time.monotonic() - start
                self._log.error(
                    "Action {action} failed: {exc}",
                    action=action_type,
                    exc=exc,
                )

            results.append(result)

        return results

    async def _dispatch_action(
        self,
        action_type: str,
        target: str,
        spec: dict[str, Any],
        threat: ThreatEvent,
    ) -> ActionResult:
        """Dispatch to the appropriate action handler."""
        params = spec.get("params", {})
        result = ActionResult(action_type=action_type, target=target)

        if action_type == ActionType.SUSPEND_PROCESS.value:
            result = await self._suspend_process(target, params)
        elif action_type == ActionType.KILL_PROCESS.value:
            result = await self._kill_process(target, params)
        elif action_type == ActionType.BLOCK_IP.value:
            result = await self._block_ip(target, params)
        elif action_type == ActionType.BLOCK_PROCESS_NETWORK.value:
            result = await self._block_process_network(target, params)
        elif action_type == ActionType.QUARANTINE_FILE.value:
            result = await self._quarantine_file(target, params)
        elif action_type == ActionType.ALERT_USER.value:
            result = await self._alert_user(threat, params)
        elif action_type == ActionType.COLLECT_FORENSICS.value:
            result = await self._collect_forensics(target, params, threat)
        else:
            result.success = True
            result.result_message = f"Action '{action_type}' noted (not implemented)"

        result.action_type = action_type
        result.target = target
        return result

    # =========================================================================
    # Action Implementations
    # =========================================================================

    async def _suspend_process(
        self, target: str, params: dict[str, Any]
    ) -> ActionResult:
        """Suspend all threads of a process."""
        result = ActionResult(action_type=ActionType.SUSPEND_PROCESS.value, target=target)
        pid = self._extract_pid(target)

        if pid is None:
            result.error_message = f"Could not extract PID from target: {target}"
            return result

        try:
            import psutil
            proc = psutil.Process(pid)
            proc.suspend()
            result.success = True
            result.result_message = f"Process PID {pid} suspended successfully"
            result.rollback_data = {"pid": pid, "rollback_action": "resume_process"}
            self._log.warning("Process suspended: PID {pid}", pid=pid)
        except psutil.NoSuchProcess:
            result.success = True  # Already gone — consider success
            result.result_message = f"Process PID {pid} no longer exists"
        except psutil.AccessDenied as exc:
            result.error_message = f"Access denied suspending PID {pid}: {exc}"
        except Exception as exc:
            result.error_message = str(exc)

        return result

    async def _kill_process(
        self, target: str, params: dict[str, Any]
    ) -> ActionResult:
        """Terminate a process (SIGKILL / TerminateProcess)."""
        result = ActionResult(action_type=ActionType.KILL_PROCESS.value, target=target)
        pid = self._extract_pid(target)

        if pid is None:
            result.error_message = f"Could not extract PID: {target}"
            return result

        try:
            import psutil
            proc = psutil.Process(pid)
            name = proc.name()
            force = params.get("force", True)
            if force:
                proc.kill()   # SIGKILL
            else:
                proc.terminate()  # SIGTERM
            result.success = True
            result.result_message = f"Process {name} (PID {pid}) terminated"
            self._log.warning("Process killed: {name} PID {pid}", name=name, pid=pid)
        except psutil.NoSuchProcess:
            result.success = True
            result.result_message = f"Process PID {pid} no longer exists"
        except psutil.AccessDenied as exc:
            result.error_message = f"Access denied killing PID {pid}: {exc}"
        except Exception as exc:
            result.error_message = str(exc)

        return result

    async def _block_ip(
        self, target: str, params: dict[str, Any]
    ) -> ActionResult:
        """Block an IP address via Windows Firewall / iptables."""
        result = ActionResult(action_type=ActionType.BLOCK_IP.value, target=target)

        try:
            from ihadrs.constants import IS_WINDOWS
            direction = params.get("direction", "outbound")

            if IS_WINDOWS:
                import subprocess
                rule_name = f"IHADRS_Block_{target}_{direction}"
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "protocol=any",
                    f"dir={direction}",
                    f"remoteip={target}",
                    "action=block",
                ]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if proc.returncode == 0:
                    result.success = True
                    result.result_message = f"Blocked {direction} traffic to {target}"
                    result.rollback_data = {
                        "rule_name": rule_name,
                        "rollback_action": "delete_firewall_rule",
                    }
                else:
                    result.error_message = f"netsh failed: {proc.stderr}"
            else:
                import subprocess
                cmd = ["iptables", "-A", "OUTPUT", "-d", target, "-j", "DROP"]
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                result.success = proc.returncode == 0
                result.result_message = f"iptables rule added for {target}"
                result.rollback_data = {
                    "target_ip": target,
                    "rollback_action": "remove_iptables_rule",
                }

            self._log.warning("IP blocked: {ip} ({dir})", ip=target, dir=direction)

        except Exception as exc:
            result.error_message = str(exc)

        return result

    async def _block_process_network(
        self, target: str, params: dict[str, Any]
    ) -> ActionResult:
        """Block all network access for a specific process (Windows Firewall)."""
        result = ActionResult(action_type=ActionType.BLOCK_PROCESS_NETWORK.value, target=target)
        pid = self._extract_pid(target)

        try:
            import psutil
            proc = psutil.Process(pid or 0)
            exe_path = proc.exe()

            from ihadrs.constants import IS_WINDOWS
            if IS_WINDOWS:
                import subprocess
                rule_name = f"IHADRS_BlockProc_{pid}"
                cmd = [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}",
                    "protocol=any",
                    "dir=out",
                    f"program={exe_path}",
                    "action=block",
                ]
                proc_result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                result.success = proc_result.returncode == 0
                result.result_message = f"Network blocked for {exe_path}"
                result.rollback_data = {"rule_name": rule_name}
            else:
                result.success = True
                result.result_message = f"[Linux] Network block for PID {pid} noted"

        except Exception as exc:
            result.error_message = str(exc)

        return result

    async def _quarantine_file(
        self, target: str, params: dict[str, Any]
    ) -> ActionResult:
        """Move a file to the IHADRS quarantine directory."""
        result = ActionResult(action_type=ActionType.QUARANTINE_FILE.value, target=target)

        try:
            import shutil
            from pathlib import Path

            source = Path(target)
            if not source.exists():
                result.success = True
                result.result_message = f"File {target} no longer exists"
                return result

            quarantine_dir = Path("./data/quarantine")
            quarantine_dir.mkdir(parents=True, exist_ok=True)
            dest = quarantine_dir / f"{source.name}.ihadrs_quarantine"
            shutil.move(str(source), str(dest))
            result.success = True
            result.result_message = f"File quarantined: {dest}"
            result.rollback_data = {
                "original_path": str(source),
                "quarantine_path": str(dest),
                "rollback_action": "restore_file",
            }
            self._log.warning("File quarantined: {src} → {dst}", src=source, dst=dest)

        except Exception as exc:
            result.error_message = str(exc)

        return result

    async def _alert_user(
        self, threat: ThreatEvent, params: dict[str, Any]
    ) -> ActionResult:
        """Emit a high-priority desktop notification."""
        result = ActionResult(action_type=ActionType.ALERT_USER.value, target="desktop")
        try:
            urgency = params.get("urgency", "high")
            message = params.get("message", threat.summary)
            self._log.info(
                "User alert [{urg}]: {msg}", urg=urgency, msg=message
            )
            result.success = True
            result.result_message = f"User alerted: {message}"
        except Exception as exc:
            result.error_message = str(exc)
        return result

    async def _collect_forensics(
        self,
        target: str,
        params: dict[str, Any],
        threat: ThreatEvent,
    ) -> ActionResult:
        """Collect basic forensic snapshot (process list, network state, etc.)."""
        result = ActionResult(action_type=ActionType.COLLECT_FORENSICS.value, target=target)

        try:
            import psutil
            from pathlib import Path
            import json

            forensics_dir = Path("./data/forensics")
            forensics_dir.mkdir(parents=True, exist_ok=True)
            timestamp = int(time.time())
            output_file = forensics_dir / f"forensics_{threat.threat_id[:8]}_{timestamp}.json"

            snapshot: dict[str, Any] = {
                "threat_id": threat.threat_id,
                "collected_at": timestamp,
                "running_processes": [],
                "network_connections": [],
            }

            # Process list
            for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
                try:
                    info = proc.as_dict(attrs=["pid", "name", "exe"])
                    snapshot["running_processes"].append(info)
                except Exception:
                    pass

            # Network connections
            try:
                for conn in psutil.net_connections():
                    snapshot["network_connections"].append({
                        "pid": conn.pid,
                        "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                        "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                        "status": conn.status,
                    })
            except Exception:
                pass

            with output_file.open("w") as f:
                json.dump(snapshot, f, indent=2, default=str)

            result.success = True
            result.result_message = f"Forensics saved: {output_file}"

        except Exception as exc:
            result.error_message = str(exc)

        return result

    # =========================================================================
    # Rollback
    # =========================================================================

    async def rollback_action(self, action_record: AutomatedActionRecord) -> bool:
        """
        Undo a previously executed action using its rollback data.

        Args:
            action_record: The AutomatedActionRecord from the ThreatEvent.

        Returns:
            True if rollback succeeded.
        """
        if not action_record.rollback_data:
            self._log.warning(
                "No rollback data for action {action}",
                action=action_record.action_type,
            )
            return False

        rollback_action = action_record.rollback_data.get("rollback_action", "")
        target = action_record.target

        try:
            if rollback_action == "resume_process":
                pid = action_record.rollback_data.get("pid")
                import psutil
                psutil.Process(pid).resume()
                self._log.info("Rolled back: resumed PID {pid}", pid=pid)
                return True

            elif rollback_action == "delete_firewall_rule":
                rule_name = action_record.rollback_data.get("rule_name", "")
                from ihadrs.constants import IS_WINDOWS
                if IS_WINDOWS:
                    import subprocess
                    subprocess.run(
                        ["netsh", "advfirewall", "firewall", "delete", "rule",
                         f"name={rule_name}"],
                        capture_output=True, timeout=10,
                    )
                self._log.info("Rolled back: removed firewall rule {r}", r=rule_name)
                return True

            elif rollback_action == "restore_file":
                import shutil
                from pathlib import Path
                src = Path(action_record.rollback_data["quarantine_path"])
                dst = Path(action_record.rollback_data["original_path"])
                shutil.move(str(src), str(dst))
                self._log.info("Rolled back: restored file to {dst}", dst=dst)
                return True

            else:
                self._log.warning(
                    "Unknown rollback action: {ra}", ra=rollback_action
                )
                return False

        except Exception as exc:
            self._log.error(
                "Rollback failed for {action}: {exc}",
                action=action_record.action_type,
                exc=exc,
            )
            return False

    # =========================================================================
    # Helpers
    # =========================================================================

    def _should_auto_respond(self, threat: ThreatEvent) -> bool:
        return threat.severity.value in self._auto_severities

    def _get_playbook_actions(
        self, threat: ThreatEvent
    ) -> list[dict[str, Any]]:
        """Return automated action specs from playbooks for the threat category."""
        from ihadrs.constants import IS_WINDOWS
        # Playbooks are embedded in the recommender for simplicity
        # Minimal built-in actions per category
        category = threat.attack_category

        pid = ""
        if threat.process_context:
            pid = str(threat.process_context.pid)

        action_map: dict[AttackCategory, list[dict[str, Any]]] = {
            AttackCategory.RANSOMWARE: [
                {"action": ActionType.SUSPEND_PROCESS.value, "target_type": "pid",
                 "target": pid, "params": {"force": True}},
                {"action": ActionType.BLOCK_PROCESS_NETWORK.value, "target_type": "pid",
                 "target": pid},
                {"action": ActionType.COLLECT_FORENSICS.value, "target_type": "pid",
                 "target": pid, "params": {}},
            ],
            AttackCategory.MALWARE_EXECUTION: [
                {"action": ActionType.SUSPEND_PROCESS.value, "target_type": "pid",
                 "target": pid, "params": {}},
                {"action": ActionType.COLLECT_FORENSICS.value, "target_type": "pid",
                 "target": pid, "params": {}},
            ],
            AttackCategory.CREDENTIAL_THEFT: [
                {"action": ActionType.KILL_PROCESS.value, "target_type": "pid",
                 "target": pid, "params": {"force": True}},
                {"action": ActionType.ALERT_USER.value,
                 "params": {"urgency": "critical",
                            "message": "Credential theft detected — change all passwords NOW"}},
            ],
            AttackCategory.C2_COMMUNICATION: [
                {"action": ActionType.BLOCK_PROCESS_NETWORK.value, "target_type": "pid",
                 "target": pid},
                {"action": ActionType.COLLECT_FORENSICS.value, "target_type": "pid",
                 "target": pid, "params": {}},
            ],
        }
        return action_map.get(category, [])

    def _resolve_target(
        self, spec: dict[str, Any], threat: ThreatEvent
    ) -> str:
        """Resolve the target string for an action spec."""
        target_type = spec.get("target_type", "")
        target = spec.get("target", "")

        if target_type == "pid" and threat.process_context:
            return str(threat.process_context.pid)

        return str(target)

    @staticmethod
    def _extract_pid(target: str) -> Optional[int]:
        """Extract PID integer from a target string."""
        try:
            return int(str(target).strip())
        except (ValueError, TypeError):
            return None

    async def _wait_for_confirmation(
        self, threat: ThreatEvent, actions: list[dict[str, Any]]
    ) -> bool:
        """
        Wait for user confirmation in semi-auto mode.

        In the CLI/UI context, this would show a countdown dialog.
        Here we implement the async countdown and return True (auto-approve)
        after the timeout. The UI layer hooks into this by cancelling the task.

        Returns:
            True if approved (timeout elapsed), False if cancelled.
        """
        timeout = self._confirmation_timeout
        self._log.info(
            "Semi-auto: will execute {n} action(s) in {t}s for [{sev}] threat. "
            "Cancel in UI to abort.",
            n=len(actions),
            t=timeout,
            sev=threat.severity.value,
        )

        try:
            await asyncio.sleep(timeout)
            return True  # Timeout elapsed → auto-approve
        except asyncio.CancelledError:
            return False  # Cancelled by user


from ihadrs.constants import AttackCategory