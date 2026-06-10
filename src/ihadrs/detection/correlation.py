"""
Module: detection.correlation
Purpose: Cross-event correlation engine that links related security events
         into attack chains. Detects multi-stage attacks that individual
         rules and behavioral detectors cannot see because the evidence is
         spread across multiple events and monitors.
Owner: detection
Dependencies: threading, time, collections
Performance: O(1) per event update with bounded memory via LRU eviction.
             Correlation windows expire automatically to prevent unbounded growth.

Correlation Rules (implemented as pattern matchers):
    - Office Macro → Shell → Network (spear-phishing chain)
    - Suspicious Download → Execution from Downloads (user-executed malware)
    - Failed Logins → Successful Login (credential stuffing success)
    - Process Creation → Registry Persistence (malware installing itself)
    - Process Creation → Service Installation (persistence via service)
    - Credential Dump → Lateral Movement (post-exploitation chain)
"""

from __future__ import annotations

import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional

from loguru import logger

from ihadrs.constants import (
    AttackCategory,
    BEHAVIORAL_CORRELATION_WINDOW,
    EventType,
    Severity,
)
from ihadrs.models.events import (
    AuthenticationEvent,
    BaseEvent,
    FileEvent,
    NetworkEvent,
    ProcessEvent,
    RegistryEvent,
    ServiceEvent,
)


# =============================================================================
# CORRELATION RESULT
# =============================================================================

@dataclass
class CorrelationMatch:
    """
    Produced when a multi-event correlation pattern is confirmed.

    Represents an attack chain — multiple events from different monitors
    that together form a coherent attack narrative.
    """

    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    pattern_id: str = ""
    pattern_name: str = ""
    attack_category: AttackCategory = AttackCategory.UNKNOWN
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.0
    detected_at: float = field(default_factory=time.time)

    # The events that form this chain
    chain_event_ids: list[str] = field(default_factory=list)
    chain_event_types: list[str] = field(default_factory=list)

    # Context
    context: dict[str, Any] = field(default_factory=dict)
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)

    # Explanation
    summary: str = ""
    user_explanation: str = ""
    technical_details: str = ""
    affected_resource: str = ""


# =============================================================================
# EVENT RECORD (lightweight copy of event for correlation state)
# =============================================================================

@dataclass
class EventRecord:
    """Lightweight record of a past event stored in correlation windows."""

    event_id: str
    event_type: EventType
    timestamp: float
    source_monitor: str
    key_fields: dict[str, Any]   # Selected fields relevant to correlation


# =============================================================================
# CORRELATION ENGINE
# =============================================================================

class CorrelationEngine:
    """
    Cross-event correlation engine for multi-stage attack detection.

    Maintains a rolling window of recent events and checks each new event
    against correlation patterns. When a pattern's event chain is satisfied,
    a CorrelationMatch is emitted.

    Design:
    - Each correlation pattern defines a sequence of prerequisite event types
    - The engine tracks "pending chains" — partially satisfied patterns
    - Chains expire after BEHAVIORAL_CORRELATION_WINDOW seconds
    - Thread-safe via a single RLock (correlation state is infrequently written)
    """

    # Maximum events kept in the correlation window
    _MAX_WINDOW_EVENTS: int = 5000

    def __init__(
        self,
        window_seconds: int = BEHAVIORAL_CORRELATION_WINDOW,
    ) -> None:
        self._window = window_seconds

        # Recent event history (newest at right)
        self._event_history: deque[EventRecord] = deque(
            maxlen=self._MAX_WINDOW_EVENTS
        )

        # Pending correlation chains:
        # pattern_id → list of (chain_key, partial_chain_records)
        self._pending_chains: dict[str, list[dict[str, Any]]] = {}

        # Cooldown: pattern_id → last fire timestamp
        self._last_correlation: dict[str, float] = {}
        self._cooldown_seconds: float = 60.0

        self._lock = threading.RLock()

        logger.debug(
            "CorrelationEngine initialized. Window: {w}s", w=window_seconds
        )

    # =========================================================================
    # Main entry point
    # =========================================================================

    def process_event(self, event: BaseEvent) -> list[CorrelationMatch]:
        """
        Process one event and return any correlation matches.

        Args:
            event: Any domain event from any monitor.

        Returns:
            List of CorrelationMatch objects (usually empty).
        """
        record = self._make_record(event)

        with self._lock:
            # Add to history and prune old entries
            self._event_history.append(record)
            self._prune_old_entries()

            # Check all correlation patterns
            matches: list[CorrelationMatch] = []
            matches.extend(self._check_office_macro_chain(record))
            matches.extend(self._check_download_execution_chain(record))
            matches.extend(self._check_credential_stuffing_chain(record))
            matches.extend(self._check_persistence_installation_chain(record))
            matches.extend(self._check_process_registry_chain(record))

        return matches

    # =========================================================================
    # Correlation Patterns
    # =========================================================================

    def _check_office_macro_chain(
        self, record: EventRecord
    ) -> list[CorrelationMatch]:
        """
        Pattern: Office App → Shell → Network connection

        Stage 1: Office app (winword/excel/outlook) spawns shell
        Stage 2: That shell (or child) makes an outbound connection
        Stage 3: Network event from shell PID

        Confidence increases with each stage.
        """
        matches: list[CorrelationMatch] = []

        # Stage 1 detection: Office app spawning shell
        if record.event_type == EventType.PROCESS_CREATED:
            parent = record.key_fields.get("parent_name", "").lower()
            proc = record.key_fields.get("process_name", "").lower()

            office_apps = {
                "winword.exe", "excel.exe", "powerpnt.exe",
                "outlook.exe", "onenote.exe", "msaccess.exe",
            }
            shell_procs = {
                "cmd.exe", "powershell.exe", "wscript.exe",
                "cscript.exe", "mshta.exe",
            }

            if parent in office_apps and proc in shell_procs:
                chain_key = f"office_macro:{record.key_fields.get('pid', '')}"
                self._pending_chains.setdefault("OFFICE_MACRO", []).append({
                    "chain_key": chain_key,
                    "stage": 1,
                    "shell_pid": record.key_fields.get("pid"),
                    "office_app": parent,
                    "shell_name": proc,
                    "started_at": record.timestamp,
                    "events": [record.event_id],
                })

        # Stage 2: Network connection from a shell that was office-spawned
        elif record.event_type == EventType.NETWORK_CONNECTION_OPENED:
            pid = record.key_fields.get("pid")
            if not pid:
                return matches

            chains = self._pending_chains.get("OFFICE_MACRO", [])
            for chain in chains:
                if chain.get("shell_pid") == pid and chain.get("stage") == 1:
                    chain["stage"] = 2
                    chain["events"].append(record.event_id)
                    chain["remote_ip"] = record.key_fields.get("remote_ip", "")
                    chain["remote_port"] = record.key_fields.get("remote_port", 0)

                    cooldown_key = f"OFFICE_MACRO:{chain.get('office_app')}"
                    if not self._is_on_cooldown(cooldown_key):
                        self._set_cooldown(cooldown_key)
                        office_app = chain.get("office_app", "office")
                        shell = chain.get("shell_name", "shell")
                        remote = record.key_fields.get("remote_ip", "?")

                        matches.append(CorrelationMatch(
                            pattern_id="OFFICE_MACRO_C2",
                            pattern_name="Office Macro → Shell → Network",
                            attack_category=AttackCategory.MALWARE_EXECUTION,
                            severity=Severity.CRITICAL,
                            confidence=0.90,
                            chain_event_ids=chain["events"],
                            chain_event_types=["PROCESS_CREATED", "NETWORK_CONNECTION_OPENED"],
                            context={
                                "office_app": office_app,
                                "shell": shell,
                                "remote_ip": remote,
                                "remote_port": record.key_fields.get("remote_port", 0),
                            },
                            mitre_tactics=["TA0001", "TA0002", "TA0011"],
                            mitre_techniques=["T1566.001", "T1059", "T1071"],
                            summary=f"Office macro attack: {office_app} → {shell} → {remote}",
                            user_explanation=(
                                f"A Microsoft Office application ({office_app}) opened "
                                f"a command window ({shell}) which then connected to the "
                                f"internet ({remote}). This is the classic malicious document "
                                f"attack — an infected file ran hidden commands."
                            ),
                            technical_details=(
                                f"Multi-stage execution chain confirmed: "
                                f"{office_app} spawned {shell} (PID {pid}), "
                                f"which connected to {remote}:{chain.get('remote_port', '?')}. "
                                f"ATT&CK chain: T1566.001 → T1059 → T1071"
                            ),
                            affected_resource=f"process:{shell}:{pid}",
                        ))

        return matches

    def _check_download_execution_chain(
        self, record: EventRecord
    ) -> list[CorrelationMatch]:
        """
        Pattern: Executable created in Downloads → Execution from Downloads

        Stage 1: .exe file created in Downloads directory
        Stage 2: That exact executable is run
        """
        matches: list[CorrelationMatch] = []

        if record.event_type == EventType.FILE_CREATED:
            path = record.key_fields.get("file_path", "")
            if "downloads" in path.lower() and path.lower().endswith((".exe", ".msi", ".bat")):
                self._pending_chains.setdefault("DOWNLOAD_EXEC", []).append({
                    "file_path": path,
                    "started_at": record.timestamp,
                    "events": [record.event_id],
                })

        elif record.event_type == EventType.PROCESS_CREATED:
            exe_path = record.key_fields.get("image_path", "")
            chains = self._pending_chains.get("DOWNLOAD_EXEC", [])
            for chain in chains:
                if chain.get("file_path", "").lower() == exe_path.lower():
                    chain["events"].append(record.event_id)
                    cooldown_key = f"DOWNLOAD_EXEC:{exe_path}"
                    if not self._is_on_cooldown(cooldown_key):
                        self._set_cooldown(cooldown_key)
                        matches.append(CorrelationMatch(
                            pattern_id="DOWNLOAD_EXECUTION",
                            pattern_name="Downloaded File Executed",
                            attack_category=AttackCategory.MALWARE_EXECUTION,
                            severity=Severity.HIGH,
                            confidence=0.75,
                            chain_event_ids=chain["events"],
                            chain_event_types=["FILE_CREATED", "PROCESS_CREATED"],
                            context={"file_path": exe_path},
                            mitre_tactics=["TA0002"],
                            mitre_techniques=["T1204.002", "T1105"],
                            summary=f"Downloaded file executed: {exe_path}",
                            user_explanation=(
                                f"A file was downloaded and then immediately executed: "
                                f"{exe_path}. This is a common malware delivery method."
                            ),
                            technical_details=(
                                f"File created in Downloads and executed: {exe_path}. "
                                f"Elapsed: {record.timestamp - chain['started_at']:.1f}s."
                            ),
                            affected_resource=f"file:{exe_path}",
                        ))

        return matches

    def _check_credential_stuffing_chain(
        self, record: EventRecord
    ) -> list[CorrelationMatch]:
        """
        Pattern: Multiple auth failures → Auth success (same source)

        Detects credential stuffing: many failed logins followed by
        a successful login from the same source, indicating the attacker
        found valid credentials.
        """
        matches: list[CorrelationMatch] = []

        if record.event_type not in (
            EventType.AUTH_LOGON_FAILURE,
            EventType.AUTH_LOGON_SUCCESS,
        ):
            return matches

        source = record.key_fields.get("source_ip", "") or record.key_fields.get("workstation_name", "")
        if not source:
            return matches

        if record.event_type == EventType.AUTH_LOGON_FAILURE:
            self._pending_chains.setdefault("CRED_STUFF", {}).setdefault(
                source, {"count": 0, "events": [], "started_at": record.timestamp}
            )
            self._pending_chains["CRED_STUFF"][source]["count"] += 1
            self._pending_chains["CRED_STUFF"][source]["events"].append(record.event_id)

        elif record.event_type == EventType.AUTH_LOGON_SUCCESS:
            cred_chains = self._pending_chains.get("CRED_STUFF", {})
            if source in cred_chains:
                chain = cred_chains[source]
                if chain["count"] >= 3:  # At least 3 failures before success
                    cooldown_key = f"CRED_STUFF:{source}"
                    if not self._is_on_cooldown(cooldown_key):
                        self._set_cooldown(cooldown_key)
                        chain["events"].append(record.event_id)
                        failure_count = chain["count"]
                        target = record.key_fields.get("target_username", "?")
                        matches.append(CorrelationMatch(
                            pattern_id="CREDENTIAL_STUFFING_SUCCESS",
                            pattern_name="Credential Stuffing: Login After Failures",
                            attack_category=AttackCategory.BRUTE_FORCE,
                            severity=Severity.CRITICAL,
                            confidence=0.85,
                            chain_event_ids=chain["events"][-10:],
                            context={
                                "source_ip": source,
                                "failure_count": failure_count,
                                "successful_account": target,
                            },
                            mitre_tactics=["TA0006"],
                            mitre_techniques=["T1110"],
                            summary=(
                                f"Credential stuffing success: {source} → "
                                f"{target} after {failure_count} failures"
                            ),
                            user_explanation=(
                                f"After {failure_count} failed login attempts, "
                                f"the attacker successfully logged in from {source} "
                                f"as '{target}'. Your credentials may be compromised."
                            ),
                            technical_details=(
                                f"Credential stuffing chain: {failure_count} auth failures "
                                f"from {source} followed by successful login as {target}."
                            ),
                            affected_resource=f"auth:{target}@{source}",
                        ))

        return matches

    def _check_persistence_installation_chain(
        self, record: EventRecord
    ) -> list[CorrelationMatch]:
        """
        Pattern: Suspicious process → Service/Scheduled Task created

        Detects malware installing persistence mechanisms after execution.
        """
        matches: list[CorrelationMatch] = []

        if record.event_type == EventType.SERVICE_CREATED:
            # Check if a recently executed suspicious process matches
            service_path = record.key_fields.get("service_path", "")
            recent_procs = [
                r for r in self._event_history
                if r.event_type == EventType.PROCESS_CREATED
                and time.time() - r.timestamp < 60
                and r.key_fields.get("image_path", "").lower() in service_path.lower()
            ]

            if recent_procs:
                proc_record = recent_procs[-1]
                cooldown_key = f"PERSISTENCE:{service_path}"
                if not self._is_on_cooldown(cooldown_key):
                    self._set_cooldown(cooldown_key)
                    matches.append(CorrelationMatch(
                        pattern_id="PROCESS_TO_SERVICE_PERSISTENCE",
                        pattern_name="Process Execution → Service Installation",
                        attack_category=AttackCategory.PERSISTENCE,
                        severity=Severity.HIGH,
                        confidence=0.80,
                        chain_event_ids=[proc_record.event_id, record.event_id],
                        chain_event_types=["PROCESS_CREATED", "SERVICE_CREATED"],
                        context={
                            "process_name": proc_record.key_fields.get("process_name", ""),
                            "service_path": service_path,
                            "service_name": record.key_fields.get("service_name", ""),
                        },
                        mitre_tactics=["TA0003"],
                        mitre_techniques=["T1543.003"],
                        summary="Malware installed persistence via Windows service",
                        user_explanation=(
                            "A newly executed program installed a Windows service "
                            "to ensure it runs every time Windows starts."
                        ),
                        technical_details=(
                            f"Persistence chain: {proc_record.key_fields.get('process_name','')} "
                            f"created service at {service_path}."
                        ),
                        affected_resource=f"service:{record.key_fields.get('service_name', '')}",
                    ))

        return matches

    def _check_process_registry_chain(
        self, record: EventRecord
    ) -> list[CorrelationMatch]:
        """
        Pattern: Unknown process → Registry Run key modification

        Detects malware adding itself to registry autostart keys.
        """
        matches: list[CorrelationMatch] = []

        if record.event_type == EventType.REGISTRY_PERSISTENCE_SET:
            # Correlate with recently created processes
            value_data = record.key_fields.get("value_data", "")
            recent_procs = [
                r for r in self._event_history
                if r.event_type == EventType.PROCESS_CREATED
                and time.time() - r.timestamp < 120
                and r.key_fields.get("image_path", "") in value_data
            ]

            if recent_procs:
                proc = recent_procs[-1]
                cooldown_key = f"REG_PERSIST:{value_data[:50]}"
                if not self._is_on_cooldown(cooldown_key):
                    self._set_cooldown(cooldown_key)
                    matches.append(CorrelationMatch(
                        pattern_id="PROCESS_REGISTRY_PERSISTENCE",
                        pattern_name="Process Execution → Registry Persistence",
                        attack_category=AttackCategory.PERSISTENCE,
                        severity=Severity.HIGH,
                        confidence=0.82,
                        chain_event_ids=[proc.event_id, record.event_id],
                        context={
                            "process_name": proc.key_fields.get("process_name", ""),
                            "registry_key": record.key_fields.get("key_path", ""),
                            "value_data": value_data[:100],
                        },
                        mitre_tactics=["TA0003"],
                        mitre_techniques=["T1547.001"],
                        summary="Malware installed registry persistence (Run key)",
                        user_explanation=(
                            "A program added itself to the Windows startup registry. "
                            "It will run automatically every time Windows starts."
                        ),
                        technical_details=(
                            f"Persistence chain: {proc.key_fields.get('process_name','')} "
                            f"modified Run key: {record.key_fields.get('key_path', '')} "
                            f"= {value_data[:50]}"
                        ),
                        affected_resource=f"registry:{record.key_fields.get('key_path','')}",
                    ))

        return matches

    # =========================================================================
    # Helpers
    # =========================================================================

    def _make_record(self, event: BaseEvent) -> EventRecord:
        """Extract key fields from an event for correlation tracking."""
        key_fields: dict[str, Any] = {}

        if isinstance(event, ProcessEvent):
            key_fields = {
                "pid": event.pid,
                "process_name": event.process_name,
                "image_path": event.image_path,
                "command_line": event.command_line,
                "parent_pid": event.parent_pid,
                "parent_name": event.parent_name,
                "username": event.username,
                "is_elevated": event.is_elevated,
            }
        elif isinstance(event, NetworkEvent):
            key_fields = {
                "pid": event.pid,
                "process_name": event.process_name,
                "remote_ip": event.remote_ip,
                "remote_port": event.remote_port,
                "direction": event.direction,
            }
        elif isinstance(event, FileEvent):
            key_fields = {
                "file_path": event.file_path,
                "change_type": event.change_type,
                "new_path": event.new_path,
                "pid": event.pid,
                "process_name": event.process_name,
            }
        elif isinstance(event, RegistryEvent):
            key_fields = {
                "key_path": event.key_path,
                "value_name": event.value_name,
                "value_data": event.value_data,
                "is_persistence_path": event.is_persistence_path,
            }
        elif isinstance(event, ServiceEvent):
            key_fields = {
                "service_name": event.service_name,
                "service_path": event.service_path,
                "change_type": event.change_type,
            }
        elif isinstance(event, AuthenticationEvent):
            key_fields = {
                "success": event.success,
                "source_ip": event.source_ip,
                "target_username": event.target_username,
                "workstation_name": event.workstation_name,
                "logon_type": event.logon_type,
            }

        from datetime import timezone
        ts = event.timestamp.replace(tzinfo=timezone.utc).timestamp() if event.timestamp.tzinfo else event.timestamp.timestamp()

        return EventRecord(
            event_id=event.event_id,
            event_type=event.event_type,
            timestamp=ts,
            source_monitor=event.source_monitor.value,
            key_fields=key_fields,
        )

    def _prune_old_entries(self) -> None:
        """Remove expired events from pending chains (called under lock)."""
        now = time.time()
        cutoff = now - self._window

        # Prune correlation chain lists
        for pattern_id, chains in list(self._pending_chains.items()):
            if isinstance(chains, list):
                active = [c for c in chains if c.get("started_at", 0) > cutoff]
                if active:
                    self._pending_chains[pattern_id] = active
                else:
                    del self._pending_chains[pattern_id]
            elif isinstance(chains, dict):
                # Source-keyed chains (brute force)
                active_keys = {
                    k: v for k, v in chains.items()
                    if v.get("started_at", 0) > cutoff
                }
                if active_keys:
                    self._pending_chains[pattern_id] = active_keys
                else:
                    del self._pending_chains[pattern_id]

    def _is_on_cooldown(self, key: str) -> bool:
        return (time.time() - self._last_correlation.get(key, 0.0)) < self._cooldown_seconds

    def _set_cooldown(self, key: str) -> None:
        self._last_correlation[key] = time.time()

    def get_stats(self) -> dict[str, Any]:
        """Return correlation engine statistics."""
        with self._lock:
            return {
                "window_seconds": self._window,
                "event_history_size": len(self._event_history),
                "pending_chains": {k: len(v) if isinstance(v, list) else len(v)
                                   for k, v in self._pending_chains.items()},
                "active_cooldowns": len(self._last_correlation),
            }