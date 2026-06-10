"""
Module: monitors.auth_monitor
Purpose: Authentication event monitoring.
         Windows: reads Security Event Log (Event IDs 4624, 4625, etc.)
         Linux: parses /var/log/auth.log for PAM/SSH events.
Owner: monitors
"""
from __future__ import annotations

import asyncio
import re
import socket
import subprocess
import time
from datetime import datetime, timezone
from typing import Any, Optional

from ihadrs.constants import IS_WINDOWS, WINDOWS_EVENT_IDS, MonitorType, EventType
from ihadrs.core.config import IHADRSConfig
from ihadrs.core.event_bus import EventBus, EventPriority
from ihadrs.core.resource_manager import ResourceManager
from ihadrs.exceptions import MonitorInitializationError
from ihadrs.models.events import AuthenticationEvent
from ihadrs.monitors.base import BaseMonitor


class AuthMonitor(BaseMonitor):
    """
    Authentication event monitor — cross-platform.

    Windows: Uses PowerShell Get-EventLog to read Security Event Log.
    Linux:   Parses /var/log/auth.log using tail.
    """

    def __init__(
        self,
        config: IHADRSConfig,
        event_bus: EventBus,
        resource_manager: Optional[ResourceManager] = None,
    ) -> None:
        super().__init__(config, event_bus, resource_manager)
        self._monitor_type = MonitorType.AUTHENTICATION
        self._poll_interval = config.monitors.auth_poll_interval
        self._status.monitor_type = MonitorType.AUTHENTICATION
        self._status.name = "AuthMonitor"
        self._status.poll_interval_seconds = self._poll_interval
        self._hostname = socket.gethostname()
        self._last_event_time: float = time.time()

    async def initialize(self) -> None:
        if IS_WINDOWS:
            await self._init_windows()
        else:
            await self._init_linux()
        self._mark_initialized()

    async def _init_windows(self) -> None:
        """Verify access to Windows Security Event Log."""
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "Get-EventLog -LogName Security -Newest 1 -ErrorAction Stop | "
                 "Select-Object -ExpandProperty EventID"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                raise MonitorInitializationError(
                    "AuthMonitor",
                    f"Cannot read Security Event Log: {result.stderr}",
                )
            self._log.info("AuthMonitor: Windows Security Event Log accessible.")
        except subprocess.TimeoutExpired:
            raise MonitorInitializationError(
                "AuthMonitor",
                "Timeout reading Security Event Log — run as Administrator.",
            )
        except FileNotFoundError:
            raise MonitorInitializationError(
                "AuthMonitor",
                "PowerShell not found — required for Windows auth monitoring.",
            )

    async def _init_linux(self) -> None:
        """Verify access to auth.log on Linux."""
        import os
        auth_logs = ["/var/log/auth.log", "/var/log/secure"]
        for log_path in auth_logs:
            if os.path.exists(log_path):
                self._auth_log_path = log_path
                self._log.info("AuthMonitor: Using {p}", p=log_path)
                return
        raise MonitorInitializationError(
            "AuthMonitor",
            "No auth log found at /var/log/auth.log or /var/log/secure.",
        )

    async def stop(self) -> None:
        await self._base_stop()

    async def _run_monitor_loop(self) -> None:
        self._log.debug("AuthMonitor loop started.")
        while not self._stop_event.is_set():
            try:
                if IS_WINDOWS:
                    events = await self._poll_windows_events()
                else:
                    events = await self._poll_linux_events()
                if events:
                    self._publish_many(events)  # type: ignore[arg-type]
            except Exception as exc:
                self._record_error(exc, "auth poll")
            await self._sleep_poll_interval()
        self._log.debug("AuthMonitor loop exited.")

    async def _poll_windows_events(self) -> list[AuthenticationEvent]:
        """
        Read recent Security Event Log entries via PowerShell.
        Returns authentication events since last poll.
        """
        since_seconds = max(int(self._poll_interval * 2), 10)
        ps_cmd = f"""
$since = (Get-Date).AddSeconds(-{since_seconds})
Get-WinEvent -FilterHashtable @{{
    LogName='Security';
    Id=@(4624,4625,4648,4634);
    StartTime=$since
}} -ErrorAction SilentlyContinue |
Select-Object Id,TimeCreated,
    @{{n='TargetUser';e={{$_.Properties[5].Value}}}},
    @{{n='TargetDomain';e={{$_.Properties[6].Value}}}},
    @{{n='LogonType';e={{$_.Properties[8].Value}}}},
    @{{n='SourceIP';e={{$_.Properties[18].Value}}}},
    @{{n='WorkstationName';e={{$_.Properties[11].Value}}}},
    @{{n='AuthPackage';e={{$_.Properties[10].Value}}}} |
ConvertTo-Json -Compress
"""
        try:
            result = subprocess.run(
                ["powershell", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=15,
            )
            if not result.stdout.strip():
                return []

            import json
            raw = result.stdout.strip()
            data = json.loads(raw)
            if isinstance(data, dict):
                data = [data]

            events: list[AuthenticationEvent] = []
            logon_type_names = {
                2: "Interactive", 3: "Network", 4: "Batch",
                5: "Service", 7: "Unlock", 8: "NetworkCleartext",
                10: "RemoteInteractive", 11: "CachedInteractive",
            }

            for item in data:
                eid = int(item.get("Id", 0))
                success = eid in (4624, 4648)
                logon_type = int(item.get("LogonType") or 0)

                ev = AuthenticationEvent(
                    event_type=EventType.AUTH_LOGON_SUCCESS if success
                               else EventType.AUTH_LOGON_FAILURE,
                    source_monitor=MonitorType.AUTHENTICATION,
                    hostname=self._hostname,
                    windows_event_id=eid,
                    success=success,
                    logon_type=logon_type,
                    logon_type_name=logon_type_names.get(logon_type, str(logon_type)),
                    target_username=str(item.get("TargetUser") or ""),
                    target_domain=str(item.get("TargetDomain") or ""),
                    source_ip=str(item.get("SourceIP") or ""),
                    workstation_name=str(item.get("WorkstationName") or ""),
                    auth_package=str(item.get("AuthPackage") or ""),
                )
                events.append(ev)

            return events

        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as exc:
            self._record_error(exc, "Windows auth event poll")
            return []

    async def _poll_linux_events(self) -> list[AuthenticationEvent]:
        """
        Parse new auth.log entries via tail.
        Returns authentication events since last poll.
        """
        events: list[AuthenticationEvent] = []
        try:
            result = subprocess.run(
                ["tail", "-n", "50", self._auth_log_path],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode != 0:
                return []

            # Parse PAM / sshd patterns
            fail_patterns = [
                r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)",
                r"authentication failure.*user=(?P<user>\S+)",
                r"FAILED LOGIN.*FOR (?P<user>\S+)",
            ]
            success_patterns = [
                r"Accepted \S+ for (?P<user>\S+) from (?P<ip>[\d.]+)",
                r"session opened for user (?P<user>\S+)",
            ]

            for line in result.stdout.splitlines():
                for pattern in fail_patterns:
                    m = re.search(pattern, line, re.IGNORECASE)
                    if m:
                        ev = AuthenticationEvent(
                            event_type=EventType.AUTH_LOGON_FAILURE,
                            source_monitor=MonitorType.AUTHENTICATION,
                            hostname=self._hostname,
                            success=False,
                            target_username=m.group("user") if "user" in m.groupdict() else "",
                            source_ip=m.group("ip") if "ip" in m.groupdict() else "",
                        )
                        events.append(ev)
                        break

                for pattern in success_patterns:
                    m = re.search(pattern, line, re.IGNORECASE)
                    if m:
                        ev = AuthenticationEvent(
                            event_type=EventType.AUTH_LOGON_SUCCESS,
                            source_monitor=MonitorType.AUTHENTICATION,
                            hostname=self._hostname,
                            success=True,
                            target_username=m.group("user") if "user" in m.groupdict() else "",
                            source_ip=m.group("ip") if "ip" in m.groupdict() else "",
                        )
                        events.append(ev)
                        break

        except Exception as exc:
            self._record_error(exc, "Linux auth log parse")

        return events