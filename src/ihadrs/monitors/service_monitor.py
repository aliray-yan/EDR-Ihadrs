"""
Module: monitors.service_monitor
Purpose: Windows service creation/deletion/modification monitoring.
         Detects malicious service installations (common persistence technique).
Owner: monitors
Platform: Windows only.
"""
from __future__ import annotations

import asyncio
import socket
import time
from typing import Any, Optional

import psutil

from ihadrs.constants import IS_WINDOWS, MonitorType, EventType
from ihadrs.core.config import IHADRSConfig
from ihadrs.core.event_bus import EventBus, EventPriority
from ihadrs.core.resource_manager import ResourceManager
from ihadrs.exceptions import MonitorInitializationError
from ihadrs.models.events import ServiceEvent
from ihadrs.monitors.base import BaseMonitor


class ServiceMonitor(BaseMonitor):
    """
    Windows service state monitor.

    Polls the Windows service list (via psutil.win_service_iter()) on a
    fixed interval, comparing against the previous snapshot to detect
    new, deleted, or modified services.
    """

    def __init__(
        self,
        config: IHADRSConfig,
        event_bus: EventBus,
        resource_manager: Optional[ResourceManager] = None,
    ) -> None:
        super().__init__(config, event_bus, resource_manager)
        self._monitor_type = MonitorType.SERVICE
        self._poll_interval = config.monitors.service_poll_interval
        self._status.monitor_type = MonitorType.SERVICE
        self._status.name = "ServiceMonitor"
        self._status.poll_interval_seconds = self._poll_interval
        self._hostname = socket.gethostname()
        self._baseline: dict[str, dict[str, Any]] = {}

    async def initialize(self) -> None:
        if not IS_WINDOWS:
            raise MonitorInitializationError(
                "ServiceMonitor",
                "Windows service monitoring is only available on Windows.",
            )
        if not hasattr(psutil, "win_service_iter"):
            raise MonitorInitializationError(
                "ServiceMonitor",
                "psutil.win_service_iter not available (requires Windows).",
            )

        try:
            self._baseline = self._snapshot_services()
            self._log.info(
                "ServiceMonitor baseline: {n} services.", n=len(self._baseline)
            )
            self._mark_initialized()
        except Exception as exc:
            raise MonitorInitializationError(
                "ServiceMonitor",
                f"Failed to enumerate services: {exc}",
                original_error=exc,
            ) from exc

    async def stop(self) -> None:
        await self._base_stop()
        self._baseline.clear()

    async def _run_monitor_loop(self) -> None:
        self._log.debug("ServiceMonitor loop started.")
        while not self._stop_event.is_set():
            try:
                await self._poll_once()
            except Exception as exc:
                self._record_error(exc, "service poll")
                await asyncio.sleep(15.0)
            await self._sleep_poll_interval()
        self._log.debug("ServiceMonitor loop exited.")

    async def _poll_once(self) -> None:
        current = self._snapshot_services()
        events: list[ServiceEvent] = []

        current_names = set(current.keys())
        prev_names = set(self._baseline.keys())

        # New services
        for name in current_names - prev_names:
            svc = current[name]
            ev = self._build_event(svc, "created")
            events.append(ev)
            self._log.warning(
                "New service installed: {name} path={path}",
                name=name, path=svc.get("binpath", ""),
            )

        # Removed services
        for name in prev_names - current_names:
            svc = self._baseline[name]
            ev = self._build_event(svc, "deleted")
            events.append(ev)

        # Modified services (path or start type changed)
        for name in current_names & prev_names:
            cur = current[name]; prev = self._baseline[name]
            if cur.get("binpath") != prev.get("binpath") or cur.get("start_type") != prev.get("start_type"):
                ev = self._build_event(cur, "modified")
                ev.old_service_path = prev.get("binpath", "")
                ev.old_start_type = prev.get("start_type", "")
                events.append(ev)

        if events:
            for ev in events:
                # High risk: auto-start services from non-standard paths
                is_risky = ev.change_type in ("created", "modified") and any(
                    p in (ev.service_path or "").lower()
                    for p in ["\\temp\\", "\\appdata\\", "\\users\\public\\"]
                )
                priority = EventPriority.HIGH if is_risky else EventPriority.NORMAL
                self._publish(ev, priority=priority)

        self._baseline = current

    def _snapshot_services(self) -> dict[str, dict[str, Any]]:
        snapshot: dict[str, dict[str, Any]] = {}
        try:
            for svc in psutil.win_service_iter():  # type: ignore[attr-defined]
                try:
                    info = svc.as_dict()
                    snapshot[info["name"]] = info
                except Exception:
                    pass
        except Exception:
            pass
        return snapshot

    def _build_event(
        self, svc: dict[str, Any], change_type: str
    ) -> ServiceEvent:
        binpath = svc.get("binpath", "") or svc.get("binary_path", "") or ""
        return ServiceEvent(
            event_type=EventType.SERVICE_CREATED if change_type == "created"
                        else EventType.SERVICE_DELETED if change_type == "deleted"
                        else EventType.SERVICE_MODIFIED,
            source_monitor=MonitorType.SERVICE,
            hostname=self._hostname,
            service_name=svc.get("name", ""),
            display_name=svc.get("display_name", ""),
            service_path=binpath,
            change_type=change_type,
            start_type=svc.get("start_type", ""),
            service_account=svc.get("username", ""),
            service_type=svc.get("service_type", ""),
            is_system_path="system32" in binpath.lower() or "syswow64" in binpath.lower(),
        )