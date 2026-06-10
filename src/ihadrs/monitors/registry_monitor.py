"""
Module: monitors.registry_monitor
Purpose: Windows registry change monitoring using winreg + polling.
         Watches persistence-related registry keys for unauthorized modifications.
Owner: monitors
Platform: Windows only. No-op on Linux/macOS.
"""
from __future__ import annotations

import asyncio
import copy
import socket
import time
from typing import Any, Optional

from ihadrs.constants import (
    IS_WINDOWS, REGISTRY_PERSISTENCE_KEYS, MonitorType, EventType,
)
from ihadrs.core.config import IHADRSConfig
from ihadrs.core.event_bus import EventBus, EventPriority
from ihadrs.core.resource_manager import ResourceManager
from ihadrs.exceptions import MonitorInitializationError
from ihadrs.models.events import RegistryEvent, make_registry_event
from ihadrs.monitors.base import BaseMonitor


class RegistryMonitor(BaseMonitor):
    """
    Windows registry persistence key monitor.

    Polls a curated set of persistence-relevant registry paths on a fixed
    interval, diffs against the previous snapshot, and emits events for
    any detected changes. This approach is simpler and more reliable than
    RegNotifyChangeKeyValue for the IHADRS use case.

    On non-Windows platforms, initialize() raises MonitorInitializationError
    immediately so the orchestrator skips this monitor gracefully.
    """

    # Hives to watch: (hive_name, hive_constant, [subkeys])
    _WATCH_HIVES: list[tuple[str, Any, list[str]]] = []

    def __init__(
        self,
        config: IHADRSConfig,
        event_bus: EventBus,
        resource_manager: Optional[ResourceManager] = None,
    ) -> None:
        super().__init__(config, event_bus, resource_manager)
        self._monitor_type = MonitorType.REGISTRY
        self._poll_interval = 5.0  # Registry changes are infrequent
        self._status.monitor_type = MonitorType.REGISTRY
        self._status.name = "RegistryMonitor"
        self._status.poll_interval_seconds = self._poll_interval
        self._hostname = socket.gethostname()
        self._baseline: dict[str, dict[str, str]] = {}

    async def initialize(self) -> None:
        if not IS_WINDOWS:
            raise MonitorInitializationError(
                "RegistryMonitor",
                "Windows registry monitoring is only available on Windows.",
            )

        try:
            import winreg
            self._winreg = winreg
        except ImportError as exc:
            raise MonitorInitializationError(
                "RegistryMonitor",
                "winreg module not available.",
                original_error=exc,
            ) from exc

        # Build initial baseline snapshot
        self._baseline = self._snapshot_all()
        self._log.info(
            "RegistryMonitor baseline: {n} keys tracked.",
            n=len(self._baseline),
        )
        self._mark_initialized()

    async def stop(self) -> None:
        await self._base_stop()
        self._baseline.clear()

    async def _run_monitor_loop(self) -> None:
        self._log.debug("RegistryMonitor loop started.")
        while not self._stop_event.is_set():
            try:
                await self._poll_once()
            except Exception as exc:
                self._record_error(exc, "registry poll")
                await asyncio.sleep(10.0)
            await self._sleep_poll_interval()
        self._log.debug("RegistryMonitor loop exited.")

    async def _poll_once(self) -> None:
        """Compare current registry state to baseline, emit diff events."""
        current = self._snapshot_all()
        events: list[RegistryEvent] = []

        for key_path, values in current.items():
            prev_values = self._baseline.get(key_path, {})
            hive, subkey = key_path.split("\\", 1) if "\\" in key_path else (key_path, "")

            for value_name, value_data in values.items():
                if value_name not in prev_values:
                    # New value added
                    ev = make_registry_event(
                        hive=hive, key_path=subkey,
                        change_type="value_set",
                        value_name=value_name, value_data=str(value_data),
                    )
                    events.append(ev)
                elif prev_values[value_name] != value_data:
                    # Value changed
                    ev = make_registry_event(
                        hive=hive, key_path=subkey,
                        change_type="value_set",
                        value_name=value_name, value_data=str(value_data),
                    )
                    ev.old_value_data = str(prev_values[value_name])
                    events.append(ev)

            # Check for deleted values
            for value_name in prev_values:
                if value_name not in values:
                    ev = make_registry_event(
                        hive=hive, key_path=subkey,
                        change_type="value_deleted",
                        value_name=value_name,
                    )
                    events.append(ev)

        if events:
            for ev in events:
                priority = EventPriority.HIGH if ev.is_persistence_path else EventPriority.NORMAL
                self._publish(ev, priority=priority)
            self._log.info(
                "Registry changes detected: {n} events emitted.", n=len(events)
            )

        self._baseline = current

    def _snapshot_all(self) -> dict[str, dict[str, str]]:
        """Read all watched registry keys and return a value snapshot."""
        import winreg
        snapshot: dict[str, dict[str, str]] = {}

        hive_map = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
        }

        for key_path in REGISTRY_PERSISTENCE_KEYS:
            for hive_name, hive_const in hive_map.items():
                full_key = f"{hive_name}\\{key_path}"
                try:
                    values = self._read_key(hive_const, key_path)
                    snapshot[full_key] = values
                except Exception:
                    pass  # Key may not exist on this system

        return snapshot

    def _read_key(self, hive: Any, subkey: str) -> dict[str, str]:
        """Read all values from a registry key."""
        import winreg
        values: dict[str, str] = {}
        try:
            with winreg.OpenKey(hive, subkey, access=winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, data, _ = winreg.EnumValue(key, i)
                        values[name] = str(data)
                        i += 1
                    except OSError:
                        break  # No more values
        except (FileNotFoundError, PermissionError, OSError):
            pass
        return values