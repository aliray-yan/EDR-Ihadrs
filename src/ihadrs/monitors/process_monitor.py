"""
Module: monitors.process_monitor
Purpose: Cross-platform process creation/termination monitoring via psutil.
         Delta-diff approach: tracks PID set changes each polling cycle.
Owner: monitors
"""
from __future__ import annotations

import asyncio
import os
import socket
import time
from datetime import datetime, timezone
from typing import Any, Optional

import psutil

from ihadrs.constants import (
    IS_WINDOWS, LOLBINS, MonitorType, EventType, HIGH_RISK_EXECUTION_PATHS,
)
from ihadrs.core.config import IHADRSConfig
from ihadrs.core.event_bus import EventBus, EventPriority
from ihadrs.core.resource_manager import ResourceManager
from ihadrs.exceptions import MonitorInitializationError
from ihadrs.models.events import ProcessEvent, make_process_terminated_event
from ihadrs.monitors.base import BaseMonitor


_HIGH_RISK_EXPANDED: frozenset[str] = frozenset(
    os.path.expandvars(p).lower().replace("\\", "/")
    for p in HIGH_RISK_EXECUTION_PATHS
)


class ProcessMonitor(BaseMonitor):
    """
    Monitors process creation and termination using psutil poll-diff.
    Emits PROCESS_CREATED / PROCESS_TERMINATED events.
    Cross-platform: Windows + Linux + macOS.
    """

    def __init__(
        self,
        config: IHADRSConfig,
        event_bus: EventBus,
        resource_manager: Optional[ResourceManager] = None,
    ) -> None:
        super().__init__(config, event_bus, resource_manager)
        self._monitor_type = MonitorType.PROCESS
        self._poll_interval = config.monitors.process_poll_interval
        self._status.monitor_type = MonitorType.PROCESS
        self._status.name = "ProcessMonitor"
        self._status.poll_interval_seconds = self._poll_interval
        self._prev_pids: set[int] = set()
        self._process_cache: dict[int, dict[str, Any]] = {}
        self._hostname = socket.gethostname()
        self._whitelist: frozenset[str] = frozenset(
            n.lower() for n in config.monitors.process_baseline_whitelist
        )

    async def initialize(self) -> None:
        """Build initial PID baseline. Raises MonitorInitializationError on failure."""
        try:
            pids = list(psutil.pids())
            if not pids:
                raise MonitorInitializationError(
                    "ProcessMonitor",
                    "psutil.pids() returned empty — insufficient permissions?",
                )
            self._prev_pids = set(pids)
            for pid in pids:
                info = self._get_process_info(pid)
                if info:
                    self._process_cache[pid] = info
            self._log.info(
                "ProcessMonitor baseline: {n} processes.", n=len(self._prev_pids)
            )
            self._mark_initialized()
        except psutil.AccessDenied as exc:
            raise MonitorInitializationError(
                "ProcessMonitor",
                f"Access denied enumerating processes: {exc}",
                original_error=exc,
            ) from exc

    async def stop(self) -> None:
        await self._base_stop()
        self._process_cache.clear()
        self._prev_pids.clear()

    async def _run_monitor_loop(self) -> None:
        self._log.debug("ProcessMonitor loop started.")
        while not self._stop_event.is_set():
            try:
                await self._poll_once()
            except Exception as exc:
                self._record_error(exc, "process poll")
                await asyncio.sleep(5.0)
                continue
            await self._sleep_poll_interval()
        self._log.debug("ProcessMonitor loop exited.")

    async def _poll_once(self) -> None:
        """Single poll cycle: diff PIDs, emit create/terminate events."""
        try:
            current_pids = set(psutil.pids())
        except (psutil.AccessDenied, OSError) as exc:
            self._record_error(exc, "pids()"); return

        new_pids = current_pids - self._prev_pids
        gone_pids = self._prev_pids - current_pids

        # Emit creation events
        created: list[ProcessEvent] = []
        for pid in new_pids:
            ev = self._build_created(pid)
            if ev:
                created.append(ev)
                self._log.debug(
                    "Process created: {n} PID {p}", n=ev.process_name, p=pid
                )
        if created:
            self._publish_many(created)  # type: ignore[arg-type]

        # Emit termination events
        terminated: list[ProcessEvent] = []
        for pid in gone_pids:
            ev = self._build_terminated(pid)
            if ev:
                terminated.append(ev)
            self._process_cache.pop(pid, None)
        if terminated:
            self._publish_many(terminated)  # type: ignore[arg-type]

        self._prev_pids = current_pids
        stale = set(self._process_cache) - current_pids
        for pid in stale:
            self._process_cache.pop(pid, None)

    def _build_created(self, pid: int) -> Optional[ProcessEvent]:
        info = self._get_process_info(pid)
        if not info:
            return None
        if info["name"].lower() in self._whitelist:
            return None
        self._process_cache[pid] = info

        event = ProcessEvent(
            event_type=EventType.PROCESS_CREATED,
            source_monitor=MonitorType.PROCESS,
            hostname=self._hostname,
            username=info.get("username", ""),
            pid=pid,
            process_name=info["name"],
            image_path=info.get("exe", ""),
            command_line=info.get("cmdline", ""),
            working_directory=info.get("cwd", ""),
            parent_pid=info.get("ppid", 0),
            parent_name=info.get("parent_name", ""),
            parent_image_path=info.get("parent_exe", ""),
            create_time=info.get("create_time"),
            num_threads=info.get("num_threads", 0),
            memory_mb=info.get("memory_mb", 0.0),
            is_elevated=info.get("is_elevated", False),
            integrity_level=info.get("integrity_level", ""),
            session_id=info.get("session_id", 0),
        )

        # Tag executable path risk
        exe_lower = info.get("exe", "").lower().replace("\\", "/")
        if any(p in exe_lower for p in _HIGH_RISK_EXPANDED):
            event.tags = ["high_risk_path"]
        return event

    def _build_terminated(self, pid: int) -> Optional[ProcessEvent]:
        cached = self._process_cache.get(pid)
        if not cached:
            return None
        ct = cached.get("create_time_float", 0.0)
        lifetime = time.time() - ct if ct else 0.0
        return make_process_terminated_event(
            pid=pid,
            name=cached.get("name", f"pid:{pid}"),
            lifetime_seconds=lifetime,
            username=cached.get("username", ""),
            hostname=self._hostname,
        )

    def _get_process_info(self, pid: int) -> Optional[dict[str, Any]]:
        """Collect all process metadata in a single psutil oneshot block."""
        try:
            proc = psutil.Process(pid)
            with proc.oneshot():
                name = proc.name()
                exe = ""
                try: exe = proc.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess, OSError): pass

                cmdline = name
                try:
                    cl = proc.cmdline()
                    if cl: cmdline = " ".join(cl)
                except (psutil.AccessDenied, psutil.NoSuchProcess, OSError): pass

                cwd = ""
                try: cwd = proc.cwd()
                except (psutil.AccessDenied, psutil.NoSuchProcess, OSError): pass

                ppid = 0
                try: ppid = proc.ppid()
                except (psutil.NoSuchProcess, psutil.AccessDenied): pass

                username = ""
                try: username = proc.username()
                except (psutil.AccessDenied, psutil.NoSuchProcess): pass

                create_time_float = 0.0
                create_time = None
                try:
                    create_time_float = proc.create_time()
                    create_time = datetime.fromtimestamp(
                        create_time_float, tz=timezone.utc
                    )
                except Exception: pass

                num_threads = 0
                try: num_threads = proc.num_threads()
                except (psutil.AccessDenied, psutil.NoSuchProcess): pass

                memory_mb = 0.0
                try:
                    mi = proc.memory_info()
                    memory_mb = mi.rss / (1024 * 1024)
                except (psutil.AccessDenied, psutil.NoSuchProcess): pass

                session_id = 0
                try:
                    t = proc.terminal()
                    session_id = int(t) if t else 0
                except Exception: pass

            # Parent name
            parent_name, parent_exe = "", ""
            if ppid and ppid != pid:
                try:
                    p2 = psutil.Process(ppid)
                    parent_name = p2.name()
                    try: parent_exe = p2.exe()
                    except (psutil.AccessDenied, psutil.NoSuchProcess): pass
                except (psutil.NoSuchProcess, psutil.AccessDenied): pass

            is_elevated, integrity_level = False, ""
            if IS_WINDOWS:
                is_elevated, integrity_level = self._win_privilege(proc)

            return {
                "name": name, "exe": exe, "cmdline": cmdline, "cwd": cwd,
                "ppid": ppid, "parent_name": parent_name, "parent_exe": parent_exe,
                "username": username, "create_time": create_time,
                "create_time_float": create_time_float, "num_threads": num_threads,
                "memory_mb": memory_mb, "session_id": session_id,
                "is_elevated": is_elevated, "integrity_level": integrity_level,
                "cpu_percent": 0.0,
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
        except Exception as exc:
            self._log.debug("Could not get info for PID {p}: {e}", p=pid, e=exc)
            return None

    def _win_privilege(self, proc: psutil.Process) -> tuple[bool, str]:
        try:
            import win32api, win32security, win32con  # type: ignore
            h = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, proc.pid)
            tok = win32security.OpenProcessToken(h, win32con.TOKEN_QUERY)
            elev = win32security.GetTokenInformation(tok, win32security.TokenElevation)
            il = win32security.GetTokenInformation(tok, win32security.TokenIntegrityLevel)
            sid = il[0]
            sub = win32security.GetSidSubAuthority(
                sid, win32security.GetSidSubAuthorityCount(sid) - 1
            )
            return bool(elev), {0x1000:"Low",0x2000:"Medium",0x3000:"High",0x4000:"System"}.get(sub, "Unknown")
        except Exception:
            return False, ""

    def get_process_tree(self, pid: int, depth: int = 3) -> dict[str, Any]:
        """Build process ancestry tree for the detection engine."""
        result: dict[str, Any] = {}
        node: dict[str, Any] = {}
        cur = pid
        for _ in range(depth):
            info = self._process_cache.get(cur) or self._get_process_info(cur)
            if not info: break
            level = {"pid": cur, "name": info["name"], "exe": info.get("exe",""), "cmdline": info.get("cmdline","")}
            if not result:
                result = level; node = result
            else:
                node["parent"] = level; node = node["parent"]
            ppid = info.get("ppid", 0)
            if not ppid or ppid == cur: break
            cur = ppid
        return result