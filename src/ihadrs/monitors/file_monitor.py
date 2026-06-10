"""
Module: monitors.file_monitor
Purpose: File system change monitoring using watchdog library.
         Watches configured paths for file create/modify/delete/rename.
         Implements bulk operation detection for ransomware defense.
Owner: monitors
"""
from __future__ import annotations

import asyncio
import os
import socket
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Optional

from watchdog.events import (
    FileCreatedEvent, FileDeletedEvent, FileModifiedEvent,
    FileMovedEvent, FileSystemEvent, FileSystemEventHandler,
)
from watchdog.observers import Observer

from ihadrs.constants import (
    RANSOMWARE_EXTENSIONS, RANSOMWARE_FILE_RENAME_THRESHOLD,
    RANSOMWARE_TIME_WINDOW_SECONDS, MonitorType, EventType,
)
from ihadrs.core.config import IHADRSConfig
from ihadrs.core.event_bus import EventBus, EventPriority
from ihadrs.core.resource_manager import ResourceManager
from ihadrs.exceptions import MonitorInitializationError
from ihadrs.models.events import FileEvent, make_file_event
from ihadrs.monitors.base import BaseMonitor


class FileMonitor(BaseMonitor):
    """
    File system change monitor using watchdog OS-native APIs.

    Uses ReadDirectoryChangesW (Windows), inotify (Linux), or kqueue (macOS)
    via the watchdog library for efficient event-driven monitoring.

    Detects:
    - File creation, modification, deletion, rename
    - Executable files dropped in high-risk paths
    - Ransomware bulk-rename pattern
    - Hosts file modification
    - Startup folder modification
    """

    def __init__(
        self,
        config: IHADRSConfig,
        event_bus: EventBus,
        resource_manager: Optional[ResourceManager] = None,
    ) -> None:
        super().__init__(config, event_bus, resource_manager)
        self._monitor_type = MonitorType.FILE
        self._poll_interval = 1.0
        self._status.monitor_type = MonitorType.FILE
        self._status.name = "FileMonitor"
        self._status.poll_interval_seconds = self._poll_interval
        self._hostname = socket.gethostname()
        self._observer: Optional[Observer] = None
        self._handler: Optional[_IHADRSFileHandler] = None
        # Ransomware tracking: timestamps of crypto-extension renames
        self._crypto_rename_times: deque = deque(maxlen=200)

    async def initialize(self) -> None:
        watch_paths = self._config.monitors.file_watch_paths
        if not watch_paths:
            raise MonitorInitializationError(
                "FileMonitor",
                "No file watch paths configured. Add paths to monitors.file_watch_paths.",
            )

        self._handler = _IHADRSFileHandler(self)
        self._observer = Observer()
        scheduled = 0

        for raw_path in watch_paths:
            expanded = os.path.expandvars(raw_path)
            path = Path(expanded)
            if not path.exists():
                self._log.warning(
                    "Watch path does not exist (skipping): {p}", p=expanded
                )
                continue
            try:
                self._observer.schedule(
                    self._handler,
                    str(path),
                    recursive=self._config.monitors.file_watch_recursive,
                )
                scheduled += 1
                self._log.debug("Watching: {p}", p=expanded)
            except Exception as exc:
                self._log.warning(
                    "Could not watch {p}: {exc}", p=expanded, exc=exc
                )

        if scheduled == 0:
            raise MonitorInitializationError(
                "FileMonitor",
                "No watch paths could be scheduled (paths may not exist or be inaccessible).",
            )

        self._log.info(
            "FileMonitor watching {n} path(s).", n=scheduled
        )
        self._mark_initialized()

    async def start(self) -> None:
        """Start the watchdog observer and the base monitor."""
        if self._observer:
            self._observer.start()
        await super().start()

    async def stop(self) -> None:
        if self._observer and self._observer.is_alive():
            self._observer.stop()
            self._observer.join(timeout=5.0)
        await self._base_stop()

    async def _run_monitor_loop(self) -> None:
        """
        Main loop: watchdog callbacks push events to _pending queue.
        We check ransomware patterns periodically.
        """
        self._log.debug("FileMonitor loop started.")
        while not self._stop_event.is_set():
            try:
                self._check_ransomware_pattern()
            except Exception as exc:
                self._record_error(exc, "ransomware check")
            await self._sleep_poll_interval()
        self._log.debug("FileMonitor loop exited.")

    def _on_file_event(self, fs_event: FileSystemEvent) -> None:
        """
        Called from watchdog thread for every file system change.
        Translates to IHADRS FileEvent and publishes to bus.
        """
        try:
            path = fs_event.src_path
            change_map = {
                FileCreatedEvent: "created",
                FileDeletedEvent: "deleted",
                FileModifiedEvent: "modified",
                FileMovedEvent: "renamed",
            }
            change_type = change_map.get(type(fs_event), "modified")
            new_path = getattr(fs_event, "dest_path", "")

            event = make_file_event(
                file_path=path,
                change_type=change_type,
                old_path=path if change_type == "renamed" else "",
                new_path=new_path,
            )

            # Ransomware extension tracking
            if change_type == "renamed" and new_path:
                new_ext = os.path.splitext(new_path)[1].lower()
                if new_ext in RANSOMWARE_EXTENSIONS:
                    self._crypto_rename_times.append(time.time())

            priority = EventPriority.NORMAL
            # Elevate priority for executables in suspicious locations
            if event.is_executable and event.tags:
                priority = EventPriority.HIGH

            self._publish(event, priority=priority)

        except Exception as exc:
            self._record_error(exc, "file event handler")

    def _check_ransomware_pattern(self) -> None:
        """
        Check if the recent rename rate exceeds the ransomware threshold.
        If so, emit a high-priority MASS_OPERATION event.
        """
        now = time.time()
        cutoff = now - RANSOMWARE_TIME_WINDOW_SECONDS
        recent = [t for t in self._crypto_rename_times if t >= cutoff]

        if len(recent) >= RANSOMWARE_FILE_RENAME_THRESHOLD:
            self._log.critical(
                "RANSOMWARE PATTERN: {n} crypto renames in {w}s!",
                n=len(recent), w=RANSOMWARE_TIME_WINDOW_SECONDS,
            )
            # Emit a synthetic mass-operation event
            summary_event = FileEvent(
                event_type=EventType.FILE_MASS_OPERATION,
                source_monitor=MonitorType.FILE,
                hostname=self._hostname,
                file_path="(multiple files)",
                change_type="renamed",
                operation_count=len(recent),
                is_batch_summary=True,
            )
            summary_event.tags = ["ransomware", "bulk_encrypt"]
            self._publish(summary_event, priority=EventPriority.CRITICAL)
            # Clear the tracker to avoid repeated alerts
            self._crypto_rename_times.clear()


class _IHADRSFileHandler(FileSystemEventHandler):
    """Watchdog event handler that routes events to FileMonitor."""

    def __init__(self, monitor: FileMonitor) -> None:
        super().__init__()
        self._monitor = monitor

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._monitor._on_file_event(event)

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._monitor._on_file_event(event)

    def on_deleted(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._monitor._on_file_event(event)

    def on_moved(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._monitor._on_file_event(event)