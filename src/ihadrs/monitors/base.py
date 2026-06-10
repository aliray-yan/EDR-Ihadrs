"""
Module: monitors.base
Purpose: Abstract base class and supporting types for all IHADRS monitors.
Owner: monitors
"""
from __future__ import annotations

import asyncio
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

from loguru import logger

from ihadrs.constants import EventType, MonitorType
from ihadrs.core.config import IHADRSConfig
from ihadrs.core.event_bus import BusEvent, EventBus, EventPriority
from ihadrs.core.resource_manager import ResourceManager
from ihadrs.exceptions import EventBusFullError, MonitorAlreadyRunningError
from ihadrs.models.events import BaseEvent


@dataclass
class MonitorStatus:
    name: str
    monitor_type: MonitorType
    running: bool = False
    initialized: bool = False
    events_published: int = 0
    events_dropped: int = 0
    errors: int = 0
    last_event_time: float = 0.0
    last_error: str = ""
    start_time: float = 0.0
    poll_interval_seconds: float = 0.0

    @property
    def uptime_seconds(self) -> float:
        return (time.time() - self.start_time) if self.running else 0.0

    @property
    def events_per_second(self) -> float:
        uptime = self.uptime_seconds
        return self.events_published / uptime if uptime > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.monitor_type.value,
            "running": self.running,
            "initialized": self.initialized,
            "events_published": self.events_published,
            "events_dropped": self.events_dropped,
            "errors": self.errors,
            "uptime_seconds": round(self.uptime_seconds, 1),
            "events_per_second": round(self.events_per_second, 2),
            "last_error": self.last_error,
        }


class BaseMonitor(ABC):
    """Abstract base class for all IHADRS system monitors."""

    def __init__(
        self,
        config: IHADRSConfig,
        event_bus: EventBus,
        resource_manager: Optional[ResourceManager] = None,
    ) -> None:
        self._config = config
        self._event_bus = event_bus
        self._resource_manager = resource_manager
        self._monitor_type: MonitorType = MonitorType.SYNTHETIC
        self._poll_interval: float = 1.0
        self._status = MonitorStatus(
            name=self.__class__.__name__,
            monitor_type=MonitorType.SYNTHETIC,
        )
        self._status_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._monitor_thread: Optional[threading.Thread] = None
        self._log = logger.bind(component=self.__class__.__name__)
        self._recent_event_keys: dict[str, float] = {}
        self._dedup_ttl_seconds: float = 1.0

    @abstractmethod
    async def initialize(self) -> None: ...

    @abstractmethod
    async def _run_monitor_loop(self) -> None: ...

    @abstractmethod
    async def stop(self) -> None: ...

    async def start(self) -> None:
        if self._status.running:
            raise MonitorAlreadyRunningError(self._status.name)
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self._thread_entry,
            name=f"ihadrs-{self._status.name.lower()}",
            daemon=True,
        )
        self._monitor_thread.start()
        with self._status_lock:
            self._status.running = True
            self._status.start_time = time.time()
        self._log.info("{name} monitor started.", name=self._status.name)

    def _thread_entry(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._run_monitor_loop())
        except Exception as exc:
            self._log.error("Monitor loop crashed: {exc}", exc=exc)
        finally:
            loop.close()
            with self._status_lock:
                self._status.running = False

    async def _base_stop(self) -> None:
        self._stop_event.set()
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5.0)
        with self._status_lock:
            self._status.running = False
        self._log.info("{name} monitor stopped.", name=self._status.name)

    async def health_check(self) -> dict[str, Any]:
        with self._status_lock:
            status_dict = self._status.to_dict()
        issues: list[str] = []
        if not self._status.running and self._status.initialized:
            health = "failed"
            issues.append("Monitor is not running")
        elif self._status.errors > 100:
            health = "degraded"
            issues.append(f"High error count: {self._status.errors}")
        else:
            health = "healthy"
        return {"status": health, "issues": issues, **status_dict}

    def _publish(
        self,
        event: BaseEvent,
        priority: EventPriority = EventPriority.NORMAL,
        dedup_key: Optional[str] = None,
    ) -> bool:
        if self._resource_manager:
            if self._resource_manager.throttle_state.is_throttled:
                with self._status_lock:
                    self._status.events_dropped += 1
                return False

        if dedup_key is not None:
            now = time.time()
            if now - self._recent_event_keys.get(dedup_key, 0.0) < self._dedup_ttl_seconds:
                return False
            self._recent_event_keys[dedup_key] = now
            if len(self._recent_event_keys) > 1000:
                cutoff = now - self._dedup_ttl_seconds * 2
                self._recent_event_keys = {k: v for k, v in self._recent_event_keys.items() if v > cutoff}

        bus_event = BusEvent(
            event_type=event.event_type,
            source=self._status.name,
            payload=event,
            priority=priority,
        )
        try:
            published = self._event_bus.publish(bus_event)
            if published:
                with self._status_lock:
                    self._status.events_published += 1
                    self._status.last_event_time = time.time()
            return published
        except EventBusFullError:
            with self._status_lock:
                self._status.events_dropped += 1
            return False
        except Exception as exc:
            with self._status_lock:
                self._status.errors += 1
                self._status.last_error = str(exc)
            self._log.error("Failed to publish event: {exc}", exc=exc)
            return False

    def _publish_many(self, events: list[BaseEvent]) -> int:
        if not events:
            return 0
        bus_events = [
            BusEvent(event_type=e.event_type, source=self._status.name,
                     payload=e, priority=EventPriority.NORMAL)
            for e in events
        ]
        count = self._event_bus.publish_many(bus_events)
        with self._status_lock:
            self._status.events_published += count
            self._status.events_dropped += len(events) - count
            if count > 0:
                self._status.last_event_time = time.time()
        return count

    def _record_error(self, error: Exception, context: str = "") -> None:
        msg = f"{context}: {error}" if context else str(error)
        with self._status_lock:
            self._status.errors += 1
            self._status.last_error = msg
        self._log.error("{name} error — {msg}", name=self._status.name, msg=msg)

    def _mark_initialized(self) -> None:
        with self._status_lock:
            self._status.initialized = True

    async def _sleep_poll_interval(self) -> None:
        deadline = time.monotonic() + self._poll_interval
        while not self._stop_event.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            await asyncio.sleep(min(remaining, 0.1))

    @property
    def name(self) -> str:
        return self._status.name

    @property
    def is_running(self) -> bool:
        return self._status.running

    @property
    def events_published(self) -> int:
        return self._status.events_published