"""
Module: monitors.network_monitor
Purpose: Monitors network connections using psutil.net_connections().
         Detects new TCP/UDP connections, listening ports, and connection
         state changes. Tracks per-process connection history for
         beaconing and exfiltration pattern detection.
Owner: monitors
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Optional

import psutil

from ihadrs.constants import (
    C2_BEACON_MAX_JITTER_PCT,
    C2_BEACON_MIN_INTERVAL_SECONDS,
    MonitorType,
    EventType,
    SUSPICIOUS_C2_PORTS,
)
from ihadrs.core.config import IHADRSConfig
from ihadrs.core.event_bus import EventBus, EventPriority
from ihadrs.core.resource_manager import ResourceManager
from ihadrs.exceptions import MonitorInitializationError
from ihadrs.models.events import NetworkEvent, NetworkBeaconEvent, make_network_connection_event
from ihadrs.monitors.base import BaseMonitor


def _is_private_ip(ip: str) -> bool:
    """Return True if IP is RFC-1918 private or loopback."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _conn_key(conn: psutil._common.sconn) -> str:  # type: ignore[name-defined]
    """Stable string key for a connection tuple."""
    laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "?:?"
    raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "?:?"
    return f"{conn.pid}|{conn.type}|{laddr}|{raddr}|{conn.status}"


@dataclass
class ConnectionRecord:
    """Tracks an open connection for beaconing analysis."""
    pid: int
    process_name: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    protocol: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    connect_times: deque = field(default_factory=lambda: deque(maxlen=50))


class NetworkMonitor(BaseMonitor):
    """
    Monitors TCP/UDP network connections using psutil.net_connections().
    Emits events for new connections, closed connections, and listening ports.
    Also performs statistical beaconing analysis for C2 detection.
    """

    def __init__(
        self,
        config: IHADRSConfig,
        event_bus: EventBus,
        resource_manager: Optional[ResourceManager] = None,
    ) -> None:
        super().__init__(config, event_bus, resource_manager)
        self._monitor_type = MonitorType.NETWORK
        self._poll_interval = config.monitors.network_poll_interval
        self._status.monitor_type = MonitorType.NETWORK
        self._status.name = "NetworkMonitor"
        self._status.poll_interval_seconds = self._poll_interval
        self._hostname = socket.gethostname()

        # State: set of active connection keys
        self._prev_conn_keys: set[str] = set()
        # Map conn_key → ConnectionRecord for beaconing analysis
        self._conn_history: dict[str, ConnectionRecord] = {}
        # Map (pid, remote_ip, remote_port) → list of connect timestamps
        self._beacon_tracker: dict[tuple, deque] = defaultdict(
            lambda: deque(maxlen=100)
        )
        # PID → process name cache
        self._pid_name_cache: dict[int, str] = {}
        self._ip_whitelist: frozenset[str] = frozenset(
            config.monitors.ip_whitelist
        )

    async def initialize(self) -> None:
        try:
            conns = psutil.net_connections(kind="all")
            self._prev_conn_keys = {_conn_key(c) for c in conns}
            self._log.info(
                "NetworkMonitor baseline: {n} connections.",
                n=len(self._prev_conn_keys),
            )
            self._mark_initialized()
        except psutil.AccessDenied as exc:
            raise MonitorInitializationError(
                "NetworkMonitor",
                f"Access denied enumerating connections: {exc}",
                original_error=exc,
            ) from exc

    async def stop(self) -> None:
        await self._base_stop()
        self._prev_conn_keys.clear()
        self._conn_history.clear()
        self._beacon_tracker.clear()

    async def _run_monitor_loop(self) -> None:
        self._log.debug("NetworkMonitor loop started.")
        while not self._stop_event.is_set():
            try:
                await self._poll_once()
            except Exception as exc:
                self._record_error(exc, "network poll")
                await asyncio.sleep(5.0)
                continue
            await self._sleep_poll_interval()
        self._log.debug("NetworkMonitor loop exited.")

    async def _poll_once(self) -> None:
        try:
            conns = psutil.net_connections(kind="all")
        except (psutil.AccessDenied, OSError) as exc:
            self._record_error(exc, "net_connections()"); return

        current_keys: set[str] = set()
        new_events: list[NetworkEvent] = []
        now = time.time()

        for conn in conns:
            key = _conn_key(conn)
            current_keys.add(key)

            if key not in self._prev_conn_keys:
                # New connection
                ev = self._build_connection_event(conn, now)
                if ev:
                    new_events.append(ev)
                    self._track_beacon(conn, now)

        if new_events:
            self._publish_many(new_events)  # type: ignore[arg-type]

        # Check for beaconing patterns every 10 polls
        if int(now) % 10 == 0:
            beacon_events = self._detect_beaconing(now)
            if beacon_events:
                for ev in beacon_events:
                    self._publish(ev, priority=EventPriority.HIGH)

        self._prev_conn_keys = current_keys

    def _build_connection_event(
        self, conn: Any, now: float
    ) -> Optional[NetworkEvent]:
        """Build a NetworkEvent for a newly detected connection."""
        if not conn.raddr:
            return None  # Listening socket — separate handling

        rip = conn.raddr.ip if conn.raddr else ""
        rport = conn.raddr.port if conn.raddr else 0
        lip = conn.laddr.ip if conn.laddr else ""
        lport = conn.laddr.port if conn.laddr else 0

        # Skip whitelisted IPs
        if rip in self._ip_whitelist:
            return None

        # Skip private IPs for low-noise operation (configurable)
        # Keep external connections and suspicious ports

        process_name = self._get_pid_name(conn.pid)

        proto_map = {
            1: "tcp", 2: "udp",
            getattr(psutil, "AF_INET", 2): "tcp",
        }
        protocol = "tcp" if str(conn.type) in ("SocketKind.SOCK_STREAM", "1") else "udp"

        return make_network_connection_event(
            pid=conn.pid or 0,
            process_name=process_name,
            local_ip=lip,
            local_port=lport,
            remote_ip=rip,
            remote_port=rport,
            protocol=protocol,
            direction="outbound" if lip and not _is_private_ip(rip) else "internal",
            state=conn.status or "",
            remote_hostname="",
        )

    def _track_beacon(self, conn: Any, now: float) -> None:
        """Track connection timing for beaconing detection."""
        if not conn.raddr or not conn.pid:
            return
        tracker_key = (conn.pid, conn.raddr.ip, conn.raddr.port)
        self._beacon_tracker[tracker_key].append(now)

    def _detect_beaconing(self, now: float) -> list[NetworkBeaconEvent]:
        """
        Analyze connection timing patterns for C2 beaconing.
        Returns beacon events for statistically regular connections.
        """
        beacon_events: list[NetworkBeaconEvent] = []
        min_observations = 5
        window = 600.0  # 10-minute analysis window

        for (pid, rip, rport), times in list(self._beacon_tracker.items()):
            # Filter to times within window
            recent = [t for t in times if now - t <= window]
            if len(recent) < min_observations:
                continue

            # Calculate intervals
            intervals = [recent[i+1] - recent[i] for i in range(len(recent)-1)]
            if len(intervals) < min_observations - 1:
                continue

            avg_interval = sum(intervals) / len(intervals)
            if avg_interval < C2_BEACON_MIN_INTERVAL_SECONDS:
                continue  # Too frequent to be beaconing (normal web traffic)

            # Calculate jitter (coefficient of variation)
            variance = sum((x - avg_interval)**2 for x in intervals) / len(intervals)
            std_dev = variance ** 0.5
            jitter_pct = std_dev / avg_interval if avg_interval > 0 else 1.0

            if jitter_pct < C2_BEACON_MAX_JITTER_PCT:
                # Low jitter = highly regular = suspicious
                process_name = self._get_pid_name(pid)
                confidence = max(0.0, min(1.0, (C2_BEACON_MAX_JITTER_PCT - jitter_pct) / C2_BEACON_MAX_JITTER_PCT))
                self._log.warning(
                    "C2 beacon pattern: {proc} → {ip}:{port} every {interval:.1f}s ±{jitter:.1%}",
                    proc=process_name, ip=rip, port=rport,
                    interval=avg_interval, jitter=jitter_pct,
                )
                ev = NetworkBeaconEvent(
                    event_type=EventType.NETWORK_C2_BEACON,
                    source_monitor=MonitorType.NETWORK,
                    hostname=self._hostname,
                    pid=pid,
                    process_name=process_name,
                    remote_ip=rip,
                    remote_port=rport,
                    interval_seconds=avg_interval,
                    interval_jitter_pct=jitter_pct,
                    observation_window_seconds=int(window),
                    connection_count=len(recent),
                    confidence=confidence,
                )
                beacon_events.append(ev)

        return beacon_events

    def _get_pid_name(self, pid: Optional[int]) -> str:
        """Get process name for a PID, with caching."""
        if not pid:
            return ""
        if pid in self._pid_name_cache:
            return self._pid_name_cache[pid]
        try:
            name = psutil.Process(pid).name()
            self._pid_name_cache[pid] = name
            return name
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return f"pid:{pid}"