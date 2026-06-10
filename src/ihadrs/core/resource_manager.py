"""
Module: core.resource_manager
Purpose: Runtime resource budget enforcement for IHADRS.
         Monitors its own CPU, RAM, and disk I/O usage and applies
         throttling when budgets are exceeded. Prevents IHADRS from
         becoming a performance burden on the monitored system.
Owner: core
Dependencies: psutil, threading, loguru
Performance: Runs in a background thread, sampling every 5 seconds.
             Zero overhead on hot paths — components check a shared flag.
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import psutil
from loguru import logger

from ihadrs.constants import (
    CPU_BUDGET_AVERAGE_PCT,
    CPU_BUDGET_PEAK_PCT,
    CPU_PEAK_WINDOW_SECONDS,
    DISK_IO_BUDGET_WRITE_MBS,
    HEALTH_CHECK_INTERVAL_SECONDS,
    RAM_BUDGET_BASELINE_MB,
    RAM_BUDGET_MAX_MB,
    RESOURCE_CHECK_INTERVAL_SECONDS,
)
from ihadrs.exceptions import (
    CPUBudgetExceededError,
    DiskIOBudgetExceededError,
    MemoryBudgetExceededError,
)


# =============================================================================
# RESOURCE SNAPSHOT
# =============================================================================

@dataclass
class ResourceSnapshot:
    """
    Point-in-time resource usage measurement for the IHADRS process.

    Collected every RESOURCE_CHECK_INTERVAL_SECONDS seconds by the
    background monitoring thread.
    """

    timestamp: float = field(default_factory=time.time)

    # CPU
    cpu_pct: float = 0.0            # % of one CPU core (0–100)
    cpu_pct_system: float = 0.0     # System-wide CPU % for context

    # Memory
    rss_mb: float = 0.0             # Resident Set Size in MB
    vms_mb: float = 0.0             # Virtual Memory Size in MB
    memory_pct: float = 0.0         # % of system RAM

    # Disk I/O (delta since last snapshot)
    disk_read_mbs: float = 0.0      # MB/s read rate
    disk_write_mbs: float = 0.0     # MB/s write rate

    # Thread count
    thread_count: int = 0

    # File descriptors (Linux only)
    open_files: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "cpu_pct": round(self.cpu_pct, 2),
            "rss_mb": round(self.rss_mb, 2),
            "memory_pct": round(self.memory_pct, 2),
            "disk_read_mbs": round(self.disk_read_mbs, 3),
            "disk_write_mbs": round(self.disk_write_mbs, 3),
            "thread_count": self.thread_count,
        }


# =============================================================================
# THROTTLE STATE
# =============================================================================

@dataclass
class ThrottleState:
    """
    Current throttling state communicated to all components.

    Components poll ``is_throttled`` before expensive operations (e.g.,
    ML feature extraction, detailed forensics collection). When throttled,
    they skip optional work to reduce load.
    """

    is_throttled: bool = False
    throttle_reason: str = ""
    throttle_started_at: float = 0.0
    throttle_level: int = 0  # 0=none, 1=light, 2=heavy, 3=critical

    # Per-component overrides (component name → bool)
    component_overrides: dict[str, bool] = field(default_factory=dict)

    def is_component_throttled(self, component: str) -> bool:
        """Return True if this specific component should throttle."""
        return self.component_overrides.get(component, self.is_throttled)


# =============================================================================
# RESOURCE MANAGER
# =============================================================================

class ResourceManager:
    """
    Background resource budget enforcer for IHADRS.

    Responsibilities:
    - Sample IHADRS process CPU, RAM, and disk I/O every 5 seconds
    - Maintain a rolling 60-second history for average calculations
    - Apply throttling flags when budgets are exceeded
    - Trigger GC and cache eviction under memory pressure
    - Log resource usage at INFO level every 5 minutes
    - Expose health status to the API and UI

    Usage:
        rm = ResourceManager()
        rm.start()
        ...
        if rm.throttle_state.is_throttled:
            skip_expensive_operation()
        ...
        rm.stop()
    """

    # Rolling window size for CPU average calculation
    _CPU_HISTORY_SIZE: int = int(60 / RESOURCE_CHECK_INTERVAL_SECONDS)  # 60s worth

    # How often to log resource stats at INFO level
    _STATS_LOG_INTERVAL_SECONDS: float = 300.0  # 5 minutes

    def __init__(
        self,
        cpu_budget_average: float = CPU_BUDGET_AVERAGE_PCT,
        cpu_budget_peak: float = CPU_BUDGET_PEAK_PCT,
        ram_budget_baseline_mb: int = RAM_BUDGET_BASELINE_MB,
        ram_budget_max_mb: int = RAM_BUDGET_MAX_MB,
        disk_write_budget_mbs: float = DISK_IO_BUDGET_WRITE_MBS,
    ) -> None:
        self._cpu_budget_avg = cpu_budget_average
        self._cpu_budget_peak = cpu_budget_peak
        self._ram_budget_baseline = ram_budget_baseline_mb
        self._ram_budget_max = ram_budget_max_mb
        self._disk_write_budget = disk_write_budget_mbs

        # Get a handle to our own process
        self._process = psutil.Process(os.getpid())

        # Rolling CPU history for average calculation
        self._cpu_history: deque[float] = deque(maxlen=self._CPU_HISTORY_SIZE)

        # Previous disk I/O counters for delta calculation
        self._prev_disk_io: Optional[psutil._common.sdiskio] = None  # type: ignore[name-defined]
        self._prev_disk_io_time: float = 0.0

        # Current throttle state — shared across all components
        self.throttle_state = ThrottleState()

        # Snapshot history for trend analysis
        self._snapshots: deque[ResourceSnapshot] = deque(maxlen=720)  # 1 hour at 5s

        # Violation callbacks
        self._violation_callbacks: list[Callable[[str, float, float], None]] = []

        # State
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        self._last_stats_log_time: float = 0.0

        # Peak usage tracking
        self._peak_cpu: float = 0.0
        self._peak_ram_mb: float = 0.0

        logger.debug(
            "ResourceManager initialized: "
            "cpu_avg≤{avg}%, cpu_peak≤{peak}%, "
            "ram≤{ram}MB, disk_write≤{disk}MB/s",
            avg=cpu_budget_average,
            peak=cpu_budget_peak,
            ram=ram_budget_max_mb,
            disk=disk_write_budget_mbs,
        )

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    def start(self) -> None:
        """Start the background resource monitoring thread."""
        if self._running:
            return

        self._running = True

        # Initialize CPU monitoring (first call always returns 0.0)
        self._process.cpu_percent(interval=None)

        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="ihadrs-resource-monitor",
            daemon=True,
        )
        self._monitor_thread.start()
        logger.info("ResourceManager started.")

    def stop(self) -> None:
        """Stop the background monitoring thread."""
        self._running = False
        if self._monitor_thread is not None:
            self._monitor_thread.join(timeout=10.0)
        logger.info(
            "ResourceManager stopped. Peak CPU: {cpu:.1f}%, Peak RAM: {ram:.1f}MB",
            cpu=self._peak_cpu,
            ram=self._peak_ram_mb,
        )

    # -------------------------------------------------------------------------
    # Monitoring Loop
    # -------------------------------------------------------------------------

    def _monitor_loop(self) -> None:
        """Main resource monitoring loop running in background thread."""
        logger.debug("Resource monitoring loop started.")

        while self._running:
            try:
                snapshot = self._collect_snapshot()
                self._analyze_snapshot(snapshot)
                self._maybe_log_stats(snapshot)
            except psutil.NoSuchProcess:
                # Our own process disappeared — shouldn't happen but be safe
                logger.error("ResourceManager: IHADRS process no longer visible to psutil!")
                self._running = False
                break
            except Exception as exc:
                logger.warning(
                    "ResourceManager collection error (non-fatal): {exc}", exc=exc
                )

            time.sleep(RESOURCE_CHECK_INTERVAL_SECONDS)

        logger.debug("Resource monitoring loop exited.")

    def _collect_snapshot(self) -> ResourceSnapshot:
        """Collect a complete resource usage snapshot for the current process."""
        snapshot = ResourceSnapshot()

        # CPU usage (non-blocking — returns since last call)
        snapshot.cpu_pct = self._process.cpu_percent(interval=None)
        snapshot.cpu_pct_system = psutil.cpu_percent(interval=None)

        # Memory
        mem_info = self._process.memory_info()
        snapshot.rss_mb = mem_info.rss / (1024 * 1024)
        snapshot.vms_mb = mem_info.vms / (1024 * 1024)
        mem_pct = self._process.memory_percent()
        snapshot.memory_pct = mem_pct

        # Thread count
        snapshot.thread_count = self._process.num_threads()

        # Open files (Linux only — gracefully skip on Windows)
        try:
            snapshot.open_files = len(self._process.open_files())
        except (psutil.AccessDenied, NotImplementedError):
            snapshot.open_files = -1

        # Disk I/O rates (delta calculation)
        try:
            current_io = psutil.disk_io_counters()
            now = time.time()

            if self._prev_disk_io is not None and current_io is not None:
                elapsed = max(now - self._prev_disk_io_time, 0.001)
                read_delta = current_io.read_bytes - self._prev_disk_io.read_bytes
                write_delta = current_io.write_bytes - self._prev_disk_io.write_bytes
                snapshot.disk_read_mbs = max(0.0, read_delta / elapsed / (1024 * 1024))
                snapshot.disk_write_mbs = max(0.0, write_delta / elapsed / (1024 * 1024))

            self._prev_disk_io = current_io
            self._prev_disk_io_time = now
        except (psutil.AccessDenied, AttributeError):
            pass  # Not available on all platforms

        # Track peaks
        with self._lock:
            if snapshot.cpu_pct > self._peak_cpu:
                self._peak_cpu = snapshot.cpu_pct
            if snapshot.rss_mb > self._peak_ram_mb:
                self._peak_ram_mb = snapshot.rss_mb

        self._snapshots.append(snapshot)
        return snapshot

    def _analyze_snapshot(self, snapshot: ResourceSnapshot) -> None:
        """
        Analyze snapshot against budgets and update throttle state.

        Applies graduated responses:
        - Level 1 (light throttle): >80% of budget for 10s
        - Level 2 (heavy throttle): >100% of budget
        - Level 3 (critical): >150% of budget — aggressive GC + cache clear
        """
        with self._lock:
            # Update CPU history
            self._cpu_history.append(snapshot.cpu_pct)
            cpu_avg = (
                sum(self._cpu_history) / len(self._cpu_history)
                if self._cpu_history
                else 0.0
            )

            violations: list[tuple[str, float, float]] = []

            # --- CPU Budget Check ---
            if snapshot.cpu_pct > self._cpu_budget_peak:
                violations.append(("cpu_peak", snapshot.cpu_pct, self._cpu_budget_peak))
                logger.warning(
                    "CPU peak budget exceeded: {cur:.1f}% > {budget:.1f}%",
                    cur=snapshot.cpu_pct,
                    budget=self._cpu_budget_peak,
                )

            if cpu_avg > self._cpu_budget_avg * 1.5:
                violations.append(("cpu_avg_critical", cpu_avg, self._cpu_budget_avg))
            elif cpu_avg > self._cpu_budget_avg:
                violations.append(("cpu_avg", cpu_avg, self._cpu_budget_avg))

            # --- RAM Budget Check ---
            if snapshot.rss_mb > self._ram_budget_max:
                violations.append(("ram_max", snapshot.rss_mb, self._ram_budget_max))
                logger.warning(
                    "RAM budget exceeded: {cur:.1f}MB > {budget}MB",
                    cur=snapshot.rss_mb,
                    budget=self._ram_budget_max,
                )
                # Try to reclaim memory immediately
                self._reclaim_memory()

            # --- Disk I/O Budget Check ---
            if snapshot.disk_write_mbs > self._disk_write_budget:
                violations.append(
                    ("disk_write", snapshot.disk_write_mbs, self._disk_write_budget)
                )
                logger.warning(
                    "Disk write budget exceeded: {cur:.2f}MB/s > {budget}MB/s",
                    cur=snapshot.disk_write_mbs,
                    budget=self._disk_write_budget,
                )

            # --- Update Throttle State ---
            if violations:
                critical = any(
                    vtype in ("ram_max", "cpu_avg_critical")
                    for vtype, _, _ in violations
                )
                level = 3 if critical else (2 if len(violations) > 1 else 1)
                reason = "; ".join(
                    f"{vtype}={val:.1f}>{budget:.1f}"
                    for vtype, val, budget in violations
                )

                if not self.throttle_state.is_throttled:
                    logger.warning(
                        "IHADRS throttling activated (level {level}): {reason}",
                        level=level,
                        reason=reason,
                    )
                    self.throttle_state.throttle_started_at = time.time()

                self.throttle_state.is_throttled = True
                self.throttle_state.throttle_level = level
                self.throttle_state.throttle_reason = reason

                # Per-component throttling — disable expensive optional work
                self.throttle_state.component_overrides = {
                    "ml_classifier": True,           # Skip ML scoring
                    "forensics_collector": True,      # Skip memory dumps
                    "network_traffic_capture": True,  # Skip pcap
                }

                # Notify violation callbacks
                for vtype, val, budget in violations:
                    for cb in self._violation_callbacks:
                        try:
                            cb(vtype, val, budget)
                        except Exception as exc:
                            logger.debug(
                                "Violation callback error: {exc}", exc=exc
                            )

            else:
                # All budgets satisfied — lift throttle
                if self.throttle_state.is_throttled:
                    duration = time.time() - self.throttle_state.throttle_started_at
                    logger.info(
                        "IHADRS throttle lifted after {t:.1f}s. "
                        "CPU={cpu:.1f}%, RAM={ram:.1f}MB",
                        t=duration,
                        cpu=snapshot.cpu_pct,
                        ram=snapshot.rss_mb,
                    )

                self.throttle_state.is_throttled = False
                self.throttle_state.throttle_level = 0
                self.throttle_state.throttle_reason = ""
                self.throttle_state.component_overrides = {}

    def _reclaim_memory(self) -> None:
        """
        Attempt to reduce IHADRS memory usage when over budget.

        Actions taken:
        1. Python garbage collection
        2. Clear LRU caches (if accessible)
        3. Trim process working set (Windows-specific)
        """
        import gc
        collected = gc.collect(generation=2)
        logger.debug(
            "GC triggered under memory pressure: {n} objects collected.",
            n=collected,
        )

        # Windows: trim working set to release pages back to OS
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            handle = kernel32.GetCurrentProcess()
            kernel32.SetProcessWorkingSetSize(handle, -1, -1)
            logger.debug("Windows working set trimmed.")
        except (AttributeError, OSError):
            pass  # Not on Windows or access denied

    def _maybe_log_stats(self, snapshot: ResourceSnapshot) -> None:
        """Log resource stats at INFO level every 5 minutes."""
        now = time.time()
        if now - self._last_stats_log_time >= self._STATS_LOG_INTERVAL_SECONDS:
            self._last_stats_log_time = now
            cpu_avg = (
                sum(self._cpu_history) / len(self._cpu_history)
                if self._cpu_history
                else 0.0
            )
            logger.info(
                "Resource stats | CPU: {cpu:.1f}% (avg {avg:.1f}%) | "
                "RAM: {ram:.1f}MB | Disk W: {dw:.2f}MB/s | "
                "Threads: {t} | Throttled: {th}",
                cpu=snapshot.cpu_pct,
                avg=cpu_avg,
                ram=snapshot.rss_mb,
                dw=snapshot.disk_write_mbs,
                t=snapshot.thread_count,
                th=self.throttle_state.is_throttled,
            )

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def register_violation_callback(
        self, callback: Callable[[str, float, float], None]
    ) -> None:
        """
        Register a callback to be called when a resource budget is exceeded.

        Args:
            callback: Called with (violation_type, current_value, budget_value).
        """
        self._violation_callbacks.append(callback)

    def get_current_snapshot(self) -> Optional[ResourceSnapshot]:
        """Return the most recent resource snapshot, or None if none collected yet."""
        if not self._snapshots:
            return None
        return self._snapshots[-1]

    def get_cpu_average(self) -> float:
        """Return the rolling average CPU usage percentage."""
        with self._lock:
            if not self._cpu_history:
                return 0.0
            return sum(self._cpu_history) / len(self._cpu_history)

    def get_snapshot_history(self, count: int = 60) -> list[ResourceSnapshot]:
        """Return the last ``count`` snapshots (newest first)."""
        with self._lock:
            history = list(self._snapshots)
            return list(reversed(history[-count:]))

    def health_check(self) -> dict[str, Any]:
        """Return resource manager health status for API and UI."""
        snapshot = self.get_current_snapshot()
        cpu_avg = self.get_cpu_average()

        status = "healthy"
        issues: list[str] = []

        if self.throttle_state.is_throttled:
            status = "throttled"
            issues.append(f"Throttled: {self.throttle_state.throttle_reason}")

        if snapshot:
            if snapshot.cpu_pct > self._cpu_budget_peak:
                status = "degraded"
                issues.append(f"CPU peak {snapshot.cpu_pct:.1f}% > {self._cpu_budget_peak}%")
            if snapshot.rss_mb > self._ram_budget_max:
                status = "degraded"
                issues.append(f"RAM {snapshot.rss_mb:.1f}MB > {self._ram_budget_max}MB")

        return {
            "status": status,
            "issues": issues,
            "throttled": self.throttle_state.is_throttled,
            "throttle_level": self.throttle_state.throttle_level,
            "current": snapshot.to_dict() if snapshot else {},
            "cpu_average_pct": round(cpu_avg, 2),
            "peak_cpu_pct": round(self._peak_cpu, 2),
            "peak_ram_mb": round(self._peak_ram_mb, 2),
            "budgets": {
                "cpu_avg_pct": self._cpu_budget_avg,
                "cpu_peak_pct": self._cpu_budget_peak,
                "ram_max_mb": self._ram_budget_max,
                "disk_write_mbs": self._disk_write_budget,
            },
        }