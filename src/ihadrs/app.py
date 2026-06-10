"""
Module: app
Purpose: IHADRS application orchestrator.
         Responsible for initializing all subsystems in the correct order,
         wiring them together (event bus subscriptions, scheduler jobs),
         running the main event loop, and coordinating graceful shutdown.
Owner: application
Dependencies: all core subsystems
Performance: The orchestrator is the thin coordinator layer — all heavy work
             is delegated to components. Its overhead is negligible.

Startup Sequence:
    1. Load and validate configuration
    2. Set up logging
    3. Start resource manager (begin CPU/RAM monitoring)
    4. Initialize event bus and start dispatch loop
    5. Initialize storage (SQLite connection, run migrations)
    6. Initialize detection engine (load rules, ML model)
    7. Register detection engine as event bus subscriber
    8. Start all configured monitors
    9. Start scheduler (ML retrain, log rotation, health checks)
    10. Start alerting channels
    11. Start API server (if enabled)
    12. Emit IHADRS_STARTED event
    13. Enter wait loop (monitors + dispatcher run in background threads)

Shutdown Sequence (reverse of startup):
    1. Emit IHADRS_STOPPED event
    2. Stop API server
    3. Stop all monitors
    4. Stop scheduler
    5. Drain event bus (process remaining events)
    6. Stop event bus
    7. Flush and close logging
    8. Stop resource manager
"""

from __future__ import annotations

import asyncio
import os
import signal
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from loguru import logger

from ihadrs.constants import (
    APP_NAME,
    APP_VERSION,
    EventType,
    IS_WINDOWS,
    MonitorType,
    PLATFORM,
    STARTUP_TIMEOUT_SECONDS,
)
from ihadrs.core.config import IHADRSConfig
from ihadrs.core.event_bus import BusEvent, EventBus, EventPriority, initialize_event_bus
from ihadrs.core.resource_manager import ResourceManager
from ihadrs.core.scheduler import TaskScheduler
from ihadrs.exceptions import IHADRSError, MonitorInitializationError
from ihadrs.logging.logger import (
    get_audit_logger,
    get_component_logger,
    setup_audit_log,
    setup_logging,
)
from ihadrs.models.events import IHADRSInternalEvent

_log = get_component_logger("app")
_audit = get_audit_logger()


class Application:
    """
    IHADRS application instance.

    One instance per running IHADRS process. Owns all subsystem references
    and coordinates their lifecycle.

    Usage:
        config = ConfigLoader.load(config_path)
        app = Application(config)
        asyncio.run(app.run())   # Blocks until shutdown
    """

    def __init__(self, config: IHADRSConfig) -> None:
        self._config = config

        # Component references (set during initialization)
        self._event_bus: Optional[EventBus] = None
        self._resource_manager: Optional[ResourceManager] = None
        self._scheduler: Optional[TaskScheduler] = None

        # Monitor references
        self._monitors: list[Any] = []  # noqa: F821 — forward ref to base monitor

        # Detection engine
        self._detection_engine: Optional[Any] = None  # noqa: F821

        # State
        self._running = False
        self._startup_time: float = 0.0
        self._shutdown_event = threading.Event()

        # Hostname for event tagging
        self._hostname = socket.gethostname()

    # =========================================================================
    # PUBLIC INTERFACE
    # =========================================================================

    async def run(self) -> None:
        """
        Start IHADRS and run until shutdown is requested.

        Blocks until Ctrl+C, SIGTERM, or stop() is called.
        """
        start_time = time.monotonic()

        try:
            await self._initialize()
        except IHADRSError as exc:
            logger.critical(
                "IHADRS initialization failed: {exc}",
                exc=exc,
            )
            raise

        startup_duration = time.monotonic() - start_time
        self._startup_time = time.time()

        if startup_duration > STARTUP_TIMEOUT_SECONDS:
            logger.warning(
                "Startup took {t:.1f}s — exceeds {budget}s target.",
                t=startup_duration,
                budget=STARTUP_TIMEOUT_SECONDS,
            )
        else:
            logger.info(
                "IHADRS started successfully in {t:.2f}s. "
                "Platform: {platform} | Response: {mode}",
                t=startup_duration,
                platform=PLATFORM,
                mode=self._config.response.mode,
            )

        # Install signal handlers for graceful shutdown
        self._install_signal_handlers()

        # Emit startup event
        self._publish_internal_event(
            event_type=EventType.IHADRS_STARTED,
            message=(
                f"IHADRS {APP_VERSION} started. "
                f"Platform: {PLATFORM} | "
                f"Monitors: {len(self._monitors)} | "
                f"Response mode: {self._config.response.mode}"
            ),
        )

        # =====================================================================
        # MAIN WAIT LOOP
        # All actual work happens in background threads started during init.
        # The main thread just monitors health and waits for shutdown.
        # =====================================================================
        try:
            await self._wait_for_shutdown()
        except asyncio.CancelledError:
            logger.info("IHADRS shutdown via asyncio cancellation.")
        finally:
            await self._shutdown()

    async def stop(self) -> None:
        """Request graceful shutdown."""
        logger.info("Shutdown requested via Application.stop().")
        self._shutdown_event.set()

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def uptime_seconds(self) -> float:
        if self._startup_time == 0.0:
            return 0.0
        return time.time() - self._startup_time

    # =========================================================================
    # INITIALIZATION
    # =========================================================================

    async def _initialize(self) -> None:
        """
        Initialize all subsystems in dependency order.

        Each step must complete successfully before the next begins.
        """
        # 1. Logging
        self._setup_logging()

        _log.info(
            "Initializing {name} {version}...",
            name=APP_NAME,
            version=APP_VERSION,
        )

        # 2. Data directories
        self._ensure_directories()

        # 3. Resource Manager
        self._resource_manager = ResourceManager(
            cpu_budget_average=self._config.performance.cpu_budget_average_pct,
            cpu_budget_peak=self._config.performance.cpu_budget_peak_pct,
            ram_budget_max_mb=self._config.performance.ram_budget_max_mb,
        )
        self._resource_manager.start()
        _log.debug("Resource manager started.")

        # 4. Event Bus
        self._event_bus = initialize_event_bus(
            max_queue_size=self._config.performance.event_queue_size,
            max_events_per_second=self._config.performance.max_events_per_second,
        )
        _log.debug("Event bus started.")

        # 5. Storage (SQLite)
        await self._init_storage()

        # 6. Detection Engine
        await self._init_detection_engine()

        # 7. Alerting Channels
        self._init_alerting()

        # 7b. SecureOps outbound SOC exporter
        await self._init_secureops_exporter()

        # 8. Monitors
        await self._init_monitors()

        # 9. Scheduler
        self._init_scheduler()

        # 10. API Server
        if self._config.api.enabled:
            await self._init_api_server()

        self._running = True

    def _setup_logging(self) -> None:
        """Configure logging based on config."""
        log_dir = Path(self._config.logging.log_dir)

        setup_logging(
            log_dir=log_dir,
            level=self._config.logging.level,
            json_format=self._config.logging.json_format,
            console_output=self._config.logging.console_output,
            rotation_size=self._config.logging.rotation_size,
            retention_days=self._config.logging.retention_days,
            compression=self._config.logging.compression,
        )

        if self._config.security.audit_logging:
            setup_audit_log(log_dir=log_dir)

    def _ensure_directories(self) -> None:
        """Create required runtime directories if they don't exist."""
        dirs_to_create = [
            self._config.app.data_dir,
            self._config.logging.log_dir,
        ]
        for d in dirs_to_create:
            path = Path(d)
            path.mkdir(parents=True, exist_ok=True)
            _log.debug("Directory ready: {path}", path=path)

    async def _init_storage(self) -> None:
        """Initialize SQLite event store and subscribe it to the event bus."""
        _log.debug("Initializing event store...")
        try:
            from ihadrs.storage.event_store import EventStore
            self._event_store = EventStore(
                db_path=Path(self._config.storage.db_path),
                wal_mode=self._config.storage.wal_mode,
            )
            await self._event_store.initialize()
            _log.info("Event store ready: {path}", path=self._config.storage.db_path)

            # ── Subscribe event store to the bus so events are persisted ──
            assert self._event_bus is not None

            # Save ALL raw security events (process, file, network, auth, etc.)
            self._event_bus.subscribe(
                name="event_store_raw",
                callback=self._event_store.handle_bus_event,
                event_types=None,      # None = subscribe to ALL event types
                min_priority=EventPriority.LOW,
            )

            # Save detected threats separately for fast threat queries
            self._event_bus.subscribe(
                name="event_store_threats",
                callback=self._event_store.handle_threat_event,
                event_types={EventType.IHADRS_DETECTION_TRIGGERED},
                min_priority=EventPriority.LOW,
            )

            _log.info("Event store subscribed to event bus — all events will be persisted.")

        except Exception as exc:
            # Storage failure is serious but not always fatal — log and continue
            _log.error(
                "Event store initialization failed: {exc}. "
                "Events will not be persisted this session.",
                exc=exc,
            )
            self._event_store = None  # type: ignore[assignment]

    async def _init_detection_engine(self) -> None:
        """
        Initialize the detection engine and subscribe it to the event bus.

        The detection engine subscribes to ALL event types and processes
        each event through the rule chain.
        """
        _log.debug("Initializing detection engine...")
        try:
            from ihadrs.detection.engine import DetectionEngine
            self._detection_engine = DetectionEngine(
                config=self._config,
                event_bus=self._event_bus,
                resource_manager=self._resource_manager,
            )
            await self._detection_engine.initialize()

            # Subscribe detection engine to ALL events on the bus
            assert self._event_bus is not None
            self._event_bus.subscribe(
                name="detection_engine",
                callback=self._detection_engine.process_event,
                event_types=None,  # Subscribe to all
                min_priority=EventPriority.LOW,
            )

            _log.info("Detection engine ready with {n} rules.", n=self._detection_engine.rule_count)

        except Exception as exc:
            _log.error(
                "Detection engine initialization failed: {exc}", exc=exc
            )
            raise IHADRSError(
                f"Detection engine failed to start: {exc}",
                recoverable=False,
            ) from exc

    def _init_alerting(self) -> None:
        """Initialize alerting channels (console, desktop, email, webhook)."""
        _log.debug("Initializing alerting channels...")
        try:
            from ihadrs.alerting.notifier import Notifier
            self._notifier = Notifier(config=self._config)

            # Subscribe notifier to threat detection events only
            assert self._event_bus is not None
            self._event_bus.subscribe(
                name="alerting_notifier",
                callback=self._notifier.handle_event,
                event_types={EventType.IHADRS_DETECTION_TRIGGERED},
                min_priority=EventPriority.LOW,
            )
            _log.info("Alerting channels initialized.")
        except Exception as exc:
            # Alerting failure is recoverable — system protects even without alerts
            _log.error(
                "Alerting initialization failed: {exc}. "
                "Threats will be detected but no notifications sent.",
                exc=exc,
            )

    async def _init_secureops_exporter(self) -> None:
        """Initialize the SecureOps outbound EDR ingest exporter."""
        _log.debug("Initializing SecureOps SOC exporter...")
        try:
            from ihadrs.integrations.secureops import SecureOpsExporter

            self._secureops_exporter = SecureOpsExporter(config=self._config)
            await self._secureops_exporter.start()

            assert self._event_bus is not None
            self._event_bus.subscribe(
                name="secureops_exporter",
                callback=self._secureops_exporter.handle_event,
                event_types={EventType.IHADRS_DETECTION_TRIGGERED},
                min_priority=EventPriority.LOW,
            )
            _log.info("SecureOps SOC exporter initialized.")
        except Exception as exc:
            _log.error(
                "SecureOps exporter initialization failed: {exc}. "
                "SOC export will be unavailable.",
                exc=exc,
            )
            self._secureops_exporter = None  # type: ignore[assignment]

    async def _init_monitors(self) -> None:
        """
        Start all configured system monitors.

        Monitors that fail to initialize are logged but don't prevent
        other monitors from starting (graceful degradation).
        """
        _log.debug("Starting monitors: {monitors}", monitors=self._config.monitors.enabled_monitors)

        monitor_classes = self._get_monitor_classes()
        failed_monitors: list[str] = []

        for monitor_name, monitor_class in monitor_classes.items():
            if monitor_name not in self._config.monitors.enabled_monitors:
                _log.debug("Monitor '{name}' disabled — skipping.", name=monitor_name)
                continue

            try:
                monitor = monitor_class(
                    config=self._config,
                    event_bus=self._event_bus,
                )
                await monitor.initialize()
                await monitor.start()
                self._monitors.append(monitor)
                _log.info("Monitor started: {name}", name=monitor_name)

            except MonitorInitializationError as exc:
                failed_monitors.append(monitor_name)
                _log.error(
                    "Monitor '{name}' failed to start: {exc}",
                    name=monitor_name,
                    exc=exc,
                )
            except Exception as exc:
                failed_monitors.append(monitor_name)
                _log.error(
                    "Monitor '{name}' raised unexpected error: {exc}",
                    name=monitor_name,
                    exc=exc,
                )

        started = len(self._monitors)
        total = len([m for m in self._config.monitors.enabled_monitors
                     if m in monitor_classes])

        if started == 0 and total > 0:
            raise IHADRSError(
                "No monitors could be started. IHADRS cannot protect the system.",
                recoverable=False,
            )

        if failed_monitors:
            _log.warning(
                "{started}/{total} monitors started. Failed: {failed}",
                started=started,
                total=total,
                failed=", ".join(failed_monitors),
            )
        else:
            _log.info("{n} monitors running.", n=started)

    def _get_monitor_classes(self) -> dict[str, type]:
        """
        Return a mapping of monitor name → class.

        Uses lazy imports to avoid import errors on platforms where
        some monitors aren't available (e.g., registry monitor on Linux).
        """
        monitors: dict[str, type] = {}

        # Process monitor — works on all platforms
        try:
            from ihadrs.monitors.process_monitor import ProcessMonitor
            monitors["process"] = ProcessMonitor
        except ImportError as exc:
            _log.warning("Process monitor unavailable: {exc}", exc=exc)

        # Network monitor — works on all platforms
        try:
            from ihadrs.monitors.network_monitor import NetworkMonitor
            monitors["network"] = NetworkMonitor
        except ImportError as exc:
            _log.warning("Network monitor unavailable: {exc}", exc=exc)

        # File monitor — works on all platforms
        try:
            from ihadrs.monitors.file_monitor import FileMonitor
            monitors["file"] = FileMonitor
        except ImportError as exc:
            _log.warning("File monitor unavailable: {exc}", exc=exc)

        # Windows-only monitors
        if IS_WINDOWS:
            try:
                from ihadrs.monitors.registry_monitor import RegistryMonitor
                monitors["registry"] = RegistryMonitor
            except ImportError as exc:
                _log.warning("Registry monitor unavailable: {exc}", exc=exc)

            try:
                from ihadrs.monitors.service_monitor import ServiceMonitor
                monitors["service"] = ServiceMonitor
            except ImportError as exc:
                _log.warning("Service monitor unavailable: {exc}", exc=exc)

            try:
                from ihadrs.monitors.wmi_monitor import WMIMonitor
                monitors["wmi"] = WMIMonitor
            except ImportError as exc:
                _log.debug("WMI monitor unavailable: {exc}", exc=exc)

        # Authentication monitor — Event Log on Windows, auth.log on Linux
        try:
            from ihadrs.monitors.auth_monitor import AuthMonitor
            monitors["authentication"] = AuthMonitor
        except ImportError as exc:
            _log.warning("Auth monitor unavailable: {exc}", exc=exc)

        return monitors

    def _init_scheduler(self) -> None:
        """Register and start all recurring background jobs."""
        self._scheduler = TaskScheduler()

        # Health check — every 30 seconds
        self._scheduler.add_job(
            name="health_check",
            func=self._run_health_check,
            interval_seconds=30,
            run_immediately=True,
        )

        # ML model retrain — weekly (7 days = 604800 seconds)
        if self._config.ml.enabled:
            self._scheduler.add_job(
                name="ml_retrain",
                func=self._trigger_ml_retrain,
                interval_seconds=self._config.ml.retrain_interval_days * 86400,
            )

        # Database pruning — daily
        self._scheduler.add_job(
            name="db_prune",
            func=self._prune_old_events,
            interval_seconds=86400,
        )

        # Resource stats log — every 5 minutes
        self._scheduler.add_job(
            name="resource_stats",
            func=self._log_resource_stats,
            interval_seconds=300,
        )

        self._scheduler.start()
        _log.info(
            "Scheduler started with {n} jobs.",
            n=len(self._scheduler.get_jobs()),
        )

    async def _init_api_server(self) -> None:
        """Start the FastAPI REST API server in a background thread."""
        _log.debug("Starting API server...")
        try:
            from ihadrs.api.server import APIServer
            self._api_server = APIServer(config=self._config)

            # ── WIRE all live components into the API server ──
            # This is what makes /api/v1/status, /rules, /threats etc. return data
            self._api_server.monitors        = self._monitors
            self._api_server.detection_engine = self._detection_engine
            if hasattr(self, "_event_store"):
                self._api_server.event_store = self._event_store
            if hasattr(self, "_secureops_exporter"):
                self._api_server.secureops_exporter = self._secureops_exporter

            await self._api_server.start()
            _log.info(
                "API server listening on http://{host}:{port}",
                host=self._config.api.host,
                port=self._config.api.port,
            )
        except Exception as exc:
            _log.error(
                "API server failed to start: {exc}. API will be unavailable.",
                exc=exc,
            )

    # =========================================================================
    # MAIN LOOP
    # =========================================================================

    async def _wait_for_shutdown(self) -> None:
        """
        Block until shutdown is requested via signal or stop().

        Uses asyncio.sleep in 1-second intervals to remain responsive
        without busy-looping.
        """
        _log.debug("Entering main wait loop.")

        while not self._shutdown_event.is_set():
            await asyncio.sleep(1.0)

            # Periodic liveness check — restart any monitors that crashed
            if int(self.uptime_seconds) % 60 == 0:
                await self._check_monitor_health()

        _log.info("Shutdown event received. Beginning graceful stop.")

    async def _check_monitor_health(self) -> None:
        """Check all monitors are still running; attempt restart if not."""
        for monitor in self._monitors:
            try:
                health = await monitor.health_check()
                if health.get("status") == "failed":
                    _log.warning(
                        "Monitor '{name}' has failed — attempting restart.",
                        name=health.get("name", "unknown"),
                    )
                    await monitor.stop()
                    await monitor.initialize()
                    await monitor.start()
            except Exception as exc:
                _log.error(
                    "Monitor health check raised: {exc}", exc=exc
                )

    # =========================================================================
    # SHUTDOWN
    # =========================================================================

    async def _shutdown(self) -> None:
        """Graceful shutdown — reverse order of startup."""
        _log.info("Shutting down IHADRS...")

        self._publish_internal_event(
            event_type=EventType.IHADRS_STOPPED,
            message=f"IHADRS stopping after {self.uptime_seconds:.0f}s uptime.",
        )

        self._running = False

        # 1. Stop API server
        if hasattr(self, "_api_server"):
            try:
                await self._api_server.stop()
                _log.debug("API server stopped.")
            except Exception as exc:
                _log.error("API server stop error: {exc}", exc=exc)

        # 1b. Stop SecureOps exporter
        if hasattr(self, "_secureops_exporter") and self._secureops_exporter:
            try:
                await self._secureops_exporter.stop()
                _log.debug("SecureOps exporter stopped.")
            except Exception as exc:
                _log.error("SecureOps exporter stop error: {exc}", exc=exc)

        # 2. Stop scheduler
        if self._scheduler:
            self._scheduler.stop()
            _log.debug("Scheduler stopped.")

        # 3. Stop all monitors
        for monitor in reversed(self._monitors):
            try:
                await monitor.stop()
                _log.debug("Monitor stopped: {name}", name=monitor.__class__.__name__)
            except Exception as exc:
                _log.error("Monitor stop error: {exc}", exc=exc)

        # 4. Stop detection engine
        if self._detection_engine:
            try:
                await self._detection_engine.stop()
                _log.debug("Detection engine stopped.")
            except Exception as exc:
                _log.error("Detection engine stop error: {exc}", exc=exc)

        # 5. Drain and stop event bus
        if self._event_bus:
            self._event_bus.stop(drain_timeout_seconds=10.0)
            _log.debug("Event bus stopped.")

        # 6. Close storage
        if hasattr(self, "_event_store") and self._event_store:
            try:
                await self._event_store.close()
                _log.debug("Event store closed.")
            except Exception as exc:
                _log.error("Event store close error: {exc}", exc=exc)

        # 7. Stop resource manager
        if self._resource_manager:
            self._resource_manager.stop()

        _audit.info(
            "IHADRS shutdown complete.",
            uptime_seconds=round(self.uptime_seconds, 1),
        )
        _log.info("IHADRS shutdown complete. Uptime: {t:.0f}s", t=self.uptime_seconds)

    # =========================================================================
    # SIGNAL HANDLING
    # =========================================================================

    def _install_signal_handlers(self) -> None:
        """Install OS signal handlers for graceful shutdown."""
        loop = asyncio.get_event_loop()

        def _handle_signal(signame: str) -> None:
            _log.info("Received signal {sig} — initiating shutdown.", sig=signame)
            self._shutdown_event.set()

        try:
            loop.add_signal_handler(
                signal.SIGINT,
                lambda: _handle_signal("SIGINT"),
            )
            loop.add_signal_handler(
                signal.SIGTERM,
                lambda: _handle_signal("SIGTERM"),
            )
        except (NotImplementedError, RuntimeError):
            # Windows doesn't support add_signal_handler for all signals
            signal.signal(signal.SIGINT, lambda s, f: _handle_signal("SIGINT"))
            signal.signal(signal.SIGTERM, lambda s, f: _handle_signal("SIGTERM"))

    # =========================================================================
    # SCHEDULER JOBS
    # =========================================================================

    def _run_health_check(self) -> None:
        """Periodic health check — log status of all components."""
        issues: list[str] = []

        if self._event_bus:
            bus_health = self._event_bus.health_check()
            if bus_health["status"] != "healthy":
                issues.extend(bus_health.get("issues", []))

        if self._resource_manager:
            rm_health = self._resource_manager.health_check()
            if rm_health["status"] not in ("healthy",):
                issues.extend(rm_health.get("issues", []))

        if issues:
            _log.warning("Health check: {n} issue(s): {issues}", n=len(issues), issues=issues)
        else:
            _log.debug(
                "Health check OK. Uptime: {t:.0f}s | Monitors: {m}",
                t=self.uptime_seconds,
                m=len(self._monitors),
            )

    def _trigger_ml_retrain(self) -> None:
        """Trigger ML model retraining (called by scheduler)."""
        _log.info("Scheduled ML retrain triggered.")
        # Will be fully implemented in Phase 4
        _log.debug("ML retrain: not yet implemented (Phase 4).")

    def _prune_old_events(self) -> None:
        """Remove old events from the database (called by scheduler)."""
        _log.debug("Running daily database prune...")
        # Will be fully implemented in Phase 1b (storage)
        _log.debug("DB prune: not yet implemented (storage module).")

    def _log_resource_stats(self) -> None:
        """Log resource usage stats every 5 minutes."""
        if self._resource_manager:
            snapshot = self._resource_manager.get_current_snapshot()
            if snapshot:
                _log.info(
                    "Resource stats | CPU: {cpu:.1f}% | RAM: {ram:.1f}MB | "
                    "Disk W: {dw:.2f}MB/s | Monitors: {m} | Uptime: {t:.0f}s",
                    cpu=snapshot.cpu_pct,
                    ram=snapshot.rss_mb,
                    dw=snapshot.disk_write_mbs,
                    m=len(self._monitors),
                    t=self.uptime_seconds,
                )

    # =========================================================================
    # HELPERS
    # =========================================================================

    def _publish_internal_event(
        self,
        event_type: EventType,
        message: str,
        level: str = "INFO",
        details: Optional[dict] = None,
    ) -> None:
        """Publish an IHADRS internal lifecycle event to the bus."""
        if self._event_bus is None:
            return

        payload = IHADRSInternalEvent(
            event_type=event_type,
            source_monitor=MonitorType.SYNTHETIC,
            component="app",
            message=message,
            level=level,
            details=details or {},
            hostname=self._hostname,
        )

        try:
            self._event_bus.publish(
                BusEvent(
                    event_type=event_type,
                    source="app",
                    payload=payload,
                    priority=EventPriority.NORMAL,
                )
            )
        except Exception as exc:
            _log.debug(
                "Failed to publish internal event {type}: {exc}",
                type=event_type.value,
                exc=exc,
            )