"""
Module: storage.event_store
Purpose: SQLite-backed persistence for security events and threat detections.
         Provides async read/write operations with WAL mode for concurrent
         access, automatic schema migration, and efficient time-range queries.
Owner: storage
Dependencies: sqlite3 (stdlib), asyncio, loguru
Performance: SQLite with WAL mode handles ~10k writes/sec easily.
             Write path is non-blocking (asyncio executor). Read path
             is also async. Indexed on timestamp + severity + event_type
             for fast dashboard queries.

Schema:
    events          — Raw BusEvent payloads (JSONL-style)
    threat_events   — ThreatEvent records with full serialization
    audit_log       — Immutable audit trail for all IHADRS actions
    false_positives — User-marked false positive records
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Optional

from loguru import logger

from ihadrs.constants import (
    DB_CACHE_SIZE_KB,
    DB_MAX_EVENTS,
    DB_PRUNE_KEEP_DAYS,
    DB_WAL_MODE,
)
from ihadrs.exceptions import (
    DatabaseConnectionError,
    DatabaseMigrationError,
    DatabaseQueryError,
)


# =============================================================================
# SCHEMA MIGRATIONS
# =============================================================================

# Each migration is a list of SQL statements to execute in order.
# Migration IDs are sequential integers. Never modify a migration once
# it has been deployed — add a new one instead.
MIGRATIONS: dict[int, list[str]] = {
    1: [
        # Core events table — stores all raw bus events
        """
        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id    TEXT    NOT NULL UNIQUE,
            event_type  TEXT    NOT NULL,
            source      TEXT    NOT NULL,
            timestamp   REAL    NOT NULL,
            severity    TEXT,
            priority    INTEGER DEFAULT 2,
            payload     TEXT    NOT NULL,   -- JSON
            tags        TEXT    DEFAULT '[]',-- JSON array
            created_at  REAL    DEFAULT (unixepoch('now'))
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_events_timestamp   ON events(timestamp DESC)",
        "CREATE INDEX IF NOT EXISTS idx_events_event_type  ON events(event_type)",
        "CREATE INDEX IF NOT EXISTS idx_events_severity    ON events(severity)",
        "CREATE INDEX IF NOT EXISTS idx_events_source      ON events(source)",

        # Threat events table — classified threat detections
        """
        CREATE TABLE IF NOT EXISTS threat_events (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_id           TEXT    NOT NULL UNIQUE,
            timestamp           REAL    NOT NULL,
            attack_category     TEXT    NOT NULL,
            severity            TEXT    NOT NULL,
            confidence          REAL    NOT NULL,
            mitre_techniques    TEXT    DEFAULT '[]',   -- JSON array
            mitre_tactics       TEXT    DEFAULT '[]',   -- JSON array
            affected_resource   TEXT    NOT NULL,
            summary             TEXT    NOT NULL,
            source_monitor      TEXT    NOT NULL,
            triggered_rules     TEXT    DEFAULT '[]',   -- JSON array
            response_status     TEXT    DEFAULT 'none',
            false_positive      INTEGER DEFAULT 0,      -- boolean
            hostname            TEXT    DEFAULT '',
            username            TEXT    DEFAULT '',
            full_json           TEXT    NOT NULL,       -- Complete serialized ThreatEvent
            created_at          REAL    DEFAULT (unixepoch('now'))
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_threat_timestamp  ON threat_events(timestamp DESC)",
        "CREATE INDEX IF NOT EXISTS idx_threat_severity   ON threat_events(severity)",
        "CREATE INDEX IF NOT EXISTS idx_threat_category   ON threat_events(attack_category)",
        "CREATE INDEX IF NOT EXISTS idx_threat_fp         ON threat_events(false_positive)",

        # Audit log — append-only record of all IHADRS actions
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            audit_id        TEXT    NOT NULL UNIQUE,
            timestamp       REAL    NOT NULL,
            action_type     TEXT    NOT NULL,
            component       TEXT    NOT NULL,
            target          TEXT    DEFAULT '',
            threat_id       TEXT    DEFAULT '',
            operator        TEXT    DEFAULT 'auto',    -- 'auto' or username
            result          TEXT    DEFAULT 'success', -- 'success' | 'failure' | 'rolled_back'
            details         TEXT    DEFAULT '{}',      -- JSON
            created_at      REAL    DEFAULT (unixepoch('now'))
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC)",
        "CREATE INDEX IF NOT EXISTS idx_audit_threat_id ON audit_log(threat_id)",

        # False positive records
        """
        CREATE TABLE IF NOT EXISTS false_positives (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_id       TEXT    NOT NULL UNIQUE,
            marked_by       TEXT    NOT NULL,
            marked_at       REAL    NOT NULL,
            reason          TEXT    DEFAULT '',
            rule_ids        TEXT    DEFAULT '[]',  -- JSON array of suppressed rules
            created_at      REAL    DEFAULT (unixepoch('now'))
        )
        """,

        # Schema version tracking
        """
        CREATE TABLE IF NOT EXISTS schema_version (
            version     INTEGER NOT NULL,
            applied_at  REAL    NOT NULL
        )
        """,
    ],
}

_SCHEMA_VERSION = max(MIGRATIONS.keys())


# =============================================================================
# EVENT STORE
# =============================================================================

class EventStore:
    """
    SQLite-backed persistence layer for IHADRS security events.

    All I/O is non-blocking — writes and reads run in a thread pool
    executor so they never block the asyncio event loop.

    Usage:
        store = EventStore(db_path=Path("./data/ihadrs.db"))
        await store.initialize()
        await store.save_threat(threat_event)
        threats = await store.get_threats(limit=50, severity="CRITICAL")
        await store.close()
    """

    def __init__(
        self,
        db_path: Path,
        wal_mode: bool = DB_WAL_MODE,
        cache_size_kb: int = DB_CACHE_SIZE_KB,
    ) -> None:
        self._db_path = db_path
        self._wal_mode = wal_mode
        self._cache_size_kb = cache_size_kb
        self._connection: Optional[sqlite3.Connection] = None
        self._lock = asyncio.Lock()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        logger.debug(
            "EventStore configured: path={path} wal={wal}",
            path=db_path,
            wal=wal_mode,
        )

    # =========================================================================
    # Lifecycle
    # =========================================================================

    async def initialize(self) -> None:
        """
        Open the database and run any pending schema migrations.

        Creates the database file and parent directories if they don't exist.

        Raises:
            DatabaseConnectionError: Cannot open or create the database.
            DatabaseMigrationError:  Migration SQL fails to execute.
        """
        self._loop = asyncio.get_event_loop()

        # Ensure parent directory exists
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            await self._run_in_executor(self._open_connection)
        except sqlite3.Error as exc:
            raise DatabaseConnectionError(
                db_path=str(self._db_path),
                reason=str(exc),
            ) from exc

        await self._run_migrations()
        logger.info("EventStore initialized: {path}", path=self._db_path)

    def _open_connection(self) -> None:
        """Open SQLite connection with optimal settings (runs in executor)."""
        self._connection = sqlite3.connect(
            str(self._db_path),
            check_same_thread=False,  # We serialize access via asyncio.Lock
            timeout=10.0,
        )
        self._connection.row_factory = sqlite3.Row  # Dict-like rows

        # Performance settings
        if self._wal_mode:
            self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute(
            f"PRAGMA cache_size=-{self._cache_size_kb}"  # Negative = KB
        )
        self._connection.execute("PRAGMA synchronous=NORMAL")
        self._connection.execute("PRAGMA temp_store=MEMORY")
        self._connection.execute("PRAGMA mmap_size=268435456")  # 256MB mmap
        self._connection.execute("PRAGMA foreign_keys=ON")

    async def close(self) -> None:
        """Flush and close the database connection."""
        if self._connection:
            await self._run_in_executor(self._connection.close)
            self._connection = None
        logger.debug("EventStore closed.")

    # =========================================================================
    # Migrations
    # =========================================================================

    async def _run_migrations(self) -> None:
        """Apply any pending schema migrations in version order."""
        current_version = await self._run_in_executor(self._get_schema_version)
        pending = {
            v: sqls
            for v, sqls in MIGRATIONS.items()
            if v > current_version
        }

        if not pending:
            logger.debug(
                "EventStore schema is up to date (version {v}).",
                v=current_version,
            )
            return

        for version in sorted(pending.keys()):
            logger.info(
                "Applying EventStore migration v{v}...", v=version
            )
            await self._run_in_executor(
                self._apply_migration, version, pending[version]
            )
            logger.info("Migration v{v} applied successfully.", v=version)

    def _get_schema_version(self) -> int:
        """Return the current schema version from the database."""
        assert self._connection
        try:
            # schema_version table may not exist yet (fresh DB)
            result = self._connection.execute(
                "SELECT MAX(version) FROM schema_version"
            ).fetchone()
            return int(result[0]) if result and result[0] else 0
        except sqlite3.OperationalError:
            return 0

    def _apply_migration(self, version: int, statements: list[str]) -> None:
        """Execute a migration within a transaction (runs in executor)."""
        assert self._connection
        try:
            with self._connection:  # Auto-commit/rollback
                for sql in statements:
                    self._connection.execute(sql.strip())
                self._connection.execute(
                    "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                    (version, time.time()),
                )
        except sqlite3.Error as exc:
            raise DatabaseMigrationError(
                migration_id=f"v{version}",
                reason=str(exc),
            ) from exc

    # =========================================================================
    # Raw Event Operations
    # =========================================================================

    async def save_event(
        self,
        event_id: str,
        event_type: str,
        source: str,
        timestamp: float,
        payload: dict[str, Any],
        severity: Optional[str] = None,
        priority: int = 2,
        tags: Optional[list[str]] = None,
    ) -> None:
        """
        Persist a raw bus event to the events table.

        Args:
            event_id:   Unique BusEvent ID.
            event_type: EventType string value.
            source:     Source monitor name.
            timestamp:  Unix timestamp (UTC).
            payload:    Serializable event payload dict.
            severity:   Optional severity string.
            priority:   Queue priority level (0–3).
            tags:       Optional list of string tags.

        Raises:
            DatabaseQueryError: If the INSERT fails.
        """
        def _insert() -> None:
            assert self._connection
            try:
                with self._connection:
                    self._connection.execute(
                        """
                        INSERT OR IGNORE INTO events
                            (event_id, event_type, source, timestamp, severity,
                             priority, payload, tags)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            event_id,
                            event_type,
                            source,
                            timestamp,
                            severity,
                            priority,
                            json.dumps(payload, default=str),
                            json.dumps(tags or []),
                        ),
                    )
            except sqlite3.Error as exc:
                raise DatabaseQueryError(
                    query="INSERT INTO events ...",
                    reason=str(exc),
                ) from exc

        async with self._lock:
            await self._run_in_executor(_insert)

    async def get_events(
        self,
        limit: int = 100,
        offset: int = 0,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        source: Optional[str] = None,
        since_timestamp: Optional[float] = None,
        until_timestamp: Optional[float] = None,
    ) -> list[dict[str, Any]]:
        """
        Query raw events with flexible filtering.

        Args:
            limit:           Maximum rows to return.
            offset:          Pagination offset.
            event_type:      Filter by event type string.
            severity:        Filter by severity level.
            source:          Filter by source monitor name.
            since_timestamp: Return only events after this Unix timestamp.
            until_timestamp: Return only events before this Unix timestamp.

        Returns:
            List of event dicts, newest first.
        """
        conditions: list[str] = []
        params: list[Any] = []

        if event_type:
            conditions.append("event_type = ?")
            params.append(event_type)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if source:
            conditions.append("source = ?")
            params.append(source)
        if since_timestamp is not None:
            conditions.append("timestamp >= ?")
            params.append(since_timestamp)
        if until_timestamp is not None:
            conditions.append("timestamp <= ?")
            params.append(until_timestamp)

        where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
        query = f"""
            SELECT event_id, event_type, source, timestamp, severity,
                   priority, payload, tags
            FROM events
            {where_clause}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """
        params.extend([min(limit, 500), offset])

        def _query() -> list[dict[str, Any]]:
            assert self._connection
            try:
                rows = self._connection.execute(query, params).fetchall()
                results = []
                for row in rows:
                    record = dict(row)
                    record["payload"] = json.loads(record["payload"])
                    record["tags"] = json.loads(record["tags"])
                    results.append(record)
                return results
            except sqlite3.Error as exc:
                raise DatabaseQueryError(
                    query=query[:100],
                    reason=str(exc),
                ) from exc

        async with self._lock:
            return await self._run_in_executor(_query)

    # =========================================================================
    # Threat Event Operations
    # =========================================================================

    async def save_threat(self, threat_dict: dict[str, Any]) -> None:
        """
        Persist a serialized ThreatEvent to the threat_events table.

        Args:
            threat_dict: Output of ThreatEvent.to_dict().

        Raises:
            DatabaseQueryError: If the INSERT fails.
        """
        def _insert() -> None:
            assert self._connection
            threat_id = threat_dict["threat_id"]
            ts = datetime.fromisoformat(
                threat_dict["timestamp"]
            ).timestamp()

            try:
                with self._connection:
                    self._connection.execute(
                        """
                        INSERT OR REPLACE INTO threat_events
                            (threat_id, timestamp, attack_category, severity,
                             confidence, mitre_techniques, mitre_tactics,
                             affected_resource, summary, source_monitor,
                             triggered_rules, response_status, false_positive,
                             hostname, username, full_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            threat_id,
                            ts,
                            threat_dict.get("attack_category", "Unknown"),
                            threat_dict.get("severity", "MEDIUM"),
                            threat_dict.get("confidence", 0.5),
                            json.dumps(
                                threat_dict.get("mitre", {}).get("techniques", [])
                            ),
                            json.dumps(
                                threat_dict.get("mitre", {}).get("tactics", [])
                            ),
                            threat_dict.get("affected_resource", ""),
                            threat_dict.get("summary", ""),
                            threat_dict.get("source_monitor", ""),
                            json.dumps(
                                threat_dict.get("evidence", {}).get("triggered_rules", [])
                            ),
                            threat_dict.get("response_status", "none"),
                            int(threat_dict.get("false_positive", {}).get("marked", False)),
                            threat_dict.get("hostname", ""),
                            threat_dict.get("username", ""),
                            json.dumps(threat_dict, default=str),
                        ),
                    )
            except sqlite3.Error as exc:
                raise DatabaseQueryError(
                    query="INSERT INTO threat_events ...",
                    reason=str(exc),
                ) from exc

        async with self._lock:
            await self._run_in_executor(_insert)

    async def get_threats(
        self,
        limit: int = 50,
        offset: int = 0,
        severity: Optional[str] = None,
        attack_category: Optional[str] = None,
        include_false_positives: bool = False,
        since_timestamp: Optional[float] = None,
    ) -> list[dict[str, Any]]:
        """
        Query threat events with filtering.

        Returns:
            List of full ThreatEvent dicts (from full_json column),
            newest first.
        """
        conditions: list[str] = []
        params: list[Any] = []

        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if attack_category:
            conditions.append("attack_category = ?")
            params.append(attack_category)
        if not include_false_positives:
            conditions.append("false_positive = 0")
        if since_timestamp is not None:
            conditions.append("timestamp >= ?")
            params.append(since_timestamp)

        where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
        query = f"""
            SELECT full_json
            FROM threat_events
            {where_clause}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """
        params.extend([min(limit, 500), offset])

        def _query() -> list[dict[str, Any]]:
            assert self._connection
            try:
                rows = self._connection.execute(query, params).fetchall()
                return [json.loads(row["full_json"]) for row in rows]
            except sqlite3.Error as exc:
                raise DatabaseQueryError(
                    query=query[:100],
                    reason=str(exc),
                ) from exc

        async with self._lock:
            return await self._run_in_executor(_query)

    async def get_threat_by_id(self, threat_id: str) -> Optional[dict[str, Any]]:
        """Return a single ThreatEvent dict by ID, or None if not found."""
        def _query() -> Optional[dict[str, Any]]:
            assert self._connection
            row = self._connection.execute(
                "SELECT full_json FROM threat_events WHERE threat_id = ?",
                (threat_id,),
            ).fetchone()
            return json.loads(row["full_json"]) if row else None

        async with self._lock:
            return await self._run_in_executor(_query)

    async def update_threat_response_status(
        self, threat_id: str, status: str
    ) -> None:
        """Update the response_status field for a threat."""
        def _update() -> None:
            assert self._connection
            with self._connection:
                self._connection.execute(
                    "UPDATE threat_events SET response_status = ? WHERE threat_id = ?",
                    (status, threat_id),
                )

        async with self._lock:
            await self._run_in_executor(_update)

    async def mark_false_positive(
        self,
        threat_id: str,
        marked_by: str,
        reason: str = "",
    ) -> None:
        """Mark a threat event as a false positive."""
        def _update() -> None:
            assert self._connection
            with self._connection:
                self._connection.execute(
                    "UPDATE threat_events SET false_positive = 1 WHERE threat_id = ?",
                    (threat_id,),
                )
                self._connection.execute(
                    """
                    INSERT OR REPLACE INTO false_positives
                        (threat_id, marked_by, marked_at, reason)
                    VALUES (?, ?, ?, ?)
                    """,
                    (threat_id, marked_by, time.time(), reason),
                )

        async with self._lock:
            await self._run_in_executor(_update)

    # =========================================================================
    # Audit Log Operations
    # =========================================================================

    # =========================================================================
    # Bus Event Handlers — called directly by the event bus subscriber threads
    # =========================================================================

    def set_event_loop(self, loop: Any) -> None:
        """Store the main asyncio event loop so threaded handlers can schedule saves."""
        self._main_loop = loop

    def handle_bus_event(self, bus_event: Any) -> None:
        """
        Synchronous bus callback — saves raw security events to SQLite.
        Called from event bus worker threads.
        Uses run_coroutine_threadsafe() to schedule saves on the main event loop.
        """
        try:
            from ihadrs.constants import EventType
            if bus_event.event_type == EventType.IHADRS_DETECTION_TRIGGERED:
                return  # Threats handled separately

            payload = bus_event.payload
            payload_dict: dict = {}
            if hasattr(payload, "to_dict"):
                try:
                    payload_dict = payload.to_dict()
                except Exception:
                    payload_dict = {"raw": str(payload)[:500]}
            elif isinstance(payload, dict):
                payload_dict = payload

            import time as _time
            event_id   = str(getattr(bus_event, "bus_event_id",
                             getattr(payload, "event_id", id(bus_event))))
            event_type = (bus_event.event_type.value
                          if hasattr(bus_event.event_type, "value")
                          else str(bus_event.event_type))
            source     = str(getattr(bus_event, "source", "unknown"))
            timestamp  = _time.time()
            severity   = payload_dict.get("severity") or getattr(bus_event, "severity", None)
            if hasattr(severity, "value"):
                severity = severity.value
            tags = list(getattr(bus_event, "tags", []))

            self._save_event_sync(
                event_id=event_id,
                event_type=event_type,
                source=source,
                timestamp=timestamp,
                payload=payload_dict,
                severity=str(severity) if severity else None,
                tags=tags,
            )
        except Exception:
            pass  # Never crash the bus

    def handle_threat_event(self, bus_event: Any) -> None:
        """
        Synchronous bus callback — saves ThreatEvents to SQLite.
        Called from event bus worker threads.
        """
        try:
            threat = bus_event.payload
            if not hasattr(threat, "to_dict"):
                return
            threat_dict = threat.to_dict()
            self._save_threat_sync(threat_dict)
        except Exception:
            pass  # Never crash the bus

    def _save_event_sync(
        self,
        event_id: str,
        event_type: str,
        source: str,
        timestamp: float,
        payload: dict,
        severity: Any = None,
        tags: list = None,
    ) -> None:
        """Direct synchronous SQLite write for raw events. Called from bus threads."""
        import json as _json
        if not self._connection:
            return
        try:
            with self._connection:
                self._connection.execute(
                    """
                    INSERT OR IGNORE INTO events
                        (event_id, event_type, source, timestamp, severity,
                         priority, payload, tags)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        event_type,
                        source,
                        timestamp,
                        severity,
                        2,
                        _json.dumps(payload, default=str),
                        _json.dumps(tags or []),
                    ),
                )
        except Exception:
            pass

    def _save_threat_sync(self, threat_dict: dict) -> None:
        """Direct synchronous SQLite write for threats. Called from bus threads."""
        import json as _json
        if not self._connection:
            return
        try:
            threat_id = threat_dict.get("threat_id", "")
            from datetime import datetime, timezone
            ts_str = threat_dict.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_str).timestamp()
            except Exception:
                import time as _time
                ts = _time.time()

            mitre = threat_dict.get("mitre", {})
            evidence = threat_dict.get("evidence", {})

            with self._connection:
                self._connection.execute(
                    """
                    INSERT OR REPLACE INTO threat_events
                        (threat_id, timestamp, attack_category, severity,
                         confidence, mitre_techniques, mitre_tactics,
                         affected_resource, summary, source_monitor,
                         triggered_rules, response_status, false_positive,
                         hostname, username, full_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        threat_id,
                        ts,
                        threat_dict.get("attack_category", "Unknown"),
                        threat_dict.get("severity", "MEDIUM"),
                        threat_dict.get("confidence", 0.5),
                        _json.dumps(mitre.get("techniques", [])),
                        _json.dumps(mitre.get("tactics", [])),
                        threat_dict.get("affected_resource", ""),
                        threat_dict.get("summary", ""),
                        threat_dict.get("source_monitor", ""),
                        _json.dumps(evidence.get("triggered_rule_ids", [])),
                        threat_dict.get("response_status", "none"),
                        0,
                        threat_dict.get("hostname", ""),
                        threat_dict.get("username", ""),
                        _json.dumps(threat_dict, default=str),
                    ),
                )
        except Exception:
            pass

    async def save_audit_record(
        self,
        action_type: str,
        component: str,
        target: str = "",
        threat_id: str = "",
        operator: str = "auto",
        result: str = "success",
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        """
        Append an immutable record to the audit log.

        The audit log records every action IHADRS takes for accountability
        and forensic purposes. Records are never deleted (except by explicit
        retention policy).

        Args:
            action_type: Type of action (e.g., "kill_process", "block_ip").
            component:   Which IHADRS component took the action.
            target:      What was acted upon (PID, IP, file path).
            threat_id:   The ThreatEvent that triggered this action.
            operator:    "auto" or the username who approved.
            result:      "success" | "failure" | "rolled_back".
            details:     Additional context as a dict.
        """
        import uuid

        audit_id = str(uuid.uuid4())

        def _insert() -> None:
            assert self._connection
            with self._connection:
                self._connection.execute(
                    """
                    INSERT INTO audit_log
                        (audit_id, timestamp, action_type, component, target,
                         threat_id, operator, result, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        audit_id,
                        time.time(),
                        action_type,
                        component,
                        target,
                        threat_id,
                        operator,
                        result,
                        json.dumps(details or {}, default=str),
                    ),
                )

        async with self._lock:
            await self._run_in_executor(_insert)

    # =========================================================================
    # Statistics & Dashboard Queries
    # =========================================================================

    async def get_threat_stats(
        self, since_hours: int = 24
    ) -> dict[str, Any]:
        """
        Return aggregated threat statistics for the dashboard.

        Args:
            since_hours: Time window in hours (default: last 24 hours).

        Returns:
            Dict with counts by severity, category, and top techniques.
        """
        since_ts = time.time() - (since_hours * 3600)

        def _stats() -> dict[str, Any]:
            assert self._connection
            conn = self._connection

            total = conn.execute(
                "SELECT COUNT(*) FROM threat_events WHERE timestamp >= ? "
                "AND false_positive = 0",
                (since_ts,),
            ).fetchone()[0]

            by_severity = {}
            for row in conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM threat_events "
                "WHERE timestamp >= ? AND false_positive = 0 "
                "GROUP BY severity",
                (since_ts,),
            ).fetchall():
                by_severity[row["severity"]] = row["cnt"]

            by_category = {}
            for row in conn.execute(
                "SELECT attack_category, COUNT(*) as cnt FROM threat_events "
                "WHERE timestamp >= ? AND false_positive = 0 "
                "GROUP BY attack_category ORDER BY cnt DESC LIMIT 10",
                (since_ts,),
            ).fetchall():
                by_category[row["attack_category"]] = row["cnt"]

            false_positives = conn.execute(
                "SELECT COUNT(*) FROM threat_events WHERE timestamp >= ? "
                "AND false_positive = 1",
                (since_ts,),
            ).fetchone()[0]

            return {
                "total_threats": total,
                "false_positives": false_positives,
                "by_severity": by_severity,
                "by_category": by_category,
                "window_hours": since_hours,
            }

        async with self._lock:
            return await self._run_in_executor(_stats)

    # =========================================================================
    # Maintenance
    # =========================================================================

    async def prune_old_events(
        self,
        keep_days: int = DB_PRUNE_KEEP_DAYS,
        max_events: int = DB_MAX_EVENTS,
    ) -> int:
        """
        Delete old events to keep the database within size limits.

        Prune strategy:
        1. Delete events older than keep_days
        2. If total count still > max_events, delete oldest until at limit

        Returns:
            Number of rows deleted.
        """
        cutoff = time.time() - (keep_days * 86400)

        def _prune() -> int:
            assert self._connection
            deleted = 0
            with self._connection:
                # Age-based pruning
                cursor = self._connection.execute(
                    "DELETE FROM events WHERE timestamp < ?",
                    (cutoff,),
                )
                deleted += cursor.rowcount

                # Volume-based pruning (keep only max_events newest)
                count = self._connection.execute(
                    "SELECT COUNT(*) FROM events"
                ).fetchone()[0]

                if count > max_events:
                    excess = count - max_events
                    cursor = self._connection.execute(
                        """
                        DELETE FROM events WHERE id IN (
                            SELECT id FROM events
                            ORDER BY timestamp ASC
                            LIMIT ?
                        )
                        """,
                        (excess,),
                    )
                    deleted += cursor.rowcount

                # VACUUM to reclaim disk space
                if deleted > 1000:
                    self._connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")

            return deleted

        async with self._lock:
            deleted = await self._run_in_executor(_prune)
            if deleted > 0:
                logger.info(
                    "EventStore pruned {n} old events.", n=deleted
                )
            return deleted

    async def get_database_stats(self) -> dict[str, Any]:
        """Return database file size and row counts for health reporting."""
        def _stats() -> dict[str, Any]:
            assert self._connection
            conn = self._connection
            return {
                "events_count": conn.execute(
                    "SELECT COUNT(*) FROM events"
                ).fetchone()[0],
                "threats_count": conn.execute(
                    "SELECT COUNT(*) FROM threat_events"
                ).fetchone()[0],
                "audit_count": conn.execute(
                    "SELECT COUNT(*) FROM audit_log"
                ).fetchone()[0],
                "db_size_mb": round(
                    self._db_path.stat().st_size / (1024 * 1024), 2
                ) if self._db_path.exists() else 0,
                "schema_version": self._get_schema_version(),
            }

        async with self._lock:
            return await self._run_in_executor(_stats)

    # =========================================================================
    # Async Executor Helper
    # =========================================================================

    async def _run_in_executor(self, func: Any, *args: Any) -> Any:
        """Run a synchronous function in the default thread pool executor."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, func, *args)