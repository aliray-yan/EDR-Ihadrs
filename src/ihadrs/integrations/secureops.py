"""
SecureOps SOC export integration.

The exporter subscribes to IHADRS detections, converts them to the SecureOps
EDR ingest schema, stores them in a durable outbound queue, and uploads due
alerts with retry/backoff semantics.
"""

from __future__ import annotations

import base64
import json
import os
import platform as platform_module
import re
import socket
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib import error as urllib_error
from urllib import request as urllib_request
from urllib.parse import urlparse

from loguru import logger

from ihadrs.constants import APP_VERSION, IS_WINDOWS, Severity
from ihadrs.core.config import IHADRSConfig
from ihadrs.core.event_bus import BusEvent
from ihadrs.models.threats import ThreatEvent

SECUREOPS_HEADER = "X-SecureOps-Ingest-Key"
SECUREOPS_SOURCE = "EDR"
DEFAULT_BACKOFF_SECONDS = [10, 30, 120, 300, 900]

_HOST_ID_RE = re.compile(r"[^A-Za-z0-9_.-]+")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class SecureOpsResponse:
    status_code: int
    text: str

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    def json(self) -> Any:
        return json.loads(self.text or "{}")


class SecureOpsRequestError(Exception):
    """Raised when SecureOps cannot be reached over the network."""


@dataclass
class SecureOpsSettings:
    enabled: bool
    api_base_url: str
    allow_http_lab: bool
    key_configured: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "api_base_url": self.api_base_url,
            "allow_http_lab": self.allow_http_lab,
            "key_configured": self.key_configured,
            "header": SECUREOPS_HEADER,
            "source": SECUREOPS_SOURCE,
        }


class SecureOpsCredentialStore:
    """Stores the SecureOps ingest key with Windows DPAPI."""

    ENV_KEY = "IHADRS_SECUREOPS_INGEST_KEY"

    def __init__(self, data_dir: Path) -> None:
        self._path = Path(data_dir) / "secureops_ingest_key.dpapi"
        self._entropy = b"IHADRS SecureOps ingest key v1"
        self._log = logger.bind(component="SecureOpsCredentialStore")

    def get_key(self) -> Optional[str]:
        env_key = os.environ.get(self.ENV_KEY)
        if env_key:
            return env_key

        if not self._path.exists():
            return None
        if not IS_WINDOWS:
            self._log.warning("SecureOps ingest key file exists but DPAPI is Windows-only.")
            return None

        try:
            import win32crypt

            encrypted = base64.b64decode(self._path.read_text(encoding="ascii"))
            _, secret = win32crypt.CryptUnprotectData(
                encrypted,
                self._entropy,
                None,
                None,
                0,
            )
            return secret.decode("utf-8")
        except Exception as exc:
            self._log.warning("Could not decrypt SecureOps ingest key: {exc}", exc=exc)
            return None

    def set_key(self, ingest_key: str) -> None:
        cleaned = ingest_key.strip()
        if not cleaned:
            self.delete_key()
            return
        if not IS_WINDOWS:
            raise RuntimeError("Saving the SecureOps ingest key requires Windows DPAPI.")

        try:
            import win32crypt
        except ImportError as exc:
            raise RuntimeError("pywin32 is required to save the ingest key with DPAPI.") from exc

        self._path.parent.mkdir(parents=True, exist_ok=True)
        encrypted = win32crypt.CryptProtectData(
            cleaned.encode("utf-8"),
            "IHADRS SecureOps ingest key",
            self._entropy,
            None,
            None,
            0,
        )
        self._path.write_text(base64.b64encode(encrypted).decode("ascii"), encoding="ascii")

    def delete_key(self) -> None:
        try:
            if self._path.exists():
                self._path.unlink()
        except OSError as exc:
            self._log.warning("Could not delete SecureOps ingest key: {exc}", exc=exc)

    def has_key(self) -> bool:
        return bool(os.environ.get(self.ENV_KEY)) or self._path.exists()


class SecureOpsSettingsStore:
    """Persists non-secret SecureOps settings and delegates key storage to DPAPI."""

    def __init__(self, config: IHADRSConfig) -> None:
        self._config = config
        self._data_dir = Path(config.app.data_dir)
        self._path = self._data_dir / "secureops_settings.json"
        self.credentials = SecureOpsCredentialStore(self._data_dir)
        self._lock = threading.RLock()

    def load(self) -> SecureOpsSettings:
        secureops = self._config.secureops
        settings = {
            "enabled": secureops.enabled,
            "api_base_url": secureops.api_base_url,
            "allow_http_lab": secureops.allow_http_lab,
        }

        with self._lock:
            if self._path.exists():
                try:
                    persisted = json.loads(self._path.read_text(encoding="utf-8"))
                    if isinstance(persisted, dict):
                        settings.update({
                            key: persisted[key]
                            for key in ("enabled", "api_base_url", "allow_http_lab")
                            if key in persisted
                        })
                except (OSError, json.JSONDecodeError) as exc:
                    logger.warning("Could not read SecureOps settings: {exc}", exc=exc)

        settings["api_base_url"] = normalize_api_base_url(str(settings["api_base_url"]))
        return SecureOpsSettings(
            enabled=bool(settings["enabled"]),
            api_base_url=str(settings["api_base_url"]),
            allow_http_lab=bool(settings["allow_http_lab"]),
            key_configured=self.credentials.has_key(),
        )

    def update(
        self,
        *,
        enabled: Optional[bool] = None,
        api_base_url: Optional[str] = None,
        ingest_key: Optional[str] = None,
        allow_http_lab: Optional[bool] = None,
    ) -> SecureOpsSettings:
        current = self.load()
        next_settings = {
            "enabled": current.enabled if enabled is None else bool(enabled),
            "api_base_url": current.api_base_url,
            "allow_http_lab": current.allow_http_lab
            if allow_http_lab is None
            else bool(allow_http_lab),
        }

        if api_base_url is not None:
            next_settings["api_base_url"] = normalize_api_base_url(api_base_url)

        validate_secureops_url(
            next_settings["api_base_url"],
            allow_http_lab=next_settings["allow_http_lab"],
        )

        if ingest_key is not None:
            self.credentials.set_key(ingest_key)

        with self._lock:
            self._data_dir.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps(next_settings, indent=2, sort_keys=True),
                encoding="utf-8",
            )

        return self.load()

    def get_key(self) -> Optional[str]:
        return self.credentials.get_key()


class SecureOpsQueue:
    """Durable SQLite outbound queue for SecureOps alerts."""

    def __init__(self, db_path: Path, backoff_seconds: Optional[list[int]] = None) -> None:
        self._db_path = Path(db_path)
        self._backoff_seconds = backoff_seconds or DEFAULT_BACKOFF_SECONDS
        self._connection: Optional[sqlite3.Connection] = None
        self._lock = threading.RLock()
        self._log = logger.bind(component="SecureOpsQueue")

    def initialize(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(
            str(self._db_path),
            check_same_thread=False,
            timeout=10.0,
        )
        self._connection.row_factory = sqlite3.Row
        with self._connection:
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS secureops_alert_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL UNIQUE,
                    severity TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'queued',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at REAL NOT NULL DEFAULT 0,
                    last_attempt_at REAL,
                    last_status_code INTEGER,
                    last_error TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_secureops_due "
                "ON secureops_alert_queue(status, next_attempt_at)"
            )
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS secureops_queue_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None

    def enqueue(self, payload: dict[str, Any]) -> None:
        alert_id = str(payload.get("alert_id", "")).strip()
        if not alert_id:
            raise ValueError("SecureOps alert payload missing stable alert_id.")

        severity = str(payload.get("severity", "medium")).lower()
        now = time.time()
        payload_json = json.dumps(payload, default=str, sort_keys=True)

        with self._lock:
            conn = self._require_connection()
            with conn:
                conn.execute(
                    """
                    INSERT INTO secureops_alert_queue
                        (alert_id, severity, payload, status, attempts,
                         next_attempt_at, created_at, updated_at)
                    VALUES (?, ?, ?, 'queued', 0, ?, ?, ?)
                    ON CONFLICT(alert_id) DO UPDATE SET
                        severity = excluded.severity,
                        payload = excluded.payload,
                        status = 'queued',
                        next_attempt_at = excluded.next_attempt_at,
                        updated_at = excluded.updated_at
                    """,
                    (alert_id, severity, payload_json, now, now, now),
                )

    def get_due(self, limit: int) -> list[dict[str, Any]]:
        now = time.time()
        with self._lock:
            conn = self._require_connection()
            rows = conn.execute(
                """
                SELECT alert_id, payload, attempts
                FROM secureops_alert_queue
                WHERE status = 'queued' AND next_attempt_at <= ?
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 0
                        WHEN 'high' THEN 1
                        WHEN 'medium' THEN 2
                        WHEN 'low' THEN 3
                        ELSE 4
                    END,
                    created_at ASC
                LIMIT ?
                """,
                (now, limit),
            ).fetchall()

        return [
            {
                "alert_id": row["alert_id"],
                "payload": json.loads(row["payload"]),
                "attempts": int(row["attempts"]),
            }
            for row in rows
        ]

    def mark_success(self, alert_ids: list[str]) -> None:
        if not alert_ids:
            return
        now = time.time()
        placeholders = ",".join("?" for _ in alert_ids)
        with self._lock:
            conn = self._require_connection()
            with conn:
                conn.execute(
                    f"DELETE FROM secureops_alert_queue WHERE alert_id IN ({placeholders})",
                    alert_ids,
                )
                self._set_meta_locked(conn, "last_successful_upload", str(now))
                self._set_meta_locked(conn, "last_error", "")
                self._set_meta_locked(conn, "bad_ingest_key", "false")

    def mark_retry(self, alert_ids: list[str], status_code: Optional[int], error: str) -> None:
        if not alert_ids:
            return
        now = time.time()
        clean_error = error[:500]
        with self._lock:
            conn = self._require_connection()
            with conn:
                for alert_id in alert_ids:
                    row = conn.execute(
                        "SELECT attempts FROM secureops_alert_queue WHERE alert_id = ?",
                        (alert_id,),
                    ).fetchone()
                    attempts = int(row["attempts"]) + 1 if row else 1
                    delay = self._backoff_seconds[min(attempts - 1, len(self._backoff_seconds) - 1)]
                    conn.execute(
                        """
                        UPDATE secureops_alert_queue
                        SET attempts = ?, next_attempt_at = ?, last_attempt_at = ?,
                            last_status_code = ?, last_error = ?, updated_at = ?
                        WHERE alert_id = ?
                        """,
                        (attempts, now + delay, now, status_code, clean_error, now, alert_id),
                    )
                self._set_meta_locked(conn, "last_error", clean_error)

    def mark_permanent(
        self,
        alert_ids: list[str],
        status_code: Optional[int],
        error: str,
    ) -> None:
        if not alert_ids:
            return
        now = time.time()
        clean_error = error[:500]
        placeholders = ",".join("?" for _ in alert_ids)
        params: list[Any] = [status_code, clean_error, now, *alert_ids]
        with self._lock:
            conn = self._require_connection()
            with conn:
                conn.execute(
                    f"""
                    UPDATE secureops_alert_queue
                    SET status = 'permanent_error', last_status_code = ?,
                        last_error = ?, updated_at = ?
                    WHERE alert_id IN ({placeholders})
                    """,
                    params,
                )
                self._set_meta_locked(conn, "last_error", clean_error)

    def mark_bad_key(self, error: str) -> None:
        with self._lock:
            conn = self._require_connection()
            with conn:
                self._set_meta_locked(conn, "bad_ingest_key", "true")
                self._set_meta_locked(conn, "last_error", error[:500])

    def clear_bad_key(self) -> None:
        with self._lock:
            conn = self._require_connection()
            with conn:
                self._set_meta_locked(conn, "bad_ingest_key", "false")

    def get_status(self) -> dict[str, Any]:
        with self._lock:
            conn = self._require_connection()
            counts = conn.execute(
                """
                SELECT
                    SUM(CASE WHEN status = 'queued' THEN 1 ELSE 0 END) AS queued,
                    SUM(CASE WHEN status = 'permanent_error' THEN 1 ELSE 0 END) AS permanent,
                    SUM(CASE WHEN status = 'queued'
                              AND severity IN ('critical', 'high')
                             THEN 1 ELSE 0 END) AS critical_high,
                    MIN(CASE WHEN status = 'queued' THEN created_at ELSE NULL END) AS oldest
                FROM secureops_alert_queue
                """
            ).fetchone()
            meta = {
                row["key"]: row["value"]
                for row in conn.execute("SELECT key, value FROM secureops_queue_meta").fetchall()
            }

        return {
            "queue_depth": int(counts["queued"] or 0),
            "critical_high_queued": int(counts["critical_high"] or 0),
            "permanent_errors": int(counts["permanent"] or 0),
            "oldest_queued_at": _format_ts(counts["oldest"]),
            "last_successful_upload": _format_ts(meta.get("last_successful_upload")),
            "last_error": meta.get("last_error") or "",
            "bad_ingest_key": meta.get("bad_ingest_key") == "true",
        }

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise RuntimeError("SecureOps queue has not been initialized.")
        return self._connection

    @staticmethod
    def _set_meta_locked(conn: sqlite3.Connection, key: str, value: str) -> None:
        conn.execute(
            """
            INSERT INTO secureops_queue_meta (key, value)
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )


class SecureOpsClient:
    """Thin HTTP client for the SecureOps EDR ingest API."""

    def __init__(self, timeout_seconds: int) -> None:
        self._timeout = timeout_seconds

    def test_connection(self, api_base_url: str, ingest_key: str) -> SecureOpsResponse:
        return self._request("GET", f"{api_base_url}/ingest/edr/config", ingest_key)

    def send_single(
        self,
        api_base_url: str,
        ingest_key: str,
        alert: dict[str, Any],
    ) -> SecureOpsResponse:
        return self._request("POST", f"{api_base_url}/ingest/edr/alerts", ingest_key, alert)

    def send_batch(
        self,
        api_base_url: str,
        ingest_key: str,
        alerts: list[dict[str, Any]],
    ) -> SecureOpsResponse:
        return self._request(
            "POST",
            f"{api_base_url}/ingest/edr/alerts/batch",
            ingest_key,
            {"alerts": alerts},
        )

    @staticmethod
    def _headers(ingest_key: str) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            SECUREOPS_HEADER: ingest_key,
        }

    def _request(
        self,
        method: str,
        url: str,
        ingest_key: str,
        payload: Optional[dict[str, Any]] = None,
    ) -> SecureOpsResponse:
        data = None if payload is None else json.dumps(payload, default=str).encode("utf-8")
        req = urllib_request.Request(
            url=url,
            data=data,
            headers=self._headers(ingest_key),
            method=method,
        )

        try:
            with urllib_request.urlopen(req, timeout=self._timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
                return SecureOpsResponse(status_code=response.status, text=body)
        except urllib_error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            return SecureOpsResponse(status_code=exc.code, text=body)
        except (TimeoutError, OSError, urllib_error.URLError) as exc:
            raise SecureOpsRequestError(str(exc)) from exc


class SecureOpsExporter:
    """Event-bus subscriber and background queue uploader."""

    def __init__(self, config: IHADRSConfig) -> None:
        self._config = config
        self._settings = SecureOpsSettingsStore(config)
        self._queue = SecureOpsQueue(
            Path(config.secureops.queue_db_path),
            backoff_seconds=list(config.secureops.retry_backoff_seconds),
        )
        self._client = SecureOpsClient(timeout_seconds=config.secureops.timeout_seconds)
        self._max_batch_size = config.secureops.max_batch_size
        self._device_id = config.app.instance_id or f"win-edr-{socket.gethostname()}"
        self._endpoint_id = self._device_id
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._log = logger.bind(component="SecureOpsExporter")

    async def start(self) -> None:
        self._queue.initialize()
        self._thread = threading.Thread(
            target=self._run,
            name="secureops-exporter",
            daemon=True,
        )
        self._thread.start()

    async def stop(self) -> None:
        self._stop_event.set()
        self._wake_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)
        self._queue.close()

    def handle_event(self, bus_event: BusEvent) -> None:
        payload = bus_event.payload
        if not isinstance(payload, ThreatEvent):
            return

        settings = self._settings.load()
        if not settings.enabled:
            return

        try:
            alert = build_secureops_payload(
                payload,
                device_id=self._device_id,
                endpoint_id=self._endpoint_id,
            )
            self._queue.enqueue(alert)
            self._wake_event.set()
        except Exception as exc:
            self._log.warning(
                "Could not enqueue SecureOps alert for threat {id}: {exc}",
                id=getattr(payload, "threat_id", "unknown"),
                exc=exc,
            )

    def get_settings(self) -> dict[str, Any]:
        settings = self._settings.load().to_dict()
        settings.update(self._queue.get_status())
        settings["configured"] = bool(settings["api_base_url"] and settings["key_configured"])
        return settings

    def update_settings(
        self,
        *,
        enabled: Optional[bool] = None,
        api_base_url: Optional[str] = None,
        ingest_key: Optional[str] = None,
        allow_http_lab: Optional[bool] = None,
    ) -> dict[str, Any]:
        settings = self._settings.update(
            enabled=enabled,
            api_base_url=api_base_url,
            ingest_key=ingest_key,
            allow_http_lab=allow_http_lab,
        )
        if ingest_key:
            self._queue.clear_bad_key()
        self._wake_event.set()
        result = settings.to_dict()
        result.update(self._queue.get_status())
        result["configured"] = bool(result["api_base_url"] and result["key_configured"])
        return result

    def get_status(self) -> dict[str, Any]:
        settings = self._settings.load()
        status = settings.to_dict()
        status.update(self._queue.get_status())
        status["configured"] = bool(settings.api_base_url and settings.key_configured)
        return status

    def test_connection(
        self,
        *,
        api_base_url: Optional[str] = None,
        ingest_key: Optional[str] = None,
        allow_http_lab: Optional[bool] = None,
    ) -> dict[str, Any]:
        settings = self._settings.load()
        base_url = normalize_api_base_url(api_base_url or settings.api_base_url)
        allow_http = settings.allow_http_lab if allow_http_lab is None else allow_http_lab
        validate_secureops_url(base_url, allow_http_lab=allow_http)

        key = ingest_key or self._settings.get_key()
        if not key:
            return {
                "success": False,
                "status_code": 400,
                "error": "SecureOps ingest key is not configured.",
            }

        try:
            response = self._client.test_connection(base_url, key)
        except SecureOpsRequestError as exc:
            self._queue.mark_retry([], None, str(exc))
            return {"success": False, "status_code": 0, "error": str(exc)}

        try:
            data = response.json()
        except ValueError:
            data = {"raw": response.text[:500]}

        if response.status_code == 401:
            self._queue.mark_bad_key("SecureOps rejected the ingest key.")
        elif response.ok:
            self._queue.clear_bad_key()

        return {
            "success": response.ok,
            "status_code": response.status_code,
            "response": data,
            "expected_endpoint": f"{base_url}/ingest/edr/alerts",
            "expected_batch_endpoint": f"{base_url}/ingest/edr/alerts/batch",
        }

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._upload_due_alerts()
            except Exception as exc:
                self._log.debug("SecureOps upload loop error: {exc}", exc=exc)
            self._wake_event.wait(timeout=1.0)
            self._wake_event.clear()

    def _upload_due_alerts(self) -> None:
        settings = self._settings.load()
        if not settings.enabled:
            return

        status = self._queue.get_status()
        if status["bad_ingest_key"]:
            return

        key = self._settings.get_key()
        if not key:
            return

        validate_secureops_url(settings.api_base_url, allow_http_lab=settings.allow_http_lab)
        due = self._queue.get_due(limit=self._max_batch_size)
        if not due:
            return

        alert_ids = [item["alert_id"] for item in due]
        alerts = [item["payload"] for item in due]

        try:
            if len(alerts) == 1:
                response = self._client.send_single(settings.api_base_url, key, alerts[0])
            else:
                response = self._client.send_batch(settings.api_base_url, key, alerts)
        except SecureOpsRequestError as exc:
            self._queue.mark_retry(alert_ids, None, f"Network failure: {exc}")
            return

        self._handle_upload_response(response, alert_ids)

    def _handle_upload_response(self, response: SecureOpsResponse, alert_ids: list[str]) -> None:
        status_code = response.status_code
        message = _response_message(response)

        if 200 <= status_code < 300:
            self._queue.mark_success(alert_ids)
            self._log.info("Uploaded {n} alert(s) to SecureOps.", n=len(alert_ids))
            return

        if status_code == 401:
            self._queue.mark_bad_key("SecureOps rejected the ingest key.")
            self._log.warning("SecureOps upload halted because the ingest key was rejected.")
            return

        if status_code in (400, 422):
            self._queue.mark_permanent(alert_ids, status_code, message)
            self._log.warning(
                "SecureOps rejected {n} alert(s) as permanent payload errors: {msg}",
                n=len(alert_ids),
                msg=message[:120],
            )
            return

        if status_code in (429, 500, 502, 503, 504) or status_code >= 500:
            self._queue.mark_retry(alert_ids, status_code, message)
            return

        self._queue.mark_permanent(alert_ids, status_code, message)


def build_secureops_payload(
    threat: ThreatEvent,
    *,
    device_id: str,
    endpoint_id: str,
) -> dict[str, Any]:
    """Convert an IHADRS ThreatEvent into the SecureOps EDR payload schema."""
    hostname = threat.hostname or socket.gethostname()
    raw_event = _first_raw_event(threat)
    process_context = threat.process_context

    process_name = (
        process_context.name
        if process_context
        else raw_event.get("process_name", "")
    )
    command_line = (
        process_context.command_line
        if process_context
        else raw_event.get("command_line", "")
    )
    file_hash = (
        process_context.sha256
        if process_context and process_context.sha256
        else raw_event.get("sha256", "")
    )

    src_ip = raw_event.get("source_ip") or raw_event.get("src_ip") or raw_event.get("local_ip") or ""
    dst_ip = raw_event.get("remote_ip") or raw_event.get("dst_ip") or ""
    network_protocol = raw_event.get("protocol") or ("tcp" if dst_ip else "")
    event_type = _event_type_for_threat(threat, raw_event)
    remediation = [step.description for step in threat.remediation_steps]

    enriched_raw = dict(raw_event)
    enriched_raw.update({
        "event_type": event_type,
        "rule_id": _first(threat.evidence.triggered_rule_ids),
        "rule_name": _first(threat.evidence.triggered_rule_names),
        "risk_score": int(round(threat.confidence * 100)),
        "process_id": raw_event.get("pid") or (process_context.pid if process_context else 0),
        "parent_process_id": raw_event.get("parent_pid")
        or (process_context.parent_pid if process_context else 0),
        "parent_process_name": raw_event.get("parent_name")
        or (process_context.parent_name if process_context else ""),
        "file_path": raw_event.get("image_path")
        or (process_context.image_path if process_context else ""),
        "signed": raw_event.get("is_signed")
        if "is_signed" in raw_event
        else (process_context.is_signed if process_context else False),
        "signer": raw_event.get("signer") or (process_context.signer if process_context else ""),
        "integrity_level": raw_event.get("integrity_level")
        or (process_context.integrity_level if process_context else ""),
        "mitre_tactics": threat.mitre_tactic_names or threat.mitre_tactics,
        "mitre_techniques": threat.mitre_techniques,
        "remediation": remediation,
        "timestamp": _iso_z(threat.timestamp),
    })

    return {
        "alert_id": f"win-edr-{_safe_id_part(hostname)}-{threat.threat_id}",
        "title": threat.summary or f"{threat.severity.value.title()} detection",
        "description": threat.technical_details or threat.user_explanation or threat.summary,
        "severity": _severity_to_secureops(threat.severity),
        "category": _category_for_threat(threat),
        "event_type": event_type,
        "device_id": device_id,
        "endpoint_id": endpoint_id,
        "hostname": hostname,
        "platform": "windows",
        "os_version": platform_module.platform(),
        "app_version": APP_VERSION,
        "username": threat.username,
        "process_name": process_name,
        "command_line": command_line,
        "file_hash": file_hash,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "network_protocol": network_protocol,
        "action_taken": "detected",
        "confidence": round(threat.confidence, 3),
        "iocs": _collect_iocs(
            threat=threat,
            raw_event=raw_event,
            hostname=hostname,
            process_name=process_name,
            file_hash=file_hash,
            dst_ip=dst_ip,
        ),
        "raw_event": enriched_raw,
    }


def normalize_api_base_url(value: str) -> str:
    cleaned = value.strip().rstrip("/")
    if not cleaned:
        raise ValueError("SecureOps API base URL is required.")

    parsed = urlparse(cleaned)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("SecureOps API base URL must include http:// or https://.")

    path = parsed.path.rstrip("/")
    if path == "":
        cleaned = f"{cleaned}/api/v1"
    elif path == "/api":
        cleaned = f"{cleaned}/v1"
    elif not path.endswith("/api/v1"):
        raise ValueError("SecureOps API base URL must end with /api/v1.")
    return cleaned


def validate_secureops_url(api_base_url: str, *, allow_http_lab: bool) -> None:
    parsed = urlparse(api_base_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("SecureOps API base URL must use http or https.")
    if parsed.scheme == "http" and not allow_http_lab:
        raise ValueError("HTTP is disabled for SecureOps export. Use HTTPS or enable lab mode.")


def _severity_to_secureops(severity: Severity) -> str:
    mapping = {
        Severity.CRITICAL: "critical",
        Severity.HIGH: "high",
        Severity.MEDIUM: "medium",
        Severity.LOW: "low",
    }
    return mapping.get(severity, "medium")


def _category_for_threat(threat: ThreatEvent) -> str:
    if threat.mitre_tactic_names:
        return threat.mitre_tactic_names[0]
    if threat.attack_category:
        return threat.attack_category.value
    return "Unknown"


def _event_type_for_threat(threat: ThreatEvent, raw_event: dict[str, Any]) -> str:
    haystack = " ".join(
        [
            threat.summary,
            threat.affected_resource,
            threat.attack_category.value,
            " ".join(threat.evidence.triggered_rule_ids),
            " ".join(threat.evidence.triggered_rule_names),
            json.dumps(raw_event, default=str),
        ]
    ).lower()

    checks = [
        ("powershell", "suspicious_powershell"),
        ("credential", "credential_dumping"),
        ("mimikatz", "credential_dumping"),
        ("ransom", "ransomware_behavior"),
        ("registry", "persistence_registry_run_key"),
        ("scheduled task", "scheduled_task_created"),
        ("service", "service_created"),
        ("c2", "c2_beacon"),
        ("beacon", "c2_beacon"),
        ("exfil", "data_exfiltration"),
        ("privilege", "privilege_escalation"),
        ("defense", "defense_evasion"),
        ("lateral", "lateral_movement"),
        ("brute", "brute_force_logon"),
        ("network", "suspicious_network_connection"),
        ("driver", "driver_loaded"),
        ("unsigned", "unsigned_binary_execution"),
        ("injection", "process_injection"),
    ]
    for needle, event_type in checks:
        if needle in haystack:
            return event_type
    return "malware_detected"


def _collect_iocs(
    *,
    threat: ThreatEvent,
    raw_event: dict[str, Any],
    hostname: str,
    process_name: str,
    file_hash: str,
    dst_ip: str,
) -> list[dict[str, str]]:
    values: list[str] = []
    values.extend(str(ioc) for ioc in threat.evidence.iocs)
    values.extend([hostname, process_name, file_hash, dst_ip])
    values.extend(str(v) for v in raw_event.values() if isinstance(v, str))

    seen: set[tuple[str, str]] = set()
    iocs: list[dict[str, str]] = []

    def add(ioc_type: str, value: str) -> None:
        clean = value.strip()
        if not clean:
            return
        key = (ioc_type, clean)
        if key in seen:
            return
        seen.add(key)
        iocs.append({"type": ioc_type, "value": clean})

    for value in values:
        for match in _SHA256_RE.findall(value):
            add("hash_sha256", match.lower())
        for match in _SHA1_RE.findall(value):
            add("hash_sha1", match.lower())
        for match in _MD5_RE.findall(value):
            add("hash_md5", match.lower())
        for match in _IP_RE.findall(value):
            add("ip", match)

    if process_name:
        add("process", process_name)
    if hostname:
        add("hostname", hostname)
    return iocs[:50]


def _first_raw_event(threat: ThreatEvent) -> dict[str, Any]:
    if threat.evidence.raw_events:
        raw = threat.evidence.raw_events[0]
        if isinstance(raw, dict):
            return raw
    return {}


def _safe_id_part(value: str) -> str:
    cleaned = _HOST_ID_RE.sub("-", value.strip()).strip("-")
    return cleaned or "unknown-host"


def _first(values: list[str]) -> str:
    return values[0] if values else ""


def _iso_z(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _format_ts(value: Any) -> Optional[str]:
    if value in (None, ""):
        return None
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (TypeError, ValueError):
        return None


def _response_message(response: SecureOpsResponse) -> str:
    try:
        data = response.json()
        return json.dumps(data, default=str)[:500]
    except ValueError:
        return response.text[:500] or f"HTTP {response.status_code}"
