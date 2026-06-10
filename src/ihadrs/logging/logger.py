"""
Module: logging.logger
Purpose: Centralized logging configuration for IHADRS.
         Sets up loguru with structured JSON output to files,
         rich-formatted output to console, and separate JSONL
         streams for security events and audit records.
Owner: logging
Dependencies: loguru, rich, pathlib
Performance: Async-capable loguru sinks. File I/O is the only overhead.
             JSONL format for machine-parseable logs (SIEM integration).

Log Streams:
    1. ihadrs_debug.log    — All log levels, rotating, for debugging
    2. ihadrs_events.jsonl — Security events only (JSONL, SIEM-ready)
    3. ihadrs_audit.jsonl  — All IHADRS actions (JSONL, non-repudiation)
    4. Console (stdout)    — Rich-formatted, filtered by configured level
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Optional

from loguru import logger

from ihadrs.constants import (
    AUDIT_LOG_RETENTION_DAYS,
    LOG_COMPRESSION,
    LOG_FILE_AUDIT,
    LOG_FILE_DEBUG,
    LOG_FILE_EVENTS,
    LOG_RETENTION_DAYS,
    LOG_ROTATION_SIZE,
    APP_NAME,
    APP_VERSION,
)


# =============================================================================
# CUSTOM LOG RECORD EXTRAS
# =============================================================================

# Fields automatically added to every log record
_LOG_EXTRAS: dict[str, Any] = {
    "app": APP_NAME,
    "version": APP_VERSION,
    "component": "ihadrs",
}


# =============================================================================
# FORMATTERS
# =============================================================================

def _json_formatter(record: dict[str, Any]) -> str:
    """
    Produce a structured JSON log line from a loguru record.

    Output is a single JSON object per line (JSONL format), suitable
    for ingestion by Splunk, ELK, Graylog, or any SIEM platform.

    Fields:
        timestamp, level, component, message, file, line, exception
        + any extra fields added via logger.bind()
    """
    extra = record.get("extra", {})

    log_entry: dict[str, Any] = {
        "timestamp": record["time"].isoformat(),
        "level": record["level"].name,
        "component": extra.get("component", "ihadrs"),
        "message": record["message"],
        "file": f"{record['file'].name}:{record['line']}",
        "function": record["function"],
    }

    # Merge extra fields (from logger.bind() calls)
    for key, value in extra.items():
        if key not in ("component",):
            log_entry[key] = value

    # Include exception info if present
    if record.get("exception"):
        exc_info = record["exception"]
        log_entry["exception"] = {
            "type": exc_info.type.__name__ if exc_info.type else None,
            "value": str(exc_info.value) if exc_info.value else None,
        }

    return json.dumps(log_entry, default=str, ensure_ascii=False) + "\n"


def _console_formatter(record: dict[str, Any]) -> str:
    """
    Rich-compatible console log formatter.

    Uses loguru's colorize=True for level-based coloring.
    Format: <time> | <level> | <component> | <message>
    """
    component = record["extra"].get("component", "ihadrs")
    return (
        "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
        "<level>{level: <8}</level> | "
        f"<cyan>{component: <20}</cyan> | "
        "<level>{message}</level>\n"
        "{exception}"
    )


# =============================================================================
# LOGGER SETUP
# =============================================================================

def setup_logging(
    log_dir: Path,
    level: str = "INFO",
    json_format: bool = True,
    console_output: bool = True,
    rotation_size: str = LOG_ROTATION_SIZE,
    retention_days: int = LOG_RETENTION_DAYS,
    compression: str = LOG_COMPRESSION,
) -> None:
    """
    Initialize and configure the IHADRS logging system.

    Must be called once during application startup before any other
    component uses the logger. Subsequent calls reconfigure logging.

    Args:
        log_dir: Directory for log files (created if it doesn't exist).
        level: Minimum log level for file output.
        json_format: If True, emit JSONL to files; else emit plain text.
        console_output: If True, also log to stdout.
        rotation_size: Rotate log files at this size (e.g., "50 MB").
        retention_days: Delete rotated files older than this many days.
        compression: Compression format for rotated files ("gz", "zip", "bz2").

    Raises:
        OSError: If log_dir cannot be created or is not writable.
    """
    # Create log directory
    log_dir.mkdir(parents=True, exist_ok=True)

    # Remove default loguru handler
    logger.remove()

    # Bind global extras to every record
    logger.configure(extra=_LOG_EXTRAS)

    # -------------------------------------------------------------------------
    # Sink 1: Debug log (all levels, rotating, plain text for human reading)
    # -------------------------------------------------------------------------
    debug_log_path = log_dir / LOG_FILE_DEBUG
    logger.add(
        str(debug_log_path),
        level="DEBUG",
        format=(
            _console_formatter  # Use function formatter to avoid KeyError
        ),
        rotation=rotation_size,
        retention=f"{retention_days} days",
        compression=compression,
        enqueue=True,           # Async I/O — never blocks calling thread
        backtrace=True,
        diagnose=True,          # Show variable values in tracebacks
        catch=True,             # Catch exceptions in this sink
        encoding="utf-8",
    )

    # -------------------------------------------------------------------------
    # Sink 2: Security events JSONL (INFO+, for SIEM/analysis)
    # -------------------------------------------------------------------------
    events_log_path = log_dir / LOG_FILE_EVENTS
    logger.add(
        str(events_log_path),
        level=level,
        format=_json_formatter if json_format else (
            "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level} | {message}\n"
        ),
        rotation=rotation_size,
        retention=f"{retention_days} days",
        compression=compression,
        enqueue=True,
        catch=True,
        encoding="utf-8",
        serialize=False,        # We handle serialization ourselves
    )

    # -------------------------------------------------------------------------
    # Sink 3: Console (filtered by configured level)
    # -------------------------------------------------------------------------
    if console_output:
        logger.add(
            sys.stdout,
            level=level,
            format=_console_formatter,
            colorize=True,
            enqueue=False,      # Console is synchronous for immediate feedback
            catch=True,
            backtrace=False,    # Don't expose internals in console
            diagnose=False,
        )

    logger.info(
        "Logging initialized. dir={dir} level={level} json={json}",
        dir=log_dir,
        level=level,
        json=json_format,
    )


def get_component_logger(component_name: str) -> "logger":  # type: ignore[name-defined]
    """
    Return a logger instance bound to a specific component name.

    All log records from this logger will include {"component": component_name}
    in their extra fields, making it easy to filter logs by component.

    Usage:
        logger = get_component_logger("process_monitor")
        logger.info("Monitor started")
        # → {"component": "process_monitor", "message": "Monitor started", ...}

    Args:
        component_name: Name to tag log records with (e.g., "process_monitor").
    """
    return logger.bind(component=component_name)


# =============================================================================
# AUDIT LOG SETUP
# =============================================================================

def setup_audit_log(log_dir: Path) -> None:
    """
    Set up the audit log sink — separate from regular logging.

    The audit log records every action IHADRS takes (responses, config
    changes, user interactions). Retained for AUDIT_LOG_RETENTION_DAYS
    (1 year by default) for forensic purposes.

    Audit log entries are tagged with {"audit": true} in their extra fields.
    This sink only captures records with that tag.

    Args:
        log_dir: Directory where the audit log will be written.
    """
    audit_log_path = log_dir / LOG_FILE_AUDIT

    def _audit_filter(record: dict[str, Any]) -> bool:
        """Only capture records explicitly marked for audit logging."""
        return record["extra"].get("audit", False) is True

    logger.add(
        str(audit_log_path),
        level="DEBUG",
        format=_json_formatter,
        filter=_audit_filter,
        rotation=LOG_ROTATION_SIZE,
        retention=f"{AUDIT_LOG_RETENTION_DAYS} days",
        compression=LOG_COMPRESSION,
        enqueue=True,
        catch=True,
        encoding="utf-8",
    )

    logger.bind(component="audit", audit=True).info(
        "Audit log initialized at {path}", path=audit_log_path
    )


def get_audit_logger() -> "logger":  # type: ignore[name-defined]
    """
    Return an audit-tagged logger instance.

    All records from this logger are written to the audit log in addition
    to the regular log files. Use for: response actions, config changes,
    false-positive markings, user interactions.

    Usage:
        audit = get_audit_logger()
        audit.info(
            "Response action executed",
            action_type="kill_process",
            target="malware.exe:4821",
            approved_by="auto",
        )
    """
    return logger.bind(component="audit", audit=True)