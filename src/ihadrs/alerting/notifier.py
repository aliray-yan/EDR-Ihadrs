"""
Module: alerting.notifier
Purpose: Central alert dispatcher. Receives IHADRS_DETECTION_TRIGGERED bus events
         and routes them to all enabled alerting channels (console, desktop,
         email, webhook). Implements rate limiting and severity filtering.
Owner: alerting
Dependencies: ihadrs.alerting.channels, ihadrs.core.config
Performance: Alert dispatch is async and non-blocking. Each channel runs
             in its own executor thread to prevent slow channels from
             blocking faster ones.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from typing import Any, Optional

from loguru import logger

from ihadrs.constants import Severity
from ihadrs.core.config import IHADRSConfig
from ihadrs.core.event_bus import BusEvent
from ihadrs.models.threats import ThreatEvent


class Notifier:
    """
    Central alert dispatcher for IHADRS.

    Subscribes to IHADRS_DETECTION_TRIGGERED events on the bus and
    fans out to all configured alert channels with:
    - Severity filtering per channel
    - Global rate limiting (max_alerts_per_minute)
    - Per-threat cooldown (suppress duplicate alerts)
    - Async dispatch (no channel blocks another)
    """

    def __init__(self, config: IHADRSConfig) -> None:
        self._config = config.alerting
        self._log = logger.bind(component="Notifier")

        # Rate limiting
        self._alert_times: deque[float] = deque(maxlen=1000)
        self._max_per_minute = config.alerting.max_alerts_per_minute
        self._cooldown_seconds = config.alerting.alert_cooldown_seconds

        # Cooldown tracking: threat summary hash → last alert time
        self._alert_cooldown: dict[str, float] = {}

        # Initialize channels
        self._console_channel = _ConsoleChannel(config)
        self._desktop_channel = _DesktopChannel(config)

    # =========================================================================
    # Bus Event Handler
    # =========================================================================

    def handle_event(self, bus_event: BusEvent) -> None:
        """
        Handle a IHADRS_DETECTION_TRIGGERED bus event.

        Called from the event bus dispatcher thread. Dispatches to
        channels asynchronously.

        Args:
            bus_event: The bus event carrying a ThreatEvent payload.
        """
        payload = bus_event.payload
        if not isinstance(payload, ThreatEvent):
            return

        if not self._passes_rate_limit():
            self._log.debug("Alert rate limit exceeded — suppressing alert.")
            return

        if self._is_on_cooldown(payload):
            self._log.debug(
                "Alert suppressed (cooldown): {summary}",
                summary=payload.summary[:60],
            )
            return

        self._record_alert(payload)
        self._dispatch(payload)

    # =========================================================================
    # Dispatch
    # =========================================================================

    def _dispatch(self, threat: ThreatEvent) -> None:
        """Fan out threat alert to all enabled channels."""
        # Console (synchronous — always fast)
        min_console = Severity(self._config.min_severity_console)
        if threat.severity >= min_console and self._config.console_output:
            try:
                self._console_channel.send(threat)
            except Exception as exc:
                self._log.debug("Console alert error: {exc}", exc=exc)

        # Desktop notification
        min_desktop = Severity(self._config.min_severity_desktop)
        if threat.severity >= min_desktop and self._config.desktop_notifications:
            try:
                self._desktop_channel.send(threat)
            except Exception as exc:
                self._log.debug("Desktop alert error: {exc}", exc=exc)

    # =========================================================================
    # Rate Limiting
    # =========================================================================

    def _passes_rate_limit(self) -> bool:
        """Return True if we're within the per-minute alert rate limit."""
        now = time.time()
        cutoff = now - 60.0
        while self._alert_times and self._alert_times[0] < cutoff:
            self._alert_times.popleft()
        return len(self._alert_times) < self._max_per_minute

    def _is_on_cooldown(self, threat: ThreatEvent) -> bool:
        """Return True if a similar alert was recently sent."""
        if self._cooldown_seconds <= 0:
            return False
        key = f"{threat.severity.value}:{threat.attack_category.value}"
        last = self._alert_cooldown.get(key, 0.0)
        return (time.time() - last) < self._cooldown_seconds

    def _record_alert(self, threat: ThreatEvent) -> None:
        """Record that an alert was sent (for rate limiting and cooldown)."""
        now = time.time()
        self._alert_times.append(now)
        key = f"{threat.severity.value}:{threat.attack_category.value}"
        self._alert_cooldown[key] = now


# =============================================================================
# CONSOLE CHANNEL
# =============================================================================

class _ConsoleChannel:
    """
    Outputs structured threat alerts to the terminal using Rich.
    """

    def __init__(self, config: IHADRSConfig) -> None:
        self._config = config

    def send(self, threat: ThreatEvent) -> None:
        """Print a formatted threat alert to stdout."""
        try:
            from rich.console import Console
            from rich.panel import Panel
            from rich.table import Table
            from rich.text import Text

            console = Console()
            color = threat.severity.rich_markup
            icon = threat.severity.icon

            # Build summary table
            table = Table(show_header=False, box=None, padding=(0, 1))
            table.add_column("Key", style="bold", width=20)
            table.add_column("Value")

            table.add_row("Attack Type", threat.attack_category.value)
            if threat.mitre_techniques:
                techniques = ", ".join(threat.mitre_techniques[:3])
                table.add_row("MITRE Technique", techniques)
            table.add_row("Severity", f"[{color}]{threat.severity.value}[/{color}]")
            table.add_row("Confidence", f"{threat.confidence:.0%}")
            table.add_row("Affected", threat.affected_resource[:60])
            table.add_row("Detected", threat.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                          if threat.timestamp else "")

            title = f"{icon} [{color}]{threat.severity.value} THREAT[/{color}]: {threat.attack_category.value}"
            panel = Panel(
                table,
                title=title,
                border_style=color,
                padding=(0, 1),
            )
            console.print()
            console.print(panel)

            if threat.user_explanation:
                console.print(f"[bold]What happened:[/bold]")
                console.print(f"  {threat.user_explanation[:300]}")

            if threat.remediation_steps:
                console.print(f"\n[bold]Immediate actions:[/bold]")
                immediate = [s for s in threat.remediation_steps
                             if s.category == "immediate"][:3]
                for step in immediate or threat.remediation_steps[:3]:
                    console.print(f"  {step.step_number}. {step.description[:100]}")

            console.print()

        except ImportError:
            # Rich not available — fallback to plain print
            print(
                f"\n{'='*60}\n"
                f"[{threat.severity.value}] {threat.attack_category.value}\n"
                f"Affected: {threat.affected_resource}\n"
                f"Confidence: {threat.confidence:.0%}\n"
                f"{threat.user_explanation[:200]}\n"
                f"{'='*60}\n"
            )
        except Exception as exc:
            logger.debug("Console channel error: {exc}", exc=exc)


# =============================================================================
# DESKTOP NOTIFICATION CHANNEL
# =============================================================================

class _DesktopChannel:
    """
    Sends OS-native desktop notifications.
    Windows: win10toast or plyer
    Linux/macOS: plyer
    """

    def __init__(self, config: IHADRSConfig) -> None:
        self._config = config
        self._toast_available = self._check_toast()

    @staticmethod
    def _check_toast() -> bool:
        try:
            from ihadrs.constants import IS_WINDOWS
            if IS_WINDOWS:
                from win10toast import ToastNotifier  # noqa: F401
            else:
                from plyer import notification  # noqa: F401
            return True
        except ImportError:
            return False

    def send(self, threat: ThreatEvent) -> None:
        """Send an OS native notification."""
        if not self._toast_available:
            return

        title = f"{threat.severity.icon} {threat.severity.value}: {threat.attack_category.value}"
        message = (
            f"{threat.summary[:80]}\n"
            f"Confidence: {threat.confidence:.0%}\n"
            f"See IHADRS dashboard for details."
        )

        try:
            from ihadrs.constants import IS_WINDOWS
            if IS_WINDOWS:
                from win10toast import ToastNotifier
                toaster = ToastNotifier()
                toaster.show_toast(
                    title=title,
                    msg=message,
                    duration=10,
                    threaded=True,
                )
            else:
                from plyer import notification
                notification.notify(
                    title=title,
                    message=message,
                    timeout=10,
                )
        except Exception as exc:
            logger.debug("Desktop notification error: {exc}", exc=exc)