"""
Module: detection.behavioral
Purpose: Stateful behavioral pattern detection using sliding time windows.
         Detects attacks that unfold across multiple events over time —
         things a simple per-event rule engine cannot catch.
Owner: detection
Dependencies: collections, threading, time
Performance: O(1) amortized per event update. Window pruning runs inline.
             Memory: ~100 bytes per tracked event × window depth.
             Thread-safe via per-tracker RLock.

Behavioral Patterns Detected:
    - Ransomware: Mass file renames with crypto extensions in time window
    - Brute Force: Authentication failure spike from single source
    - Rapid Process Spawning: >N shells in M seconds
    - C2 Beaconing: Handled in network_monitor.py (statistical)
    - Bulk File Read: Data staging before exfiltration
    - Process Parent Anomalies: Office app spawning shell

Each pattern produces a BehavioralMatch that the detection engine
converts into a ThreatEvent via the classifier.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Optional

from loguru import logger

from ihadrs.constants import (
    BRUTE_FORCE_FAILURE_THRESHOLD,
    BRUTE_FORCE_TIME_WINDOW_SECONDS,
    BULK_FILE_READ_THRESHOLD,
    BULK_FILE_READ_WINDOW_SECONDS,
    PROCESS_SPAWN_THRESHOLD,
    PROCESS_SPAWN_WINDOW_SECONDS,
    RANSOMWARE_FILE_RENAME_THRESHOLD,
    RANSOMWARE_TIME_WINDOW_SECONDS,
    AttackCategory,
    EventType,
    Severity,
)
from ihadrs.models.events import (
    AuthenticationEvent,
    BaseEvent,
    FileEvent,
    ProcessEvent,
)


# =============================================================================
# BEHAVIORAL MATCH
# =============================================================================

@dataclass
class BehavioralMatch:
    """
    Result of a behavioral pattern detection.

    Produced when a sliding-window threshold is exceeded or a
    stateful pattern is confirmed. The detection engine converts
    these into ThreatEvents.
    """

    pattern_id: str             # e.g., "RANSOMWARE_BULK_ENCRYPT"
    pattern_name: str           # Human-readable pattern name
    attack_category: AttackCategory
    severity: Severity
    confidence: float
    triggered_at: float = field(default_factory=time.time)

    # Evidence
    event_count: int = 0        # Number of events in the window
    window_seconds: float = 0.0
    sample_events: list[dict[str, Any]] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)

    # MITRE
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)

    # Explanation
    summary: str = ""
    user_explanation: str = ""
    technical_details: str = ""
    affected_resource: str = ""


# =============================================================================
# SLIDING WINDOW TRACKER
# =============================================================================

class SlidingWindowTracker:
    """
    Thread-safe sliding time window event counter.

    Tracks events within a rolling time window and detects when
    the count exceeds a threshold. Used by all behavioral detectors.
    """

    def __init__(
        self,
        window_seconds: float,
        threshold: int,
        max_history: int = 500,
    ) -> None:
        self._window = window_seconds
        self._threshold = threshold
        self._events: deque[tuple[float, dict[str, Any]]] = deque(maxlen=max_history)
        self._lock = threading.RLock()

    def add(self, metadata: dict[str, Any] | None = None) -> bool:
        """
        Add an event to the window.

        Returns:
            True if the threshold was just exceeded (new detection),
            False if threshold was already exceeded or not yet reached.
        """
        now = time.time()
        with self._lock:
            self._events.append((now, metadata or {}))
            self._prune(now)
            count = len(self._events)

        return count == self._threshold  # True only on exact threshold crossing

    def count_in_window(self) -> int:
        """Return the number of events within the current window."""
        with self._lock:
            self._prune(time.time())
            return len(self._events)

    def get_events_in_window(self) -> list[dict[str, Any]]:
        """Return all event metadata records in the current window."""
        now = time.time()
        with self._lock:
            self._prune(now)
            return [meta for _, meta in self._events]

    def _prune(self, now: float) -> None:
        """Remove events older than the window. Must be called under lock."""
        cutoff = now - self._window
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()

    def reset(self) -> None:
        """Clear all tracked events (e.g., after a detection fires)."""
        with self._lock:
            self._events.clear()


# =============================================================================
# BEHAVIORAL DETECTOR
# =============================================================================

class BehavioralDetector:
    """
    Stateful behavioral detection engine.

    Maintains sliding window state for each tracked pattern and entity
    (e.g., per-PID, per-source-IP). Processes events one at a time and
    emits BehavioralMatch objects when thresholds are crossed.

    Thread Safety:
        All public methods are thread-safe. Internal state is protected
        by fine-grained locks per tracker instance.
    """

    def __init__(
        self,
        ransomware_rename_threshold: int = RANSOMWARE_FILE_RENAME_THRESHOLD,
        ransomware_window_seconds: float = RANSOMWARE_TIME_WINDOW_SECONDS,
        brute_force_threshold: int = BRUTE_FORCE_FAILURE_THRESHOLD,
        brute_force_window_seconds: float = BRUTE_FORCE_TIME_WINDOW_SECONDS,
        process_spawn_threshold: int = PROCESS_SPAWN_THRESHOLD,
        process_spawn_window_seconds: float = PROCESS_SPAWN_WINDOW_SECONDS,
        bulk_file_threshold: int = BULK_FILE_READ_THRESHOLD,
        bulk_file_window_seconds: float = BULK_FILE_READ_WINDOW_SECONDS,
    ) -> None:
        # Thresholds
        self._ransomware_threshold = ransomware_rename_threshold
        self._ransomware_window = ransomware_window_seconds
        self._brute_force_threshold = brute_force_threshold
        self._brute_force_window = brute_force_window_seconds
        self._spawn_threshold = process_spawn_threshold
        self._spawn_window = process_spawn_window_seconds
        self._bulk_threshold = bulk_file_threshold
        self._bulk_window = bulk_file_window_seconds

        # Per-entity sliding window trackers
        # Keys: entity identifier (e.g., source_ip, pid, process_name)
        self._ransomware_tracker: SlidingWindowTracker = SlidingWindowTracker(
            ransomware_window_seconds, ransomware_rename_threshold
        )
        self._brute_force_trackers: dict[str, SlidingWindowTracker] = defaultdict(
            lambda: SlidingWindowTracker(brute_force_window_seconds, brute_force_threshold)
        )
        self._spawn_trackers: dict[str, SlidingWindowTracker] = defaultdict(
            lambda: SlidingWindowTracker(process_spawn_window_seconds, process_spawn_threshold)
        )
        self._bulk_file_trackers: dict[str, SlidingWindowTracker] = defaultdict(
            lambda: SlidingWindowTracker(bulk_file_window_seconds, bulk_file_threshold)
        )

        # Track recent detections to avoid duplicate alerts
        # Maps pattern_id → timestamp of last alert
        self._last_detection: dict[str, float] = {}
        self._detection_cooldown: float = 30.0  # Seconds between duplicate alerts

        logger.debug("BehavioralDetector initialized.")

    # =========================================================================
    # Main entry point
    # =========================================================================

    def process_event(self, event: BaseEvent) -> list[BehavioralMatch]:
        """
        Process one event and return any behavioral matches detected.

        Called by the detection engine for every event on the bus.
        Most calls return an empty list (no match).

        Args:
            event: Any domain event (ProcessEvent, FileEvent, etc.)

        Returns:
            List of BehavioralMatch objects (usually empty).
        """
        matches: list[BehavioralMatch] = []

        try:
            if isinstance(event, FileEvent):
                match = self._check_ransomware(event)
                if match:
                    matches.append(match)
                match = self._check_bulk_file_read(event)
                if match:
                    matches.append(match)

            elif isinstance(event, AuthenticationEvent):
                match = self._check_brute_force(event)
                if match:
                    matches.append(match)

            elif isinstance(event, ProcessEvent):
                match = self._check_process_spawn_burst(event)
                if match:
                    matches.append(match)

        except Exception as exc:
            logger.debug(
                "BehavioralDetector non-fatal error: {exc}", exc=exc
            )

        return matches

    # =========================================================================
    # Ransomware detection
    # =========================================================================

    def _check_ransomware(self, event: FileEvent) -> Optional[BehavioralMatch]:
        """
        Detect mass file encryption by counting crypto-extension renames.

        Fires when RANSOMWARE_FILE_RENAME_THRESHOLD renames occur in
        RANSOMWARE_TIME_WINDOW_SECONDS seconds.
        """
        from ihadrs.constants import RANSOMWARE_EXTENSIONS

        if event.event_type not in (EventType.FILE_RENAMED, EventType.FILE_MASS_OPERATION):
            return None

        new_ext = event.new_extension.lower()
        if new_ext not in RANSOMWARE_EXTENSIONS:
            return None

        metadata = {
            "file_path": event.file_path,
            "new_path": event.new_path,
            "new_extension": new_ext,
            "pid": event.pid,
            "process_name": event.process_name,
        }

        threshold_crossed = self._ransomware_tracker.add(metadata)

        # Also check if we're above threshold (for ongoing attacks)
        count = self._ransomware_tracker.count_in_window()

        # Fire on threshold crossing OR every 10 additional events
        should_fire = threshold_crossed or (
            count >= self._ransomware_threshold and
            count % 10 == 0
        )

        if not should_fire:
            return None

        if self._is_on_cooldown("RANSOMWARE_BULK_ENCRYPT"):
            return None

        events_in_window = self._ransomware_tracker.get_events_in_window()
        self._set_cooldown("RANSOMWARE_BULK_ENCRYPT")

        process_name = event.process_name or "unknown process"
        affected_path = event.directory or event.file_path

        return BehavioralMatch(
            pattern_id="RANSOMWARE_BULK_ENCRYPT",
            pattern_name="Mass File Encryption Pattern",
            attack_category=AttackCategory.RANSOMWARE,
            severity=Severity.CRITICAL,
            confidence=0.92,
            event_count=count,
            window_seconds=self._ransomware_window,
            sample_events=events_in_window[:5],
            context={
                "process_name": process_name,
                "pid": event.pid,
                "crypto_extension": new_ext,
                "directory": affected_path,
            },
            mitre_tactics=["TA0040"],
            mitre_techniques=["T1486"],
            summary=f"Ransomware: {count} files encrypted by {process_name}",
            user_explanation=(
                f"A program ({process_name}) is rapidly renaming your files "
                f"and adding the extension '{new_ext}'. This is the signature "
                f"behavior of ransomware — your files are being encrypted."
            ),
            technical_details=(
                f"Process {process_name} (PID {event.pid}) performed {count} "
                f"file renames with ransomware extension '{new_ext}' in "
                f"{self._ransomware_window:.0f}s. Threshold: "
                f"{self._ransomware_threshold}."
            ),
            affected_resource=f"file:{affected_path}",
        )

    # =========================================================================
    # Brute force detection
    # =========================================================================

    def _check_brute_force(
        self, event: AuthenticationEvent
    ) -> Optional[BehavioralMatch]:
        """
        Detect authentication brute force by counting failures per source IP.

        Fires when BRUTE_FORCE_FAILURE_THRESHOLD failures occur from the
        same source IP within BRUTE_FORCE_TIME_WINDOW_SECONDS seconds.
        """
        if event.success:
            return None  # Only track failures

        source_key = event.source_ip or event.workstation_name or "unknown"
        tracker = self._brute_force_trackers[source_key]

        metadata = {
            "source_ip": event.source_ip,
            "target_username": event.target_username,
            "auth_package": event.auth_package,
            "logon_type": event.logon_type,
        }

        threshold_crossed = tracker.add(metadata)
        count = tracker.count_in_window()

        if not threshold_crossed:
            return None

        cooldown_key = f"BRUTE_FORCE:{source_key}"
        if self._is_on_cooldown(cooldown_key):
            return None

        self._set_cooldown(cooldown_key)
        events_in_window = tracker.get_events_in_window()

        # Extract unique target accounts
        targets = list({e.get("target_username", "") for e in events_in_window if e.get("target_username")})

        return BehavioralMatch(
            pattern_id="BRUTE_FORCE_AUTH",
            pattern_name="Authentication Brute Force",
            attack_category=AttackCategory.BRUTE_FORCE,
            severity=Severity.HIGH,
            confidence=0.85,
            event_count=count,
            window_seconds=self._brute_force_window,
            sample_events=events_in_window[:5],
            context={
                "source_ip": event.source_ip,
                "source_key": source_key,
                "target_accounts": targets,
                "failure_count": count,
            },
            mitre_tactics=["TA0006"],
            mitre_techniques=["T1110"],
            summary=f"Brute force: {count} failures from {source_key}",
            user_explanation=(
                f"{count} failed login attempts from {source_key} in "
                f"{self._brute_force_window:.0f}s. This indicates an "
                f"automated password-guessing attack."
            ),
            technical_details=(
                f"Authentication failure burst: {count} failures from "
                f"{source_key} targeting accounts: {', '.join(targets[:3])}. "
                f"Window: {self._brute_force_window:.0f}s, "
                f"threshold: {self._brute_force_threshold}."
            ),
            affected_resource=f"auth:{source_key}",
        )

    # =========================================================================
    # Process spawn burst
    # =========================================================================

    def _check_process_spawn_burst(
        self, event: ProcessEvent
    ) -> Optional[BehavioralMatch]:
        """
        Detect rapid spawning of command shells from the same parent.

        Fires when more than PROCESS_SPAWN_THRESHOLD shell processes are
        created within PROCESS_SPAWN_WINDOW_SECONDS by the same parent.
        """
        if event.event_type != EventType.PROCESS_CREATED:
            return None

        shell_names = frozenset({
            "cmd.exe", "powershell.exe", "wscript.exe",
            "cscript.exe", "bash", "sh", "zsh",
        })

        proc_name_lower = event.process_name.lower()
        if proc_name_lower not in shell_names:
            return None

        # Track per-parent-process-name
        parent_key = event.parent_name.lower() or "unknown"
        tracker = self._spawn_trackers[parent_key]

        metadata = {
            "pid": event.pid,
            "process_name": event.process_name,
            "command_line": event.command_line,
            "parent_name": event.parent_name,
            "parent_pid": event.parent_pid,
        }

        threshold_crossed = tracker.add(metadata)
        count = tracker.count_in_window()

        if not threshold_crossed:
            return None

        cooldown_key = f"SPAWN_BURST:{parent_key}"
        if self._is_on_cooldown(cooldown_key):
            return None

        self._set_cooldown(cooldown_key)

        return BehavioralMatch(
            pattern_id="RAPID_SHELL_SPAWN",
            pattern_name="Rapid Shell Process Spawning",
            attack_category=AttackCategory.MALWARE_EXECUTION,
            severity=Severity.HIGH,
            confidence=0.75,
            event_count=count,
            window_seconds=self._spawn_window,
            sample_events=tracker.get_events_in_window()[:5],
            context={
                "parent_name": event.parent_name,
                "parent_pid": event.parent_pid,
                "shell_name": event.process_name,
                "spawn_count": count,
            },
            mitre_tactics=["TA0002"],
            mitre_techniques=["T1059"],
            summary=(
                f"Rapid spawning: {count} {event.process_name} processes "
                f"from {event.parent_name}"
            ),
            user_explanation=(
                f"{count} command windows were opened in {self._spawn_window:.0f}s "
                f"by {event.parent_name}. This pattern is associated with "
                f"malware scripts running automated commands."
            ),
            technical_details=(
                f"Process spawn burst: {count} instances of "
                f"{event.process_name} spawned by {event.parent_name} "
                f"(PID {event.parent_pid}) in {self._spawn_window:.0f}s."
            ),
            affected_resource=f"process:{event.parent_name}:{event.parent_pid}",
        )

    # =========================================================================
    # Bulk file read
    # =========================================================================

    def _check_bulk_file_read(
        self, event: FileEvent
    ) -> Optional[BehavioralMatch]:
        """
        Detect data staging: bulk file reads before exfiltration.

        Fires when a process reads more than BULK_FILE_READ_THRESHOLD
        files within BULK_FILE_READ_WINDOW_SECONDS.
        """
        if event.event_type != EventType.FILE_MODIFIED:
            return None

        process_key = f"{event.process_name}:{event.pid}" if event.pid else "unknown"
        tracker = self._bulk_file_trackers[process_key]

        metadata = {
            "file_path": event.file_path,
            "pid": event.pid,
            "process_name": event.process_name,
        }

        threshold_crossed = tracker.add(metadata)
        count = tracker.count_in_window()

        if not threshold_crossed:
            return None

        cooldown_key = f"BULK_FILE:{process_key}"
        if self._is_on_cooldown(cooldown_key):
            return None

        self._set_cooldown(cooldown_key)

        return BehavioralMatch(
            pattern_id="BULK_FILE_ACCESS",
            pattern_name="Bulk File Access (Data Staging)",
            attack_category=AttackCategory.COLLECTION,
            severity=Severity.LOW,
            confidence=0.50,
            event_count=count,
            window_seconds=self._bulk_window,
            context={
                "process_name": event.process_name,
                "pid": event.pid,
                "file_count": count,
            },
            mitre_tactics=["TA0009"],
            mitre_techniques=["T1005"],
            summary=f"Bulk file access: {count} files by {event.process_name}",
            user_explanation=(
                f"{event.process_name} accessed {count} files in "
                f"{self._bulk_window:.0f}s — possible data collection "
                f"before exfiltration."
            ),
            technical_details=(
                f"Process {event.process_name} (PID {event.pid}) read "
                f"{count} files in {self._bulk_window:.0f}s "
                f"(threshold: {self._bulk_threshold})."
            ),
            affected_resource=f"process:{event.process_name}:{event.pid}",
        )

    # =========================================================================
    # Cooldown management
    # =========================================================================

    def _is_on_cooldown(self, pattern_key: str) -> bool:
        """Return True if this pattern was recently detected (suppress duplicate)."""
        last = self._last_detection.get(pattern_key, 0.0)
        return (time.time() - last) < self._detection_cooldown

    def _set_cooldown(self, pattern_key: str) -> None:
        """Record that a detection just fired for cooldown tracking."""
        self._last_detection[pattern_key] = time.time()

    # =========================================================================
    # Introspection
    # =========================================================================

    def get_tracker_stats(self) -> dict[str, Any]:
        """Return statistics about active trackers for health reporting."""
        return {
            "ransomware_window_count": self._ransomware_tracker.count_in_window(),
            "brute_force_sources_tracked": len(self._brute_force_trackers),
            "spawn_parents_tracked": len(self._spawn_trackers),
            "bulk_processes_tracked": len(self._bulk_file_trackers),
            "active_cooldowns": len(self._last_detection),
        }

    def reset_all_trackers(self) -> None:
        """Reset all sliding window state. Called after config reload."""
        self._ransomware_tracker.reset()
        self._brute_force_trackers.clear()
        self._spawn_trackers.clear()
        self._bulk_file_trackers.clear()
        self._last_detection.clear()
        logger.info("BehavioralDetector: all trackers reset.")