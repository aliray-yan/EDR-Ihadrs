"""
Module: detection.engine
Purpose: Central detection coordinator. Subscribes to all bus events,
         routes each event through the full detection pipeline, and
         emits ThreatEvents back onto the bus for classification,
         alerting, and response.
Owner: detection
Dependencies: detection.rule_engine, detection.behavioral, detection.correlation
Performance: Stateless per-event evaluation. Behavioral/correlation state
             maintained in dedicated components. Target: <2ms per event.

Detection Pipeline (per event):
    1. Rule Engine    → deterministic YAML rule matching (O(R×C))
    2. Behavioral     → sliding-window pattern matching (O(1))
    3. Correlation    → cross-event chain detection (O(H) where H = history)
    4. Deduplication  → suppress duplicate ThreatEvents within cooldown
    5. Construction   → build ThreatEvent with full context
    6. Publication    → emit IHADRS_DETECTION_TRIGGERED on event bus
"""

from __future__ import annotations

import asyncio
import socket
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from loguru import logger

from ihadrs.constants import (
    AttackCategory,
    EventType,
    MonitorType,
    ResponseStatus,
    Severity,
)
from ihadrs.core.config import IHADRSConfig
from ihadrs.core.event_bus import BusEvent, EventBus, EventPriority
from ihadrs.core.resource_manager import ResourceManager
from ihadrs.detection.behavioral import BehavioralDetector, BehavioralMatch
from ihadrs.detection.correlation import CorrelationEngine, CorrelationMatch
from ihadrs.detection.rule_engine import DetectionRule, RuleEvaluator, RuleLoader
from ihadrs.models.events import BaseEvent
from ihadrs.models.threats import (
    ProcessContext,
    RemediationStep,
    ThreatEvent,
    ThreatEvidence,
)


# =============================================================================
# DETECTION METRICS
# =============================================================================

@dataclass
class DetectionMetrics:
    """Runtime metrics for the detection engine."""

    events_processed: int = 0
    rule_matches: int = 0
    behavioral_matches: int = 0
    correlation_matches: int = 0
    threats_emitted: int = 0
    threats_deduplicated: int = 0
    processing_errors: int = 0
    avg_latency_ms: float = 0.0
    peak_latency_ms: float = 0.0
    start_time: float = field(default_factory=time.time)

    def update_latency(self, latency_seconds: float) -> None:
        ms = latency_seconds * 1000
        alpha = 0.1
        self.avg_latency_ms = alpha * ms + (1 - alpha) * self.avg_latency_ms
        if ms > self.peak_latency_ms:
            self.peak_latency_ms = ms

    def to_dict(self) -> dict[str, Any]:
        uptime = time.time() - self.start_time
        return {
            "events_processed": self.events_processed,
            "rule_matches": self.rule_matches,
            "behavioral_matches": self.behavioral_matches,
            "correlation_matches": self.correlation_matches,
            "threats_emitted": self.threats_emitted,
            "threats_deduplicated": self.threats_deduplicated,
            "processing_errors": self.processing_errors,
            "avg_latency_ms": round(self.avg_latency_ms, 3),
            "peak_latency_ms": round(self.peak_latency_ms, 3),
            "uptime_seconds": round(uptime, 1),
            "events_per_second": round(
                self.events_processed / max(uptime, 1), 2
            ),
        }


# =============================================================================
# THREAT DEDUPLICATION RECORD
# =============================================================================

@dataclass
class DedupRecord:
    """Tracks recently emitted threats to suppress duplicates."""

    rule_ids: frozenset[str]
    affected_resource: str
    last_seen: float = field(default_factory=time.time)
    count: int = 1


# =============================================================================
# DETECTION ENGINE
# =============================================================================

class DetectionEngine:
    """
    Central detection coordinator for IHADRS.

    Receives every event from the bus, runs the full detection pipeline,
    and emits ThreatEvents for confirmed detections.

    Responsibilities:
    - Load and manage detection rules
    - Route events through rule/behavioral/correlation engines
    - Deduplicate rapid re-detections
    - Construct rich ThreatEvent objects
    - Publish detections back to the event bus

    Thread Safety:
        process_event() is called from the event bus dispatcher thread.
        All state mutations are atomic or protected by the behavioral/
        correlation engine's own locks.
    """

    # How long to suppress re-detection of the same rule+resource (seconds)
    # Overridden by whitelist.deduplication_window_seconds in rules.yaml
    _DEDUP_COOLDOWN_SECONDS: float = 300.0

    # Maximum dedup cache entries before LRU eviction
    _DEDUP_CACHE_MAX: int = 10_000

    def __init__(
        self,
        config: IHADRSConfig,
        event_bus: EventBus,
        resource_manager: Optional[ResourceManager] = None,
    ) -> None:
        self._config = config
        self._event_bus = event_bus
        self._resource_manager = resource_manager
        self._hostname = socket.gethostname()

        # Sub-components (initialized in initialize())
        self._rule_evaluator: Optional[RuleEvaluator] = None
        self._behavioral: Optional[BehavioralDetector] = None
        self._correlation: Optional[CorrelationEngine] = None

        # Deduplication: (frozenset of rule_ids, affected_resource) → DedupRecord
        self._dedup_cache: dict[tuple, DedupRecord] = {}

        # Metrics
        self._metrics = DetectionMetrics()

        self._log = logger.bind(component="DetectionEngine")

        # Whitelist / suppression config (loaded from rules.yaml whitelist block)
        self._trusted_processes: frozenset[str] = frozenset()
        self._trusted_parent_child: list[dict] = []
        self._trusted_paths: list[str] = []
        self._trusted_publishers: frozenset[str] = frozenset()
        self._min_confidence: float = 0.55
        self._spawn_trusted_parents: frozenset[str] = frozenset()
        self._dedup_window: float = 300.0

    # =========================================================================
    # Lifecycle
    # =========================================================================

    async def initialize(self) -> None:
        """
        Load rules and initialize all detection sub-components.

        Raises:
            RuleLoadError: If rules.yaml cannot be loaded.
        """
        # Load detection rules from YAML
        rules_path = Path(self._config.detection.rules_file)
        all_rules = RuleLoader.load_rules(rules_path)

        # Apply user's enabled/disabled rule overrides
        self._rule_evaluator = RuleEvaluator(
            rules=all_rules,
            enabled_rule_ids=list(self._config.detection.enabled_rules),
            disabled_rule_ids=list(self._config.detection.disabled_rules),
        )

        # Behavioral detector with config-driven thresholds
        det = self._config.detection
        self._behavioral = BehavioralDetector(
            ransomware_rename_threshold=det.ransomware_rename_threshold,
            ransomware_window_seconds=det.ransomware_time_window_seconds,
            brute_force_threshold=det.brute_force_failure_threshold,
            brute_force_window_seconds=det.brute_force_time_window_seconds,
            process_spawn_threshold=5,
            process_spawn_window_seconds=30.0,
            bulk_file_threshold=det.bulk_file_read_threshold,
            bulk_file_window_seconds=det.bulk_file_read_window_seconds,
        )

        # Correlation engine
        self._correlation = CorrelationEngine(
            window_seconds=det.correlation_window_seconds,
        )

        self._log.info(
            "DetectionEngine initialized: {n} rules active.",
            n=self._rule_evaluator.active_rule_count,
        )

        # Load whitelist / suppression config from rules.yaml
        self._load_whitelist()

    async def stop(self) -> None:
        """Shut down the detection engine cleanly."""
        self._log.info(
            "DetectionEngine stopping. Final metrics: {m}",
            m=self._metrics.to_dict(),
        )

    # =========================================================================
    # Main event processing (called from event bus dispatcher thread)
    # =========================================================================

    def process_event(self, bus_event: BusEvent) -> None:
        """
        Process one event through the full detection pipeline.

        This is the event bus subscriber callback — called from the
        bus dispatcher thread pool. Must be fast and non-blocking.

        Args:
            bus_event: The BusEvent from the event bus.
        """
        if not isinstance(bus_event, BusEvent):
            return

        payload = bus_event.payload
        if not isinstance(payload, BaseEvent):
            return

        # Skip IHADRS internal events (avoid detecting ourselves)
        if bus_event.source in ("DetectionEngine", "app"):
            return

        start_time = time.monotonic()

        try:
            self._metrics.events_processed += 1
            self._run_detection_pipeline(payload)
        except Exception as exc:
            self._metrics.processing_errors += 1
            self._log.error(
                "Detection pipeline error for {type}: {exc}",
                type=payload.event_type.value,
                exc=exc,
            )
        finally:
            elapsed = time.monotonic() - start_time
            self._metrics.update_latency(elapsed)

    def _load_whitelist(self) -> None:
        """Load whitelist and suppression config from rules.yaml."""
        try:
            import yaml
            rules_path = Path(self._config.detection.rules_file)
            with rules_path.open("r", encoding="utf-8") as f:
                raw = yaml.safe_load(f)
            wl = raw.get("whitelist", {})

            self._trusted_processes = frozenset(
                p.lower() for p in wl.get("trusted_processes", [])
            )
            self._trusted_parent_child = wl.get("trusted_parent_child", [])
            self._trusted_paths = wl.get("trusted_paths", [])
            self._trusted_publishers = frozenset(
                p.lower() for p in wl.get("trusted_publishers", [])
            )
            self._min_confidence = float(wl.get("min_confidence_threshold", 0.55))
            self._dedup_window = float(wl.get("deduplication_window_seconds", 300.0))
            self._spawn_trusted_parents = frozenset(
                p.lower() for p in wl.get("spawn_burst_trusted_parents", [])
            )

            # Apply disabled_rules to evaluator
            disabled = set(wl.get("disabled_rules", []))
            if disabled and self._rule_evaluator:
                self._rule_evaluator._disabled.update(disabled)
                self._rule_evaluator._active_rules = [
                    r for r in self._rule_evaluator._active_rules
                    if r.rule_id not in disabled
                ]

            self._log.info(
                "Whitelist loaded: {tp} trusted processes, {dr} disabled rules.",
                tp=len(self._trusted_processes),
                dr=len(disabled),
            )
        except Exception as exc:
            self._log.warning("Could not load whitelist: {exc}", exc=exc)

    def _is_whitelisted(self, event: "BaseEvent") -> bool:
        """Return True if event should be suppressed (trusted source)."""
        from ihadrs.models.events import ProcessEvent, FileEvent

        if isinstance(event, ProcessEvent):
            name   = event.process_name.lower()
            parent = event.parent_name.lower()
            exe    = event.image_path.lower().replace("\\", "/")

            # Trusted process name
            if name in self._trusted_processes:
                return True

            # Trusted parent-child pair
            for pair in self._trusted_parent_child:
                if (parent == pair.get("parent","").lower() and
                        name == pair.get("child","").lower()):
                    return True

            # Trusted path fragments
            for tp in self._trusted_paths:
                frag = tp.lower().replace("*","").replace("\\","/").strip("/")
                if frag and frag in exe:
                    return True

            # Signed by trusted publisher
            if event.is_microsoft_signed:
                return True
            if event.signer and event.signer.lower() in self._trusted_publishers:
                return True

        elif isinstance(event, FileEvent):
            path = event.file_path.lower().replace("\\", "/")
            for tp in self._trusted_paths:
                frag = tp.lower().replace("*","").replace("\\","/").strip("/")
                if frag and frag in path:
                    return True

        return False

    def _run_detection_pipeline(self, event: BaseEvent) -> None:
        """Run the full detection pipeline for one event."""
        # Fast whitelist check — skip entirely if trusted
        if self._is_whitelisted(event):
            return

        all_threats: list[ThreatEvent] = []

        # --- Stage 1: Rule Engine ---
        if self._rule_evaluator:
            matched_rules = self._rule_evaluator.evaluate(event)
            if matched_rules:
                self._metrics.rule_matches += len(matched_rules)
                threat = self._build_threat_from_rules(event, matched_rules)
                if threat:
                    all_threats.append(threat)

        # --- Stage 2: Behavioral Detection ---
        if self._behavioral:
            behavioral_matches = self._behavioral.process_event(event)
            if behavioral_matches:
                self._metrics.behavioral_matches += len(behavioral_matches)
                for match in behavioral_matches:
                    threat = self._build_threat_from_behavioral(event, match)
                    if threat:
                        all_threats.append(threat)

        # --- Stage 3: Correlation Engine ---
        if self._correlation:
            corr_matches = self._correlation.process_event(event)
            if corr_matches:
                self._metrics.correlation_matches += len(corr_matches)
                for match in corr_matches:
                    threat = self._build_threat_from_correlation(match)
                    if threat:
                        all_threats.append(threat)

        # --- Stage 4: Deduplication & Emission ---
        for threat in all_threats:
            if self._should_emit(threat):
                self._emit_threat(threat)

    # =========================================================================
    # ThreatEvent Builders
    # =========================================================================

    def _build_threat_from_rules(
        self,
        event: BaseEvent,
        matched_rules: list[DetectionRule],
    ) -> Optional[ThreatEvent]:
        """Construct a ThreatEvent from one or more matched detection rules."""
        if not matched_rules:
            return None

        # Use the highest-severity matched rule as the primary
        primary = max(matched_rules, key=lambda r: r.severity.numeric)

        # Merge MITRE data from all matched rules
        all_tactics: list[str] = []
        all_techniques: list[str] = []
        for rule in matched_rules:
            all_tactics.extend(rule.mitre.tactics)
            all_techniques.extend(rule.mitre.techniques)

        # Deduplicate preserving order
        tactics = list(dict.fromkeys(all_tactics))
        techniques = list(dict.fromkeys(all_techniques))

        # Resolve tactic/technique names from mapping
        from ihadrs.constants import MITRE_TACTICS
        from ihadrs.intelligence.mitre import MITREMapper

        tactic_names = [MITRE_TACTICS.get(t, t) for t in tactics]
        technique_names = MITREMapper.get_technique_names(techniques)

        # Affected resource string
        affected_resource = self._get_affected_resource(event)

        # Build evidence
        evidence = ThreatEvidence(
            triggered_rule_ids=[r.rule_id for r in matched_rules],
            triggered_rule_names=[r.name for r in matched_rules],
            raw_events=[event.to_dict()],
        )

        # Build remediation steps from primary rule
        remediation_steps = self._build_remediation_steps(primary)

        # Interpolate explanation templates with event context
        ctx = self._build_template_context(event)
        user_explanation = _interpolate(primary.user_explanation, ctx)
        technical_details = _interpolate(primary.technical_details, ctx)

        return ThreatEvent(
            hostname=self._hostname,
            username=getattr(event, "username", ""),
            source_monitor=event.source_monitor.value,
            source_event_ids=[event.event_id],
            attack_category=primary.attack_category,
            severity=primary.severity,
            confidence=primary.confidence,
            mitre_tactics=tactics,
            mitre_techniques=techniques,
            mitre_tactic_names=tactic_names,
            mitre_technique_names=technique_names,
            affected_resource=affected_resource,
            summary=f"{primary.name}: {affected_resource}",
            user_explanation=user_explanation or primary.name,
            technical_details=technical_details,
            evidence=evidence,
            process_context=self._extract_process_context(event),
            remediation_steps=remediation_steps,
            false_positive_hints=primary.false_positive_hints,
            references=primary.references,
            tags=primary.tags,
        )

    def _build_threat_from_behavioral(
        self,
        event: BaseEvent,
        match: BehavioralMatch,
    ) -> Optional[ThreatEvent]:
        """Construct a ThreatEvent from a behavioral pattern match."""
        from ihadrs.constants import MITRE_TACTICS
        from ihadrs.intelligence.mitre import MITREMapper

        tactic_names = [MITRE_TACTICS.get(t, t) for t in match.mitre_tactics]
        technique_names = MITREMapper.get_technique_names(match.mitre_techniques)

        evidence = ThreatEvidence(
            triggered_rule_ids=[match.pattern_id],
            triggered_rule_names=[match.pattern_name],
            raw_events=match.sample_events,
            behavioral_pattern=match.pattern_id,
        )

        return ThreatEvent(
            hostname=self._hostname,
            username=getattr(event, "username", ""),
            source_monitor=event.source_monitor.value,
            source_event_ids=[event.event_id],
            attack_category=match.attack_category,
            severity=match.severity,
            confidence=match.confidence,
            mitre_tactics=match.mitre_tactics,
            mitre_techniques=match.mitre_techniques,
            mitre_tactic_names=tactic_names,
            mitre_technique_names=technique_names,
            affected_resource=match.affected_resource or self._get_affected_resource(event),
            summary=match.summary,
            user_explanation=match.user_explanation,
            technical_details=match.technical_details,
            evidence=evidence,
            process_context=self._extract_process_context(event),
        )

    def _build_threat_from_correlation(
        self,
        match: CorrelationMatch,
    ) -> Optional[ThreatEvent]:
        """Construct a ThreatEvent from a correlation pattern match."""
        from ihadrs.constants import MITRE_TACTICS
        from ihadrs.intelligence.mitre import MITREMapper

        tactic_names = [MITRE_TACTICS.get(t, t) for t in match.mitre_tactics]
        technique_names = MITREMapper.get_technique_names(match.mitre_techniques)

        evidence = ThreatEvidence(
            triggered_rule_ids=[match.pattern_id],
            triggered_rule_names=[match.pattern_name],
            correlated_event_ids=match.chain_event_ids,
            behavioral_pattern=f"correlation:{match.pattern_id}",
        )

        return ThreatEvent(
            hostname=self._hostname,
            source_monitor="correlation_engine",
            source_event_ids=match.chain_event_ids,
            attack_category=match.attack_category,
            severity=match.severity,
            confidence=match.confidence,
            mitre_tactics=match.mitre_tactics,
            mitre_techniques=match.mitre_techniques,
            mitre_tactic_names=tactic_names,
            mitre_technique_names=technique_names,
            affected_resource=match.affected_resource,
            summary=match.summary,
            user_explanation=match.user_explanation,
            technical_details=match.technical_details,
            evidence=evidence,
            tags=["correlation"],
        )

    # =========================================================================
    # Deduplication
    # =========================================================================

    def _should_emit(self, threat: ThreatEvent) -> bool:
        """
        Return True if this threat should be emitted (not a recent duplicate
        and meets minimum confidence threshold).
        """
        # Minimum confidence filter
        if threat.confidence < self._min_confidence:
            self._metrics.threats_deduplicated += 1
            return False

        rule_key = frozenset(threat.evidence.triggered_rule_ids)
        dedup_key = (rule_key, threat.affected_resource)

        existing = self._dedup_cache.get(dedup_key)
        if existing:
            elapsed = time.time() - existing.last_seen
            cooldown = self._dedup_window or self._DEDUP_COOLDOWN_SECONDS
            if elapsed < cooldown:
                existing.last_seen = time.time()
                existing.count += 1
                self._metrics.threats_deduplicated += 1
                return False

        # Not a duplicate — add to cache
        self._dedup_cache[dedup_key] = DedupRecord(
            rule_ids=rule_key,
            affected_resource=threat.affected_resource,
        )

        # Evict oldest entries if cache is too large
        if len(self._dedup_cache) > self._DEDUP_CACHE_MAX:
            oldest_key = min(
                self._dedup_cache,
                key=lambda k: self._dedup_cache[k].last_seen,
            )
            del self._dedup_cache[oldest_key]

        return True

    # =========================================================================
    # Event Emission
    # =========================================================================

    def _emit_threat(self, threat: ThreatEvent) -> None:
        """Publish a ThreatEvent on the event bus as IHADRS_DETECTION_TRIGGERED."""
        self._metrics.threats_emitted += 1

        # Log the detection
        self._log.warning(
            "THREAT DETECTED [{sev}] {cat}: {summary} (confidence={conf:.0%})",
            sev=threat.severity.value,
            cat=threat.attack_category.value,
            summary=threat.summary[:80],
            conf=threat.confidence,
        )

        # Priority mapping: CRITICAL→CRITICAL, HIGH→HIGH, MEDIUM/LOW→NORMAL
        priority_map = {
            Severity.CRITICAL: EventPriority.CRITICAL,
            Severity.HIGH: EventPriority.HIGH,
            Severity.MEDIUM: EventPriority.NORMAL,
            Severity.LOW: EventPriority.LOW,
        }
        priority = priority_map.get(threat.severity, EventPriority.NORMAL)

        try:
            self._event_bus.publish(
                BusEvent(
                    event_type=EventType.IHADRS_DETECTION_TRIGGERED,
                    source="DetectionEngine",
                    payload=threat,
                    priority=priority,
                    severity=threat.severity,
                    tags=threat.tags,
                )
            )
        except Exception as exc:
            self._log.error(
                "Failed to emit threat {id}: {exc}",
                id=threat.threat_id, exc=exc,
            )

    # =========================================================================
    # Context Helpers
    # =========================================================================

    def _get_affected_resource(self, event: BaseEvent) -> str:
        """Build a human-readable affected resource string from an event."""
        from ihadrs.models.events import (
            ProcessEvent, NetworkEvent, FileEvent,
            RegistryEvent, ServiceEvent, AuthenticationEvent,
        )

        if isinstance(event, ProcessEvent):
            return f"process:{event.process_name}:{event.pid}"
        elif isinstance(event, NetworkEvent):
            return f"network:{event.remote_ip}:{event.remote_port}"
        elif isinstance(event, FileEvent):
            return f"file:{event.file_path}"
        elif isinstance(event, RegistryEvent):
            return f"registry:{event.full_path}"
        elif isinstance(event, ServiceEvent):
            return f"service:{event.service_name}"
        elif isinstance(event, AuthenticationEvent):
            return f"auth:{event.target_username}@{event.source_ip}"
        else:
            return f"event:{event.event_type.value}"

    def _extract_process_context(
        self, event: BaseEvent
    ) -> Optional[ProcessContext]:
        """Extract ProcessContext if the event is process-related."""
        from ihadrs.models.events import ProcessEvent

        if not isinstance(event, ProcessEvent):
            return None

        return ProcessContext(
            pid=event.pid,
            name=event.process_name,
            image_path=event.image_path,
            command_line=event.command_line,
            username=event.username,
            is_elevated=event.is_elevated,
            integrity_level=event.integrity_level,
            is_signed=event.is_signed,
            signer=event.signer,
            sha256=event.sha256,
            parent_pid=event.parent_pid,
            parent_name=event.parent_name,
            create_time=event.create_time,
            lifetime_seconds=event.lifetime_seconds,
            num_threads=event.num_threads,
            memory_mb=event.memory_mb,
        )

    def _build_remediation_steps(
        self, rule: DetectionRule
    ) -> list[RemediationStep]:
        """Convert raw rule remediation steps to RemediationStep objects."""
        steps: list[RemediationStep] = []
        for i, step_text in enumerate(rule.remediation.manual_steps, 1):
            # Detect step category from text
            text_lower = step_text.lower()
            if any(w in text_lower for w in ["immediate", "disconnect", "do not"]):
                category = "immediate"
            elif any(w in text_lower for w in ["check", "review", "investigate", "verify"]):
                category = "investigation"
            elif any(w in text_lower for w in ["delete", "remove", "restore", "scan", "run"]):
                category = "remediation"
            else:
                category = "prevention"

            # Extract command if present (lines with taskkill, net, sc, etc.)
            command = ""
            if any(cmd in step_text for cmd in ["taskkill", "net ", "sc ", "MpCmdRun", "schtasks"]):
                command = step_text.strip()

            steps.append(RemediationStep(
                step_number=i,
                category=category,
                description=step_text,
                command=command,
            ))
        return steps

    def _build_template_context(self, event: BaseEvent) -> dict[str, Any]:
        """Build template variable context from an event for explanation interpolation."""
        ctx: dict[str, Any] = {
            "event_type": event.event_type.value,
            "hostname": self._hostname,
        }
        from ihadrs.models.events import ProcessEvent, NetworkEvent, FileEvent

        if isinstance(event, ProcessEvent):
            ctx.update({
                "process_name": event.process_name,
                "pid": event.pid,
                "command_line": event.command_line,
                "parent_name": event.parent_name,
                "parent_pid": event.parent_pid,
                "username": event.username,
                "image_path": event.image_path,
            })
        elif isinstance(event, NetworkEvent):
            ctx.update({
                "process_name": event.process_name,
                "pid": event.pid,
                "remote_ip": event.remote_ip,
                "remote_port": event.remote_port,
                "remote_hostname": event.remote_hostname,
            })
        elif isinstance(event, FileEvent):
            ctx.update({
                "file_path": event.file_path,
                "process_name": event.process_name,
                "pid": event.pid,
                "new_path": event.new_path,
                "new_extension": event.new_extension,
            })
        return ctx

    # =========================================================================
    # Properties & Health
    # =========================================================================

    @property
    def rule_count(self) -> int:
        """Number of active detection rules."""
        return self._rule_evaluator.active_rule_count if self._rule_evaluator else 0

    def get_metrics(self) -> dict[str, Any]:
        """Return detection engine metrics for the API."""
        return self._metrics.to_dict()

    def health_check(self) -> dict[str, Any]:
        """Return health status for API /health endpoint."""
        issues: list[str] = []

        if self._rule_evaluator is None:
            issues.append("Rule evaluator not initialized")
        if self._behavioral is None:
            issues.append("Behavioral detector not initialized")
        if self._correlation is None:
            issues.append("Correlation engine not initialized")

        status = "healthy" if not issues else "degraded"
        return {
            "status": status,
            "issues": issues,
            "rule_count": self.rule_count,
            "metrics": self._metrics.to_dict(),
            "behavioral_stats": (
                self._behavioral.get_tracker_stats()
                if self._behavioral else {}
            ),
            "correlation_stats": (
                self._correlation.get_stats()
                if self._correlation else {}
            ),
        }


# =============================================================================
# TEMPLATE INTERPOLATION
# =============================================================================

def _interpolate(template: str, context: dict[str, Any]) -> str:
    """
    Safely interpolate a template string with context variables.

    Uses Python str.format_map with a default-missing dict so that
    missing variables produce the placeholder text rather than raising.

    Example:
        _interpolate("Process {process_name} (PID {pid})", {"process_name": "cmd.exe", "pid": 1234})
        → "Process cmd.exe (PID 1234)"
    """
    if not template:
        return ""
    try:
        return template.format_map(defaultdict(lambda: "?", context))
    except Exception:
        return template