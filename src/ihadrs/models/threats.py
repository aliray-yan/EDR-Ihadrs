"""
Module: models.threats
Purpose: ThreatEvent and related models — the core data structure passed
         between detection, classification, response, and alerting systems.
         A ThreatEvent represents a confirmed (or suspected) security threat
         with full evidence, context, MITRE mapping, and remediation steps.
Owner: models
Dependencies: dataclasses, typing, constants
Performance: ThreatEvent instances are created rarely relative to raw events.
             Fields are dataclasses, not Pydantic, for minimal overhead.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from ihadrs.constants import (
    AttackCategory,
    ResponseStatus,
    Severity,
)


# =============================================================================
# EVIDENCE
# =============================================================================

@dataclass
class ThreatEvidence:
    """
    Raw evidence that triggered the detection.

    Preserves the original event data so analysts can inspect exactly
    what the system saw. Never mutated after creation.
    """

    # Which detection rules fired
    triggered_rule_ids: list[str] = field(default_factory=list)
    triggered_rule_names: list[str] = field(default_factory=list)

    # The raw event payloads that matched (serialized to dicts)
    raw_events: list[dict[str, Any]] = field(default_factory=list)

    # Extracted indicators of compromise
    iocs: list[str] = field(default_factory=list)  # hashes, IPs, domains, paths

    # ML anomaly score (if ML detection contributed)
    ml_anomaly_score: Optional[float] = None
    ml_contributing_features: list[dict[str, Any]] = field(default_factory=list)

    # Behavioral pattern that matched (for behavioral rules)
    behavioral_pattern: str = ""

    # Correlation info (if this threat is part of a larger chain)
    correlated_event_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "triggered_rules": list(zip(
                self.triggered_rule_ids,
                self.triggered_rule_names,
            )),
            "iocs": self.iocs,
            "ml_anomaly_score": self.ml_anomaly_score,
            "ml_features": self.ml_contributing_features,
            "behavioral_pattern": self.behavioral_pattern,
            "correlated_events": self.correlated_event_ids,
        }


# =============================================================================
# PROCESS / NETWORK / FILE CONTEXT
# =============================================================================

@dataclass
class ProcessContext:
    """
    Full process tree context around the threatening process.

    Built by the context_builder module after detection fires.
    Provides analysts with the complete picture: what ran it,
    what it spawned, what network connections it had.
    """

    pid: int = 0
    name: str = ""
    image_path: str = ""
    command_line: str = ""
    username: str = ""
    integrity_level: str = ""
    is_elevated: bool = False
    is_signed: bool = False
    signer: str = ""
    sha256: str = ""
    md5: str = ""

    # Process tree
    parent_pid: int = 0
    parent_name: str = ""
    parent_command_line: str = ""
    grandparent_name: str = ""
    children: list[dict[str, Any]] = field(default_factory=list)

    # Runtime state
    create_time: Optional[datetime] = None
    lifetime_seconds: float = 0.0
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    num_threads: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "name": self.name,
            "image_path": self.image_path,
            "command_line": self.command_line,
            "username": self.username,
            "integrity_level": self.integrity_level,
            "is_elevated": self.is_elevated,
            "is_signed": self.is_signed,
            "signer": self.signer,
            "sha256": self.sha256,
            "parent": {
                "pid": self.parent_pid,
                "name": self.parent_name,
                "command_line": self.parent_command_line,
            },
            "grandparent_name": self.grandparent_name,
            "children_count": len(self.children),
        }


@dataclass
class NetworkContext:
    """Network activity context associated with a threat."""

    active_connections: list[dict[str, Any]] = field(default_factory=list)
    listening_ports: list[int] = field(default_factory=list)
    unique_remote_ips: list[str] = field(default_factory=list)
    bytes_sent_total: int = 0
    bytes_received_total: int = 0
    has_external_connection: bool = False
    suspicious_ips: list[str] = field(default_factory=list)
    c2_candidates: list[str] = field(default_factory=list)


@dataclass
class FileContext:
    """File system operations context associated with a threat."""

    files_read: list[str] = field(default_factory=list)
    files_written: list[str] = field(default_factory=list)
    files_deleted: list[str] = field(default_factory=list)
    files_renamed: list[tuple[str, str]] = field(default_factory=list)  # (old, new)
    files_created: list[str] = field(default_factory=list)
    total_bytes_read: int = 0
    total_bytes_written: int = 0
    encrypted_extensions_seen: list[str] = field(default_factory=list)
    high_risk_paths_accessed: list[str] = field(default_factory=list)


# =============================================================================
# REMEDIATION STEP
# =============================================================================

@dataclass
class RemediationStep:
    """
    A single remediation action step for the user to take.

    Steps are ordered (step_number) and categorized by urgency.
    Some steps include embedded commands/links the UI can make interactive.
    """

    step_number: int
    category: str       # "immediate" | "investigation" | "recovery" | "prevention"
    description: str    # Human-readable instruction
    command: str = ""   # Optional: command the user can run
    url: str = ""       # Optional: link to more information
    is_automated: bool = False  # True if IHADRS has already done this automatically
    automated_result: str = ""  # Result of automated action, if applicable

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step_number,
            "category": self.category,
            "description": self.description,
            "command": self.command,
            "url": self.url,
            "is_automated": self.is_automated,
            "automated_result": self.automated_result,
        }


# =============================================================================
# AUTOMATED ACTION RECORD
# =============================================================================

@dataclass
class AutomatedActionRecord:
    """
    Record of an automated response action taken by IHADRS.

    Stored in the audit log and displayed in the UI so users know
    exactly what IHADRS did and can undo it.
    """

    action_type: str            # ActionType enum value
    target: str                 # What was acted on (PID, IP, file path)
    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    success: bool = False
    result_message: str = ""
    error_message: str = ""
    rollback_available: bool = False
    rollback_data: dict[str, Any] = field(default_factory=dict)
    rolled_back: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "target": self.target,
            "timestamp": self.timestamp.isoformat(),
            "success": self.success,
            "result_message": self.result_message,
            "error_message": self.error_message,
            "rollback_available": self.rollback_available,
            "rolled_back": self.rolled_back,
        }


# =============================================================================
# THREAT EVENT — THE CORE MODEL
# =============================================================================

@dataclass
class ThreatEvent:
    """
    Represents a detected security threat with complete context.

    This is the primary data structure produced by the detection engine
    and consumed by: classification, response, alerting, logging, storage,
    and the UI/API.

    Lifecycle:
        1. Detection engine creates ThreatEvent with basic fields
        2. Classifier enriches: attack_category, severity, confidence
        3. Context builder enriches: process_context, network_context
        4. Intelligence module enriches: mitre details, IOC info
        5. Recommender adds: remediation_steps
        6. Auto-responder executes: automated_actions
        7. Alerter notifies: user/email/webhook
        8. Event store persists: to SQLite

    Immutability Note:
        ThreatEvent fields are mutable during the enrichment pipeline
        (pipeline pattern). After storage/alerting they should be
        treated as read-only.
    """

    # -------------------------------------------------------------------------
    # Identity
    # -------------------------------------------------------------------------
    threat_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )
    hostname: str = ""
    username: str = ""

    # -------------------------------------------------------------------------
    # Source
    # -------------------------------------------------------------------------
    source_monitor: str = ""        # MonitorType.value
    source_event_ids: list[str] = field(default_factory=list)  # BusEvent IDs

    # -------------------------------------------------------------------------
    # Classification
    # -------------------------------------------------------------------------
    attack_category: AttackCategory = AttackCategory.UNKNOWN
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.5         # 0.0 – 1.0

    # MITRE ATT&CK mapping
    mitre_tactics: list[str] = field(default_factory=list)      # ["TA0002"]
    mitre_techniques: list[str] = field(default_factory=list)   # ["T1059.001"]
    mitre_tactic_names: list[str] = field(default_factory=list)  # ["Execution"]
    mitre_technique_names: list[str] = field(default_factory=list)  # ["PowerShell"]

    # -------------------------------------------------------------------------
    # Affected Resource
    # -------------------------------------------------------------------------
    # Human-readable identifier: "process:powershell.exe:4821"
    # or "file:C:\Users\John\report.docx" or "network:192.168.1.100:4444"
    affected_resource: str = ""

    # -------------------------------------------------------------------------
    # Evidence
    # -------------------------------------------------------------------------
    evidence: ThreatEvidence = field(default_factory=ThreatEvidence)

    # -------------------------------------------------------------------------
    # Context (enriched after initial detection)
    # -------------------------------------------------------------------------
    process_context: Optional[ProcessContext] = None
    network_context: Optional[NetworkContext] = None
    file_context: Optional[FileContext] = None

    # -------------------------------------------------------------------------
    # Human-Readable Explanation
    # -------------------------------------------------------------------------
    # For end users with no security background:
    user_explanation: str = ""

    # For security analysts with technical context:
    technical_details: str = ""

    # Brief one-line summary for notifications and list views:
    summary: str = ""

    # -------------------------------------------------------------------------
    # False Positive Assessment
    # -------------------------------------------------------------------------
    false_positive_likelihood: float = 0.0  # 0.0=definitely malicious, 1.0=probably FP
    false_positive_hints: list[str] = field(default_factory=list)
    marked_as_false_positive: bool = False
    false_positive_marked_by: str = ""
    false_positive_reason: str = ""

    # -------------------------------------------------------------------------
    # Remediation
    # -------------------------------------------------------------------------
    remediation_steps: list[RemediationStep] = field(default_factory=list)
    prevention_tips: list[str] = field(default_factory=list)
    educational_content: str = ""   # Link/content about this attack type

    # -------------------------------------------------------------------------
    # Automated Response
    # -------------------------------------------------------------------------
    automated_actions: list[AutomatedActionRecord] = field(default_factory=list)
    response_status: ResponseStatus = ResponseStatus.NONE
    response_approved_by: str = ""  # "auto" | username | ""
    response_timestamp: Optional[datetime] = None

    # -------------------------------------------------------------------------
    # Relations
    # -------------------------------------------------------------------------
    related_threat_ids: list[str] = field(default_factory=list)  # Related threats
    attack_chain_id: Optional[str] = None  # Links threats in same attack sequence

    # -------------------------------------------------------------------------
    # Metadata
    # -------------------------------------------------------------------------
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)  # URLs to ATT&CK, CVEs, etc.

    # -------------------------------------------------------------------------
    # Derived Properties
    # -------------------------------------------------------------------------

    @property
    def is_critical(self) -> bool:
        return self.severity == Severity.CRITICAL

    @property
    def is_high_confidence(self) -> bool:
        return self.confidence >= 0.8

    @property
    def requires_immediate_action(self) -> bool:
        return (
            self.severity in (Severity.CRITICAL, Severity.HIGH)
            and self.confidence >= 0.7
            and not self.marked_as_false_positive
        )

    @property
    def alert_color_hex(self) -> str:
        return self.severity.color_hex

    @property
    def alert_icon(self) -> str:
        return self.severity.icon

    @property
    def primary_technique(self) -> str:
        """Return the most specific MITRE technique ID, or empty string."""
        return self.mitre_techniques[0] if self.mitre_techniques else ""

    @property
    def primary_technique_name(self) -> str:
        """Return the name of the primary MITRE technique."""
        return self.mitre_technique_names[0] if self.mitre_technique_names else ""

    # -------------------------------------------------------------------------
    # Serialization
    # -------------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Full serialization for API responses, logging, and storage."""
        return {
            "threat_id": self.threat_id,
            "timestamp": self.timestamp.isoformat(),
            "hostname": self.hostname,
            "username": self.username,
            "source_monitor": self.source_monitor,
            "attack_category": self.attack_category.value,
            "severity": self.severity.value,
            "severity_icon": self.severity.icon,
            "severity_color": self.severity.color_hex,
            "confidence": round(self.confidence, 3),
            "mitre": {
                "tactics": self.mitre_tactics,
                "tactic_names": self.mitre_tactic_names,
                "techniques": self.mitre_techniques,
                "technique_names": self.mitre_technique_names,
            },
            "affected_resource": self.affected_resource,
            "summary": self.summary,
            "explanation": {
                "user": self.user_explanation,
                "technical": self.technical_details,
                "educational": self.educational_content,
            },
            "evidence": self.evidence.to_dict(),
            "process_context": (
                self.process_context.to_dict()
                if self.process_context
                else None
            ),
            "remediation": [s.to_dict() for s in self.remediation_steps],
            "prevention_tips": self.prevention_tips,
            "automated_actions": [a.to_dict() for a in self.automated_actions],
            "response_status": self.response_status.value,
            "false_positive": {
                "likelihood": round(self.false_positive_likelihood, 3),
                "hints": self.false_positive_hints,
                "marked": self.marked_as_false_positive,
                "reason": self.false_positive_reason,
            },
            "tags": self.tags,
            "references": self.references,
            "related_threats": self.related_threat_ids,
        }

    def to_log_dict(self) -> dict[str, Any]:
        """
        Compact serialization for JSONL event logging.

        Omits large nested objects to keep log files manageable.
        """
        return {
            "threat_id": self.threat_id,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity.value,
            "attack_category": self.attack_category.value,
            "confidence": round(self.confidence, 2),
            "techniques": self.mitre_techniques,
            "affected_resource": self.affected_resource,
            "summary": self.summary,
            "response_status": self.response_status.value,
            "false_positive": self.marked_as_false_positive,
            "rules": self.evidence.triggered_rule_ids,
        }

    def to_alert_dict(self) -> dict[str, Any]:
        """Compact format for desktop notification and email alerts."""
        return {
            "threat_id": self.threat_id,
            "severity": self.severity.value,
            "icon": self.alert_icon,
            "color": self.alert_color_hex,
            "attack_category": self.attack_category.value,
            "summary": self.summary,
            "confidence_pct": f"{self.confidence:.0%}",
            "affected_resource": self.affected_resource,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "top_remediation": (
                self.remediation_steps[0].description
                if self.remediation_steps
                else "See IHADRS dashboard for details."
            ),
        }

    def __repr__(self) -> str:
        return (
            f"ThreatEvent("
            f"id={self.threat_id[:8]}..., "
            f"severity={self.severity.value}, "
            f"category={self.attack_category.value}, "
            f"confidence={self.confidence:.0%}, "
            f"resource='{self.affected_resource[:40]}')"
        )