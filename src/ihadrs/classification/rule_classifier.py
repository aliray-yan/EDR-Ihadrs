"""
Module: classification.rule_classifier
Purpose: Deterministic rule-based classifier that maps detected threats
         to attack categories, refines severity, and adjusts confidence
         based on contextual signals (elevation, path, parent chain, etc.)
Owner: classification
Dependencies: ihadrs.constants, ihadrs.models
Performance: Pure dict/enum lookups — O(1) per classification.
"""

from __future__ import annotations

from typing import Any, Optional

from ihadrs.constants import (
    AttackCategory,
    ConfidenceLevel,
    LOLBINS,
    SYSTEM_PROCESS_NAMES,
    Severity,
    TECHNIQUE_TO_CATEGORY,
)
from ihadrs.models.events import (
    AuthenticationEvent,
    BaseEvent,
    FileEvent,
    NetworkEvent,
    ProcessEvent,
    RegistryEvent,
    ServiceEvent,
)
from ihadrs.models.threats import ThreatEvent


class RuleClassifier:
    """
    Deterministic threat classifier using rule-based logic.

    Takes a ThreatEvent produced by the detection engine and refines:
    - attack_category: based on MITRE technique mapping + event type
    - severity:        adjusted based on contextual risk signals
    - confidence:      boosted/reduced based on false-positive likelihood
    - false_positive_likelihood: estimated from process whitelist / context

    This runs AFTER the detection engine creates the initial ThreatEvent,
    adding domain-specific intelligence that the generic rule evaluator
    cannot provide.
    """

    # Risk multipliers applied to base confidence
    # Positive = increase confidence (more likely malicious)
    # Negative = decrease confidence (more likely FP)
    _RISK_SIGNALS: dict[str, float] = {
        "is_elevated":          +0.10,
        "path_is_temp":         +0.15,
        "path_is_appdata":      +0.08,
        "path_is_downloads":    +0.12,
        "is_lolbin":            +0.10,
        "is_signed":            -0.15,
        "is_microsoft_signed":  -0.20,
        "parent_is_office":     +0.20,
        "parent_is_shell":      +0.05,
        "parent_is_system":     -0.10,
        "low_lifetime":         +0.05,  # Very short-lived process
        "high_cpu_user":        -0.05,  # Likely a legitimate computation task
    }

    def classify(
        self,
        threat: ThreatEvent,
        source_event: Optional[BaseEvent] = None,
    ) -> ThreatEvent:
        """
        Refine a ThreatEvent's classification using contextual signals.

        Args:
            threat:       The initial ThreatEvent from the detection engine.
            source_event: The raw event that triggered detection (for context).

        Returns:
            The same ThreatEvent with refined fields (mutated in place).
        """
        # 1. Refine attack category from MITRE techniques
        if threat.attack_category == AttackCategory.UNKNOWN and threat.mitre_techniques:
            for technique in threat.mitre_techniques:
                if technique in TECHNIQUE_TO_CATEGORY:
                    threat.attack_category = TECHNIQUE_TO_CATEGORY[technique]
                    break

        # 2. Context-based confidence adjustment
        if source_event is not None:
            confidence_delta = self._compute_confidence_delta(source_event)
            threat.confidence = max(0.05, min(0.99, threat.confidence + confidence_delta))

        # 3. False positive likelihood estimation
        if source_event is not None:
            threat.false_positive_likelihood = self._estimate_fp_likelihood(
                threat, source_event
            )

        # 4. Severity upgrade for critical contexts
        if source_event is not None:
            threat.severity = self._adjust_severity(threat, source_event)

        return threat

    def _compute_confidence_delta(self, event: BaseEvent) -> float:
        """Compute confidence adjustment from contextual risk signals."""
        delta = 0.0

        if isinstance(event, ProcessEvent):
            if event.is_elevated:
                delta += self._RISK_SIGNALS["is_elevated"]

            exe = event.image_path.lower().replace("\\", "/")
            if "temp" in exe or "/tmp" in exe:
                delta += self._RISK_SIGNALS["path_is_temp"]
            if "appdata" in exe:
                delta += self._RISK_SIGNALS["path_is_appdata"]
            if "downloads" in exe:
                delta += self._RISK_SIGNALS["path_is_downloads"]

            proc_lower = event.process_name.lower()
            if proc_lower in LOLBINS:
                delta += self._RISK_SIGNALS["is_lolbin"]

            if event.is_signed:
                delta += self._RISK_SIGNALS["is_signed"]
            if event.is_microsoft_signed:
                delta += self._RISK_SIGNALS["is_microsoft_signed"]

            parent_lower = event.parent_name.lower()
            office_apps = {
                "winword.exe", "excel.exe", "powerpnt.exe",
                "outlook.exe", "onenote.exe",
            }
            shell_apps = {"cmd.exe", "powershell.exe", "bash", "sh"}
            system_procs = {"services.exe", "wininit.exe", "systemd", "init"}

            if parent_lower in office_apps:
                delta += self._RISK_SIGNALS["parent_is_office"]
            elif parent_lower in shell_apps:
                delta += self._RISK_SIGNALS["parent_is_shell"]
            elif parent_lower in system_procs:
                delta += self._RISK_SIGNALS["parent_is_system"]

            if event.lifetime_seconds < 5.0 and event.lifetime_seconds > 0:
                delta += self._RISK_SIGNALS["low_lifetime"]

        return delta

    def _estimate_fp_likelihood(
        self, threat: ThreatEvent, event: BaseEvent
    ) -> float:
        """
        Estimate the probability that this detection is a false positive.

        Returns 0.0 = definitely malicious, 1.0 = definitely FP.
        """
        fp_score = 0.0

        if isinstance(event, ProcessEvent):
            # Signed Microsoft binaries rarely trigger legitimate security rules
            if event.is_microsoft_signed:
                fp_score += 0.3
            elif event.is_signed:
                fp_score += 0.15

            # System processes have legitimate reasons for most behaviors
            proc_lower = event.process_name.lower()
            if proc_lower in SYSTEM_PROCESS_NAMES:
                fp_score += 0.25

            # Short-lived processes are more suspicious
            if event.lifetime_seconds < 1.0:
                fp_score -= 0.1

            # Medium confidence rule = more uncertainty
            if threat.confidence < 0.7:
                fp_score += 0.10

        elif isinstance(event, NetworkEvent):
            # Private IP connections are more likely FPs
            try:
                import ipaddress
                addr = ipaddress.ip_address(event.remote_ip)
                if addr.is_private:
                    fp_score += 0.2
            except ValueError:
                pass

        return max(0.0, min(1.0, fp_score))

    def _adjust_severity(
        self, threat: ThreatEvent, event: BaseEvent
    ) -> Severity:
        """
        Upgrade severity based on high-risk contextual signals.

        Rules:
        - Elevated process + CRITICAL category → stay CRITICAL
        - Office app spawning shell → upgrade to CRITICAL if HIGH
        - Signed binary + LOW/MEDIUM → may downgrade
        """
        current = threat.severity

        if isinstance(event, ProcessEvent):
            parent_lower = event.parent_name.lower()
            office_apps = {
                "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"
            }

            # Office spawning shell is always CRITICAL
            if parent_lower in office_apps and current == Severity.HIGH:
                return Severity.CRITICAL

            # Signed Microsoft binary — reduce severity one level
            if event.is_microsoft_signed and current == Severity.MEDIUM:
                return Severity.LOW
            if event.is_microsoft_signed and current == Severity.HIGH:
                return Severity.MEDIUM

        return current

    def get_category_description(self, category: AttackCategory) -> str:
        """Return a human-readable description for an attack category."""
        descriptions = {
            AttackCategory.RANSOMWARE: (
                "Malicious software that encrypts your files and demands "
                "payment to restore them."
            ),
            AttackCategory.C2_COMMUNICATION: (
                "A program on your computer is communicating with an "
                "attacker's remote server to receive commands."
            ),
            AttackCategory.CREDENTIAL_THEFT: (
                "An attempt to steal usernames, passwords, or authentication "
                "tokens from your system."
            ),
            AttackCategory.DATA_EXFILTRATION: (
                "Sensitive data is being copied and sent outside your system "
                "to an attacker-controlled location."
            ),
            AttackCategory.LATERAL_MOVEMENT: (
                "An attacker is attempting to spread from your computer to "
                "other machines on your network."
            ),
            AttackCategory.PRIVILEGE_ESCALATION: (
                "An attacker is attempting to gain higher-level access "
                "permissions on your system."
            ),
            AttackCategory.DEFENSE_EVASION: (
                "An attacker is trying to disable or bypass security tools "
                "to avoid detection."
            ),
            AttackCategory.PERSISTENCE: (
                "Malware is attempting to install itself so it survives "
                "reboots and continues running."
            ),
            AttackCategory.MALWARE_EXECUTION: (
                "Malicious code is being executed on your system."
            ),
            AttackCategory.BRUTE_FORCE: (
                "An automated tool is rapidly guessing passwords to "
                "gain unauthorized access."
            ),
            AttackCategory.RECONNAISSANCE: (
                "An attacker is gathering information about your system "
                "and network to plan an attack."
            ),
            AttackCategory.COLLECTION: (
                "Sensitive files or data are being gathered, likely before "
                "being exfiltrated."
            ),
            AttackCategory.RESOURCE_HIJACKING: (
                "Your computer's resources are being used for the attacker's "
                "benefit (e.g., cryptocurrency mining)."
            ),
            AttackCategory.UNKNOWN: (
                "Suspicious activity detected that doesn't match a specific "
                "known attack pattern."
            ),
        }
        return descriptions.get(category, "Suspicious security event detected.")