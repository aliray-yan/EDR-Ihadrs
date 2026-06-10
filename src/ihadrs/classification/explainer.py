"""
Module: classification.explainer
Purpose: Generates human-readable threat explanations and educational content
         from ThreatEvent data. Produces both user-friendly (non-technical)
         and analyst-level (technical) explanations.
Owner: classification
Dependencies: ihadrs.constants, ihadrs.models
Performance: Pure string formatting — negligible overhead.
"""

from __future__ import annotations

from typing import Any

from ihadrs.constants import AttackCategory, Severity
from ihadrs.models.threats import RemediationStep, ThreatEvent


class ThreatExplainer:
    """
    Generates structured explanations for threat events.

    Takes a ThreatEvent and enriches its explanation fields with:
    - user_explanation:    Plain English, no security jargon
    - technical_details:   Full technical context for analysts
    - educational_content: What this attack is and how to prevent it
    - prevention_tips:     Proactive measures the user can take

    The explainer is called after the detection engine and classifier
    have enriched the ThreatEvent with MITRE context, severity, and
    affected resource information.
    """

    def explain(self, threat: ThreatEvent) -> ThreatEvent:
        """
        Fill in explanation fields on a ThreatEvent.

        Only overwrites fields that are empty — preserves any
        explanations already set by the detection rules.

        Args:
            threat: The ThreatEvent to explain.

        Returns:
            The same ThreatEvent with explanation fields populated.
        """
        # Fill user explanation if empty
        if not threat.user_explanation:
            threat.user_explanation = self._build_user_explanation(threat)

        # Fill technical details if empty
        if not threat.technical_details:
            threat.technical_details = self._build_technical_details(threat)

        # Fill summary if empty
        if not threat.summary:
            threat.summary = self._build_summary(threat)

        # Always enrich educational content and prevention tips
        if not threat.educational_content:
            threat.educational_content = self._get_educational_content(
                threat.attack_category
            )

        if not threat.prevention_tips:
            threat.prevention_tips = self._get_prevention_tips(
                threat.attack_category
            )

        return threat

    # =========================================================================
    # Summary
    # =========================================================================

    def _build_summary(self, threat: ThreatEvent) -> str:
        """One-line summary suitable for notification titles and list views."""
        category = threat.attack_category.value
        resource = threat.affected_resource.split(":")[1] if ":" in threat.affected_resource else threat.affected_resource
        technique = threat.primary_technique_name or threat.primary_technique
        if technique:
            return f"{category}: {technique} detected on {resource}"
        return f"{category} detected: {resource}"

    # =========================================================================
    # User Explanation
    # =========================================================================

    def _build_user_explanation(self, threat: ThreatEvent) -> str:
        """
        Plain-English explanation for non-technical users.

        Avoids jargon. Focuses on what happened and why it matters.
        """
        category = threat.attack_category
        resource = threat.affected_resource
        severity = threat.severity

        templates: dict[AttackCategory, str] = {
            AttackCategory.RANSOMWARE: (
                "A program is rapidly encrypting your files — this is "
                "ransomware behavior. Your files may be held hostage unless "
                "you pay a ransom. IHADRS has attempted to stop the process. "
                "Do NOT restart your computer."
            ),
            AttackCategory.C2_COMMUNICATION: (
                "A program on your computer is regularly contacting an "
                "external server at precise intervals. This is the behavior "
                "of malware checking in with an attacker for instructions. "
                "Your computer may be under attacker control."
            ),
            AttackCategory.CREDENTIAL_THEFT: (
                "A program tried to steal your passwords and login credentials "
                "from Windows memory. If this succeeded, all passwords stored "
                "on this computer should be considered compromised."
            ),
            AttackCategory.DATA_EXFILTRATION: (
                "Files or data may be leaving your computer without your "
                "knowledge. An attacker may be copying sensitive information "
                "to a server they control."
            ),
            AttackCategory.LATERAL_MOVEMENT: (
                "Something on your computer is trying to connect to other "
                "computers on your network using tools commonly used by "
                "attackers. This could spread an infection."
            ),
            AttackCategory.PRIVILEGE_ESCALATION: (
                "A program attempted to gain higher-level access on your "
                "computer. This is often done by attackers to take full "
                "control of a system."
            ),
            AttackCategory.DEFENSE_EVASION: (
                "A program attempted to disable or bypass security software "
                "on your computer. Attackers do this to avoid being detected "
                "while carrying out their attack."
            ),
            AttackCategory.PERSISTENCE: (
                "A program installed itself to automatically start whenever "
                "Windows starts. This is how malware survives reboots and "
                "remains on your system."
            ),
            AttackCategory.MALWARE_EXECUTION: (
                "Suspicious code was detected running on your computer. "
                "This may be malware attempting to execute commands or "
                "download additional malicious software."
            ),
            AttackCategory.BRUTE_FORCE: (
                "Multiple failed login attempts were detected from the same "
                "source. An automated tool may be guessing your password. "
                "If successful, your account could be compromised."
            ),
            AttackCategory.COLLECTION: (
                "A large number of files were accessed in a short time. "
                "This behavior is consistent with an attacker collecting "
                "your data before sending it out."
            ),
            AttackCategory.RESOURCE_HIJACKING: (
                "A program is using an unusually high amount of your "
                "computer's resources. This may be cryptocurrency mining "
                "malware using your hardware without your consent."
            ),
        }

        base = templates.get(
            category,
            f"Suspicious {category.value.lower()} activity was detected on your system. "
            f"Review the technical details and follow the remediation steps."
        )

        # Add severity context
        if severity == Severity.CRITICAL:
            prefix = "⚠️ CRITICAL: "
        elif severity == Severity.HIGH:
            prefix = "🚨 "
        else:
            prefix = ""

        return prefix + base

    # =========================================================================
    # Technical Details
    # =========================================================================

    def _build_technical_details(self, threat: ThreatEvent) -> str:
        """Technical explanation for security analysts."""
        parts: list[str] = []

        # Detection source
        rules_str = ", ".join(threat.evidence.triggered_rule_ids[:5])
        parts.append(f"Triggered rules: {rules_str}")

        # MITRE context
        if threat.mitre_techniques:
            techniques = ", ".join(
                f"{tid} ({name})" for tid, name in
                zip(threat.mitre_techniques[:3], threat.mitre_technique_names[:3])
            )
            parts.append(f"MITRE ATT&CK: {techniques}")

        # Process context
        if threat.process_context:
            pc = threat.process_context
            parts.append(
                f"Process: {pc.name} (PID {pc.pid}), "
                f"Parent: {pc.parent_name} (PID {pc.parent_pid})"
            )
            if pc.command_line:
                cmd_preview = pc.command_line[:120]
                parts.append(f"Command: {cmd_preview}")
            if pc.is_elevated:
                parts.append("Elevation: Process is running with elevated privileges")
            if pc.sha256:
                parts.append(f"SHA256: {pc.sha256}")

        # Confidence and FP assessment
        fp_pct = f"{threat.false_positive_likelihood:.0%}"
        parts.append(
            f"Confidence: {threat.confidence:.0%} | "
            f"FP likelihood: {fp_pct}"
        )

        # Affected resource
        parts.append(f"Affected resource: {threat.affected_resource}")

        return "\n".join(parts)

    # =========================================================================
    # Educational Content
    # =========================================================================

    def _get_educational_content(self, category: AttackCategory) -> str:
        """Return educational content about the attack category."""
        content: dict[AttackCategory, str] = {
            AttackCategory.RANSOMWARE: (
                "Ransomware encrypts your files using strong cryptography and demands "
                "payment (usually Bitcoin) for the decryption key. Modern ransomware "
                "often exfiltrates data before encrypting, threatening to publish it "
                "if you don't pay (double extortion). Notable examples: WannaCry (2017), "
                "NotPetya (2017), LockBit (2022-present). "
                "Prevention: maintain offline backups, keep software updated, "
                "don't open email attachments from unknown senders. "
                "Resources: https://www.nomoreransom.org — free decryptors for many families."
            ),
            AttackCategory.C2_COMMUNICATION: (
                "Command and Control (C2) is how malware receives instructions from "
                "attackers. The malware 'beacons' — makes regular connections to the "
                "attacker's server — to check for commands, upload stolen data, or "
                "download additional payloads. Regular timing with low jitter is the "
                "telltale sign. Common C2 frameworks: Cobalt Strike, Metasploit, Empire. "
                "ATT&CK reference: https://attack.mitre.org/tactics/TA0011/"
            ),
            AttackCategory.CREDENTIAL_THEFT: (
                "Attackers steal credentials to move laterally and escalate privileges. "
                "Windows stores password hashes and plaintext credentials in LSASS memory. "
                "Tools like Mimikatz can extract these. Once credentials are stolen, "
                "attackers can impersonate users across the entire network. "
                "Mitigation: enable Windows Credential Guard, use LAPS for local admin "
                "passwords, enable MFA on all accounts. "
                "ATT&CK reference: https://attack.mitre.org/tactics/TA0006/"
            ),
            AttackCategory.MALWARE_EXECUTION: (
                "Initial execution is often achieved through phishing documents, "
                "drive-by downloads, or exploiting software vulnerabilities. "
                "Attackers use Living-off-the-Land (LOLBin) techniques to execute "
                "code using trusted Windows binaries to evade detection. "
                "ATT&CK reference: https://attack.mitre.org/tactics/TA0002/"
            ),
            AttackCategory.PERSISTENCE: (
                "Persistence ensures malware survives reboots. Common methods include "
                "registry Run keys, scheduled tasks, Windows services, and startup folders. "
                "More sophisticated: WMI subscriptions, DLL hijacking, boot sectors. "
                "Audit: use Autoruns (Sysinternals) to enumerate all persistence mechanisms. "
                "ATT&CK reference: https://attack.mitre.org/tactics/TA0003/"
            ),
            AttackCategory.BRUTE_FORCE: (
                "Brute force attacks systematically try password combinations. "
                "Password spraying tries one common password across many accounts "
                "to avoid lockouts. Credential stuffing uses leaked password databases. "
                "Mitigation: enforce account lockout policies, use MFA, monitor "
                "authentication logs for failure spikes. "
                "ATT&CK reference: https://attack.mitre.org/techniques/T1110/"
            ),
        }
        return content.get(
            category,
            f"Learn more about {category.value}: "
            f"https://attack.mitre.org/tactics/"
        )

    # =========================================================================
    # Prevention Tips
    # =========================================================================

    def _get_prevention_tips(self, category: AttackCategory) -> list[str]:
        """Return actionable prevention tips for the attack category."""
        tips: dict[AttackCategory, list[str]] = {
            AttackCategory.RANSOMWARE: [
                "Keep regular offline backups (disconnected from your computer)",
                "Enable Windows Defender Controlled Folder Access",
                "Never open email attachments from unknown senders",
                "Keep Windows and all software updated",
                "Consider ransomware-specific backup solutions with versioning",
            ],
            AttackCategory.C2_COMMUNICATION: [
                "Use a next-generation firewall with application-layer inspection",
                "Monitor outbound traffic for unusual beaconing patterns",
                "Implement DNS filtering to block known malicious domains",
                "Use endpoint detection and response (EDR) software",
                "Segment your network to limit blast radius",
            ],
            AttackCategory.CREDENTIAL_THEFT: [
                "Enable Windows Credential Guard (Windows 10+ Enterprise)",
                "Use multi-factor authentication on all accounts",
                "Use a password manager with unique passwords per site",
                "Enable Protected Users security group in Active Directory",
                "Regularly audit privileged accounts and remove unnecessary access",
            ],
            AttackCategory.MALWARE_EXECUTION: [
                "Keep Windows and all applications updated",
                "Use application whitelisting (Windows Defender Application Control)",
                "Don't open attachments or click links in unexpected emails",
                "Download software only from official sources",
                "Run with standard user privileges, not administrator",
            ],
            AttackCategory.PERSISTENCE: [
                "Regularly review autostart entries with Sysinternals Autoruns",
                "Monitor registry Run keys with a file integrity monitoring tool",
                "Use Windows Defender to detect persistence mechanisms",
                "Audit scheduled tasks and Windows services regularly",
                "Apply principle of least privilege — limit who can install services",
            ],
            AttackCategory.BRUTE_FORCE: [
                "Enable account lockout policies (5 failures → 15min lockout)",
                "Use multi-factor authentication on all external-facing services",
                "Disable or rename default administrator accounts",
                "Use strong, unique passwords (minimum 16 characters)",
                "Block brute force sources with your firewall",
            ],
        }
        return tips.get(category, [
            "Keep your operating system and software updated",
            "Use multi-factor authentication where possible",
            "Maintain regular backups of important data",
            "Be cautious with email attachments and downloads",
        ])