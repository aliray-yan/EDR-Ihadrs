"""
Module: classification.heuristic
Purpose: Fast heuristic risk scorer for processes and events.
         Used as a complement to ML classification (always available,
         no training required) and for rapid pre-filtering.
Owner: classification
Dependencies: ihadrs.constants
Performance: Pure arithmetic — sub-millisecond per event.
"""

from __future__ import annotations

from typing import Any

from ihadrs.constants import (
    HIGH_RISK_EXECUTION_PATHS,
    LOLBINS,
    RANSOMWARE_EXTENSIONS,
    SUSPICIOUS_C2_PORTS,
    SUSPICIOUS_EXTENSIONS,
    SYSTEM_PROCESS_NAMES,
)
from ihadrs.models.events import (
    AuthenticationEvent,
    BaseEvent,
    FileEvent,
    NetworkEvent,
    ProcessEvent,
)


class HeuristicScorer:
    """
    Fast heuristic risk scorer for security events.

    Produces a risk_score in [0.0, 1.0] based on a weighted
    checklist of risk indicators. Does NOT require training.

    Used by:
    - Detection engine: pre-filter low-risk events
    - ML classifier: calibrate anomaly threshold
    - API: expose process risk scores
    """

    def score_event(self, event: BaseEvent) -> float:
        """
        Score any event. Returns risk score in [0.0, 1.0].

        0.0 = definitely benign
        1.0 = extremely suspicious
        """
        if isinstance(event, ProcessEvent):
            return self.score_process(event)
        elif isinstance(event, NetworkEvent):
            return self.score_network(event)
        elif isinstance(event, FileEvent):
            return self.score_file(event)
        elif isinstance(event, AuthenticationEvent):
            return self.score_auth(event)
        return 0.0

    def score_process(self, event: ProcessEvent) -> float:
        """Score a process creation event."""
        score = 0.0

        name_lower = event.process_name.lower()
        exe_lower = event.image_path.lower().replace("\\", "/")
        parent_lower = event.parent_name.lower()
        cmd_lower = event.command_line.lower()

        # High-risk execution path (+0.3)
        import os
        for p in HIGH_RISK_EXECUTION_PATHS:
            expanded = os.path.expandvars(p).lower().replace("\\", "/")
            if expanded in exe_lower:
                score += 0.30
                break

        # LOLBin usage (+0.20)
        if name_lower in LOLBINS:
            score += 0.20

        # Encoding/obfuscation in command line (+0.30)
        obfuscation_markers = ["-enc", "-encodedcommand", "frombase64", "::frombase64"]
        if any(m in cmd_lower for m in obfuscation_markers):
            score += 0.30

        # Office app spawning shell (+0.40)
        office_apps = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe"}
        shell_procs = {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
        if parent_lower in office_apps and name_lower in shell_procs:
            score += 0.40

        # Credential dumping keywords (+0.40)
        cred_markers = ["sekurlsa", "mimikatz", "procdump", "lsass"]
        if any(m in cmd_lower for m in cred_markers):
            score += 0.40

        # Privilege elevation (+0.10)
        if event.is_elevated:
            score += 0.10

        # Signed binary (reduces score by 0.15)
        if event.is_microsoft_signed:
            score -= 0.15
        elif event.is_signed:
            score -= 0.08

        # System process (reduces score)
        if name_lower in SYSTEM_PROCESS_NAMES:
            score -= 0.20

        return max(0.0, min(1.0, score))

    def score_network(self, event: NetworkEvent) -> float:
        """Score a network connection event."""
        score = 0.0

        # Suspicious C2 port (+0.30)
        if event.remote_port in SUSPICIOUS_C2_PORTS:
            score += 0.30

        # External connection from unexpected process (+0.10)
        try:
            import ipaddress
            addr = ipaddress.ip_address(event.remote_ip)
            if not addr.is_private and not addr.is_loopback:
                score += 0.10
        except ValueError:
            pass

        # Known malicious IP reputation (+0.50) — placeholder
        # (populated by ThreatIntelligence module in production)
        if event.remote_ip_reputation_score > 0.7:
            score += event.remote_ip_reputation_score * 0.50

        return max(0.0, min(1.0, score))

    def score_file(self, event: FileEvent) -> float:
        """Score a file system event."""
        score = 0.0

        ext_lower = event.file_extension.lower()
        new_ext = event.new_extension.lower()

        # Ransomware extension on renamed file (+0.60)
        if new_ext in RANSOMWARE_EXTENSIONS:
            score += 0.60

        # Executable created in temp/downloads (+0.35)
        path_lower = event.file_path.lower().replace("\\", "/")
        if event.is_executable:
            risk_paths = ["temp", "/tmp", "downloads", "appdata"]
            if any(p in path_lower for p in risk_paths):
                score += 0.35

        # Suspicious extension created (+0.10)
        if ext_lower in SUSPICIOUS_EXTENSIONS:
            score += 0.10

        return max(0.0, min(1.0, score))

    def score_auth(self, event: AuthenticationEvent) -> float:
        """Score an authentication event."""
        if event.success:
            return 0.05  # Successful logins are low risk individually

        # Failed login is mildly suspicious
        score = 0.15

        # Network logon type is higher risk (lateral movement vector)
        if event.logon_type == 3:
            score += 0.10

        return max(0.0, min(1.0, score))

    def get_process_risk_label(self, score: float) -> str:
        """Convert a numeric score to a human-readable risk label."""
        if score >= 0.70:
            return "CRITICAL"
        if score >= 0.50:
            return "HIGH"
        if score >= 0.30:
            return "MEDIUM"
        if score >= 0.10:
            return "LOW"
        return "BENIGN"