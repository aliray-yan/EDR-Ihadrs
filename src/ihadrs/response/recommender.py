"""
Module: response.recommender
Purpose: Generates ordered, contextual remediation plans for detected threats.
         Combines playbook-defined steps with dynamic context from the ThreatEvent
         to produce actionable, human-readable remediation guidance.
Owner: response
Dependencies: PyYAML, ihadrs.models, ihadrs.constants
Performance: Pure dict/string operations. <1ms per recommendation.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

import yaml
from loguru import logger

from ihadrs.constants import AttackCategory
from ihadrs.models.threats import RemediationStep, ThreatEvent


class RemediationRecommender:
    """
    Generates ordered remediation plans for detected threats.

    Sources:
    1. Playbooks (config/playbooks.yaml) — pre-defined steps per attack category
    2. Detection rule definitions — rule-specific manual_steps
    3. Dynamic context — interpolated from the ThreatEvent fields

    Output is a list of RemediationStep objects, ordered:
        immediate → investigation → remediation → prevention
    """

    _CATEGORY_ORDER = ["immediate", "investigation", "remediation", "prevention"]

    def __init__(self, playbooks_file: Optional[Path] = None) -> None:
        self._playbooks: dict[str, dict[str, Any]] = {}
        pb_path = playbooks_file or Path("config/playbooks.yaml")
        self._load_playbooks(pb_path)

    def _load_playbooks(self, path: Path) -> None:
        """Load playbooks from YAML. Silently continue if file not found."""
        if not path.exists():
            logger.debug("Playbooks file not found: {p}", p=path)
            return
        try:
            with path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            for pb in data.get("playbooks", []):
                cat = pb.get("attack_category", "")
                if cat:
                    self._playbooks[cat] = pb
            logger.debug(
                "Loaded {n} response playbooks.", n=len(self._playbooks)
            )
        except Exception as exc:
            logger.warning("Could not load playbooks: {exc}", exc=exc)

    def generate(self, threat: ThreatEvent) -> list[RemediationStep]:
        """
        Generate an ordered remediation plan for a ThreatEvent.

        Args:
            threat: The detected ThreatEvent with full context.

        Returns:
            Ordered list of RemediationStep objects.
        """
        ctx = self._build_context(threat)
        steps: list[tuple[str, str, str]] = []  # (category, description, command)

        # 1. Pull steps from playbook
        playbook = self._playbooks.get(threat.attack_category.value)
        if playbook:
            steps.extend(self._extract_playbook_steps(playbook, ctx))

        # 2. If no playbook, use default steps
        if not steps:
            steps.extend(self._default_steps(threat, ctx))

        # 3. Sort by category order
        category_rank = {c: i for i, c in enumerate(self._CATEGORY_ORDER)}
        steps.sort(key=lambda s: category_rank.get(s[0], 99))

        # 4. Convert to RemediationStep objects
        return [
            RemediationStep(
                step_number=i + 1,
                category=cat,
                description=self._interpolate(desc, ctx),
                command=self._interpolate(cmd, ctx),
            )
            for i, (cat, desc, cmd) in enumerate(steps)
        ]

    def _extract_playbook_steps(
        self,
        playbook: dict[str, Any],
        ctx: dict[str, Any],
    ) -> list[tuple[str, str, str]]:
        """Extract steps from a playbook entry."""
        steps: list[tuple[str, str, str]] = []
        for section in playbook.get("manual_steps", []):
            category = section.get("category", "investigation")
            for step_text in section.get("steps", []):
                command = ""
                # Extract command if line looks like a shell command
                if any(
                    kw in step_text
                    for kw in ["taskkill", "sc ", "net ", "MpCmd", "vssadmin",
                               "schtasks", "reg ", "netstat", "Get-", "Set-"]
                ):
                    command = step_text.strip()
                steps.append((category, step_text, command))
        return steps

    def _default_steps(
        self,
        threat: ThreatEvent,
        ctx: dict[str, Any],
    ) -> list[tuple[str, str, str]]:
        """Generate fallback steps when no playbook is available."""
        return [
            ("immediate", "Review the event details in IHADRS", ""),
            ("immediate", f"Check the affected resource: {threat.affected_resource}", ""),
            ("investigation",
             f"Investigate: {ctx.get('process_name', 'the affected process')}",
             ""),
            ("investigation",
             "Search the file hash on VirusTotal: https://www.virustotal.com",
             ""),
            ("remediation",
             "Run a full Windows Defender scan",
             "MpCmdRun.exe -Scan -ScanType 2"),
            ("remediation",
             "Check for persistence: review startup entries with Autoruns",
             ""),
            ("prevention", "Keep Windows and all software updated", ""),
            ("prevention",
             "Enable multi-factor authentication on important accounts", ""),
        ]

    def _build_context(self, threat: ThreatEvent) -> dict[str, Any]:
        """Build template variable context from a ThreatEvent."""
        ctx: dict[str, Any] = {
            "threat_id": threat.threat_id,
            "severity": threat.severity.value,
            "attack_category": threat.attack_category.value,
            "affected_resource": threat.affected_resource,
            "hostname": threat.hostname,
            "username": threat.username,
            "event_timestamp": threat.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            if threat.timestamp else "",
        }
        if threat.process_context:
            pc = threat.process_context
            ctx.update({
                "process_name": pc.name,
                "pid": pc.pid,
                "image_path": pc.image_path,
                "command_line": pc.command_line,
                "parent_name": pc.parent_name,
                "parent_pid": pc.parent_pid,
                "username": pc.username or threat.username,
                "is_elevated": pc.is_elevated,
            })
        if threat.network_context:
            nc = threat.network_context
            remote_ips = nc.unique_remote_ips
            ctx["remote_ip"] = remote_ips[0] if remote_ips else ""
            ctx["c2_ip"] = ctx["remote_ip"]
        return ctx

    @staticmethod
    def _interpolate(template: str, context: dict[str, Any]) -> str:
        """Replace {variable} placeholders with context values."""
        if not template:
            return ""
        from collections import defaultdict
        try:
            return template.format_map(defaultdict(lambda: "?", context))
        except Exception:
            return template