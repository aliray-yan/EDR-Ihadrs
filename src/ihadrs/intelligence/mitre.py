"""
Module: intelligence.mitre
Purpose: MITRE ATT&CK framework integration — technique name resolution,
         tactic lookup, and threat enrichment. Loads from config/mitre_mapping.yaml.
Owner: intelligence
Dependencies: PyYAML
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

import yaml
from loguru import logger


class MITREMapper:
    """
    Singleton-style MITRE ATT&CK technique/tactic mapper.

    Loaded once from config/mitre_mapping.yaml on first access.
    All methods are class methods — no instantiation needed.
    """

    _techniques: dict[str, dict[str, Any]] = {}
    _tactics: dict[str, str] = {}
    _loaded: bool = False
    _mapping_path: Path = Path("config/mitre_mapping.yaml")

    @classmethod
    def _ensure_loaded(cls) -> None:
        if cls._loaded:
            return

        if not cls._mapping_path.exists():
            logger.debug(
                "MITRE mapping file not found: {p}. Using empty mapping.",
                p=cls._mapping_path,
            )
            cls._loaded = True
            return

        try:
            with cls._mapping_path.open("r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            for tactic_id, tactic_info in (data.get("tactics") or {}).items():
                cls._tactics[tactic_id] = tactic_info.get("name", tactic_id)

            for technique_id, tech_info in (data.get("techniques") or {}).items():
                cls._techniques[technique_id] = tech_info
                # Load subtechniques
                for sub_id, sub_info in (tech_info.get("subtechniques") or {}).items():
                    cls._techniques[sub_id] = sub_info

            cls._loaded = True
            logger.debug(
                "MITRE mapping loaded: {t} techniques, {tac} tactics.",
                t=len(cls._techniques),
                tac=len(cls._tactics),
            )
        except Exception as exc:
            logger.warning(
                "Failed to load MITRE mapping: {exc}. Using empty mapping.", exc=exc
            )
            cls._loaded = True

    @classmethod
    def get_technique_name(cls, technique_id: str) -> str:
        """Return the human-readable name for a MITRE technique ID."""
        cls._ensure_loaded()
        info = cls._techniques.get(technique_id)
        return info.get("name", technique_id) if info else technique_id

    @classmethod
    def get_technique_names(cls, technique_ids: list[str]) -> list[str]:
        """Return names for a list of technique IDs."""
        return [cls.get_technique_name(tid) for tid in technique_ids]

    @classmethod
    def get_tactic_name(cls, tactic_id: str) -> str:
        """Return the human-readable name for a MITRE tactic ID."""
        cls._ensure_loaded()
        # Try loaded mapping first, fall back to constants
        from ihadrs.constants import MITRE_TACTICS
        return cls._tactics.get(tactic_id) or MITRE_TACTICS.get(tactic_id, tactic_id)

    @classmethod
    def get_technique_info(cls, technique_id: str) -> dict[str, Any]:
        """Return the full metadata dict for a technique ID."""
        cls._ensure_loaded()
        return cls._techniques.get(technique_id) or {}

    @classmethod
    def get_technique_severity_hint(cls, technique_id: str) -> Optional[str]:
        """Return the severity hint for a technique, or None if not defined."""
        info = cls.get_technique_info(technique_id)
        return info.get("severity_hint")

    @classmethod
    def get_technique_url(cls, technique_id: str) -> str:
        """Return the ATT&CK URL for a technique."""
        info = cls.get_technique_info(technique_id)
        return info.get("url", f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/")

    @classmethod
    def reload(cls, mapping_path: Optional[Path] = None) -> None:
        """Force reload of the MITRE mapping from disk."""
        if mapping_path:
            cls._mapping_path = mapping_path
        cls._loaded = False
        cls._techniques.clear()
        cls._tactics.clear()
        cls._ensure_loaded()