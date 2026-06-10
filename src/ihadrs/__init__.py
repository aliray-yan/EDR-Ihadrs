"""
IHADRS — Intelligent Host-Based Attack Detection and Response System
====================================================================

A lightweight, standalone, Python-based Host Intrusion Detection and
Response System (HIDS/EDR) for individual users and small teams.

Key Features:
    - Real-time process, network, file, and registry monitoring
    - 30+ MITRE ATT&CK-mapped detection rules
    - Machine learning anomaly detection (Isolation Forest)
    - Automated and guided response with rollback capability
    - Human-readable threat explanations with remediation steps
    - PyQt6 dashboard and REST API

Quick Start:
    # Run from terminal (requires Administrator on Windows):
    python -m ihadrs start

    # Train ML baseline model:
    python -m ihadrs train

    # Launch dashboard:
    python -m ihadrs ui

Platform Support:
    Primary:   Windows 10 21H2+, Windows 11
    Secondary: Ubuntu 22.04+ (core features only)
    Requires:  Python 3.11+, Administrator/root privileges

Architecture:
    Monitors (sensors) → Event Bus → Detection Engine →
    Classification → Response System → Alerting

Documentation:
    https://ihadrs.readthedocs.io

License:
    MIT — see LICENSE file for details.
"""

from __future__ import annotations

# Package version — single source of truth.
# Updated here and in pyproject.toml (both must match).
__version__: str = "0.1.0"
__version_info__: tuple[int, int, int] = (0, 1, 0)

__author__: str = "IHADRS Team"
__license__: str = "MIT"
__url__: str = "https://github.com/ihadrs/ihadrs"

# Minimum Python version required
__python_requires__: str = ">=3.11"

# =============================================================================
# PUBLIC API — what ``from ihadrs import *`` exposes
# =============================================================================
# Keep this minimal. Consumers should import from submodules directly
# for anything beyond these top-level conveniences.

from ihadrs.constants import (
    APP_NAME,
    APP_VERSION,
    AttackCategory,
    EventType,
    MonitorType,
    Severity,
)
from ihadrs.exceptions import IHADRSError

__all__: list[str] = [
    # Version
    "__version__",
    "__version_info__",
    # Top-level enums most consumers need
    "Severity",
    "EventType",
    "MonitorType",
    "AttackCategory",
    # Base exception
    "IHADRSError",
    # Metadata
    "APP_NAME",
    "APP_VERSION",
]