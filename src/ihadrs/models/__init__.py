"""
Package: models
Purpose: Domain data models for IHADRS — events, threats, and telemetry.
         All dataclasses and typed structures live here.
"""

from __future__ import annotations

from ihadrs.models.events import (
    AuthenticationEvent,
    BaseEvent,
    FileEvent,
    IHADRSInternalEvent,
    NetworkBeaconEvent,
    NetworkEvent,
    ProcessEvent,
    ProcessInjectionEvent,
    RegistryEvent,
    ServiceEvent,
    SystemEvent,
    make_file_event,
    make_network_connection_event,
    make_process_created_event,
    make_process_terminated_event,
    make_registry_event,
)
from ihadrs.models.threats import (
    AutomatedActionRecord,
    FileContext,
    NetworkContext,
    ProcessContext,
    RemediationStep,
    ThreatEvent,
    ThreatEvidence,
)

__all__ = [
    # Events
    "BaseEvent",
    "ProcessEvent",
    "ProcessInjectionEvent",
    "NetworkEvent",
    "NetworkBeaconEvent",
    "FileEvent",
    "RegistryEvent",
    "ServiceEvent",
    "AuthenticationEvent",
    "SystemEvent",
    "IHADRSInternalEvent",
    # Event factories
    "make_process_created_event",
    "make_process_terminated_event",
    "make_network_connection_event",
    "make_file_event",
    "make_registry_event",
    # Threats
    "ThreatEvent",
    "ThreatEvidence",
    "ProcessContext",
    "NetworkContext",
    "FileContext",
    "RemediationStep",
    "AutomatedActionRecord",
]