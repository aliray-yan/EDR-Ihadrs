"""
Module: models.events
Purpose: Typed dataclass definitions for every event type produced by
         IHADRS monitors. These are the payload objects carried inside
         BusEvent.payload on the event bus.
Owner: models
Dependencies: dataclasses, typing, datetime
Performance: Dataclasses have minimal overhead. __slots__ is used on
             frequently-instantiated classes to reduce memory usage.

Event Hierarchy:
    BaseEvent               Common fields for all events
    ├── ProcessEvent        Process create/terminate/modify
    ├── NetworkEvent        Connection open/close/listen
    ├── FileEvent           File create/modify/delete/rename
    ├── RegistryEvent       Registry key/value changes (Windows)
    ├── ServiceEvent        Windows service changes
    ├── AuthenticationEvent Login success/failure
    └── SystemEvent         USB, shadow copy, defender, USB
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from ihadrs.constants import EventType, MonitorType


# =============================================================================
# BASE EVENT
# =============================================================================

@dataclass
class BaseEvent:
    """
    Common fields shared by all IHADRS domain events.

    Every monitor-produced event embeds these fields. The event_id
    is preserved through the entire pipeline (monitor → bus → detector
    → classifier → response → logger) for full traceability.
    """

    event_type: EventType
    source_monitor: MonitorType
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    hostname: str = ""
    username: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for logging and storage."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "source_monitor": self.source_monitor.value,
            "timestamp": self.timestamp.isoformat(),
            "hostname": self.hostname,
            "username": self.username,
        }


# =============================================================================
# PROCESS EVENTS
# =============================================================================

@dataclass
class ProcessEvent(BaseEvent):
    """
    Emitted when a process is created, terminated, or exhibits anomalous behavior.

    This is the highest-volume event type. Fields are kept minimal to reduce
    memory pressure. Extended context (parent tree, handles) is lazily populated
    by the enrichment pipeline when a detection rule fires.

    Key fields for detection:
        process_name: Used by LOLBin, encoded PowerShell, and parent-child rules
        command_line: Used by encoded PowerShell, mass execution rules
        image_path: Used by execution-from-temp and unsigned binary rules
        parent_name: Used by office-spawning-shell, suspicious-parent-child rules
    """

    # Process identity
    pid: int = 0
    process_name: str = ""
    image_path: str = ""
    command_line: str = ""
    working_directory: str = ""

    # Parent process
    parent_pid: int = 0
    parent_name: str = ""
    parent_image_path: str = ""

    # Resource usage (snapshot at event time)
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    num_threads: int = 0

    # Timing
    create_time: Optional[datetime] = None
    terminate_time: Optional[datetime] = None
    lifetime_seconds: float = 0.0

    # Security context
    integrity_level: str = ""       # Windows: Low, Medium, High, System
    is_elevated: bool = False
    session_id: int = 0
    token_privileges: list[str] = field(default_factory=list)

    # Code signing (Windows)
    is_signed: bool = False
    signature_valid: bool = False
    signer: str = ""
    is_microsoft_signed: bool = False

    # File hashes (populated on-demand by enrichment)
    sha256: str = ""
    md5: str = ""

    # Network connections at the time of event (populated by enrichment)
    active_connections: list[dict[str, Any]] = field(default_factory=list)

    # Children spawned from this process
    child_pids: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update({
            "pid": self.pid,
            "process_name": self.process_name,
            "image_path": self.image_path,
            "command_line": self.command_line,
            "parent_pid": self.parent_pid,
            "parent_name": self.parent_name,
            "cpu_percent": self.cpu_percent,
            "memory_mb": self.memory_mb,
            "is_elevated": self.is_elevated,
            "is_signed": self.is_signed,
            "signer": self.signer,
            "sha256": self.sha256,
        })
        return base


@dataclass
class ProcessInjectionEvent(ProcessEvent):
    """
    Emitted when process injection indicators are detected.

    Used by DLL injection, process hollowing, and reflective loading rules.
    """

    injection_technique: str = ""    # "dll_injection", "process_hollowing", etc.
    source_pid: int = 0              # Injecting process
    target_pid: int = 0              # Victim process
    injected_dll_path: str = ""
    remote_thread_address: int = 0   # Memory address of injected code


# =============================================================================
# NETWORK EVENTS
# =============================================================================

@dataclass
class NetworkEvent(BaseEvent):
    """
    Emitted when a network connection is opened, closed, or a port begins listening.

    Key fields for detection:
        remote_ip / remote_port: Used by C2 beacon and suspicious port rules
        pid / process_name: Associates connection to a process
        protocol: TCP (most malware), UDP (some C2/exfil), RAW
    """

    # Connection details
    local_ip: str = ""
    local_port: int = 0
    remote_ip: str = ""
    remote_port: int = 0
    protocol: str = "tcp"           # "tcp" | "udp" | "raw"
    direction: str = "outbound"     # "inbound" | "outbound" | "listening"
    state: str = ""                 # "ESTABLISHED", "TIME_WAIT", etc.

    # Associated process
    pid: int = 0
    process_name: str = ""
    process_path: str = ""

    # Traffic metrics (for beaconing and exfil detection)
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    connection_duration_seconds: float = 0.0

    # DNS resolution (if available)
    remote_hostname: str = ""

    # Geolocation (populated by enrichment if GeoIP available)
    remote_country: str = ""
    remote_asn: str = ""
    remote_is_tor: bool = False
    remote_is_vpn: bool = False
    remote_is_datacenter: bool = False

    # Threat intelligence
    remote_ip_reputation_score: float = 0.0   # 0.0 = clean, 1.0 = confirmed bad
    remote_ip_threat_categories: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update({
            "pid": self.pid,
            "process_name": self.process_name,
            "local_ip": self.local_ip,
            "local_port": self.local_port,
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "protocol": self.protocol,
            "direction": self.direction,
            "state": self.state,
            "remote_hostname": self.remote_hostname,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
        })
        return base


@dataclass
class NetworkBeaconEvent(NetworkEvent):
    """
    Emitted when C2 beaconing behavior is detected (regular interval connections).

    Produced by the behavioral detector after observing multiple
    NetworkEvents from the same process at regular intervals.
    """

    interval_seconds: float = 0.0       # Average interval between connections
    interval_jitter_pct: float = 0.0    # % variance in interval (low jitter = suspicious)
    observation_window_seconds: int = 0  # How long the pattern was observed
    connection_count: int = 0            # Number of connections in window
    confidence: float = 0.0             # How confident we are this is beaconing


# =============================================================================
# FILE EVENTS
# =============================================================================

@dataclass
class FileEvent(BaseEvent):
    """
    Emitted when a file system change is detected.

    High volume event type — filtered aggressively before being published
    to avoid overwhelming the event bus with routine I/O.

    Key fields for detection:
        file_path: Used by temp-execution, startup-folder, host-file-mod rules
        new_extension: Used by ransomware extension rules
        is_executable: Used by executable-drop rules
        pid: Associates file operations to a process
    """

    # File identity
    file_path: str = ""
    file_name: str = ""
    file_extension: str = ""
    directory: str = ""

    # Change details
    change_type: str = ""           # "created" | "modified" | "deleted" | "renamed"
    old_path: str = ""              # For rename operations
    new_path: str = ""              # For rename operations
    new_extension: str = ""         # The extension AFTER rename

    # File properties
    file_size_bytes: int = 0
    is_executable: bool = False
    is_hidden: bool = False
    is_system: bool = False

    # Code signing (Windows PE files)
    is_signed: bool = False
    signer: str = ""

    # Hashes (populated on-demand to avoid hashing every file change)
    sha256: str = ""
    md5: str = ""

    # Associated process (the process that made this change)
    pid: int = 0
    process_name: str = ""

    # Context for high-volume detection
    operation_count: int = 1        # For batch events, number of ops represented
    is_batch_summary: bool = False  # True if this represents multiple similar ops

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update({
            "file_path": self.file_path,
            "change_type": self.change_type,
            "old_path": self.old_path,
            "new_path": self.new_path,
            "new_extension": self.new_extension,
            "is_executable": self.is_executable,
            "pid": self.pid,
            "process_name": self.process_name,
            "sha256": self.sha256,
            "file_size_bytes": self.file_size_bytes,
        })
        return base


# =============================================================================
# REGISTRY EVENTS (Windows)
# =============================================================================

@dataclass
class RegistryEvent(BaseEvent):
    """
    Emitted when a Windows registry key or value is modified.

    Key fields for detection:
        key_path: Matched against REGISTRY_PERSISTENCE_KEYS constant
        value_name: Specific value being set (e.g., "Run", "Load")
        value_data: The data being written (command/path for persistence)
        hive: HKLM persistence is more impactful than HKCU
    """

    # Key identity
    hive: str = ""                  # "HKLM", "HKCU", "HKCR", "HKU", "HKCC"
    key_path: str = ""              # Registry key path (without hive prefix)
    full_path: str = ""             # hive + key_path

    # Change details
    change_type: str = ""           # "key_created" | "key_deleted" | "value_set" | "value_deleted"
    value_name: str = ""
    value_type: str = ""            # "REG_SZ", "REG_DWORD", "REG_BINARY", etc.
    value_data: str = ""            # String representation of the new value
    old_value_data: str = ""        # Previous value (if available)

    # Associated process
    pid: int = 0
    process_name: str = ""

    # Context flags
    is_persistence_path: bool = False   # True if key_path matches known persistence locations
    is_security_path: bool = False      # True if modifying security/defender settings

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update({
            "hive": self.hive,
            "full_path": self.full_path,
            "change_type": self.change_type,
            "value_name": self.value_name,
            "value_data": self.value_data[:200],  # Truncate long values
            "is_persistence_path": self.is_persistence_path,
            "pid": self.pid,
            "process_name": self.process_name,
        })
        return base


# =============================================================================
# SERVICE EVENTS (Windows)
# =============================================================================

@dataclass
class ServiceEvent(BaseEvent):
    """
    Emitted when a Windows service is created, modified, or changes state.

    Key fields for detection:
        service_path: Execution-from-unusual-path detection
        service_type: Kernel drivers are highest risk
        start_type: Automatic/Boot services = persistence
    """

    service_name: str = ""
    display_name: str = ""
    service_path: str = ""          # Path to the service executable
    service_arguments: str = ""

    change_type: str = ""           # "created" | "deleted" | "modified" | "started" | "stopped"

    # Service configuration
    service_type: str = ""          # "win32_own", "win32_share", "kernel_driver", etc.
    start_type: str = ""            # "auto", "manual", "disabled", "boot", "system"
    service_account: str = ""       # LocalSystem, LocalService, NetworkService, or domain account

    # Previous values (for modification events)
    old_service_path: str = ""
    old_start_type: str = ""

    # Risk indicators
    is_system_path: bool = False    # Executable in expected system paths
    is_signed: bool = False
    signer: str = ""

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update({
            "service_name": self.service_name,
            "service_path": self.service_path,
            "change_type": self.change_type,
            "start_type": self.start_type,
            "service_account": self.service_account,
            "is_signed": self.is_signed,
        })
        return base


# =============================================================================
# AUTHENTICATION EVENTS
# =============================================================================

@dataclass
class AuthenticationEvent(BaseEvent):
    """
    Emitted on Windows logon/logoff and authentication-related events.

    Parsed from Windows Security Event Log (Event IDs 4624, 4625, etc.)

    Key fields for detection:
        success: Failed events for brute-force detection
        logon_type: Network logon (type 3) used by lateral movement
        source_ip: Remote login source for lateral movement
    """

    # Event identity
    windows_event_id: int = 0       # e.g., 4624, 4625

    # Authentication details
    success: bool = True
    logon_type: int = 0             # 2=interactive, 3=network, 10=remote interactive
    logon_type_name: str = ""       # Human-readable logon type

    # Account
    target_username: str = ""
    target_domain: str = ""
    subject_username: str = ""      # Who initiated the logon
    subject_domain: str = ""

    # Source
    source_ip: str = ""
    source_port: int = 0
    workstation_name: str = ""

    # Authentication method
    auth_package: str = ""          # NTLM, Kerberos, etc.
    failure_reason: str = ""        # For failed logons

    # Privilege use
    privileges_granted: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update({
            "windows_event_id": self.windows_event_id,
            "success": self.success,
            "logon_type": self.logon_type,
            "logon_type_name": self.logon_type_name,
            "target_username": self.target_username,
            "source_ip": self.source_ip,
            "auth_package": self.auth_package,
            "failure_reason": self.failure_reason,
        })
        return base


# =============================================================================
# SYSTEM EVENTS
# =============================================================================

@dataclass
class SystemEvent(BaseEvent):
    """
    Emitted for system-level events: USB, shadow copy deletion, Defender changes.

    Catchall for events that don't fit other categories.
    """

    # Generic fields
    subsystem: str = ""             # "usb", "shadowcopy", "defender", "firewall", etc.
    action: str = ""
    description: str = ""

    # USB-specific
    device_name: str = ""
    device_type: str = ""           # "disk", "cdrom", "keyboard", etc.
    drive_letter: str = ""
    volume_name: str = ""
    volume_size_bytes: int = 0

    # Shadow copy deletion
    shadow_copy_id: str = ""
    shadow_copy_volume: str = ""

    # Defender / security product
    security_product_name: str = ""
    feature_disabled: str = ""      # Which Defender feature was disabled

    # Context
    associated_pid: int = 0
    associated_process_name: str = ""

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update({
            "subsystem": self.subsystem,
            "action": self.action,
            "description": self.description,
            "device_name": self.device_name,
            "drive_letter": self.drive_letter,
            "associated_process_name": self.associated_process_name,
        })
        return base


# =============================================================================
# SYNTHETIC / INTERNAL EVENTS
# =============================================================================

@dataclass
class IHADRSInternalEvent(BaseEvent):
    """
    Internal IHADRS lifecycle events (startup, shutdown, component failures).

    Published on the event bus so that the logger and alerter can react to
    IHADRS's own lifecycle without needing direct coupling.
    """

    component: str = ""
    message: str = ""
    level: str = "INFO"             # INFO | WARNING | ERROR | CRITICAL
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        base = super().to_dict()
        base.update({
            "component": self.component,
            "message": self.message,
            "level": self.level,
            "details": self.details,
        })
        return base


# =============================================================================
# EVENT FACTORY
# =============================================================================

def make_process_created_event(
    pid: int,
    name: str,
    image_path: str,
    command_line: str,
    parent_pid: int,
    parent_name: str,
    username: str = "",
    hostname: str = "",
    is_elevated: bool = False,
) -> ProcessEvent:
    """
    Factory for PROCESS_CREATED events.

    Preferred over direct dataclass construction for consistent defaults
    and to decouple callers from the internal field layout.
    """
    return ProcessEvent(
        event_type=EventType.PROCESS_CREATED,
        source_monitor=MonitorType.PROCESS,
        pid=pid,
        process_name=name,
        image_path=image_path,
        command_line=command_line,
        parent_pid=parent_pid,
        parent_name=parent_name,
        username=username,
        hostname=hostname,
        is_elevated=is_elevated,
    )


def make_process_terminated_event(
    pid: int,
    name: str,
    lifetime_seconds: float,
    username: str = "",
    hostname: str = "",
) -> ProcessEvent:
    """Factory for PROCESS_TERMINATED events."""
    return ProcessEvent(
        event_type=EventType.PROCESS_TERMINATED,
        source_monitor=MonitorType.PROCESS,
        pid=pid,
        process_name=name,
        lifetime_seconds=lifetime_seconds,
        username=username,
        hostname=hostname,
    )


def make_network_connection_event(
    pid: int,
    process_name: str,
    local_ip: str,
    local_port: int,
    remote_ip: str,
    remote_port: int,
    protocol: str = "tcp",
    direction: str = "outbound",
    state: str = "ESTABLISHED",
    remote_hostname: str = "",
) -> NetworkEvent:
    """Factory for NETWORK_CONNECTION_OPENED events."""
    return NetworkEvent(
        event_type=EventType.NETWORK_CONNECTION_OPENED,
        source_monitor=MonitorType.NETWORK,
        pid=pid,
        process_name=process_name,
        local_ip=local_ip,
        local_port=local_port,
        remote_ip=remote_ip,
        remote_port=remote_port,
        protocol=protocol,
        direction=direction,
        state=state,
        remote_hostname=remote_hostname,
    )


def make_file_event(
    file_path: str,
    change_type: str,
    pid: int = 0,
    process_name: str = "",
    old_path: str = "",
    new_path: str = "",
) -> FileEvent:
    """Factory for file system events."""
    import os
    import ntpath
    import posixpath

    # Use ntpath for Windows-style paths (containing backslash or drive letter),
    # posixpath otherwise — ensures correct parsing on both platforms.
    if "\\" in file_path or (len(file_path) > 1 and file_path[1] == ":"):
        _basename = ntpath.basename
        _dirname = ntpath.dirname
        _splitext = ntpath.splitext
    else:
        _basename = posixpath.basename
        _dirname = posixpath.dirname
        _splitext = posixpath.splitext

    name = _basename(file_path)
    ext = _splitext(name)[1].lower()
    directory = _dirname(file_path)
    new_ext = _splitext(_basename(new_path))[1].lower() if new_path else ""

    type_map = {
        "created": EventType.FILE_CREATED,
        "modified": EventType.FILE_MODIFIED,
        "deleted": EventType.FILE_DELETED,
        "renamed": EventType.FILE_RENAMED,
    }
    event_type = type_map.get(change_type, EventType.FILE_MODIFIED)

    return FileEvent(
        event_type=event_type,
        source_monitor=MonitorType.FILE,
        file_path=file_path,
        file_name=name,
        file_extension=ext,
        directory=directory,
        change_type=change_type,
        old_path=old_path,
        new_path=new_path,
        new_extension=new_ext,
        pid=pid,
        process_name=process_name,
        is_executable=ext in {".exe", ".dll", ".sys", ".scr", ".com", ".pif"},
    )


def make_registry_event(
    hive: str,
    key_path: str,
    change_type: str,
    value_name: str = "",
    value_data: str = "",
    pid: int = 0,
    process_name: str = "",
) -> RegistryEvent:
    """Factory for Windows registry events."""
    from ihadrs.constants import REGISTRY_PERSISTENCE_KEYS

    full_path = f"{hive}\\{key_path}"
    is_persistence = any(
        pk.lower() in key_path.lower()
        for pk in REGISTRY_PERSISTENCE_KEYS
    )

    type_map = {
        "key_created": EventType.REGISTRY_KEY_CREATED,
        "key_deleted": EventType.REGISTRY_KEY_DELETED,
        "value_set": EventType.REGISTRY_VALUE_SET,
        "value_deleted": EventType.REGISTRY_VALUE_DELETED,
    }
    event_type = type_map.get(change_type, EventType.REGISTRY_VALUE_SET)

    return RegistryEvent(
        event_type=event_type,
        source_monitor=MonitorType.REGISTRY,
        hive=hive,
        key_path=key_path,
        full_path=full_path,
        change_type=change_type,
        value_name=value_name,
        value_data=value_data,
        pid=pid,
        process_name=process_name,
        is_persistence_path=is_persistence,
    )