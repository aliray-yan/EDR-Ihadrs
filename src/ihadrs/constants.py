"""
Module: constants
Purpose: Global constants, enumerations, and type aliases for IHADRS.
         This is the single source of truth — import from here, never
         redefine values in other modules.
Owner: core
Dependencies: enum, typing, sys
Performance: Zero runtime cost — all values resolved at import time.
"""

from __future__ import annotations

import sys
from enum import Enum, IntEnum, auto, unique
from typing import Final, Literal

# =============================================================================
# PLATFORM DETECTION
# =============================================================================

IS_WINDOWS: Final[bool] = sys.platform == "win32"
IS_LINUX: Final[bool] = sys.platform.startswith("linux")
IS_MACOS: Final[bool] = sys.platform == "darwin"

PLATFORM: Final[Literal["windows", "linux", "macos", "unknown"]] = (
    "windows"
    if IS_WINDOWS
    else "linux"
    if IS_LINUX
    else "macos"
    if IS_MACOS
    else "unknown"
)

# =============================================================================
# APPLICATION METADATA
# =============================================================================

APP_NAME: Final[str] = "IHADRS"
APP_FULL_NAME: Final[str] = "Intelligent Host-Based Attack Detection and Response System"
APP_VERSION: Final[str] = "0.1.0"
APP_AUTHOR: Final[str] = "IHADRS Team"
APP_LICENSE: Final[str] = "MIT"
APP_URL: Final[str] = "https://github.com/ihadrs/ihadrs"

# Internal identifiers used in logs and event sources
APP_PROCESS_NAME: Final[str] = "ihadrs"
APP_SERVICE_NAME: Final[str] = "IHADRSService"
APP_SERVICE_DISPLAY_NAME: Final[str] = "IHADRS - Host Intrusion Detection"

# =============================================================================
# PERFORMANCE BUDGETS
# These values are enforced by resource_manager.py at runtime.
# =============================================================================

# CPU budget
CPU_BUDGET_AVERAGE_PCT: Final[float] = 3.0   # ≤3% average
CPU_BUDGET_PEAK_PCT: Final[float] = 15.0      # ≤15% peak (10s burst)
CPU_PEAK_WINDOW_SECONDS: Final[int] = 10

# Memory budget
RAM_BUDGET_BASELINE_MB: Final[int] = 80       # ≤80MB baseline
RAM_BUDGET_MAX_MB: Final[int] = 200           # ≤200MB under load

# Disk I/O budget
DISK_IO_BUDGET_WRITE_MBS: Final[float] = 5.0  # ≤5MB/s write

# Startup
STARTUP_TIMEOUT_SECONDS: Final[int] = 5       # ≤5s to operational

# Detection
DETECTION_LATENCY_TARGET_SECONDS: Final[float] = 2.0  # ≤2s event → alert

# False positives
FALSE_POSITIVE_RATE_TARGET: Final[float] = 0.05  # ≤5%

# =============================================================================
# EVENT BUS
# =============================================================================

# Maximum size of the internal event queue before backpressure is applied
EVENT_QUEUE_SIZE: Final[int] = 10_000

# Maximum events processed per second across all monitors combined
MAX_EVENTS_PER_SECOND: Final[int] = 1_000

# Maximum events that can be dispatched to a single subscriber per second
MAX_SUBSCRIBER_EVENTS_PER_SECOND: Final[int] = 500

# Event expiry — events older than this are dropped from backlog
EVENT_MAX_AGE_SECONDS: Final[int] = 300  # 5 minutes

# Publisher timeout — if a monitor hangs publishing, it's killed after this
PUBLISHER_TIMEOUT_SECONDS: Final[float] = 5.0

# =============================================================================
# SEVERITY LEVELS
# =============================================================================

@unique
class Severity(str, Enum):
    """
    Threat severity levels, ordered from least to most severe.

    Used throughout detection, alerting, and response systems.
    String values match MITRE ATT&CK and common SIEM conventions.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __lt__(self, other: Severity) -> bool:
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other: Severity) -> bool:
        return self == other or self < other

    def __gt__(self, other: Severity) -> bool:
        return not self <= other

    def __ge__(self, other: Severity) -> bool:
        return self == other or self > other

    @property
    def numeric(self) -> int:
        """Numeric representation for comparison and ML features."""
        return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]

    @property
    def color_ansi(self) -> str:
        """ANSI color code for terminal output."""
        return {
            "LOW": "\033[32m",      # Green
            "MEDIUM": "\033[33m",   # Yellow
            "HIGH": "\033[91m",     # Bright Red
            "CRITICAL": "\033[31m", # Red (bold)
        }[self.value]

    @property
    def color_hex(self) -> str:
        """Hex color for UI/web rendering."""
        return {
            "LOW": "#28a745",
            "MEDIUM": "#ffc107",
            "HIGH": "#fd7e14",
            "CRITICAL": "#dc3545",
        }[self.value]

    @property
    def rich_markup(self) -> str:
        """Rich library color name for console output."""
        return {
            "LOW": "green",
            "MEDIUM": "yellow",
            "HIGH": "orange3",
            "CRITICAL": "red",
        }[self.value]

    @property
    def icon(self) -> str:
        """Unicode icon for display."""
        return {
            "LOW": "🟢",
            "MEDIUM": "🟡",
            "HIGH": "🟠",
            "CRITICAL": "🔴",
        }[self.value]


# =============================================================================
# ATTACK CATEGORIES
# =============================================================================

@unique
class AttackCategory(str, Enum):
    """
    High-level attack classification taxonomy.

    Maps to MITRE ATT&CK tactics at a coarser granularity for
    user-facing display and response playbook selection.
    """

    RANSOMWARE = "Ransomware"
    C2_COMMUNICATION = "Command & Control"
    CREDENTIAL_THEFT = "Credential Theft"
    DATA_EXFILTRATION = "Data Exfiltration"
    LATERAL_MOVEMENT = "Lateral Movement"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    PERSISTENCE = "Persistence"
    MALWARE_EXECUTION = "Malware Execution"
    BRUTE_FORCE = "Brute Force Attack"
    RECONNAISSANCE = "Reconnaissance"
    IMPACT = "System Impact"
    COLLECTION = "Data Collection"
    RESOURCE_HIJACKING = "Resource Hijacking"
    UNKNOWN = "Unknown/Uncategorized"

    @property
    def icon(self) -> str:
        """Unicode icon for UI display."""
        return {
            AttackCategory.RANSOMWARE: "🔒",
            AttackCategory.C2_COMMUNICATION: "📡",
            AttackCategory.CREDENTIAL_THEFT: "🔑",
            AttackCategory.DATA_EXFILTRATION: "📤",
            AttackCategory.LATERAL_MOVEMENT: "↔️",
            AttackCategory.PRIVILEGE_ESCALATION: "⬆️",
            AttackCategory.DEFENSE_EVASION: "🛡️",
            AttackCategory.PERSISTENCE: "📌",
            AttackCategory.MALWARE_EXECUTION: "💀",
            AttackCategory.BRUTE_FORCE: "🔨",
            AttackCategory.RECONNAISSANCE: "🔍",
            AttackCategory.IMPACT: "💥",
            AttackCategory.COLLECTION: "🗂️",
            AttackCategory.RESOURCE_HIJACKING: "⛏️",
            AttackCategory.UNKNOWN: "❓",
        }[self]


# =============================================================================
# MONITOR TYPES
# =============================================================================

@unique
class MonitorType(str, Enum):
    """
    Identifies which sensor/monitor produced an event.

    Used for routing events to appropriate detectors and
    for tagging events in the event store.
    """

    PROCESS = "process_monitor"
    NETWORK = "network_monitor"
    FILE = "file_monitor"
    REGISTRY = "registry_monitor"
    SERVICE = "service_monitor"
    WMI = "wmi_monitor"
    ETW = "etw_monitor"
    SYSTEM = "system_monitor"        # CPU/RAM/disk telemetry
    AUTHENTICATION = "auth_monitor"  # Login events (Windows Event Log)
    SYNTHETIC = "synthetic"          # Test/simulation events


# =============================================================================
# EVENT TYPES
# =============================================================================

@unique
class EventType(str, Enum):
    """
    Granular event type classification.

    Monitors emit these specific event types on the event bus.
    Detectors subscribe to subsets of these types.
    """

    # --- Process Events ---
    PROCESS_CREATED = "process.created"
    PROCESS_TERMINATED = "process.terminated"
    PROCESS_INJECTED = "process.injected"
    PROCESS_HOLLOWED = "process.hollowed"
    PROCESS_ELEVATED = "process.elevated"       # Privilege escalation
    PROCESS_CHILD_SPAWNED = "process.child_spawned"
    PROCESS_ANOMALY = "process.anomaly"          # ML-detected

    # --- Network Events ---
    NETWORK_CONNECTION_OPENED = "network.connection.opened"
    NETWORK_CONNECTION_CLOSED = "network.connection.closed"
    NETWORK_PORT_LISTENING = "network.port.listening"
    NETWORK_OUTBOUND_UNUSUAL = "network.outbound.unusual"
    NETWORK_C2_BEACON = "network.c2.beacon"
    NETWORK_DNS_QUERY = "network.dns.query"
    NETWORK_LARGE_UPLOAD = "network.large.upload"

    # --- File System Events ---
    FILE_CREATED = "file.created"
    FILE_MODIFIED = "file.modified"
    FILE_DELETED = "file.deleted"
    FILE_RENAMED = "file.renamed"
    FILE_PERMISSION_CHANGED = "file.permission.changed"
    FILE_MASS_OPERATION = "file.mass.operation"    # Bulk changes
    FILE_EXECUTABLE_DROPPED = "file.executable.dropped"
    FILE_ENCRYPTED = "file.encrypted"              # Ransomware indicator

    # --- Registry Events (Windows) ---
    REGISTRY_KEY_CREATED = "registry.key.created"
    REGISTRY_KEY_DELETED = "registry.key.deleted"
    REGISTRY_VALUE_SET = "registry.value.set"
    REGISTRY_VALUE_DELETED = "registry.value.deleted"
    REGISTRY_PERSISTENCE_SET = "registry.persistence.set"

    # --- Service Events (Windows) ---
    SERVICE_CREATED = "service.created"
    SERVICE_DELETED = "service.deleted"
    SERVICE_MODIFIED = "service.modified"
    SERVICE_STARTED = "service.started"
    SERVICE_STOPPED = "service.stopped"

    # --- Authentication Events ---
    AUTH_LOGON_SUCCESS = "auth.logon.success"
    AUTH_LOGON_FAILURE = "auth.logon.failure"
    AUTH_LOGON_FAILURE_BURST = "auth.logon.failure_burst"  # Brute force
    AUTH_PRIVILEGE_USE = "auth.privilege.use"
    AUTH_ACCOUNT_CREATED = "auth.account.created"
    AUTH_ACCOUNT_DELETED = "auth.account.deleted"

    # --- System Events ---
    SYSTEM_STARTUP = "system.startup"
    SYSTEM_SHUTDOWN = "system.shutdown"
    SYSTEM_HIGH_CPU = "system.high.cpu"
    SYSTEM_HIGH_MEMORY = "system.high.memory"
    SYSTEM_USB_CONNECTED = "system.usb.connected"
    SYSTEM_USB_DISCONNECTED = "system.usb.disconnected"
    SYSTEM_SHADOW_COPY_DELETED = "system.shadowcopy.deleted"
    SYSTEM_DEFENDER_DISABLED = "system.defender.disabled"

    # --- IHADRS Internal Events ---
    IHADRS_STARTED = "ihadrs.started"
    IHADRS_STOPPED = "ihadrs.stopped"
    IHADRS_MONITOR_FAILED = "ihadrs.monitor.failed"
    IHADRS_DETECTION_TRIGGERED = "ihadrs.detection.triggered"
    IHADRS_RESPONSE_EXECUTED = "ihadrs.response.executed"
    IHADRS_HEALTH_CHECK = "ihadrs.health.check"


# =============================================================================
# RESPONSE SYSTEM
# =============================================================================

@unique
class ResponseMode(str, Enum):
    """Operating mode for the automated response system."""

    MANUAL = "manual"           # Log alerts, no automated actions
    SEMI_AUTO = "semi_auto"     # Show confirmation dialog, auto after timeout
    FULL_AUTO = "full_auto"     # Execute immediately without asking


@unique
class ResponseStatus(str, Enum):
    """Lifecycle status of an automated response action."""

    NONE = "none"                       # No response attempted
    PENDING_APPROVAL = "pending_approval"  # Waiting for user confirmation
    EXECUTING = "executing"             # Currently running
    EXECUTED = "executed"               # Completed successfully
    FAILED = "failed"                   # Execution error
    ROLLED_BACK = "rolled_back"         # Successfully undone
    ROLLBACK_FAILED = "rollback_failed" # Could not undo
    CANCELLED = "cancelled"             # User declined


@unique
class ActionType(str, Enum):
    """Types of automated response actions IHADRS can perform."""

    # Process actions
    KILL_PROCESS = "kill_process"
    SUSPEND_PROCESS = "suspend_process"
    RESUME_PROCESS = "resume_process"
    DUMP_PROCESS_MEMORY = "dump_process_memory"

    # Network actions
    BLOCK_IP = "block_ip"
    UNBLOCK_IP = "unblock_ip"
    BLOCK_PORT = "block_port"
    BLOCK_PROCESS_NETWORK = "block_process_network"
    CAPTURE_NETWORK_TRAFFIC = "capture_network_traffic"

    # File actions
    QUARANTINE_FILE = "quarantine_file"
    RESTORE_FILE = "restore_file"
    DELETE_FILE = "delete_file"
    SNAPSHOT_FILESYSTEM = "snapshot_filesystem"

    # Registry actions (Windows)
    DELETE_REGISTRY_KEY = "delete_registry_key"
    RESTORE_REGISTRY_KEY = "restore_registry_key"

    # Service actions (Windows)
    STOP_SERVICE = "stop_service"
    DISABLE_SERVICE = "disable_service"
    RESTORE_SERVICE = "restore_service"

    # Alert/notification actions
    ALERT_USER = "alert_user"
    SEND_EMAIL = "send_email"
    CALL_WEBHOOK = "call_webhook"

    # Investigation actions
    COLLECT_FORENSICS = "collect_forensics"
    UPLOAD_TO_VIRUSTOTAL = "upload_to_virustotal"


# =============================================================================
# DETECTION ENGINE
# =============================================================================

@unique
class DetectionCondition(str, Enum):
    """
    Logic condition for combining multiple rule clauses.

    Mirrors Sigma rule condition syntax for compatibility.
    """

    ALL = "all"              # All clauses must match (AND)
    ANY = "any"              # At least one clause must match (OR)
    THRESHOLD = "threshold"  # N events in time window
    BEHAVIORAL = "behavioral" # Delegated to BehavioralDetector (stateful)


@unique
class RuleOperator(str, Enum):
    """
    Field-level comparison operators for detection rules.

    Used in rules.yaml to specify how a field value should be compared.
    """

    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    CONTAINS_ANY = "contains_any"
    CONTAINS_ALL = "contains_all"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    REGEX = "regex"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    GREATER_THAN_OR_EQUAL = "gte"
    LESS_THAN_OR_EQUAL = "lte"
    IN = "in"
    NOT_IN = "not_in"
    IS_NULL = "is_null"
    IS_NOT_NULL = "is_not_null"


@unique
class ConfidenceLevel(str, Enum):
    """Human-readable confidence band for threat classifications."""

    VERY_LOW = "very_low"     # 0.0 – 0.2
    LOW = "low"               # 0.2 – 0.4
    MEDIUM = "medium"         # 0.4 – 0.6
    HIGH = "high"             # 0.6 – 0.8
    VERY_HIGH = "very_high"   # 0.8 – 1.0

    @classmethod
    def from_score(cls, score: float) -> ConfidenceLevel:
        """Convert a 0.0–1.0 confidence score to a confidence level."""
        if score < 0.2:
            return cls.VERY_LOW
        if score < 0.4:
            return cls.LOW
        if score < 0.6:
            return cls.MEDIUM
        if score < 0.8:
            return cls.HIGH
        return cls.VERY_HIGH


# =============================================================================
# MITRE ATT&CK CONSTANTS
# =============================================================================

# MITRE ATT&CK tactic IDs and names
# Source: https://attack.mitre.org/tactics/enterprise/
MITRE_TACTICS: Final[dict[str, str]] = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0042": "Resource Development",
    "TA0043": "Reconnaissance",
}

# Map from MITRE technique IDs to attack categories (curated subset)
TECHNIQUE_TO_CATEGORY: Final[dict[str, AttackCategory]] = {
    "T1486": AttackCategory.RANSOMWARE,
    "T1490": AttackCategory.RANSOMWARE,
    "T1071": AttackCategory.C2_COMMUNICATION,
    "T1071.001": AttackCategory.C2_COMMUNICATION,
    "T1573": AttackCategory.C2_COMMUNICATION,
    "T1003": AttackCategory.CREDENTIAL_THEFT,
    "T1003.001": AttackCategory.CREDENTIAL_THEFT,
    "T1555": AttackCategory.CREDENTIAL_THEFT,
    "T1555.003": AttackCategory.CREDENTIAL_THEFT,
    "T1110": AttackCategory.BRUTE_FORCE,
    "T1041": AttackCategory.DATA_EXFILTRATION,
    "T1048": AttackCategory.DATA_EXFILTRATION,
    "T1021": AttackCategory.LATERAL_MOVEMENT,
    "T1021.002": AttackCategory.LATERAL_MOVEMENT,
    "T1055": AttackCategory.PRIVILEGE_ESCALATION,
    "T1134": AttackCategory.PRIVILEGE_ESCALATION,
    "T1562": AttackCategory.DEFENSE_EVASION,
    "T1562.001": AttackCategory.DEFENSE_EVASION,
    "T1218": AttackCategory.DEFENSE_EVASION,
    "T1547": AttackCategory.PERSISTENCE,
    "T1547.001": AttackCategory.PERSISTENCE,
    "T1053": AttackCategory.PERSISTENCE,
    "T1053.005": AttackCategory.PERSISTENCE,
    "T1543": AttackCategory.PERSISTENCE,
    "T1543.003": AttackCategory.PERSISTENCE,
    "T1059": AttackCategory.MALWARE_EXECUTION,
    "T1059.001": AttackCategory.MALWARE_EXECUTION,
    "T1566": AttackCategory.MALWARE_EXECUTION,
    "T1204": AttackCategory.MALWARE_EXECUTION,
    "T1496": AttackCategory.RESOURCE_HIJACKING,
    "T1046": AttackCategory.RECONNAISSANCE,
    "T1135": AttackCategory.RECONNAISSANCE,
    "T1005": AttackCategory.COLLECTION,
    "T1115": AttackCategory.COLLECTION,
}

# =============================================================================
# WINDOWS-SPECIFIC CONSTANTS
# =============================================================================

# Windows event log IDs relevant to security monitoring
WINDOWS_EVENT_IDS: Final[dict[str, int]] = {
    "LOGON_SUCCESS": 4624,
    "LOGON_FAILURE": 4625,
    "LOGON_EXPLICIT_CREDENTIALS": 4648,
    "LOGOFF": 4634,
    "ACCOUNT_CREATED": 4720,
    "ACCOUNT_ENABLED": 4722,
    "ACCOUNT_DISABLED": 4725,
    "ACCOUNT_DELETED": 4726,
    "PASSWORD_CHANGED": 4723,
    "PASSWORD_RESET": 4724,
    "USER_ADDED_TO_GROUP": 4728,
    "PRIVILEGE_USE": 4672,
    "SENSITIVE_PRIVILEGE_USE": 4673,
    "PROCESS_CREATED": 4688,
    "PROCESS_TERMINATED": 4689,
    "SERVICE_CREATED": 7045,
    "SERVICE_STARTED": 7036,
    "SCHEDULED_TASK_CREATED": 4698,
    "SCHEDULED_TASK_DELETED": 4699,
    "SCHEDULED_TASK_ENABLED": 4700,
    "SCHEDULED_TASK_DISABLED": 4701,
    "AUDIT_POLICY_CHANGED": 4719,
    "REGISTRY_VALUE_MODIFIED": 4657,
    "OBJECT_ACCESS": 4663,
    "FIREWALL_RULE_ADDED": 4946,
    "FIREWALL_RULE_DELETED": 4947,
    "WINDOWS_DEFENDER_DISABLED": 5001,
    "WINDOWS_DEFENDER_REALTIME_DISABLED": 5004,
}

# Windows registry hives
REGISTRY_HIVES: Final[dict[str, str]] = {
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKCU": "HKEY_CURRENT_USER",
    "HKCR": "HKEY_CLASSES_ROOT",
    "HKU": "HKEY_USERS",
    "HKCC": "HKEY_CURRENT_CONFIG",
}

# Registry persistence paths to monitor
REGISTRY_PERSISTENCE_KEYS: Final[list[str]] = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"SYSTEM\CurrentControlSet\Services",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
    r"SOFTWARE\Classes\exefile\shell\open\command",
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
]

# High-risk file system paths for executable monitoring
HIGH_RISK_EXECUTION_PATHS: Final[list[str]] = [
    "%TEMP%",
    "%TMP%",
    "%APPDATA%",
    "%LOCALAPPDATA%",
    "%PUBLIC%",
    r"C:\Users\Public",
    r"C:\ProgramData",
    r"C:\Windows\Temp",
]

# Windows system process names (legitimate)
SYSTEM_PROCESS_NAMES: Final[frozenset[str]] = frozenset({
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "dwm.exe",
    "explorer.exe",
    "taskhost.exe",
    "taskhostw.exe",
    "spoolsv.exe",
    "audiodg.exe",
    "conhost.exe",
    "fontdrvhost.exe",
    "sihost.exe",
    "ctfmon.exe",
    "dllhost.exe",
    "msiexec.exe",
    "wuauclt.exe",
    "trustedinstaller.exe",
    "tiworker.exe",
})

# Known living-off-the-land binaries (LOLBins) to monitor closely
LOLBINS: Final[frozenset[str]] = frozenset({
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "installutil.exe",
    "regasm.exe",
    "regsvcs.exe",
    "msbuild.exe",
    "cmstp.exe",
    "xwizard.exe",
    "forfiles.exe",
    "pcalua.exe",
    "syncappvpublishingserver.exe",
    "appsyncpublishingserver.exe",
    "msiexec.exe",
    "wmic.exe",
    "powershell.exe",
    "powershell_ise.exe",
    "cmd.exe",
    "ftp.exe",
    "curl.exe",
    "wget.exe",
    "expand.exe",
    "makecab.exe",
    "ieexec.exe",
    "odbcconf.exe",
    "msdeploy.exe",
    "desktopimgdownldr.exe",
    "esentutl.exe",
})

# Suspicious file extensions that should trigger elevated scrutiny
SUSPICIOUS_EXTENSIONS: Final[frozenset[str]] = frozenset({
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".jse", ".wsf", ".wsh", ".hta", ".scr", ".pif", ".com",
    ".cpl", ".msi", ".msp", ".msc", ".reg", ".inf", ".lnk",
    ".iso", ".img", ".vhd", ".vhdx",
})

# Extensions added by common ransomware families
RANSOMWARE_EXTENSIONS: Final[frozenset[str]] = frozenset({
    ".encrypted", ".locked", ".crypt", ".crypto", ".enc", ".locky",
    ".cerber", ".zepto", ".thor", ".aaa", ".abc", ".xyz", ".zzz",
    ".micro", ".ttt", ".vvv", ".ecc", ".ezz", ".exx", ".wncry",
    ".wncryt", ".wcry", ".onion", ".aesir", ".xncrypt", ".cryptowall",
    ".cryptolocker", ".sage", ".globe", ".dharma", ".phobos",
    ".maze", ".netwalker", ".sodinokibi", ".revil", ".lockbit",
})

# =============================================================================
# NETWORK CONSTANTS
# =============================================================================

# Ports that are commonly used by C2 frameworks (elevated scrutiny)
SUSPICIOUS_C2_PORTS: Final[frozenset[int]] = frozenset({
    # Common C2 ports that are not standard service ports
    1234, 4444, 5555, 6666, 7777, 8888, 9999,
    # Metasploit defaults
    4444, 4445, 4446,
    # Cobalt Strike defaults
    50050, 443, 80,
    # Empire defaults
    8080, 8443,
    # Common reverse shell ports
    1337, 31337, 12345,
})

# Ports that legitimate user processes should NOT normally listen on
SYSTEM_RESERVED_PORTS: Final[frozenset[int]] = frozenset(range(1024))

# Maximum legitimate connection rate (connections/min) before flagging
MAX_NORMAL_CONNECTIONS_PER_MIN: Final[int] = 60

# Beacon detection: minimum interval regularity to flag as C2 (seconds)
C2_BEACON_MIN_INTERVAL_SECONDS: Final[int] = 30
C2_BEACON_MAX_JITTER_PCT: Final[float] = 0.15  # <15% jitter = suspicious

# =============================================================================
# MACHINE LEARNING CONSTANTS
# =============================================================================

# Isolation Forest parameters
ML_N_ESTIMATORS: Final[int] = 100
ML_CONTAMINATION: Final[float] = 0.05      # Expect 5% anomalous samples
ML_MAX_SAMPLES: Final[int] = 256
ML_RANDOM_STATE: Final[int] = 42

# Feature collection interval
ML_FEATURE_COLLECTION_INTERVAL_SECONDS: Final[int] = 5

# Minimum process lifetime before ML scores it (avoid false positives on
# short-lived legitimate processes like software update helpers)
ML_MIN_PROCESS_LIFETIME_SECONDS: Final[int] = 30

# Anomaly score threshold (Isolation Forest score_samples output)
# Scores below this value are considered anomalous.
# Range: typically -1.0 to 0.0 (more negative = more anomalous)
ML_ANOMALY_THRESHOLD: Final[float] = -0.5

# Training constants
ML_BASELINE_DURATION_SECONDS: Final[int] = 600   # 10 minutes
ML_RETRAIN_INTERVAL_DAYS: Final[int] = 7
ML_MIN_TRAINING_SAMPLES: Final[int] = 100         # Need at least 100 samples
ML_MAX_TRAINING_SAMPLES: Final[int] = 10_000      # Cap to limit memory

# =============================================================================
# LOGGING CONSTANTS
# =============================================================================

# Log file names
LOG_FILE_EVENTS: Final[str] = "ihadrs_events.jsonl"
LOG_FILE_AUDIT: Final[str] = "ihadrs_audit.jsonl"
LOG_FILE_DEBUG: Final[str] = "ihadrs_debug.log"

# Log rotation
LOG_ROTATION_SIZE: Final[str] = "50 MB"
LOG_RETENTION_DAYS: Final[int] = 30
LOG_COMPRESSION: Final[str] = "gz"

# Audit log — retained longer for forensics
AUDIT_LOG_RETENTION_DAYS: Final[int] = 365

# =============================================================================
# STORAGE CONSTANTS
# =============================================================================

# SQLite database settings
DB_FILENAME: Final[str] = "ihadrs.db"
DB_WAL_MODE: Final[bool] = True          # Write-Ahead Logging for performance
DB_CACHE_SIZE_KB: Final[int] = 8192      # 8MB SQLite page cache
DB_MAX_EVENTS: Final[int] = 1_000_000   # Maximum stored events before pruning
DB_PRUNE_KEEP_DAYS: Final[int] = 90     # Keep 90 days of events

# In-memory cache
CACHE_PROCESS_TTL_SECONDS: Final[int] = 60      # Cache process info for 60s
CACHE_NETWORK_TTL_SECONDS: Final[int] = 30      # Cache network state for 30s
CACHE_FILE_HASH_TTL_SECONDS: Final[int] = 3600  # Cache file hashes for 1h
CACHE_MAX_SIZE: Final[int] = 5_000              # Maximum cached items

# =============================================================================
# API CONSTANTS
# =============================================================================

API_VERSION: Final[str] = "v1"
API_PREFIX: Final[str] = f"/api/{API_VERSION}"
API_DEFAULT_PAGE_SIZE: Final[int] = 50
API_MAX_PAGE_SIZE: Final[int] = 500
API_TOKEN_HEADER: Final[str] = "X-IHADRS-Token"

# Rate limiting
API_RATE_LIMIT_REQUESTS: Final[int] = 100
API_RATE_LIMIT_WINDOW_SECONDS: Final[int] = 60

# =============================================================================
# SCHEDULER / TASK INTERVALS
# =============================================================================

# How often monitors poll for changes (when event-driven is unavailable)
MONITOR_POLL_INTERVAL_PROCESS_SECONDS: Final[float] = 1.0
MONITOR_POLL_INTERVAL_NETWORK_SECONDS: Final[float] = 2.0
MONITOR_POLL_INTERVAL_SERVICE_SECONDS: Final[float] = 5.0
MONITOR_POLL_INTERVAL_AUTH_SECONDS: Final[float] = 2.0

# Behavioral analysis window
BEHAVIORAL_WINDOW_SECONDS: Final[int] = 60        # 1 minute sliding window
BEHAVIORAL_CORRELATION_WINDOW: Final[int] = 300   # 5 minute correlation

# Health check interval
HEALTH_CHECK_INTERVAL_SECONDS: Final[int] = 30

# Resource monitoring interval
RESOURCE_CHECK_INTERVAL_SECONDS: Final[float] = 5.0

# ML feature collection
ML_COLLECTION_INTERVAL_SECONDS: Final[float] = 5.0

# =============================================================================
# RANSOMWARE DETECTION THRESHOLDS
# =============================================================================

# Number of file renames with suspicious extensions within time window
RANSOMWARE_FILE_RENAME_THRESHOLD: Final[int] = 20
RANSOMWARE_TIME_WINDOW_SECONDS: Final[float] = 10.0

# Brute force detection
BRUTE_FORCE_FAILURE_THRESHOLD: Final[int] = 5
BRUTE_FORCE_TIME_WINDOW_SECONDS: Final[float] = 60.0

# Process spawning anomaly detection
PROCESS_SPAWN_THRESHOLD: Final[int] = 5
PROCESS_SPAWN_WINDOW_SECONDS: Final[float] = 30.0

# Bulk file operations
BULK_FILE_READ_THRESHOLD: Final[int] = 100
BULK_FILE_READ_WINDOW_SECONDS: Final[float] = 5.0

# =============================================================================
# TYPE ALIASES
# =============================================================================

# Primitive type aliases for semantic clarity in function signatures
ProcessID = int
ThreadID = int
NetworkPort = int
FilePath = str
IPAddress = str
RuleID = str
EventID = str
ThreatID = str
MitreTechniqueID = str
MitreTacticID = str
ConfidenceScore = float       # 0.0 – 1.0
AnomalyScore = float          # typically -1.0 – 0.0 (Isolation Forest)
TimestampUTC = float          # Unix timestamp (UTC)
HashMD5 = str                 # 32-char hex string
HashSHA256 = str              # 64-char hex string