"""
Module: core.config
Purpose: Singleton configuration loader for IHADRS.
         Loads settings.yaml, validates against JSON Schema, overlays
         environment variables, and exposes a typed, immutable config object.
         Supports hot-reload when the config file changes on disk.
Owner: core
Dependencies: PyYAML, jsonschema, pydantic, python-dotenv, watchdog
Performance: Config is loaded once and cached; no file I/O on access.
             Hot-reload adds a single inotify/ReadDirectoryChangesW watch.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any, Callable, ClassVar, Optional

import yaml
from dotenv import load_dotenv
from jsonschema import Draft7Validator, ValidationError, SchemaError
from loguru import logger
from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from watchdog.events import FileSystemEvent, FileModifiedEvent, FileSystemEventHandler
from watchdog.observers import Observer

from ihadrs.constants import (
    API_DEFAULT_PAGE_SIZE,
    API_MAX_PAGE_SIZE,
    AUDIT_LOG_RETENTION_DAYS,
    BRUTE_FORCE_FAILURE_THRESHOLD,
    BRUTE_FORCE_TIME_WINDOW_SECONDS,
    BULK_FILE_READ_THRESHOLD,
    BULK_FILE_READ_WINDOW_SECONDS,
    C2_BEACON_MAX_JITTER_PCT,
    C2_BEACON_MIN_INTERVAL_SECONDS,
    CPU_BUDGET_AVERAGE_PCT,
    CPU_BUDGET_PEAK_PCT,
    DB_FILENAME,
    DB_MAX_EVENTS,
    DB_PRUNE_KEEP_DAYS,
    DB_WAL_MODE,
    DETECTION_LATENCY_TARGET_SECONDS,
    EVENT_QUEUE_SIZE,
    LOG_COMPRESSION,
    LOG_FILE_DEBUG,
    LOG_FILE_EVENTS,
    LOG_RETENTION_DAYS,
    LOG_ROTATION_SIZE,
    MAX_EVENTS_PER_SECOND,
    ML_ANOMALY_THRESHOLD,
    ML_BASELINE_DURATION_SECONDS,
    ML_CONTAMINATION,
    ML_MAX_SAMPLES,
    ML_MIN_PROCESS_LIFETIME_SECONDS,
    ML_N_ESTIMATORS,
    ML_RANDOM_STATE,
    ML_RETRAIN_INTERVAL_DAYS,
    RAM_BUDGET_BASELINE_MB,
    RAM_BUDGET_MAX_MB,
    RANSOMWARE_FILE_RENAME_THRESHOLD,
    RANSOMWARE_TIME_WINDOW_SECONDS,
    ResponseMode,
)
from ihadrs.exceptions import (
    ConfigFileNotFoundError,
    ConfigSchemaError,
    ConfigValidationError,
    EnvironmentVariableError,
)


# =============================================================================
# PYDANTIC CONFIGURATION MODELS
# These provide type safety, validation, and IDE autocompletion.
# =============================================================================


class AppConfig(BaseModel):
    """Top-level application identity settings."""

    name: str = Field(default="IHADRS", description="Application display name.")
    instance_id: Optional[str] = Field(
        default=None,
        description=(
            "Unique identifier for this IHADRS instance. "
            "Auto-generated on first start if not set."
        ),
    )
    data_dir: Path = Field(
        default=Path("./data"),
        description="Directory for the event database and runtime data.",
    )
    require_admin: bool = Field(
        default=True,
        description="Refuse to start if not running as administrator/root.",
    )


class LoggingConfig(BaseModel):
    """Logging subsystem settings."""

    level: str = Field(
        default="INFO",
        description="Log verbosity: DEBUG | INFO | WARNING | ERROR | CRITICAL",
    )
    log_dir: Path = Field(
        default=Path("./logs"),
        description="Directory where log files are written.",
    )
    events_file: str = Field(default=LOG_FILE_EVENTS)
    debug_file: str = Field(default=LOG_FILE_DEBUG)
    rotation_size: str = Field(
        default=LOG_ROTATION_SIZE,
        description="Rotate when file reaches this size (e.g. '50 MB').",
    )
    retention_days: int = Field(
        default=LOG_RETENTION_DAYS,
        ge=1,
        le=3650,
        description="Delete rotated logs older than this many days.",
    )
    compression: str = Field(default=LOG_COMPRESSION)
    json_format: bool = Field(
        default=True,
        description="Emit structured JSON logs (recommended for SIEM integration).",
    )
    console_output: bool = Field(
        default=True,
        description="Print log lines to stdout in addition to files.",
    )

    @field_validator("level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in valid:
            raise ValueError(f"Invalid log level '{v}'. Must be one of: {valid}")
        return upper


class MonitorConfig(BaseModel):
    """Settings for the monitoring subsystem."""

    enabled_monitors: list[str] = Field(
        default_factory=lambda: [
            "process",
            "network",
            "file",
            "registry",
            "service",
            "authentication",
        ],
        description="Which monitors to run. Omit to disable specific monitors.",
    )
    process_poll_interval: float = Field(
        default=1.0,
        ge=0.1,
        le=60.0,
        description="Seconds between process list polls.",
    )
    network_poll_interval: float = Field(
        default=2.0,
        ge=0.5,
        le=60.0,
        description="Seconds between network connection polls.",
    )
    service_poll_interval: float = Field(
        default=5.0,
        ge=1.0,
        le=300.0,
        description="Seconds between service list polls.",
    )
    auth_poll_interval: float = Field(
        default=2.0,
        ge=0.5,
        le=60.0,
        description="Seconds between authentication event polls.",
    )
    file_watch_paths: list[str] = Field(
        default_factory=lambda: [
            "%USERPROFILE%\\Documents",
            "%USERPROFILE%\\Desktop",
            "%TEMP%",
            "%APPDATA%",
            "%LOCALAPPDATA%",
            "C:\\Windows\\System32\\drivers\\etc",
        ],
        description="File system paths to monitor for changes.",
    )
    file_watch_recursive: bool = Field(
        default=True,
        description="Monitor subdirectories recursively.",
    )
    process_baseline_whitelist: list[str] = Field(
        default_factory=list,
        description="Process names that should never be flagged (user overrides).",
    )
    ip_whitelist: list[str] = Field(
        default_factory=list,
        description="IP addresses/CIDRs that should never be flagged.",
    )


class DetectionConfig(BaseModel):
    """Detection engine settings."""

    rules_file: Path = Field(
        default=Path("config/rules.yaml"),
        description="Path to detection rules YAML file.",
    )
    enabled_rules: list[str] = Field(
        default_factory=list,
        description="If non-empty, only these rule IDs are evaluated. Overrides disabled_rules.",
    )
    disabled_rules: list[str] = Field(
        default_factory=list,
        description="Rule IDs to skip (user-defined false positive suppressions).",
    )
    behavioral_window_seconds: int = Field(
        default=60,
        ge=10,
        le=3600,
        description="Time window for behavioral pattern analysis (seconds).",
    )
    correlation_window_seconds: int = Field(
        default=300,
        ge=30,
        le=3600,
        description="Time window for cross-event correlation (seconds).",
    )
    # Thresholds for built-in detections
    ransomware_rename_threshold: int = Field(
        default=RANSOMWARE_FILE_RENAME_THRESHOLD,
        description="File renames with crypto extensions triggering ransomware alert.",
    )
    ransomware_time_window_seconds: float = Field(
        default=RANSOMWARE_TIME_WINDOW_SECONDS,
    )
    brute_force_failure_threshold: int = Field(
        default=BRUTE_FORCE_FAILURE_THRESHOLD,
    )
    brute_force_time_window_seconds: float = Field(
        default=BRUTE_FORCE_TIME_WINDOW_SECONDS,
    )
    bulk_file_read_threshold: int = Field(default=BULK_FILE_READ_THRESHOLD)
    bulk_file_read_window_seconds: float = Field(
        default=BULK_FILE_READ_WINDOW_SECONDS
    )
    c2_beacon_min_interval_seconds: int = Field(
        default=C2_BEACON_MIN_INTERVAL_SECONDS,
    )
    c2_beacon_max_jitter_pct: float = Field(
        default=C2_BEACON_MAX_JITTER_PCT,
    )
    false_positive_suppression: bool = Field(
        default=True,
        description="Enable automatic false-positive reduction based on process whitelist.",
    )


class MLConfig(BaseModel):
    """Machine learning anomaly detection settings."""

    enabled: bool = Field(
        default=True,
        description="Enable ML-based anomaly detection.",
    )
    model_path: Path = Field(
        default=Path("config/baseline_model.pkl"),
        description="Path to the trained Isolation Forest model.",
    )
    baseline_duration_seconds: int = Field(
        default=ML_BASELINE_DURATION_SECONDS,
        ge=60,
        le=86400,
        description="Observation duration for initial baseline training.",
    )
    retrain_interval_days: int = Field(
        default=ML_RETRAIN_INTERVAL_DAYS,
        ge=1,
        le=365,
    )
    anomaly_threshold: float = Field(
        default=ML_ANOMALY_THRESHOLD,
        ge=-1.0,
        le=0.0,
        description=(
            "Isolation Forest score threshold. Scores below this are anomalous. "
            "Range: -1.0 (flag everything) to 0.0 (flag nothing)."
        ),
    )
    min_process_lifetime_seconds: int = Field(
        default=ML_MIN_PROCESS_LIFETIME_SECONDS,
        description="Ignore processes younger than this (avoids false positives).",
    )
    # Isolation Forest hyperparameters
    n_estimators: int = Field(default=ML_N_ESTIMATORS, ge=10, le=1000)
    contamination: float = Field(default=ML_CONTAMINATION, ge=0.001, le=0.5)
    max_samples: int = Field(default=ML_MAX_SAMPLES, ge=10, le=10000)
    random_state: int = Field(default=ML_RANDOM_STATE)
    feature_collection_interval_seconds: float = Field(
        default=5.0,
        ge=1.0,
        le=60.0,
    )


class ResponseConfig(BaseModel):
    """Automated response system settings."""

    mode: str = Field(
        default="semi_auto",
        description="Response mode: manual | semi_auto | full_auto",
    )
    confirmation_timeout_seconds: int = Field(
        default=10,
        ge=3,
        le=300,
        description="Seconds to wait for user confirmation in semi_auto mode.",
    )
    auto_respond_severities: list[str] = Field(
        default_factory=lambda: ["CRITICAL"],
        description="Severity levels that trigger automated response.",
    )
    playbooks_file: Path = Field(
        default=Path("config/playbooks.yaml"),
    )
    max_concurrent_responses: int = Field(
        default=3,
        ge=1,
        le=20,
        description="Maximum number of response actions running simultaneously.",
    )
    rollback_on_false_positive: bool = Field(
        default=True,
        description="Automatically roll back actions when user marks event as FP.",
    )

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        valid = {m.value for m in ResponseMode}
        if v not in valid:
            raise ValueError(f"Invalid response mode '{v}'. Must be one of: {valid}")
        return v

    @field_validator("auto_respond_severities")
    @classmethod
    def validate_severities(cls, v: list[str]) -> list[str]:
        valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        for sev in v:
            if sev.upper() not in valid:
                raise ValueError(f"Invalid severity '{sev}'")
        return [s.upper() for s in v]


class EmailAlertConfig(BaseModel):
    """Email alerting channel settings."""

    enabled: bool = Field(default=False)
    smtp_host: str = Field(default="")
    smtp_port: int = Field(default=587, ge=1, le=65535)
    use_tls: bool = Field(default=True)
    username: str = Field(default="")
    password: Optional[SecretStr] = Field(default=None)
    from_address: str = Field(default="")
    to_addresses: list[str] = Field(default_factory=list)
    min_severity: str = Field(
        default="CRITICAL",
        description="Minimum severity to send email alerts.",
    )


class WebhookAlertConfig(BaseModel):
    """Webhook alerting channel settings."""

    enabled: bool = Field(default=False)
    url: str = Field(default="")
    secret: Optional[SecretStr] = Field(
        default=None,
        description="HMAC secret for request signing.",
    )
    timeout_seconds: int = Field(default=10, ge=1, le=60)
    min_severity: str = Field(default="HIGH")
    retry_attempts: int = Field(default=3, ge=1, le=10)
    retry_delay_seconds: float = Field(default=2.0, ge=0.5, le=30.0)


class AlertingConfig(BaseModel):
    """Alerting subsystem settings."""

    desktop_notifications: bool = Field(
        default=True,
        description="Show OS-native desktop notifications.",
    )
    console_output: bool = Field(
        default=True,
        description="Print alerts to the console with Rich formatting.",
    )
    min_severity_console: str = Field(
        default="LOW",
        description="Minimum severity for console output.",
    )
    min_severity_desktop: str = Field(
        default="MEDIUM",
        description="Minimum severity for desktop notifications.",
    )
    max_alerts_per_minute: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Rate limit for alerts (prevents alert fatigue).",
    )
    alert_cooldown_seconds: int = Field(
        default=60,
        ge=0,
        le=3600,
        description="Suppress duplicate alerts for this many seconds.",
    )
    email: EmailAlertConfig = Field(default_factory=EmailAlertConfig)
    webhook: WebhookAlertConfig = Field(default_factory=WebhookAlertConfig)


class StorageConfig(BaseModel):
    """Event storage and database settings."""

    db_path: Path = Field(
        default=Path(f"./data/{DB_FILENAME}"),
        description="SQLite database file path.",
    )
    wal_mode: bool = Field(
        default=DB_WAL_MODE,
        description="Enable WAL mode for better concurrent performance.",
    )
    max_events: int = Field(
        default=DB_MAX_EVENTS,
        ge=1000,
        description="Maximum stored events before oldest are pruned.",
    )
    prune_keep_days: int = Field(
        default=DB_PRUNE_KEEP_DAYS,
        ge=1,
        le=3650,
    )
    audit_retention_days: int = Field(
        default=AUDIT_LOG_RETENTION_DAYS,
        ge=30,
    )


class APIConfig(BaseModel):
    """REST API server settings."""

    enabled: bool = Field(default=True)
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8765, ge=1024, le=65535)
    token: Optional[SecretStr] = Field(
        default=None,
        description=(
            "API authentication token. Required if enabled. "
            "Set via IHADRS_API_TOKEN environment variable."
        ),
    )
    cors_origins: list[str] = Field(
        default_factory=lambda: ["http://127.0.0.1:8765"],
    )
    page_size_default: int = Field(default=API_DEFAULT_PAGE_SIZE)
    page_size_max: int = Field(default=API_MAX_PAGE_SIZE)
    rate_limit_requests: int = Field(default=100, ge=10)
    rate_limit_window_seconds: int = Field(default=60, ge=10)

    @model_validator(mode="after")
    def validate_token_when_enabled(self) -> "APIConfig":
        """
        Warn (not error) when API is enabled without a token.

        We log a warning rather than raising an error so that config
        loading succeeds — the API server itself will refuse to start
        without a token. This allows the monitoring daemon to run
        even if the API config is incomplete.
        """
        if self.enabled and not self.token:
            import warnings
            warnings.warn(
                "API is enabled but no token is configured. "
                "The API server will refuse to start. "
                "Set IHADRS_API_TOKEN environment variable or "
                "add api.token to settings.yaml.",
                UserWarning,
                stacklevel=2,
            )
        return self


class SecureOpsConfig(BaseModel):
    """SecureOps SOC export settings."""

    enabled: bool = Field(
        default=False,
        description="Push detections to SecureOps using the EDR ingest API.",
    )
    api_base_url: str = Field(
        default="http://127.0.0.1:8000/api/v1",
        description="SecureOps API base URL, including the /api/v1 suffix.",
    )
    allow_http_lab: bool = Field(
        default=True,
        description="Allow HTTP for local lab/dev mode. Use HTTPS in production.",
    )
    queue_db_path: Path = Field(
        default=Path("./data/secureops_queue.db"),
        description="SQLite queue for unsent SecureOps alerts.",
    )
    timeout_seconds: int = Field(
        default=10,
        ge=1,
        le=60,
        description="SecureOps request timeout.",
    )
    max_batch_size: int = Field(default=50, ge=1, le=500)
    retry_backoff_seconds: list[int] = Field(
        default_factory=lambda: [10, 30, 120, 300, 900],
        description="Retry delays for network/5xx failures.",
    )


class PerformanceConfig(BaseModel):
    """Resource usage budget configuration."""

    event_queue_size: int = Field(
        default=EVENT_QUEUE_SIZE,
        ge=100,
        le=100_000,
        description="Maximum events buffered in memory before backpressure.",
    )
    max_events_per_second: int = Field(
        default=MAX_EVENTS_PER_SECOND,
        ge=10,
        le=100_000,
    )
    cpu_budget_average_pct: float = Field(
        default=CPU_BUDGET_AVERAGE_PCT,
        ge=0.5,
        le=50.0,
    )
    cpu_budget_peak_pct: float = Field(
        default=CPU_BUDGET_PEAK_PCT,
        ge=1.0,
        le=100.0,
    )
    ram_budget_baseline_mb: int = Field(default=RAM_BUDGET_BASELINE_MB, ge=20)
    ram_budget_max_mb: int = Field(default=RAM_BUDGET_MAX_MB, ge=50)
    detection_latency_target_seconds: float = Field(
        default=DETECTION_LATENCY_TARGET_SECONDS,
        ge=0.1,
        le=30.0,
    )


class ThreatIntelligenceConfig(BaseModel):
    """Threat intelligence and IOC settings."""

    virustotal_api_key: Optional[SecretStr] = Field(default=None)
    abuseipdb_api_key: Optional[SecretStr] = Field(default=None)
    otx_api_key: Optional[SecretStr] = Field(default=None)
    mitre_mapping_file: Path = Field(
        default=Path("config/mitre_mapping.yaml"),
    )
    ioc_database_path: Path = Field(
        default=Path("./data/iocs.db"),
    )
    enable_online_lookups: bool = Field(
        default=False,
        description=(
            "Enable real-time IOC lookups against external services. "
            "Requires internet access and API keys."
        ),
    )
    lookup_timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0)


class SecurityConfig(BaseModel):
    """IHADRS self-protection and security settings."""

    require_password_to_disable: bool = Field(
        default=False,
        description="Require a password to stop IHADRS via CLI.",
    )
    file_integrity_check: bool = Field(
        default=True,
        description="Verify IHADRS binaries have not been tampered with.",
    )
    audit_logging: bool = Field(
        default=True,
        description="Log all IHADRS actions to the audit trail.",
    )
    audit_log_signed: bool = Field(
        default=False,
        description="Sign audit log entries (requires secret key).",
    )


class IHADRSConfig(BaseModel):
    """
    Root configuration model.

    This is the fully validated, typed configuration object that
    all IHADRS components receive. Construct via ConfigLoader.load().
    """

    model_config = {"frozen": True}  # Immutable after loading

    app: AppConfig = Field(default_factory=AppConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    monitors: MonitorConfig = Field(default_factory=MonitorConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    ml: MLConfig = Field(default_factory=MLConfig)
    response: ResponseConfig = Field(default_factory=ResponseConfig)
    alerting: AlertingConfig = Field(default_factory=AlertingConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    api: APIConfig = Field(default_factory=APIConfig)
    secureops: SecureOpsConfig = Field(default_factory=SecureOpsConfig)
    performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
    threat_intelligence: ThreatIntelligenceConfig = Field(
        default_factory=ThreatIntelligenceConfig
    )
    security: SecurityConfig = Field(default_factory=SecurityConfig)


# =============================================================================
# CONFIG LOADER
# =============================================================================

class ConfigLoader:
    """
    Loads, validates, and caches IHADRS configuration.

    This class is the single entry point for configuration. It:
    1. Loads .env file for environment variable overrides
    2. Reads settings.yaml
    3. Validates against config/schema.json (JSON Schema)
    4. Applies environment variable overrides
    5. Validates with Pydantic models
    6. Returns a frozen IHADRSConfig instance

    Usage:
        config = ConfigLoader.load(Path("config/settings.yaml"))

    Hot-reload (optional):
        loader = ConfigLoader(Path("config/settings.yaml"))
        loader.start_watching(on_reload_callback)
    """

    _SCHEMA_PATH: ClassVar[Path] = Path("config/schema.json")

    # Environment variable → config path mappings.
    # Format: "ENV_VAR_NAME": "dotted.config.path"
    _ENV_OVERRIDES: ClassVar[dict[str, tuple[str, ...]]] = {
        "IHADRS_LOG_LEVEL": ("logging", "level"),
        "IHADRS_API_HOST": ("api", "host"),
        "IHADRS_API_PORT": ("api", "port"),
        "IHADRS_API_TOKEN": ("api", "token"),
        "IHADRS_API_ENABLED": ("api", "enabled"),
        "IHADRS_DB_PATH": ("storage", "db_path"),
        "IHADRS_ANOMALY_THRESHOLD": ("ml", "anomaly_threshold"),
        "IHADRS_BASELINE_DURATION": ("ml", "baseline_duration_seconds"),
        "IHADRS_MAX_EVENTS_PER_SEC": ("performance", "max_events_per_second"),
        "IHADRS_EVENT_QUEUE_SIZE": ("performance", "event_queue_size"),
        "IHADRS_SMTP_HOST": ("alerting", "email", "smtp_host"),
        "IHADRS_SMTP_PORT": ("alerting", "email", "smtp_port"),
        "IHADRS_SMTP_USERNAME": ("alerting", "email", "username"),
        "IHADRS_SMTP_PASSWORD": ("alerting", "email", "password"),
        "IHADRS_EMAIL_FROM": ("alerting", "email", "from_address"),
        "IHADRS_EMAIL_ENABLED": ("alerting", "email", "enabled"),
        "IHADRS_WEBHOOK_ENABLED": ("alerting", "webhook", "enabled"),
        "IHADRS_WEBHOOK_URL": ("alerting", "webhook", "url"),
        "IHADRS_WEBHOOK_SECRET": ("alerting", "webhook", "secret"),
        "IHADRS_SECUREOPS_ENABLED": ("secureops", "enabled"),
        "IHADRS_SECUREOPS_API_BASE_URL": ("secureops", "api_base_url"),
        "IHADRS_SECUREOPS_ALLOW_HTTP_LAB": ("secureops", "allow_http_lab"),
        "IHADRS_SECUREOPS_QUEUE_DB_PATH": ("secureops", "queue_db_path"),
        "IHADRS_SECUREOPS_MAX_BATCH_SIZE": ("secureops", "max_batch_size"),
        "IHADRS_VIRUSTOTAL_API_KEY": ("threat_intelligence", "virustotal_api_key"),
        "IHADRS_ABUSEIPDB_API_KEY": ("threat_intelligence", "abuseipdb_api_key"),
        "IHADRS_OTX_API_KEY": ("threat_intelligence", "otx_api_key"),
    }

    def __init__(self, config_path: Path) -> None:
        self._config_path = config_path
        self._config: Optional[IHADRSConfig] = None
        self._observer: Optional[Observer] = None
        self._reload_callbacks: list[Callable[[IHADRSConfig], None]] = []
        self._lock = threading.RLock()

    # -------------------------------------------------------------------------
    # Public class method — primary interface
    # -------------------------------------------------------------------------

    @classmethod
    def load(cls, config_path: Path) -> IHADRSConfig:
        """
        Load and return a validated IHADRSConfig from the given path.

        This is a convenience classmethod for one-shot loading.
        For hot-reload support, instantiate ConfigLoader directly.

        Args:
            config_path: Path to the settings.yaml file.

        Returns:
            A frozen, validated IHADRSConfig instance.

        Raises:
            ConfigFileNotFoundError: If settings.yaml does not exist.
            ConfigSchemaError: If YAML does not conform to JSON Schema.
            ConfigValidationError: If Pydantic model validation fails.
            EnvironmentVariableError: If a required env var is invalid.
        """
        instance = cls(config_path)
        return instance._load()

    # -------------------------------------------------------------------------
    # Internal loading pipeline
    # -------------------------------------------------------------------------

    def _load(self) -> IHADRSConfig:
        """Execute the full configuration loading pipeline."""
        with self._lock:
            # Step 1: Load .env file (silently ignore if missing — it's optional)
            self._load_dotenv()

            # Step 2: Read YAML
            raw_yaml = self._read_yaml_file()

            # Step 3: Validate against JSON Schema
            self._validate_schema(raw_yaml)

            # Step 4: Apply environment variable overrides
            merged = self._apply_env_overrides(raw_yaml)

            # Step 5: Parse and validate with Pydantic
            config = self._parse_pydantic(merged)

            self._config = config
            logger.debug(
                "Configuration loaded successfully from {path}",
                path=self._config_path,
            )
            return config

    def _load_dotenv(self) -> None:
        """Load .env file from project root (does not override existing env vars)."""
        env_path = Path(".env")
        if env_path.exists():
            load_dotenv(env_path, override=False)
            logger.debug("Loaded environment variables from {path}", path=env_path)

    def _read_yaml_file(self) -> dict[str, Any]:
        """Read and parse the YAML configuration file."""
        if not self._config_path.exists():
            raise ConfigFileNotFoundError(str(self._config_path))

        try:
            with self._config_path.open("r", encoding="utf-8") as f:
                raw = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            raise ConfigValidationError(
                field="<file>",
                value=str(self._config_path),
                reason=f"YAML parse error: {exc}",
            ) from exc

        if not isinstance(raw, dict):
            raise ConfigValidationError(
                field="<root>",
                value=type(raw).__name__,
                reason="Configuration file root must be a YAML mapping (dict).",
            )

        return raw

    def _validate_schema(self, raw_config: dict[str, Any]) -> None:
        """
        Validate raw YAML against config/schema.json.

        We use jsonschema for structural validation (required fields,
        allowed values, type checks) before Pydantic does semantic
        validation. This provides better error messages for users.
        """
        if not self._SCHEMA_PATH.exists():
            logger.warning(
                "JSON Schema file not found at {path}, skipping schema validation.",
                path=self._SCHEMA_PATH,
            )
            return

        try:
            with self._SCHEMA_PATH.open("r", encoding="utf-8") as f:
                schema = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning(
                "Could not load config schema: {exc}. Skipping validation.",
                exc=exc,
            )
            return

        try:
            validator = Draft7Validator(schema)
            errors = list(validator.iter_errors(raw_config))
        except SchemaError as exc:
            logger.error("Config JSON Schema is invalid: {exc}", exc=exc)
            return

        if errors:
            # Sort by path depth for clearer reporting
            errors.sort(key=lambda e: len(e.path))
            error_messages = [
                f"[{'.'.join(str(p) for p in err.path) or 'root'}] {err.message}"
                for err in errors[:10]  # Cap at 10 to avoid overwhelming output
            ]
            raise ConfigSchemaError(
                schema_path=str(self._SCHEMA_PATH),
                errors=error_messages,
            )

    def _apply_env_overrides(self, raw: dict[str, Any]) -> dict[str, Any]:
        """
        Apply environment variable overrides to the raw config dict.

        Environment variables take precedence over file-based config.
        This is standard 12-factor app practice.

        Args:
            raw: Raw dict from YAML parsing.

        Returns:
            Modified dict with env var values applied.
        """
        import copy
        result = copy.deepcopy(raw)

        for env_var, config_path_tuple in self._ENV_OVERRIDES.items():
            env_value = os.environ.get(env_var)
            if env_value is None:
                continue

            # Type-coerce env var strings to appropriate Python types
            coerced_value = self._coerce_env_value(env_var, env_value)

            # Navigate to the parent dict and set the value
            target = result
            for key in config_path_tuple[:-1]:
                if key not in target:
                    target[key] = {}
                target = target[key]

            final_key = config_path_tuple[-1]
            target[final_key] = coerced_value
            logger.debug(
                "Config override: {path} = *** (from env {var})",
                path=".".join(config_path_tuple),
                var=env_var,
            )

        return result

    def _coerce_env_value(self, env_var: str, value: str) -> Any:
        """
        Coerce a string environment variable to an appropriate Python type.

        Handles: booleans, integers, floats, lists (comma-separated), strings.
        """
        # Boolean conversion
        if value.lower() in ("true", "1", "yes", "on"):
            return True
        if value.lower() in ("false", "0", "no", "off"):
            return False

        # Integer conversion
        try:
            return int(value)
        except ValueError:
            pass

        # Float conversion
        try:
            return float(value)
        except ValueError:
            pass

        # Comma-separated list (e.g. IHADRS_CORS_ORIGINS)
        if "," in value:
            return [v.strip() for v in value.split(",") if v.strip()]

        # Path types for known path vars
        _PATH_VARS = {"IHADRS_DB_PATH", "IHADRS_MODEL_PATH", "IHADRS_CONFIG_PATH"}
        if env_var in _PATH_VARS:
            return Path(value)

        # Default: string
        return value

    def _parse_pydantic(self, raw: dict[str, Any]) -> IHADRSConfig:
        """
        Parse the raw dict into the Pydantic IHADRSConfig model.

        Converts Pydantic ValidationErrors to IHADRS ConfigValidationErrors
        for consistent error handling throughout the codebase.
        """
        from pydantic import ValidationError

        try:
            return IHADRSConfig.model_validate(raw)
        except ValidationError as exc:
            # Extract the most important error for the message
            first_error = exc.errors(include_url=False)[0]
            field_path = " → ".join(str(loc) for loc in first_error["loc"])
            reason = first_error["msg"]
            value = first_error.get("input", "<unknown>")

            raise ConfigValidationError(
                field=field_path,
                value=value,
                reason=reason,
            ) from exc

    # -------------------------------------------------------------------------
    # Hot-reload support
    # -------------------------------------------------------------------------

    def start_watching(
        self,
        on_reload: Callable[[IHADRSConfig], None] | None = None,
    ) -> None:
        """
        Start watching the config file for changes.

        When the file changes, the config is reloaded and ``on_reload``
        is called with the new IHADRSConfig instance. Invalid configs
        are logged and ignored — the running config remains active.

        Args:
            on_reload: Callback called with the new config after reload.
        """
        if on_reload:
            self._reload_callbacks.append(on_reload)

        if self._observer is not None:
            return  # Already watching

        handler = _ConfigReloadHandler(self)
        self._observer = Observer()
        self._observer.schedule(
            handler,
            str(self._config_path.parent),
            recursive=False,
        )
        self._observer.start()
        logger.info(
            "Watching config file for changes: {path}",
            path=self._config_path,
        )

    def stop_watching(self) -> None:
        """Stop watching the config file for changes."""
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5.0)
            self._observer = None
            logger.debug("Stopped watching config file.")

    def _reload(self) -> None:
        """
        Internal reload method called by the file watcher.

        Thread-safe. Invalid configs are logged and ignored.
        """
        logger.info(
            "Config file changed — reloading: {path}",
            path=self._config_path,
        )
        try:
            new_config = self._load()
            for callback in self._reload_callbacks:
                try:
                    callback(new_config)
                except Exception as exc:
                    logger.error(
                        "Config reload callback failed: {exc}", exc=exc
                    )
            logger.info("Configuration reloaded successfully.")
        except Exception as exc:
            logger.error(
                "Config reload failed — keeping current config. Error: {exc}",
                exc=exc,
            )

    @property
    def current_config(self) -> Optional[IHADRSConfig]:
        """Return the currently loaded configuration, or None if not loaded."""
        return self._config


# =============================================================================
# FILE WATCHER
# =============================================================================

class _ConfigReloadHandler(FileSystemEventHandler):
    """
    Watchdog file system event handler for config hot-reload.

    Watches the config file parent directory and triggers reloads
    only when the specific config file is modified.
    """

    # Debounce — avoid multiple reloads for a single save operation
    _DEBOUNCE_SECONDS: float = 1.0

    def __init__(self, loader: ConfigLoader) -> None:
        super().__init__()
        self._loader = loader
        self._last_reload: float = 0.0
        self._timer: Optional[threading.Timer] = None
        self._lock = threading.Lock()

    def on_modified(self, event: FileSystemEvent) -> None:
        """Handle file modification events."""
        if not isinstance(event, FileModifiedEvent):
            return

        modified_path = Path(event.src_path)
        config_path = self._loader._config_path

        # Only react to changes in our specific config file
        if modified_path.name != config_path.name:
            return

        self._schedule_reload()

    def _schedule_reload(self) -> None:
        """Schedule a debounced reload to avoid thrashing on rapid saves."""
        with self._lock:
            # Cancel any pending reload
            if self._timer is not None:
                self._timer.cancel()

            # Schedule new reload after debounce period
            self._timer = threading.Timer(
                self._DEBOUNCE_SECONDS, self._loader._reload
            )
            self._timer.daemon = True
            self._timer.start()


# =============================================================================
# MODULE-LEVEL SINGLETON ACCESSOR
# =============================================================================

# Module-level singleton — set after first load.
# Other modules should call get_config() rather than storing the instance.
_singleton_config: Optional[IHADRSConfig] = None
_singleton_loader: Optional[ConfigLoader] = None


def initialize(config_path: Path, watch: bool = False) -> IHADRSConfig:
    """
    Initialize the module-level configuration singleton.

    Must be called once during application startup before any other
    module calls get_config().

    Args:
        config_path: Path to settings.yaml.
        watch: If True, start watching for config file changes.

    Returns:
        The loaded IHADRSConfig instance.
    """
    global _singleton_config, _singleton_loader

    loader = ConfigLoader(config_path)
    config = loader._load()

    if watch:
        loader.start_watching(on_reload=_on_singleton_reload)

    _singleton_config = config
    _singleton_loader = loader
    return config


def get_config() -> IHADRSConfig:
    """
    Return the current global configuration singleton.

    Raises:
        RuntimeError: If initialize() has not been called yet.
    """
    if _singleton_config is None:
        raise RuntimeError(
            "Configuration has not been initialized. "
            "Call core.config.initialize() during application startup."
        )
    return _singleton_config


def _on_singleton_reload(new_config: IHADRSConfig) -> None:
    """Update the global singleton on hot-reload."""
    global _singleton_config
    _singleton_config = new_config
    logger.info("Global configuration singleton updated via hot-reload.")