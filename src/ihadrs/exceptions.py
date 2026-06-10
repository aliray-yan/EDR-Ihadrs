"""
Module: exceptions
Purpose: Complete custom exception hierarchy for IHADRS.
         All application-level errors descend from IHADRSError.
         Each subsystem has its own exception branch for precise error handling.
Owner: core
Dependencies: None (no internal imports — prevents circular dependencies)
Performance: Zero runtime cost beyond normal exception machinery.

Exception Hierarchy:
    IHADRSError                         Base for all IHADRS errors
    ├── ConfigurationError              Configuration loading/validation
    │   ├── ConfigFileNotFoundError
    │   ├── ConfigValidationError
    │   ├── ConfigSchemaError
    │   └── EnvironmentVariableError
    ├── MonitorError                    System monitoring errors
    │   ├── MonitorInitializationError
    │   ├── MonitorPermissionError
    │   ├── MonitorTimeoutError
    │   └── MonitorAlreadyRunningError
    ├── DetectionError                  Detection engine errors
    │   ├── RuleLoadError
    │   ├── RuleValidationError
    │   ├── RuleEvaluationError
    │   └── CorrelationError
    ├── ClassificationError             ML and rule classification errors
    │   ├── ModelNotTrainedError
    │   ├── ModelLoadError
    │   ├── ModelSaveError
    │   ├── FeatureExtractionError
    │   └── BaselineTrainingError
    ├── ResponseError                   Automated response errors
    │   ├── ActionNotFoundError
    │   ├── ActionExecutionError
    │   ├── ActionRollbackError
    │   ├── PlaybookNotFoundError
    │   └── InsufficientPrivilegesError
    ├── StorageError                    Database/persistence errors
    │   ├── DatabaseConnectionError
    │   ├── DatabaseQueryError
    │   ├── DatabaseMigrationError
    │   └── CacheError
    ├── AlertingError                   Alert delivery errors
    │   ├── NotificationDeliveryError
    │   ├── EmailDeliveryError
    │   └── WebhookDeliveryError
    ├── APIError                        Web API errors
    │   ├── AuthenticationError
    │   ├── AuthorizationError
    │   ├── RateLimitError
    │   └── ResourceNotFoundError
    ├── EventBusError                   Internal event system errors
    │   ├── EventBusFullError
    │   ├── EventPublishError
    │   └── SubscriberError
    ├── ResourceBudgetError             Performance budget violations
    │   ├── CPUBudgetExceededError
    │   ├── MemoryBudgetExceededError
    │   └── DiskIOBudgetExceededError
    └── IntelligenceError               Threat intelligence errors
        ├── IOCLookupError
        ├── MITREMappingError
        └── ThreatFeedError
"""

from __future__ import annotations

from typing import Any


# =============================================================================
# BASE EXCEPTION
# =============================================================================

class IHADRSError(Exception):
    """
    Base exception for all IHADRS application errors.

    All custom exceptions inherit from this class, enabling callers to
    catch any IHADRS-specific error with a single ``except IHADRSError``
    clause while still being able to catch specific subtypes.

    Attributes:
        message: Human-readable error description.
        context: Optional dictionary of additional error context for
                 structured logging.
        recoverable: Whether the system can continue operating after
                     this error (used by the health check system).
    """

    def __init__(
        self,
        message: str,
        context: dict[str, Any] | None = None,
        recoverable: bool = True,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.context: dict[str, Any] = context or {}
        self.recoverable = recoverable

    def __str__(self) -> str:
        if self.context:
            ctx_str = ", ".join(f"{k}={v!r}" for k, v in self.context.items())
            return f"{self.message} [{ctx_str}]"
        return self.message

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"context={self.context!r}, "
            f"recoverable={self.recoverable!r})"
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for structured logging."""
        return {
            "exception_type": self.__class__.__name__,
            "message": self.message,
            "context": self.context,
            "recoverable": self.recoverable,
        }


# =============================================================================
# CONFIGURATION ERRORS
# =============================================================================

class ConfigurationError(IHADRSError):
    """
    Base for all configuration-related errors.

    Raised when IHADRS cannot load, parse, or validate its configuration.
    These errors are generally fatal — the system cannot operate without
    a valid configuration.
    """

    def __init__(
        self,
        message: str,
        context: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, context=context, recoverable=False)


class ConfigFileNotFoundError(ConfigurationError):
    """
    Raised when a required configuration file does not exist.

    Args:
        path: The file system path that was not found.
    """

    def __init__(self, path: str) -> None:
        super().__init__(
            f"Configuration file not found: {path}",
            context={"path": path},
        )
        self.path = path


class ConfigValidationError(ConfigurationError):
    """
    Raised when configuration values fail validation.

    Args:
        field: The configuration field that failed validation.
        value: The invalid value that was provided.
        reason: A human-readable explanation of why validation failed.
    """

    def __init__(self, field: str, value: Any, reason: str) -> None:
        super().__init__(
            f"Configuration validation failed for '{field}': {reason}",
            context={"field": field, "value": value, "reason": reason},
        )
        self.field = field
        self.value = value
        self.reason = reason


class ConfigSchemaError(ConfigurationError):
    """
    Raised when a config file does not conform to its JSON Schema.

    Args:
        schema_path: Path to the schema file.
        errors: List of schema validation error messages.
    """

    def __init__(self, schema_path: str, errors: list[str]) -> None:
        error_summary = "; ".join(errors[:3])  # Show first 3 errors
        super().__init__(
            f"Configuration does not match schema ({schema_path}): {error_summary}",
            context={"schema_path": schema_path, "errors": errors},
        )
        self.schema_path = schema_path
        self.errors = errors


class EnvironmentVariableError(ConfigurationError):
    """
    Raised when a required environment variable is missing or invalid.

    Args:
        variable_name: Name of the environment variable.
        reason: Why the variable is invalid or missing.
    """

    def __init__(self, variable_name: str, reason: str = "not set") -> None:
        super().__init__(
            f"Environment variable '{variable_name}' is invalid: {reason}",
            context={"variable": variable_name, "reason": reason},
        )
        self.variable_name = variable_name


# =============================================================================
# MONITOR ERRORS
# =============================================================================

class MonitorError(IHADRSError):
    """Base for all system monitor errors."""

    def __init__(
        self,
        monitor_name: str,
        message: str,
        context: dict[str, Any] | None = None,
        recoverable: bool = True,
    ) -> None:
        ctx = {"monitor": monitor_name, **(context or {})}
        super().__init__(message, context=ctx, recoverable=recoverable)
        self.monitor_name = monitor_name


class MonitorInitializationError(MonitorError):
    """
    Raised when a monitor fails to initialize.

    This is a non-recoverable monitor-level error. The monitor will be
    marked as failed and the health check system will be notified.

    Args:
        monitor_name: Name of the monitor that failed.
        reason: Human-readable explanation of why initialization failed.
        original_error: The underlying exception that caused this failure.
    """

    def __init__(
        self,
        monitor_name: str,
        reason: str,
        original_error: Exception | None = None,
    ) -> None:
        ctx: dict[str, Any] = {"reason": reason}
        if original_error is not None:
            ctx["original_error"] = str(original_error)
            ctx["original_type"] = type(original_error).__name__
        super().__init__(
            monitor_name,
            f"Monitor '{monitor_name}' failed to initialize: {reason}",
            context=ctx,
            recoverable=False,
        )
        self.original_error = original_error


class MonitorPermissionError(MonitorError):
    """
    Raised when a monitor lacks the permissions needed to run.

    Common cause: running without Administrator/root privileges.

    Args:
        monitor_name: Name of the monitor.
        required_permission: What permission is missing.
    """

    def __init__(self, monitor_name: str, required_permission: str) -> None:
        super().__init__(
            monitor_name,
            f"Monitor '{monitor_name}' requires elevated permissions: "
            f"{required_permission}. Run IHADRS as Administrator.",
            context={"required_permission": required_permission},
            recoverable=False,
        )
        self.required_permission = required_permission


class MonitorTimeoutError(MonitorError):
    """
    Raised when a monitor's polling operation exceeds its timeout.

    The monitor will be reset and retried.

    Args:
        monitor_name: Name of the monitor.
        timeout_seconds: The timeout that was exceeded.
    """

    def __init__(self, monitor_name: str, timeout_seconds: float) -> None:
        super().__init__(
            monitor_name,
            f"Monitor '{monitor_name}' operation timed out after {timeout_seconds}s",
            context={"timeout_seconds": timeout_seconds},
            recoverable=True,
        )
        self.timeout_seconds = timeout_seconds


class MonitorAlreadyRunningError(MonitorError):
    """
    Raised when attempting to start a monitor that is already running.

    Args:
        monitor_name: Name of the monitor.
    """

    def __init__(self, monitor_name: str) -> None:
        super().__init__(
            monitor_name,
            f"Monitor '{monitor_name}' is already running. "
            "Call stop() before starting again.",
            recoverable=True,
        )


# =============================================================================
# DETECTION ERRORS
# =============================================================================

class DetectionError(IHADRSError):
    """Base for all detection engine errors."""


class RuleLoadError(DetectionError):
    """
    Raised when a detection rule file cannot be loaded.

    Args:
        rule_file: Path to the rules YAML file.
        reason: Why loading failed.
    """

    def __init__(self, rule_file: str, reason: str) -> None:
        super().__init__(
            f"Failed to load detection rules from '{rule_file}': {reason}",
            context={"rule_file": rule_file, "reason": reason},
            recoverable=False,
        )
        self.rule_file = rule_file


class RuleValidationError(DetectionError):
    """
    Raised when a detection rule fails schema validation.

    Args:
        rule_id: ID of the invalid rule.
        rule_name: Name of the invalid rule.
        errors: List of validation error messages.
    """

    def __init__(self, rule_id: str, rule_name: str, errors: list[str]) -> None:
        super().__init__(
            f"Rule '{rule_id}' ({rule_name}) failed validation: {errors[0]}",
            context={"rule_id": rule_id, "rule_name": rule_name, "errors": errors},
            recoverable=True,  # System can run with invalid rules skipped
        )
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.errors = errors


class RuleEvaluationError(DetectionError):
    """
    Raised when a rule encounters an error during evaluation.

    This typically indicates a bug in the rule definition or an
    unexpected event structure. The rule will be skipped for this event.

    Args:
        rule_id: ID of the rule that failed.
        event_type: The event type being evaluated.
        reason: Why evaluation failed.
    """

    def __init__(self, rule_id: str, event_type: str, reason: str) -> None:
        super().__init__(
            f"Rule '{rule_id}' failed to evaluate event '{event_type}': {reason}",
            context={"rule_id": rule_id, "event_type": event_type, "reason": reason},
            recoverable=True,
        )
        self.rule_id = rule_id
        self.event_type = event_type


class CorrelationError(DetectionError):
    """
    Raised when the event correlation engine encounters an error.

    Args:
        reason: Description of the correlation failure.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(
            f"Event correlation failed: {reason}",
            context={"reason": reason},
            recoverable=True,
        )


# =============================================================================
# CLASSIFICATION ERRORS
# =============================================================================

class ClassificationError(IHADRSError):
    """Base for all classification and ML errors."""


class ModelNotTrainedError(ClassificationError):
    """
    Raised when ML classification is requested but no model has been trained.

    The system will fall back to rule-based classification until a
    baseline model is trained.
    """

    def __init__(self) -> None:
        super().__init__(
            "ML model has not been trained. Run: python -m ihadrs train "
            "to generate a baseline model.",
            recoverable=True,  # System continues with rule-based classification
        )


class ModelLoadError(ClassificationError):
    """
    Raised when a saved model file cannot be loaded.

    Args:
        model_path: Path to the model file.
        reason: Why loading failed.
    """

    def __init__(self, model_path: str, reason: str) -> None:
        super().__init__(
            f"Failed to load ML model from '{model_path}': {reason}",
            context={"model_path": model_path, "reason": reason},
            recoverable=True,
        )
        self.model_path = model_path


class ModelSaveError(ClassificationError):
    """
    Raised when a trained model cannot be saved to disk.

    Args:
        model_path: Path where the model was being saved.
        reason: Why saving failed.
    """

    def __init__(self, model_path: str, reason: str) -> None:
        super().__init__(
            f"Failed to save ML model to '{model_path}': {reason}",
            context={"model_path": model_path, "reason": reason},
            recoverable=True,
        )
        self.model_path = model_path


class FeatureExtractionError(ClassificationError):
    """
    Raised when feature extraction fails for a process.

    Args:
        pid: Process ID that caused the error.
        feature_name: Name of the feature that could not be extracted.
        reason: Why extraction failed.
    """

    def __init__(self, pid: int, feature_name: str, reason: str) -> None:
        super().__init__(
            f"Feature extraction failed for PID {pid} ({feature_name}): {reason}",
            context={"pid": pid, "feature": feature_name, "reason": reason},
            recoverable=True,
        )
        self.pid = pid
        self.feature_name = feature_name


class BaselineTrainingError(ClassificationError):
    """
    Raised when baseline model training fails or produces insufficient data.

    Args:
        reason: Why training failed.
        samples_collected: Number of samples collected before failure.
        samples_needed: Minimum samples needed for training.
    """

    def __init__(
        self,
        reason: str,
        samples_collected: int = 0,
        samples_needed: int = 0,
    ) -> None:
        super().__init__(
            f"Baseline training failed: {reason} "
            f"(collected {samples_collected}/{samples_needed} samples)",
            context={
                "reason": reason,
                "samples_collected": samples_collected,
                "samples_needed": samples_needed,
            },
            recoverable=True,
        )


# =============================================================================
# RESPONSE ERRORS
# =============================================================================

class ResponseError(IHADRSError):
    """Base for all automated response errors."""


class ActionNotFoundError(ResponseError):
    """
    Raised when a playbook references an action type that doesn't exist.

    Args:
        action_type: The action type that was not found.
        available_actions: List of valid action types.
    """

    def __init__(self, action_type: str, available_actions: list[str]) -> None:
        super().__init__(
            f"Response action '{action_type}' is not registered. "
            f"Available: {', '.join(available_actions)}",
            context={
                "action_type": action_type,
                "available": available_actions,
            },
            recoverable=True,
        )
        self.action_type = action_type


class ActionExecutionError(ResponseError):
    """
    Raised when a response action fails to execute.

    Args:
        action_type: The action that failed.
        target: What the action was targeting (PID, IP, file path, etc.).
        reason: Why execution failed.
        rollback_data: Any rollback data collected before failure.
    """

    def __init__(
        self,
        action_type: str,
        target: str,
        reason: str,
        rollback_data: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            f"Response action '{action_type}' failed on target '{target}': {reason}",
            context={
                "action_type": action_type,
                "target": target,
                "reason": reason,
            },
            recoverable=True,
        )
        self.action_type = action_type
        self.target = target
        self.rollback_data = rollback_data


class ActionRollbackError(ResponseError):
    """
    Raised when rolling back a response action fails.

    This is serious — the system could not undo an action it performed.
    A human operator must intervene.

    Args:
        action_type: The action that failed to roll back.
        target: What the action was targeting.
        reason: Why rollback failed.
    """

    def __init__(self, action_type: str, target: str, reason: str) -> None:
        super().__init__(
            f"ROLLBACK FAILED for action '{action_type}' on target '{target}': "
            f"{reason}. Manual intervention required.",
            context={"action_type": action_type, "target": target, "reason": reason},
            recoverable=False,  # Manual intervention needed
        )
        self.action_type = action_type
        self.target = target


class PlaybookNotFoundError(ResponseError):
    """
    Raised when no playbook exists for a given attack category.

    Args:
        attack_category: The attack category with no playbook.
    """

    def __init__(self, attack_category: str) -> None:
        super().__init__(
            f"No response playbook found for attack category: '{attack_category}'",
            context={"attack_category": attack_category},
            recoverable=True,  # System will use generic response
        )
        self.attack_category = attack_category


class InsufficientPrivilegesError(ResponseError):
    """
    Raised when a response action requires privileges IHADRS doesn't have.

    Args:
        action_type: The action that requires elevated privileges.
        required_privilege: The specific privilege needed.
    """

    def __init__(self, action_type: str, required_privilege: str) -> None:
        super().__init__(
            f"Cannot execute '{action_type}': requires '{required_privilege}' privilege. "
            "Restart IHADRS as Administrator.",
            context={
                "action_type": action_type,
                "required_privilege": required_privilege,
            },
            recoverable=False,
        )
        self.action_type = action_type
        self.required_privilege = required_privilege


# =============================================================================
# STORAGE ERRORS
# =============================================================================

class StorageError(IHADRSError):
    """Base for all storage and persistence errors."""


class DatabaseConnectionError(StorageError):
    """
    Raised when a database connection cannot be established.

    Args:
        db_path: Path to the SQLite database file.
        reason: Why the connection failed.
    """

    def __init__(self, db_path: str, reason: str) -> None:
        super().__init__(
            f"Cannot connect to database at '{db_path}': {reason}",
            context={"db_path": db_path, "reason": reason},
            recoverable=False,
        )
        self.db_path = db_path


class DatabaseQueryError(StorageError):
    """
    Raised when a database query fails.

    Args:
        query: The SQL query that failed (sanitized).
        reason: Why the query failed.
    """

    def __init__(self, query: str, reason: str) -> None:
        # Truncate long queries for safety
        truncated_query = query[:200] + "..." if len(query) > 200 else query
        super().__init__(
            f"Database query failed: {reason}",
            context={"query_preview": truncated_query, "reason": reason},
            recoverable=True,
        )


class DatabaseMigrationError(StorageError):
    """
    Raised when a database schema migration fails.

    Args:
        migration_id: Identifier of the migration that failed.
        reason: Why the migration failed.
    """

    def __init__(self, migration_id: str, reason: str) -> None:
        super().__init__(
            f"Database migration '{migration_id}' failed: {reason}. "
            "Database may be in inconsistent state — check backup.",
            context={"migration_id": migration_id, "reason": reason},
            recoverable=False,
        )
        self.migration_id = migration_id


class CacheError(StorageError):
    """
    Raised when cache operations fail.

    Cache errors are always recoverable — the system simply skips caching.

    Args:
        operation: The cache operation that failed (get, set, delete, etc.).
        key: The cache key involved.
        reason: Why the operation failed.
    """

    def __init__(self, operation: str, key: str, reason: str) -> None:
        super().__init__(
            f"Cache {operation} failed for key '{key}': {reason}",
            context={"operation": operation, "key": key, "reason": reason},
            recoverable=True,
        )
        self.operation = operation
        self.key = key


# =============================================================================
# ALERTING ERRORS
# =============================================================================

class AlertingError(IHADRSError):
    """Base for all alerting and notification errors."""

    def __init__(
        self,
        message: str,
        context: dict[str, Any] | None = None,
    ) -> None:
        # Alerting errors are always recoverable — a missed alert is not fatal
        super().__init__(message, context=context, recoverable=True)


class NotificationDeliveryError(AlertingError):
    """
    Raised when a desktop/OS notification cannot be delivered.

    Args:
        channel: The notification channel that failed (desktop, console, etc.).
        reason: Why delivery failed.
    """

    def __init__(self, channel: str, reason: str) -> None:
        super().__init__(
            f"Notification delivery failed via '{channel}': {reason}",
            context={"channel": channel, "reason": reason},
        )
        self.channel = channel


class EmailDeliveryError(AlertingError):
    """
    Raised when an email alert cannot be sent.

    Args:
        recipient: Email address the alert was being sent to.
        reason: Why delivery failed.
    """

    def __init__(self, recipient: str, reason: str) -> None:
        super().__init__(
            f"Email alert delivery failed to '{recipient}': {reason}",
            context={"recipient": recipient, "reason": reason},
        )
        self.recipient = recipient


class WebhookDeliveryError(AlertingError):
    """
    Raised when a webhook call fails.

    Args:
        url: The webhook URL that was called.
        status_code: HTTP status code received (if any).
        reason: Why delivery failed.
    """

    def __init__(
        self,
        url: str,
        reason: str,
        status_code: int | None = None,
    ) -> None:
        ctx: dict[str, Any] = {"url": url, "reason": reason}
        if status_code is not None:
            ctx["status_code"] = status_code
        super().__init__(
            f"Webhook delivery failed to '{url}': {reason}",
            context=ctx,
        )
        self.url = url
        self.status_code = status_code


# =============================================================================
# API ERRORS
# =============================================================================

class APIError(IHADRSError):
    """
    Base for all web API errors.

    Includes HTTP status code for converting to proper HTTP responses.
    """

    def __init__(
        self,
        message: str,
        status_code: int = 500,
        context: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, context=context, recoverable=True)
        self.status_code = status_code


class AuthenticationError(APIError):
    """
    Raised when an API request fails authentication.

    Args:
        reason: Why authentication failed.
    """

    def __init__(self, reason: str = "Invalid or missing API token") -> None:
        super().__init__(
            f"Authentication failed: {reason}",
            status_code=401,
            context={"reason": reason},
        )


class AuthorizationError(APIError):
    """
    Raised when an authenticated API request lacks permission for an action.

    Args:
        action: The action that was denied.
        reason: Why the action is forbidden.
    """

    def __init__(self, action: str, reason: str) -> None:
        super().__init__(
            f"Authorization denied for '{action}': {reason}",
            status_code=403,
            context={"action": action, "reason": reason},
        )
        self.action = action


class RateLimitError(APIError):
    """
    Raised when an API client exceeds the rate limit.

    Args:
        limit: The rate limit that was exceeded.
        window_seconds: The time window for the limit.
        retry_after_seconds: How long to wait before retrying.
    """

    def __init__(
        self, limit: int, window_seconds: int, retry_after_seconds: int
    ) -> None:
        super().__init__(
            f"Rate limit exceeded: {limit} requests per {window_seconds}s. "
            f"Retry after {retry_after_seconds}s.",
            status_code=429,
            context={
                "limit": limit,
                "window_seconds": window_seconds,
                "retry_after_seconds": retry_after_seconds,
            },
        )
        self.retry_after_seconds = retry_after_seconds


class ResourceNotFoundError(APIError):
    """
    Raised when a requested API resource does not exist.

    Args:
        resource_type: The type of resource (event, alert, etc.).
        resource_id: The ID that was not found.
    """

    def __init__(self, resource_type: str, resource_id: str) -> None:
        super().__init__(
            f"{resource_type} with ID '{resource_id}' not found",
            status_code=404,
            context={"resource_type": resource_type, "resource_id": resource_id},
        )
        self.resource_type = resource_type
        self.resource_id = resource_id


# =============================================================================
# EVENT BUS ERRORS
# =============================================================================

class EventBusError(IHADRSError):
    """Base for all event bus errors."""


class EventBusFullError(EventBusError):
    """
    Raised when the event queue is full and cannot accept new events.

    This indicates the detection engine is falling behind the rate of
    incoming events. The resource manager will apply backpressure.

    Args:
        queue_size: Current size of the queue.
        max_size: Maximum allowed queue size.
        dropped_event_type: The event type that was dropped.
    """

    def __init__(
        self, queue_size: int, max_size: int, dropped_event_type: str
    ) -> None:
        super().__init__(
            f"Event queue full ({queue_size}/{max_size}). "
            f"Dropping event type '{dropped_event_type}'.",
            context={
                "queue_size": queue_size,
                "max_size": max_size,
                "dropped_event_type": dropped_event_type,
            },
            recoverable=True,
        )
        self.queue_size = queue_size
        self.max_size = max_size
        self.dropped_event_type = dropped_event_type


class EventPublishError(EventBusError):
    """
    Raised when an event cannot be published to the event bus.

    Args:
        event_type: The event type that failed to publish.
        reason: Why publishing failed.
    """

    def __init__(self, event_type: str, reason: str) -> None:
        super().__init__(
            f"Failed to publish event '{event_type}': {reason}",
            context={"event_type": event_type, "reason": reason},
            recoverable=True,
        )
        self.event_type = event_type


class SubscriberError(EventBusError):
    """
    Raised when a subscriber callback raises an unhandled exception.

    The failing subscriber will be isolated and other subscribers
    will continue to receive events.

    Args:
        subscriber_name: Name of the subscriber that failed.
        event_type: The event type being processed.
        reason: The error from the subscriber.
    """

    def __init__(
        self, subscriber_name: str, event_type: str, reason: str
    ) -> None:
        super().__init__(
            f"Subscriber '{subscriber_name}' failed processing event "
            f"'{event_type}': {reason}",
            context={
                "subscriber": subscriber_name,
                "event_type": event_type,
                "reason": reason,
            },
            recoverable=True,
        )
        self.subscriber_name = subscriber_name
        self.event_type = event_type


# =============================================================================
# RESOURCE BUDGET ERRORS
# =============================================================================

class ResourceBudgetError(IHADRSError):
    """
    Base for resource budget violations.

    These are recoverable — the resource manager will throttle operations
    until usage returns to acceptable levels.
    """

    def __init__(self, message: str, context: dict[str, Any] | None = None) -> None:
        super().__init__(message, context=context, recoverable=True)


class CPUBudgetExceededError(ResourceBudgetError):
    """
    Raised when IHADRS exceeds its CPU usage budget.

    Args:
        current_pct: Current CPU usage percentage.
        budget_pct: Allowed maximum CPU percentage.
        offending_component: Name of the component consuming too much CPU.
    """

    def __init__(
        self, current_pct: float, budget_pct: float, offending_component: str
    ) -> None:
        super().__init__(
            f"CPU budget exceeded: {current_pct:.1f}% > {budget_pct:.1f}% "
            f"(component: {offending_component})",
            context={
                "current_pct": current_pct,
                "budget_pct": budget_pct,
                "offending_component": offending_component,
            },
        )
        self.current_pct = current_pct
        self.budget_pct = budget_pct
        self.offending_component = offending_component


class MemoryBudgetExceededError(ResourceBudgetError):
    """
    Raised when IHADRS exceeds its memory usage budget.

    Args:
        current_mb: Current memory usage in MB.
        budget_mb: Allowed maximum memory in MB.
    """

    def __init__(self, current_mb: float, budget_mb: int) -> None:
        super().__init__(
            f"Memory budget exceeded: {current_mb:.1f}MB > {budget_mb}MB",
            context={"current_mb": current_mb, "budget_mb": budget_mb},
        )
        self.current_mb = current_mb
        self.budget_mb = budget_mb


class DiskIOBudgetExceededError(ResourceBudgetError):
    """
    Raised when IHADRS exceeds its disk I/O write budget.

    Args:
        current_mbs: Current write rate in MB/s.
        budget_mbs: Allowed maximum write rate in MB/s.
    """

    def __init__(self, current_mbs: float, budget_mbs: float) -> None:
        super().__init__(
            f"Disk I/O budget exceeded: {current_mbs:.2f}MB/s > {budget_mbs}MB/s",
            context={"current_mbs": current_mbs, "budget_mbs": budget_mbs},
        )
        self.current_mbs = current_mbs
        self.budget_mbs = budget_mbs


# =============================================================================
# INTELLIGENCE ERRORS
# =============================================================================

class IntelligenceError(IHADRSError):
    """Base for all threat intelligence errors."""

    def __init__(
        self,
        message: str,
        context: dict[str, Any] | None = None,
    ) -> None:
        # Intelligence errors are always recoverable
        super().__init__(message, context=context, recoverable=True)


class IOCLookupError(IntelligenceError):
    """
    Raised when an IOC lookup fails (e.g., VirusTotal API error).

    Args:
        ioc_type: Type of IOC (hash, ip, domain, url).
        ioc_value: The IOC value being looked up.
        reason: Why the lookup failed.
    """

    def __init__(self, ioc_type: str, ioc_value: str, reason: str) -> None:
        super().__init__(
            f"IOC lookup failed for {ioc_type} '{ioc_value}': {reason}",
            context={"ioc_type": ioc_type, "ioc_value": ioc_value, "reason": reason},
        )
        self.ioc_type = ioc_type
        self.ioc_value = ioc_value


class MITREMappingError(IntelligenceError):
    """
    Raised when a technique ID cannot be mapped to MITRE ATT&CK data.

    Args:
        technique_id: The technique ID that could not be resolved.
    """

    def __init__(self, technique_id: str) -> None:
        super().__init__(
            f"Unknown MITRE ATT&CK technique: '{technique_id}'. "
            "Check config/mitre_mapping.yaml.",
            context={"technique_id": technique_id},
        )
        self.technique_id = technique_id


class ThreatFeedError(IntelligenceError):
    """
    Raised when a threat intelligence feed fails to update.

    Args:
        feed_name: Name of the feed that failed.
        reason: Why the update failed.
    """

    def __init__(self, feed_name: str, reason: str) -> None:
        super().__init__(
            f"Threat feed '{feed_name}' update failed: {reason}",
            context={"feed_name": feed_name, "reason": reason},
        )
        self.feed_name = feed_name


# =============================================================================
# SENTINEL: catch-all for unexpected internal errors
# =============================================================================

class UnexpectedInternalError(IHADRSError):
    """
    Raised for unexpected internal errors that don't fit other categories.

    This should be used as a last resort in bare-except clauses that
    need to wrap unknown exceptions for structured logging.

    Args:
        component: Which component encountered the unexpected error.
        original_error: The unexpected exception.
    """

    def __init__(self, component: str, original_error: Exception) -> None:
        super().__init__(
            f"Unexpected internal error in '{component}': "
            f"{type(original_error).__name__}: {original_error}",
            context={
                "component": component,
                "original_type": type(original_error).__name__,
                "original_message": str(original_error),
            },
            recoverable=True,
        )
        self.component = component
        self.original_error = original_error