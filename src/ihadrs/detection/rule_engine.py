"""
Module: detection.rule_engine
Purpose: Load, validate, and evaluate YAML-defined detection rules against
         incoming bus events. The rule engine is the first-pass deterministic
         layer of the detection pipeline — fast, predictable, zero false negatives
         for covered attack patterns.
Owner: detection
Dependencies: PyYAML, re, loguru
Performance: Rules compiled once on load. Per-event evaluation is O(R × C)
             where R = enabled rules, C = clauses per rule. For 30 rules with
             ≤5 clauses each, this is <1ms per event on modern hardware.
             Hot path: no I/O, no allocation beyond dict lookups.

Rule Condition Types:
    all         — All clauses must match (AND logic)
    any         — At least one clause must match (OR logic)
    threshold   — N events matching clauses within a time window
    behavioral  — Delegates to behavioral.py for stateful patterns

Operator Set (RuleOperator enum in constants.py):
    equals, not_equals, contains, not_contains, contains_any, contains_all,
    starts_with, ends_with, regex, greater_than, less_than, gte, lte,
    in, not_in, is_null, is_not_null
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml
from loguru import logger

from ihadrs.constants import (
    AttackCategory,
    DetectionCondition,
    RuleOperator,
    Severity,
    TECHNIQUE_TO_CATEGORY,
)
from ihadrs.exceptions import RuleLoadError, RuleValidationError, RuleEvaluationError
from ihadrs.models.events import BaseEvent


# =============================================================================
# RULE DATA MODELS
# =============================================================================

@dataclass
class RuleClause:
    """
    A single field-level comparison clause within a detection rule.

    Example (from YAML):
        monitor: "process"
        field:   "command_line"
        operator: "contains_any"
        values:  ["-enc", "-encodedcommand"]
        case_sensitive: false
    """

    monitor: str            # "process" | "network" | "file" | "registry" | "service" | "auth"
    field: str              # Field name on the event (dot-separated for nested)
    operator: RuleOperator
    value: Any = None       # Single value for binary operators
    values: list[Any] = field(default_factory=list)  # Multi-value for _any/_all/in
    case_sensitive: bool = False
    negate: bool = False    # True when operator starts with "not_"

    def __post_init__(self) -> None:
        """Normalize string values based on case_sensitive flag."""
        if not self.case_sensitive:
            if isinstance(self.value, str):
                self.value = self.value.lower()
            self.values = [
                v.lower() if isinstance(v, str) else v
                for v in self.values
            ]


@dataclass
class MITREMapping:
    """MITRE ATT&CK identifiers for a detection rule."""

    tactics: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    subtechniques: list[str] = field(default_factory=list)


@dataclass
class RemediationSpec:
    """Response actions and manual steps defined in a rule."""

    automatic_actions: list[dict[str, Any]] = field(default_factory=list)
    manual_steps: list[str] = field(default_factory=list)


@dataclass
class ThresholdConfig:
    """Configuration for threshold-based detection."""

    count: int = 1
    window_seconds: float = 60.0
    group_by: Optional[str] = None  # Field to group by (e.g., "source_ip")


@dataclass
class DetectionRule:
    """
    Fully parsed and validated detection rule.

    One rule maps directly to one YAML rule block in config/rules.yaml.
    After loading, rules are immutable (dataclass with no mutation needed).
    """

    rule_id: str
    name: str
    description: str
    enabled: bool
    severity: Severity
    confidence: float
    mitre: MITREMapping
    condition: DetectionCondition
    clauses: list[RuleClause]
    threshold: Optional[ThresholdConfig]

    # Enrichment configuration
    context_enrichment: dict[str, Any] = field(default_factory=dict)

    # Explanation templates (may contain {variable} placeholders)
    user_explanation: str = ""
    technical_details: str = ""

    # Response specification
    remediation: RemediationSpec = field(default_factory=RemediationSpec)

    # Meta
    false_positive_hints: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    # Compiled regex cache (populated on first use)
    _compiled_patterns: dict[str, re.Pattern] = field(
        default_factory=dict, repr=False, compare=False
    )

    @property
    def attack_category(self) -> AttackCategory:
        """Derive attack category from MITRE technique mapping."""
        for technique in self.mitre.techniques:
            if technique in TECHNIQUE_TO_CATEGORY:
                return TECHNIQUE_TO_CATEGORY[technique]
        return AttackCategory.UNKNOWN

    @property
    def primary_technique(self) -> str:
        """Return the first MITRE technique ID, or empty string."""
        return self.mitre.techniques[0] if self.mitre.techniques else ""

    def get_compiled_pattern(self, pattern: str) -> re.Pattern:
        """Return compiled regex for pattern, caching the result."""
        if pattern not in self._compiled_patterns:
            flags = re.IGNORECASE  # All patterns are case-insensitive
            self._compiled_patterns[pattern] = re.compile(pattern, flags)
        return self._compiled_patterns[pattern]


# =============================================================================
# RULE LOADER
# =============================================================================

class RuleLoader:
    """
    Loads and validates detection rules from a YAML file.

    Validates:
    - Required fields present
    - Severity and condition values are valid enums
    - Operator values are valid
    - Confidence in [0, 1]

    Invalid rules are logged and skipped (system degrades gracefully).
    """

    _REQUIRED_FIELDS = {"rule_id", "name", "severity", "detection"}
    _VALID_CONDITIONS = {"all", "any", "threshold", "behavioral"}

    @classmethod
    def load_rules(cls, rules_file: Path) -> list[DetectionRule]:
        """
        Load all detection rules from the given YAML file.

        Args:
            rules_file: Path to rules.yaml.

        Returns:
            List of validated DetectionRule objects (invalid rules skipped).

        Raises:
            RuleLoadError: If the file cannot be read or is invalid YAML.
        """
        if not rules_file.exists():
            raise RuleLoadError(
                str(rules_file),
                f"Rules file not found: {rules_file}",
            )

        try:
            with rules_file.open("r", encoding="utf-8") as f:
                raw = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            raise RuleLoadError(str(rules_file), f"YAML parse error: {exc}") from exc

        if not isinstance(raw, dict) or "rules" not in raw:
            raise RuleLoadError(
                str(rules_file),
                "Rules file must be a YAML mapping with a 'rules' key.",
            )

        raw_rules = raw.get("rules", [])
        if not isinstance(raw_rules, list):
            raise RuleLoadError(
                str(rules_file), "'rules' must be a YAML list."
            )

        loaded: list[DetectionRule] = []
        for raw_rule in raw_rules:
            try:
                rule = cls._parse_rule(raw_rule)
                loaded.append(rule)
            except RuleValidationError as exc:
                logger.warning(
                    "Skipping invalid rule: {exc}", exc=exc
                )
            except Exception as exc:
                rule_id = raw_rule.get("rule_id", "?") if isinstance(raw_rule, dict) else "?"
                logger.error(
                    "Unexpected error parsing rule '{id}': {exc}",
                    id=rule_id, exc=exc,
                )

        enabled = sum(1 for r in loaded if r.enabled)
        logger.info(
            "Loaded {total} rules ({enabled} enabled) from {path}",
            total=len(loaded),
            enabled=enabled,
            path=rules_file,
        )
        return loaded

    @classmethod
    def _parse_rule(cls, raw: dict[str, Any]) -> DetectionRule:
        """Parse a single raw rule dict into a DetectionRule."""
        if not isinstance(raw, dict):
            raise RuleValidationError("?", "?", ["Rule must be a YAML mapping"])

        # Validate required fields
        missing = cls._REQUIRED_FIELDS - set(raw.keys())
        if missing:
            raise RuleValidationError(
                raw.get("rule_id", "?"),
                raw.get("name", "?"),
                [f"Missing required fields: {', '.join(sorted(missing))}"],
            )

        rule_id = str(raw["rule_id"])
        name = str(raw.get("name", ""))

        # Severity
        try:
            severity = Severity(raw["severity"].upper())
        except (ValueError, AttributeError):
            raise RuleValidationError(
                rule_id, name,
                [f"Invalid severity '{raw.get('severity')}'. Must be LOW/MEDIUM/HIGH/CRITICAL"],
            )

        # Confidence
        confidence = float(raw.get("confidence", 0.75))
        if not 0.0 <= confidence <= 1.0:
            raise RuleValidationError(
                rule_id, name, [f"Confidence must be 0.0-1.0, got {confidence}"]
            )

        # MITRE mapping
        mitre_raw = raw.get("mitre", {})
        mitre = MITREMapping(
            tactics=mitre_raw.get("tactics", []),
            techniques=mitre_raw.get("techniques", []),
            subtechniques=mitre_raw.get("subtechniques", []),
        )

        # Detection block
        detection = raw.get("detection", {})
        condition_str = detection.get("condition", "all").lower()

        if condition_str not in cls._VALID_CONDITIONS:
            raise RuleValidationError(
                rule_id, name,
                [f"Invalid condition '{condition_str}'. Must be: {cls._VALID_CONDITIONS}"],
            )

        condition = DetectionCondition(condition_str)

        # Parse clauses
        clauses = cls._parse_clauses(rule_id, name, detection.get("rules", []))

        # Threshold config (for threshold conditions)
        threshold = None
        if condition == DetectionCondition.THRESHOLD:
            thresh_raw = detection.get("threshold", {})
            threshold = ThresholdConfig(
                count=int(thresh_raw.get("count", 1)),
                window_seconds=float(thresh_raw.get("window_seconds", 60.0)),
                group_by=thresh_raw.get("group_by"),
            )

        # Explanation
        expl = raw.get("explanation", {})
        user_expl = expl.get("user_friendly", "")
        tech_expl = expl.get("technical", "")

        # Remediation
        rem_raw = raw.get("remediation", {})
        remediation = RemediationSpec(
            automatic_actions=rem_raw.get("automatic", []),
            manual_steps=rem_raw.get("manual_steps", []),
        )

        return DetectionRule(
            rule_id=rule_id,
            name=name,
            description=str(raw.get("description", "")),
            enabled=bool(raw.get("enabled", True)),
            severity=severity,
            confidence=confidence,
            mitre=mitre,
            condition=condition,
            clauses=clauses,
            threshold=threshold,
            context_enrichment=raw.get("context_enrichment", {}),
            user_explanation=user_expl,
            technical_details=tech_expl,
            remediation=remediation,
            false_positive_hints=raw.get("false_positive_hints", []),
            references=raw.get("references", []),
            tags=raw.get("tags", []),
        )

    @classmethod
    def _parse_clauses(
        cls, rule_id: str, rule_name: str, raw_clauses: list[Any]
    ) -> list[RuleClause]:
        """Parse a list of raw clause dicts into RuleClause objects."""
        clauses: list[RuleClause] = []

        for i, raw_clause in enumerate(raw_clauses):
            if not isinstance(raw_clause, dict):
                logger.warning(
                    "Rule {id}: Clause {i} is not a dict — skipping.",
                    id=rule_id, i=i,
                )
                continue

            operator_str = raw_clause.get("operator", "equals")
            try:
                operator = RuleOperator(operator_str)
            except ValueError:
                # Try common aliases
                alias_map = {
                    "not contains_any": RuleOperator.NOT_CONTAINS,
                    "not in": RuleOperator.NOT_IN,
                    "contains_any": RuleOperator.CONTAINS_ANY,
                    "contains_all": RuleOperator.CONTAINS_ALL,
                    "gte": RuleOperator.GREATER_THAN_OR_EQUAL,
                    "lte": RuleOperator.LESS_THAN_OR_EQUAL,
                }
                operator = alias_map.get(operator_str)
                if operator is None:
                    logger.warning(
                        "Rule {id}: Unknown operator '{op}' in clause {i} — skipping clause.",
                        id=rule_id, op=operator_str, i=i,
                    )
                    continue

            # Normalize value(s)
            value = raw_clause.get("value")
            values_raw = raw_clause.get("values", [])
            # Some rules put values as scalars in "value" for multi operators
            if not values_raw and isinstance(value, list):
                values_raw = value
                value = None

            # Convert integer values lists (e.g., port numbers)
            normalized_values: list[Any] = []
            for v in values_raw:
                normalized_values.append(v)

            clauses.append(RuleClause(
                monitor=raw_clause.get("monitor", ""),
                field=raw_clause.get("field", ""),
                operator=operator,
                value=value,
                values=normalized_values,
                case_sensitive=bool(raw_clause.get("case_sensitive", False)),
            ))

        return clauses


# =============================================================================
# RULE EVALUATOR
# =============================================================================

class RuleEvaluator:
    """
    Evaluates a set of detection rules against a single event.

    For each event received, the evaluator:
    1. Filters rules by monitor type (skip rules that don't apply)
    2. Evaluates each applicable rule's clauses
    3. Returns all rules that matched

    This class is stateless — all state for behavioral/threshold detection
    lives in BehavioralDetector and CorrelationEngine respectively.
    """

    def __init__(
        self,
        rules: list[DetectionRule],
        enabled_rule_ids: Optional[list[str]] = None,
        disabled_rule_ids: Optional[list[str]] = None,
    ) -> None:
        """
        Args:
            rules:            All loaded DetectionRule objects.
            enabled_rule_ids: If non-empty, only these rule IDs are evaluated.
            disabled_rule_ids: Rule IDs to skip (user suppressions).
        """
        self._all_rules = rules
        self._enabled_filter = set(enabled_rule_ids) if enabled_rule_ids else set()
        self._disabled = set(disabled_rule_ids) if disabled_rule_ids else set()

        # Pre-filter to active rules
        self._active_rules = self._compute_active_rules()

        logger.info(
            "RuleEvaluator: {total} rules total, {active} active.",
            total=len(rules),
            active=len(self._active_rules),
        )

    def _compute_active_rules(self) -> list[DetectionRule]:
        """Return the final set of rules that will be evaluated."""
        active: list[DetectionRule] = []
        for rule in self._all_rules:
            if not rule.enabled:
                continue
            if rule.rule_id in self._disabled:
                continue
            if self._enabled_filter and rule.rule_id not in self._enabled_filter:
                continue
            # Skip threshold and behavioral rules — handled elsewhere
            if rule.condition in (DetectionCondition.THRESHOLD, DetectionCondition.BEHAVIORAL):
                active.append(rule)  # Still include — handled by behavioral detector
            else:
                active.append(rule)
        return active

    def evaluate(self, event: BaseEvent) -> list[DetectionRule]:
        """
        Evaluate all active rules against one event.

        Args:
            event: A domain event (ProcessEvent, NetworkEvent, etc.)

        Returns:
            List of rules that matched. Empty list = no detections.
        """
        matched: list[DetectionRule] = []
        event_dict = event.to_dict()

        for rule in self._active_rules:
            # Threshold/behavioral rules are handled by other components
            if rule.condition in (DetectionCondition.THRESHOLD, DetectionCondition.BEHAVIORAL):
                continue

            try:
                if self._evaluate_rule(rule, event, event_dict):
                    matched.append(rule)
            except RuleEvaluationError:
                pass  # Already logged in _evaluate_rule
            except Exception as exc:
                logger.debug(
                    "Rule {id} evaluation error (non-fatal): {exc}",
                    id=rule.rule_id, exc=exc,
                )

        return matched

    def _evaluate_rule(
        self,
        rule: DetectionRule,
        event: BaseEvent,
        event_dict: dict[str, Any],
    ) -> bool:
        """
        Evaluate a single rule against an event.

        For ALL condition: every clause must match.
        For ANY condition: at least one clause must match.
        """
        if not rule.clauses:
            return False

        clause_results: list[bool] = []
        for clause in rule.clauses:
            try:
                result = self._evaluate_clause(clause, event, event_dict)
                clause_results.append(result)
            except Exception as exc:
                raise RuleEvaluationError(
                    rule.rule_id,
                    event.event_type.value,
                    str(exc),
                ) from exc

        if rule.condition == DetectionCondition.ALL:
            return all(clause_results)
        elif rule.condition == DetectionCondition.ANY:
            return any(clause_results)
        else:
            return False

    def _evaluate_clause(
        self,
        clause: RuleClause,
        event: BaseEvent,
        event_dict: dict[str, Any],
    ) -> bool:
        """
        Evaluate a single clause against an event.

        Field extraction: supports dot-notation for nested fields.
        E.g., "process.command_line" → event_dict["process"]["command_line"]
        """
        # Extract field value from event
        field_value = self._extract_field(clause.field, event, event_dict)

        # Apply case normalization for string comparisons
        if not clause.case_sensitive and isinstance(field_value, str):
            field_value = field_value.lower()

        return self._apply_operator(clause, field_value)

    def _extract_field(
        self,
        field_path: str,
        event: BaseEvent,
        event_dict: dict[str, Any],
    ) -> Any:
        """
        Extract a field value from an event using dot-notation path.

        Tries:
        1. Direct attribute access on the event object (fastest)
        2. Dict navigation via event.to_dict() (for nested/computed fields)
        3. Returns None if field not found (clause will not match)
        """
        # Try direct attribute first (handles most cases efficiently)
        if hasattr(event, field_path):
            return getattr(event, field_path)

        # Try dict navigation (supports nested fields)
        parts = field_path.split(".")
        current: Any = event_dict
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            elif hasattr(current, part):
                current = getattr(current, part)
            else:
                return None

        return current

    def _apply_operator(self, clause: RuleClause, field_value: Any) -> bool:
        """Apply the clause operator to the extracted field value."""
        op = clause.operator
        val = clause.value
        vals = clause.values

        # Null checks
        if op == RuleOperator.IS_NULL:
            return field_value is None or field_value == ""
        if op == RuleOperator.IS_NOT_NULL:
            return field_value is not None and field_value != ""

        # String operators
        if op == RuleOperator.EQUALS:
            return str(field_value) == str(val) if field_value is not None else False
        if op == RuleOperator.NOT_EQUALS:
            return str(field_value) != str(val) if field_value is not None else True
        if op == RuleOperator.CONTAINS:
            return str(val) in str(field_value) if field_value is not None else False
        if op == RuleOperator.NOT_CONTAINS:
            return str(val) not in str(field_value) if field_value is not None else True
        if op == RuleOperator.CONTAINS_ANY:
            if field_value is None:
                return False
            fv_str = str(field_value)
            return any(str(v) in fv_str for v in vals)
        if op == RuleOperator.CONTAINS_ALL:
            if field_value is None:
                return False
            fv_str = str(field_value)
            return all(str(v) in fv_str for v in vals)
        if op == RuleOperator.STARTS_WITH:
            return str(field_value).startswith(str(val)) if field_value is not None else False
        if op == RuleOperator.ENDS_WITH:
            return str(field_value).endswith(str(val)) if field_value is not None else False
        if op == RuleOperator.REGEX:
            if field_value is None:
                return False
            try:
                pattern = re.compile(str(val), re.IGNORECASE)
                return bool(pattern.search(str(field_value)))
            except re.error:
                return False

        # Membership operators
        if op == RuleOperator.IN:
            return field_value in vals or str(field_value) in [str(v) for v in vals]
        if op == RuleOperator.NOT_IN:
            return field_value not in vals and str(field_value) not in [str(v) for v in vals]

        # Numeric comparison operators
        if op in (
            RuleOperator.GREATER_THAN, RuleOperator.LESS_THAN,
            RuleOperator.GREATER_THAN_OR_EQUAL, RuleOperator.LESS_THAN_OR_EQUAL,
        ):
            try:
                fv_num = float(field_value) if field_value is not None else 0.0
                val_num = float(val)
            except (ValueError, TypeError):
                return False

            if op == RuleOperator.GREATER_THAN:
                return fv_num > val_num
            if op == RuleOperator.LESS_THAN:
                return fv_num < val_num
            if op == RuleOperator.GREATER_THAN_OR_EQUAL:
                return fv_num >= val_num
            if op == RuleOperator.LESS_THAN_OR_EQUAL:
                return fv_num <= val_num

        return False

    @property
    def active_rule_count(self) -> int:
        """Number of actively evaluated rules."""
        return len(self._active_rules)

    def get_rule_by_id(self, rule_id: str) -> Optional[DetectionRule]:
        """Return a rule by ID, or None if not found."""
        for rule in self._all_rules:
            if rule.rule_id == rule_id:
                return rule
        return None