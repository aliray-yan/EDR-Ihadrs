"""Package: detection — IHADRS detection subsystem."""
from __future__ import annotations

from ihadrs.detection.behavioral import BehavioralDetector, BehavioralMatch, SlidingWindowTracker
from ihadrs.detection.correlation import CorrelationEngine, CorrelationMatch
from ihadrs.detection.engine import DetectionEngine, DetectionMetrics
from ihadrs.detection.rule_engine import (
    DetectionRule, RuleClause, RuleEvaluator,
    RuleLoader, MITREMapping, ThresholdConfig,
)

__all__ = [
    "DetectionEngine", "DetectionMetrics",
    "RuleLoader", "RuleEvaluator", "DetectionRule", "RuleClause",
    "MITREMapping", "ThresholdConfig",
    "BehavioralDetector", "BehavioralMatch", "SlidingWindowTracker",
    "CorrelationEngine", "CorrelationMatch",
]