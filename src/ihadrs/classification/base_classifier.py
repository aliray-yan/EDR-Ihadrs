"""
Module: classification.base_classifier
Purpose: Abstract base class for all IHADRS classifiers.
         Defines the common interface that rule_classifier and
         ml_classifier implement.
Owner: classification
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ihadrs.models.threats import ThreatEvent


class BaseClassifier(ABC):
    """Abstract base for threat classifiers."""

    @abstractmethod
    def classify(self, threat: ThreatEvent, **kwargs: Any) -> ThreatEvent:
        """
        Classify / enrich a ThreatEvent.

        Args:
            threat: The ThreatEvent to classify.

        Returns:
            The same ThreatEvent with enriched classification fields.
        """
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the classifier name for logging."""
        ...