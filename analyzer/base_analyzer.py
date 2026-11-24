"""
Base analyzer module for PhishGuard detection engine.

Defines the abstract base class that enforces a common interface
for all specialized analyzers in the detection pipeline.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseAnalyzer(ABC):
    """
    Abstract Base Class for detection engine analyzers.

    Enforces a consistent contract across all specialized analyzers
    (e.g., URLAnalyzer, ContentAnalyzer) in the PhishGuard pipeline.
    Subclasses must implement the abstract `analyze` method.
    """

    def __init__(self, name: str | None = None) -> None:
        """
        Initialize the analyzer with an optional name identifier.

        :param name: Human-readable name for the analyzer instance.
        """
        self._name: str = name or self.__class__.__name__

    @property
    def name(self) -> str:
        """Return the analyzer name."""
        return self._name

    @abstractmethod
    def analyze(self, data: Any) -> Dict[str, Any]:
        """
        Execute analysis on the provided input data.

        Must be implemented by concrete subclasses.

        :param data: The input data to analyze (e.g., URLs, text, email content).
        :return: A dictionary containing structured findings, indicators, or scores.
        :raises NotImplementedError: If the subclass does not implement this method.
        """
        raise NotImplementedError("Subclasses must implement the analyze method.")

    def __repr__(self) -> str:
        """Return a string representation of the analyzer."""
        return f"<{self.__class__.__name__}(name='{self.name}')>"
