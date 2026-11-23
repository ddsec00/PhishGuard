"""
Structured analysis result model for PhishGuard detection engine.

Provides strongly-typed data structures to store, serialize, and transfer
the complete results of email inspection without coupling to Django models.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional


@dataclass
class AnalysisResult:
    """
    Encapsulates the complete findings and threat evaluation of an email scan.

    Attributes:
        sender: Sender address extracted from email headers.
        recipient: Target recipient address, if available.
        subject: Email subject line.
        date: Email date header value, if present.
        extracted_urls: List of all unique URLs extracted from the email.
        url_findings: Detailed dictionary of URL indicators and suspicion flags.
        content_findings: Detailed dictionary of content language categories and matches.
        risk_score: Computed heuristic threat score bounded between 0.0 and 100.0.
        classification: Final discrete category ('Safe', 'Suspicious', 'Phishing').
        is_phishing: Convenience boolean flag indicating high-confidence threat.
        analyzed_at: ISO 8601 UTC timestamp of when analysis occurred.
        metadata: Extensible dictionary for engine version, processing time, etc.
    """
    sender: str = ""
    recipient: str = ""
    subject: str = ""
    date: str = ""
    extracted_urls: List[str] = field(default_factory=list)
    url_findings: Dict[str, Any] = field(default_factory=dict)
    content_findings: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    classification: str = "Safe"
    is_phishing: bool = False
    analyzed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate and normalize fields after dataclass initialization."""
        # Clamp risk score to valid range [0.0, 100.0]
        self.risk_score = max(0.0, min(100.0, float(self.risk_score)))

        # Synchronize is_phishing boolean with classification
        if self.classification == "Phishing":
            self.is_phishing = True

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the analysis result into a native dictionary representation.

        Suitable for JSON serialization, API responses, or Django model ingestion.
        :return: Standard dictionary containing all analysis attributes.
        """
        return asdict(self)

    def to_json(self, indent: Optional[int] = None) -> str:
        """
        Serialize the result directly to a JSON-formatted string.

        :param indent: Formatting indentation for pretty-printing.
        :return: Valid JSON string representation.
        """
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AnalysisResult":
        """
        Reconstruct an AnalysisResult instance from a dictionary.

        :param data: Dictionary containing result fields.
        :return: AnalysisResult instance.
        """
        data_copy = dict(data)
        # Filter keys to match valid dataclass field names
        valid_fields = cls.__dataclass_fields__.keys()
        filtered_data = {k: v for k, v in data_copy.items() if k in valid_fields}
        return cls(**filtered_data)

    def summary(self) -> str:
        """
        Generate a concise, human-readable summary of the scan results.

        :return: One-line summary string.
        """
        urls_count = len(self.extracted_urls)
        content_alerts = len(self.content_findings.get("categories_detected", []))
        return (
            f"[{self.classification.upper()}] Score: {self.risk_score:.1f}/100 | "
            f"Subject: '{self.subject}' | URLs: {urls_count} | Content Alerts: {content_alerts}"
        )
