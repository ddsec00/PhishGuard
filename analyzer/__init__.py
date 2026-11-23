"""
PhishGuard Detection Engine Package.

Provides modular, object-oriented email parsing, URL extraction, suspicious URL
analysis, content threat detection, and heuristic risk scoring.
"""

from .base_analyzer import BaseAnalyzer
from .content_analyzer import ContentAnalyzer
from .email_analyzer import EmailAnalyzer
from .email_parser import EmailParser, EmailParsingError, ParsedEmail
from .result import AnalysisResult
from .risk_scorer import RiskScorer
from .url_analyzer import URLAnalyzer
from .url_extractor import ExtractedURL, URLExtractor

__all__ = [
    "BaseAnalyzer",
    "ContentAnalyzer",
    "EmailAnalyzer",
    "EmailParser",
    "EmailParsingError",
    "ParsedEmail",
    "AnalysisResult",
    "RiskScorer",
    "URLAnalyzer",
    "URLExtractor",
    "ExtractedURL",
]
