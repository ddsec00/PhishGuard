"""
Main email analyzer orchestration module for PhishGuard detection engine.

Coordinates email parsing, URL extraction, URL analysis, content inspection,
and risk scoring using object-oriented composition to produce a unified,
structured AnalysisResult completely decoupled from Django.
"""

import logging
from typing import Optional, Union

from .content_analyzer import ContentAnalyzer
from .email_parser import EmailParser, EmailParsingError, ParsedEmail
from .result import AnalysisResult
from .risk_scorer import RiskScorer
from .url_analyzer import URLAnalyzer
from .url_extractor import URLExtractor

logger = logging.getLogger(__name__)


class EmailAnalyzer:
    """
    Orchestrator for the complete PhishGuard email phishing detection pipeline.

    Demonstrates the Object-Oriented principle of Composition: instead of
    implementing parsing, scanning, and scoring logic directly within a monolithic
    class, EmailAnalyzer delegates each responsibility to specialized, decoupled
    components.
    """

    def __init__(
        self,
        parser: Optional[EmailParser] = None,
        url_extractor: Optional[URLExtractor] = None,
        url_analyzer: Optional[URLAnalyzer] = None,
        content_analyzer: Optional[ContentAnalyzer] = None,
        risk_scorer: Optional[RiskScorer] = None,
    ) -> None:
        """
        Initialize the orchestrator with its composed detection engine components.

        Supports dependency injection for enhanced testability and modularity.

        :param parser: Component responsible for RFC 822 / MIME email parsing.
        :param url_extractor: Component responsible for extracting URLs from content.
        :param url_analyzer: Component responsible for analyzing URLs for threats.
        :param content_analyzer: Component responsible for natural language threat analysis.
        :param risk_scorer: Component responsible for calculating composite risk scores.
        """
        self.parser: EmailParser = parser or EmailParser()
        self.url_extractor: URLExtractor = url_extractor or URLExtractor()
        self.url_analyzer: URLAnalyzer = url_analyzer or URLAnalyzer()
        self.content_analyzer: ContentAnalyzer = content_analyzer or ContentAnalyzer()
        self.risk_scorer: RiskScorer = risk_scorer or RiskScorer()

    def analyze_email(self, raw_email: Union[str, bytes]) -> AnalysisResult:
        """
        Execute the end-to-end phishing detection workflow on a raw email message.

        Execution Flow:
          1. Parse raw email into structured fields (sender, subject, body, etc.).
          2. Extract all URLs from plain-text and HTML bodies without network access.
          3. Evaluate extracted URLs for syntactic and domain-based anomalies.
          4. Inspect email subject and body content for deceptive and urgent language.
          5. Compute a heuristic risk score (0-100) and assign a classification.
          6. Construct and return an immutable AnalysisResult object.

        :param raw_email: Raw RFC 822 email text string or bytes.
        :return: Populated AnalysisResult instance.
        """
        # Step 1: Parse the email structure
        try:
            parsed: ParsedEmail = self.parser.parse(raw_email)
        except EmailParsingError as err:
            logger.warning("Failed to parse raw email: %s", err)
            return AnalysisResult(
                subject="[Unparseable Email]",
                classification="Suspicious",
                risk_score=35.0,
                metadata={"error": str(err), "pipeline_stage": "parsing"},
            )
        except Exception as err:
            logger.error("Unexpected error during parsing: %s", err)
            return AnalysisResult(
                subject="[Parsing Exception]",
                classification="Suspicious",
                risk_score=30.0,
                metadata={"error": str(err), "pipeline_stage": "parsing"},
            )

        # Step 2: Extract URLs from body parts
        extracted_urls = self.url_extractor.extract(
            text=parsed.body_plain,
            html=parsed.body_html if parsed.body_html else None,
        )

        # Step 3: Analyze extracted URLs
        url_findings = self.url_analyzer.analyze(extracted_urls)

        # Step 4: Analyze email content (subject + body)
        content_findings = self.content_analyzer.analyze(parsed)

        # Step 5: Calculate composite heuristic risk score
        scoring_result = self.risk_scorer.calculate(
            url_findings=url_findings,
            content_findings=content_findings,
            sender=parsed.sender,
        )

        # Step 6: Assemble structured AnalysisResult
        url_strings = [item.url for item in extracted_urls]
        return AnalysisResult(
            sender=parsed.sender,
            recipient=parsed.recipient,
            subject=parsed.subject,
            date=parsed.date,
            extracted_urls=url_strings,
            url_findings=url_findings,
            content_findings=content_findings,
            risk_score=scoring_result["risk_score"],
            classification=scoring_result["classification"],
            metadata={
                "engine_version": "1.0.0",
                "applied_indicators": scoring_result["applied_indicators"],
                "thresholds": scoring_result["thresholds"],
                "total_urls_found": len(url_strings),
                "suspicious_urls_found": url_findings.get("suspicious_urls_count", 0),
                "content_categories_detected": content_findings.get(
                    "categories_detected", []
                ),
            },
        )
