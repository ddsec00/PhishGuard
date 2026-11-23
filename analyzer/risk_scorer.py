"""
Phishing risk scoring module for PhishGuard detection engine.

Implements a transparent, configurable heuristic scoring model that aggregates
findings from URL analysis, content inspection, and sender metadata into a
normalized 0–100 threat score and assigns discrete classifications.
"""

from typing import Any, Dict, List, Optional, Tuple


class RiskScorer:
    """
    Computes heuristic risk scores and classifications for scanned emails.

    Note: The resulting score represents an empirical heuristic indicator of risk
    derived from observable threat patterns, not a scientifically calibrated Bayesian
    probability.

    Default Classification Thresholds:
      - 0 to 29: Safe
      - 30 to 59: Suspicious
      - 60 to 100: Phishing
    """

    DEFAULT_WEIGHTS: Dict[str, float] = {
        "suspicious_url": 25.0,
        "ip_address_url": 20.0,
        "suspicious_sender": 20.0,
        "urgency_language": 10.0,
        "credential_request": 25.0,
        "domain_impersonation": 20.0,
        "url_shortener": 10.0,
        "account_threats": 20.0,
        "sensitive_info_request": 20.0,
    }

    def __init__(
        self,
        weights: Optional[Dict[str, float]] = None,
        safe_max: float = 29.0,
        suspicious_max: float = 59.0,
    ) -> None:
        """
        Initialize the RiskScorer with configurable weights and thresholds.

        :param weights: Optional custom indicator weight dictionary.
        :param safe_max: Maximum score considered 'Safe' (inclusive).
        :param suspicious_max: Maximum score considered 'Suspicious' (inclusive).
        """
        self.weights: Dict[str, float] = dict(self.DEFAULT_WEIGHTS)
        if weights:
            self.weights.update(weights)

        self.safe_max: float = float(safe_max)
        self.suspicious_max: float = float(suspicious_max)

    def calculate(
        self,
        url_findings: Dict[str, Any],
        content_findings: Dict[str, Any],
        sender: str = "",
    ) -> Dict[str, Any]:
        """
        Compute the cumulative risk score and classification.

        Deduplicates indicators so that multiple instances of the same indicator
        type (e.g. 5 shortened links) do not artificially saturate the score.

        :param url_findings: Result dictionary from URLAnalyzer.
        :param content_findings: Result dictionary from ContentAnalyzer.
        :param sender: Extracted sender string from EmailParser.
        :return: Dictionary containing risk_score, classification, and breakdown.
        """
        applied_indicators: List[Dict[str, Any]] = []

        # 1. URL Analysis Indicators
        url_summary = url_findings.get("indicator_summary", {})
        suspicious_urls_count = url_findings.get("suspicious_urls_count", 0)

        # IP address used in any URL
        if url_summary.get("ip_address_host", 0) > 0:
            applied_indicators.append(
                {
                    "indicator": "ip_address_url",
                    "weight": self.weights["ip_address_url"],
                    "reason": "Email contains one or more URLs using raw IP addresses",
                }
            )

        # Domain impersonation in any URL
        if url_summary.get("brand_impersonation", 0) > 0:
            applied_indicators.append(
                {
                    "indicator": "domain_impersonation",
                    "weight": self.weights["domain_impersonation"],
                    "reason": "URL mimics a recognized brand or service domain",
                }
            )

        # URL shortener in any URL
        if url_summary.get("url_shortener", 0) > 0:
            applied_indicators.append(
                {
                    "indicator": "url_shortener",
                    "weight": self.weights["url_shortener"],
                    "reason": "URL uses a shortening service concealing destination",
                }
            )

        # Other suspicious URL characteristics (excessive subdomains, risky TLD, @ symbol)
        other_url_anomalies = (
            url_summary.get("excessive_subdomains", 0)
            + url_summary.get("risky_tld", 0)
            + url_summary.get("misleading_at_symbol", 0)
        )
        if other_url_anomalies > 0 and suspicious_urls_count > 0:
            applied_indicators.append(
                {
                    "indicator": "suspicious_url",
                    "weight": self.weights["suspicious_url"],
                    "reason": "URL contains anomalous structure, risky TLD, or misleading syntax",
                }
            )

        # 2. Content Analysis Indicators
        content_categories = set(content_findings.get("categories_detected", []))

        # Credential harvesting requests
        if "credential_harvesting" in content_categories:
            applied_indicators.append(
                {
                    "indicator": "credential_request",
                    "weight": self.weights["credential_request"],
                    "reason": "Message contains direct requests for credentials, passwords, or PINs",
                }
            )

        # Urgency language
        if "urgency_pressure" in content_categories:
            applied_indicators.append(
                {
                    "indicator": "urgency_language",
                    "weight": self.weights["urgency_language"],
                    "reason": "Message employs artificial urgency cues or countdown pressure",
                }
            )

        # Account threats
        if "account_threats" in content_categories:
            applied_indicators.append(
                {
                    "indicator": "account_threats",
                    "weight": self.weights.get("account_threats", 20.0),
                    "reason": "Message threatens account lock, closure, or termination",
                }
            )

        # Sensitive personal information
        if "sensitive_personal_info" in content_categories:
            applied_indicators.append(
                {
                    "indicator": "sensitive_info_request",
                    "weight": self.weights.get("sensitive_info_request", 20.0),
                    "reason": "Message solicits SSN, passport, or credit card details",
                }
            )

        # 3. Sender Domain Indicators
        if self._is_suspicious_sender(sender):
            applied_indicators.append(
                {
                    "indicator": "suspicious_sender",
                    "weight": self.weights["suspicious_sender"],
                    "reason": "Sender address displays anomalous domain, mismatched display name, or risky TLD",
                }
            )

        # Calculate raw score and clamp between 0.0 and 100.0
        raw_score = sum(item["weight"] for item in applied_indicators)
        clamped_score = max(0.0, min(100.0, float(raw_score)))

        # Determine classification category
        classification = self.classify(clamped_score)

        return {
            "risk_score": clamped_score,
            "classification": classification,
            "applied_indicators": applied_indicators,
            "thresholds": {
                "safe_max": self.safe_max,
                "suspicious_max": self.suspicious_max,
            },
        }

    def classify(self, score: float) -> str:
        """
        Classify a numerical score into Safe, Suspicious, or Phishing.

        :param score: Numeric risk score (0.0 to 100.0).
        :return: Classification string ('Safe', 'Suspicious', 'Phishing').
        """
        if score <= self.safe_max:
            return "Safe"
        elif score <= self.suspicious_max:
            return "Suspicious"
        return "Phishing"

    def _is_suspicious_sender(self, sender: str) -> bool:
        """
        Inspect sender string for obvious spoofing or suspicious free-mail impersonation.

        :param sender: Raw sender header string.
        :return: True if sender appears suspicious, False otherwise.
        """
        if not sender:
            return False

        sender_lower = sender.lower()

        # Check for free webmail service claiming to be official security or bank
        # e.g., "PayPal Support <paypal_security_update123@gmail.com>"
        free_mail_providers = ("@gmail.com", "@yahoo.com", "@hotmail.com", "@outlook.com")
        impersonated_brands = ("paypal", "microsoft", "apple", "netflix", "bank", "security")

        if any(provider in sender_lower for provider in free_mail_providers):
            # If display name mentions a brand but actual domain is a generic freemail
            for brand in impersonated_brands:
                if brand in sender_lower.split("@")[0] or (
                    "<" in sender_lower and brand in sender_lower.split("<")[0]
                ):
                    return True

        # Check for risky TLD in sender address
        risky_tlds = (".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".buzz", ".work", ".click", ".loan")
        if any(sender_lower.endswith(tld) or f"{tld}>" in sender_lower for tld in risky_tlds):
            return True

        return False
