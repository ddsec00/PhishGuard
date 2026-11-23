"""
Email content analysis module for PhishGuard detection engine.

Implements rule-based natural language inspection to detect phishing indicators
such as urgency cues, password and credential requests, account suspension threats,
and unusual financial solicitations without external network dependencies.
"""

from dataclasses import dataclass
import re
from typing import Any, Dict, List, Set

from .base_analyzer import BaseAnalyzer


@dataclass
class IndicatorCategory:
    """Definition of a content indicator category and its associated patterns."""
    name: str
    description: str
    severity: str  # 'low', 'medium', 'high'
    patterns: List[str]


class ContentAnalyzer(BaseAnalyzer):
    """
    Analyzes email subject and body content for deceptive language patterns.

    Inherits from BaseAnalyzer, implementing the analyze() method.
    Avoids treating isolated keywords as proof of phishing by evaluating
    multi-category co-occurrence and weighted indicators.
    """

    CATEGORIES: List[IndicatorCategory] = [
        IndicatorCategory(
            name="urgency_pressure",
            description="Phrases designed to induce panic, rush decisions, or bypass critical thinking",
            severity="medium",
            patterns=[
                r"\bact immediately\b",
                r"\baction required immediately\b",
                r"\burgent(?:ly)?\b",
                r"\bwithin 24 hours\b",
                r"\bwithin 48 hours\b",
                r"\btime[- ]sensitive\b",
                r"\bfinal notice\b",
                r"\bimmediate response required\b",
                r"\baccount will be closed\b",
                r"\bexpires today\b",
                r"\bdo not delay\b",
            ],
        ),
        IndicatorCategory(
            name="credential_harvesting",
            description="Requests for passwords, credentials, login verifications, or authentication codes",
            severity="high",
            patterns=[
                r"\benter your password\b",
                r"\bverify your password\b",
                r"\breset your password\b",
                r"\bconfirm your credentials\b",
                r"\bprovide your login\b",
                r"\bverify your identity\b",
                r"\bupdate your login credentials\b",
                r"\bsecurity credentials\b",
                r"\bone[- ]time password\b",
                r"\botp code\b",
                r"\bconfirm your account details\b",
            ],
        ),
        IndicatorCategory(
            name="sensitive_personal_info",
            description="Requests for highly sensitive personal identification numbers or data",
            severity="high",
            patterns=[
                r"\bsocial security number\b",
                r"\bssn\b",
                r"\bdate of birth\b",
                r"\bcredit card number\b",
                r"\bcvv\b",
                r"\bcard verification value\b",
                r"\bpin number\b",
                r"\bpassport details\b",
                r"\bnational id number\b",
            ],
        ),
        IndicatorCategory(
            name="account_threats",
            description="Threats of account suspension, termination, or unauthorized compromise",
            severity="high",
            patterns=[
                r"\baccount has been suspended\b",
                r"\baccount will be suspended\b",
                r"\baccount (?:has been )?locked\b",
                r"\bunauthorized access detected\b",
                r"\bsuspicious activity detected\b",
                r"\baccess has been restricted\b",
                r"\btermination notice\b",
                r"\bsecurity alert: suspicious login\b",
                r"\btemporary suspension\b",
            ],
        ),
        IndicatorCategory(
            name="financial_solicitation",
            description="Unusual financial transactions, cryptocurrency requests, or wire transfers",
            severity="high",
            patterns=[
                r"\bwire transfer\b",
                r"\bwestern union\b",
                r"\bmoneygram\b",
                r"\bbitcoin wallet\b",
                r"\bcrypto(?:currency)? payment\b",
                r"\bgift card\b",
                r"\bunclaimed funds\b",
                r"\blottery winner\b",
                r"\binheritance fund\b",
                r"\boverdue payment\b",
                r"\bclaim your refund\b",
            ],
        ),
        IndicatorCategory(
            name="call_to_action",
            description="Generic phishing calls to action directing users to external links",
            severity="low",
            patterns=[
                r"\bclick the link below\b",
                r"\bclick here to verify\b",
                r"\bclick here to log ?in\b",
                r"\bclick here to confirm\b",
                r"\bfollow this link\b",
                r"\bdownload the attached file\b",
                r"\bopen attachment to view\b",
            ],
        ),
    ]

    def __init__(self, name: str | None = None) -> None:
        super().__init__(name=name or "ContentAnalyzer")
        # Compile all regular expressions once for performance
        self._compiled_rules: List[tuple[IndicatorCategory, List[re.Pattern]]] = [
            (cat, [re.compile(p, re.IGNORECASE) for p in cat.patterns])
            for cat in self.CATEGORIES
        ]

    def analyze(self, data: Any) -> Dict[str, Any]:
        """
        Analyze email content for phishing language and structural cues.

        :param data: Email text string, ParsedEmail object, or dictionary.
        :return: Structured findings containing detected categories and matched phrases.
        """
        text_to_analyze = ""
        subject = ""

        if isinstance(data, str):
            text_to_analyze = data
        elif hasattr(data, "full_body"):  # ParsedEmail object
            text_to_analyze = data.full_body
            subject = getattr(data, "subject", "")
        elif isinstance(data, dict):
            text_to_analyze = data.get("text", "") or data.get("body", "")
            subject = data.get("subject", "")

        combined_text = f"{subject}\n\n{text_to_analyze}".strip()

        findings: List[Dict[str, Any]] = []
        categories_detected: Set[str] = set()
        total_matches = 0
        has_high_severity = False

        for category, patterns in self._compiled_rules:
            matched_phrases: Set[str] = set()
            for pattern in patterns:
                matches = pattern.findall(combined_text)
                if matches:
                    matched_phrases.update(matches)

            if matched_phrases:
                categories_detected.add(category.name)
                match_count = len(matched_phrases)
                total_matches += match_count
                if category.severity == "high":
                    has_high_severity = True

                findings.append(
                    {
                        "category": category.name,
                        "description": category.description,
                        "severity": category.severity,
                        "matched_phrases": sorted(list(matched_phrases)),
                        "match_count": match_count,
                    }
                )

        # Classification heuristics:
        # Suspicious if:
        # - Any high-severity category matched alongside another category, OR
        # - 2 or more distinct categories matched, OR
        # - Direct credential harvesting phrase detected
        is_suspicious = (
            "credential_harvesting" in categories_detected
            or (has_high_severity and len(categories_detected) >= 2)
            or len(categories_detected) >= 2
        )

        overall_severity = "none"
        if has_high_severity:
            overall_severity = "high"
        elif categories_detected:
            overall_severity = "medium"

        return {
            "categories_detected": sorted(list(categories_detected)),
            "total_matches": total_matches,
            "findings": findings,
            "is_suspicious": is_suspicious,
            "severity": overall_severity,
        }
