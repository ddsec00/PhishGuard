"""
Suspicious URL analysis module for PhishGuard detection engine.

Implements heuristic inspection of URLs to detect phishing indicators
such as IP hostnames, URL shorteners, deceptive @ syntax, risky TLDs,
and excessive length without performing any network requests.
"""

from ipaddress import ip_address
import re
from typing import Any, Dict, List, Set, Union
from urllib.parse import urlparse

from .base_analyzer import BaseAnalyzer


class URLAnalyzer(BaseAnalyzer):
    """
    Analyzes URLs for common syntactic and structural phishing indicators.

    Inherits from BaseAnalyzer, implementing the common analyze() interface.
    All evaluations are strictly offline and rule-based.
    """

    # Common URL shorteners used to obfuscate destinations
    KNOWN_SHORTENERS: Set[str] = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "cutt.ly",
        "adf.ly",
        "bit.do",
        "rb.gy",
        "rebrand.ly",
    }

    # Top-Level Domains frequently abused in phishing or spam
    RISKY_TLDS: Set[str] = {
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq",
        ".top",
        ".xyz",
        ".work",
        ".click",
        ".loan",
        ".fit",
        ".surf",
        ".buzz",
        ".country",
        ".kim",
    }

    # High-value brand names often impersonated in phishing domains
    TARGET_BRAND_KEYWORDS: Set[str] = {
        "paypal",
        "microsoft",
        "apple",
        "google",
        "netflix",
        "amazon",
        "bank",
        "chase",
        "wellsfargo",
        "facebook",
        "instagram",
        "whatsapp",
        "security-update",
        "account-verification",
    }

    def __init__(self, name: str | None = None) -> None:
        super().__init__(name=name or "URLAnalyzer")

    def analyze(self, data: Any) -> Dict[str, Any]:
        """
        Analyze one or more URLs for phishing indicators.

        :param data: A single URL string, an ExtractedURL object, or an iterable of them.
        :return: Structured dictionary containing findings for each URL and summary counts.
        """
        urls: List[str] = []

        if isinstance(data, str):
            urls = [data]
        elif hasattr(data, "url"):  # ExtractedURL instance
            urls = [getattr(data, "url")]
        elif isinstance(data, (list, tuple, set)):
            for item in data:
                if isinstance(item, str):
                    urls.append(item)
                elif hasattr(item, "url"):
                    urls.append(getattr(item, "url"))

        findings: List[Dict[str, Any]] = []
        suspicious_count = 0
        indicator_summary: Dict[str, int] = {}

        for url in urls:
            url_finding = self.analyze_single_url(url)
            findings.append(url_finding)
            if url_finding["is_suspicious"]:
                suspicious_count += 1
            for ind in url_finding["indicators"]:
                rule_name = ind["rule"]
                indicator_summary[rule_name] = indicator_summary.get(rule_name, 0) + 1

        return {
            "total_urls": len(urls),
            "suspicious_urls_count": suspicious_count,
            "findings": findings,
            "indicator_summary": indicator_summary,
        }

    def analyze_single_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze a single URL and return detailed structured indicators.

        :param url: URL string to inspect.
        :return: Dictionary containing the URL, indicators list, and suspicion status.
        """
        indicators: List[Dict[str, str]] = []

        try:
            parsed = urlparse(url)
        except Exception:
            return {
                "url": url,
                "indicators": [
                    {
                        "rule": "malformed_url",
                        "description": "URL cannot be parsed by standard URL parser",
                        "severity": "medium",
                    }
                ],
                "suspicious_count": 1,
                "is_suspicious": True,
            }

        hostname = (parsed.hostname or "").lower()
        netloc = (parsed.netloc or "").lower()

        # Rule 1: IP address used as hostname instead of a registered domain
        if self._is_ip_address(hostname):
            indicators.append(
                {
                    "rule": "ip_address_host",
                    "description": "URL uses a raw IP address instead of a domain name",
                    "severity": "high",
                }
            )

        # Rule 2: URL shortener service used to mask final destination
        if hostname in self.KNOWN_SHORTENERS:
            indicators.append(
                {
                    "rule": "url_shortener",
                    "description": f"URL uses a known shortening service ({hostname}) to obscure destination",
                    "severity": "medium",
                }
            )

        # Rule 3: Deceptive use of '@' symbol in URL
        # e.g., http://trusted-bank.com@malicious-host.com
        if "@" in netloc:
            indicators.append(
                {
                    "rule": "misleading_at_symbol",
                    "description": "URL contains '@' symbol in authority, deceiving users about actual host",
                    "severity": "high",
                }
            )

        # Rule 4: Excessive URL length (> 75 characters)
        if len(url) > 75:
            indicators.append(
                {
                    "rule": "excessive_length",
                    "description": f"Unusually long URL ({len(url)} characters)",
                    "severity": "low",
                }
            )

        # Rule 5: Suspicious subdomain depth (>= 3 subdomains)
        # e.g., login.paypal.com.account-update.badsite.com
        if hostname.count(".") >= 3 and not self._is_ip_address(hostname):
            indicators.append(
                {
                    "rule": "excessive_subdomains",
                    "description": f"Excessive subdomain hierarchy ({hostname.count('.')} dots)",
                    "severity": "medium",
                }
            )

        # Rule 6: Target brand impersonation in domain
        for brand in self.TARGET_BRAND_KEYWORDS:
            if brand in hostname:
                # If hostname is not the legitimate exact domain (e.g. not paypal.com)
                if not (hostname == f"{brand}.com" or hostname.endswith(f".{brand}.com")):
                    indicators.append(
                        {
                            "rule": "brand_impersonation",
                            "description": f"Domain appears to mimic trusted brand '{brand}' in host '{hostname}'",
                            "severity": "high",
                        }
                    )
                    break

        # Rule 7: Risky or spam-heavy Top-Level Domain
        for risky_tld in self.RISKY_TLDS:
            if hostname.endswith(risky_tld):
                indicators.append(
                    {
                        "rule": "risky_tld",
                        "description": f"Domain uses high-risk Top-Level Domain '{risky_tld}'",
                        "severity": "medium",
                    }
                )
                break

        # Rule 8: Unencrypted HTTP protocol (weak indicator)
        if parsed.scheme.lower() == "http":
            indicators.append(
                {
                    "rule": "http_unencrypted",
                    "description": "URL uses unencrypted HTTP protocol instead of HTTPS",
                    "severity": "low",
                }
            )

        # Classify as suspicious if any high severity indicator, or 2+ medium/low indicators
        high_count = sum(1 for i in indicators if i["severity"] == "high")
        is_suspicious = high_count > 0 or len(indicators) >= 2

        return {
            "url": url,
            "hostname": hostname,
            "indicators": indicators,
            "suspicious_count": len(indicators),
            "is_suspicious": is_suspicious,
        }

    def _is_ip_address(self, host: str) -> bool:
        """Check if hostname is a valid IPv4 or IPv6 address."""
        if not host:
            return False
        # Fast regex pre-check for IPv4 format
        if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", host):
            try:
                ip_address(host)
                return True
            except ValueError:
                return False
        # Check IPv6 (bracketed or bare)
        clean_host = host.strip("[]")
        try:
            ip_address(clean_host)
            return True
        except ValueError:
            return False
