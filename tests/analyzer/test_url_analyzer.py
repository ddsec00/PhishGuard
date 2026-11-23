"""Unit tests for URLAnalyzer component."""

from analyzer.base_analyzer import BaseAnalyzer
from analyzer.url_analyzer import URLAnalyzer


def test_url_analyzer_inherits_from_base_analyzer():
    analyzer = URLAnalyzer()
    assert isinstance(analyzer, BaseAnalyzer)
    assert analyzer.name == "URLAnalyzer"


def test_detect_ip_address_hostname():
    analyzer = URLAnalyzer()
    result = analyzer.analyze_single_url("http://192.168.1.100/admin/login.php")

    assert result["is_suspicious"] is True
    assert any(i["rule"] == "ip_address_host" for i in result["indicators"])


def test_detect_url_shortener():
    analyzer = URLAnalyzer()
    result = analyzer.analyze_single_url("https://bit.ly/3AbCdEf")

    assert any(i["rule"] == "url_shortener" for i in result["indicators"])


def test_detect_misleading_at_symbol():
    analyzer = URLAnalyzer()
    result = analyzer.analyze_single_url("http://paypal.com@evil-phish.net/account")

    assert result["is_suspicious"] is True
    assert any(i["rule"] == "misleading_at_symbol" for i in result["indicators"])


def test_detect_excessive_length():
    analyzer = URLAnalyzer()
    long_url = "https://example.com/auth/login?session=" + "a" * 80
    result = analyzer.analyze_single_url(long_url)

    assert any(i["rule"] == "excessive_length" for i in result["indicators"])


def test_detect_excessive_subdomains():
    analyzer = URLAnalyzer()
    result = analyzer.analyze_single_url("http://login.verification.account.update.fakebank.com/auth")

    assert any(i["rule"] == "excessive_subdomains" for i in result["indicators"])


def test_detect_brand_impersonation_and_risky_tld():
    analyzer = URLAnalyzer()
    result = analyzer.analyze_single_url("http://paypal-security-update.top/verify")

    assert result["is_suspicious"] is True
    assert any(i["rule"] == "brand_impersonation" for i in result["indicators"])
    assert any(i["rule"] == "risky_tld" for i in result["indicators"])


def test_legitimate_url_not_flagged():
    analyzer = URLAnalyzer()
    result = analyzer.analyze_single_url("https://www.google.com/search?q=oop")

    assert result["is_suspicious"] is False
    assert len(result["indicators"]) == 0


def test_batch_analyze_via_common_interface():
    analyzer = URLAnalyzer()
    urls = [
        "http://10.0.0.1/login",
        "https://www.wikipedia.org",
        "https://bit.ly/testlink",
    ]
    batch_result = analyzer.analyze(urls)

    assert batch_result["total_urls"] == 3
    assert batch_result["suspicious_urls_count"] == 2
    assert "ip_address_host" in batch_result["indicator_summary"]
    assert "url_shortener" in batch_result["indicator_summary"]
