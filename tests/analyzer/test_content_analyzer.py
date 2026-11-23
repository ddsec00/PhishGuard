"""Unit tests for ContentAnalyzer component."""

from analyzer.base_analyzer import BaseAnalyzer
from analyzer.content_analyzer import ContentAnalyzer


def test_content_analyzer_inherits_from_base_analyzer():
    analyzer = ContentAnalyzer()
    assert isinstance(analyzer, BaseAnalyzer)
    assert analyzer.name == "ContentAnalyzer"


def test_legitimate_content_not_suspicious():
    analyzer = ContentAnalyzer()
    text = (
        "Subject: Weekly Sync Notes\n\n"
        "Hi everyone, here are the action items from our Monday meeting.\n"
        "Let us review the progress on Friday afternoon.\n"
        "Regards,\nAlex"
    )
    result = analyzer.analyze(text)

    assert result["is_suspicious"] is False
    assert len(result["findings"]) == 0
    assert result["severity"] == "none"


def test_detect_urgency_and_pressure():
    analyzer = ContentAnalyzer()
    text = "URGENT: You must act immediately within 24 hours to prevent account closure."
    result = analyzer.analyze(text)

    assert "urgency_pressure" in result["categories_detected"]
    finding = next(f for f in result["findings"] if f["category"] == "urgency_pressure")
    assert any("immediately" in p or "within 24 hours" in p for p in finding["matched_phrases"])


def test_detect_credential_harvesting():
    analyzer = ContentAnalyzer()
    text = "Please enter your password to confirm your credentials and login."
    result = analyzer.analyze(text)

    assert "credential_harvesting" in result["categories_detected"]
    assert result["is_suspicious"] is True


def test_detect_sensitive_personal_info():
    analyzer = ContentAnalyzer()
    text = "Kindly provide your social security number, cvv, and date of birth."
    result = analyzer.analyze(text)

    assert "sensitive_personal_info" in result["categories_detected"]


def test_detect_account_threats_and_financial():
    analyzer = ContentAnalyzer()
    text = (
        "Your account has been suspended due to suspicious activity detected.\n"
        "Send an immediate wire transfer or bitcoin wallet payment to restore access."
    )
    result = analyzer.analyze(text)

    assert "account_threats" in result["categories_detected"]
    assert "financial_solicitation" in result["categories_detected"]
    assert result["is_suspicious"] is True
    assert result["severity"] == "high"


def test_empty_content_handling():
    analyzer = ContentAnalyzer()
    result = analyzer.analyze("")

    assert result["is_suspicious"] is False
    assert result["total_matches"] == 0
    assert result["categories_detected"] == []
