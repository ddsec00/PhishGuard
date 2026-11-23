"""Unit and integration tests for EmailAnalyzer orchestration component."""

import json
from analyzer.email_analyzer import EmailAnalyzer
from analyzer.result import AnalysisResult


def test_analyze_legitimate_email_pipeline():
    raw_email = (
        "From: professor@university.edu\n"
        "To: student@university.edu\n"
        "Subject: OOP Lab Assignment Notes\n"
        "Date: Mon, 23 Nov 2026 09:30:00 +0000\n\n"
        "Dear class,\n"
        "Please review the assignment guidelines at https://cs.university.edu/oop.\n"
        "Submission deadline is next Monday.\n"
        "Best regards,\nProfessor Smith"
    )
    analyzer = EmailAnalyzer()
    result = analyzer.analyze_email(raw_email)

    assert isinstance(result, AnalysisResult)
    assert result.sender == "professor@university.edu"
    assert result.subject == "OOP Lab Assignment Notes"
    assert result.classification == "Safe"
    assert result.risk_score < 30.0
    assert result.is_phishing is False
    assert "https://cs.university.edu/oop" in result.extracted_urls


def test_analyze_phishing_email_pipeline():
    raw_email = (
        "From: Security Team <security-alert@gmail.com>\n"
        "To: victim@example.com\n"
        "Subject: Urgent: PayPal Account Suspended\n"
        "Date: Mon, 23 Nov 2026 11:15:00 +0000\n"
        'Content-Type: text/html; charset="utf-8"\n\n'
        "<html><body>\n"
        "<p>Unauthorized access detected on your PayPal account.</p>\n"
        "<p>Your account will be suspended within 24 hours.</p>\n"
        '<p>Please enter your password here: <a href="http://192.168.1.200/paypal.php">Verify Now</a></p>\n'
        "</body></html>"
    )
    analyzer = EmailAnalyzer()
    result = analyzer.analyze_email(raw_email)

    assert isinstance(result, AnalysisResult)
    assert result.classification == "Phishing"
    assert result.risk_score >= 60.0
    assert result.is_phishing is True
    assert "http://192.168.1.200/paypal.php" in result.extracted_urls
    assert result.url_findings["suspicious_urls_count"] >= 1
    assert "credential_harvesting" in result.content_findings["categories_detected"]


def test_analyze_suspicious_borderline_email():
    raw_email = (
        "From: recruiter@careers-portal.work\n"
        "To: student@university.edu\n"
        "Subject: Urgent: Review your application status\n"
        "Date: Mon, 23 Nov 2026 14:00:00 +0000\n\n"
        "Hi,\n"
        "Your application requires attention within 24 hours.\n"
        "Check details at https://bit.ly/quick-job-status.\n"
    )
    analyzer = EmailAnalyzer()
    result = analyzer.analyze_email(raw_email)

    assert isinstance(result, AnalysisResult)
    assert result.classification in ("Suspicious", "Phishing")
    assert result.risk_score >= 30.0


def test_analyze_handles_empty_or_malformed_email():
    analyzer = EmailAnalyzer()
    res_empty = analyzer.analyze_email("")
    assert isinstance(res_empty, AnalysisResult)
    assert res_empty.classification == "Safe"

    res_none = analyzer.analyze_email(None)  # type: ignore
    assert isinstance(res_none, AnalysisResult)
    assert res_none.metadata.get("pipeline_stage") == "parsing"


def test_analysis_result_serialization():
    analyzer = EmailAnalyzer()
    raw_email = "From: a@b.com\nSubject: Hi\n\nHello world at https://example.com"
    result = analyzer.analyze_email(raw_email)

    as_dict = result.to_dict()
    assert isinstance(as_dict, dict)
    assert as_dict["sender"] == "a@b.com"
    assert as_dict["extracted_urls"] == ["https://example.com"]

    json_str = result.to_json()
    parsed = json.loads(json_str)
    assert parsed["subject"] == "Hi"

    reconstructed = AnalysisResult.from_dict(as_dict)
    assert reconstructed.sender == result.sender
    assert reconstructed.risk_score == result.risk_score
    assert reconstructed.classification == result.classification
