"""Unit tests for RiskScorer component."""

from analyzer.risk_scorer import RiskScorer


def test_risk_scorer_minimum_score():
    scorer = RiskScorer()
    result = scorer.calculate(url_findings={}, content_findings={}, sender="")

    assert result["risk_score"] == 0.0
    assert result["classification"] == "Safe"
    assert len(result["applied_indicators"]) == 0


def test_risk_scorer_maximum_score_clamping():
    scorer = RiskScorer()
    url_findings = {
        "indicator_summary": {
            "ip_address_host": 1,
            "brand_impersonation": 1,
            "url_shortener": 1,
            "misleading_at_symbol": 1,
        },
        "suspicious_urls_count": 2,
    }
    content_findings = {
        "categories_detected": [
            "credential_harvesting",
            "urgency_pressure",
            "account_threats",
            "sensitive_personal_info",
        ]
    }
    sender = "PayPal Alert <fake_paypal@gmail.com>"
    result = scorer.calculate(url_findings, content_findings, sender=sender)

    assert result["risk_score"] == 100.0
    assert result["classification"] == "Phishing"


def test_threshold_boundaries():
    scorer = RiskScorer(safe_max=29.0, suspicious_max=59.0)

    assert scorer.classify(0.0) == "Safe"
    assert scorer.classify(29.0) == "Safe"
    assert scorer.classify(29.1) == "Suspicious"
    assert scorer.classify(30.0) == "Suspicious"
    assert scorer.classify(59.0) == "Suspicious"
    assert scorer.classify(59.1) == "Phishing"
    assert scorer.classify(60.0) == "Phishing"
    assert scorer.classify(100.0) == "Phishing"


def test_indicator_deduplication():
    scorer = RiskScorer()
    # 5 shortened URLs should only apply the shortener weight once
    url_findings = {
        "indicator_summary": {"url_shortener": 5},
        "suspicious_urls_count": 5,
    }
    result = scorer.calculate(url_findings, content_findings={}, sender="")

    applied = result["applied_indicators"]
    assert len(applied) == 1
    assert applied[0]["indicator"] == "url_shortener"
    assert result["risk_score"] == 10.0


def test_suspicious_sender_detection():
    scorer = RiskScorer()
    res1 = scorer.calculate({}, {}, sender="Support <support@legitimate-company.com>")
    assert not any(i["indicator"] == "suspicious_sender" for i in res1["applied_indicators"])

    res2 = scorer.calculate({}, {}, sender="Netflix Account <netflix_billing@gmail.com>")
    assert any(i["indicator"] == "suspicious_sender" for i in res2["applied_indicators"])


def test_custom_weights():
    custom_weights = {"credential_request": 50.0, "urgency_language": 15.0}
    scorer = RiskScorer(weights=custom_weights)

    content_findings = {"categories_detected": ["credential_harvesting", "urgency_pressure"]}
    result = scorer.calculate({}, content_findings, sender="")

    # 50.0 + 15.0 = 65.0 (Phishing)
    assert result["risk_score"] == 65.0
    assert result["classification"] == "Phishing"
