"""Unit tests for EmailParser component."""

import pytest
from analyzer.email_parser import EmailParser, EmailParsingError, ParsedEmail


def test_parse_simple_plain_text_email():
    raw_email = (
        "From: alice@example.com\n"
        "To: bob@example.com\n"
        "Subject: Project Discussion\n"
        "Date: Mon, 23 Nov 2026 10:00:00 +0000\n\n"
        "Hello Bob,\nLet's review the code tomorrow.\n"
    )
    parser = EmailParser()
    result = parser.parse(raw_email)

    assert isinstance(result, ParsedEmail)
    assert result.sender == "alice@example.com"
    assert result.recipient == "bob@example.com"
    assert result.subject == "Project Discussion"
    assert result.date == "Mon, 23 Nov 2026 10:00:00 +0000"
    assert "review the code tomorrow" in result.body_plain
    assert result.body_html == ""


def test_parse_multipart_email():
    raw_multipart = (
        "MIME-Version: 1.0\n"
        "From: alerts@service.com\n"
        "To: user@example.com\n"
        "Subject: Service Notification\n"
        'Content-Type: multipart/alternative; boundary="boundary_abc"\n\n'
        "--boundary_abc\n"
        'Content-Type: text/plain; charset="utf-8"\n\n'
        "Plain text notification body.\n"
        "--boundary_abc\n"
        'Content-Type: text/html; charset="utf-8"\n\n'
        "<p>HTML notification body.</p>\n"
        "--boundary_abc--\n"
    )
    parser = EmailParser()
    result = parser.parse(raw_multipart)

    assert "Plain text notification body." in result.body_plain
    assert "<p>HTML notification body.</p>" in result.body_html
    assert "Plain text notification body." in result.full_body
    assert "<p>HTML notification body.</p>" in result.full_body


def test_parse_missing_headers():
    raw_email = "Just a body message without any RFC headers at all."
    parser = EmailParser()
    result = parser.parse(raw_email)

    assert result.sender == ""
    assert result.subject == ""
    assert result.date == ""
    assert "Just a body message" in result.body_plain


def test_parse_empty_email():
    parser = EmailParser()
    result = parser.parse("")

    assert isinstance(result, ParsedEmail)
    assert result.sender == ""
    assert result.subject == ""
    assert result.body_plain == ""
    assert result.raw_content == ""


def test_parse_encoded_subject():
    raw_email = (
        "From: sender@example.com\n"
        "Subject: =?UTF-8?B?U2VjdXJpdHkgQWxlcnQ=?=\n\n"
        "Encoded header test.\n"
    )
    parser = EmailParser()
    result = parser.parse(raw_email)

    assert result.subject == "Security Alert"


def test_parse_invalid_type_raises_error():
    parser = EmailParser()
    with pytest.raises(EmailParsingError):
        parser.parse(12345)  # type: ignore

    with pytest.raises(EmailParsingError):
        parser.parse(None)  # type: ignore


def test_parse_bytes_input():
    raw_bytes = b"From: user@test.com\nSubject: Bytes Test\n\nContent in bytes."
    parser = EmailParser()
    result = parser.parse(raw_bytes)

    assert result.sender == "user@test.com"
    assert result.subject == "Bytes Test"
    assert "Content in bytes." in result.body_plain
