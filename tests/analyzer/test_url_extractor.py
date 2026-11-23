"""Unit tests for URLExtractor component."""

from analyzer.url_extractor import URLExtractor, ExtractedURL


def test_extract_single_url():
    text = "Please check our guide at https://docs.example.com/start for details."
    extractor = URLExtractor()
    urls = extractor.extract_urls(text)

    assert urls == ["https://docs.example.com/start"]


def test_extract_multiple_urls():
    text = "Primary site: https://example.org and secondary: http://backup.net/api."
    extractor = URLExtractor()
    urls = extractor.extract_urls(text)

    assert urls == ["https://example.org", "http://backup.net/api"]


def test_extract_duplicate_urls():
    text = "Visit https://test.com once, and visit https://test.com twice."
    extractor = URLExtractor()
    urls = extractor.extract_urls(text)

    assert urls == ["https://test.com"]


def test_extract_no_urls():
    text = "Hello team, let us meet in room 402 at 2:00 PM without any laptops."
    extractor = URLExtractor()
    urls = extractor.extract_urls(text)

    assert urls == []


def test_extract_strips_trailing_punctuation():
    text = "Links in punctuation: (https://example.com/page), https://example.com/dot. or https://example.com/exclamation!"
    extractor = URLExtractor()
    urls = extractor.extract_urls(text)

    assert "https://example.com/page" in urls
    assert "https://example.com/dot" in urls
    assert "https://example.com/exclamation" in urls


def test_extract_from_html_anchor_tags():
    html = '<p>Click <a href="https://secure.bank.com/login">here to sign in</a></p>'
    extractor = URLExtractor()
    extracted = extractor.extract(text="", html=html)

    assert len(extracted) == 1
    assert isinstance(extracted[0], ExtractedURL)
    assert extracted[0].url == "https://secure.bank.com/login"
    assert extracted[0].source == "html_href"
    assert extracted[0].anchor_text == "here to sign in"


def test_extract_handles_malformed_input():
    extractor = URLExtractor()
    assert extractor.extract_urls("") == []
    assert extractor.extract_urls("http:// with no host") == []
    assert extractor.extract(text="", html="<a href=''>empty href</a>") == []
