"""
URL extraction module for PhishGuard detection engine.

Extracts URLs from plain-text and HTML email content safely without making
any network connections or performing security classifications.
"""

from dataclasses import dataclass
from html.parser import HTMLParser
import re
from typing import List, Optional, Set, Tuple


@dataclass
class ExtractedURL:
    """
    Represents an extracted URL along with its context.

    Attributes:
        url: The extracted URL string.
        source: Source context ('plain_text', 'html_href', or 'html_text').
        anchor_text: Visible anchor text if extracted from an HTML <a> tag.
    """
    url: str
    source: str = "plain_text"
    anchor_text: Optional[str] = None


class _AnchorTagParser(HTMLParser):
    """
    Internal HTML parser helper to safely extract href attributes and anchor text.
    """

    def __init__(self) -> None:
        super().__init__()
        self.links: List[Tuple[str, str]] = []  # (href, anchor_text)
        self._current_href: Optional[str] = None
        self._current_text: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag.lower() == "a":
            attr_dict = {k.lower(): (v or "") for k, v in attrs}
            href = attr_dict.get("href", "").strip()
            if href:
                self._current_href = href
                self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._current_href is not None:
            anchor_text = " ".join("".join(self._current_text).split()).strip()
            self.links.append((self._current_href, anchor_text))
            self._current_href = None
            self._current_text = []


class URLExtractor:
    """
    Extracts HTTP and HTTPS URLs from email plain-text and HTML bodies.

    Guarantees:
    - Deduplication preserving first-seen order.
    - Stripping trailing punctuation adhering to URL syntax.
    - Zero network requests.
    - Safe handling of malformed input and HTML tags.
    """

    # Matches http:// and https:// URLs up to whitespace, quotes, or angle brackets
    _URL_REGEX = re.compile(
        r"(https?://[^\s<>\"'{}|\\^`\[\]]+)",
        re.IGNORECASE,
    )

    # Characters that are often trailing punctuation rather than part of the URL
    _TRAILING_PUNCTUATION = ".,;:!?)'\""

    def extract(self, text: str, html: Optional[str] = None) -> List[ExtractedURL]:
        """
        Extract structured ExtractedURL objects from plain text and HTML.

        :param text: Plain-text email content.
        :param html: Optional HTML email content.
        :return: List of deduplicated ExtractedURL objects.
        """
        results: List[ExtractedURL] = []
        seen_urls: Set[str] = set()

        # 1. Extract from HTML anchor tags if HTML provided
        if html and isinstance(html, str):
            anchor_links = self._extract_from_html_anchors(html)
            for href, anchor_text in anchor_links:
                cleaned = self._clean_url(href)
                if cleaned and self._is_valid_http_url(cleaned) and cleaned not in seen_urls:
                    seen_urls.add(cleaned)
                    results.append(
                        ExtractedURL(
                            url=cleaned,
                            source="html_href",
                            anchor_text=anchor_text if anchor_text else None,
                        )
                    )

            # Also scan raw HTML text for any unlinked URLs
            for raw_url in self._find_regex_urls(html):
                cleaned = self._clean_url(raw_url)
                if cleaned and self._is_valid_http_url(cleaned) and cleaned not in seen_urls:
                    seen_urls.add(cleaned)
                    results.append(ExtractedURL(url=cleaned, source="html_text"))

        # 2. Extract from plain-text body
        if text and isinstance(text, str):
            for raw_url in self._find_regex_urls(text):
                cleaned = self._clean_url(raw_url)
                if cleaned and self._is_valid_http_url(cleaned) and cleaned not in seen_urls:
                    seen_urls.add(cleaned)
                    results.append(ExtractedURL(url=cleaned, source="plain_text"))

        return results

    def extract_urls(self, text: str, html: Optional[str] = None) -> List[str]:
        """
        Convenience method to return only a list of deduplicated URL strings.

        :param text: Plain-text email content.
        :param html: Optional HTML email content.
        :return: List of unique URL strings.
        """
        return [item.url for item in self.extract(text, html)]

    def _find_regex_urls(self, text: str) -> List[str]:
        """Find all regex-matched URL strings in text."""
        if not text:
            return []
        return self._URL_REGEX.findall(text)

    def _extract_from_html_anchors(self, html: str) -> List[Tuple[str, str]]:
        """Safely parse HTML and extract href and anchor text pairs."""
        parser = _AnchorTagParser()
        try:
            parser.feed(html)
            return parser.links
        except Exception:
            # Fall back to regex if HTML parser encounters malformed markup
            fallback_pattern = re.compile(
                r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
                re.IGNORECASE | re.DOTALL,
            )
            matches = fallback_pattern.findall(html)
            clean_matches = []
            for href, anchor in matches:
                clean_anchor = re.sub(r"<[^>]+>", "", anchor).strip()
                clean_matches.append((href.strip(), clean_anchor))
            return clean_matches

    def _clean_url(self, raw_url: str) -> str:
        """Strip trailing punctuation that is not part of the URL."""
        if not raw_url:
            return ""
        url = raw_url.strip()
        while url and url[-1] in self._TRAILING_PUNCTUATION:
            url = url[:-1]
        return url

    def _is_valid_http_url(self, url: str) -> bool:
        """Check if URL starts with http:// or https:// and has minimal host structure."""
        if not url:
            return False
        lower = url.lower()
        if not (lower.startswith("http://") or lower.startswith("https://")):
            return False
        # Must have something after scheme://
        remainder = url.split("://", 1)[-1]
        return len(remainder.strip()) > 0
