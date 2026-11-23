"""
Email parsing module for PhishGuard detection engine.

Parses raw RFC 822 / MIME email messages, extracting headers, metadata,
plain-text body, and HTML body into a structured representation without
performing any security classification.
"""

from dataclasses import dataclass, field
import email
from email.header import decode_header, make_header
from email.message import Message
from typing import Any, Dict, List, Optional, Union


class EmailParsingError(Exception):
    """Raised when an email cannot be parsed due to invalid format or structure."""
    pass


@dataclass
class ParsedEmail:
    """
    Data transfer object representing the extracted fields of an email.

    Attributes:
        sender: The sender header string (e.g., 'From: Security Team <sec@bank.com>').
        recipient: The recipient header string (e.g., 'To: victim@example.com').
        subject: The subject line of the email, decoded to Unicode.
        date: The timestamp string extracted from the Date header.
        body_plain: Extracted plain-text body content.
        body_html: Extracted HTML body content, if present.
        headers: Dictionary containing all raw headers as key-value pairs.
        raw_content: The original raw email text passed to the parser.
    """
    sender: str = ""
    recipient: str = ""
    subject: str = ""
    date: str = ""
    body_plain: str = ""
    body_html: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    raw_content: str = ""

    @property
    def full_body(self) -> str:
        """Return combined body text (plain text + html) for unified inspection."""
        parts = [p for p in (self.body_plain, self.body_html) if p]
        return "\n\n".join(parts)


class EmailParser:
    """
    Parses raw RFC 822 / MIME emails using the Python standard email library.

    Extracts sender, recipient, subject, date, headers, and both plain-text
    and HTML bodies across single-part and multipart MIME structures.
    """

    def parse(self, raw_email: Union[str, bytes]) -> ParsedEmail:
        """
        Parse raw email content into a structured ParsedEmail object.

        :param raw_email: The raw email string or bytes.
        :return: ParsedEmail containing extracted fields.
        :raises EmailParsingError: If raw_email is None or of an unsupported type.
        """
        if raw_email is None:
            raise EmailParsingError("Raw email content cannot be None.")

        if not isinstance(raw_email, (str, bytes)):
            raise EmailParsingError(
                f"Expected str or bytes for raw_email, got {type(raw_email).__name__}"
            )

        # Convert bytes to string if needed for raw representation
        raw_text: str = (
            raw_email.decode("utf-8", errors="replace")
            if isinstance(raw_email, bytes)
            else raw_email
        )

        if not raw_text.strip():
            # Return empty ParsedEmail for empty inputs rather than failing abruptly
            return ParsedEmail(raw_content=raw_text)

        try:
            msg: Message = email.message_from_string(raw_text)
        except Exception as exc:
            raise EmailParsingError(f"Failed to parse email message: {exc}") from exc

        # Extract headers safely
        headers: Dict[str, str] = {}
        for key, val in msg.items():
            headers[key] = self._decode_header_value(val)

        sender = self._decode_header_value(msg.get("From", ""))
        recipient = self._decode_header_value(msg.get("To", ""))
        subject = self._decode_header_value(msg.get("Subject", ""))
        date_str = self._decode_header_value(msg.get("Date", ""))

        plain_parts: List[str] = []
        html_parts: List[str] = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                disposition = str(part.get("Content-Disposition", "")).lower()

                # Skip file attachments to preserve security
                if "attachment" in disposition:
                    continue

                payload_text = self._extract_part_text(part)
                if not payload_text:
                    continue

                if content_type == "text/plain":
                    plain_parts.append(payload_text)
                elif content_type == "text/html":
                    html_parts.append(payload_text)
        else:
            content_type = msg.get_content_type()
            payload_text = self._extract_part_text(msg)
            if content_type == "text/html":
                html_parts.append(payload_text)
            else:
                plain_parts.append(payload_text)

        return ParsedEmail(
            sender=sender,
            recipient=recipient,
            subject=subject,
            date=date_str,
            body_plain="\n".join(plain_parts).strip(),
            body_html="\n".join(html_parts).strip(),
            headers=headers,
            raw_content=raw_text,
        )

    def _decode_header_value(self, header_val: Optional[str]) -> str:
        """
        Safely decode RFC 2047 encoded header strings (e.g. =?UTF-8?B?...?=).

        :param header_val: Raw header string.
        :return: Decoded human-readable Unicode string.
        """
        if not header_val:
            return ""
        try:
            return str(make_header(decode_header(header_val)))
        except Exception:
            return str(header_val)

    def _extract_part_text(self, part: Message) -> str:
        """
        Safely decode part payload using the specified or fallback charset.

        :param part: An email Message or MIME part.
        :return: Decoded string content.
        """
        try:
            payload = part.get_payload(decode=True)
            if payload is None:
                # May be a string if decode=True wasn't applicable
                raw_payload = part.get_payload()
                return str(raw_payload) if raw_payload is not None else ""

            if isinstance(payload, bytes):
                charset = part.get_content_charset() or "utf-8"
                try:
                    return payload.decode(charset, errors="replace")
                except (LookupError, UnicodeDecodeError):
                    return payload.decode("latin-1", errors="replace")
            return str(payload)
        except Exception:
            return ""
