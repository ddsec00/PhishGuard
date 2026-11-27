"""
Scanner service layer.

Connects the Django web application to the underlying phishing detection engine and handles persistance of ScanReport records.
"""

from decimal import Decimal
import logging
from typing import Any, List, Optional

from django.core.files.uploadedfile import UploadedFile
from django.db import DatabaseError, transaction

from analyzer.email_analyzer import EmailAnalyzer
from analyzer.result import AnalysisResult
from .models import ScanReport

logger = logging.getLogger(__name__)


class ScanServiceError(Exception):
    """Raised when email extraction, analysis, or report persistence fails."""
    pass

class ScanService:
    """Application service coordinating email input processing and phishing detection."""
    def __init__(self, analyzer: Optional[EmailAnalyzer] = None) -> None:
        """
        Initialize ScanService with an EmailAnalyzer instance.

        :param analyzer: Optional EmailAnalyzer instance for dependency injection.
        """
        self.analyzer: EmailAnalyzer = analyzer or EmailAnalyzer()

    def extract_email_content(
        self,
        raw_email: str = "",
        uploaded_file: Optional[UploadedFile] = None,
    ) -> str:
        """
        Validate and extract raw email text from either pasted content or a .eml file.

        :param raw_email: Pasted raw RFC 822 email string.
        :param uploaded_file: Uploaded .eml file object.
        :return: Clean raw email string ready for analysis.
        :raises ScanServiceError: If input is missing, ambiguous, invalid, or empty.
        """
        cleaned_text = (raw_email or "").strip()

        if cleaned_text and uploaded_file is not None:
            raise ScanServiceError(
                "Choose pasted email content or one .eml file, not both."
            )

        if uploaded_file is not None:
            file_name = getattr(uploaded_file, "name", "")
            if not file_name.lower().endswith(".eml"):
                raise ScanServiceError(
                    "Upload an email file with the .eml extension."
                )
            try:
                if hasattr(uploaded_file, "seek"):
                    uploaded_file.seek(0)
                file_bytes = uploaded_file.read()
                if hasattr(uploaded_file, "seek"):
                    uploaded_file.seek(0)
            except Exception as exc:
                logger.error("Failed to read uploaded .eml file: %s", exc)
                raise ScanServiceError(
                    "Could not read the uploaded .eml file."
                ) from exc

            if isinstance(file_bytes, bytes):
                cleaned_text = file_bytes.decode("utf-8", errors="replace").strip()
            else:
                cleaned_text = str(file_bytes).strip()

            if not cleaned_text:
                raise ScanServiceError("The uploaded .eml file is empty.")

            return cleaned_text

        if not cleaned_text:
            raise ScanServiceError(
                "Provide either pasted email content or one .eml file."
            )

        return cleaned_text