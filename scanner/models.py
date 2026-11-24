from django.conf import settings
from django.core.validators import (
    FileExtensionValidator,
    MaxValueValidator,
    MinValueValidator,
)
from django.db import models


class ScanReport(models.Model):
    """A saved email scan and its structured analysis results."""

    class Classification(models.TextChoices):
        SAFE = "Safe", "Safe"
        SUSPICIOUS = "Suspicious", "Suspicious"
        PHISHING = "Phishing", "Phishing"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="scan_reports",
    )
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    raw_email = models.TextField()
    uploaded_file = models.FileField(
        upload_to="scans/%Y/%m/%d/",
        blank=True,
        validators=[FileExtensionValidator(allowed_extensions=["eml"])],
    )
    sender = models.CharField(max_length=320, blank=True)
    recipient = models.CharField(max_length=320, blank=True)
    subject = models.CharField(max_length=998, blank=True)
    email_date = models.CharField(max_length=255, blank=True)

    classification = models.CharField(
        max_length=16,
        choices=Classification.choices,
        default=Classification.SAFE,
        db_index=True,
    )
    risk_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
    )
    extracted_urls = models.JSONField(default=list, blank=True)
    url_findings = models.JSONField(default=dict, blank=True)
    content_findings = models.JSONField(default=dict, blank=True)
    analysis_tags = models.JSONField(default=list, blank=True)
    engine_metadata = models.JSONField(default=dict, blank=True)

    # Private user notes provide an editable part of a report without changing
    # the saved engine output.
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(
                fields=["user", "-created_at"], name="scan_user_created_idx"
            ),
            models.Index(
                fields=["user", "classification"], name="scan_user_class_idx"
            ),
        ]

    def __str__(self):
        title = self.subject or "Untitled email"
        return f"{title} — {self.classification}"
