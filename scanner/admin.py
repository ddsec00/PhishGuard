from django.contrib import admin

from .models import ScanReport


@admin.register(ScanReport)
class ScanReportAdmin(admin.ModelAdmin):
    list_display = (
        "subject",
        "sender",
        "classification",
        "risk_score",
        "user",
        "created_at",
    )
    list_filter = ("classification", "created_at")
    search_fields = (
        "subject",
        "sender",
        "recipient",
        "user__username",
        "user__email",
    )
    readonly_fields = ("created_at", "updated_at")
    list_select_related = ("user",)
