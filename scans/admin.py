from django.contrib import admin

from .models import Alert, Scan


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ("module", "prediction", "risk_level", "score", "user", "source", "created_at")
    list_filter = ("module", "risk_level", "source")
    search_fields = ("input_summary", "user__username")
    readonly_fields = ("id", "created_at")


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ("title", "severity", "user", "is_read", "created_at")
    list_filter = ("severity", "is_read")