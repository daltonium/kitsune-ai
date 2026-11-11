from django.contrib import admin

from .models import APIClient, APIKey, APIPlan, APIUsage, Subscription


@admin.register(APIPlan)
class APIPlanAdmin(admin.ModelAdmin):
    list_display = ("name", "monthly_quota", "rate_limit_per_minute", "price_inr", "is_active")


@admin.register(APIClient)
class APIClientAdmin(admin.ModelAdmin):
    list_display = ("company_name", "owner", "is_active", "created_at")


@admin.register(Subscription)
class SubscriptionAdmin(admin.ModelAdmin):
    list_display = ("client", "plan", "status", "billing_mode", "current_period_end")
    list_filter = ("status", "plan")


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    list_display = ("prefix", "client", "name", "is_active", "last_used_at")
    exclude = ("key_hash",)
    readonly_fields = ("prefix", "created_at", "revoked_at", "last_used_at")


@admin.register(APIUsage)
class APIUsageAdmin(admin.ModelAdmin):
    list_display = ("client", "endpoint", "status_code", "response_time_ms", "created_at")
    list_filter = ("status_code", "module")