import re

from django.utils import timezone
from rest_framework import serializers

from .models import APIClient, APIKey, APIPlan, Subscription

CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class PlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = APIPlan
        fields = [
            "slug",
            "name",
            "monthly_quota",
            "rate_limit_per_minute",
            "price_inr",
            "allow_pay_as_you_go",
            "overage_price_inr",
        ]


class CompanySerializer(serializers.ModelSerializer):
    class Meta:
        model = APIClient
        fields = [
            "company_name",
            "contact_email",
            "website",
            "is_active",
            "created_at",
        ]


class SubscriptionSerializer(serializers.ModelSerializer):
    plan = PlanSerializer(read_only=True)

    class Meta:
        model = Subscription
        fields = [
            "status",
            "billing_mode",
            "payment_provider",
            "current_period_start",
            "current_period_end",
            "plan",
        ]


class KeySerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField()

    class Meta:
        model = APIKey
        fields = [
            "id",
            "name",
            "prefix",
            "status",
            "created_at",
            "last_used_at",
            "expires_at",
            "revoked_at",
        ]

    def get_status(self, obj):
        if not obj.is_active:
            return "revoked"
        if obj.expires_at and obj.expires_at <= timezone.now():
            return "expired"
        return "active"


class RegisterSerializer(serializers.Serializer):
    company_name = serializers.CharField(min_length=2, max_length=150)
    contact_email = serializers.EmailField()
    website = serializers.URLField(
        required=False, allow_blank=True, default=""
    )

    def validate_company_name(self, value):
        if CONTROL_CHARS.search(value):
            raise serializers.ValidationError(
                "Control characters are not allowed."
            )
        return value

    def validate_website(self, value):
        if value and not value.lower().startswith(("http://", "https://")):
            raise serializers.ValidationError(
                "Website must start with http:// or https://."
            )
        return value


class SubscriptionChangeSerializer(serializers.Serializer):
    plan = serializers.SlugRelatedField(
        slug_field="slug",
        queryset=APIPlan.objects.filter(is_active=True),
    )
    billing_mode = serializers.ChoiceField(
        choices=Subscription.Billing.choices,
        default=Subscription.Billing.MONTHLY,
    )

    def validate(self, attrs):
        payg = attrs["billing_mode"] == Subscription.Billing.PAYG
        if payg and not attrs["plan"].allow_pay_as_you_go:
            raise serializers.ValidationError(
                "This plan does not support pay as you go."
            )
        return attrs


class KeyCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=80, default="default")
    expires_in_days = serializers.IntegerField(
        min_value=1, max_value=365, required=False
    )

    def validate_name(self, value):
        if CONTROL_CHARS.search(value):
            raise serializers.ValidationError(
                "Control characters are not allowed."
            )
        return value


class UsageQuerySerializer(serializers.Serializer):
    days = serializers.IntegerField(min_value=1, max_value=90, default=30)