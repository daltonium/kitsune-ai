import hashlib
import hmac
import secrets

from django.conf import settings
from django.db import models
from django.utils import timezone


class APIPlan(models.Model):
    name = models.CharField(max_length=50)
    slug = models.SlugField(unique=True)
    monthly_quota = models.PositiveIntegerField()
    rate_limit_per_minute = models.PositiveIntegerField()
    price_inr = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    allow_pay_as_you_go = models.BooleanField(default=False)
    overage_price_inr = models.DecimalField(max_digits=8, decimal_places=4, default=0)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.name


class APIClient(models.Model):
    owner = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="api_client"
    )
    company_name = models.CharField(max_length=150)
    contact_email = models.EmailField()
    website = models.URLField(blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.company_name


class Subscription(models.Model):
    class Status(models.TextChoices):
        TRIAL = "trial", "Trial"
        ACTIVE = "active", "Active"
        PAST_DUE = "past_due", "Past due"
        CANCELLED = "cancelled", "Cancelled"

    class Billing(models.TextChoices):
        MONTHLY = "monthly", "Monthly"
        PAYG = "payg", "Pay as you go"

    client = models.ForeignKey(
        APIClient, on_delete=models.CASCADE, related_name="subscriptions"
    )
    plan = models.ForeignKey(APIPlan, on_delete=models.PROTECT, related_name="subscriptions")
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.ACTIVE)
    billing_mode = models.CharField(max_length=7, choices=Billing.choices, default=Billing.MONTHLY)
    payment_provider = models.CharField(max_length=30, default="dummy")
    external_ref = models.CharField(max_length=100, blank=True)
    current_period_start = models.DateTimeField(default=timezone.now)
    current_period_end = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["client"],
                condition=models.Q(status="active"),
                name="one_active_subscription_per_client",
            )
        ]

    def __str__(self):
        return f"{self.client} - {self.plan} ({self.status})"


class APIKey(models.Model):
    client = models.ForeignKey(APIClient, on_delete=models.CASCADE, related_name="api_keys")
    name = models.CharField(max_length=80, default="default")
    prefix = models.CharField(max_length=12, db_index=True)
    key_hash = models.CharField(max_length=64, unique=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.prefix}... ({self.client})"

    @staticmethod
    def hash_key(raw: str) -> str:
        pepper = settings.API_KEY_PEPPER.encode()
        return hmac.new(pepper, raw.encode(), hashlib.sha256).hexdigest()

    @classmethod
    def issue(cls, client, name="default", expires_at=None):
        """Create a key. Returns (APIKey, raw_key). The raw key is never stored."""
        raw = f"ksn_{secrets.token_urlsafe(32)}"
        obj = cls.objects.create(
            client=client,
            name=name,
            prefix=raw[:12],
            key_hash=cls.hash_key(raw),
            expires_at=expires_at,
        )
        return obj, raw

    def revoke(self):
        self.is_active = False
        self.revoked_at = timezone.now()
        self.save(update_fields=["is_active", "revoked_at"])

    @property
    def is_valid(self):
        if not self.is_active:
            return False
        return not (self.expires_at and self.expires_at <= timezone.now())


class APIUsage(models.Model):
    client = models.ForeignKey(APIClient, on_delete=models.CASCADE, related_name="usage")
    api_key = models.ForeignKey(
        APIKey, on_delete=models.SET_NULL, null=True, blank=True, related_name="usage"
    )
    scan = models.ForeignKey(
        "scans.Scan", on_delete=models.SET_NULL, null=True, blank=True, related_name="api_usage"
    )
    endpoint = models.CharField(max_length=100)
    module = models.CharField(max_length=32, blank=True)
    status_code = models.PositiveSmallIntegerField()
    response_time_ms = models.PositiveIntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["client", "-created_at"]),
            models.Index(fields=["api_key", "-created_at"]),
        ]

    def __str__(self):
        return f"{self.endpoint} {self.status_code}"