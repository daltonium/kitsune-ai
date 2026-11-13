import uuid

from django.conf import settings
from django.db import models


class Module(models.TextChoices):
    PHISHING_URL = "phishing_url", "Phishing URL"
    NETWORK_INTRUSION = "network_intrusion", "Network Intrusion"
    PHISHING_EMAIL = "phishing_email", "Phishing Email"
    MALWARE_RISK = "malware_risk", "Malware Risk"
    SUSPICIOUS_LOGIN = "suspicious_login", "Suspicious Login"


class RiskLevel(models.TextChoices):
    LOW = "low", "Low"
    MEDIUM = "medium", "Medium"
    HIGH = "high", "High"
    CRITICAL = "critical", "Critical"


class Scan(models.Model):
    class Source(models.TextChoices):
        WEB = "web", "Web app"
        API = "api", "Paid API"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="scans"
    )
    source = models.CharField(max_length=3, choices=Source.choices, default=Source.WEB)
    module = models.CharField(max_length=32, choices=Module.choices)
    input_summary = models.CharField(max_length=500, blank=True)
    prediction = models.CharField(max_length=64)
    risk_level = models.CharField(max_length=10, choices=RiskLevel.choices)
    score = models.FloatField(null=True, blank=True)
    explanation = models.JSONField(default=dict, blank=True)
    model_version = models.CharField(max_length=64, blank=True)
    latency_ms = models.PositiveIntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "-created_at"]),
            models.Index(fields=["module", "-created_at"]),
            models.Index(fields=["risk_level"]),
        ]

    def __str__(self):
        return f"{self.module}:{self.prediction} ({self.risk_level})"


class Alert(models.Model):
    scan = models.OneToOneField(Scan, on_delete=models.CASCADE, related_name="alert")
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="alerts"
    )
    severity = models.CharField(max_length=10, choices=RiskLevel.choices)
    title = models.CharField(max_length=200)
    message = models.TextField(blank=True)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["user", "is_read", "-created_at"])]

    def __str__(self):
        return f"[{self.severity}] {self.title}"