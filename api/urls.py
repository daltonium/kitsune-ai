from django.urls import re_path

from .views import (
    MalwareScanView,
    NetworkIntrusionScanView,
    PhishingEmailScanView,
    PhishingUrlScanView,
    SuspiciousLoginAnalyzeView,
)

urlpatterns = [
    re_path(
        r"^phishing-url/scan/?$",
        PhishingUrlScanView.as_view(),
        name="v1-phishing-url",
    ),
    re_path(
        r"^network-intrusion/scan/?$",
        NetworkIntrusionScanView.as_view(),
        name="v1-network-intrusion",
    ),
    re_path(
        r"^phishing-email/scan/?$",
        PhishingEmailScanView.as_view(),
        name="v1-phishing-email",
    ),
    re_path(
        r"^malware/scan/?$",
        MalwareScanView.as_view(),
        name="v1-malware",
    ),
    re_path(
        r"^suspicious-login/analyze/?$",
        SuspiciousLoginAnalyzeView.as_view(),
        name="v1-suspicious-login",
    ),
]