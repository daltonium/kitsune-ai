import pytest
from django.contrib.auth import get_user_model

from scans.models import Alert, Module, RiskLevel, Scan

pytestmark = pytest.mark.django_db


def make_user():
    return get_user_model().objects.create_user("alice", "a@example.com", "pw12345!")


def test_scan_and_alert_created():
    u = make_user()
    s = Scan.objects.create(
        user=u, module=Module.PHISHING_URL, input_summary="http://example.test",
        prediction="phishing", risk_level=RiskLevel.HIGH, score=0.93,
    )
    a = Alert.objects.create(scan=s, user=u, severity=s.risk_level, title="Phishing URL detected")
    assert s.alert == a
    assert u.scans.count() == 1


def test_user_email_unique():
    make_user()
    with pytest.raises(Exception):
        get_user_model().objects.create_user("bob", "a@example.com", "pw12345!")