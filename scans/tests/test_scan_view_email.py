import pytest
from django.contrib.auth import get_user_model

from scans.models import Scan

pytestmark = pytest.mark.django_db
URL = "/api/web/scan/phishing_email/"


@pytest.fixture
def user():
    return get_user_model().objects.create_user("eve", "eve@example.com", "pw12345!")


def test_email_scan_saved_without_content(client, user, email_detector):
    client.force_login(user)
    body = {"subject": "Urgent: verify your account", "body": "Please verify your account password now: http://a.example.top/x"}
    res = client.post(URL, body, content_type="application/json")
    assert res.status_code == 201 and res.json()["module"] == "phishing_email"
    assert "password" not in Scan.objects.get(user=user).input_summary


def test_email_missing_body_400(client, user, email_detector):
    client.force_login(user)
    res = client.post(URL, {"subject": "hi"}, content_type="application/json")
    assert res.status_code == 400 and res.json()["error"]["code"] == "invalid_input"