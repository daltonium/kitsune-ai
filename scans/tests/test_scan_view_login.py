import pytest
from django.contrib.auth import get_user_model

from detectors.suspicious_login.tests.synthetic import normal_events, odd_event
from scans.models import Scan

pytestmark = pytest.mark.django_db
URL = "/api/web/scan/suspicious_login/"


@pytest.fixture
def user():
    return get_user_model().objects.create_user("sec", "sec@example.com", "pw12345!")


def test_events_scan_saved_without_raw_ids(client, user, login_detector):
    client.force_login(user)
    events = normal_events(5, 60, seed=4, prefix="carol_") + [odd_event("carol_0")]
    res = client.post(URL, {"events": events}, content_type="application/json")
    assert res.status_code == 201 and res.json()["prediction"] == "Suspicious"
    saved = Scan.objects.get(user=user)
    assert "carol_" not in saved.input_summary and "carol_" not in str(saved.explanation)


def test_too_little_history_returns_400(client, user, login_detector):
    client.force_login(user)
    res = client.post(URL, {"events": normal_events(1, 5)}, content_type="application/json")
    assert res.status_code == 400 and res.json()["error"]["code"] == "invalid_input"
    assert Scan.objects.count() == 0