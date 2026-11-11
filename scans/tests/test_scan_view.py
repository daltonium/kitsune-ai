import pytest
from django.contrib.auth import get_user_model

from detectors import registry
from detectors.phishing_url.predictor import PhishingURLDetector
from scans.models import Scan

pytestmark = pytest.mark.django_db
URL = "/api/web/scan/phishing_url/"


@pytest.fixture
def user():
    return get_user_model().objects.create_user("alice", "a@example.com", "pw12345!")


def post(client, path, body):
    return client.post(path, body, content_type="application/json")


def test_requires_login(client):
    assert post(client, URL, {"url": "https://example.com"}).status_code in (401, 403)


def test_unknown_module_404(client, user):
    client.force_login(user)
    assert post(client, "/api/web/scan/nope/", {}).status_code == 404


def test_valid_scan_creates_record(client, user, phishing_detector):
    client.force_login(user)
    res = post(client, URL, {"url": "http://10.0.0.5/login/verify"})
    assert res.status_code == 201
    body = res.json()
    assert body["prediction"] in ("Phishing", "Legitimate") and "scan_id" in body and body["disclaimer"]
    assert Scan.objects.filter(user=user, module="phishing_url").count() == 1


def test_invalid_url_400_and_nothing_saved(client, user, phishing_detector):
    client.force_login(user)
    res = post(client, URL, {"url": "nope"})
    assert res.status_code == 400 and res.json()["error"]["code"] == "invalid_input"
    assert Scan.objects.count() == 0


def test_untrained_model_503(client, user, tmp_path):
    registry.register(PhishingURLDetector)
    registry._INSTANCES["phishing_url"] = PhishingURLDetector(artifacts_dir=tmp_path)
    try:
        client.force_login(user)
        res = post(client, URL, {"url": "https://example.com"})
        assert res.status_code == 503 and res.json()["error"]["code"] == "module_unavailable"
    finally:
        registry._INSTANCES.pop("phishing_url", None)