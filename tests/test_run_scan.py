import pytest
from django.contrib.auth import get_user_model

from detectors import registry
from detectors.base import BaseDetector, DetectionResult, RISK_ORDER, risk_from_score
from detectors.exceptions import DetectorNotFoundError, InvalidInputError
from scans.models import Alert, RiskLevel, Scan
from scans.services import run_scan

pytestmark = pytest.mark.django_db


class FakeDetector(BaseDetector):
    key = "phishing_url"
    display_name = "Phishing URL"
    version = "test-1"

    def load(self):
        pass

    def validate_input(self, payload):
        if "url" not in payload:
            raise InvalidInputError("url is required")
        return payload

    def _predict(self, data):
        score = 0.95 if "evil" in data["url"] else 0.05
        return DetectionResult(
            prediction="phishing" if score > 0.5 else "benign",
            risk_level=risk_from_score(score),
            score=score,
            explanation={"top_features": ["demo"]},
            model_version=self.version,
            input_summary=data["url"],
        )


@pytest.fixture(autouse=True)
def fake_registered():
    registry.register(FakeDetector)
    yield
    registry.unregister("phishing_url")


@pytest.fixture
def user():
    return get_user_model().objects.create_user("alice", "a@example.com", "pw12345!")


def test_high_risk_creates_alert(user):
    scan = run_scan(user=user, module="phishing_url", payload={"url": "http://evil.test"})
    assert scan.risk_level == "critical"
    assert Alert.objects.filter(scan=scan, user=user).exists()


def test_low_risk_no_alert(user):
    scan = run_scan(user=user, module="phishing_url", payload={"url": "http://ok.test"})
    assert scan.risk_level == "low"
    assert not Alert.objects.exists()


def test_invalid_input_saves_nothing(user):
    with pytest.raises(InvalidInputError):
        run_scan(user=user, module="phishing_url", payload={})
    assert Scan.objects.count() == 0


def test_unknown_module_raises(user):
    with pytest.raises(DetectorNotFoundError):
        run_scan(user=user, module="malware_risk", payload={})


def test_api_source_and_risk_levels_match(user):
    scan = run_scan(user=user, module="phishing_url", payload={"url": "x"}, source=Scan.Source.API)
    assert scan.source == "api"
    assert set(RISK_ORDER) == set(RiskLevel.values)


def test_modules_endpoint_requires_login(client):
    assert client.get("/api/web/modules/").status_code in (401, 403)


def test_modules_endpoint_lists_six(client, user):
    client.force_login(user)
    res = client.get("/api/web/modules/")
    assert res.status_code == 200
    assert len(res.json()) == 6