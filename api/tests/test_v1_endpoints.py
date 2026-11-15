import json
from datetime import timedelta

import pytest
from django.utils import timezone

from api.models import APIClient as Company
from api.models import APIKey, APIPlan, APIUsage, Subscription
from api.quota import enforce_access
from detectors import registry
from detectors.base import DetectionResult
from detectors.exceptions import InvalidInputError, ModelNotLoadedError
from scans.models import Scan

pytestmark = pytest.mark.django_db

PATHS = [
    ("/api/v1/phishing-url/scan/", "phishing_url"),
    ("/api/v1/network-intrusion/scan/", "network_intrusion"),
    ("/api/v1/phishing-email/scan/", "phishing_email"),
    ("/api/v1/malware/scan/", "malware_risk"),
    ("/api/v1/suspicious-login/analyze/", "suspicious_login"),
]
URL_PATH = PATHS[0][0]


class StubDetector:
    display_name = "Stub"

    def __init__(self):
        self.error = None
        self.payloads = []

    def analyze(self, payload):
        self.payloads.append(payload)
        if self.error:
            raise self.error
        return DetectionResult(
            prediction="Phishing",
            risk_level="high",
            score=0.9,
            explanation={"summary": "stub"},
            model_version="stub-1",
            input_summary="stub input",
        )


@pytest.fixture
def stub(monkeypatch):
    detector = StubDetector()
    monkeypatch.setattr(registry, "get_detector", lambda module: detector)
    return detector


@pytest.fixture
def plan():
    return APIPlan.objects.create(
        name="V1 plan",
        slug="v1-plan-x",
        monthly_quota=3,
        rate_limit_per_minute=100,
    )


@pytest.fixture
def company(django_user_model):
    user = django_user_model.objects.create_user(
        "v1acme", "v1acme@example.com", "pw-12345!"
    )
    return Company.objects.create(
        owner=user,
        company_name="V1 Acme",
        contact_email="v1acme@example.com",
    )


@pytest.fixture
def subscription(company, plan):
    now = timezone.now()
    return Subscription.objects.create(
        client=company,
        plan=plan,
        current_period_start=now - timedelta(days=1),
        current_period_end=now + timedelta(days=29),
    )


@pytest.fixture
def key(company):
    return APIKey.issue(company)


def post(client, path, raw=None, data=None, content=None):
    headers = {"HTTP_AUTHORIZATION": f"Bearer {raw}"} if raw else {}
    body = content if content is not None else json.dumps(
        data if data is not None else {"x": 1}
    )
    return client.post(
        path,
        data=body,
        content_type="application/json",
        **headers,
    )


def add_usage(company, api_key, n, status=201, age=timedelta(minutes=5)):
    for _ in range(n):
        row = APIUsage.objects.create(
            client=company,
            api_key=api_key,
            endpoint="/api/v1/x/",
            module="phishing_url",
            status_code=status,
        )
        APIUsage.objects.filter(pk=row.pk).update(
            created_at=timezone.now() - age
        )


def test_missing_key_returns_401(client, stub):
    res = post(client, URL_PATH)
    assert res.status_code == 401
    assert res.json()["error"]["code"] == "not_authenticated"
    assert "Bearer" in res["WWW-Authenticate"]


def test_invalid_key_returns_401(client, stub):
    res = post(client, URL_PATH, raw="ksn_" + "z" * 43)
    assert res.status_code == 401
    assert res.json()["error"]["code"] == "authentication_failed"


@pytest.mark.parametrize("path,module", PATHS)
def test_endpoint_scans_with_api_source(
    client, stub, company, subscription, key, path, module
):
    api_key, raw = key
    res = post(client, path, raw=raw)
    assert res.status_code == 201
    scan = Scan.objects.get()
    assert scan.module == module
    assert scan.source == "api"
    assert scan.user == company.owner
    usage = APIUsage.objects.get()
    assert usage.status_code == 201
    assert usage.api_key_id == api_key.pk
    assert usage.scan_id == scan.id
    assert usage.module == module


def test_trailing_slash_is_optional(client, stub, subscription, key):
    res = post(client, "/api/v1/phishing-url/scan", raw=key[1])
    assert res.status_code == 201


def test_session_login_is_not_enough(client, stub, company, subscription):
    client.force_login(company.owner)
    assert post(client, URL_PATH).status_code == 401


def test_quota_headers(client, stub, subscription, key):
    res = post(client, URL_PATH, raw=key[1])
    assert res["X-Quota-Limit"] == "3"
    assert res["X-Quota-Remaining"] == "2"


def test_invalid_input_is_400_and_not_billed(
    client, stub, subscription, key
):
    stub.error = InvalidInputError("bad input")
    res = post(client, URL_PATH, raw=key[1])
    assert res.status_code == 400
    assert res.json()["error"]["code"] == "invalid_input"
    assert Scan.objects.count() == 0
    assert APIUsage.objects.get().status_code == 400
    assert enforce_access(key[0]).used == 0


def test_unloaded_model_is_503(client, stub, subscription, key):
    stub.error = ModelNotLoadedError("not trained")
    res = post(client, URL_PATH, raw=key[1])
    assert res.status_code == 503
    assert res.json()["error"]["code"] == "module_unavailable"


def test_quota_exhausted_is_429(client, stub, company, subscription, key):
    add_usage(company, key[0], n=3)
    res = post(client, URL_PATH, raw=key[1])
    assert res.status_code == 429
    assert res.json()["error"]["code"] == "quota_exceeded"
    assert "Retry-After" in res
    assert Scan.objects.count() == 0
    assert APIUsage.objects.filter(status_code=429).count() == 1


def test_rate_limit_is_429(client, stub, subscription, key, plan):
    plan.rate_limit_per_minute = 1
    plan.save(update_fields=["rate_limit_per_minute"])
    assert post(client, URL_PATH, raw=key[1]).status_code == 201
    res = post(client, URL_PATH, raw=key[1])
    assert res.status_code == 429
    assert res.json()["error"]["code"] == "rate_limited"


def test_no_subscription_is_403(client, stub, key):
    res = post(client, URL_PATH, raw=key[1])
    assert res.status_code == 403
    assert res.json()["error"]["code"] == "no_active_subscription"


def test_revoked_key_is_401(client, stub, subscription, key):
    key[0].revoke()
    assert post(client, URL_PATH, raw=key[1]).status_code == 401


def test_oversized_body_is_413(client, stub, subscription, key):
    res = post(client, URL_PATH, raw=key[1], data={"url": "a" * 70_000})
    assert res.status_code == 413
    assert res.json()["error"]["code"] == "payload_too_large"
    assert Scan.objects.count() == 0


def test_malformed_json_is_400(client, stub, subscription, key):
    res = post(client, URL_PATH, raw=key[1], content="{bad")
    assert res.status_code == 400
    assert res.json()["error"]["code"] == "parse_error"


def test_get_is_405(client, stub, subscription, key):
    res = client.get(URL_PATH, HTTP_AUTHORIZATION=f"Bearer {key[1]}")
    assert res.status_code == 405
    assert res.json()["error"]["code"] == "method_not_allowed"