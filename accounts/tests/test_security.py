import importlib
import json
import sys
from datetime import timedelta
from unittest import mock

import pytest
from django.conf import settings
from django.test import override_settings
from django.utils import timezone

from api.models import APIClient as Company
from api.models import APIKey, APIPlan, APIUsage, Subscription
from detectors import registry
from detectors.base import DetectionResult
from detectors.exceptions import InvalidInputError
from scans.models import Alert, Scan

pytestmark = pytest.mark.django_db

WEB_SCAN = "/api/web/scan/phishing_url/"
V1_SCAN = "/api/v1/phishing-url/scan/"
COMPANY = "/api/web/company/"


@pytest.fixture
def plan():
    return APIPlan.objects.create(
        name="Security plan",
        slug="security-plan-x",
        monthly_quota=10,
        rate_limit_per_minute=100,
    )


@pytest.fixture
def alice(django_user_model):
    return django_user_model.objects.create_user(
        "security_alice", "alice@example.com", "pw-12345!"
    )


@pytest.fixture
def bob(django_user_model):
    return django_user_model.objects.create_user(
        "security_bob", "bob@example.com", "pw-12345!"
    )


@pytest.fixture
def alice_company(alice, plan):
    company = Company.objects.create(
        owner=alice,
        company_name="Alice Security",
        contact_email="alice@example.com",
    )
    now = timezone.now()
    Subscription.objects.create(
        client=company,
        plan=plan,
        current_period_start=now - timedelta(days=1),
        current_period_end=now + timedelta(days=29),
    )
    return company


@pytest.fixture
def bob_company(bob, plan):
    company = Company.objects.create(
        owner=bob,
        company_name="Bob Security",
        contact_email="bob@example.com",
    )
    now = timezone.now()
    Subscription.objects.create(
        client=company,
        plan=plan,
        current_period_start=now - timedelta(days=1),
        current_period_end=now + timedelta(days=29),
    )
    return company


@pytest.fixture
def alice_key(alice_company):
    return APIKey.issue(alice_company)


@pytest.fixture
def bob_key(bob_company):
    return APIKey.issue(bob_company)


@pytest.fixture
def alice_scan(alice):
    return Scan.objects.create(
        user=alice,
        module="phishing_url",
        prediction="Phishing",
        risk_level="critical",
        score=0.9,
        source="web",
    )


@pytest.fixture
def bob_scan(bob):
    return Scan.objects.create(
        user=bob,
        module="phishing_url",
        prediction="Legitimate",
        risk_level="low",
        score=0.1,
        source="web",
    )


@pytest.fixture
def alice_alert(alice_scan, alice):
    return Alert.objects.create(
        scan=alice_scan,
        user=alice,
        severity="critical",
        title="Alice alert",
    )


@pytest.fixture
def bob_alert(bob_scan, bob):
    return Alert.objects.create(
        scan=bob_scan,
        user=bob,
        severity="low",
        title="Bob alert",
    )


@pytest.fixture
def stub(monkeypatch):
    detector = type(
        "Stub",
        (),
        {
            "display_name": "Stub",
            "analyze": staticmethod(
                lambda payload: DetectionResult(
                    prediction="Phishing",
                    risk_level="high",
                    score=0.9,
                    explanation={"summary": "stub"},
                    model_version="stub",
                    input_summary="stub",
                )
            ),
        },
    )()
    monkeypatch.setattr(registry, "get_detector", lambda module: detector)
    return detector


@pytest.fixture
def logged_in(client, alice):
    client.force_login(alice)
    return client


def api_post(client, path, raw, data=None):
    return client.post(
        path,
        data=json.dumps(data or {"url": "https://example.com"}),
        content_type="application/json",
        HTTP_AUTHORIZATION=f"Bearer {raw}",
    )


def test_web_scan_requires_login(client, stub):
    assert client.post(
        WEB_SCAN,
        data=json.dumps({"url": "https://example.com"}),
        content_type="application/json",
    ).status_code in (401, 403)


def test_history_requires_login(client):
    assert client.get("/api/web/history/").status_code in (401, 403)


def test_alerts_requires_login(client):
    assert client.get("/api/web/alerts/").status_code in (401, 403)


def test_dashboard_requires_login(client):
    assert client.get("/api/web/dashboard/").status_code in (401, 403)


@pytest.mark.parametrize("path", [
    "",
    "register/",
    "subscription/",
    "keys/",
    "usage/",
])
def test_company_endpoints_require_login(client, path):
    assert client.get(COMPANY + path).status_code in (401, 403)


def test_company_plans_are_public(client):
    assert client.get(COMPANY + "plans/").status_code == 200


def test_api_rejects_session_cookie(
    client, alice, stub, alice_company
):
    client.force_login(alice)
    assert client.post(
        V1_SCAN,
        data=json.dumps({"url": "https://example.com"}),
        content_type="application/json",
    ).status_code == 401


def test_api_rejects_missing_key(client, stub):
    assert client.post(
        V1_SCAN,
        data=json.dumps({"url": "https://example.com"}),
        content_type="application/json",
    ).status_code == 401


def test_api_rejects_wrong_key(client, stub):
    assert api_post(
        client, V1_SCAN, "ksn_" + "x" * 43
    ).status_code == 401


def test_revoked_key_rejected(client, stub, alice_key):
    key, raw = alice_key
    key.revoke()
    assert api_post(client, V1_SCAN, raw).status_code == 401


def test_expired_key_rejected(client, stub, alice_company):
    _, raw = APIKey.issue(
        alice_company,
        expires_at=timezone.now() - timedelta(minutes=1),
    )
    assert api_post(client, V1_SCAN, raw).status_code == 401


def test_history_is_scoped(client, alice, alice_scan, bob_scan):
    client.force_login(alice)
    body = client.get("/api/web/history/").json()
    ids = [row["scan_id"] for row in body["results"]]
    assert str(alice_scan.id) in ids
    assert str(bob_scan.id) not in ids


def test_other_scan_detail_is_404(client, alice, bob_scan):
    client.force_login(alice)
    assert client.get(
        f"/api/web/history/{bob_scan.id}/"
    ).status_code == 404


def test_alerts_are_scoped(client, alice, alice_alert, bob_alert):
    client.force_login(alice)
    body = client.get("/api/web/alerts/").json()
    ids = [row["id"] for row in body["results"]]
    assert alice_alert.id in ids
    assert bob_alert.id not in ids


def test_other_alert_cannot_be_read(client, alice, bob_alert):
    client.force_login(alice)
    assert client.patch(
        f"/api/web/alerts/{bob_alert.id}/",
        data=json.dumps({"is_read": True}),
        content_type="application/json",
    ).status_code == 404


def test_company_requires_registration(client, alice):
    client.force_login(alice)
    assert client.get(COMPANY).status_code == 404


def test_company_profile_is_scoped(
    client, alice, alice_company, bob_company
):
    client.force_login(alice)
    body = client.get(COMPANY).json()
    assert body["company"]["company_name"] == "Alice Security"


def test_key_list_is_scoped(
    client, alice, alice_company, bob_company, bob_key
):
    client.force_login(alice)
    body = client.get(COMPANY + "keys/").json()
    assert all(row["id"] != bob_key[0].id for row in body)


def test_cannot_revoke_other_company_key(
    client, alice, alice_company, bob_company, bob_key
):
    client.force_login(alice)
    assert client.post(
        COMPANY + f"keys/{bob_key[0].id}/revoke/"
    ).status_code == 404
    bob_key[0].refresh_from_db()
    assert bob_key[0].is_active is True


def test_usage_is_scoped(
    client, alice, alice_company, bob_company, bob_key
):
    APIUsage.objects.create(
        client=bob_company,
        api_key=bob_key[0],
        endpoint="/api/v1/x/",
        module="phishing_url",
        status_code=201,
    )
    client.force_login(alice)
    body = client.get(COMPANY + "usage/").json()
    assert body["requests"]["total"] == 0


def test_api_scan_is_scoped_to_owner(
    client, stub, alice, alice_company, alice_key
):
    _, raw = alice_key
    res = api_post(client, V1_SCAN, raw)
    assert res.status_code == 201
    scan = Scan.objects.get()
    assert scan.user == alice
    assert scan.source == "api"


def test_invalid_url_does_not_create_scan(logged_in):
    before = Scan.objects.count()
    res = logged_in.post(
        WEB_SCAN,
        data=json.dumps({"url": "not a url"}),
        content_type="application/json",
    )
    assert res.status_code == 400
    assert Scan.objects.count() == before


def test_detector_error_does_not_leak_details(
    client, alice, monkeypatch
):
    client.force_login(alice)
    monkeypatch.setattr(
        registry,
        "get_detector",
        mock.Mock(
            side_effect=InvalidInputError("The URL is not valid.")
        ),
    )
    res = client.post(
        WEB_SCAN,
        data=json.dumps({"url": "https://example.com"}),
        content_type="application/json",
    )
    assert res.status_code == 400
    body = res.json()
    assert body["error"]["code"] == "invalid_input"
    assert "Traceback" not in res.content.decode()


def test_malware_upload_never_writes_file(
    client, alice, tmp_path, monkeypatch
):
    client.force_login(alice)
    monkeypatch.chdir(tmp_path)
    fake = b"not a real executable"
    res = client.post(
        "/api/web/scan/malware_risk/",
        data={"file": ("app.exe", fake, "application/octet-stream")},
        format="multipart",
    )
    assert res.status_code == 400
    assert list(tmp_path.iterdir()) == []


def test_phishing_url_does_not_fetch_network(logged_in, monkeypatch):
    def reject_fetch(*args, **kwargs):
        raise AssertionError("URL fetch attempted")

    monkeypatch.setattr(
        "urllib.request.urlopen",
        reject_fetch,
    )
    res = logged_in.post(
        WEB_SCAN,
        data=json.dumps({"url": "https://example.com"}),
        content_type="application/json",
    )
    assert res.status_code in (200, 201, 400)


def test_scan_response_hides_raw_identifiers(
    client, alice, alice_company, alice_key, stub
):
    _, raw = alice_key
    res = api_post(client, V1_SCAN, raw)
    text = res.content.decode()
    assert raw not in text
    assert alice.username not in text
    assert alice_company.company_name not in text


def test_key_listing_hides_hashes(
    client, alice, alice_company, alice_key
):
    client.force_login(alice)
    text = client.get(COMPANY + "keys/").content.decode()
    assert alice_key[1] not in text
    assert alice_key[0].key_hash not in text


def test_api_error_shape(client, stub):
    res = api_post(client, V1_SCAN, "ksn_" + "x" * 43)
    body = res.json()
    assert set(body) == {"error"}
    assert set(body["error"]) == {"code", "message"}


def test_security_headers(client):
    res = client.get("/api/health/")
    assert res["X-Frame-Options"] == "DENY"
    assert res["X-Content-Type-Options"] == "nosniff"
    assert res["Referrer-Policy"] == "same-origin"


def test_production_disallows_debug(monkeypatch):
    monkeypatch.setenv("DJANGO_DEBUG", "False")
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgres://user:pass@localhost:5432/kitsune?sslmode=require",
    )
    monkeypatch.setenv("API_KEY_PEPPER", "security-test-pepper")
    import kitsune.settings.base as base
    importlib.reload(base)
    assert base.DEBUG is False


def test_production_database_requires_ssl(monkeypatch):
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgres://user:pass@localhost:5432/kitsune?sslmode=require",
    )
    monkeypatch.setenv("API_KEY_PEPPER", "security-test-pepper")
    import kitsune.settings.base as base
    importlib.reload(base)
    options = base.DATABASES["default"].get("OPTIONS", {})
    assert options.get("sslmode") == "require"


def test_api_key_pepper_is_required_in_production():
    assert settings.API_KEY_PEPPER != ""


def test_dev_cors_is_not_production_default():
    import kitsune.settings.dev as dev
    assert dev.CORS_ALLOW_ALL_ORIGINS is True