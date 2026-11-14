from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone

from scans.models import Alert, Module, RiskLevel, Scan

pytestmark = pytest.mark.django_db


@pytest.fixture
def owned_data(client):
    User = get_user_model()
    alice = User.objects.create_user(
        "history_alice",
        "history_alice@example.com",
        "test-password",
    )
    bob = User.objects.create_user(
        "history_bob",
        "history_bob@example.com",
        "test-password",
    )

    def make_scan(user, risk, module=Module.PHISHING_URL):
        return Scan.objects.create(
            user=user,
            module=module,
            prediction="test-result",
            risk_level=risk,
            score=0.9 if risk == RiskLevel.HIGH else 0.1,
        )

    own_scan = make_scan(alice, RiskLevel.HIGH)
    other_scan = make_scan(bob, RiskLevel.HIGH)
    own_alert = Alert.objects.create(
        scan=own_scan,
        user=alice,
        severity=RiskLevel.HIGH,
        title="Alice alert",
    )
    other_alert = Alert.objects.create(
        scan=other_scan,
        user=bob,
        severity=RiskLevel.HIGH,
        title="Bob alert",
    )
    client.force_login(alice)

    return {
        "alice": alice,
        "bob": bob,
        "scan": own_scan,
        "other_scan": other_scan,
        "alert": own_alert,
        "other_alert": other_alert,
    }


@pytest.mark.parametrize("path", [
    "/api/web/history/",
    "/api/web/alerts/",
    "/api/web/dashboard/",
])
def test_read_endpoints_require_login(client, path):
    assert client.get(path).status_code in (401, 403)


def test_history_only_shows_owned_scans(client, owned_data):
    response = client.get("/api/web/history/")
    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 1
    assert body["results"][0]["scan_id"] == str(owned_data["scan"].id)


def test_other_user_scan_returns_404(client, owned_data):
    response = client.get(
        f"/api/web/history/{owned_data['other_scan'].id}/"
    )
    assert response.status_code == 404


def test_own_scan_detail(client, owned_data):
    response = client.get(
        f"/api/web/history/{owned_data['scan'].id}/"
    )
    assert response.status_code == 200
    assert response.json()["scan_id"] == str(owned_data["scan"].id)


def test_history_filters(client, owned_data):
    Scan.objects.create(
        user=owned_data["alice"],
        module=Module.PHISHING_EMAIL,
        prediction="Legitimate",
        risk_level=RiskLevel.LOW,
    )
    response = client.get(
        "/api/web/history/",
        {"module": "phishing_url", "risk_level": "high"},
    )
    assert response.status_code == 200
    assert response.json()["count"] == 1


@pytest.mark.parametrize("params", [
    {"module": "ransomware_behavior"},
    {"risk_level": "dangerous"},
    {"source": "unknown"},
    {"date_from": "not-a-date"},
    {"date_from": "2026-12-01", "date_to": "2026-01-01"},
])
def test_bad_history_filters_return_400(client, owned_data, params):
    assert client.get(
        "/api/web/history/",
        params,
    ).status_code == 400


def test_history_date_filter(client, owned_data):
    old = timezone.now() - timedelta(days=20)
    Scan.objects.filter(pk=owned_data["scan"].pk).update(
        created_at=old
    )
    response = client.get(
        "/api/web/history/",
        {"date_from": timezone.localdate().isoformat()},
    )
    assert response.status_code == 200
    assert response.json()["count"] == 0


def test_history_pagination(client, owned_data):
    for _ in range(3):
        Scan.objects.create(
            user=owned_data["alice"],
            module=Module.PHISHING_URL,
            prediction="Legitimate",
            risk_level=RiskLevel.LOW,
        )
    response = client.get(
        "/api/web/history/",
        {"page_size": 2},
    )
    body = response.json()
    assert body["count"] == 4
    assert len(body["results"]) == 2
    assert body["next"] is not None


def test_alerts_only_show_owned_alerts(client, owned_data):
    response = client.get("/api/web/alerts/")
    body = response.json()
    assert body["count"] == 1
    assert body["results"][0]["id"] == owned_data["alert"].id


def test_mark_alert_read_and_filter(client, owned_data):
    response = client.patch(
        f"/api/web/alerts/{owned_data['alert'].id}/",
        {"is_read": True},
        content_type="application/json",
    )
    assert response.status_code == 200
    owned_data["alert"].refresh_from_db()
    assert owned_data["alert"].is_read is True
    assert client.get(
        "/api/web/alerts/",
        {"is_read": "false"},
    ).json()["count"] == 0


def test_cannot_modify_other_user_alert(client, owned_data):
    response = client.patch(
        f"/api/web/alerts/{owned_data['other_alert'].id}/",
        {"is_read": True},
        content_type="application/json",
    )
    assert response.status_code == 404
    owned_data["other_alert"].refresh_from_db()
    assert owned_data["other_alert"].is_read is False


def test_cannot_modify_alert_severity(client, owned_data):
    alert = owned_data["alert"]
    response = client.patch(
        f"/api/web/alerts/{alert.id}/",
        {"is_read": True, "severity": "low"},
        content_type="application/json",
    )
    assert response.status_code == 400
    alert.refresh_from_db()
    assert alert.severity == RiskLevel.HIGH
    assert alert.is_read is False


def test_dashboard_is_owned_and_zero_filled(client, owned_data):
    response = client.get(
        "/api/web/dashboard/",
        {"days": 7},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["total_scans"] == 1
    assert body["period_scans"] == 1
    assert body["period_high_risk_scans"] == 1
    assert body["unread_alerts"] == 1
    assert len(body["by_module"]) == 5
    assert len(body["daily_scans"]) == 7
    assert sum(day["scans"] for day in body["daily_scans"]) == 1
    assert body["recent_alerts"][0]["id"] == owned_data["alert"].id


@pytest.mark.parametrize("days", [0, 91, "bad"])
def test_dashboard_rejects_bad_day_range(client, owned_data, days):
    assert client.get(
        "/api/web/dashboard/",
        {"days": days},
    ).status_code == 400