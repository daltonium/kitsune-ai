import json
from datetime import timedelta

import pytest
from django.utils import timezone

from api.company import MAX_ACTIVE_KEYS
from api.models import APIClient as Company
from api.models import APIKey, APIPlan, APIUsage, Subscription

pytestmark = pytest.mark.django_db

BASE = "/api/web/company/"
REGISTER = {
    "company_name": "Acme Security",
    "contact_email": "sec@acme.example",
    "website": "https://acme.example",
}


def post(client, path, data=None):
    return client.post(
        BASE + path,
        data=json.dumps(data or {}),
        content_type="application/json",
    )


def add_usage(company, key, status, module, n=1):
    for _ in range(n):
        APIUsage.objects.create(
            client=company,
            api_key=key,
            endpoint="/api/v1/x/",
            module=module,
            status_code=status,
            response_time_ms=100,
        )


@pytest.fixture
def plans():
    return {
        "free": APIPlan.objects.create(
            name="Free", slug="free", monthly_quota=1000,
            rate_limit_per_minute=10,
        ),
        "starter": APIPlan.objects.create(
            name="Starter", slug="starter", monthly_quota=25000,
            rate_limit_per_minute=60, price_inr=999,
        ),
        "business": APIPlan.objects.create(
            name="Business", slug="business", monthly_quota=250000,
            rate_limit_per_minute=300, price_inr=7999,
            allow_pay_as_you_go=True,
        ),
        "legacy": APIPlan.objects.create(
            name="Legacy", slug="legacy", monthly_quota=10,
            rate_limit_per_minute=1, is_active=False,
        ),
    }


@pytest.fixture
def owner(django_user_model):
    return django_user_model.objects.create_user(
        "owner1", "owner1@example.com", "pw-12345!"
    )


@pytest.fixture
def api(client, owner):
    client.force_login(owner)
    return client


@pytest.fixture
def other_company(django_user_model):
    user = django_user_model.objects.create_user(
        "owner2", "owner2@example.com", "pw-12345!"
    )
    return Company.objects.create(
        owner=user, company_name="Other", contact_email="o@example.com"
    )


def test_plans_are_public(client, plans):
    res = client.get(BASE + "plans/")
    assert res.status_code == 200
    slugs = [p["slug"] for p in res.json()]
    assert slugs == ["free", "starter", "business"]


@pytest.mark.parametrize("path", ["", "keys/", "usage/"])
def test_endpoints_require_login(client, path):
    assert client.get(BASE + path).status_code in (401, 403)


def test_register_creates_company_and_free_subscription(api, owner, plans):
    res = post(api, "register/", REGISTER)
    assert res.status_code == 201
    body = res.json()
    assert body["company"]["company_name"] == "Acme Security"
    assert body["subscription"]["plan"]["slug"] == "free"
    assert body["subscription"]["status"] == "active"
    assert Company.objects.get(owner=owner)
    assert Subscription.objects.count() == 1


def test_register_twice_conflicts(api, plans):
    assert post(api, "register/", REGISTER).status_code == 201
    res = post(api, "register/", REGISTER)
    assert res.status_code == 409
    assert res.json()["error"]["code"] == "company_already_registered"


@pytest.mark.parametrize("payload", [
    {"company_name": "A", "contact_email": "sec@acme.example"},
    {"company_name": "Acme", "contact_email": "not-an-email"},
    {
        "company_name": "Acme",
        "contact_email": "a@b.example",
        "website": "ftp://files.example",
    },
])
def test_register_validation(api, plans, payload):
    res = post(api, "register/", payload)
    assert res.status_code == 400
    error = res.json()["error"]
    assert error["code"] == "validation_error"
    assert "fields" in error
    assert Company.objects.count() == 0


def test_register_without_free_plan_leaves_no_subscription(api):
    res = post(api, "register/", REGISTER)
    assert res.status_code == 201
    assert res.json()["subscription"] is None
    usage = api.get(BASE + "usage/")
    assert usage.status_code == 200
    assert usage.json()["quota"] is None


def test_company_requires_registration(api, plans):
    res = api.get(BASE)
    assert res.status_code == 404
    assert res.json()["error"]["code"] == "company_not_registered"


def test_company_profile(api, plans):
    post(api, "register/", REGISTER)
    body = api.get(BASE).json()
    assert body["company"]["company_name"] == "Acme Security"
    assert body["subscription"]["plan"]["slug"] == "free"
    assert body["active_keys"] == 0


def test_change_plan_keeps_period(api, plans):
    post(api, "register/", REGISTER)
    before = Subscription.objects.get()
    res = post(api, "subscription/", {"plan": "starter"})
    assert res.status_code == 200
    after = Subscription.objects.get()
    assert after.plan.slug == "starter"
    assert after.current_period_start == before.current_period_start
    assert after.current_period_end == before.current_period_end


def test_payg_requires_plan_support(api, plans):
    post(api, "register/", REGISTER)
    res = post(api, "subscription/", {"plan": "starter", "billing_mode": "payg"})
    assert res.status_code == 400
    res = post(api, "subscription/", {"plan": "business", "billing_mode": "payg"})
    assert res.status_code == 200
    assert res.json()["subscription"]["billing_mode"] == "payg"


def test_unknown_or_inactive_plan_rejected(api, plans):
    post(api, "register/", REGISTER)
    assert post(api, "subscription/", {"plan": "nope"}).status_code == 400
    assert post(api, "subscription/", {"plan": "legacy"}).status_code == 400


def test_expired_subscription_is_replaced(api, owner, plans):
    post(api, "register/", REGISTER)
    company = Company.objects.get(owner=owner)
    Subscription.objects.filter(client=company).update(
        current_period_end=timezone.now() - timedelta(minutes=1)
    )
    res = post(api, "subscription/", {"plan": "starter"})
    assert res.status_code == 200
    assert Subscription.objects.filter(status="cancelled").count() == 1
    active = Subscription.objects.get(status="active")
    assert active.plan.slug == "starter"
    assert active.current_period_end > timezone.now()


def test_create_key_shows_raw_key_once(api, plans):
    post(api, "register/", REGISTER)
    res = post(api, "keys/", {"name": "server-1"})
    assert res.status_code == 201
    assert "no-store" in res["Cache-Control"]
    raw = res.json()["api_key"]
    assert raw.startswith("ksn_")
    assert APIKey.objects.filter(key_hash=APIKey.hash_key(raw)).exists()

    listing = api.get(BASE + "keys/")
    assert listing.status_code == 200
    assert raw not in listing.content.decode()
    assert "key_hash" not in listing.content.decode()


def test_key_limit(api, owner, plans):
    post(api, "register/", REGISTER)
    company = Company.objects.get(owner=owner)
    for i in range(MAX_ACTIVE_KEYS):
        APIKey.issue(company, name=f"k{i}")
    res = post(api, "keys/", {"name": "one-too-many"})
    assert res.status_code == 409
    assert res.json()["error"]["code"] == "key_limit_reached"


def test_revoke_key(api, plans):
    post(api, "register/", REGISTER)
    key_id = post(api, "keys/").json()["key"]["id"]
    first = post(api, f"keys/{key_id}/revoke/")
    assert first.status_code == 200
    assert first.json()["status"] == "revoked"
    assert post(api, f"keys/{key_id}/revoke/").status_code == 200
    assert APIKey.objects.get(pk=key_id).is_active is False


def test_cannot_revoke_other_company_key(api, plans, other_company):
    post(api, "register/", REGISTER)
    foreign, _ = APIKey.issue(other_company)
    res = post(api, f"keys/{foreign.pk}/revoke/")
    assert res.status_code == 404
    foreign.refresh_from_db()
    assert foreign.is_active is True


def test_key_list_is_scoped(api, plans, other_company):
    post(api, "register/", REGISTER)
    APIKey.issue(other_company)
    own_id = post(api, "keys/").json()["key"]["id"]
    ids = [k["id"] for k in api.get(BASE + "keys/").json()]
    assert ids == [own_id]


def test_key_expiry(api, plans):
    post(api, "register/", REGISTER)
    res = post(api, "keys/", {"name": "temp", "expires_in_days": 7})
    assert res.status_code == 201
    assert res.json()["key"]["expires_at"] is not None
    assert post(api, "keys/", {"expires_in_days": 0}).status_code == 400


def test_usage_report_counts(api, owner, plans):
    post(api, "register/", REGISTER)
    company = Company.objects.get(owner=owner)
    key, _ = APIKey.issue(company)
    add_usage(company, key, 201, "phishing_url", n=2)
    add_usage(company, key, 400, "phishing_email")
    add_usage(company, key, 429, "phishing_url")
    add_usage(company, key, 500, "malware_risk")

    body = api.get(BASE + "usage/", {"days": 7}).json()
    assert body["requests"]["total"] == 5
    assert body["requests"]["success"] == 2
    assert body["requests"]["client_errors"] == 1
    assert body["requests"]["rate_limited"] == 1
    assert body["requests"]["server_errors"] == 1
    assert body["requests"]["avg_response_ms"] == 100
    assert body["by_module"]["phishing_url"] == 3
    assert body["by_module"]["suspicious_login"] == 0
    assert body["by_key"] == [
        {"prefix": key.prefix, "name": "default", "requests": 5}
    ]
    assert body["quota"]["limit"] == 1000
    assert body["quota"]["used"] == 2
    assert body["quota"]["remaining"] == 998
    assert len(body["daily_requests"]) == 7
    assert sum(d["requests"] for d in body["daily_requests"]) == 5


def test_usage_report_is_isolated(api, plans, other_company):
    post(api, "register/", REGISTER)
    other_key, _ = APIKey.issue(other_company)
    add_usage(other_company, other_key, 201, "phishing_url", n=3)
    body = api.get(BASE + "usage/").json()
    assert body["requests"]["total"] == 0
    assert body["quota"]["used"] == 0


@pytest.mark.parametrize("days", [0, 91])
def test_usage_rejects_bad_days(api, plans, days):
    post(api, "register/", REGISTER)
    assert api.get(BASE + "usage/", {"days": days}).status_code == 400