from datetime import timedelta

import pytest
from django.utils import timezone
from rest_framework import exceptions
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory

from api.authentication import APIKeyAuthentication
from api.models import APIClient as Company
from api.models import APIKey, APIPlan, APIUsage, Subscription
from api.quota import enforce_access

pytestmark = pytest.mark.django_db
factory = APIRequestFactory()


def authenticate(header=None):
    extra = {"HTTP_AUTHORIZATION": header} if header is not None else {}
    request = Request(factory.get("/api/v1/test/", **extra))
    return APIKeyAuthentication().authenticate(request)


def make_company(django_user_model, name):
    user = django_user_model.objects.create_user(
        name, f"{name}@example.com", "pw-12345!"
    )
    return Company.objects.create(
        owner=user,
        company_name=name,
        contact_email=f"{name}@example.com",
    )


def add_usage(company, key, n=1, status=201, age=timedelta(0)):
    for _ in range(n):
        row = APIUsage.objects.create(
            client=company,
            api_key=key,
            endpoint="/api/v1/test/",
            module="phishing_url",
            status_code=status,
        )
        if age:
            APIUsage.objects.filter(pk=row.pk).update(
                created_at=timezone.now() - age
            )


@pytest.fixture
def plan():
    return APIPlan.objects.create(
        name="Test plan",
        slug="test-plan-x",
        monthly_quota=3,
        rate_limit_per_minute=2,
    )


@pytest.fixture
def company(django_user_model):
    return make_company(django_user_model, "acme")


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
def issued(company):
    return APIKey.issue(company)


def test_valid_key_authenticates(issued, company):
    key, raw = issued
    user, auth = authenticate(f"Bearer {raw}")
    assert user == company.owner and auth.pk == key.pk


def test_missing_header_returns_none():
    assert authenticate() is None


def test_other_scheme_returns_none():
    assert authenticate("Basic abc") is None


@pytest.mark.parametrize("header", [
    "Bearer",
    "Bearer ksn_a ksn_b",
    "Bearer notaprefixedkey",
])
def test_malformed_headers_rejected(header):
    with pytest.raises(exceptions.AuthenticationFailed):
        authenticate(header)


def test_unknown_key_rejected():
    with pytest.raises(exceptions.AuthenticationFailed):
        authenticate("Bearer ksn_" + "x" * 43)


def test_revoked_key_rejected(issued):
    key, raw = issued
    key.revoke()
    with pytest.raises(exceptions.AuthenticationFailed):
        authenticate(f"Bearer {raw}")


def test_expired_key_rejected(company):
    _, raw = APIKey.issue(
        company,
        expires_at=timezone.now() - timedelta(minutes=1),
    )
    with pytest.raises(exceptions.AuthenticationFailed):
        authenticate(f"Bearer {raw}")


def test_disabled_company_forbidden(issued, company):
    _, raw = issued
    company.is_active = False
    company.save(update_fields=["is_active"])
    with pytest.raises(exceptions.PermissionDenied):
        authenticate(f"Bearer {raw}")


def test_raw_key_never_stored(issued):
    key, raw = issued
    assert raw.startswith("ksn_") and key.prefix == raw[:12]
    assert raw not in key.key_hash
    assert not APIKey.objects.filter(key_hash=raw).exists()


def test_last_used_is_recorded(issued):
    key, raw = issued
    assert key.last_used_at is None
    authenticate(f"Bearer {raw}")
    key.refresh_from_db()
    assert key.last_used_at is not None


def test_no_subscription_forbidden(issued):
    with pytest.raises(exceptions.PermissionDenied):
        enforce_access(issued[0])


@pytest.mark.parametrize("status", ["past_due", "cancelled"])
def test_unusable_subscription_status_forbidden(
    issued, subscription, status
):
    Subscription.objects.filter(pk=subscription.pk).update(status=status)
    with pytest.raises(exceptions.PermissionDenied):
        enforce_access(issued[0])


def test_expired_period_forbidden(issued, subscription):
    Subscription.objects.filter(pk=subscription.pk).update(
        current_period_end=timezone.now() - timedelta(minutes=1)
    )
    with pytest.raises(exceptions.PermissionDenied):
        enforce_access(issued[0])


def test_allows_within_quota(issued, company, subscription):
    key = issued[0]
    add_usage(company, key, n=2, age=timedelta(minutes=5))
    allowance = enforce_access(key)
    assert allowance.used == 2
    assert allowance.remaining == 1
    assert allowance.overage is False


def test_quota_exhausted_returns_429(issued, company, subscription):
    key = issued[0]
    add_usage(company, key, n=3, age=timedelta(minutes=5))
    with pytest.raises(exceptions.Throttled) as exc:
        enforce_access(key)
    assert exc.value.status_code == 429
    assert exc.value.get_codes() == "quota_exceeded"
    assert exc.value.wait > 0


def test_failed_requests_do_not_use_quota(issued, company, subscription):
    key = issued[0]
    add_usage(company, key, n=5, status=400, age=timedelta(minutes=5))
    assert enforce_access(key).used == 0


def test_usage_outside_period_ignored(issued, company, subscription):
    key = issued[0]
    add_usage(company, key, n=5, age=timedelta(days=2))
    assert enforce_access(key).used == 0


def test_other_company_usage_ignored(
    issued, company, subscription, django_user_model
):
    other = make_company(django_user_model, "other")
    other_key, _ = APIKey.issue(other)
    add_usage(other, other_key, n=5, age=timedelta(minutes=5))
    assert enforce_access(issued[0]).used == 0


def test_payg_allows_overage(issued, company, subscription, plan):
    plan.allow_pay_as_you_go = True
    plan.save(update_fields=["allow_pay_as_you_go"])
    Subscription.objects.filter(pk=subscription.pk).update(
        billing_mode="payg"
    )
    key = issued[0]
    add_usage(company, key, n=5, age=timedelta(minutes=5))
    allowance = enforce_access(key)
    assert allowance.overage is True
    assert allowance.remaining == 0


def test_monthly_billing_blocked_even_if_plan_allows_payg(
    issued, company, subscription, plan
):
    plan.allow_pay_as_you_go = True
    plan.save(update_fields=["allow_pay_as_you_go"])
    key = issued[0]
    add_usage(company, key, n=3, age=timedelta(minutes=5))
    with pytest.raises(exceptions.Throttled):
        enforce_access(key)


def test_rate_limit_blocks(issued, company, subscription):
    key = issued[0]
    add_usage(company, key, n=2)
    with pytest.raises(exceptions.Throttled) as exc:
        enforce_access(key)
    assert exc.value.get_codes() == "rate_limited"
    assert 1 <= exc.value.wait <= 60


def test_rate_limit_ignores_old_and_429(issued, company, subscription):
    key = issued[0]
    add_usage(company, key, n=1, age=timedelta(minutes=2))
    add_usage(company, key, n=5, status=429)
    assert enforce_access(key).used == 1


def test_rate_limit_is_per_key(issued, company, subscription):
    first = issued[0]
    second, _ = APIKey.issue(company, name="second")
    add_usage(company, second, n=2)
    assert enforce_access(first).limit == 3