from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.utils import timezone

from api.models import APIClient, APIKey, APIPlan, Subscription

pytestmark = pytest.mark.django_db


@pytest.fixture
def client_obj():
    u = get_user_model().objects.create_user("acme", "acme@example.com", "pw12345!", role="company")
    return APIClient.objects.create(owner=u, company_name="Acme", contact_email="acme@example.com")


def test_key_issue_stores_only_hash(client_obj):
    key, raw = APIKey.issue(client_obj)
    assert raw.startswith("ksn_")
    assert key.key_hash != raw and raw not in key.key_hash
    assert APIKey.objects.get(key_hash=APIKey.hash_key(raw)) == key
    assert key.is_valid


def test_key_revoke(client_obj):
    key, _ = APIKey.issue(client_obj)
    key.revoke()
    assert not key.is_valid and key.revoked_at is not None


def test_one_active_subscription(client_obj):
    plan = APIPlan.objects.create(name="Free", slug="free", monthly_quota=10, rate_limit_per_minute=1)
    end = timezone.now() + timedelta(days=30)
    Subscription.objects.create(client=client_obj, plan=plan, current_period_end=end)
    with pytest.raises(IntegrityError), transaction.atomic():
        Subscription.objects.create(client=client_obj, plan=plan, current_period_end=end)