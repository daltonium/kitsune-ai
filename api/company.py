from datetime import datetime, time, timedelta

from django.db import IntegrityError, transaction
from django.db.models import Avg, Count, Q
from django.db.models.functions import TruncDate
from django.utils import timezone
from rest_framework import exceptions

from scans.models import Module

from .errors import CompanyAlreadyRegistered, KeyLimitReached
from .models import APIClient, APIKey, APIPlan, APIUsage, Subscription
from .quota import USABLE_STATUSES, period_usage

PERIOD_DAYS = 30
MAX_ACTIVE_KEYS = 5
FREE_PLAN_SLUG = "free"


def local_midnight(day):
    return timezone.make_aware(
        datetime.combine(day, time.min),
        timezone.get_current_timezone(),
    )


def current_subscription(company, now=None):
    now = now or timezone.now()
    return (
        company.subscriptions.select_related("plan")
        .filter(
            status__in=USABLE_STATUSES,
            current_period_start__lte=now,
            current_period_end__gt=now,
        )
        .order_by("-current_period_start")
        .first()
    )


def start_subscription(company, plan, billing_mode, now):
    return Subscription.objects.create(
        client=company,
        plan=plan,
        status=Subscription.Status.ACTIVE,
        billing_mode=billing_mode,
        payment_provider="dummy",
        current_period_start=now,
        current_period_end=now + timedelta(days=PERIOD_DAYS),
    )


def register_company(user, *, company_name, contact_email, website=""):
    if APIClient.objects.filter(owner=user).exists():
        raise CompanyAlreadyRegistered()
    try:
        with transaction.atomic():
            company = APIClient.objects.create(
                owner=user,
                company_name=company_name,
                contact_email=contact_email,
                website=website,
            )
            plan = APIPlan.objects.filter(
                slug=FREE_PLAN_SLUG, is_active=True
            ).first()
            subscription = None
            if plan is not None:
                subscription = start_subscription(
                    company,
                    plan,
                    Subscription.Billing.MONTHLY,
                    timezone.now(),
                )
    except IntegrityError:
        raise CompanyAlreadyRegistered()
    return company, subscription


def set_plan(
    company,
    plan,
    billing_mode=Subscription.Billing.MONTHLY,
    *,
    now=None,
):
    """Dummy checkout. Keeps the current period so quota use carries over."""
    now = now or timezone.now()
    with transaction.atomic():
        APIClient.objects.select_for_update().get(pk=company.pk)
        current = current_subscription(company, now)
        stale = company.subscriptions.filter(status__in=USABLE_STATUSES)
        if current is not None:
            stale = stale.exclude(pk=current.pk)
        stale.update(status=Subscription.Status.CANCELLED)

        if current is None:
            return start_subscription(company, plan, billing_mode, now)

        current.plan = plan
        current.billing_mode = billing_mode
        current.status = Subscription.Status.ACTIVE
        current.save(update_fields=["plan", "billing_mode", "status"])
        return current


def create_key(company, name="default", expires_in_days=None):
    with transaction.atomic():
        APIClient.objects.select_for_update().get(pk=company.pk)
        active = company.api_keys.filter(is_active=True).count()
        if active >= MAX_ACTIVE_KEYS:
            raise KeyLimitReached()
        expires_at = None
        if expires_in_days:
            expires_at = timezone.now() + timedelta(days=expires_in_days)
        return APIKey.issue(company, name=name, expires_at=expires_at)


def revoke_key(company, key_id):
    key = company.api_keys.filter(pk=key_id).first()
    if key is None:
        raise exceptions.NotFound("API key not found.", code="key_not_found")
    if key.is_active:
        key.revoke()
    return key


def usage_report(company, days, now=None):
    now = now or timezone.now()
    today = timezone.localdate(now)
    first_day = today - timedelta(days=days - 1)
    window = APIUsage.objects.filter(
        client=company,
        created_at__gte=local_midnight(first_day),
        created_at__lt=local_midnight(today + timedelta(days=1)),
    )

    totals = window.aggregate(
        total=Count("id"),
        success=Count("id", filter=Q(status_code__gte=200, status_code__lt=300)),
        client_errors=Count(
            "id",
            filter=Q(status_code__gte=400, status_code__lt=500)
            & ~Q(status_code=429),
        ),
        rate_limited=Count("id", filter=Q(status_code=429)),
        server_errors=Count("id", filter=Q(status_code__gte=500)),
        avg_ms=Avg("response_time_ms"),
    )
    avg = totals.pop("avg_ms")
    totals["avg_response_ms"] = None if avg is None else round(avg)

    module_counts = {
        row["module"]: row["total"]
        for row in window.exclude(module="")
        .values("module")
        .annotate(total=Count("id"))
    }
    by_key = [
        {
            "prefix": row["api_key__prefix"] or "deleted",
            "name": row["api_key__name"] or "",
            "requests": row["total"],
        }
        for row in window.values("api_key__prefix", "api_key__name")
        .annotate(total=Count("id"))
        .order_by("-total")
    ]
    daily_counts = {
        row["day"]: row["total"]
        for row in window.annotate(
            day=TruncDate(
                "created_at", tzinfo=timezone.get_current_timezone()
            )
        )
        .values("day")
        .annotate(total=Count("id"))
    }
    daily = [
        {
            "date": (first_day + timedelta(days=i)).isoformat(),
            "requests": daily_counts.get(first_day + timedelta(days=i), 0),
        }
        for i in range(days)
    ]

    subscription = current_subscription(company, now)
    quota = None
    if subscription is not None:
        limit = subscription.plan.monthly_quota
        used = period_usage(subscription)
        quota = {
            "limit": limit,
            "used": used,
            "remaining": max(limit - used, 0),
            "overage_requests": max(used - limit, 0),
            "renews_at": subscription.current_period_end,
        }

    return {
        "period": {
            "days": days,
            "date_from": first_day.isoformat(),
            "date_to": today.isoformat(),
            "timezone": timezone.get_current_timezone_name(),
        },
        "subscription": subscription,
        "quota": quota,
        "requests": totals,
        "by_module": {m: module_counts.get(m, 0) for m in Module.values},
        "by_key": by_key,
        "daily_requests": daily,
    }