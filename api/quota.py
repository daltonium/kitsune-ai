from dataclasses import dataclass
from datetime import timedelta

from django.utils import timezone
from rest_framework import exceptions

from .models import APIUsage, Subscription

RATE_WINDOW = timedelta(seconds=60)
USABLE_STATUSES = (Subscription.Status.ACTIVE, Subscription.Status.TRIAL)


@dataclass(frozen=True)
class Allowance:
    subscription: Subscription
    used: int
    limit: int
    overage: bool

    @property
    def remaining(self):
        return max(self.limit - self.used, 0)


def get_subscription(company, now):
    subscription = (
        company.subscriptions.select_related("plan")
        .filter(
            status__in=USABLE_STATUSES,
            current_period_start__lte=now,
            current_period_end__gt=now,
        )
        .order_by("-current_period_start")
        .first()
    )
    if subscription is None:
        raise exceptions.PermissionDenied(
            "No active subscription for this company.",
            code="no_active_subscription",
        )
    return subscription


def period_usage(subscription):
    return APIUsage.objects.filter(
        client=subscription.client,
        created_at__gte=subscription.current_period_start,
        created_at__lt=subscription.current_period_end,
        status_code__gte=200,
        status_code__lt=300,
    ).count()


def check_rate_limit(api_key, plan, now):
    limit = plan.rate_limit_per_minute
    message = f"Rate limit of {limit} requests per minute exceeded."
    if limit <= 0:
        raise exceptions.Throttled(
            wait=RATE_WINDOW.total_seconds(),
            detail=message,
            code="rate_limited",
        )
    stamps = list(
        APIUsage.objects.filter(
            api_key=api_key,
            created_at__gt=now - RATE_WINDOW,
        )
        .exclude(status_code=429)
        .order_by("created_at")
        .values_list("created_at", flat=True)
    )
    if len(stamps) >= limit:
        blocker = stamps[len(stamps) - limit]
        wait = (blocker + RATE_WINDOW - now).total_seconds()
        raise exceptions.Throttled(
            wait=max(wait, 1),
            detail=message,
            code="rate_limited",
        )


def enforce_access(api_key, *, now=None):
    """Check subscription, per-minute rate and period quota."""
    now = now or timezone.now()
    subscription = get_subscription(api_key.client, now)
    plan = subscription.plan

    check_rate_limit(api_key, plan, now)

    used = period_usage(subscription)
    limit = plan.monthly_quota
    overage = used >= limit
    if overage:
        payg = (
            subscription.billing_mode == Subscription.Billing.PAYG
            and plan.allow_pay_as_you_go
        )
        if not payg:
            wait = (subscription.current_period_end - now).total_seconds()
            raise exceptions.Throttled(
                wait=max(wait, 1),
                detail=f"Quota of {limit} requests for this period used.",
                code="quota_exceeded",
            )
    return Allowance(subscription, used, limit, overage)


def record_usage(
    *,
    api_key,
    endpoint,
    status_code,
    module="",
    scan=None,
    response_time_ms=None,
):
    return APIUsage.objects.create(
        client=api_key.client,
        api_key=api_key,
        scan=scan,
        endpoint=endpoint[:100],
        module=module,
        status_code=status_code,
        response_time_ms=response_time_ms,
    )