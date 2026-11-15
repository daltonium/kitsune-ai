from django.urls import path

from .company_views import (
    CompanyView,
    KeyListView,
    KeyRevokeView,
    PlanListView,
    RegisterView,
    SubscriptionView,
    UsageView,
)

urlpatterns = [
    path("", CompanyView.as_view(), name="company"),
    path("plans/", PlanListView.as_view(), name="company-plans"),
    path("register/", RegisterView.as_view(), name="company-register"),
    path(
        "subscription/",
        SubscriptionView.as_view(),
        name="company-subscription",
    ),
    path("keys/", KeyListView.as_view(), name="company-keys"),
    path(
        "keys/<int:pk>/revoke/",
        KeyRevokeView.as_view(),
        name="company-key-revoke",
    ),
    path("usage/", UsageView.as_view(), name="company-usage"),
]