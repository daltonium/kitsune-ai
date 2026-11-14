from django.urls import path

from .history_views import (
    AlertDetailView,
    AlertListView,
    DashboardView,
    ScanDetailView,
    ScanHistoryView,
)
from .web_views import ModulesView, ScanView

urlpatterns = [
    path("modules/", ModulesView.as_view(), name="modules"),
    path("scan/<str:module>/", ScanView.as_view(), name="scan"),
    path("history/", ScanHistoryView.as_view(), name="scan-history"),
    path(
        "history/<uuid:scan_id>/",
        ScanDetailView.as_view(),
        name="scan-detail",
    ),
    path("alerts/", AlertListView.as_view(), name="alert-list"),
    path(
        "alerts/<int:pk>/",
        AlertDetailView.as_view(),
        name="alert-detail",
    ),
    path("dashboard/", DashboardView.as_view(), name="dashboard"),
]