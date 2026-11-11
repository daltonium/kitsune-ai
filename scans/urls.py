from django.urls import path

from .web_views import ModulesView, ScanView

urlpatterns = [
    path("modules/", ModulesView.as_view(), name="modules"),
    path("scan/<str:module>/", ScanView.as_view(), name="scan"),
]