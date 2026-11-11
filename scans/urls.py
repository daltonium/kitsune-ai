from django.urls import path

from .web_views import ModulesView

urlpatterns = [
    path("modules/", ModulesView.as_view(), name="modules"),
]