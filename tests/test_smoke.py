from django.conf import settings


def test_health_endpoint(client):
    res = client.get("/api/health/")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"


def test_custom_user_model_configured():
    assert settings.AUTH_USER_MODEL == "accounts.User"


def test_installed_apps():
    for app in ("rest_framework", "corsheaders", "accounts", "scans", "api"):
        assert app in settings.INSTALLED_APPS