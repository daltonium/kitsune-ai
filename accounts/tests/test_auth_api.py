import json

import pytest
from django.core.cache import cache
from django.test import Client

pytestmark = pytest.mark.django_db

BASE = "/api/auth/"
PASSWORD = "Q7!vM2#rT9@xL4zP"


@pytest.fixture(autouse=True)
def clear_auth_cache():
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def browser():
    return Client(enforce_csrf_checks=True)


@pytest.fixture
def user(django_user_model):
    return django_user_model.objects.create_user(
        username="session_user",
        email="session@example.com",
        password=PASSWORD,
    )


def token(browser):
    response = browser.get(BASE + "csrf/")
    assert response.status_code == 200
    return response.json()["csrf_token"]


def post(browser, path, payload, csrf=None):
    headers = {"HTTP_X_CSRFTOKEN": csrf} if csrf else {}
    return browser.post(
        BASE + path,
        data=json.dumps(payload),
        content_type="application/json",
        **headers,
    )


def registration(**changes):
    return {
        "username": "new_member",
        "email": "member@example.com",
        "password": PASSWORD,
        "password_confirm": PASSWORD,
        **changes,
    }


def test_csrf_bootstrap_sets_cookie(browser):
    csrf = token(browser)
    assert csrf
    assert "csrftoken" in browser.cookies


@pytest.mark.parametrize("path,payload", [
    ("login/", {"username": "someone", "password": PASSWORD}),
    ("register/", registration()),
    ("logout/", {}),
])
def test_writes_require_csrf_even_when_anonymous(browser, path, payload):
    assert post(browser, path, payload).status_code == 403


def test_anonymous_me_returns_401(browser):
    assert browser.get(BASE + "me/").status_code == 401


def test_registration_starts_session(browser, django_user_model):
    response = post(browser, "register/", registration(), token(browser))
    assert response.status_code == 201
    created = django_user_model.objects.get(username="new_member")
    assert created.check_password(PASSWORD)
    assert created.role == "user"
    assert not created.is_staff
    assert not created.is_superuser
    assert browser.get(BASE + "me/").json()["user"]["id"] == created.pk
    assert "password" not in response.json()["user"]
    assert response.json()["csrf_token"]


@pytest.mark.parametrize("changes", [
    {"password_confirm": "does-not-match"},
    {"password": "123", "password_confirm": "123"},
    {"email": "not-an-email"},
    {"role": "company"},
    {"is_staff": True},
    {"is_superuser": True},
])
def test_registration_rejects_invalid_or_privileged_input(browser, changes):
    response = post(
        browser,
        "register/",
        registration(**changes),
        token(browser),
    )
    assert response.status_code == 400


def test_duplicate_email_is_rejected(browser, user):
    response = post(
        browser,
        "register/",
        registration(email="SESSION@EXAMPLE.COM"),
        token(browser),
    )
    assert response.status_code == 400


def test_wrong_password_is_generic(browser, user):
    response = post(
        browser,
        "login/",
        {"username": user.username, "password": "wrong-password"},
        token(browser),
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_credentials"
    assert browser.get(BASE + "me/").status_code == 401


def test_inactive_user_cannot_login(browser, user):
    user.is_active = False
    user.save(update_fields=["is_active"])
    response = post(
        browser,
        "login/",
        {"username": user.username, "password": PASSWORD},
        token(browser),
    )
    assert response.status_code == 401


def test_login_and_logout(browser, user):
    response = post(
        browser,
        "login/",
        {"username": user.username, "password": PASSWORD},
        token(browser),
    )
    assert response.status_code == 200
    assert browser.get(BASE + "me/").json()["user"]["id"] == user.pk

    response = post(
        browser,
        "logout/",
        {},
        response.json()["csrf_token"],
    )
    assert response.status_code == 200
    assert browser.get(BASE + "me/").status_code == 401


def test_untrusted_origin_is_rejected(browser, user):
    csrf = token(browser)
    response = browser.post(
        BASE + "login/",
        data=json.dumps({
            "username": user.username,
            "password": PASSWORD,
        }),
        content_type="application/json",
        HTTP_X_CSRFTOKEN=csrf,
        HTTP_ORIGIN="http://untrusted.example",
    )
    assert response.status_code == 403