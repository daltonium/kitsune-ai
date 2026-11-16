from .base import *  # noqa: F401,F403

DEBUG = env_bool("DJANGO_DEBUG", True)  # noqa: F405

# Local Expo web frontend. Do not copy these origins into production.
CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOWED_ORIGINS = [
    "http://localhost:8081",
]
CORS_ALLOW_CREDENTIALS = True

CSRF_TRUSTED_ORIGINS = [
    "http://localhost:8081",
]

SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"

DATABASES["default"].setdefault("OPTIONS", {})  # noqa: F405