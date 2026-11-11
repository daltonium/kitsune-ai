from .base import *  # noqa: F401,F403

DEBUG = env_bool("DJANGO_DEBUG", True)  # noqa: F405

# Expo web dev server and mobile dev clients
CORS_ALLOW_ALL_ORIGINS = True

# dev can run without SSL-forced DB if you ever use a local Postgres
DATABASES["default"].setdefault("OPTIONS", {})  # noqa: F405