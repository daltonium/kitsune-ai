from datetime import timedelta

from django.utils import timezone
from rest_framework import authentication, exceptions

from .models import APIKey

LAST_USED_INTERVAL = timedelta(minutes=1)
MAX_KEY_LENGTH = 100
KEY_PREFIX = "ksn_"


class APIKeyAuthentication(authentication.BaseAuthentication):
    """Authorization: Bearer ksn_... -> (company owner, APIKey)."""

    def authenticate_header(self, request):
        return 'Bearer realm="KITSUNE API"'

    def authenticate(self, request):
        parts = authentication.get_authorization_header(request).split()
        if not parts or parts[0].lower() != b"bearer":
            return None
        if len(parts) != 2:
            raise exceptions.AuthenticationFailed(
                "Invalid Authorization header."
            )
        try:
            raw = parts[1].decode("ascii")
        except UnicodeDecodeError:
            raise exceptions.AuthenticationFailed("Invalid API key.")
        if not raw.startswith(KEY_PREFIX) or len(raw) > MAX_KEY_LENGTH:
            raise exceptions.AuthenticationFailed("Invalid API key.")

        api_key = (
            APIKey.objects.select_related("client", "client__owner")
            .filter(key_hash=APIKey.hash_key(raw))
            .first()
        )
        if api_key is None or not api_key.is_valid:
            raise exceptions.AuthenticationFailed("Invalid API key.")

        company = api_key.client
        if not company.is_active or not company.owner.is_active:
            raise exceptions.PermissionDenied(
                "This company account is disabled."
            )

        now = timezone.now()
        last = api_key.last_used_at
        if last is None or now - last > LAST_USED_INTERVAL:
            APIKey.objects.filter(pk=api_key.pk).update(last_used_at=now)
            api_key.last_used_at = now
        return company.owner, api_key