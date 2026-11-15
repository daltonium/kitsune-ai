import logging
import time

from rest_framework import status
from rest_framework.parsers import JSONParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from detectors.exceptions import (
    DetectorNotFoundError,
    InvalidInputError,
    ModelNotLoadedError,
)
from scans.models import Module, Scan
from scans.serializers import ScanSerializer
from scans.services import run_scan

from .authentication import APIKeyAuthentication
from .errors import (
    InvalidInput,
    ModuleUnavailable,
    PayloadTooLarge,
    api_exception_handler,
)
from .models import APIKey
from .quota import enforce_access, record_usage

log = logging.getLogger(__name__)

KB = 1024
MB = 1024 * 1024


def content_length(request):
    raw = request.META.get("CONTENT_LENGTH") or "0"
    try:
        value = int(raw)
    except ValueError:
        raise InvalidInput("Invalid Content-Length header.")
    if value < 0:
        raise InvalidInput("Invalid Content-Length header.")
    return value


class ModuleScanView(APIView):
    """Shared flow for every paid API scan endpoint."""

    authentication_classes = [APIKeyAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser, MultiPartParser]

    module = None
    max_body_bytes = 1 * MB

    _scan = None
    _started = None

    def get_exception_handler(self):
        return api_exception_handler

    def initial(self, request, *args, **kwargs):
        self._started = time.perf_counter()
        super().initial(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        if content_length(request) > self.max_body_bytes:
            raise PayloadTooLarge(
                f"Request body exceeds {self.max_body_bytes // KB} KB."
            )

        allowance = enforce_access(request.auth)

        data = request.data
        payload = data.dict() if hasattr(data, "dict") else data
        if not isinstance(payload, dict):
            raise InvalidInput("Request body must be a JSON object.")

        try:
            scan = run_scan(
                user=request.user,
                module=self.module,
                payload=payload,
                source=Scan.Source.API,
            )
        except InvalidInputError as exc:
            raise InvalidInput(str(exc))
        except (ModelNotLoadedError, DetectorNotFoundError):
            raise ModuleUnavailable()

        self._scan = scan
        response = Response(
            ScanSerializer(scan).data,
            status=status.HTTP_201_CREATED,
        )
        remaining = max(allowance.limit - allowance.used - 1, 0)
        response["X-Quota-Limit"] = str(allowance.limit)
        response["X-Quota-Remaining"] = str(remaining)
        return response

    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(
            request, response, *args, **kwargs
        )
        api_key = getattr(request, "_auth", None)
        if isinstance(api_key, APIKey):
            elapsed = None
            if self._started is not None:
                elapsed = int((time.perf_counter() - self._started) * 1000)
            try:
                record_usage(
                    api_key=api_key,
                    endpoint=request.path,
                    status_code=response.status_code,
                    module=self.module.value,
                    scan=self._scan,
                    response_time_ms=elapsed,
                )
            except Exception:  # never fail a customer request over logging
                log.exception("Could not record API usage")
        return response


class PhishingUrlScanView(ModuleScanView):
    module = Module.PHISHING_URL
    max_body_bytes = 64 * KB


class NetworkIntrusionScanView(ModuleScanView):
    module = Module.NETWORK_INTRUSION
    max_body_bytes = 10 * MB


class PhishingEmailScanView(ModuleScanView):
    module = Module.PHISHING_EMAIL
    max_body_bytes = 2 * MB


class MalwareScanView(ModuleScanView):
    module = Module.MALWARE_RISK
    max_body_bytes = 11 * MB  # 10 MB file limit plus multipart overhead


class SuspiciousLoginAnalyzeView(ModuleScanView):
    module = Module.SUSPICIOUS_LOGIN
    max_body_bytes = 10 * MB