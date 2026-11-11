from rest_framework import status
from rest_framework.parsers import JSONParser, MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView

from detectors import registry
from detectors.exceptions import DetectorNotFoundError, InvalidInputError, ModelNotLoadedError

from .models import Module
from .serializers import ScanSerializer
from .services import run_scan


def _error(code, message, http_status):
    return Response({"error": {"code": code, "message": message}}, status=http_status)


class ModulesView(APIView):
    """GET /api/web/modules/ - which detection modules exist and are trained."""

    def get(self, request):
        return Response(registry.status())


class ScanView(APIView):
    """POST /api/web/scan/<module>/ - run one detection module for the logged-in user."""

    parser_classes = (JSONParser, MultiPartParser)

    def post(self, request, module):
        if module not in Module.values:
            return _error("unknown_module", "Unknown detection module.", status.HTTP_404_NOT_FOUND)
        data = request.data
        payload = data.dict() if hasattr(data, "dict") else data
        if not isinstance(payload, dict):
            return _error("invalid_input", "Request body must be a JSON object.", status.HTTP_400_BAD_REQUEST)
        try:
            scan = run_scan(user=request.user, module=module, payload=payload)
        except InvalidInputError as exc:
            return _error("invalid_input", str(exc), status.HTTP_400_BAD_REQUEST)
        except (ModelNotLoadedError, DetectorNotFoundError):
            return _error("module_unavailable", "This detection module is not available yet.",
                          status.HTTP_503_SERVICE_UNAVAILABLE)
        return Response(ScanSerializer(scan).data, status=status.HTTP_201_CREATED)