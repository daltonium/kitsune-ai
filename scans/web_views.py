from rest_framework.response import Response
from rest_framework.views import APIView

from detectors import registry


class ModulesView(APIView):
    """GET /api/web/modules/ - which detection modules exist and are trained."""

    def get(self, request):
        return Response(registry.status())