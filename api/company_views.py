from rest_framework import exceptions, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from . import company as service
from .errors import api_exception_handler
from .models import APIClient, APIPlan
from .serializers import (
    CompanySerializer,
    KeyCreateSerializer,
    KeySerializer,
    PlanSerializer,
    RegisterSerializer,
    SubscriptionChangeSerializer,
    SubscriptionSerializer,
    UsageQuerySerializer,
)


class CompanyBaseView(APIView):
    permission_classes = [IsAuthenticated]

    def get_exception_handler(self):
        return api_exception_handler

    def get_company(self, request):
        company = APIClient.objects.filter(owner=request.user).first()
        if company is None:
            raise exceptions.NotFound(
                "Register a company first.", code="company_not_registered"
            )
        if not company.is_active:
            raise exceptions.PermissionDenied(
                "This company account is disabled.", code="company_disabled"
            )
        return company


class PlanListView(CompanyBaseView):
    permission_classes = [AllowAny]

    def get(self, request):
        plans = APIPlan.objects.filter(is_active=True).order_by("price_inr")
        return Response(PlanSerializer(plans, many=True).data)


class RegisterView(CompanyBaseView):
    def post(self, request):
        data = RegisterSerializer(data=request.data)
        data.is_valid(raise_exception=True)
        company, subscription = service.register_company(
            request.user, **data.validated_data
        )
        return Response(
            {
                "company": CompanySerializer(company).data,
                "subscription": (
                    SubscriptionSerializer(subscription).data
                    if subscription
                    else None
                ),
            },
            status=status.HTTP_201_CREATED,
        )


class CompanyView(CompanyBaseView):
    def get(self, request):
        company = self.get_company(request)
        subscription = service.current_subscription(company)
        return Response(
            {
                "company": CompanySerializer(company).data,
                "subscription": (
                    SubscriptionSerializer(subscription).data
                    if subscription
                    else None
                ),
                "active_keys": company.api_keys.filter(
                    is_active=True
                ).count(),
            }
        )


class SubscriptionView(CompanyBaseView):
    def post(self, request):
        company = self.get_company(request)
        data = SubscriptionChangeSerializer(data=request.data)
        data.is_valid(raise_exception=True)
        subscription = service.set_plan(
            company,
            data.validated_data["plan"],
            data.validated_data["billing_mode"],
        )
        return Response(
            {
                "subscription": SubscriptionSerializer(subscription).data,
                "note": "Payments are simulated (dummy provider).",
            }
        )


class KeyListView(CompanyBaseView):
    def get(self, request):
        company = self.get_company(request)
        keys = company.api_keys.order_by("-created_at")
        return Response(KeySerializer(keys, many=True).data)

    def post(self, request):
        company = self.get_company(request)
        data = KeyCreateSerializer(data=request.data)
        data.is_valid(raise_exception=True)
        key, raw = service.create_key(
            company,
            name=data.validated_data["name"],
            expires_in_days=data.validated_data.get("expires_in_days"),
        )
        response = Response(
            {
                "key": KeySerializer(key).data,
                "api_key": raw,
                "warning": "Copy this key now. It will not be shown again.",
            },
            status=status.HTTP_201_CREATED,
        )
        response["Cache-Control"] = "no-store"
        return response


class KeyRevokeView(CompanyBaseView):
    def post(self, request, pk):
        company = self.get_company(request)
        key = service.revoke_key(company, pk)
        return Response(KeySerializer(key).data)


class UsageView(CompanyBaseView):
    def get(self, request):
        company = self.get_company(request)
        query = UsageQuerySerializer(data=request.query_params)
        query.is_valid(raise_exception=True)
        report = service.usage_report(company, query.validated_data["days"])
        if report["subscription"] is not None:
            report["subscription"] = SubscriptionSerializer(
                report["subscription"]
            ).data
        report["note"] = (
            "Counts cover authenticated /api/v1 requests. "
            "Quota uses successful (2xx) requests in the billing period."
        )
        return Response(report)