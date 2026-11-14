from datetime import datetime, time, timedelta

from django.db.models import Count
from django.db.models.functions import TruncDate
from django.utils import timezone
from rest_framework import generics, serializers
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.settings import api_settings

from .models import Alert, Module, RiskLevel, Scan
from .serializers import AlertSerializer, ScanSerializer


class HistoryPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = "page_size"
    max_page_size = 100


class ScanFilters(serializers.Serializer):
    module = serializers.ChoiceField(
        choices=Module.choices,
        required=False,
    )
    risk_level = serializers.ChoiceField(
        choices=RiskLevel.choices,
        required=False,
    )
    source = serializers.ChoiceField(
        choices=Scan.Source.choices,
        required=False,
    )
    date_from = serializers.DateField(required=False)
    date_to = serializers.DateField(required=False)

    def validate(self, attrs):
        start = attrs.get("date_from")
        end = attrs.get("date_to")
        if start and end and start > end:
            raise serializers.ValidationError(
                "date_from must not be later than date_to."
            )
        return attrs


class AlertFilters(serializers.Serializer):
    severity = serializers.ChoiceField(
        choices=RiskLevel.choices,
        required=False,
    )
    is_read = serializers.BooleanField(required=False)


class AlertUpdateSerializer(serializers.Serializer):
    is_read = serializers.BooleanField(required=True)

    def to_internal_value(self, data):
        key = api_settings.NON_FIELD_ERRORS_KEY
        if not isinstance(data, dict):
            raise serializers.ValidationError(
                {key: ["Request body must be a JSON object."]}
            )
        unknown = sorted(set(data) - {"is_read"})
        if unknown:
            raise serializers.ValidationError(
                {key: [f"Only is_read may be updated: {', '.join(unknown)}"]}
            )
        return super().to_internal_value(data)


class DashboardQuery(serializers.Serializer):
    days = serializers.IntegerField(
        min_value=1,
        max_value=90,
        default=30,
    )


def local_midnight(day):
    value = datetime.combine(day, time.min)
    return timezone.make_aware(
        value,
        timezone.get_current_timezone(),
    )


def filter_scans(queryset, params):
    validator = ScanFilters(data=params)
    validator.is_valid(raise_exception=True)
    filters = validator.validated_data

    for field in ("module", "risk_level", "source"):
        if field in filters:
            queryset = queryset.filter(**{field: filters[field]})

    if "date_from" in filters:
        queryset = queryset.filter(
            created_at__gte=local_midnight(filters["date_from"])
        )
    if "date_to" in filters:
        queryset = queryset.filter(
            created_at__lt=local_midnight(
                filters["date_to"] + timedelta(days=1)
            )
        )
    return queryset


class ScanHistoryView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ScanSerializer
    pagination_class = HistoryPagination

    def get_queryset(self):
        owned = Scan.objects.filter(user=self.request.user)
        return filter_scans(
            owned,
            self.request.query_params,
        ).order_by("-created_at", "-id")


class ScanDetailView(generics.RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ScanSerializer
    lookup_url_kwarg = "scan_id"

    def get_queryset(self):
        return Scan.objects.filter(user=self.request.user)


class AlertListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = AlertSerializer
    pagination_class = HistoryPagination

    def get_queryset(self):
        validator = AlertFilters(data=self.request.query_params)
        validator.is_valid(raise_exception=True)
        queryset = Alert.objects.filter(user=self.request.user)
        return queryset.filter(
            **validator.validated_data
        ).order_by("-created_at", "-id")


class AlertDetailView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = AlertSerializer

    def get_queryset(self):
        return Alert.objects.filter(user=self.request.user)

    def patch(self, request, *args, **kwargs):
        alert = self.get_object()
        validator = AlertUpdateSerializer(data=request.data)
        validator.is_valid(raise_exception=True)
        alert.is_read = validator.validated_data["is_read"]
        alert.save(update_fields=["is_read"])
        return Response(self.get_serializer(alert).data)


class DashboardView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        validator = DashboardQuery(data=request.query_params)
        validator.is_valid(raise_exception=True)
        days = validator.validated_data["days"]

        today = timezone.localdate()
        first_day = today - timedelta(days=days - 1)
        start = local_midnight(first_day)
        end = local_midnight(today + timedelta(days=1))

        owned_scans = Scan.objects.filter(user=request.user)
        period_scans = owned_scans.filter(
            created_at__gte=start,
            created_at__lt=end,
        )
        owned_alerts = Alert.objects.filter(user=request.user)

        module_counts = {
            row["module"]: row["total"]
            for row in period_scans.values("module").annotate(
                total=Count("id")
            )
        }
        risk_counts = {
            row["risk_level"]: row["total"]
            for row in period_scans.values("risk_level").annotate(
                total=Count("id")
            )
        }
        daily_counts = {
            row["day"]: row["total"]
            for row in period_scans.annotate(
                day=TruncDate(
                    "created_at",
                    tzinfo=timezone.get_current_timezone(),
                )
            ).values("day").annotate(total=Count("id"))
        }

        daily = []
        for offset in range(days):
            day = first_day + timedelta(days=offset)
            daily.append({
                "date": day.isoformat(),
                "scans": daily_counts.get(day, 0),
            })

        return Response({
            "period": {
                "days": days,
                "date_from": first_day.isoformat(),
                "date_to": today.isoformat(),
                "timezone": timezone.get_current_timezone_name(),
            },
            "total_scans": owned_scans.count(),
            "period_scans": period_scans.count(),
            "period_high_risk_scans": period_scans.filter(
                risk_level__in=[
                    RiskLevel.HIGH,
                    RiskLevel.CRITICAL,
                ]
            ).count(),
            "unread_alerts": owned_alerts.filter(
                is_read=False
            ).count(),
            "by_module": {
                key: module_counts.get(key, 0)
                for key in Module.values
            },
            "by_risk": {
                key: risk_counts.get(key, 0)
                for key in RiskLevel.values
            },
            "daily_scans": daily,
            "recent_alerts": AlertSerializer(
                owned_alerts.order_by("-created_at", "-id")[:5],
                many=True,
            ).data,
            "note": (
                "Counts represent scans and model-generated alerts, "
                "not confirmed incidents. A batch upload is one scan."
            ),
        })