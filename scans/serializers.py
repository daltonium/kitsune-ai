from rest_framework import serializers

from .models import Alert, Scan

DISCLAIMER = "Predictions are risk estimates, not proof that something is safe or malicious."


class ScanSerializer(serializers.ModelSerializer):
    scan_id = serializers.UUIDField(source="id", read_only=True)
    disclaimer = serializers.SerializerMethodField()

    class Meta:
        model = Scan
        fields = (
            "scan_id", "module", "prediction", "risk_level", "score",
            "explanation", "model_version", "latency_ms", "input_summary",
            "source", "created_at", "disclaimer",
        )
        read_only_fields = fields

    def get_disclaimer(self, obj):
        return DISCLAIMER


class AlertSerializer(serializers.ModelSerializer):
    scan_id = serializers.UUIDField(source="scan.id", read_only=True)

    class Meta:
        model = Alert
        fields = ("id", "scan_id", "severity", "title", "message", "is_read", "created_at")
        read_only_fields = fields