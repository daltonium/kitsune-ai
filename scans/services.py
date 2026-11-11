import re
import time

from django.conf import settings
from django.db import transaction

from detectors import registry
from detectors.base import RISK_ORDER

from .models import Alert, Scan

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def clean_summary(text: str, limit: int = 500) -> str:
    return _CONTROL_CHARS.sub(" ", text or "")[:limit]


def run_scan(*, user, module: str, payload: dict, source: str = Scan.Source.WEB) -> Scan:
    """The only route into a detector. Used by the web app and the paid API."""
    detector = registry.get_detector(module)

    started = time.perf_counter()
    result = detector.analyze(payload)
    latency_ms = int((time.perf_counter() - started) * 1000)

    with transaction.atomic():
        scan = Scan.objects.create(
            user=user,
            source=source,
            module=module,
            input_summary=clean_summary(result.input_summary),
            prediction=result.prediction,
            risk_level=result.risk_level,
            score=result.score,
            explanation=result.explanation,
            model_version=result.model_version,
            latency_ms=latency_ms,
        )
        if RISK_ORDER[result.risk_level] >= RISK_ORDER[settings.ALERT_MIN_RISK]:
            Alert.objects.create(
                scan=scan,
                user=user,
                severity=result.risk_level,
                title=f"{detector.display_name}: {result.prediction}",
                message=f"{result.risk_level.upper()} risk (score={result.score}).",
            )
    return scan