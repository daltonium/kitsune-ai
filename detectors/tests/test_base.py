import pytest

from detectors.base import (
    BaseDetector, DetectionResult, RISK_CRITICAL, RISK_HIGH, RISK_LOW, RISK_MEDIUM,
    risk_from_score,
)
from detectors.exceptions import ModelNotLoadedError


class Counting(BaseDetector):
    key = "demo"
    loads = 0

    def load(self):
        type(self).loads += 1

    def validate_input(self, payload):
        return payload

    def _predict(self, data):
        return DetectionResult("ok", RISK_LOW, 0.1)


def test_risk_from_score_bands():
    assert risk_from_score(0.1) == RISK_LOW
    assert risk_from_score(0.4) == RISK_MEDIUM
    assert risk_from_score(0.7) == RISK_HIGH
    assert risk_from_score(0.95) == RISK_CRITICAL


def test_result_rejects_bad_risk_level():
    with pytest.raises(ValueError):
        DetectionResult("x", "scary")


def test_missing_artifacts_raise(tmp_path):
    class NeedsFiles(Counting):
        artifact_files = ("model.joblib",)

    with pytest.raises(ModelNotLoadedError):
        NeedsFiles(artifacts_dir=tmp_path).analyze({})


def test_model_loads_once():
    Counting.loads = 0
    d = Counting()
    d.analyze({})
    d.analyze({})
    assert Counting.loads == 1