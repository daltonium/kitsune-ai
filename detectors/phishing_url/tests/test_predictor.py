import json

import pytest

from detectors.base import RISK_ORDER, DetectionResult
from detectors.exceptions import InvalidInputError, ModelNotLoadedError
from detectors.phishing_url.predictor import PhishingURLDetector
from detectors.phishing_url.tests.synthetic import make_synthetic


def test_valid_url_returns_full_result(demo_artifacts):
    res = PhishingURLDetector(artifacts_dir=demo_artifacts).analyze({"url": "http://10.0.0.5/login/verify"})
    assert isinstance(res, DetectionResult)
    assert res.prediction in ("Phishing", "Legitimate")
    assert 0.0 <= res.score <= 1.0 and res.risk_level in RISK_ORDER
    assert isinstance(res.explanation["signals"], list) and res.explanation["url_was_visited"] is False
    assert res.model_version


def test_model_separates_unseen_synthetic_urls(demo_artifacts):
    det = PhishingURLDetector(artifacts_dir=demo_artifacts)
    urls, labels = make_synthetic(40, seed=99)
    hits = sum((det.analyze({"url": u}).score >= 0.5) == bool(y) for u, y in zip(urls, labels))
    assert hits / len(urls) >= 0.9


@pytest.mark.parametrize("payload", [
    {}, {"url": ""}, {"url": "   "}, {"url": "example.com"}, {"url": "ftp://example.com"},
    {"url": "http://"}, {"url": "http://a b.com"}, {"url": "http://" + "a" * 3000}, {"url": 123},
])
def test_invalid_input_rejected(demo_artifacts, payload):
    with pytest.raises(InvalidInputError):
        PhishingURLDetector(artifacts_dir=demo_artifacts).analyze(payload)


def test_summary_hides_credentials_and_query(demo_artifacts):
    res = PhishingURLDetector(artifacts_dir=demo_artifacts).analyze({"url": "https://user:pw@site.com/p?token=secret#frag"})
    assert "secret" not in res.input_summary and "pw" not in res.input_summary and "frag" not in res.input_summary
    assert res.input_summary.startswith("https://site.com/p")


def test_missing_artifacts_raise(tmp_path):
    with pytest.raises(ModelNotLoadedError):
        PhishingURLDetector(artifacts_dir=tmp_path).analyze({"url": "https://example.com"})


def test_feature_mismatch_refuses_to_load(demo_artifacts, tmp_path):
    (tmp_path / "model.joblib").write_bytes((demo_artifacts / "model.joblib").read_bytes())
    meta = json.loads((demo_artifacts / "meta.json").read_text())
    meta["feature_names"] = meta["feature_names"][:-1]
    (tmp_path / "meta.json").write_text(json.dumps(meta))
    with pytest.raises(ModelNotLoadedError):
        PhishingURLDetector(artifacts_dir=tmp_path).analyze({"url": "https://example.com"})