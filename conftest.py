import pytest

from detectors import registry
from detectors.phishing_url.predictor import PhishingURLDetector
from detectors.phishing_url.tests.synthetic import make_synthetic
from detectors.phishing_url.train_model import train_quick


@pytest.fixture(scope="session")
def demo_artifacts(tmp_path_factory):
    out = tmp_path_factory.mktemp("phishing_url_demo")
    urls, labels = make_synthetic(200, seed=1)
    train_quick(urls, labels, out)
    return out


@pytest.fixture
def phishing_detector(demo_artifacts):
    registry.register(PhishingURLDetector)
    inst = PhishingURLDetector(artifacts_dir=demo_artifacts)
    registry._INSTANCES["phishing_url"] = inst
    yield inst
    registry._INSTANCES.pop("phishing_url", None)