import pytest

from detectors import registry
from detectors.network_intrusion.predictor import NetworkIntrusionDetector
from detectors.network_intrusion.tests.synthetic import make_flows
from detectors.network_intrusion.train_model import train_quick as train_network_quick
from detectors.phishing_email.predictor import PhishingEmailDetector
from detectors.phishing_email.tests.synthetic import make_emails
from detectors.phishing_email.train_model import train_quick as train_email_quick
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


@pytest.fixture(scope="session")
def network_artifacts(tmp_path_factory):
    out = tmp_path_factory.mktemp("network_demo")
    X, y = make_flows(400, seed=1)
    train_network_quick(X, y, out)
    return out


@pytest.fixture
def network_detector(network_artifacts):
    registry.register(NetworkIntrusionDetector)
    inst = NetworkIntrusionDetector(artifacts_dir=network_artifacts)
    registry._INSTANCES["network_intrusion"] = inst
    yield inst
    registry._INSTANCES.pop("network_intrusion", None)


@pytest.fixture(scope="session")
def email_artifacts(tmp_path_factory):
    out = tmp_path_factory.mktemp("email_demo")
    texts, labels = make_emails(200, seed=1)
    train_email_quick(texts, labels, out)
    return out


@pytest.fixture
def email_detector(email_artifacts):
    registry.register(PhishingEmailDetector)
    inst = PhishingEmailDetector(artifacts_dir=email_artifacts)
    registry._INSTANCES["phishing_email"] = inst
    yield inst
    registry._INSTANCES.pop("phishing_email", None)