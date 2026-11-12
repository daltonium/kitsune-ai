import pytest
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile

from detectors.network_intrusion.tests.synthetic import flow_dict, make_flows
from scans.models import Scan

pytestmark = pytest.mark.django_db
URL = "/api/web/scan/network_intrusion/"


@pytest.fixture
def user():
    return get_user_model().objects.create_user("neo", "neo@example.com", "pw12345!")


def test_flow_json_scan(client, user, network_detector):
    client.force_login(user)
    X, _ = make_flows(10, seed=3)
    res = client.post(URL, {"flow": flow_dict(X.iloc[0])}, content_type="application/json")
    assert res.status_code == 201 and res.json()["module"] == "network_intrusion"
    assert Scan.objects.filter(user=user, module="network_intrusion").count() == 1


def test_csv_upload_scan(client, user, network_detector):
    client.force_login(user)
    X, _ = make_flows(12, seed=4)
    upload = SimpleUploadedFile("flows.csv", X.to_csv(index=False).encode(), content_type="text/csv")
    res = client.post(URL, {"file": upload})
    assert res.status_code == 201
    assert res.json()["explanation"]["flows_analyzed"] == 12


def test_bad_flow_returns_400(client, user, network_detector):
    client.force_login(user)
    res = client.post(URL, {"flow": {"nope": 1}}, content_type="application/json")
    assert res.status_code == 400 and res.json()["error"]["code"] == "invalid_input"
    assert Scan.objects.count() == 0