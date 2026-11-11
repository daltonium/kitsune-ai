import socket
from pathlib import Path

import pytest
from django.contrib.auth import get_user_model

from scans.services import run_scan

ROOT = Path(__file__).resolve().parent.parent
FORBIDDEN = ("import requests", "urllib.request", "import socket", "http.client", "httpx", "aiohttp")


def test_detector_sources_have_no_network_imports():
    for name in ("feature_extractor.py", "predictor.py"):
        text = (ROOT / "detectors" / "phishing_url" / name).read_text(encoding="utf-8")
        assert not [s for s in FORBIDDEN if s in text], name


@pytest.mark.django_db
def test_scan_makes_no_network_calls(monkeypatch, phishing_detector):
    def boom(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(socket, "gethostbyname", boom)

    user = get_user_model().objects.create_user("net", "net@example.com", "pw12345!")
    scan = run_scan(user=user, module="phishing_url", payload={"url": "http://never-resolved-12345.invalid/login"})
    assert scan.module == "phishing_url"