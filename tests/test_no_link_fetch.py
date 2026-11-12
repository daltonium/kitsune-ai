import socket
from pathlib import Path

import pytest
from django.contrib.auth import get_user_model

from scans.services import run_scan

ROOT = Path(__file__).resolve().parent.parent
FORBIDDEN = ("import requests", "urllib.request", "import socket", "http.client", "httpx", "aiohttp")


def test_email_detector_sources_have_no_network_imports():
    for name in ("text_preprocessing.py", "predictor.py"):
        text = (ROOT / "detectors" / "phishing_email" / name).read_text(encoding="utf-8")
        assert not [s for s in FORBIDDEN if s in text], name


@pytest.mark.django_db
def test_email_scan_makes_no_network_calls(monkeypatch, email_detector):
    def boom(*args, **kwargs):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    user = get_user_model().objects.create_user("net2", "net2@example.com", "pw12345!")
    body = {"subject": "Verify", "body": "Click http://never-resolved-12345.invalid/login to verify your account"}
    scan = run_scan(user=user, module="phishing_email", payload=body)
    assert scan.module == "phishing_email"