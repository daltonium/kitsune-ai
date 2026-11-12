import pytest

from detectors.base import RISK_ORDER
from detectors.exceptions import InvalidInputError, ModelNotLoadedError
from detectors.phishing_email.predictor import PhishingEmailDetector
from detectors.phishing_email.tests.synthetic import make_emails

SUBJECT = "Urgent: verify your account"
BODY = "Please verify your account password now: http://secure.example.top/login"


def det(art):
    return PhishingEmailDetector(artifacts_dir=art)


def test_valid_email_returns_full_result(email_artifacts):
    res = det(email_artifacts).analyze({"subject": SUBJECT, "body": BODY})
    assert res.prediction == "Phishing" and res.risk_level in RISK_ORDER and 0.0 <= res.score <= 1.0
    assert isinstance(res.explanation["top_phishing_terms"], list) and res.explanation["links_were_visited"] is False


def test_separates_unseen_synthetic_emails(email_artifacts):
    d = det(email_artifacts)
    texts, labels = make_emails(40, seed=99)
    hits = sum((d.analyze({"body": t}).score >= 0.5) == bool(y) for t, y in zip(texts, labels))
    assert hits / len(texts) >= 0.9


@pytest.mark.parametrize("payload", [
    {}, {"body": ""}, {"body": "   "}, {"body": 123},
    {"subject": 5, "body": "hello there friend"},
    {"subject": "x" * 301, "body": "hello there friend"},
    {"body": "a" * 50001}, "not a dict",
])
def test_invalid_input_rejected(email_artifacts, payload):
    with pytest.raises(InvalidInputError):
        det(email_artifacts).analyze(payload)


def test_email_with_no_readable_text_rejected(email_artifacts):
    with pytest.raises(InvalidInputError, match="too little"):
        det(email_artifacts).analyze({"body": "<br><br><br><br>"})


def test_summary_never_contains_email_content(email_artifacts):
    res = det(email_artifacts).analyze({"subject": "secret codename", "body": "my secret project codeword is zebra"})
    assert "zebra" not in res.input_summary and "codename" not in res.input_summary


def test_links_counted_not_visited(email_artifacts):
    body = "Please verify here http://a.example.top/x and also http://b.example.top/y today"
    res = det(email_artifacts).analyze({"body": body})
    assert res.explanation["link_count"] == 2 and res.explanation["links_were_visited"] is False


def test_missing_artifacts_raise(tmp_path):
    with pytest.raises(ModelNotLoadedError):
        det(tmp_path).analyze({"body": "hello there my friend"})