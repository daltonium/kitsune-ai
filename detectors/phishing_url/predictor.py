from __future__ import annotations

import json
import logging
from urllib.parse import urlsplit

import joblib
import pandas as pd
import sklearn

from ..base import BaseDetector, DetectionResult, risk_from_score
from ..exceptions import InvalidInputError, ModelNotLoadedError
from ..registry import register
from .feature_extractor import FEATURE_NAMES, extract_features, uses_https

log = logging.getLogger(__name__)
MAX_URL_LENGTH = 2048


def normalize_url(raw) -> str:
    if raw is None:
        raise InvalidInputError("url is required.")
    if not isinstance(raw, str):
        raise InvalidInputError("url must be a string.")
    url = raw.strip()
    if not url:
        raise InvalidInputError("url is required.")
    if len(url) > MAX_URL_LENGTH:
        raise InvalidInputError(f"url must be at most {MAX_URL_LENGTH} characters.")
    if any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise InvalidInputError("url must not contain spaces or control characters.")
    try:
        parts = urlsplit(url)
        host = parts.hostname
    except ValueError:
        raise InvalidInputError("url is not a valid URL.")
    if parts.scheme.lower() not in ("http", "https"):
        raise InvalidInputError("url must start with http:// or https://")
    if not host:
        raise InvalidInputError("url must include a hostname.")
    return url


def safe_summary(url: str) -> str:
    """Stored form of the URL: no credentials, query string or fragment."""
    parts = urlsplit(url)
    summary = f"{parts.scheme.lower()}://{parts.hostname or ''}{parts.path}"
    return summary + ("?[query omitted]" if parts.query else "")


def describe_signals(f: dict, url: str) -> list:
    signals = []
    if f["host_is_ip"]:
        signals.append("Host is an IP address instead of a domain name")
    if f["num_at"]:
        signals.append("URL contains an '@' symbol")
    if not uses_https(url):
        signals.append("Does not use HTTPS")
    if f["num_subdomains"] >= 3:
        signals.append(f"Unusually many subdomains ({int(f['num_subdomains'])})")
    if f["has_punycode"]:
        signals.append("Hostname uses punycode (possible look-alike characters)")
    if f["suspicious_keyword_count"]:
        signals.append(f"Contains {int(f['suspicious_keyword_count'])} sensitive keyword(s) such as login or verify")
    if f["url_length"] > 100:
        signals.append(f"Very long URL ({int(f['url_length'])} characters)")
    if f["host_num_hyphens"] >= 2:
        signals.append("Hostname contains several hyphens")
    if f["has_nonstandard_port"]:
        signals.append("Uses a non-standard port")
    if f["num_suspicious_chars"] >= 3:
        signals.append("Contains several unusual special characters")
    return signals


@register
class PhishingURLDetector(BaseDetector):
    key = "phishing_url"
    display_name = "Phishing URL"
    version = "1.0.0"
    artifact_files = ("model.joblib", "meta.json")

    def load(self):
        meta = json.loads((self.artifacts_dir / "meta.json").read_text(encoding="utf-8"))
        names = meta.get("feature_names") or []
        if not names or any(n not in FEATURE_NAMES for n in names):
            raise ModelNotLoadedError("phishing_url: model uses unknown features, retrain the model")
        if meta.get("sklearn_version") != sklearn.__version__:
            log.warning("phishing_url model trained with scikit-learn %s, running %s",
                        meta.get("sklearn_version"), sklearn.__version__)
        # Only load artifacts produced by our own training script.
        self._model = joblib.load(self.artifacts_dir / "model.joblib")
        if getattr(self._model, "n_features_in_", len(names)) != len(names):
            raise ModelNotLoadedError("phishing_url: model and metadata disagree, retrain the model")
        self._feature_names = names
        self._meta = meta
        self._phish_idx = list(self._model.classes_).index(1)

    def validate_input(self, payload):
        if not isinstance(payload, dict):
            raise InvalidInputError("Request body must be a JSON object.")
        return {"url": normalize_url(payload.get("url"))}

    def _predict(self, data):
        url = data["url"]
        try:
            feats = extract_features(url)
        except ValueError:
            raise InvalidInputError("url is not a valid URL.")
        row = pd.DataFrame([[feats[n] for n in self._feature_names]], columns=self._feature_names)
        score = float(self._model.predict_proba(row)[0][self._phish_idx])
        threshold = self._meta.get("decision_threshold", 0.5)
        signals = describe_signals(feats, url)
        summary = (
            f"{len(signals)} suspicious URL pattern(s) found."
            if signals else "No common suspicious URL patterns were found."
        )
        return DetectionResult(
            prediction="Phishing" if score >= threshold else "Legitimate",
            risk_level=risk_from_score(score, tuple(self._meta.get("risk_thresholds", (0.3, 0.6, 0.85)))),
            score=round(score, 4),
            explanation={
                "summary": summary,
                "signals": signals,
                "score_note": self._meta.get("score_meaning", ""),
                "url_was_visited": False,
            },
            model_version=self._meta.get("model_version", ""),
            input_summary=safe_summary(url),
        )