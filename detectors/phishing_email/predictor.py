from __future__ import annotations

import json
import logging

import joblib
import numpy as np
import sklearn

from ..base import BaseDetector, DetectionResult, risk_from_score
from ..exceptions import InvalidInputError, ModelNotLoadedError
from ..registry import register
from .text_preprocessing import PLACEHOLDERS, build_email_text, clean_text, count_links

log = logging.getLogger(__name__)
MAX_SUBJECT_CHARS = 300
MAX_BODY_CHARS = 50000
MIN_BODY_CHARS = 10


def _readable(term: str) -> str:
    for token, shown in PLACEHOLDERS.items():
        term = term.replace(token, shown)
    return term


@register
class PhishingEmailDetector(BaseDetector):
    key = "phishing_email"
    display_name = "Phishing Email"
    version = "1.0.0"
    artifact_files = ("vectorizer.joblib", "model.joblib", "meta.json")

    def load(self):
        meta = json.loads((self.artifacts_dir / "meta.json").read_text(encoding="utf-8"))
        if meta.get("sklearn_version") != sklearn.__version__:
            log.warning("phishing_email model trained with scikit-learn %s, running %s",
                        meta.get("sklearn_version"), sklearn.__version__)
        # Only load artifacts produced by our own training script.
        vectorizer = joblib.load(self.artifacts_dir / "vectorizer.joblib")
        model = joblib.load(self.artifacts_dir / "model.joblib")
        if hasattr(model, "coef_"):
            weights = np.asarray(model.coef_[0], dtype=float)
        elif hasattr(model, "feature_log_prob_"):
            weights = np.asarray(model.feature_log_prob_[1] - model.feature_log_prob_[0], dtype=float)
        else:
            raise ModelNotLoadedError("phishing_email: unsupported classifier, retrain the model")
        names = vectorizer.get_feature_names_out()
        if len(weights) != len(names):
            raise ModelNotLoadedError("phishing_email: vectorizer and model disagree, retrain the model")
        self._vectorizer, self._model, self._weights, self._terms = vectorizer, model, weights, names
        self._meta = meta
        self._phish_idx = list(model.classes_).index(1)

    def validate_input(self, payload):
        if not isinstance(payload, dict):
            raise InvalidInputError("Request body must be a JSON object with 'subject' and 'body'.")
        subject, body = payload.get("subject", ""), payload.get("body")
        if subject is None:
            subject = ""
        if not isinstance(subject, str):
            raise InvalidInputError("subject must be a string.")
        if len(subject) > MAX_SUBJECT_CHARS:
            raise InvalidInputError(f"subject must be at most {MAX_SUBJECT_CHARS} characters.")
        if body is None:
            raise InvalidInputError("body is required.")
        if not isinstance(body, str):
            raise InvalidInputError("body must be a string.")
        if len(body) > MAX_BODY_CHARS:
            raise InvalidInputError(f"body must be at most {MAX_BODY_CHARS} characters.")
        if len(body.strip()) < MIN_BODY_CHARS:
            raise InvalidInputError(f"body must contain at least {MIN_BODY_CHARS} characters.")
        return {"subject": subject.strip(), "body": body}

    def _predict(self, data):
        subject, body = data["subject"], data["body"]
        raw = build_email_text(subject, body)
        text = clean_text(raw)
        if len(text) < MIN_BODY_CHARS:
            raise InvalidInputError("The email has too little readable text to analyze.")

        X = self._vectorizer.transform([text])
        score = float(self._model.predict_proba(X)[0][self._phish_idx])
        threshold = self._meta.get("decision_threshold", 0.5)

        row = X.tocsr()
        cols, contrib = row.indices, row.data * self._weights[row.indices]
        order = np.argsort(-contrib)
        pos = [(cols[i], contrib[i]) for i in order if contrib[i] > 0][:5]
        neg = [(cols[i], contrib[i]) for i in order[::-1] if contrib[i] < 0][:3]
        links = count_links(raw)

        explanation = {
            "summary": (f"{len(pos)} term(s) pushed the score toward phishing; "
                        f"the email contains {links} link(s)."),
            "top_phishing_terms": [{"term": _readable(self._terms[c]), "weight": round(float(v), 3)} for c, v in pos],
            "top_legitimate_terms": [{"term": _readable(self._terms[c]), "weight": round(float(v), 3)} for c, v in neg],
            "link_count": links,
            "links_were_visited": False,
            "terms_note": "Terms show what pushed the score. They are not proof that an email is phishing.",
            "score_note": self._meta.get("score_meaning", ""),
        }
        return DetectionResult(
            prediction="Phishing" if score >= threshold else "Legitimate",
            risk_level=risk_from_score(score, tuple(self._meta.get("risk_thresholds", (0.3, 0.6, 0.85)))),
            score=round(score, 4),
            explanation=explanation,
            model_version=self._meta.get("model_version", ""),
            input_summary=f"Email (subject: {len(subject)} chars, body: {len(body)} chars, {links} links)",
        )