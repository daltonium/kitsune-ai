from __future__ import annotations

import hashlib
import json
import logging
import os
import re

import joblib
import numpy as np
import sklearn

from ..base import BaseDetector, DetectionResult
from ..exceptions import InvalidInputError, ModelNotLoadedError
from ..registry import register
from .feature_extractor import FEATURE_NAMES, build_features, describe_reasons
from .log_preprocessing import clean_events, frame_from_csv, frame_from_events

log = logging.getLogger(__name__)
MAX_EVENTS = 20000
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_SHOWN = 10


def _ref(value) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:10]


def level_for(risk, levels) -> str:
    if risk >= levels["critical"]:
        return "critical"
    if risk >= levels["high"]:
        return "high"
    if risk >= levels["medium"]:
        return "medium"
    return "low"


@register
class SuspiciousLoginDetector(BaseDetector):
    key = "suspicious_login"
    display_name = "Suspicious Login"
    version = "1.0.0"
    artifact_files = ("model.joblib", "meta.json")

    def load(self):
        meta = json.loads((self.artifacts_dir / "meta.json").read_text(encoding="utf-8"))
        if meta.get("feature_names") != FEATURE_NAMES:
            raise ModelNotLoadedError("suspicious_login: feature set changed, retrain the model")
        if meta.get("sklearn_version") != sklearn.__version__:
            log.warning("suspicious_login model trained with scikit-learn %s, running %s",
                        meta.get("sklearn_version"), sklearn.__version__)
        # Only load artifacts produced by our own training script.
        self._model = joblib.load(self.artifacts_dir / "model.joblib")
        self._quantiles = np.asarray(meta["score_quantiles"], dtype=float)
        self._grid = np.linspace(0.0, 1.0, len(self._quantiles))
        self._levels, self._alert = meta["risk_levels"], float(meta["alert_threshold"])
        self._min_history = int(meta["min_history"])
        self._meta = meta

    def validate_input(self, payload):
        if not isinstance(payload, dict):
            raise InvalidInputError("Send either 'events' (a list of login events) or a CSV 'file'.")
        events, upload = payload.get("events"), payload.get("file")
        if events is not None and upload is not None:
            raise InvalidInputError("Send either 'events' or 'file', not both.")
        if events is not None:
            if not isinstance(events, list) or not events:
                raise InvalidInputError("events must be a non-empty list.")
            if len(events) > MAX_EVENTS:
                raise InvalidInputError(f"Too many events (maximum {MAX_EVENTS}).")
            return {"frame": frame_from_events(events)}
        if upload is not None:
            return {"frame": self._read_upload(upload)}
        raise InvalidInputError("Provide 'events' (list) or 'file' (CSV upload).")

    @staticmethod
    def _read_upload(upload):
        if not hasattr(upload, "read"):
            raise InvalidInputError("file must be uploaded as a CSV file (multipart/form-data).")
        name = os.path.basename(str(getattr(upload, "name", "") or ""))
        if not name.lower().endswith(".csv"):
            raise InvalidInputError("Only .csv files are accepted.")
        too_large = f"File is too large (maximum {MAX_UPLOAD_BYTES / 1024 / 1024:.0f} MB)."
        size = getattr(upload, "size", None)
        if isinstance(size, int) and size > MAX_UPLOAD_BYTES:
            raise InvalidInputError(too_large)
        raw = upload.read(MAX_UPLOAD_BYTES + 1)
        if isinstance(raw, str):
            raw = raw.encode("utf-8", "replace")
        if len(raw) > MAX_UPLOAD_BYTES:
            raise InvalidInputError(too_large)
        if not raw.strip():
            raise InvalidInputError("The uploaded file is empty.")
        frame = frame_from_csv(raw, MAX_EVENTS)
        if len(frame) > MAX_EVENTS:
            raise InvalidInputError(f"Too many events (maximum {MAX_EVENTS}).")
        return frame

    def _predict(self, data):
        events, stats = clean_events(data["frame"])
        if events.empty:
            raise InvalidInputError("No valid login events found (check timestamps, user and device fields).")
        feats = build_features(events, min_history=self._min_history)
        if feats.empty:
            raise InvalidInputError(
                f"No logon has enough earlier history: each user needs at least {self._min_history} "
                "earlier logons in the same request. Include more history."
            )
        raw_scores = -self._model.score_samples(feats[FEATURE_NAMES].to_numpy(dtype=float))
        risk = np.interp(raw_scores, self._quantiles, self._grid)
        n_flagged = int((risk >= self._alert).sum())
        top_risk = float(risk.max())

        shown = []
        for i in np.argsort(-risk)[:MAX_SHOWN]:
            if risk[i] < self._levels["medium"]:
                break
            idx = feats.index[i]
            ev = events.loc[idx]
            shown.append({
                "row": int(ev["_row"]),
                "time": ev["date"].isoformat(),
                "risk": round(float(risk[i]), 4),
                "level": level_for(float(risk[i]), self._levels),
                "reasons": describe_reasons(feats.iloc[i]),
                "user_ref": _ref(ev["user"]),
                "pc_ref": _ref(ev["pc"]),
            })

        explanation = {
            "summary": (f"{n_flagged} of {len(risk)} scored logons look unusual for their users."
                        if n_flagged else "No scored logon looked unusual for its user."),
            **stats,
            "logon_events_scored": int(len(risk)),
            "flagged_count": n_flagged,
            "alert_threshold": self._alert,
            "top_events": shown,
            "refs_note": "user_ref and pc_ref are short hashes; use row numbers to find events in your data.",
            "limits_note": "Detects unusual login behaviour only. It cannot prove an account is compromised.",
            "score_note": self._meta.get("score_meaning", ""),
        }
        return DetectionResult(
            prediction="Suspicious" if n_flagged else "Normal",
            risk_level=level_for(top_risk, self._levels),
            score=round(top_risk, 4),
            explanation=explanation,
            model_version=self._meta.get("model_version", ""),
            input_summary=f"{stats['events_received']} login events received, {len(risk)} logons scored",
        )