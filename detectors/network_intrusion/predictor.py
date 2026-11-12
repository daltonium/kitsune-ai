from __future__ import annotations

import json
import logging
import os
import re
from math import isfinite

import joblib
import numpy as np
import pandas as pd
import sklearn

from ..base import (
    RISK_CRITICAL, RISK_HIGH, RISK_LOW, RISK_MEDIUM,
    BaseDetector, DetectionResult, risk_from_score,
)
from ..exceptions import InvalidInputError, ModelNotLoadedError
from ..registry import register
from .preprocess import clean_features, read_flow_csv, unusual_features
from .schema import (
    CIC_FEATURES, MAX_FLOW_FIELDS, MAX_FLOWS, MAX_UPLOAD_BYTES,
    must_be_non_negative, normalize_column,
)

log = logging.getLogger(__name__)


def _preview(names, k=5):
    names = list(names)
    return ", ".join(names[:k]) + (f" (+{len(names) - k} more)" if len(names) > k else "")


def batch_risk(attacks: int, n: int) -> str:
    if attacks == 0:
        return RISK_LOW
    share = attacks / n
    if share < 0.01:
        return RISK_MEDIUM
    if share < 0.10:
        return RISK_HIGH
    return RISK_CRITICAL


@register
class NetworkIntrusionDetector(BaseDetector):
    key = "network_intrusion"
    display_name = "Network Intrusion"
    version = "1.0.0"
    artifact_files = ("model.joblib", "meta.json")

    def load(self):
        meta = json.loads((self.artifacts_dir / "meta.json").read_text(encoding="utf-8"))
        names = meta.get("feature_names") or []
        if not names or any(n not in CIC_FEATURES for n in names):
            raise ModelNotLoadedError("network_intrusion: model uses unknown features, retrain the model")
        if meta.get("sklearn_version") != sklearn.__version__:
            log.warning("network_intrusion model trained with scikit-learn %s, running %s",
                        meta.get("sklearn_version"), sklearn.__version__)
        # Only load artifacts produced by our own training script.
        self._model = joblib.load(self.artifacts_dir / "model.joblib")
        if getattr(self._model, "n_features_in_", len(names)) != len(names):
            raise ModelNotLoadedError("network_intrusion: model and metadata disagree, retrain the model")
        try:
            self._medians = np.array([meta["benign_median"][n] for n in names], dtype=float)
            iqrs = np.array([meta["benign_iqr"][n] for n in names], dtype=float)
        except KeyError:
            raise ModelNotLoadedError("network_intrusion: baseline statistics missing, retrain the model")
        iqrs[iqrs <= 0] = 1.0
        self._iqrs = iqrs
        self._feature_names = names
        self._meta = meta
        self._attack_idx = list(self._model.classes_).index(1)

    # ---- input handling -------------------------------------------------
    def validate_input(self, payload):
        if not isinstance(payload, dict):
            raise InvalidInputError("Request body must be a JSON object or a CSV upload.")
        flow, upload = payload.get("flow"), payload.get("file")
        if flow is not None and upload is not None:
            raise InvalidInputError("Send either 'flow' or 'file', not both.")
        if flow is not None:
            if not isinstance(flow, dict) or not flow:
                raise InvalidInputError("flow must be a JSON object of flow features.")
            if len(flow) > MAX_FLOW_FIELDS:
                raise InvalidInputError(f"flow has too many fields (maximum {MAX_FLOW_FIELDS}).")
            return {"kind": "flow", "flow": flow}
        if upload is not None:
            raw, name = self._read_upload(upload)
            return {"kind": "csv", "raw": raw, "name": name}
        raise InvalidInputError("Provide either 'flow' (JSON object) or 'file' (CSV upload).")

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
        return raw, re.sub(r"[^A-Za-z0-9._-]", "_", name)[:60]

    def _flow_to_frame(self, flow):
        names = self._feature_names
        norm = {}
        for k, v in flow.items():
            nk = normalize_column(k)
            if nk in norm:
                raise InvalidInputError(f"Duplicate field after normalisation: {k}")
            norm[nk] = v
        unknown = [k for k in norm if k not in names]
        if unknown:
            raise InvalidInputError(f"Unknown field(s): {_preview(unknown)}. Only the model's feature fields are accepted.")
        missing = [n for n in names if n not in norm]
        if missing:
            raise InvalidInputError(f"Missing required feature(s): {_preview(missing)}.")
        row = []
        for n in names:
            v = norm[n]
            if isinstance(v, bool) or not isinstance(v, (int, float)) or not isfinite(v):
                raise InvalidInputError(f"Field '{n}' must be a finite number.")
            if must_be_non_negative(n) and v < 0:
                raise InvalidInputError(f"Field '{n}' must not be negative.")
            row.append(float(v))
        return pd.DataFrame([row], columns=names), 0, 0

    def _csv_to_frame(self, raw):
        names = self._feature_names
        df = read_flow_csv(raw, MAX_FLOWS)
        if len(df) > MAX_FLOWS:
            raise InvalidInputError(f"CSV has too many flows (maximum {MAX_FLOWS}).")
        if df.empty:
            raise InvalidInputError("CSV contains no rows.")
        missing = [n for n in names if n not in df.columns]
        if missing:
            raise InvalidInputError(f"CSV is missing required column(s): {_preview(missing)}.")
        X, keep = clean_features(df, names)
        skipped = int((~keep).sum())
        if X.empty:
            raise InvalidInputError("No valid flows found: every row had missing, non-numeric or invalid values.")
        name_set = set(names)
        ignored = sum(1 for c in df.columns if c not in name_set)
        return X, skipped, ignored

    # ---- prediction -----------------------------------------------------
    def _predict(self, data):
        if data["kind"] == "flow":
            X, skipped, ignored = self._flow_to_frame(data["flow"])
            source_text = "1 network flow"
        else:
            X, skipped, ignored = self._csv_to_frame(data["raw"])
            source_text = f"CSV upload '{data['name']}': {len(X)} flows analyzed"

        scores = self._model.predict_proba(X)[:, self._attack_idx]
        threshold = self._meta.get("decision_threshold", 0.5)
        thresholds = tuple(self._meta.get("risk_thresholds", (0.3, 0.6, 0.85)))
        n = int(len(scores))
        attacks = int((scores >= threshold).sum())
        top = int(np.argmax(scores))
        max_score = float(scores[top])

        if data["kind"] == "flow":
            risk = risk_from_score(max_score, thresholds)
            kind_text = "attack traffic" if attacks else "benign traffic"
            summary = f"This flow looks like {kind_text} (model score {max_score:.2f})."
        else:
            risk = batch_risk(attacks, n)
            summary = (
                f"{attacks} of {n} flows ({attacks / n:.1%}) were flagged as possible attacks."
                if attacks else "No flows were flagged as possible attacks."
            )

        explanation = {
            "summary": summary,
            "flows_analyzed": n,
            "benign_count": n - attacks,
            "attack_count": attacks,
            "attack_share": round(attacks / n, 4),
            "skipped_rows": skipped,
            "ignored_columns": ignored,
            "max_score": round(max_score, 4),
            "unusual_features": unusual_features(
                X.iloc[top].to_numpy(), self._feature_names, self._medians, self._iqrs),
            "unusual_features_note": (
                "Compared with typical benign traffic for the highest-scoring flow. "
                "Descriptive only: this is not a model attribution."
            ),
            "score_note": self._meta.get("score_meaning", ""),
        }
        return DetectionResult(
            prediction="Attack" if attacks else "Benign",
            risk_level=risk,
            score=round(max_score, 4),
            explanation=explanation,
            model_version=self._meta.get("model_version", ""),
            input_summary=source_text,
        )