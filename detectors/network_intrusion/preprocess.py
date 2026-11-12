from __future__ import annotations

import io

import numpy as np
import pandas as pd

from ..exceptions import InvalidInputError
from .schema import must_be_non_negative, normalize_column


def read_flow_csv(raw: bytes, max_rows: int) -> pd.DataFrame:
    """Parse untrusted CSV bytes. Reads at most max_rows + 1 rows."""
    try:
        df = pd.read_csv(io.BytesIO(raw), encoding="latin-1", nrows=max_rows + 1, low_memory=False)
    except (pd.errors.ParserError, pd.errors.EmptyDataError, ValueError) as exc:
        raise InvalidInputError("The file could not be parsed as a CSV of flow records.") from exc
    df.columns = [normalize_column(c) for c in df.columns]
    return df.loc[:, ~df.columns.duplicated()]


def clean_features(df: pd.DataFrame, features):
    """Return (numeric frame of valid rows, boolean keep-mask aligned to df rows)."""
    features = list(features)
    X = df[features].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
    bad = X.isna().any(axis=1).to_numpy()
    for col in features:
        if must_be_non_negative(col):
            bad |= (X[col] < 0).to_numpy()
    keep = ~bad
    return X.loc[keep].astype("float64"), keep


def compute_baseline(X: pd.DataFrame):
    """Median and a positive scale per feature (IQR, else 5-95% range, else std, else 1)."""
    med = X.median()
    scale = X.quantile(0.75) - X.quantile(0.25)
    scale = scale.where(scale > 0, X.quantile(0.95) - X.quantile(0.05))
    scale = scale.where(scale > 0, X.std())
    scale = scale.where(scale > 0, 1.0)
    return {k: float(v) for k, v in med.items()}, {k: float(v) for k, v in scale.items()}


def unusual_features(values, names, medians, iqrs, top=3):
    """Features furthest from typical benign traffic (robust z-score). Descriptive only."""
    values = np.asarray(values, dtype=float)
    z = np.abs((values - medians) / iqrs)
    return [
        {
            "feature": names[i],
            "value": round(float(values[i]), 4),
            "typical_benign_value": round(float(medians[i]), 4),
            "robust_z": round(float(z[i]), 2),
        }
        for i in np.argsort(-z)[:top]
    ]