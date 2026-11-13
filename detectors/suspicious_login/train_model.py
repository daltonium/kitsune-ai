"""Train the suspicious-login Isolation Forest on CERT r4.2 logon.csv.

    python -m detectors.suspicious_login.train_model --quick
    python -m detectors.suspicious_login.train_model

The answer files are used ONLY to evaluate; they are never model inputs.
"""
from __future__ import annotations

import argparse
import json
import platform
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, roc_auc_score

from ..base import ARTIFACTS_ROOT
from .feature_extractor import BUSINESS_END, BUSINESS_START, FEATURE_NAMES, MIN_HISTORY, build_features
from .log_preprocessing import clean_events, frame_from_dataframe

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "datasets" / "cert_r4_2"
ARTIFACT_DIR = ARTIFACTS_ROOT / "suspicious_login"
METRICS_DIR = ARTIFACTS_ROOT / "metrics"
SEED = 42
LEVELS = {"medium": 0.98, "high": 0.995, "critical": 0.999}
ALERT_THRESHOLD = 0.995
GRID = np.linspace(0.0, 1.0, 1001)
SCORE_MEANING = (
    "Risk is the percentile of the anomaly score among normal training logons "
    "(0.995 means more unusual than 99.5 percent of them). It is not a probability of compromise."
)


def _json_default(obj):
    return obj.item() if hasattr(obj, "item") else str(obj)


def parse_answer_logons(answers_dir):
    """{logon event id: scenario number} from answers/r4.2-N/*.csv."""
    found = {}
    for path in sorted(Path(answers_dir).glob("r4.2-*/*.csv")):
        scenario = int(path.parent.name.rsplit("-", 1)[1])
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("logon,"):
                parts = line.split(",", 5)
                if (
                    len(parts) == 6
                    and parts[5].strip().lower() == "logon"
                ):
                    found[parts[1]] = scenario
    return found


def time_split(times, positive_times):
    """Train before the first attack, validation up to the median attack date, test after."""
    ordered = positive_times.sort_values().reset_index(drop=True)
    first = ordered.iloc[0].normalize()
    mid = ordered.iloc[len(ordered) // 2]
    train = (times < first).to_numpy()
    val = ((times >= first) & (times < mid)).to_numpy()
    test = (times >= mid).to_numpy()
    return train, val, test, first, mid


def evaluate(scores, risk, y, scenarios, n_days):
    out = {"n": int(len(y)), "positives": int(y.sum()), "base_rate": float(y.mean())}
    if y.sum() == 0 or y.sum() == len(y):
        return out
    out["roc_auc"] = float(roc_auc_score(y, scores))
    out["average_precision"] = float(average_precision_score(y, scores))
    table = {}
    for name, thr in LEVELS.items():
        flagged = risk >= thr
        tp = int((flagged & (y == 1)).sum())
        n_flag = int(flagged.sum())
        table[f"risk>={thr} ({name})"] = {
            "flagged": n_flag, "flagged_per_day": round(n_flag / max(n_days, 1), 2),
            "recall": tp / int(y.sum()), "precision": (tp / n_flag) if n_flag else None,
        }
    out["thresholds"] = table
    alert = risk >= ALERT_THRESHOLD
    by_scenario = {}
    for s in (1, 2, 3):
        m = scenarios == s
        by_scenario[str(s)] = {"positives": int(m.sum()),
                               "recall": float((alert & m).sum() / m.sum()) if m.sum() else None}
    out["recall_at_alert_by_scenario"] = by_scenario
    return out


def build_meta(model_name, metrics, extra, quantiles):
    now = datetime.now(timezone.utc)
    return {
        "module": "suspicious_login",
        "model_version": f"{model_name}-{now:%Y%m%d}",
        "trained_at": now.isoformat(),
        "feature_names": FEATURE_NAMES,
        "min_history": MIN_HISTORY,
        "business_hours": [BUSINESS_START, BUSINESS_END],
        "risk_levels": LEVELS,
        "alert_threshold": ALERT_THRESHOLD,
        "score_quantiles": [float(q) for q in quantiles],
        "score_meaning": SCORE_MEANING,
        "sklearn_version": sklearn.__version__,
        "python_version": platform.python_version(),
        "metrics": metrics,
        **extra,
    }


def save_artifacts(model, meta, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, out_dir / "model.joblib", compress=3)
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2, default=_json_default), encoding="utf-8")


def train_quick(features, out_dir, n_estimators=50):
    """Tiny model used by the tests. `features` has the FEATURE_NAMES columns."""
    X = features[FEATURE_NAMES].to_numpy(dtype=float)
    model = IsolationForest(n_estimators=n_estimators, random_state=SEED).fit(X)
    quantiles = np.quantile(-model.score_samples(X), GRID)
    save_artifacts(model, build_meta("suspicious_login-demo", {}, {"dataset": "synthetic"}, quantiles), out_dir)
    return model


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="all insiders plus 150 random users")
    args = ap.parse_args()

    t0 = time.time()
    logon_path = next(iter(DATA_DIR.rglob("logon.csv")), None)
    if logon_path is None:
        raise SystemExit(f"logon.csv not found under {DATA_DIR}.")
    answers = parse_answer_logons(DATA_DIR / "answers")
    if not answers:
        raise SystemExit("No logon events found in the answer files.")
    raw = pd.read_csv(logon_path, dtype=str, keep_default_na=False)
    if args.quick:
        bad_users = set(raw.loc[raw["id"].isin(answers), "user"])
        others = raw.loc[~raw["user"].isin(bad_users), "user"].drop_duplicates().sample(150, random_state=SEED)
        raw = raw[raw["user"].isin(bad_users | set(others))]
    print(f"read {len(raw)} events; {len(answers)} malicious logon ids in the answer files", flush=True)

    events, clean_stats = clean_events(frame_from_dataframe(raw))
    feats = build_features(events)
    info = events.loc[feats.index, ["id", "date"]].reset_index(drop=True)
    y = info["id"].isin(answers).to_numpy().astype(int)
    scen = info["id"].map(answers).fillna(0).astype(int).to_numpy()
    times = info["date"]
    if y.sum() == 0:
        raise SystemExit("None of the malicious logons has enough history to be scored.")
    tr, va, te, first, mid = time_split(times, times[y == 1])
    print(f"scored logons: {len(y)} | positives: {int(y.sum())} | first attack {first.date()} | median attack {mid.date()}")
    for name, m in (("train", tr), ("validation", va), ("test", te)):
        print(f"  {name}: {int(m.sum())} logons, {int(y[m].sum())} positives")
    if y[va].sum() == 0 or y[te].sum() == 0:
        raise SystemExit("Validation or test split has no positives; check the dates.")

    X = feats[FEATURE_NAMES].to_numpy(dtype=float)
    X_tr, X_va, X_te = X[tr], X[va], X[te]
    candidates, selection = {}, {}
    for ms in (256, 1024, 4096):
        model = IsolationForest(n_estimators=300, max_samples=min(ms, len(X_tr)), random_state=SEED, n_jobs=-1).fit(X_tr)
        s_va = -model.score_samples(X_va)
        selection[f"max_samples={ms}"] = {
            "val_average_precision": float(average_precision_score(y[va], s_va)),
            "val_roc_auc": float(roc_auc_score(y[va], s_va)),
        }
        candidates[f"max_samples={ms}"] = model
        print(f"validation {ms}: {selection[f'max_samples={ms}']}", flush=True)
    best = max(selection, key=lambda k: selection[k]["val_average_precision"])
    model = candidates[best]
    print(f"\nSelected: {best}")

    quantiles = np.quantile(-model.score_samples(X_tr), GRID)

    def risk_of(scores):
        return np.interp(scores, quantiles, GRID)

    def days(mask):
        t = times[mask]
        return (t.max() - t.min()).days + 1

    s_va, s_te = -model.score_samples(X_va), -model.score_samples(X_te)
    metrics = {
        "validation": evaluate(s_va, risk_of(s_va), y[va], scen[va], days(va)),
        "test": evaluate(s_te, risk_of(s_te), y[te], scen[te], days(te)),
    }
    print("\nMETRICS (test evaluated once):")
    print(json.dumps(metrics, indent=2, default=_json_default))

    extra = {
        "selection": selection, "selected": best,
        "dataset": {
            "name": "CERT r4.2 logon.csv (Hugging Face mirror) + answer files for evaluation only",
            "quick_run": bool(args.quick), "cleaning": clean_stats,
            "scored_logons": int(len(y)), "positives": int(y.sum()),
            "positives_by_scenario": {str(s): int((scen == s).sum()) for s in (1, 2, 3)},
            "split": {"train_before": str(first.date()), "validation_until": str(mid.date())},
            "caveats": ["synthetic data", "no success/failure field in logon.csv",
                        "scenario 2 has almost no logon footprint", "very few positives; metrics are noisy"],
        },
    }
    meta = build_meta("suspicious_login-isolation_forest", metrics, extra, quantiles)
    METRICS_DIR.mkdir(parents=True, exist_ok=True)
    (METRICS_DIR / "suspicious_login_metrics.json").write_text(json.dumps(meta, indent=2, default=_json_default), encoding="utf-8")
    save_artifacts(model, meta, ARTIFACT_DIR)
    print(f"\nSaved model + meta to {ARTIFACT_DIR}\nDone in {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()