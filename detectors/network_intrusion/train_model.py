"""Train the network-intrusion model on CIC-IDS2017 MachineLearningCSV (benign vs attack).

    python -m detectors.network_intrusion.train_model --quick
    python -m detectors.network_intrusion.train_model
    python -m detectors.network_intrusion.train_model --holdout Wednesday --model xgboost
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
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, brier_score_loss, confusion_matrix,
    precision_recall_fscore_support, roc_auc_score,
)
from sklearn.model_selection import train_test_split

from ..base import ARTIFACTS_ROOT
from .preprocess import compute_baseline
from .schema import (
    CIC_FEATURES, DEFAULT_FEATURES, fix_label, is_attack_label,
    must_be_non_negative, normalize_column,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASET_DIR = REPO_ROOT / "datasets" / "cicids2017"
ARTIFACT_DIR = ARTIFACTS_ROOT / "network_intrusion"
METRICS_DIR = ARTIFACTS_ROOT / "metrics"
SEED = 42
THRESHOLDS = [0.30, 0.60, 0.85]
DECISION_THRESHOLD = 0.5
SCORE_MEANING = (
    "Raw model probability that the flow is an attack. "
    "Not calibrated: it is not a real-world probability of an intrusion."
)


def _json_default(obj):
    return obj.item() if hasattr(obj, "item") else str(obj)


def load_dataset(folder):
    files = sorted(Path(folder).rglob("*.csv"))
    if not files:
        raise SystemExit(f"No CSV files in {folder}. Extract the CIC-IDS2017 flow CSVs there.")
    cols = list(CIC_FEATURES)
    frames, stats = [], {"files": {}}
    for f in files:
        raw = pd.read_csv(f, encoding="latin-1", low_memory=False)
        raw.columns = [normalize_column(c) for c in raw.columns]
        raw = raw.loc[:, ~raw.columns.duplicated()]
        missing = [c for c in cols if c not in raw.columns]
        if missing or "label" not in raw.columns:
            raise SystemExit(f"{f.name}: missing columns {missing[:10]}; label present: {'label' in raw.columns}")
        feats = raw[cols].apply(pd.to_numeric, errors="coerce").astype("float32")
        feats = feats.replace([np.inf, -np.inf], np.nan)
        labels = raw["label"].astype(str)
        mapping = {u: fix_label(u) for u in labels.unique()}
        feats["label"] = labels.map(mapping).to_numpy()
        feats["source_file"] = f.name
        stats["files"][f.name] = int(len(feats))
        frames.append(feats)
        print(f"  loaded {f.name}: {len(feats)} rows")
    df = pd.concat(frames, ignore_index=True)
    del frames
    stats["raw_rows"] = int(len(df))

    bad = df[cols].isna().any(axis=1)
    stats["dropped_missing_or_infinite"] = int(bad.sum())
    neg = pd.Series(False, index=df.index)
    for c in cols:
        if must_be_non_negative(c):
            neg |= df[c] < 0
    stats["dropped_impossible_negative"] = int((neg & ~bad).sum())
    df = df[~(bad | neg)].reset_index(drop=True)

    amap = {u: int(is_attack_label(u)) for u in df["label"].unique()}
    df["is_attack"] = df["label"].map(amap).astype("int8")
    df["_h"] = pd.util.hash_pandas_object(df[cols], index=False).to_numpy()
    n_vals = df.groupby("_h")["is_attack"].nunique()
    conflicting = n_vals[n_vals > 1].index
    stats["conflicting_duplicate_rows_removed"] = int(df["_h"].isin(conflicting).sum())
    df = df[~df["_h"].isin(conflicting)]
    before = len(df)
    df = df.drop_duplicates(subset="_h")
    stats["exact_duplicates_removed"] = int(before - len(df))
    df = df.drop(columns="_h").reset_index(drop=True)
    stats["final_rows"] = int(len(df))
    return df, stats


def safe_split(idx, key, test_size):
    try:
        return train_test_split(idx, test_size=test_size, stratify=key, random_state=SEED)
    except ValueError:
        return train_test_split(idx, test_size=test_size, random_state=SEED)


def make_split(df, holdout):
    idx = np.arange(len(df))
    if holdout:
        mask = df["source_file"].str.contains(holdout, case=False, regex=False).to_numpy()
        if not mask.any() or mask.all():
            raise SystemExit(f"--holdout {holdout!r} must match some, but not all, files.")
        return idx[~mask], idx[mask], f"holdout_{holdout.lower()}"
    counts = df["label"].value_counts()
    key = df["label"].where(df["label"].map(counts) >= 2, "rare")
    tr, te = safe_split(idx, key, 0.2)
    return tr, te, "random"


def cap_training(df, cap_benign, cap_attack):
    parts = []
    for lab, g in df.groupby("label", sort=False):
        cap = cap_attack if is_attack_label(lab) else cap_benign
        parts.append(g.sample(n=min(len(g), cap), random_state=SEED))
    return pd.concat(parts, ignore_index=True)


def make_rf(n_estimators):
    return RandomForestClassifier(
        n_estimators=n_estimators, min_samples_leaf=2, class_weight="balanced_subsample",
        n_jobs=-1, random_state=SEED,
    )


def make_xgb(n_estimators):
    from xgboost import XGBClassifier

    return XGBClassifier(
        n_estimators=n_estimators, max_depth=8, learning_rate=0.1, subsample=0.8,
        colsample_bytree=0.8, tree_method="hist", n_jobs=-1, random_state=SEED,
        eval_metric="logloss",
    )


def evaluate(model, X, y, labels):
    proba = model.predict_proba(X)[:, 1]
    pred = (proba >= DECISION_THRESHOLD).astype(int)
    cm = confusion_matrix(y, pred, labels=[0, 1])
    tn, fp, fn, tp = (int(v) for v in cm.ravel())
    p, r, f, _ = precision_recall_fscore_support(y, pred, average="binary", pos_label=1, zero_division=0)
    two_classes = len(np.unique(y)) == 2
    out = {
        "n_test": int(len(y)),
        "accuracy": float(accuracy_score(y, pred)),
        "precision_attack": float(p),
        "recall_attack": float(r),
        "f1_attack": float(f),
        "attack_recall": float(tp / (tp + fn)) if (tp + fn) else None,
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else None,
        "roc_auc": float(roc_auc_score(y, proba)) if two_classes else None,
        "brier_score": float(brier_score_loss(y, proba)) if two_classes else None,
        "confusion_matrix": {"labels": ["benign", "attack"], "matrix": cm.tolist()},
    }
    per = {}
    for lab in np.unique(labels):
        m = labels == lab
        per[str(lab)] = {
            "n": int(m.sum()),
            "kind": "attack_recall" if is_attack_label(lab) else "benign_false_positive_rate",
            "flagged_as_attack": round(float((pred[m] == 1).mean()), 4),
        }
    out["per_label"] = per
    return out


def build_meta(model_name, metrics, extra, feature_names, medians, iqrs):
    now = datetime.now(timezone.utc)
    return {
        "module": "network_intrusion",
        "model_version": f"{model_name}-{now:%Y%m%d}",
        "trained_at": now.isoformat(),
        "feature_names": list(feature_names),
        "benign_median": medians,
        "benign_iqr": iqrs,
        "positive_class": "attack",
        "decision_threshold": DECISION_THRESHOLD,
        "risk_thresholds": THRESHOLDS,
        "batch_risk_rules": "no flagged flows: low; under 1% flagged: medium; under 10%: high; otherwise critical",
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


def train_quick(X, y, out_dir, n_estimators=20):
    """Small, fast training used by the tests. y: 1 = attack."""
    model = make_rf(n_estimators).fit(X, y)
    med, iqr = compute_baseline(X[np.asarray(y) == 0])
    meta = build_meta("network_intrusion-demo", {}, {"dataset": "synthetic"}, list(X.columns), med, iqr)
    save_artifacts(model, meta, out_dir)
    return model


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--folder", default=str(DATASET_DIR))
    ap.add_argument("--holdout", help="substring of a CSV filename to hold out as the test set")
    ap.add_argument("--include-port", action="store_true")
    ap.add_argument("--model", choices=["auto", "random_forest", "xgboost"], default="auto")
    ap.add_argument("--n-estimators", type=int, default=150)
    ap.add_argument("--max-benign", type=int, default=300000)
    ap.add_argument("--max-attack-per-label", type=int, default=60000)
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    if args.quick:
        args.max_benign, args.max_attack_per_label, args.n_estimators = 30000, 6000, 60

    t0 = time.time()
    print("Loading CSV files...")
    df, stats = load_dataset(args.folder)
    print("\nCleaning stats:", json.dumps(stats))
    print("\nLabel counts after cleaning:")
    print(df["label"].value_counts().to_string())

    features = list(CIC_FEATURES) if args.include_port else list(DEFAULT_FEATURES)
    tr, te, tag = make_split(df, args.holdout)
    train_df = cap_training(df.iloc[tr], args.max_benign, args.max_attack_per_label)
    X_tr, y_tr = train_df[features], train_df["is_attack"].to_numpy()
    lab_tr = train_df["label"].to_numpy()
    print(f"\nSplit={tag}  train(capped)={len(train_df)}  test={len(te)}  features={len(features)}  ({time.time()-t0:.0f}s)")

    factories = {
        "random_forest": lambda: make_rf(args.n_estimators),
        "xgboost": lambda: make_xgb(100 if args.quick else 300),
    }
    names = list(factories) if args.model == "auto" else [args.model]
    selection = {}
    if len(names) > 1:
        counts = train_df["label"].value_counts()
        key = train_df["label"].where(train_df["label"].map(counts) >= 4, "rare")
        fit_idx, val_idx = safe_split(np.arange(len(train_df)), key, 0.15)
        for name in names:
            t1 = time.time()
            m = factories[name]().fit(X_tr.iloc[fit_idx], y_tr[fit_idx])
            v = evaluate(m, X_tr.iloc[val_idx], y_tr[val_idx], lab_tr[val_idx])
            selection[name] = {
                "val_f1_attack": v["f1_attack"],
                "val_false_positive_rate": v["false_positive_rate"],
                "val_attack_recall": v["attack_recall"],
                "fit_seconds": round(time.time() - t1, 1),
            }
            print(f"validation {name}:", selection[name])
        best_name = max(selection, key=lambda k: selection[k]["val_f1_attack"])
    else:
        best_name = names[0]
    print(f"\nSelected model: {best_name}")
    model = factories[best_name]().fit(X_tr, y_tr)

    test_df = df.iloc[te]
    metrics = evaluate(model, test_df[features], test_df["is_attack"].to_numpy(), test_df["label"].to_numpy())
    top = sorted(zip(features, model.feature_importances_), key=lambda t: -t[1])[:10]
    metrics["top_feature_importances"] = {k: round(float(v), 4) for k, v in top}
    print("\nTEST METRICS (evaluated once):")
    print(json.dumps(metrics, indent=2, default=_json_default))

    med, iqr = compute_baseline(X_tr[y_tr == 0])
    extra = {
        "model_type": best_name,
        "selection": selection,
        "dataset": {
            "name": "CIC-IDS2017 MachineLearningCSV", "split": tag, "random_state": SEED,
            "include_port": bool(args.include_port), "cleaning": stats,
            "caps": {"benign": args.max_benign, "attack_per_label": args.max_attack_per_label},
        },
        "quick_run": bool(args.quick),
    }
    meta = build_meta(f"network_intrusion-{best_name}", metrics, extra, features, med, iqr)
    METRICS_DIR.mkdir(parents=True, exist_ok=True)
    suffix = "_port" if args.include_port else ""
    (METRICS_DIR / f"network_intrusion_metrics_{tag}{suffix}.json").write_text(
        json.dumps(meta, indent=2, default=_json_default), encoding="utf-8")

    if tag == "random":
        save_artifacts(model, meta, ARTIFACT_DIR)
        print(f"\nSaved model + meta to {ARTIFACT_DIR}")
    else:
        print(f"\n'{tag}' is an evaluation run: metrics saved, production model NOT overwritten.")
    print(f"Done in {time.time()-t0:.0f}s")


if __name__ == "__main__":
    main()