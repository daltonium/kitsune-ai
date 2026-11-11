"""Train the phishing-URL Random Forest on PhiUSIIL (URL column) + malicious_phish.csv.

Run from the repo root:
    python -m detectors.phishing_url.train_model --quick
    python -m detectors.phishing_url.train_model                         # saves the model
    python -m detectors.phishing_url.train_model --split grouped         # metrics only
    python -m detectors.phishing_url.train_model --holdout-source phiusiil
    python -m detectors.phishing_url.train_model --holdout-source malicious_phish
"""
from __future__ import annotations

import argparse
import json
import platform
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, brier_score_loss, confusion_matrix,
    precision_recall_fscore_support, roc_auc_score,
)
from sklearn.model_selection import (
    GridSearchCV, GroupKFold, GroupShuffleSplit, StratifiedKFold, train_test_split,
)

from ..base import ARTIFACTS_ROOT
from .feature_extractor import FEATURE_NAMES, HOST_FEATURE_NAMES, base_domain, canonicalize, extract_features

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASET_DIR = REPO_ROOT / "datasets" / "phiusiil"
DATASET2_DIR = REPO_ROOT / "datasets" / "malicious_urls"
ARTIFACT_DIR = ARTIFACTS_ROOT / "phishing_url"
METRICS_DIR = ARTIFACTS_ROOT / "metrics"
SEED = 42
THRESHOLDS = [0.30, 0.60, 0.85]
DECISION_THRESHOLD = 0.5
SCORE_MEANING = (
    "Raw Random Forest probability for the phishing class. "
    "Not calibrated: it is not a real-world probability of phishing."
)


def featurize(urls):
    rows, kept = [], []
    for i, url in enumerate(urls):
        try:
            feats = extract_features(url)
        except ValueError:
            continue
        rows.append([feats[n] for n in FEATURE_NAMES])
        kept.append(i)
    return pd.DataFrame(rows, columns=FEATURE_NAMES, dtype="float64"), np.array(kept)


def find_csv(path, folder=DATASET_DIR):
    if path:
        return Path(path)
    found = sorted(Path(folder).glob("*.csv"))
    if not found:
        raise SystemExit(f"No CSV found in {folder}. Download the dataset there first.")
    return found[0]


def _show_samples(df, col, values):
    for v in values:
        sub = df[df[col] == v]["url"]
        print(f"  {col}={v} ({len(sub)} rows):")
        for u in sub.sample(min(5, len(sub)), random_state=SEED):
            print("     ", u[:110])


def load_clean(csv_path, legit_label, sample):
    """PhiUSIIL: URL + label columns only. y = 1 means phishing."""
    df = pd.read_csv(
        csv_path, encoding="utf-8-sig",
        usecols=lambda c: c.strip().lower() in ("url", "label"),
    )
    df.columns = [c.strip().lower() for c in df.columns]
    stats = {"raw_rows": len(df)}

    df = df.dropna(subset=["url", "label"])
    df["url"] = df["url"].astype(str).str.strip()
    df["label"] = df["label"].astype(int)
    if not set(df["label"].unique()) <= {0, 1}:
        raise SystemExit(f"Unexpected label values: {sorted(df['label'].unique())}")
    df = df[df["url"].str.match(r"^https?://", case=False)]
    stats["after_dropna_and_scheme_filter"] = len(df)

    print("\nPhiUSIIL label check (confirm which label looks legitimate):")
    _show_samples(df, "label", (0, 1))

    n_labels = df.groupby("url")["label"].nunique()
    conflicting = n_labels[n_labels > 1].index
    df = df[~df["url"].isin(conflicting)]
    stats["conflicting_urls_removed"] = int(len(conflicting))
    before = len(df)
    df = df.drop_duplicates(subset="url")
    stats["duplicates_removed"] = before - len(df)

    df["y"] = np.where(df["label"] == legit_label, 0, 1)
    if sample and sample < len(df):
        df = df.sample(sample, random_state=SEED)
    df["source"] = "phiusiil"
    stats["final_rows"] = len(df)
    return df[["url", "y", "source"]].reset_index(drop=True), stats


def load_malicious(csv_path):
    """Kaggle malicious_phish.csv: keep only benign (0) and phishing (1) rows."""
    df = pd.read_csv(
        csv_path, encoding="utf-8-sig",
        usecols=lambda c: c.strip().lower() in ("url", "type"),
    )
    df.columns = [c.strip().lower() for c in df.columns]
    stats = {"raw_rows": len(df)}
    df = df.dropna(subset=["url", "type"])
    df["type"] = df["type"].astype(str).str.strip().str.lower()
    stats["class_counts"] = {k: int(v) for k, v in df["type"].value_counts().items()}
    print("\nmalicious_phish class counts:", stats["class_counts"])

    df = df[df["type"].isin(["benign", "phishing"])].copy()
    df["url"] = df["url"].astype(str).str.strip()
    df = df[df["url"].str.len().between(1, 2048)]
    print("malicious_phish samples:")
    _show_samples(df, "type", ("benign", "phishing"))

    df["y"] = (df["type"] == "phishing").astype(int)
    n_labels = df.groupby("url")["y"].nunique()
    conflicting = n_labels[n_labels > 1].index
    df = df[~df["url"].isin(conflicting)]
    stats["conflicting_urls_removed"] = int(len(conflicting))
    before = len(df)
    df = df.drop_duplicates(subset="url")
    stats["duplicates_removed"] = before - len(df)
    df["source"] = "malicious_phish"
    stats["final_rows"] = len(df)
    return df[["url", "y", "source"]].reset_index(drop=True), stats


def combine(frames, cap):
    """Dedupe on the canonical URL across sources, then cap rows per source."""
    df = pd.concat(frames, ignore_index=True)
    df["canon"] = df["url"].map(canonicalize)
    df["key"] = df["canon"].str.rstrip("/").str.lower()
    stats = {"rows_before": len(df)}
    n_labels = df.groupby("key")["y"].nunique()
    conflicting = n_labels[n_labels > 1].index
    df = df[~df["key"].isin(conflicting)]
    stats["cross_source_conflicts_removed"] = int(len(conflicting))
    before = len(df)
    df = df.drop_duplicates(subset="key")
    stats["cross_source_duplicates_removed"] = before - len(df)
    if cap:
        df = pd.concat(
            [g.sample(min(len(g), cap), random_state=SEED) for _, g in df.groupby("source")],
            ignore_index=True,
        )
    stats["final_rows"] = len(df)
    return df.reset_index(drop=True), stats


def make_forest(n_estimators, **params):
    return RandomForestClassifier(
        n_estimators=n_estimators, class_weight="balanced_subsample",
        n_jobs=-1, random_state=SEED, **params,
    )


def evaluate(model, X_test, y_test):
    proba = model.predict_proba(X_test)[:, list(model.classes_).index(1)]
    pred = (proba >= DECISION_THRESHOLD).astype(int)
    p, r, f, _ = precision_recall_fscore_support(y_test, pred, average="binary", pos_label=1, zero_division=0)
    cm = confusion_matrix(y_test, pred, labels=[0, 1])
    return {
        "accuracy": float(accuracy_score(y_test, pred)),
        "precision_phishing": float(p),
        "recall_phishing": float(r),
        "f1_phishing": float(f),
        "roc_auc": float(roc_auc_score(y_test, proba)),
        "brier_score": float(brier_score_loss(y_test, proba)),
        "confusion_matrix": {"labels": ["legitimate", "phishing"], "matrix": cm.tolist()},
        "n_test": int(len(y_test)),
    }, pred


def per_source_breakdown(pred, y, src):
    out = {}
    for s in np.unique(src):
        m = src == s
        yt, yp = y[m], pred[m]
        legit, phish = yt == 0, yt == 1
        out[str(s)] = {
            "n": int(m.sum()),
            "accuracy": float((yt == yp).mean()),
            "false_positive_rate_on_legit": float((yp[legit] == 1).mean()) if legit.any() else None,
            "recall_on_phishing": float((yp[phish] == 1).mean()) if phish.any() else None,
        }
    return out


def build_meta(model_name, metrics, extra, feature_names=None):
    return {
        "module": "phishing_url",
        "model_version": f"{model_name}-{datetime.now(timezone.utc):%Y%m%d}",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "feature_names": list(feature_names or FEATURE_NAMES),
        "positive_class": "phishing",
        "decision_threshold": DECISION_THRESHOLD,
        "risk_thresholds": THRESHOLDS,
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
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")


def train_quick(urls, labels, out_dir, n_estimators=25):
    """Small, fast training used by the tests. labels: 1 = phishing."""
    X, kept = featurize(urls)
    y = np.asarray(labels)[kept]
    model = make_forest(n_estimators, min_samples_leaf=1).fit(X, y)
    save_artifacts(model, build_meta("phishing_url-demo", {}, {"dataset": "synthetic"}), out_dir)
    return model


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", help="PhiUSIIL CSV (default: first CSV in datasets/phiusiil)")
    ap.add_argument("--extra-csv", help="malicious_phish.csv (default: first CSV in datasets/malicious_urls)")
    ap.add_argument("--phiusiil-only", action="store_true")
    ap.add_argument("--split", choices=["stratified", "grouped"], default="stratified")
    ap.add_argument("--holdout-source", choices=["phiusiil", "malicious_phish"])
    ap.add_argument("--legit-label", type=int, default=1)
    ap.add_argument("--n-estimators", type=int, default=120)
    ap.add_argument("--max-per-source", type=int, default=150000)
    ap.add_argument("--no-tune", action="store_true")
    ap.add_argument("--quick", action="store_true", help="15k rows per source, no tuning")
    ap.add_argument("--features", choices=["all", "host"], default="all")
    args = ap.parse_args()
    if args.quick:
        args.max_per_source, args.no_tune = 15000, True

    t0 = time.time()
    df1, st1 = load_clean(find_csv(args.csv), args.legit_label, 0)
    frames, source_stats = [df1], {"phiusiil": st1}
    if not args.phiusiil_only:
        df2, st2 = load_malicious(find_csv(args.extra_csv, DATASET2_DIR))
        frames.append(df2)
        source_stats["malicious_phish"] = st2
    else:
        print("\nWARNING: PhiUSIIL alone has no realistic legitimate URLs. Do not ship this model.")

    df, comb_stats = combine(frames, args.max_per_source)
    print("\nCombined cleaning stats:", json.dumps(comb_stats))
    print(pd.crosstab(df["source"], df["y"].map({0: "legit", 1: "phishing"})))

    X, kept = featurize(df["url"])
    feature_names = HOST_FEATURE_NAMES if args.features == "host" else FEATURE_NAMES
    X = X[feature_names]
    comb_stats["unparseable_urls_dropped"] = int(len(df) - len(kept))
    df = df.iloc[kept].reset_index(drop=True)
    y, src = df["y"].to_numpy(), df["source"].to_numpy()
    print(f"Features ready: {X.shape}  phishing share: {y.mean():.3f}  ({time.time()-t0:.0f}s)")

    idx = np.arange(len(df))
    groups = None
    if args.holdout_source:
        mask = src == args.holdout_source
        if not mask.any() or mask.all():
            raise SystemExit("Hold-out source must be present, and another source must remain for training.")
        tr, te, tag = idx[~mask], idx[mask], f"holdout_{args.holdout_source}"
    elif args.split == "grouped":
        groups = df["canon"].map(lambda u: base_domain((urlsplit(u).hostname or "").lower())).to_numpy()
        tr, te = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED).split(X, y, groups))
        tag = "grouped"
    else:
        strat = pd.Series(src).astype(str) + "_" + pd.Series(y).astype(str)
        tr, te = train_test_split(idx, test_size=0.2, stratify=strat, random_state=SEED)
        tag = "stratified"
    X_tr, X_te, y_tr, y_te = X.iloc[tr], X.iloc[te], y[tr], y[te]
    g_tr = groups[tr] if groups is not None else None
    print(f"Split={tag}  train={len(tr)}  test={len(te)}")

    best_params, cv_f1 = {"min_samples_leaf": 2}, None
    if args.no_tune:
        model = make_forest(args.n_estimators, **best_params).fit(X_tr, y_tr)
    else:
        cv = GroupKFold(n_splits=3) if g_tr is not None else StratifiedKFold(3, shuffle=True, random_state=SEED)
        gs = GridSearchCV(
            make_forest(args.n_estimators), {"min_samples_leaf": [2, 5]},
            scoring="f1", cv=cv, refit=True, n_jobs=1, verbose=1,
        )
        gs.fit(X_tr, y_tr, groups=g_tr)
        model, best_params, cv_f1 = gs.best_estimator_, gs.best_params_, float(gs.best_score_)
        print("Best params:", best_params, " CV F1:", round(cv_f1, 5))

    metrics, pred = evaluate(model, X_te, y_te)
    metrics["per_source"] = per_source_breakdown(pred, y_te, src[te])
    top = sorted(zip(feature_names, model.feature_importances_), key=lambda t: -t[1])[:10]
    metrics["top_feature_importances"] = {k: round(float(v), 4) for k, v in top}
    print("\nTEST METRICS (evaluated once):")
    print(json.dumps(metrics, indent=2))

    extra = {
        "dataset": {
            "sources": list(source_stats), "split": tag, "random_state": SEED,
            "max_per_source": args.max_per_source,
            "licenses": {"phiusiil": "CC BY 4.0", "malicious_phish": "check the Kaggle page"},
            "cleaning": {"per_source": source_stats, "combined": comb_stats},
        },
        "best_params": best_params, "cv_f1": cv_f1, "n_estimators": args.n_estimators,
        "quick_run": bool(args.quick),
        "feature_set": args.features,
    }
    meta = build_meta("phishing_url-rf", metrics, extra, feature_names)
    METRICS_DIR.mkdir(parents=True, exist_ok=True)
    (METRICS_DIR / f"phishing_url_metrics_{tag}_{args.features}.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    if tag == "stratified":
        save_artifacts(model, meta, ARTIFACT_DIR)
        print(f"\nSaved model + meta to {ARTIFACT_DIR}")
    else:
        print(f"\n'{tag}' is an evaluation run: metrics saved, production model NOT overwritten.")
    print(f"Done in {time.time()-t0:.0f}s")


if __name__ == "__main__":
    main()