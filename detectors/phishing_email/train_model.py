"""Train the phishing-email classifier (TF-IDF + Naive Bayes / Logistic Regression).

    python -m detectors.phishing_email.train_model --quick
    python -m detectors.phishing_email.train_model
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
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, brier_score_loss, confusion_matrix, f1_score,
    precision_recall_fscore_support, roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB

from ..base import ARTIFACTS_ROOT
from .text_preprocessing import build_email_text, clean_text

REPO_ROOT = Path(__file__).resolve().parents[2]
DATASET_DIR = REPO_ROOT / "datasets" / "zenodo_email"
ARTIFACT_DIR = ARTIFACTS_ROOT / "phishing_email"
METRICS_DIR = ARTIFACTS_ROOT / "metrics"
SEED = 42
THRESHOLDS = [0.30, 0.60, 0.85]
DECISION_THRESHOLD = 0.5
TEXT_COLUMNS = ("body", "text", "email", "message", "content")
LABEL_COLUMNS = ("label", "class", "target", "type")
TOKEN_PATTERN = r"(?u)\b[a-z][a-z0-9']+\b"
SCORE_MEANING = (
    "Raw classifier probability for the phishing class. "
    "Not calibrated: it is not a real-world probability that an email is phishing."
)

PROBES = [
    (0, "Team meeting moved to 3pm", "Hi all, the weekly sync is moved to 3pm tomorrow in the usual conference room. Please send me any agenda items before then. Thanks, Priya"),
    (0, "[repo] Pull request #42 merged", "Your pull request was merged into main. You can view the changes on GitHub: https://github.com/example/repo/pull/42"),
    (0, "Your order has shipped", "Hello, your order #123456 has shipped and should arrive by Friday. Track your package here: https://example-store.com/track/123456"),
    (0, "Assignment 3 deadline extended", "Dear students, the deadline for assignment 3 has been extended to next Monday. Please submit through the course portal. Regards, Prof. Rao"),
    (1, "Urgent: verify your account", "Dear customer, we noticed unusual activity on your account. Your account will be suspended within 24 hours unless you verify your identity now: http://secure-login-verify.example.top/login Thank you, Security Team"),
    (1, "Your password expires today", "Your email password expires today. Click here to keep the same password: http://mail-update.example.xyz/keep"),
    (1, "Business proposal", "I am Barrister John, the late client left 12.5 million dollars. Reply with your full name and bank details so I can transfer your share."),
    (1, "Payment failed - update billing", "We could not process your last payment. Update your billing information within 48 hours to avoid service interruption: http://billing-help.example.top/update"),
]


def make_vectorizer(min_df=5, max_df=0.5):
    return TfidfVectorizer(
        ngram_range=(1, 2), min_df=min_df, max_df=max_df, sublinear_tf=True,
        max_features=200000, dtype=np.float32, token_pattern=TOKEN_PATTERN,
    )


def build_classifier(kind, params):
    if kind == "naive_bayes":
        return MultinomialNB(alpha=params["alpha"])
    return LogisticRegression(C=params["C"], solver="liblinear", class_weight="balanced", max_iter=200)


def term_weights(clf):
    if hasattr(clf, "coef_"):
        return clf.coef_[0]
    return clf.feature_log_prob_[1] - clf.feature_log_prob_[0]


def find_csv(path):
    if path:
        return Path(path)
    found = sorted(DATASET_DIR.glob("*.csv"))
    if not found:
        raise SystemExit(f"No CSV in {DATASET_DIR}. Download Balanced_Dataset.csv there.")
    balanced = [f for f in found if "balanced" in f.name.lower()]
    return (balanced or found)[0]


def load_clean(csv_path, max_rows, phish_label):
    header = pd.read_csv(csv_path, nrows=0, encoding_errors="replace")
    cols = {str(c).strip().lower(): c for c in header.columns}
    text_col = next((cols[c] for c in TEXT_COLUMNS if c in cols), None)
    label_col = next((cols[c] for c in LABEL_COLUMNS if c in cols), None)
    if text_col is None or label_col is None:
        raise SystemExit(f"Could not find text/label columns. Columns present: {list(header.columns)}")
    subj_col = cols.get("subject")
    use = [text_col, label_col] + ([subj_col] if subj_col else [])
    print(f"Reading {csv_path.name} (text='{text_col}', label='{label_col}', subject={'yes' if subj_col else 'no'})")
    df = pd.read_csv(csv_path, usecols=use, dtype=str, encoding_errors="replace")
    stats = {"raw_rows": int(len(df)), "columns_used": use}

    df = df.dropna(subset=[text_col, label_col])
    lab = pd.to_numeric(df[label_col], errors="coerce")
    lab = lab[lab.isin([0, 1])]
    df = df.loc[lab.index].copy()
    df["y"] = (lab == phish_label).astype("int8")
    if max_rows and max_rows < len(df):
        df = df.sample(max_rows, random_state=SEED)
    stats["rows_with_valid_label"] = int(len(df))

    t0 = time.time()
    body = df[text_col].fillna("")
    raw = (df[subj_col].fillna("") + "\n" + body) if subj_col else body
    df["clean"] = [clean_text(t) for t in raw]
    print(f"Cleaned {len(df)} emails in {time.time()-t0:.0f}s")

    df = df[df["clean"].str.len() >= 20]
    stats["after_dropping_empty_or_tiny"] = int(len(df))
    df["key"] = df["clean"].str[:500]
    n_labels = df.groupby("key")["y"].nunique()
    conflicting = n_labels[n_labels > 1].index
    df = df[~df["key"].isin(conflicting)]
    stats["conflicting_duplicates_removed"] = int(len(conflicting))
    before = len(df)
    df = df.drop_duplicates(subset="key")
    stats["near_duplicates_removed"] = int(before - len(df))
    stats["final_rows"] = int(len(df))

    print("\nClass counts (1 = phishing):", df["y"].value_counts().to_dict())
    print("Median cleaned length (chars):", df.groupby("y")["clean"].apply(lambda s: int(s.str.len().median())).to_dict())
    for cls in (0, 1):
        print(f"\nSample cleaned texts, label={cls}:")
        for t in df[df["y"] == cls]["clean"].sample(3, random_state=SEED):
            print("   ", t[:140])
    return df[["clean", "y"]].reset_index(drop=True), stats


def evaluate(clf, X, y):
    proba = clf.predict_proba(X)[:, list(clf.classes_).index(1)]
    pred = (proba >= DECISION_THRESHOLD).astype(int)
    cm = confusion_matrix(y, pred, labels=[0, 1])
    tn, fp, fn, tp = (int(v) for v in cm.ravel())
    p, r, f, _ = precision_recall_fscore_support(y, pred, average="binary", pos_label=1, zero_division=0)
    return {
        "n_test": int(len(y)),
        "accuracy": float(accuracy_score(y, pred)),
        "precision_phishing": float(p),
        "recall_phishing": float(r),
        "f1_phishing": float(f),
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else None,
        "roc_auc": float(roc_auc_score(y, proba)),
        "brier_score": float(brier_score_loss(y, proba)),
        "confusion_matrix": {"labels": ["legitimate", "phishing"], "matrix": cm.tolist()},
    }


def build_meta(model_name, metrics, extra):
    now = datetime.now(timezone.utc)
    return {
        "module": "phishing_email",
        "model_version": f"{model_name}-{now:%Y%m%d}",
        "trained_at": now.isoformat(),
        "positive_class": "phishing",
        "decision_threshold": DECISION_THRESHOLD,
        "risk_thresholds": THRESHOLDS,
        "score_meaning": SCORE_MEANING,
        "sklearn_version": sklearn.__version__,
        "python_version": platform.python_version(),
        "metrics": metrics,
        **extra,
    }


def save_artifacts(vectorizer, clf, meta, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(vectorizer, out_dir / "vectorizer.joblib", compress=3)
    joblib.dump(clf, out_dir / "model.joblib", compress=3)
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")


def train_quick(texts, labels, out_dir):
    """Small, fast training used by the tests. labels: 1 = phishing."""
    cleaned = [clean_text(t) for t in texts]
    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=1, token_pattern=TOKEN_PATTERN, dtype=np.float32)
    clf = LogisticRegression(C=10.0, solver="liblinear", max_iter=200).fit(vec.fit_transform(cleaned), labels)
    save_artifacts(vec, clf, build_meta("phishing_email-demo", {}, {"dataset": "synthetic"}), out_dir)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv")
    ap.add_argument("--phish-label", type=int, default=1)
    ap.add_argument("--quick", action="store_true", help="30k-row random sample")
    args = ap.parse_args()

    t0 = time.time()
    df, stats = load_clean(find_csv(args.csv), 30000 if args.quick else 0, args.phish_label)
    texts, y = df["clean"].to_numpy(), df["y"].to_numpy()
    idx = np.arange(len(df))
    tr, te = train_test_split(idx, test_size=0.2, stratify=y, random_state=SEED)
    fit_i, val_i = train_test_split(tr, test_size=0.15, stratify=y[tr], random_state=SEED)
    print(f"\nTrain={len(tr)} (fit={len(fit_i)}, validation={len(val_i)})  Test={len(te)}  ({time.time()-t0:.0f}s)")

    vec_sel = make_vectorizer()
    Xf, Xv = vec_sel.fit_transform(texts[fit_i]), None
    Xv = vec_sel.transform(texts[val_i])
    candidates = {f"naive_bayes_alpha{a}": ("naive_bayes", {"alpha": a}) for a in (0.1, 0.5, 1.0)}
    candidates.update({f"logreg_C{c}": ("logreg", {"C": c}) for c in (1.0, 10.0)})
    selection = {}
    for name, (kind, params) in candidates.items():
        clf = build_classifier(kind, params).fit(Xf, y[fit_i])
        selection[name] = {"val_f1": float(f1_score(y[val_i], clf.predict(Xv))), "params": params, "kind": kind}
        print(f"validation {name}: F1={selection[name]['val_f1']:.4f}")
    best = max(selection, key=lambda k: selection[k]["val_f1"])
    kind, params = selection[best]["kind"], selection[best]["params"]
    print(f"\nSelected: {best}")

    vec = make_vectorizer()
    Xtr = vec.fit_transform(texts[tr])
    clf = build_classifier(kind, params).fit(Xtr, y[tr])
    metrics = evaluate(clf, vec.transform(texts[te]), y[te])
    print("\nTEST METRICS (evaluated once):")
    print(json.dumps(metrics, indent=2))

    w, names = term_weights(clf), vec.get_feature_names_out()
    order = np.argsort(w)
    top_phish = [names[i] for i in order[::-1][:25]]
    top_legit = [names[i] for i in order[:25]]
    print("\nTop terms pushing toward PHISHING:", top_phish)
    print("Top terms pushing toward LEGITIMATE:", top_legit)

    print("\nPROBE EMAILS (my own examples; expected label in brackets):")
    for exp, subj, body in PROBES:
        p = clf.predict_proba(vec.transform([clean_text(build_email_text(subj, body))]))[0][list(clf.classes_).index(1)]
        print(f"  {p:5.2f} [{'phishing' if exp else 'legit   '}]  {subj}")

    extra = {
        "model_type": best, "params": params, "selection": selection, "vocabulary_size": int(len(names)),
        "global_top_terms": {"phishing": top_phish, "legitimate": top_legit},
        "dataset": {
            "name": "Phishing-Email-Detection-Dataset (Zenodo 17314806), body text only",
            "license": "CC BY 4.0", "split": "stratified 80/20", "random_state": SEED, "cleaning": stats,
            "caveats": ["emails from 1998-2008", "spam, scam and phishing share one label",
                        "body-only training text", "no source column, so no source hold-out"],
        },
        "quick_run": bool(args.quick),
    }
    meta = build_meta(f"phishing_email-{best}", metrics, extra)
    METRICS_DIR.mkdir(parents=True, exist_ok=True)
    (METRICS_DIR / "phishing_email_metrics.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    save_artifacts(vec, clf, meta, ARTIFACT_DIR)
    print(f"\nSaved vectorizer + model + meta to {ARTIFACT_DIR}\nDone in {time.time()-t0:.0f}s")


if __name__ == "__main__":
    main()