"""Diagnose the phishing-URL model: dataset shortcuts + probe URLs.
Run: python -m detectors.phishing_url.diagnose
"""
import argparse
import json
from urllib.parse import urlsplit

from ..exceptions import DetectorError
from .predictor import PhishingURLDetector
from .train_model import ARTIFACT_DIR, find_csv, load_clean

PROBES = [
    "https://www.wikipedia.org",
    "https://en.wikipedia.org/wiki/Cat",
    "https://www.google.com/search?q=cat",
    "https://github.com/torvalds/linux",
    "https://docs.python.org/3/library/os.html",
    "https://stackoverflow.com/questions/11227809",
    "http://example.com/index.html",
    "http://185.23.41.7/secure-login/verify-account.php?id=1",
    "http://bit.ly-login.verify-account.example.top/a/b",
    "http://secure-update-account-verify.000webhostapp.com/login.php",
    "https://paypa1-secure-login.xyz",
]


def share(series):
    return f"{100 * series.mean():5.1f}%"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--legit-label", type=int, default=1)
    ap.add_argument("--sample", type=int, default=60000)
    args = ap.parse_args()

    meta_path = ARTIFACT_DIR / "meta.json"
    if meta_path.exists():
        meta = json.loads(meta_path.read_text())
        print("MODEL META: quick_run =", meta.get("quick_run"), "| split =", meta.get("dataset", {}).get("split"),
              "| version =", meta.get("model_version"))
        m = meta.get("metrics", {})
        print("  accuracy", m.get("accuracy"), "recall", m.get("recall_phishing"), "brier", m.get("brier_score"))
        print("  top importances:", m.get("top_feature_importances"))
    else:
        print("No meta.json found - no model has been saved.")

    df, _ = load_clean(find_csv(None), args.legit_label, args.sample)
    parts = df["url"].map(urlsplit)
    df["has_path"] = parts.map(lambda p: p.path not in ("", "/"))
    df["has_query"] = parts.map(lambda p: bool(p.query))
    df["is_https"] = parts.map(lambda p: p.scheme.lower() == "https")
    df["https_www"] = df["url"].str.lower().str.startswith("https://www.")
    df["len"] = df["url"].str.len()

    print("\nDATASET SHORTCUT CHECK (y=1 is phishing)")
    print(f"{'':14}{'legit':>10}{'phishing':>10}")
    for col in ("has_path", "has_query", "is_https", "https_www"):
        a = share(df[df.y == 0][col]); b = share(df[df.y == 1][col])
        print(f"{col:14}{a:>10}{b:>10}")
    print(f"{'median length':14}{df[df.y == 0]['len'].median():>10.0f}{df[df.y == 1]['len'].median():>10.0f}")

    print("\nPROBE URLS (score = raw phishing probability)")
    det = PhishingURLDetector()
    for url in PROBES:
        try:
            r = det.analyze({"url": url})
            print(f"{r.score:5.2f}  {r.prediction:<10} {url}")
        except DetectorError as exc:
            print("ERROR:", exc)
            break


if __name__ == "__main__":
    main()