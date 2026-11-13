"""Peek at the CERT r4.2 files to confirm their layout before building features."""
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[2] / "datasets" / "cert_r4_2"

print("Files:")
for p in sorted(ROOT.rglob("*")):
    if p.is_file():
        print(f"  {p.relative_to(ROOT)}  {p.stat().st_size / 1024 ** 2:,.2f} MB")

logon_path = next(iter(ROOT.rglob("logon.csv")), None)
if logon_path is None:
    raise SystemExit("logon.csv not found")
df = pd.read_csv(logon_path)
print("\nlogon.csv columns:", list(df.columns), "| rows:", len(df))
print(df.head(5).to_string())

ts = pd.to_datetime(df["date"], format="%m/%d/%Y %H:%M:%S", errors="coerce")
print("\nunparseable dates:", int(ts.isna().sum()), "| range:", ts.min(), "->", ts.max())
print("users:", df["user"].nunique(), "| pcs:", df["pc"].nunique())
print("activity counts:", df["activity"].value_counts().to_dict())
print("median events per user:", int(df.groupby("user").size().median()))
print("share of events outside 07:00-19:00:", round(float(((ts.dt.hour < 7) | (ts.dt.hour >= 19)).mean()), 4))
print("weekend share:", round(float((ts.dt.dayofweek >= 5).mean()), 4))

for name in ("insiders.csv",):
    p = next(iter(ROOT.rglob(name)), None)
    if p is not None:
        ins = pd.read_csv(p)
        print(f"\n{name}: columns={list(ins.columns)} rows={len(ins)}")
        print(ins.head(8).to_string())

details = sorted(ROOT.glob("answers/r4.2-*/*.csv"))
print(f"\nanswer detail files for r4.2: {len(details)}")
ids = set()
for p in details:
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split(",")
        if parts and parts[0] == "logon" and len(parts) > 1:
            ids.add(parts[1])
for p in details[:2]:
    print(f"\n--- first lines of {p.name}")
    print("\n".join(p.read_text(encoding="utf-8", errors="replace").splitlines()[:6]))
print(f"\nlogon event ids listed in answer files: {len(ids)} | found in logon.csv: {int(df['id'].isin(ids).sum())}")