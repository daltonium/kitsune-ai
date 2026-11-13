"""Causal login-behaviour features: each logon is described using only EARLIER events."""
from __future__ import annotations

import numpy as np
import pandas as pd

FEATURE_NAMES = [
    "hour", "day_of_week", "is_weekend", "after_hours", "user_hour_share",
    "user_pc_share", "is_new_pc", "pc_other_user_share",
    "hours_since_prev_logon", "logons_prev_24h",
]
BUSINESS_START, BUSINESS_END = 7, 19
MIN_HISTORY = 30


def build_features(events: pd.DataFrame, min_history: int = MIN_HISTORY) -> pd.DataFrame:
    """Features for Logon events with at least `min_history` earlier logons by the same user.

    `events` must be cleaned (see log_preprocessing.clean_events). The returned index
    refers to rows of `events`.
    """
    logons = events[events["activity"] == "Logon"].sort_values("date", kind="stable")
    if logons.empty:
        return pd.DataFrame(columns=FEATURE_NAMES)
    ts = logons["date"]
    work = pd.DataFrame({"user": logons["user"], "pc": logons["pc"], "hour": ts.dt.hour}, index=logons.index)

    cc_user = work.groupby("user", sort=False).cumcount()
    cc_user_hour = work.groupby(["user", "hour"], sort=False).cumcount()
    cc_user_pc = work.groupby(["user", "pc"], sort=False).cumcount()
    cc_pc = work.groupby("pc", sort=False).cumcount()
    prev = logons.groupby("user", sort=False)["date"].shift(1)
    gap_hours = ((ts - prev).dt.total_seconds() / 3600.0).fillna(0.0)

    secs = (ts - pd.Timestamp("1970-01-01")).dt.total_seconds().to_numpy()
    counts = np.zeros(len(logons), dtype=float)
    for pos in logons.groupby("user", sort=False).indices.values():
        t = secs[pos]
        counts[pos] = np.arange(len(t)) - np.searchsorted(t, t - 86400.0, side="left")

    dow = ts.dt.dayofweek
    feat = pd.DataFrame({
        "hour": work["hour"].astype(float),
        "day_of_week": dow.astype(float),
        "is_weekend": (dow >= 5).astype(float),
        "after_hours": ((work["hour"] < BUSINESS_START) | (work["hour"] >= BUSINESS_END)).astype(float),
        "user_hour_share": (cc_user_hour + 1.0) / (cc_user + 24.0),
        "user_pc_share": (cc_user_pc / cc_user.clip(lower=1)).where(cc_user > 0, 0.0),
        "is_new_pc": (cc_user_pc == 0).astype(float),
        "pc_other_user_share": (1.0 - cc_user_pc / cc_pc.clip(lower=1)).where(cc_pc > 0, 0.0),
        "hours_since_prev_logon": np.log1p(gap_hours),
        "logons_prev_24h": counts,
    }, index=logons.index)
    return feat.loc[cc_user >= min_history, FEATURE_NAMES]


def describe_reasons(row) -> list:
    """Plain-language observations for one feature row (descriptive, not model attribution)."""
    reasons = []
    hour = int(row["hour"])
    if row["after_hours"] and row["user_hour_share"] < 0.02:
        reasons.append(f"Unusual hour: this user rarely logs in around {hour:02d}:00")
    elif row["user_hour_share"] < 0.005:
        reasons.append(f"Unusual hour for this user ({hour:02d}:00)")
    if row["is_new_pc"]:
        reasons.append("First login by this user on this computer")
    elif row["user_pc_share"] < 0.02:
        reasons.append("User rarely uses this computer")
    if row["pc_other_user_share"] > 0.9:
        reasons.append("This computer is mostly used by other people")
    if row["is_weekend"] and row["user_hour_share"] < 0.05:
        reasons.append("Weekend login at an uncommon time for this user")
    if row["logons_prev_24h"] >= 20:
        reasons.append(f"Many logons in the previous 24 hours ({int(row['logons_prev_24h'])})")
    if np.expm1(row["hours_since_prev_logon"]) > 24 * 14:
        reasons.append("Long gap since this user's previous login (over 2 weeks)")
    return reasons or ["Overall pattern differs from this user's normal behaviour"]