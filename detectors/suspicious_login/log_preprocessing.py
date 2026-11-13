"""Cleaning of login events (CERT logon.csv style). Pure pandas; no Django."""
from __future__ import annotations

import io

import numpy as np
import pandas as pd

from ..exceptions import InvalidInputError

CERT_DATE_FORMAT = "%m/%d/%Y %H:%M:%S"
KEY_ALIASES = {
    "id": "id",
    "timestamp": "date", "date": "date", "time": "date",
    "user": "user", "user_id": "user", "username": "user",
    "pc": "pc", "device_id": "pc", "computer": "pc",
    "activity": "activity", "event": "activity",
    "success": "success",
}
_ACTIVITY = {"logon": "Logon", "login": "Logon", "logoff": "Logoff", "logout": "Logoff"}
_FAILED = {"false", "0", "no", "f", "n", "failed", "failure"}
MAX_CELL_CHARS = 200
ACCEPTED_TEXT = "timestamp, user_id, device_id (or pc), activity, success, id"


def canonical_key(name):
    return KEY_ALIASES.get(str(name).strip().lower())


def _with_row_numbers(df):
    df = df.reset_index(drop=True)
    df["_row"] = np.arange(1, len(df) + 1)
    return df


def frame_from_dataframe(df):
    mapped = {}
    for col in df.columns:
        target = canonical_key(col)
        if target and target not in mapped:
            mapped[target] = df[col]
    return _with_row_numbers(pd.DataFrame(mapped))


def frame_from_events(events):
    if not isinstance(events, list) or not events:
        raise InvalidInputError("events must be a non-empty list of objects.")
    rows, unknown = [], set()
    for ev in events:
        if not isinstance(ev, dict):
            raise InvalidInputError("Each event must be a JSON object.")
        row = {}
        for key, value in ev.items():
            target = canonical_key(key)
            if target is None:
                unknown.add(str(key)[:40])
                continue
            if isinstance(value, (dict, list)):
                raise InvalidInputError(f"Field '{key}' must be a simple value.")
            row[target] = value
        rows.append(row)
    if unknown:
        raise InvalidInputError(
            f"Unknown event field(s): {', '.join(sorted(unknown)[:5])}. Accepted: {ACCEPTED_TEXT}."
        )
    return _with_row_numbers(pd.DataFrame(rows))


def frame_from_csv(raw: bytes, max_rows: int):
    try:
        df = pd.read_csv(io.BytesIO(raw), nrows=max_rows + 1, dtype=str,
                         encoding="latin-1", keep_default_na=False)
    except (pd.errors.ParserError, pd.errors.EmptyDataError, ValueError) as exc:
        raise InvalidInputError("The file could not be parsed as a CSV of login events.") from exc
    return frame_from_dataframe(df)


def parse_timestamps(values):
    """CERT format first, then ISO 8601. Time zones are dropped, keeping the wall-clock time."""
    values = values.astype(str).str.strip()
    ts = pd.to_datetime(values, format=CERT_DATE_FORMAT, errors="coerce")
    bad = ts.isna()
    if bad.any():
        try:
            alt = pd.to_datetime(values[bad], format="ISO8601", errors="coerce")
        except (ValueError, TypeError):
            alt = pd.Series(pd.NaT, index=values[bad].index)
        if not pd.api.types.is_datetime64_any_dtype(alt):
            alt = pd.to_datetime(alt, utc=True, errors="coerce")
        if getattr(alt.dt, "tz", None) is not None:
            alt = alt.dt.tz_localize(None)
        ts = ts.copy()
        ts.loc[bad] = alt
    return ts


def clean_events(df):
    """Return (clean frame sorted by time, stats). Raises if required fields are missing."""
    missing = [c for c in ("date", "user", "pc") if c not in df.columns]
    if missing:
        raise InvalidInputError(
            f"Missing required field(s): {', '.join(missing)}. Accepted names: {ACCEPTED_TEXT}."
        )
    out = df.copy()
    stats = {"events_received": int(len(out))}
    out["date"] = parse_timestamps(out["date"])
    for col in ("user", "pc"):
        out[col] = out[col].astype(str).str.strip().str[:MAX_CELL_CHARS].replace({"nan": "", "None": ""})
    bad = out["date"].isna() | (out["user"] == "") | (out["pc"] == "")
    stats["invalid_rows_dropped"] = int(bad.sum())
    out = out[~bad]

    if "activity" in out.columns:
        act = (out["activity"].fillna("Logon").astype(str).str.strip().str.lower()
               .replace({"": "logon", "nan": "logon"}))
        mapped = act.map(_ACTIVITY)
    else:
        mapped = pd.Series("Logon", index=out.index)
    unknown = mapped.isna()
    stats["unknown_activity_dropped"] = int(unknown.sum())
    out = out.assign(activity=mapped)[~unknown]

    failed = pd.Series(False, index=out.index)
    if "success" in out.columns:
        failed = out["success"].astype(str).str.strip().str.lower().isin(_FAILED)
    stats["failed_events_ignored"] = int(failed.sum())
    out = out[~failed]
    if "id" not in out.columns:
        out = out.assign(id="")
    if "_row" not in out.columns:
        out = out.assign(_row=np.arange(1, len(out) + 1))
    return out.sort_values("date", kind="stable").reset_index(drop=True), stats