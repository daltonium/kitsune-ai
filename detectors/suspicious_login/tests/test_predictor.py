import json

import pytest

from detectors.exceptions import InvalidInputError, ModelNotLoadedError
from detectors.network_intrusion.tests.synthetic import FakeUpload
from detectors.suspicious_login.predictor import SuspiciousLoginDetector
from detectors.suspicious_login.tests.synthetic import normal_events, odd_event


def det(art):
    return SuspiciousLoginDetector(artifacts_dir=art)


def test_flags_after_hours_login_on_new_computer(login_artifacts, monkeypatch):
    import numpy as np

    from detectors.suspicious_login.feature_extractor import build_features
    from detectors.suspicious_login.log_preprocessing import (
        clean_events,
        frame_from_events,
    )

    events = normal_events(5, 60, seed=2) + [odd_event()]
    target_row = len(events)

    detector = det(login_artifacts)
    detector.ensure_loaded()

    cleaned, _ = clean_events(frame_from_events(events))
    features = build_features(
        cleaned,
        min_history=detector._min_history,
    )

    source_rows = cleaned.loc[features.index, "_row"].to_numpy()
    target_positions = np.flatnonzero(source_rows == target_row)
    assert len(target_positions) == 1

    target_position = int(target_positions[0])
    low_anomaly = float(detector._quantiles[0] - 1.0)
    high_anomaly = float(detector._quantiles[-1] + 1.0)

    def controlled_score_samples(X):
        assert len(X) == len(features)
        anomaly_scores = np.full(len(X), low_anomaly, dtype=float)
        anomaly_scores[target_position] = high_anomaly
        return -anomaly_scores

    monkeypatch.setattr(
        detector._model,
        "score_samples",
        controlled_score_samples,
    )

    result = detector.analyze({"events": events})

    assert result.prediction == "Suspicious"
    assert result.risk_level == "critical"
    assert result.explanation["flagged_count"] == 1

    top = result.explanation["top_events"][0]
    assert top["row"] == target_row
    assert "First login by this user on this computer" in top["reasons"]


def test_insufficient_history_rejected(login_artifacts):
    with pytest.raises(InvalidInputError, match="earlier"):
        det(login_artifacts).analyze({"events": normal_events(1, 10)})


def test_unknown_event_field_rejected(login_artifacts):
    ev = normal_events(1, 40)
    ev[0]["failed_attempts_recent"] = 4
    with pytest.raises(InvalidInputError, match="Unknown"):
        det(login_artifacts).analyze({"events": ev})


def test_csv_upload_is_scored(login_artifacts):
    lines = ["id,date,user,pc,activity"]
    for i, ev in enumerate(normal_events(5, 60, seed=3) + [odd_event()]):
        stamp = ev["timestamp"].replace("T", " ")
        y, m, rest = stamp[:4], stamp[5:7], stamp[8:]
        lines.append(f"{{ID{i}}},{m}/{rest[:2]}/{y} {rest[3:]},{ev['user_id']},{ev['device_id']},Logon")
    res = det(login_artifacts).analyze({"file": FakeUpload("\n".join(lines).encode(), name="logins.csv")})
    assert res.prediction == "Suspicious" and res.explanation["logon_events_scored"] > 0


def test_csv_missing_columns_rejected(login_artifacts):
    with pytest.raises(InvalidInputError, match="Missing required"):
        det(login_artifacts).analyze({"file": FakeUpload(b"user,pc\nu,p\n", name="logins.csv")})


def test_raw_identifiers_never_appear_in_output(login_artifacts):
    events = normal_events(1, 60, prefix="alice_secret_")
    res = det(login_artifacts).analyze({"events": events})
    blob = json.dumps(res.explanation) + res.input_summary
    assert "alice_secret_" not in blob and "PC-0" not in blob


def test_needs_events_or_file_but_not_both(login_artifacts):
    with pytest.raises(InvalidInputError):
        det(login_artifacts).analyze({})
    with pytest.raises(InvalidInputError, match="not both"):
        det(login_artifacts).analyze({"events": normal_events(1, 40), "file": FakeUpload(b"a", name="x.csv")})


def test_missing_artifacts_raise(tmp_path):
    with pytest.raises(ModelNotLoadedError):
        det(tmp_path).analyze({"events": normal_events(1, 40)})