import numpy as np
import pytest

import detectors.network_intrusion.predictor as pred_mod
from detectors.base import RISK_ORDER
from detectors.exceptions import InvalidInputError, ModelNotLoadedError
from detectors.network_intrusion.predictor import NetworkIntrusionDetector
from detectors.network_intrusion.tests.synthetic import FakeUpload, flow_dict, make_flows


def det(art):
    return NetworkIntrusionDetector(artifacts_dir=art)


def cic_style_csv(X):
    out = X.copy()
    out.columns = [" " + c.replace("_", " ").title() for c in out.columns]
    return out.to_csv(index=False).encode()


def test_single_flow_returns_result(network_artifacts):
    X, _ = make_flows(10, seed=5)
    res = det(network_artifacts).analyze({"flow": flow_dict(X.iloc[0])})
    assert res.prediction in ("Attack", "Benign") and res.risk_level in RISK_ORDER
    assert 0.0 <= res.score <= 1.0 and res.explanation["flows_analyzed"] == 1
    assert len(res.explanation["unusual_features"]) == 3


def test_separates_unseen_synthetic_flows(network_artifacts):
    X, y = make_flows(40, seed=99)
    d = det(network_artifacts)
    hits = sum((d.analyze({"flow": flow_dict(X.iloc[i])}).score >= 0.5) == bool(y[i]) for i in range(len(y)))
    assert hits / len(y) >= 0.9


def test_missing_feature_rejected(network_artifacts):
    X, _ = make_flows(4, seed=6)
    flow = flow_dict(X.iloc[0])
    flow.pop("flow_duration")
    with pytest.raises(InvalidInputError, match="Missing"):
        det(network_artifacts).analyze({"flow": flow})


def test_unknown_field_rejected(network_artifacts):
    X, _ = make_flows(4, seed=6)
    flow = flow_dict(X.iloc[0])
    flow["evil_field"] = 1
    with pytest.raises(InvalidInputError, match="Unknown"):
        det(network_artifacts).analyze({"flow": flow})


@pytest.mark.parametrize("field,value", [
    ("flow_duration", float("nan")), ("flow_duration", -1.0), ("total_fwd_packets", "abc"),
])
def test_bad_flow_values_rejected(network_artifacts, field, value):
    X, _ = make_flows(4, seed=6)
    flow = flow_dict(X.iloc[0])
    flow[field] = value
    with pytest.raises(InvalidInputError):
        det(network_artifacts).analyze({"flow": flow})


def test_csv_upload_counts(network_artifacts):
    X, _ = make_flows(30, seed=7)
    res = det(network_artifacts).analyze({"file": FakeUpload(cic_style_csv(X))})
    e = res.explanation
    assert e["flows_analyzed"] == 30 and e["attack_count"] + e["benign_count"] == 30
    assert e["attack_count"] >= 10 and res.prediction == "Attack" and res.risk_level == "critical"


def test_csv_extra_columns_ignored_and_bad_rows_skipped(network_artifacts):
    X, _ = make_flows(6, seed=8)
    df = X.copy()
    df["Label"] = "BENIGN"
    df["Flow ID"] = "x"
    df.loc[2, "flow_bytes_s"] = np.inf
    res = det(network_artifacts).analyze({"file": FakeUpload(df.to_csv(index=False).encode())})
    assert res.explanation["skipped_rows"] == 1 and res.explanation["flows_analyzed"] == 5
    assert res.explanation["ignored_columns"] == 2


def test_csv_wrong_extension_rejected(network_artifacts):
    X, _ = make_flows(4, seed=9)
    with pytest.raises(InvalidInputError, match="csv"):
        det(network_artifacts).analyze({"file": FakeUpload(X.to_csv(index=False).encode(), name="flows.exe")})


def test_csv_too_large_rejected(network_artifacts, monkeypatch):
    monkeypatch.setattr(pred_mod, "MAX_UPLOAD_BYTES", 50)
    X, _ = make_flows(4, seed=9)
    with pytest.raises(InvalidInputError, match="too large"):
        det(network_artifacts).analyze({"file": FakeUpload(X.to_csv(index=False).encode())})


def test_csv_too_many_flows_rejected(network_artifacts, monkeypatch):
    monkeypatch.setattr(pred_mod, "MAX_FLOWS", 5)
    X, _ = make_flows(8, seed=9)
    with pytest.raises(InvalidInputError, match="too many"):
        det(network_artifacts).analyze({"file": FakeUpload(X.to_csv(index=False).encode())})


def test_csv_missing_columns_rejected(network_artifacts):
    X, _ = make_flows(4, seed=9)
    with pytest.raises(InvalidInputError, match="missing"):
        det(network_artifacts).analyze({"file": FakeUpload(X.drop(columns=["flow_duration"]).to_csv(index=False).encode())})


def test_csv_formula_cells_are_just_invalid_numbers(network_artifacts):
    X, _ = make_flows(5, seed=10)
    df = X.copy()
    df["flow_duration"] = df["flow_duration"].astype(object)
    df.loc[1, "flow_duration"] = "=cmd|' /C calc'!A0"
    res = det(network_artifacts).analyze({"file": FakeUpload(df.to_csv(index=False).encode())})
    assert res.explanation["skipped_rows"] == 1


def test_requires_flow_or_file(network_artifacts):
    with pytest.raises(InvalidInputError):
        det(network_artifacts).analyze({})


def test_flow_and_file_together_rejected(network_artifacts):
    X, _ = make_flows(4, seed=9)
    with pytest.raises(InvalidInputError, match="not both"):
        det(network_artifacts).analyze({"flow": flow_dict(X.iloc[0]), "file": FakeUpload(b"a,b\n1,2\n")})


def test_missing_artifacts_raise(tmp_path):
    with pytest.raises(ModelNotLoadedError):
        det(tmp_path).analyze({"flow": {"a": 1}})