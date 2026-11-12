import numpy as np
import pandas as pd

from detectors.network_intrusion.preprocess import (
    clean_features, read_flow_csv, unusual_features, compute_baseline,
)
from detectors.network_intrusion.schema import (
    CIC_FEATURES, DEFAULT_FEATURES, fix_label, is_attack_label, normalize_column,
)
from detectors.network_intrusion.tests.synthetic import make_flows

ORIGINAL_HEADER = (
    "Destination Port|Flow Duration|Total Fwd Packets|Total Backward Packets|Total Length of Fwd Packets|"
    "Total Length of Bwd Packets|Fwd Packet Length Max|Fwd Packet Length Min|Fwd Packet Length Mean|"
    "Fwd Packet Length Std|Bwd Packet Length Max|Bwd Packet Length Min|Bwd Packet Length Mean|"
    "Bwd Packet Length Std|Flow Bytes/s|Flow Packets/s|Flow IAT Mean|Flow IAT Std|Flow IAT Max|Flow IAT Min|"
    "Fwd IAT Total|Fwd IAT Mean|Fwd IAT Std|Fwd IAT Max|Fwd IAT Min|Bwd IAT Total|Bwd IAT Mean|Bwd IAT Std|"
    "Bwd IAT Max|Bwd IAT Min|Fwd PSH Flags|Bwd PSH Flags|Fwd URG Flags|Bwd URG Flags|Fwd Header Length|"
    "Bwd Header Length|Fwd Packets/s|Bwd Packets/s|Min Packet Length|Max Packet Length|Packet Length Mean|"
    "Packet Length Std|Packet Length Variance|FIN Flag Count|SYN Flag Count|RST Flag Count|PSH Flag Count|"
    "ACK Flag Count|URG Flag Count|CWE Flag Count|ECE Flag Count|Down/Up Ratio|Average Packet Size|"
    "Avg Fwd Segment Size|Avg Bwd Segment Size|Fwd Header Length.1|Fwd Avg Bytes/Bulk|Fwd Avg Packets/Bulk|"
    "Fwd Avg Bulk Rate|Bwd Avg Bytes/Bulk|Bwd Avg Packets/Bulk|Bwd Avg Bulk Rate|Subflow Fwd Packets|"
    "Subflow Fwd Bytes|Subflow Bwd Packets|Subflow Bwd Bytes|Init_Win_bytes_forward|Init_Win_bytes_backward|"
    "act_data_pkt_fwd|min_seg_size_forward|Active Mean|Active Std|Active Max|Active Min|Idle Mean|Idle Std|"
    "Idle Max|Idle Min"
).split("|")


def test_normalize_column_examples():
    assert normalize_column(" Destination Port") == "destination_port"
    assert normalize_column("Flow Bytes/s") == "flow_bytes_s"
    assert normalize_column("Down/Up Ratio") == "down_up_ratio"
    assert normalize_column("Init_Win_bytes_forward") == "init_win_bytes_forward"
    assert normalize_column("Fwd Header Length.1") == "fwd_header_length_1"
    assert normalize_column("FIN Flag Count") == "fin_flag_count"


def test_schema_counts_and_port_excluded():
    assert len(CIC_FEATURES) == 77 and len(set(CIC_FEATURES)) == 77
    assert len(DEFAULT_FEATURES) == 76 and "destination_port" not in DEFAULT_FEATURES
    assert all(normalize_column(f) == f for f in CIC_FEATURES)


def test_schema_matches_real_cic_header():
    normalized = {normalize_column(c) for c in ORIGINAL_HEADER}
    assert len(ORIGINAL_HEADER) == 78
    assert set(CIC_FEATURES) <= normalized
    assert normalized - set(CIC_FEATURES) == {"fwd_header_length_1"}


def test_fix_label_and_attack_detection():
    assert fix_label("Web Attack \ufffd Brute Force") == "Web Attack - Brute Force"
    assert fix_label("Web Attack \x96 XSS") == "Web Attack - XSS"
    assert not is_attack_label("BENIGN") and is_attack_label("DoS Hulk")


def test_clean_features_drops_bad_rows():
    X, _ = make_flows(5, seed=1)
    df = X.copy()
    df.loc[1, "flow_bytes_s"] = np.inf
    df.loc[2, "flow_duration"] = np.nan
    df.loc[3, "flow_iat_min"] = -5.0
    df["total_fwd_packets"] = df["total_fwd_packets"].astype(object)
    df.loc[4, "total_fwd_packets"] = "abc"
    cleaned, keep = clean_features(df, DEFAULT_FEATURES)
    assert keep.tolist() == [True, False, False, False, False] and len(cleaned) == 1


def test_read_flow_csv_reads_at_most_limit_plus_one():
    X, _ = make_flows(8, seed=2)
    df = read_flow_csv(X.to_csv(index=False).encode(), 3)
    assert len(df) == 4


def test_unusual_features_orders_by_robust_z():
    out = unusual_features([1, 10, 5], ["a", "b", "c"], np.zeros(3), np.ones(3), top=2)
    assert [o["feature"] for o in out] == ["b", "c"]
    
def test_baseline_scale_is_positive_even_for_constant_columns():
    X = pd.DataFrame({"a": [0.0] * 50 + [5.0, 9.0], "b": [3.0] * 52})
    _, scale = compute_baseline(X)
    assert scale["a"] > 0 and scale["b"] == 1.0