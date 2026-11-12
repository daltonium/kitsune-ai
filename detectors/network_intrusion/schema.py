"""Input schema for the network-intrusion module (CIC-IDS2017 / CICFlowMeter features)."""
from __future__ import annotations

import re

CIC_FEATURES = (
    "destination_port", "flow_duration", "total_fwd_packets", "total_backward_packets",
    "total_length_of_fwd_packets", "total_length_of_bwd_packets",
    "fwd_packet_length_max", "fwd_packet_length_min", "fwd_packet_length_mean", "fwd_packet_length_std",
    "bwd_packet_length_max", "bwd_packet_length_min", "bwd_packet_length_mean", "bwd_packet_length_std",
    "flow_bytes_s", "flow_packets_s",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fwd_iat_total", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_total", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
    "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
    "fwd_header_length", "bwd_header_length", "fwd_packets_s", "bwd_packets_s",
    "min_packet_length", "max_packet_length", "packet_length_mean", "packet_length_std",
    "packet_length_variance",
    "fin_flag_count", "syn_flag_count", "rst_flag_count", "psh_flag_count",
    "ack_flag_count", "urg_flag_count", "cwe_flag_count", "ece_flag_count",
    "down_up_ratio", "average_packet_size", "avg_fwd_segment_size", "avg_bwd_segment_size",
    "fwd_avg_bytes_bulk", "fwd_avg_packets_bulk", "fwd_avg_bulk_rate",
    "bwd_avg_bytes_bulk", "bwd_avg_packets_bulk", "bwd_avg_bulk_rate",
    "subflow_fwd_packets", "subflow_fwd_bytes", "subflow_bwd_packets", "subflow_bwd_bytes",
    "init_win_bytes_forward", "init_win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
    "active_mean", "active_std", "active_max", "active_min",
    "idle_mean", "idle_std", "idle_max", "idle_min",
)

EXCLUDED_BY_DEFAULT = ("destination_port",)
DEFAULT_FEATURES = tuple(f for f in CIC_FEATURES if f not in EXCLUDED_BY_DEFAULT)

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_FLOWS = 20000
MAX_FLOW_FIELDS = 200

_NON_NEGATIVE_EXACT = {"flow_duration", "flow_bytes_s", "flow_packets_s", "fwd_packets_s", "bwd_packets_s"}
_NON_NEGATIVE_PREFIXES = ("flow_iat", "fwd_iat", "bwd_iat")


def normalize_column(name) -> str:
    """' Flow Bytes/s' -> 'flow_bytes_s'."""
    return re.sub(r"[^0-9a-zA-Z]+", "_", str(name).strip().lower()).strip("_")


def must_be_non_negative(name: str) -> bool:
    return name in _NON_NEGATIVE_EXACT or name.startswith(_NON_NEGATIVE_PREFIXES)


def fix_label(label) -> str:
    """Repair the broken dash in web-attack labels ('Web Attack <?> XSS')."""
    text = re.sub(r"[^\x00-\x7f]+", "-", str(label))
    return re.sub(r"\s+", " ", text).strip()


def is_attack_label(label) -> bool:
    return fix_label(label).lower() != "benign"