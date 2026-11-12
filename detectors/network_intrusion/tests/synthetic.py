import io

import numpy as np
import pandas as pd

from ..schema import DEFAULT_FEATURES


def make_flows(n=400, seed=0):
    """Separable fake flows. y: 0 = benign (first half), 1 = attack (second half)."""
    rng = np.random.default_rng(seed)
    X = pd.DataFrame(rng.gamma(2.0, 50.0, size=(n, len(DEFAULT_FEATURES))), columns=list(DEFAULT_FEATURES))
    y = np.zeros(n, dtype=int)
    y[n // 2:] = 1
    atk = y == 1
    X.loc[atk, "total_fwd_packets"] *= 20
    X.loc[atk, "flow_packets_s"] *= 20
    X.loc[atk, "syn_flag_count"] = 1.0
    X.loc[~atk, "syn_flag_count"] = 0.0
    return X, y


def flow_dict(row):
    return {k: float(v) for k, v in row.items()}


class FakeUpload(io.BytesIO):
    """Minimal stand-in for an uploaded file."""

    def __init__(self, data, name="flows.csv"):
        super().__init__(data)
        self.name = name
        self.size = len(data)