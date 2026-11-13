import pandas as pd

from detectors.suspicious_login.feature_extractor import FEATURE_NAMES, build_features
from detectors.suspicious_login.log_preprocessing import clean_events, frame_from_events
from detectors.suspicious_login.tests.synthetic import normal_events, odd_event


def feats_for(events, min_history=30):
    clean, _ = clean_events(frame_from_events(events))
    feats = build_features(clean, min_history=min_history)
    return feats, clean


def test_cold_start_logons_are_excluded():
    feats, _ = feats_for(normal_events(1, 40))
    assert len(feats) == 10


def test_unusual_login_has_extreme_features():
    feats, _ = feats_for(normal_events(1, 60) + [odd_event("user0", 61)])
    last = feats.iloc[-1]
    assert last["after_hours"] == 1 and last["is_new_pc"] == 1 and last["user_hour_share"] < 0.05


def test_features_use_only_earlier_events():
    events = normal_events(1, 60)
    full, clean_full = feats_for(events)
    prefix, clean_prefix = feats_for(events[:45])
    full.index = clean_full.loc[full.index, "_row"].to_numpy()
    prefix.index = clean_prefix.loc[prefix.index, "_row"].to_numpy()
    pd.testing.assert_frame_equal(full.loc[prefix.index], prefix)


def test_columns_match_feature_names():
    feats, _ = feats_for(normal_events(1, 40))
    assert list(feats.columns) == FEATURE_NAMES