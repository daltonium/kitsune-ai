import math

import pytest

from detectors.phishing_url.feature_extractor import (
    FEATURE_NAMES, canonicalize, extract_features, feature_vector,
)
from detectors.phishing_url.feature_extractor import HOST_FEATURE_NAMES


def test_host_feature_set_is_subset():
    assert set(HOST_FEATURE_NAMES) <= set(FEATURE_NAMES)


def test_host_keyword_count():
    assert extract_features("http://secure-login.example.com/x")["host_keyword_count"] == 2

def test_basic_url_features_use_canonical_form():
    f = extract_features("https://www.example.com/path?a=1")
    assert "is_https" not in f
    assert f["host_is_ip"] == 0
    assert f["host_length"] == 11 and f["path_length"] == 5 and f["query_length"] == 3
    assert f["num_dots"] == 1 and f["num_subdomains"] == 0
    assert f["path_depth"] == 1 and f["num_question"] == 1 and f["num_equals"] == 1


def test_canonicalize():
    assert canonicalize("HTTPS://WWW.Example.com/Path") == "http://Example.com/Path"
    assert canonicalize("example.com/a") == "http://example.com/a"
    assert canonicalize("www.com") == "http://www.com"


def test_scheme_and_www_do_not_change_features():
    assert extract_features("https://www.example.com/a") == extract_features("http://example.com/a")


def test_ip_host_and_keyword():
    f = extract_features("http://192.168.1.1/login")
    assert f["host_is_ip"] == 1
    assert f["suspicious_keyword_count"] == 1 and f["num_subdomains"] == 0


def test_at_symbol_and_userinfo_host():
    f = extract_features("http://paypal.com@evil.example.com/login")
    assert f["num_at"] == 1 and f["host_length"] == 16 and f["num_subdomains"] == 1


def test_two_level_suffix_subdomains():
    assert extract_features("https://a.b.c.example.co.uk/x")["num_subdomains"] == 3


def test_punycode():
    assert extract_features("https://xn--80ak6aa92e.com/")["has_punycode"] == 1


def test_vector_matches_names_and_is_finite():
    url = "https://sub.example.org/a/b?x=1&y=2"
    vec = feature_vector(url)
    assert len(vec) == len(FEATURE_NAMES)
    assert all(math.isfinite(v) for v in vec)
    assert vec == feature_vector(url)


def test_unparseable_url_raises():
    with pytest.raises(ValueError):
        extract_features("http://[::1")