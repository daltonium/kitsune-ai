"""URL-only feature extraction. Pure string parsing: never opens or fetches a URL.

Features are computed on a canonical form (no scheme, no leading 'www.') so that
dataset artifacts like 'every legit URL is https://www.' cannot be learned.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlsplit

FEATURE_NAMES = [
    "url_length", "host_length", "path_length", "query_length",
    "num_dots", "num_hyphens", "num_underscores", "num_digits", "num_at",
    "num_question", "num_equals", "num_ampersand", "num_percent", "num_slashes",
    "num_suspicious_chars", "host_is_ip", "has_nonstandard_port",
    "num_subdomains", "host_num_hyphens", "host_num_digits", "tld_length",
    "has_punycode", "path_depth", "suspicious_keyword_count", "digit_ratio",
    "url_entropy","host_entropy", "host_keyword_count", "host_digit_ratio",
]

HOST_FEATURE_NAMES = [
    "host_length", "host_is_ip", "has_nonstandard_port", "num_subdomains",
    "host_num_hyphens", "host_num_digits", "tld_length", "has_punycode",
    "host_entropy", "host_keyword_count", "host_digit_ratio",
]

SUSPICIOUS_CHARS = set("@!$*()[]{}|\\<>`~;'\"")
SUSPICIOUS_KEYWORDS = (
    "login", "signin", "verify", "secure", "account", "update", "bank", "confirm",
    "password", "wallet", "payment", "billing", "support", "suspend", "unlock", "recover",
)
TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.in",
    "net.in", "org.in", "ac.in", "gov.in", "co.jp", "com.br", "com.cn", "co.za",
    "com.mx", "co.nz",
}
_NUMERIC_HOST = re.compile(r"^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}$", re.I)
_SCHEME = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.I)


def canonicalize(url: str) -> str:
    """Drop the scheme and a leading 'www.', then re-prefix with a fixed 'http://'."""
    rest = url.strip()
    m = _SCHEME.match(rest)
    if m:
        rest = rest[m.end():]
    if rest[:4].lower() == "www." and "." in rest[4:].split("/", 1)[0]:
        rest = rest[4:]
    return "http://" + rest


def uses_https(url: str) -> bool:
    return url.strip().lower().startswith("https://")


def is_ip_host(host: str) -> bool:
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(_NUMERIC_HOST.match(host))


def base_domain(host: str) -> str:
    """Approximate registrable domain (small built-in suffix list, no network)."""
    if not host or is_ip_host(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _entropy(text: str) -> float:
    n = len(text)
    if n == 0:
        return 0.0
    return -sum((c / n) * math.log2(c / n) for c in Counter(text).values())


def extract_features(url: str) -> dict:
    """Return {feature_name: float}. Raises ValueError if the URL cannot be parsed."""
    canon = canonicalize(url)
    parts = urlsplit(canon)
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = None

    is_ip = is_ip_host(host)
    labels = host.split(".") if host else []
    if host and not is_ip:
        n_sub = max(0, len(labels) - len(base_domain(host).split(".")))
    else:
        n_sub = 0
    tld_len = len(labels[-1]) if (len(labels) >= 2 and not is_ip) else 0

    lower = canon.lower()
    n = len(canon)
    digits = sum(ch.isdigit() for ch in canon)
    path_segments = [s for s in parts.path.split("/") if s]

    values = {
        "url_length": n,
        "host_length": len(host),
        "path_length": len(parts.path),
        "query_length": len(parts.query),
        "num_dots": canon.count("."),
        "num_hyphens": canon.count("-"),
        "num_underscores": canon.count("_"),
        "num_digits": digits,
        "num_at": canon.count("@"),
        "num_question": canon.count("?"),
        "num_equals": canon.count("="),
        "num_ampersand": canon.count("&"),
        "num_percent": canon.count("%"),
        "num_slashes": canon.count("/"),
        "num_suspicious_chars": sum(ch in SUSPICIOUS_CHARS for ch in canon),
        "host_is_ip": int(is_ip),
        "has_nonstandard_port": int(port is not None and port not in (80, 443)),
        "num_subdomains": n_sub,
        "host_num_hyphens": host.count("-"),
        "host_num_digits": sum(ch.isdigit() for ch in host),
        "tld_length": tld_len,
        "has_punycode": int("xn--" in host),
        "path_depth": len(path_segments),
        "suspicious_keyword_count": sum(kw in lower for kw in SUSPICIOUS_KEYWORDS),
        "digit_ratio": digits / n if n else 0.0,
        "url_entropy": _entropy(canon),
        "host_entropy": _entropy(host),
        "host_keyword_count": sum(kw in host for kw in SUSPICIOUS_KEYWORDS),
        "host_digit_ratio": (sum(ch.isdigit() for ch in host) / len(host)) if host else 0.0,
    }
    return {name: float(values[name]) for name in FEATURE_NAMES}


def feature_vector(url: str) -> list:
    feats = extract_features(url)
    return [feats[name] for name in FEATURE_NAMES]