"""
feature_extractor.py — deterministic feature extraction for the SecBret ML sidecar.

Inputs are the exact fields carried by ClassificationRequest (proto/secbret.proto):
    - url               (string)
    - rule_score        (double)
    - tier1_findings_json (string, JSON object or "")
    - tier2_findings_json (string, JSON object or "")
    - tier3_findings_json (string, JSON object or "")

No other inputs are consumed.  All features must be reproducible given the same
request — no network calls, no randomness.

Feature vector layout (10 features):
    0  url_length              len(url)  — longer URLs are phishing-correlated
    1  url_entropy             Shannon entropy of URL characters
    2  subdomain_depth         number of dots in the hostname part
    3  has_ip_host             1 if hostname is an IPv4/v6 literal, else 0
    4  rule_score              rule_score passed through directly
    5  t1_ssl_valid            1 if tier1 "sslValid" is True, else 0
    6  t1_domain_age_days      domain age in days (0 when missing)
    7  t2_form_count           number of forms found by tier2 scanner (0 when missing)
    8  t2_external_domain_cnt  number of distinct external domains in tier2 (0 when missing)
    9  t3_kit_matched          1 if tier3 "kitMatched" is True, else 0
"""

from __future__ import annotations

import json
import math
import re
import urllib.parse
from collections import Counter
from typing import Any


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

FEATURE_NAMES = [
    "url_length",
    "url_entropy",
    "subdomain_depth",
    "has_ip_host",
    "rule_score",
    "t1_ssl_valid",
    "t1_domain_age_days",
    "t2_form_count",
    "t2_external_domain_cnt",
    "t3_kit_matched",
]

NUM_FEATURES = len(FEATURE_NAMES)  # 10

_IPV4_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)
_IPV6_BRACKET_RE = re.compile(r"^\[.*\]$")


def extract(
    url: str,
    rule_score: float,
    tier1_findings_json: str,
    tier2_findings_json: str,
    tier3_findings_json: str,
) -> list[float]:
    """Return a fixed-length feature vector (list[float], length NUM_FEATURES).

    Raises ValueError if any individual feature computation fails fatally.
    Missing or malformed JSON sub-objects are treated as absent (0 / default).
    """
    t1 = _parse_json(tier1_findings_json)
    t2 = _parse_json(tier2_findings_json)
    t3 = _parse_json(tier3_findings_json)

    parsed = _safe_parse_url(url)
    hostname = parsed.hostname or ""

    features: list[float] = [
        float(len(url)),                          # 0 url_length
        _shannon_entropy(url),                    # 1 url_entropy
        float(hostname.count(".")),               # 2 subdomain_depth
        float(_is_ip_host(hostname)),             # 3 has_ip_host
        float(rule_score),                        # 4 rule_score
        float(bool(_get(t1, "sslValid"))),        # 5 t1_ssl_valid
        float(_get(t1, "domainAgeDays", 0)),      # 6 t1_domain_age_days
        float(_get(t2, "formCount", 0)),          # 7 t2_form_count
        float(_get(t2, "externalDomainCount", 0)),# 8 t2_external_domain_cnt
        float(bool(_get(t3, "kitMatched"))),      # 9 t3_kit_matched
    ]

    assert len(features) == NUM_FEATURES, (
        f"BUG: expected {NUM_FEATURES} features, got {len(features)}"
    )
    return features


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_json(raw: str) -> dict[str, Any]:
    """Parse a JSON string into a dict; return {} on any error."""
    if not raw or not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except (json.JSONDecodeError, ValueError):
        return {}


def _get(d: dict[str, Any], key: str, default: Any = None) -> Any:
    """Safe dict get; returns default when key is absent or value is None."""
    val = d.get(key)
    return default if val is None else val


def _safe_parse_url(url: str) -> urllib.parse.ParseResult:
    try:
        return urllib.parse.urlparse(url)
    except Exception:
        return urllib.parse.urlparse("")


def _shannon_entropy(s: str) -> float:
    """Shannon entropy (bits) of the character distribution of s."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(
        (c / n) * math.log2(c / n) for c in counts.values() if c > 0
    )


def _is_ip_host(hostname: str) -> bool:
    """Return True if hostname is an IPv4 literal or a bracketed IPv6 literal."""
    if not hostname:
        return False
    if _IPV4_RE.match(hostname):
        return True
    if _IPV6_BRACKET_RE.match(hostname):
        return True
    return False
