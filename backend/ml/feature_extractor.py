"""
backend/ml/feature_extractor.py
================================
Phase 3 — URL Feature Extraction Engine for ThreatLens-Shield.

Converts a raw URL string into a deterministic, ordered feature vector
suitable for training and running a phishing-detection ML model.

Design constraints
------------------
* Pure string analysis only — no DNS lookups, no HTTP requests, no I/O.
* Deterministic feature ordering — the list FEATURE_NAMES is the single
  source of truth; the ML model will be trained on this exact order.
* Safe by default — malformed / unparseable URLs return a zero-vector
  rather than raising exceptions.
* No predictions, no scores, no hardcoded verdicts.

Public API
----------
    extract_features(url: str) -> FeatureResult

    FeatureResult is a dataclass with:
        .features   dict[str, float]   named feature values
        .vector     list[float]        ordered numerical vector (matches FEATURE_NAMES)
        .names      list[str]          FEATURE_NAMES (for reference / model training)
        .url        str                the (possibly normalised) URL that was analysed
        .error      str | None         set if parsing failed; features will be zeroed
"""

from __future__ import annotations

import math
import re
import string
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qs, unquote

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Suspicious / phishing-related keywords (all lowercase)
SUSPICIOUS_KEYWORDS: frozenset[str] = frozenset({
    "login", "signin", "verify", "verification", "account",
    "secure", "security", "update", "confirm", "password",
    "credential", "bank", "payment", "wallet", "otp",
    "free", "bonus", "claim", "urgent", "suspended",
})

# Individual keyword lists (subsets of SUSPICIOUS_KEYWORDS — kept separate
# so the model can weight them independently).
LOGIN_KEYWORDS:    frozenset[str] = frozenset({"login", "signin"})
VERIFY_KEYWORDS:   frozenset[str] = frozenset({"verify", "verification"})
ACCOUNT_KEYWORDS:  frozenset[str] = frozenset({"account"})
SECURE_KEYWORDS:   frozenset[str] = frozenset({"secure", "security"})
PASSWORD_KEYWORDS: frozenset[str] = frozenset({"password", "credential"})
UPDATE_KEYWORDS:   frozenset[str] = frozenset({"update", "confirm"})
PAYMENT_KEYWORDS:  frozenset[str] = frozenset({"payment", "wallet", "bank"})

# Well-known brands to detect potential impersonation
# NOTE: Presence of a brand name does NOT mean phishing — it is one signal
# among many that the ML model will weigh in context.
BRANDS: tuple[str, ...] = (
    "paypal", "google", "microsoft", "apple", "amazon",
    "facebook", "instagram", "github",
    "sbi", "hdfc", "icici", "axis",
    "upi", "phonepe", "paytm", "aadhaar", "irctc",
    "claude", "chatgpt", "openai", "netlify", "render",
)

# Suspicious TLDs that are disproportionately used in phishing campaigns
SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "tk", "ml", "ga", "cf", "gq",      # free Freenom TLDs
    "xyz", "top", "club", "work",
    "click", "download", "zip", "review",
    "loan", "win", "stream", "gdn",
})

# ---------------------------------------------------------------------------
# Feature name registry — SINGLE SOURCE OF TRUTH for ordering
# ---------------------------------------------------------------------------
# Any change here must be propagated to model retraining.
# Do NOT reorder existing entries without retraining the model.

FEATURE_NAMES: list[str] = [
    # ── URL-level structural features ──────────────────────────────────────
    "url_length",               # 01  total character count
    "hostname_length",          # 02  length of the hostname
    "path_length",              # 03  length of the path component
    "num_dots",                 # 04  total '.' in the full URL
    "num_hyphens",              # 05  total '-' in the full URL
    "num_digits",               # 06  digit count in the full URL
    "num_special_chars",        # 07  count of non-alphanumeric, non-standard chars
    "num_query_params",         # 08  number of key=value pairs in query string
    "url_depth",                # 09  directory depth (path segments)

    # ── Hostname-level features ────────────────────────────────────────────
    "num_subdomains",           # 10  subdomains beyond the registered domain
    "hostname_token_count",     # 11  tokens when hostname is split by '.', '-'
    "hostname_entropy",         # 12  Shannon entropy of the hostname string
    "abnormal_hostname_length", # 13  1 if hostname > 30 chars, else 0

    # ── Protocol / scheme features ─────────────────────────────────────────
    "https_enabled",            # 14  1 if scheme is https
    "http_enabled",             # 15  1 if scheme is http (plain, insecure)

    # ── Obfuscation / suspicious structure ────────────────────────────────
    "ip_hostname",              # 16  1 if hostname is an IP address
    "has_at_symbol",            # 17  1 if '@' appears in the URL
    "has_double_slash_in_path", # 18  1 if '//' appears anywhere after the authority
    "punycode_detected",        # 19  1 if hostname starts with 'xn--'
    "encoded_char_count",       # 20  count of %XX percent-encoded sequences
    "percent_encoded_count",    # 21  alias: same as encoded_char_count (kept for
                                #       model compatibility; some datasets split these)
    "url_entropy",              # 22  Shannon entropy of the full URL

    # ── Keyword / semantic features ────────────────────────────────────────
    "suspicious_keyword_count", # 23  total hits across all SUSPICIOUS_KEYWORDS
    "login_keyword_count",      # 24  hits for login / signin
    "verify_keyword_count",     # 25  hits for verify / verification
    "account_keyword_count",    # 26  hits for account
    "secure_keyword_count",     # 27  hits for secure / security
    "password_keyword_count",   # 28  hits for password / credential
    "update_keyword_count",     # 29  hits for update / confirm
    "payment_keyword_count",    # 30  hits for payment / wallet / bank

    # ── Brand impersonation features ───────────────────────────────────────
    "brand_impersonation_indicator", # 31  1 if a brand keyword found but domain
                                     #       is NOT the official brand TLD
    "brand_keyword_count",           # 32  total brand keyword hits in URL

    # ── TLD features ───────────────────────────────────────────────────────
    "suspicious_tld",           # 33  1 if TLD is in SUSPICIOUS_TLDS

    # ── Query string features ──────────────────────────────────────────────
    "url_parameter_count",      # 34  alias: same as num_query_params
                                #       (kept as named feature for ML interpretability)
]

# Sanity check at import time
assert len(FEATURE_NAMES) == 34, (
    f"Expected 34 features, got {len(FEATURE_NAMES)}. "
    "Update this assertion after intentional additions."
)


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class FeatureResult:
    """
    Returned by extract_features().

    Attributes
    ----------
    url      : The URL that was analysed (after scheme normalisation).
    features : Mapping of feature name → float value.
    vector   : Ordered list of float values matching FEATURE_NAMES.
    names    : The FEATURE_NAMES list (convenience reference).
    error    : None on success; a description string if parsing failed.
    """
    url:      str
    features: dict[str, float]
    vector:   list[float]
    names:    list[str] = field(default_factory=lambda: list(FEATURE_NAMES))
    error:    Optional[str] = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_IP_PATTERN = re.compile(
    r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
)

_PERCENT_ENC_PATTERN = re.compile(r"%[0-9A-Fa-f]{2}")

_SPECIAL_CHARS = frozenset(string.punctuation) - frozenset(".-_/:%?=&#@")


def _is_ip(hostname: str) -> bool:
    """Return True if *hostname* is an IPv4 address."""
    m = _IP_PATTERN.match(hostname)
    if not m:
        return False
    return all(0 <= int(m.group(i)) <= 255 for i in range(1, 5))


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy (bits) of string *s*."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _count_keywords(text: str, keywords: frozenset[str]) -> int:
    """Count non-overlapping occurrences of any keyword in *text*."""
    text_lower = text.lower()
    return sum(text_lower.count(kw) for kw in keywords)


def _extract_tld(hostname: str) -> str:
    """Return the TLD (last label) from a hostname. Empty string if unavailable."""
    parts = hostname.rstrip(".").split(".")
    return parts[-1].lower() if parts else ""


def _registered_domain(hostname: str) -> str:
    """
    Return a best-effort 'registered domain' (last two labels, e.g. 'google.com').
    This is intentionally simple — no PSL lookup — to keep the extractor free of I/O.
    """
    parts = hostname.rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:]).lower()
    return hostname.lower()


def _brand_impersonation(url_lower: str, hostname: str) -> tuple[int, int]:
    """
    Returns (brand_impersonation_indicator, brand_keyword_count).

    Logic:
    - brand_keyword_count = total brand keyword hits anywhere in the URL.
    - brand_impersonation_indicator = 1 if a brand keyword appears in the URL
      but the registered domain is NOT '{brand}.com/net/org/io'.
      (e.g. 'paypal-secure-login.example.com' → impersonation=1)
      (e.g. 'paypal.com'                      → impersonation=0)
    """
    count = 0
    impersonation = 0
    reg_domain = _registered_domain(hostname)

    for brand in BRANDS:
        if brand in url_lower:
            count += url_lower.count(brand)
            # Not impersonation if the registered domain IS the brand
            official = {
                f"{brand}.com", f"{brand}.net", f"{brand}.org", f"{brand}.io",
                f"{brand}.ai", f"{brand}.app", f"{brand}.co"
            }
            if reg_domain not in official:
                impersonation = 1

    return impersonation, count


def _normalise_url(raw: str) -> str:
    """Prepend https:// if no scheme is present."""
    raw = raw.strip()
    if raw and not raw.startswith(("http://", "https://", "ftp://", "ftps://")):
        raw = "https://" + raw
    return raw


# ---------------------------------------------------------------------------
# Main public function
# ---------------------------------------------------------------------------

def extract_features(url: str) -> FeatureResult:
    """
    Extract 34 phishing-detection features from *url*.

    Parameters
    ----------
    url : str
        The raw URL to analyse. A bare domain (no scheme) is accepted and
        treated as https://.

    Returns
    -------
    FeatureResult
        Named features dict, ordered vector, feature names, and any error.
        On parse failure all feature values are 0.0 and .error is set.

    Notes
    -----
    * No network I/O is performed.
    * Feature ordering matches FEATURE_NAMES exactly.
    """
    url = _normalise_url(url)

    # ── Parse ──────────────────────────────────────────────────────────────
    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        path     = parsed.path or ""
        query    = parsed.query or ""
        scheme   = (parsed.scheme or "").lower()
    except Exception as exc:
        zero = {name: 0.0 for name in FEATURE_NAMES}
        return FeatureResult(
            url=url,
            features=zero,
            vector=[0.0] * len(FEATURE_NAMES),
            error=f"URL parse error: {exc}",
        )

    url_lower = url.lower()

    # ── 01  url_length ─────────────────────────────────────────────────────
    url_length = float(len(url))

    # ── 02  hostname_length ────────────────────────────────────────────────
    hostname_length = float(len(hostname))

    # ── 03  path_length ────────────────────────────────────────────────────
    path_length = float(len(path))

    # ── 04  num_dots ──────────────────────────────────────────────────────
    num_dots = float(url.count("."))

    # ── 05  num_hyphens ────────────────────────────────────────────────────
    num_hyphens = float(url.count("-"))

    # ── 06  num_digits ────────────────────────────────────────────────────
    num_digits = float(sum(c.isdigit() for c in url))

    # ── 07  num_special_chars ─────────────────────────────────────────────
    num_special_chars = float(sum(c in _SPECIAL_CHARS for c in url))

    # ── 08  num_query_params ──────────────────────────────────────────────
    qs = parse_qs(query, keep_blank_values=True)
    num_query_params = float(len(qs))

    # ── 09  url_depth ─────────────────────────────────────────────────────
    # Count non-empty path segments
    url_depth = float(len([s for s in path.split("/") if s]))

    # ── 10  num_subdomains ────────────────────────────────────────────────
    # Labels beyond the registered domain (last 2 labels).
    host_labels = [l for l in hostname.split(".") if l]
    num_subdomains = float(max(0, len(host_labels) - 2))

    # ── 11  hostname_token_count ──────────────────────────────────────────
    # Tokens when splitting by both '.' and '-'
    tokens = re.split(r"[.\-]", hostname)
    hostname_token_count = float(len([t for t in tokens if t]))

    # ── 12  hostname_entropy ──────────────────────────────────────────────
    hostname_entropy = _shannon_entropy(hostname)

    # ── 13  abnormal_hostname_length ──────────────────────────────────────
    abnormal_hostname_length = 1.0 if len(hostname) > 30 else 0.0

    # ── 14  https_enabled ─────────────────────────────────────────────────
    https_enabled = 1.0 if scheme == "https" else 0.0

    # ── 15  http_enabled ──────────────────────────────────────────────────
    http_enabled = 1.0 if scheme == "http" else 0.0

    # ── 16  ip_hostname ───────────────────────────────────────────────────
    ip_hostname = 1.0 if _is_ip(hostname) else 0.0

    # ── 17  has_at_symbol ─────────────────────────────────────────────────
    has_at_symbol = 1.0 if "@" in url else 0.0

    # ── 18  has_double_slash_in_path ─────────────────────────────────────
    # Check for '//' that is NOT the authority separator (i.e., after '://')
    path_and_after = url.split("://", 1)[-1]          # strip 'scheme://'
    after_authority = path_and_after.split("/", 1)[-1] if "/" in path_and_after else ""
    has_double_slash_in_path = 1.0 if "//" in after_authority else 0.0

    # ── 19  punycode_detected ─────────────────────────────────────────────
    punycode_detected = 1.0 if hostname.startswith("xn--") or ".xn--" in hostname else 0.0

    # ── 20  encoded_char_count ────────────────────────────────────────────
    encoded_matches = _PERCENT_ENC_PATTERN.findall(url)
    encoded_char_count = float(len(encoded_matches))

    # ── 21  percent_encoded_count (alias) ────────────────────────────────
    percent_encoded_count = encoded_char_count

    # ── 22  url_entropy ───────────────────────────────────────────────────
    url_entropy = _shannon_entropy(url)

    # ── 23–30  keyword features ───────────────────────────────────────────
    suspicious_keyword_count = float(_count_keywords(url, SUSPICIOUS_KEYWORDS))
    login_keyword_count      = float(_count_keywords(url, LOGIN_KEYWORDS))
    verify_keyword_count     = float(_count_keywords(url, VERIFY_KEYWORDS))
    account_keyword_count    = float(_count_keywords(url, ACCOUNT_KEYWORDS))
    secure_keyword_count     = float(_count_keywords(url, SECURE_KEYWORDS))
    password_keyword_count   = float(_count_keywords(url, PASSWORD_KEYWORDS))
    update_keyword_count     = float(_count_keywords(url, UPDATE_KEYWORDS))
    payment_keyword_count    = float(_count_keywords(url, PAYMENT_KEYWORDS))

    # ── 31–32  brand features ─────────────────────────────────────────────
    brand_impersonation_indicator, brand_keyword_count = _brand_impersonation(
        url_lower, hostname
    )

    # ── 33  suspicious_tld ────────────────────────────────────────────────
    tld = _extract_tld(hostname)
    suspicious_tld = 1.0 if tld in SUSPICIOUS_TLDS else 0.0

    # ── 34  url_parameter_count (alias) ──────────────────────────────────
    url_parameter_count = num_query_params

    # ── Assemble feature dict (order matches FEATURE_NAMES) ───────────────
    features: dict[str, float] = {
        "url_length":               url_length,
        "hostname_length":          hostname_length,
        "path_length":              path_length,
        "num_dots":                 num_dots,
        "num_hyphens":              num_hyphens,
        "num_digits":               num_digits,
        "num_special_chars":        num_special_chars,
        "num_query_params":         num_query_params,
        "url_depth":                url_depth,
        "num_subdomains":           num_subdomains,
        "hostname_token_count":     hostname_token_count,
        "hostname_entropy":         hostname_entropy,
        "abnormal_hostname_length": abnormal_hostname_length,
        "https_enabled":            https_enabled,
        "http_enabled":             http_enabled,
        "ip_hostname":              ip_hostname,
        "has_at_symbol":            has_at_symbol,
        "has_double_slash_in_path": has_double_slash_in_path,
        "punycode_detected":        punycode_detected,
        "encoded_char_count":       encoded_char_count,
        "percent_encoded_count":    percent_encoded_count,
        "url_entropy":              url_entropy,
        "suspicious_keyword_count": suspicious_keyword_count,
        "login_keyword_count":      login_keyword_count,
        "verify_keyword_count":     verify_keyword_count,
        "account_keyword_count":    account_keyword_count,
        "secure_keyword_count":     secure_keyword_count,
        "password_keyword_count":   password_keyword_count,
        "update_keyword_count":     update_keyword_count,
        "payment_keyword_count":    payment_keyword_count,
        "brand_impersonation_indicator": float(brand_impersonation_indicator),
        "brand_keyword_count":      float(brand_keyword_count),
        "suspicious_tld":           suspicious_tld,
        "url_parameter_count":      url_parameter_count,
    }

    # Build ordered vector from the canonical FEATURE_NAMES list
    vector = [features[name] for name in FEATURE_NAMES]

    return FeatureResult(
        url=url,
        features=features,
        vector=vector,
    )
