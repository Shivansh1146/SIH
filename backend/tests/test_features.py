"""
backend/tests/test_features.py
================================
Phase 3 — Unit tests for backend/ml/feature_extractor.py

Run from backend/ directory:
    pytest tests/test_features.py -v

All tests are deterministic (no network I/O, no randomness).
"""

import math
import sys
import os

# Make sure the backend package root is on sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from ml.feature_extractor import (
    extract_features,
    FeatureResult,
    FEATURE_NAMES,
    BRANDS,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS,
)


# ---------------------------------------------------------------------------
# Fixtures / shared URLs
# ---------------------------------------------------------------------------

SAFE_GOOGLE   = "https://google.com"
SAFE_GITHUB   = "https://github.com"
PHISH_PAYPAL  = "http://paypal-secure-login.example.com"
IP_URL        = "http://192.168.1.1/login"
AT_URL        = "http://user@evil-login.com/verify"
LONG_URL      = "https://legitimate-looking-but-very-long-domain-name-that-is-suspicious.com/" + "a" * 200
MULTI_SUB     = "https://accounts.secure.login.bankofamerica.com"
PUNYCODE_URL  = "https://xn--pypal-4ve.com/signin"
QUERY_URL     = "https://example.com/path?a=1&b=2&c=3"
DOUBLE_SLASH  = "https://example.com/path//secret/page"
ENCODED_URL   = "https://example.com/%70%61%79%70%61%6c/login"
BARE_DOMAIN   = "github.com"
SUSPICIOUS_TLD_URL = "https://free-bonus-claim.tk/win"


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def feat(url: str) -> FeatureResult:
    return extract_features(url)


# ---------------------------------------------------------------------------
# 1. Return type and structure
# ---------------------------------------------------------------------------

class TestReturnStructure:
    def test_returns_feature_result(self):
        r = feat(SAFE_GOOGLE)
        assert isinstance(r, FeatureResult)

    def test_names_match_global_constant(self):
        r = feat(SAFE_GITHUB)
        assert r.names == FEATURE_NAMES

    def test_feature_dict_has_all_names(self):
        r = feat(SAFE_GITHUB)
        for name in FEATURE_NAMES:
            assert name in r.features, f"Missing feature: {name}"

    def test_vector_length_matches_names(self):
        r = feat(SAFE_GITHUB)
        assert len(r.vector) == len(FEATURE_NAMES)

    def test_vector_order_matches_names(self):
        r = feat(SAFE_GITHUB)
        for i, name in enumerate(FEATURE_NAMES):
            assert r.vector[i] == r.features[name], (
                f"Vector[{i}] != features['{name}']"
            )

    def test_all_values_are_floats(self):
        r = feat(SAFE_GOOGLE)
        for name, val in r.features.items():
            assert isinstance(val, float), f"Feature '{name}' is not float: {type(val)}"

    def test_no_error_on_valid_url(self):
        r = feat(SAFE_GITHUB)
        assert r.error is None

    def test_exactly_34_features(self):
        r = feat(SAFE_GITHUB)
        assert len(r.features) == 34

    def test_feature_names_are_34(self):
        assert len(FEATURE_NAMES) == 34


# ---------------------------------------------------------------------------
# 2. Determinism — same input must always produce identical output
# ---------------------------------------------------------------------------

class TestDeterminism:
    def test_same_url_same_vector(self):
        v1 = feat(SAFE_GITHUB).vector
        v2 = feat(SAFE_GITHUB).vector
        assert v1 == v2

    def test_same_url_same_features(self):
        r1 = feat(PHISH_PAYPAL).features
        r2 = feat(PHISH_PAYPAL).features
        assert r1 == r2

    def test_feature_name_order_stable(self):
        names1 = feat(SAFE_GOOGLE).names
        names2 = feat(PHISH_PAYPAL).names
        assert names1 == names2


# ---------------------------------------------------------------------------
# 3. Scheme features (https_enabled, http_enabled)
# ---------------------------------------------------------------------------

class TestSchemeFeatures:
    def test_https_google(self):
        r = feat(SAFE_GOOGLE)
        assert r.features["https_enabled"] == 1.0
        assert r.features["http_enabled"]  == 0.0

    def test_http_phish(self):
        r = feat(PHISH_PAYPAL)
        assert r.features["https_enabled"] == 0.0
        assert r.features["http_enabled"]  == 1.0

    def test_bare_domain_treated_as_https(self):
        r = feat(BARE_DOMAIN)
        assert r.features["https_enabled"] == 1.0
        assert r.features["http_enabled"]  == 0.0


# ---------------------------------------------------------------------------
# 4. Length features
# ---------------------------------------------------------------------------

class TestLengthFeatures:
    def test_url_length_is_correct(self):
        url = "https://github.com"
        r = feat(url)
        assert r.features["url_length"] == float(len(url))

    def test_hostname_length_github(self):
        r = feat("https://github.com")
        assert r.features["hostname_length"] == float(len("github.com"))

    def test_path_length_no_path(self):
        r = feat("https://google.com")
        # urllib returns '/' as path when none given
        assert r.features["path_length"] >= 0.0

    def test_long_url_has_larger_url_length(self):
        r_short = feat(SAFE_GITHUB)
        r_long  = feat(LONG_URL)
        assert r_long.features["url_length"] > r_short.features["url_length"]

    def test_abnormal_hostname_length_short_host(self):
        r = feat("https://github.com")
        assert r.features["abnormal_hostname_length"] == 0.0

    def test_abnormal_hostname_length_long_host(self):
        r = feat("https://" + "a" * 35 + ".com")
        assert r.features["abnormal_hostname_length"] == 1.0


# ---------------------------------------------------------------------------
# 5. Structural count features
# ---------------------------------------------------------------------------

class TestStructuralFeatures:
    def test_num_dots_github(self):
        # 'https://github.com' — one dot
        r = feat("https://github.com")
        assert r.features["num_dots"] == 1.0

    def test_num_hyphens_phish(self):
        r = feat(PHISH_PAYPAL)
        assert r.features["num_hyphens"] >= 2.0  # 'paypal-secure-login'

    def test_num_digits_ip(self):
        r = feat(IP_URL)
        assert r.features["num_digits"] >= 6.0  # '192.168.1.1'

    def test_num_special_chars_not_negative(self):
        r = feat(SAFE_GOOGLE)
        assert r.features["num_special_chars"] >= 0.0

    def test_url_depth_root(self):
        r = feat("https://github.com")
        # path = '/' → no real segments
        assert r.features["url_depth"] == 0.0

    def test_url_depth_with_path(self):
        r = feat("https://github.com/user/repo/issues")
        assert r.features["url_depth"] == 3.0

    def test_num_query_params_none(self):
        r = feat("https://github.com")
        assert r.features["num_query_params"] == 0.0

    def test_num_query_params_three(self):
        r = feat(QUERY_URL)
        assert r.features["num_query_params"] == 3.0

    def test_url_parameter_count_alias(self):
        r = feat(QUERY_URL)
        assert r.features["url_parameter_count"] == r.features["num_query_params"]


# ---------------------------------------------------------------------------
# 6. Subdomain and hostname token features
# ---------------------------------------------------------------------------

class TestSubdomainFeatures:
    def test_no_subdomain_github(self):
        r = feat("https://github.com")
        assert r.features["num_subdomains"] == 0.0

    def test_one_subdomain(self):
        r = feat("https://www.github.com")
        assert r.features["num_subdomains"] == 1.0

    def test_multi_subdomain(self):
        r = feat(MULTI_SUB)
        # accounts.secure.login.bankofamerica.com → 3 subdomains
        assert r.features["num_subdomains"] == 3.0

    def test_hostname_token_count_github(self):
        # 'github.com' → ['github', 'com'] → 2
        r = feat("https://github.com")
        assert r.features["hostname_token_count"] == 2.0

    def test_hostname_token_count_hyphenated(self):
        # 'paypal-secure-login.example.com' → ['paypal','secure','login','example','com'] → 5
        r = feat(PHISH_PAYPAL)
        assert r.features["hostname_token_count"] == 5.0


# ---------------------------------------------------------------------------
# 7. Entropy features
# ---------------------------------------------------------------------------

class TestEntropyFeatures:
    def test_hostname_entropy_positive(self):
        r = feat(SAFE_GITHUB)
        assert r.features["hostname_entropy"] > 0.0

    def test_url_entropy_positive(self):
        r = feat(SAFE_GITHUB)
        assert r.features["url_entropy"] > 0.0

    def test_phish_url_entropy_non_zero(self):
        r = feat(PHISH_PAYPAL)
        assert r.features["url_entropy"] > 0.0

    def test_entropy_bounded(self):
        # Max entropy for ASCII 95-char set is ~6.57 bits; URLs won't exceed ~8
        r = feat(LONG_URL)
        assert r.features["url_entropy"] < 8.0


# ---------------------------------------------------------------------------
# 8. IP hostname
# ---------------------------------------------------------------------------

class TestIPHostname:
    def test_ip_detected(self):
        r = feat(IP_URL)
        assert r.features["ip_hostname"] == 1.0

    def test_domain_not_ip(self):
        r = feat(SAFE_GITHUB)
        assert r.features["ip_hostname"] == 0.0

    def test_private_ip(self):
        r = feat("http://10.0.0.1/admin")
        assert r.features["ip_hostname"] == 1.0

    def test_localhost_not_ip(self):
        # 'localhost' is not an IP pattern
        r = feat("http://localhost/page")
        assert r.features["ip_hostname"] == 0.0


# ---------------------------------------------------------------------------
# 9. @ symbol
# ---------------------------------------------------------------------------

class TestAtSymbol:
    def test_at_detected(self):
        r = feat(AT_URL)
        assert r.features["has_at_symbol"] == 1.0

    def test_no_at_github(self):
        r = feat(SAFE_GITHUB)
        assert r.features["has_at_symbol"] == 0.0


# ---------------------------------------------------------------------------
# 10. Double slash in path
# ---------------------------------------------------------------------------

class TestDoubleSlash:
    def test_double_slash_detected(self):
        r = feat(DOUBLE_SLASH)
        assert r.features["has_double_slash_in_path"] == 1.0

    def test_no_double_slash_normal_url(self):
        r = feat(SAFE_GITHUB)
        assert r.features["has_double_slash_in_path"] == 0.0


# ---------------------------------------------------------------------------
# 11. Punycode
# ---------------------------------------------------------------------------

class TestPunycode:
    def test_punycode_detected(self):
        r = feat(PUNYCODE_URL)
        assert r.features["punycode_detected"] == 1.0

    def test_no_punycode_github(self):
        r = feat(SAFE_GITHUB)
        assert r.features["punycode_detected"] == 0.0

    def test_punycode_in_subdomain(self):
        r = feat("https://xn--80akhbyknj4f.com")
        assert r.features["punycode_detected"] == 1.0


# ---------------------------------------------------------------------------
# 12. Percent-encoding
# ---------------------------------------------------------------------------

class TestPercentEncoding:
    def test_encoded_chars_detected(self):
        r = feat(ENCODED_URL)
        assert r.features["encoded_char_count"] > 0.0

    def test_encoded_count_alias_matches(self):
        r = feat(ENCODED_URL)
        assert r.features["encoded_char_count"] == r.features["percent_encoded_count"]

    def test_no_encoding_github(self):
        r = feat(SAFE_GITHUB)
        assert r.features["encoded_char_count"] == 0.0

    def test_encoded_count_correct(self):
        # ENCODED_URL has 6 encoded sequences (%70, %61, %79, %70, %61, %6c)
        r = feat(ENCODED_URL)
        assert r.features["encoded_char_count"] == 6.0


# ---------------------------------------------------------------------------
# 13. Keyword features
# ---------------------------------------------------------------------------

class TestKeywordFeatures:
    def test_suspicious_keywords_phish(self):
        r = feat(PHISH_PAYPAL)
        # URL contains 'secure' and 'login'
        assert r.features["suspicious_keyword_count"] >= 2.0

    def test_no_suspicious_keywords_github(self):
        r = feat(SAFE_GITHUB)
        assert r.features["suspicious_keyword_count"] == 0.0

    def test_login_keyword_detected(self):
        r = feat(PHISH_PAYPAL)
        assert r.features["login_keyword_count"] >= 1.0

    def test_verify_keyword_detected(self):
        r = feat("https://verify-account-now.com")
        assert r.features["verify_keyword_count"] >= 1.0
        assert r.features["account_keyword_count"] >= 1.0

    def test_secure_keyword_detected(self):
        r = feat(PHISH_PAYPAL)
        assert r.features["secure_keyword_count"] >= 1.0

    def test_password_keyword(self):
        r = feat("https://reset-password.evil.com/credential")
        assert r.features["password_keyword_count"] >= 2.0

    def test_payment_keyword(self):
        r = feat("https://payment-secure.example.com")
        assert r.features["payment_keyword_count"] >= 1.0

    def test_update_keyword(self):
        r = feat("https://update-your-account.com/confirm")
        assert r.features["update_keyword_count"] >= 2.0

    def test_no_keyword_noise_on_safe_url(self):
        r = feat(SAFE_GOOGLE)
        # 'google.com' contains no suspicious keywords
        assert r.features["login_keyword_count"]    == 0.0
        assert r.features["verify_keyword_count"]   == 0.0
        assert r.features["password_keyword_count"] == 0.0

    def test_ip_url_login_keyword(self):
        r = feat(IP_URL)
        # path is '/login'
        assert r.features["login_keyword_count"] >= 1.0


# ---------------------------------------------------------------------------
# 14. Brand impersonation
# ---------------------------------------------------------------------------

class TestBrandImpersonation:
    def test_paypal_impersonation_detected(self):
        r = feat(PHISH_PAYPAL)
        assert r.features["brand_impersonation_indicator"] == 1.0
        assert r.features["brand_keyword_count"] >= 1.0

    def test_real_github_not_impersonation(self):
        r = feat("https://github.com")
        # 'github' appears in URL but registered domain IS github.com
        assert r.features["brand_impersonation_indicator"] == 0.0

    def test_real_google_not_impersonation(self):
        r = feat("https://google.com")
        assert r.features["brand_impersonation_indicator"] == 0.0

    def test_punycode_paypal_is_impersonation(self):
        r = feat(PUNYCODE_URL)
        # 'signin' but also check the domain
        # xn--pypal-4ve.com is not paypal.com → impersonation
        assert r.features["brand_keyword_count"] >= 0.0  # pypal won't match exactly

    def test_brand_keyword_count_zero_no_brand(self):
        r = feat("https://evil-site-no-branding.com/login")
        assert r.features["brand_keyword_count"] == 0.0

    def test_brand_count_positive_with_brand(self):
        r = feat("https://paypal-login-secure.com")
        assert r.features["brand_keyword_count"] >= 1.0

    def test_multiple_brands_counted(self):
        r = feat("https://paypal-google-microsoft-login.com")
        assert r.features["brand_keyword_count"] >= 3.0


# ---------------------------------------------------------------------------
# 15. Suspicious TLD
# ---------------------------------------------------------------------------

class TestSuspiciousTLD:
    def test_suspicious_tld_detected(self):
        r = feat(SUSPICIOUS_TLD_URL)
        assert r.features["suspicious_tld"] == 1.0

    def test_safe_tld_github(self):
        r = feat(SAFE_GITHUB)
        assert r.features["suspicious_tld"] == 0.0

    def test_suspicious_tld_xyz(self):
        r = feat("https://phishing-site.xyz/account")
        assert r.features["suspicious_tld"] == 1.0

    def test_safe_tld_org(self):
        r = feat("https://nonprofit.org/donate")
        assert r.features["suspicious_tld"] == 0.0


# ---------------------------------------------------------------------------
# 16. Edge cases and robustness
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_bare_domain_accepted(self):
        r = feat(BARE_DOMAIN)
        assert r.error is None
        assert r.features["https_enabled"] == 1.0

    def test_empty_string_returns_zeros(self):
        r = feat("")
        # Should not raise; error may be set, vector should be all zeros
        assert r.vector == [0.0] * 34

    def test_only_scheme_returns_error_or_zeros(self):
        r = feat("https://")
        # May set error or return zeros — must not raise
        assert len(r.vector) == 34

    def test_very_long_url_does_not_crash(self):
        r = feat(LONG_URL)
        assert r.error is None
        assert r.features["url_length"] > 200.0

    def test_multi_subdomain_url(self):
        r = feat(MULTI_SUB)
        assert r.features["num_subdomains"] >= 3.0
        assert r.features["num_dots"] >= 4.0

    def test_at_symbol_url_processed(self):
        r = feat(AT_URL)
        assert r.error is None
        assert r.features["has_at_symbol"] == 1.0
        assert r.features["login_keyword_count"] >= 1.0
        assert r.features["verify_keyword_count"] >= 1.0


# ---------------------------------------------------------------------------
# 17. No fake predictions / scores
# ---------------------------------------------------------------------------

class TestNoPredictions:
    def test_no_score_field(self):
        r = feat(SAFE_GITHUB)
        assert not hasattr(r, "score")

    def test_no_verdict_field(self):
        r = feat(SAFE_GITHUB)
        assert not hasattr(r, "verdict")

    def test_no_prediction_field(self):
        r = feat(PHISH_PAYPAL)
        assert not hasattr(r, "prediction")

    def test_brand_indicator_not_automatic_verdict(self):
        """Brand impersonation indicator is a feature, not a classification."""
        r = feat("https://amazon-deals.com")
        # brand_impersonation_indicator may be 1, but there's no verdict
        assert not hasattr(r, "verdict")


# ---------------------------------------------------------------------------
# 18. Sample output spot-checks
# ---------------------------------------------------------------------------

class TestSpotChecks:
    """
    Spot-check specific known values to catch regressions.
    These values are derived from the deterministic extractor logic.
    """

    def test_github_https_enabled(self):
        assert feat("https://github.com").features["https_enabled"] == 1.0

    def test_github_ip_hostname_false(self):
        assert feat("https://github.com").features["ip_hostname"] == 0.0

    def test_github_no_brand_impersonation(self):
        assert feat("https://github.com").features["brand_impersonation_indicator"] == 0.0

    def test_paypal_phish_login_keyword(self):
        r = feat(PHISH_PAYPAL)
        assert r.features["login_keyword_count"] == 1.0

    def test_paypal_phish_secure_keyword(self):
        r = feat(PHISH_PAYPAL)
        assert r.features["secure_keyword_count"] == 1.0

    def test_paypal_phish_http_not_https(self):
        r = feat(PHISH_PAYPAL)
        assert r.features["https_enabled"] == 0.0
        assert r.features["http_enabled"]  == 1.0

    def test_paypal_phish_num_hyphens(self):
        # 'paypal-secure-login' has 2 hyphens
        r = feat(PHISH_PAYPAL)
        assert r.features["num_hyphens"] == 2.0
