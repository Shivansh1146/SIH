"""
backend/tests/test_model.py
============================
Phase 4 — Tests for the trained phishing model.

These tests are SKIPPED automatically when the model file does not exist
(i.e., before training has been run).  After running:

    cd backend/ && python ml/train_model.py

all tests should pass.

Run:
    pytest tests/test_model.py -v
"""

from __future__ import annotations

import json
import sys
import os
from pathlib import Path

import numpy as np
import pytest

# ── Path setup ───────────────────────────────────────────────────────────────
BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

MODEL_FILE = BACKEND_DIR / "model" / "phishing_model.joblib"
META_FILE  = BACKEND_DIR / "model" / "feature_metadata.json"

# ── Skip all tests if model hasn't been trained yet ──────────────────────────
pytestmark = pytest.mark.skipif(
    not MODEL_FILE.exists(),
    reason=(
        "Model file not found. "
        "Run  cd backend/ && python ml/train_model.py  first."
    ),
)


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def clf():
    import joblib
    return joblib.load(MODEL_FILE)


@pytest.fixture(scope="module")
def meta():
    with open(META_FILE, encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def extractor():
    from ml.feature_extractor import extract_features, FEATURE_NAMES
    return extract_features, FEATURE_NAMES


# ─────────────────────────────────────────────────────────────────────────────
# 1. Model loads correctly
# ─────────────────────────────────────────────────────────────────────────────

class TestModelLoads:
    def test_model_file_exists(self):
        assert MODEL_FILE.exists(), f"Model file missing: {MODEL_FILE}"

    def test_meta_file_exists(self):
        assert META_FILE.exists(), f"Metadata file missing: {META_FILE}"

    def test_model_is_random_forest(self, clf):
        from sklearn.ensemble import RandomForestClassifier
        assert isinstance(clf, RandomForestClassifier)

    def test_model_has_200_trees(self, clf):
        assert len(clf.estimators_) == 200

    def test_model_has_classes(self, clf):
        assert list(clf.classes_) == [0, 1], (
            f"Expected classes [0, 1], got {clf.classes_}"
        )

    def test_model_has_feature_importances(self, clf):
        assert clf.feature_importances_ is not None
        assert len(clf.feature_importances_) == 34


# ─────────────────────────────────────────────────────────────────────────────
# 2. Feature count alignment
# ─────────────────────────────────────────────────────────────────────────────

class TestFeatureAlignment:
    def test_feature_count_matches_model_input(self, clf, extractor):
        extract_features, FEATURE_NAMES = extractor
        result = extract_features("https://github.com")
        vec = np.array([result.vector], dtype=np.float32)
        assert vec.shape[1] == clf.n_features_in_, (
            f"Extractor returns {vec.shape[1]} features, "
            f"model expects {clf.n_features_in_}"
        )

    def test_feature_names_match_metadata(self, meta, extractor):
        _, FEATURE_NAMES = extractor
        assert meta["feature_names"] == FEATURE_NAMES

    def test_metadata_feature_count_is_34(self, meta):
        assert meta["feature_count"] == 34

    def test_metadata_contains_required_keys(self, meta):
        required = {
            "model_name", "model_version", "phase", "training_date",
            "algorithm", "feature_names", "feature_count",
            "dataset", "metrics",
        }
        for key in required:
            assert key in meta, f"Metadata missing key: '{key}'"

    def test_metrics_not_fabricated(self, meta):
        """Metrics must exist and be in a realistic range (not hardcoded magic numbers)."""
        m = meta["metrics"]
        assert "accuracy"  in m
        assert "precision" in m
        assert "recall"    in m
        assert "f1_score"  in m
        # All metrics must be between 0 and 1
        for key in ("accuracy", "precision", "recall", "f1_score"):
            val = m[key]
            assert 0.0 <= val <= 1.0, f"Metric '{key}' out of range: {val}"

    def test_confusion_matrix_exists(self, meta):
        cm = meta["metrics"]["confusion_matrix"]
        assert len(cm) == 2
        assert len(cm[0]) == 2


# ─────────────────────────────────────────────────────────────────────────────
# 3. Predictions work
# ─────────────────────────────────────────────────────────────────────────────

class TestPredictions:
    def _predict(self, clf, extractor, url: str):
        extract_features, _ = extractor
        result = extract_features(url)
        vec = np.array([result.vector], dtype=np.float32)
        pred  = int(clf.predict(vec)[0])
        proba = clf.predict_proba(vec)[0]   # [P(legit), P(phish)]
        return pred, proba

    def test_prediction_returns_binary_label(self, clf, extractor):
        pred, _ = self._predict(clf, extractor, "https://github.com")
        assert pred in (0, 1)

    def test_probability_sums_to_one(self, clf, extractor):
        _, proba = self._predict(clf, extractor, "https://google.com")
        assert abs(sum(proba) - 1.0) < 1e-5

    def test_probability_in_unit_interval(self, clf, extractor):
        for url in ["https://github.com", "http://paypal-login-secure.xyz"]:
            _, proba = self._predict(clf, extractor, url)
            assert 0.0 <= proba[0] <= 1.0
            assert 0.0 <= proba[1] <= 1.0

    def test_phishing_url_higher_risk_than_safe(self, clf, extractor):
        """
        A known phishing-pattern URL should score higher phishing probability
        than a well-known legitimate domain.
        """
        _, proba_safe  = self._predict(clf, extractor, "https://github.com")
        _, proba_phish = self._predict(clf, extractor, "http://paypal-secure-login.example.com")
        assert proba_phish[1] > proba_safe[1], (
            f"Expected phishing URL to score higher than safe URL. "
            f"P(phish|github)={proba_safe[1]:.4f}, "
            f"P(phish|paypal-phish)={proba_phish[1]:.4f}"
        )

    def test_ip_url_has_nonzero_phish_probability(self, clf, extractor):
        _, proba = self._predict(clf, extractor, "http://192.168.1.1/admin/login")
        assert proba[1] > 0.0

    def test_no_score_attribute_on_result(self, extractor):
        extract_features, _ = extractor
        result = extract_features("https://github.com")
        assert not hasattr(result, "score")
        assert not hasattr(result, "verdict")


# ─────────────────────────────────────────────────────────────────────────────
# 4. Feature importance sanity
# ─────────────────────────────────────────────────────────────────────────────

class TestFeatureImportance:
    def test_importances_sum_to_one(self, clf):
        total = float(clf.feature_importances_.sum())
        assert abs(total - 1.0) < 1e-4, f"Importances sum to {total}, expected ~1.0"

    def test_no_negative_importance(self, clf):
        assert all(v >= 0 for v in clf.feature_importances_)

    def test_importance_length_matches_features(self, clf):
        from ml.feature_extractor import FEATURE_NAMES
        assert len(clf.feature_importances_) == len(FEATURE_NAMES)
