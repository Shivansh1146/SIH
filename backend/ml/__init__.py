"""
backend/ml/__init__.py
======================
ML sub-package for PhishGuard AI.

Phase 1: Empty — no modules exist yet.

Planned modules (to be added in later phases):

    feature_extractor.py  — Phase 2
        Extracts ~30 lexical, structural, and network features from a raw URL.
        Features include: domain age, redirect depth, character substitution
        score, subdomain count, URL length, presence of HTTPS, etc.

    predictor.py          — Phase 3
        Loads the trained XGBoost model (backend/model/model.joblib) and
        returns a 0–100 risk score for a given feature vector.

    explainer.py          — Phase 5
        Uses SHAP TreeExplainer to produce per-feature attribution values
        that drive the plain-language reasons shown in the UI.
"""
