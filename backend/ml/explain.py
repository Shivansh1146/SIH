"""
backend/ml/explain.py
======================
Phase 5 — PhishGuard AI Risk Engine and Explainability

Loads the trained Random Forest model and generates:
1. Phishing probability [0.0 - 1.0]
2. Risk score [0 - 100]
3. Verdict (SAFE, SUSPICIOUS, HIGH RISK, DANGEROUS)
4. Human-readable explanations based on feature values and model importance.

To keep the MVP fast and deployment-friendly, we use an intrinsic feature-importance
heuristic rather than full SHAP values, satisfying the Phase 5 requirements without
introducing heavy dependencies.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from .feature_extractor import extract_features, FEATURE_NAMES

# ── Paths ────────────────────────────────────────────────────────────────────
BACKEND_DIR = Path(__file__).resolve().parent.parent
MODEL_FILE  = BACKEND_DIR / "model" / "phishing_model.joblib"
META_FILE   = BACKEND_DIR / "model" / "feature_metadata.json"

# ── Global Model Cache ────────────────────────────────────────────────────────
_clf = None
_meta = None

def load_model():
    """Load the trained model and metadata into memory if not already loaded."""
    global _clf, _meta
    if _clf is None:
        if not MODEL_FILE.exists():
            raise FileNotFoundError(f"Model file not found: {MODEL_FILE}. Run Phase 4 training.")
        _clf = joblib.load(MODEL_FILE)
    
    if _meta is None:
        if not META_FILE.exists():
            raise FileNotFoundError(f"Metadata file not found: {META_FILE}.")
        with open(META_FILE, encoding="utf-8") as f:
            _meta = json.load(f)
            
    return _clf, _meta

# ── Verdict Logic ────────────────────────────────────────────────────────────
def get_verdict(score: int) -> str:
    if score <= 29:
        return "SAFE"
    elif score <= 59:
        return "SUSPICIOUS"
    elif score <= 79:
        return "HIGH RISK"
    else:
        return "DANGEROUS"

# ── Human-Readable Explanations ──────────────────────────────────────────────
def generate_reasons(features: dict[str, float]) -> list[str]:
    """
    Generate 3-5 human-readable reasons based on the actual feature values.
    """
    reasons = []

    # Scheme
    if features.get("https_enabled", 0) == 1:
        reasons.append("HTTPS is enabled (secure connection).")
    else:
        reasons.append("HTTPS is not enabled (insecure connection).")

    # Hostname structure
    if features.get("ip_hostname", 0) == 1:
        reasons.append("The hostname contains an IP address instead of a domain name.")
        
    if features.get("num_subdomains", 0) >= 2:
        reasons.append("Unusually deep subdomain structure detected.")

    if features.get("abnormal_hostname_length", 0) == 1:
        reasons.append("The hostname is abnormally long, often used to hide the real domain.")

    if features.get("punycode_detected", 0) == 1:
        reasons.append("Punycode detected (potential homograph attack).")

    # Path & Query structure
    if features.get("url_depth", 0) >= 4:
        reasons.append("Unusually deep URL structure.")
        
    if features.get("num_query_params", 0) >= 3:
        reasons.append("Large number of URL parameters detected.")
        
    if features.get("has_double_slash_in_path", 0) == 1:
        reasons.append("Suspicious double slash '//' found in the URL path.")
        
    if features.get("has_at_symbol", 0) == 1:
        reasons.append("An '@' symbol is present, which may obscure the true destination.")

    # Keywords
    if features.get("suspicious_keyword_count", 0) >= 2:
        reasons.append("The URL contains multiple credential-related keywords.")
    elif features.get("suspicious_keyword_count", 0) == 1:
        reasons.append("The URL contains a credential-related keyword.")

    # Brand Impersonation
    if features.get("brand_impersonation_indicator", 0) == 1:
        reasons.append("Potential brand impersonation pattern detected (brand name used in non-official domain).")
    elif features.get("brand_keyword_count", 0) > 0 and features.get("brand_impersonation_indicator", 0) == 0:
        reasons.append("Legitimate brand domain identified.")

    # Limit to top 5 most impactful reasons (heuristic sort: brand -> ip -> suspicious keywords -> etc)
    # We will just return up to 5 for brevity.
    if not reasons:
        reasons.append("No distinctly suspicious patterns observed in the URL structure.")

    return reasons[:5]

# ── Main API Function ────────────────────────────────────────────────────────
def analyze_url(url: str) -> dict[str, Any]:
    """
    End-to-end URL analysis pipeline.
    """
    try:
        clf, meta = load_model()
    except FileNotFoundError as e:
        return {
            "success": False,
            "error": str(e)
        }

    # Extract features
    res = extract_features(url)
    if res.error:
        return {
            "success": False,
            "error": res.error
        }

    # ML Inference
    vec = np.array([res.vector], dtype=np.float32)
    
    # Predict probability of class 1 (Phishing)
    prob_phish = float(clf.predict_proba(vec)[0][1])
    
    # Calculate 0-100 Risk Score
    risk_score = int(round(prob_phish * 100))
    
    # ── HEURISTIC OVERRIDE: Protect Legitimate Brands ────────────────────────
    # The ML model has a known bias against very short domains (e.g. google.com).
    # If the feature extractor confidently identified a legitimate brand domain,
    # we force the risk score to remain SAFE.
    if res.features.get("brand_keyword_count", 0) > 0 and res.features.get("brand_impersonation_indicator", 0) == 0:
        risk_score = min(risk_score, 15)  # Cap at 15
        prob_phish = risk_score / 100.0
    
    # Determine verdict
    verdict = get_verdict(risk_score)
    
    # Generate explanations
    reasons = generate_reasons(res.features)
    
    # Format feature dictionary for the response (dropping 0.0 values to keep it clean)
    clean_features = {k: v for k, v in res.features.items() if v > 0}
    
    # Build explanation mappings based on feature importances
    importances = clf.feature_importances_
    explanations = []
    
    # Get top active features
    active_features = []
    for idx, (name, val) in enumerate(zip(FEATURE_NAMES, res.vector)):
        if val > 0:
            active_features.append((name, val, importances[idx]))
            
    # Sort active features by their global importance in the model
    active_features.sort(key=lambda x: x[2], reverse=True)
    
    for name, val, imp in active_features[:5]:
        explanations.append({
            "feature": name,
            "value": val,
            "importance": round(float(imp), 4)
        })

    return {
        "success": True,
        "url": res.url,
        "risk_score": risk_score,
        "verdict": verdict,
        "confidence": round(prob_phish, 4),
        "reasons": reasons,
        "features": clean_features,
        "explanations": explanations
    }
