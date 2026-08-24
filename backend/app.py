"""
ThreatLens — Backend API
========================
Phase 1: Foundation scaffold only.

This file defines the Flask application skeleton with a /ping health-check
and a /scan endpoint stub.  No ML model is loaded in Phase 1.

Phase 2 will wire in:
  - Feature extraction  (backend/ml/feature_extractor.py)
  - ML model inference  (backend/ml/predictor.py)
  - SHAP explainability (backend/ml/explainer.py)
"""

from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # allow the frontend (Netlify) to call this API during development


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.route("/ping", methods=["GET"])
def ping():
    """Simple liveness probe — used by the frontend to verify API is reachable."""
    return jsonify({"status": "ok", "service": "ThreatLens API", "phase": 1})


# ---------------------------------------------------------------------------
# Scan endpoint (STUB — Phase 1)
# ---------------------------------------------------------------------------

@app.route("/scan", methods=["POST"])
def scan():
    """
    Accepts a URL and returns a phishing-risk assessment.

    Phase 1 status: STUB — returns a placeholder response.
    Phase 2 will replace this with real feature extraction + ML inference.

    Expected request body (JSON):
        { "url": "https://example.com" }

    Response (JSON):
        {
            "url":     str,
            "score":   int,          # 0–100 risk score
            "verdict": str,          # SAFE | SUSPICIOUS | HIGH RISK | DANGEROUS
            "reasons": list[str],    # plain-language explanations
            "phase":   int           # which implementation phase produced this
        }
    """
    data = request.get_json(silent=True)

    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' in request body"}), 400

    url = data["url"].strip()

    if not url:
        return jsonify({"error": "'url' must not be empty"}), 400

    # -----------------------------------------------------------------------
    # Phase 1 stub response
    # The real implementation (feature extraction + XGBoost + SHAP) will be
    # wired in Phase 2.  We return an explicit stub so the caller knows the
    # API is reachable but not yet functional.
    # -----------------------------------------------------------------------
    return jsonify({
        "url":     url,
        "score":   None,
        "verdict": "STUB",
        "reasons": [
            "Phase 1 scaffold — ML model not yet trained or loaded.",
            "Feature extraction pipeline not yet implemented.",
            "SHAP explainability not yet implemented."
        ],
        "phase": 1
    }), 200


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # debug=True is fine for local development; never use in production
    app.run(host="0.0.0.0", port=5000, debug=True)
