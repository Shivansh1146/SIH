"""
ThreatLens — Backend API
========================
Phase 2: Working Flask API with proper URL validation, CORS, and error handling.

Endpoints
---------
  GET  /api/health   — liveness probe
  POST /api/scan     — phishing-risk assessment (MODEL_NOT_CONNECTED until Phase 3)

Environment variables
---------------------
  FRONTEND_ORIGIN   Comma-separated list of allowed CORS origins.
                    Defaults to localhost + the live Netlify URL.
                    Example: FRONTEND_ORIGIN=https://threatlens1.netlify.app,http://localhost:3000

  FLASK_ENV         Set to "development" for debug mode (never set in production).
"""

import os
import logging
from urllib.parse import urlparse

from flask import Flask, jsonify, request
from flask_cors import CORS


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app() -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)

    # ── Logging ──────────────────────────────────────────────────────────────
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    log = logging.getLogger(__name__)

    # ── CORS ─────────────────────────────────────────────────────────────────
    # Origins are configurable via the FRONTEND_ORIGIN env var so we never
    # hardcode the Netlify URL in source code.
    default_origins = [
        "http://localhost:3000",
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "https://threatlens-shield.netlify.app",
        "https://threatlens1.netlify.app",  # legacy
    ]
    env_origins = os.environ.get("FRONTEND_ORIGIN", "")
    allowed_origins = (
        [o.strip() for o in env_origins.split(",") if o.strip()]
        if env_origins
        else default_origins
    )
    log.info("CORS allowed origins: %s", allowed_origins)

    CORS(
        app,
        resources={r"/api/*": {"origins": allowed_origins}},
        methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization"],
    )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _json_error(message: str, status: int = 400):
        """Return a consistent JSON error response."""
        return jsonify({"success": False, "error": message}), status

    def _validate_url(raw: str):
        """
        Validate that *raw* is a well-formed HTTP/HTTPS URL.

        Returns (cleaned_url, None) on success.
        Returns (None, error_message)  on failure.
        """
        if not isinstance(raw, str):
            return None, "URL must be a string."

        if not raw or not raw.strip():
            return None, "URL must not be empty."

        url = raw.strip()

        # Prepend https:// if user omitted the scheme (common for bare domains)
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        try:
            parsed = urlparse(url)
        except Exception:
            return None, "URL could not be parsed."

        if parsed.scheme not in ("http", "https"):
            return None, "Only http:// and https:// URLs are supported."

        # Must have a netloc (domain)
        if not parsed.netloc:
            return None, "URL is missing a domain."

        # Basic domain sanity check — must contain at least one dot
        hostname = parsed.hostname or ""
        if "." not in hostname:
            return None, "URL does not contain a valid domain."

        return url, None

    # ── Routes ────────────────────────────────────────────────────────────────

    @app.route("/api/health", methods=["GET"])
    def health():
        """
        Liveness probe.

        Response 200:
            { "status": "ok", "service": "ThreatLens API" }
        """
        return jsonify({"status": "ok", "service": "ThreatLens API"}), 200

    @app.route("/api/scan", methods=["POST"])
    def scan():
        """
        Submit a URL for phishing-risk analysis.

        Request body (JSON):
            { "url": "https://example.com" }

        Response 200 — MODEL_NOT_CONNECTED (Phase 2):
            {
                "success": true,
                "url":     "https://example.com",
                "status":  "MODEL_NOT_CONNECTED",
                "message": "Backend API is working. ML pipeline will be connected in a later phase."
            }

        Response 400 — invalid URL:
            { "success": false, "error": "..." }
        """
        # ── Parse request ──────────────────────────────────────────────────
        body = request.get_json(silent=True)

        if body is None:
            return _json_error(
                "Request body must be valid JSON with Content-Type: application/json."
            )

        if "url" not in body:
            return _json_error("Missing required field: 'url'.")

        # ── Validate URL ───────────────────────────────────────────────────
        url, err = _validate_url(body["url"])
        if err:
            return _json_error(f"Invalid URL — {err}")

        # ── Scan (Phase 5: ML Inference & Explainability) ──────────────────────
        log.info("Scan requested for URL: %s", url)

        from ml.explain import analyze_url
        result = analyze_url(url)
        
        if not result.get("success", False):
            return _json_error(result.get("error", "Failed to analyze URL"), 500)

        return jsonify(result), 200

    # ── Global error handlers ─────────────────────────────────────────────────

    @app.errorhandler(404)
    def not_found(exc):                         # noqa: F841
        return _json_error("Endpoint not found.", 404)

    @app.errorhandler(405)
    def method_not_allowed(exc):                # noqa: F841
        return _json_error("Method not allowed on this endpoint.", 405)

    @app.errorhandler(Exception)
    def unhandled(exc):                         # noqa: F841
        """
        Catch-all handler — never expose the stack trace to the client.
        The full traceback is written to the server log only.
        """
        log.exception("Unhandled exception: %s", exc)
        return _json_error("An unexpected server error occurred.", 500)

    return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

app = create_app()

# ── Model pre-warm ────────────────────────────────────────────────────────────
# Load the model into memory at startup so the first POST /api/scan request
# is not slowed down by a cold joblib load.  If the file is missing (e.g. in a
# test environment before training) the import is skipped gracefully.
try:
    from ml.explain import load_model as _load_model
    _load_model()
    logging.getLogger(__name__).info("ThreatLens model pre-loaded successfully.")
except FileNotFoundError:
    logging.getLogger(__name__).warning(
        "Model file not found at startup — will load on first request."
    )
except Exception as _exc:
    logging.getLogger(__name__).error("Model pre-load failed: %s", _exc)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV", "production") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)
