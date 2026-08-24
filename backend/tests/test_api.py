"""
backend/tests/test_api.py
=========================
Pytest test suite for the ThreatLens Flask API — Phase 2.

Run from the backend/ directory:
    pytest tests/ -v

Coverage:
    - GET  /api/health
    - POST /api/scan — valid URL
    - POST /api/scan — invalid / edge-case URLs
    - POST /api/scan — malformed request body
    - 404 on unknown routes
    - 405 on wrong HTTP method
"""

import pytest
from app import create_app


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

@pytest.fixture()
def client():
    """Create a Flask test client with testing mode enabled."""
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def post_scan(client, payload, content_type="application/json"):
    """POST /api/scan with the given payload."""
    return client.post("/api/scan", json=payload, content_type=content_type)


# ---------------------------------------------------------------------------
# GET /api/health
# ---------------------------------------------------------------------------

class TestHealth:
    def test_status_200(self, client):
        """Health endpoint must return HTTP 200."""
        res = client.get("/api/health")
        assert res.status_code == 200

    def test_response_json_shape(self, client):
        """Health response must contain 'status' and 'service'."""
        res = client.get("/api/health")
        data = res.get_json()
        assert data["status"] == "ok"
        assert data["service"] == "ThreatLens API"

    def test_content_type_json(self, client):
        """Health response must declare application/json."""
        res = client.get("/api/health")
        assert "application/json" in res.content_type


# ---------------------------------------------------------------------------
# POST /api/scan — valid URLs
# ---------------------------------------------------------------------------

class TestScanValid:
    def test_https_url(self, client):
        """A valid https:// URL returns 200 and MODEL_NOT_CONNECTED."""
        res = post_scan(client, {"url": "https://example.com"})
        assert res.status_code == 200

    def test_response_shape(self, client):
        """Response must include success, url, status, message fields."""
        res = post_scan(client, {"url": "https://github.com"})
        data = res.get_json()
        assert data["success"] is True
        assert data["url"] == "https://github.com"
        assert data["status"] == "MODEL_NOT_CONNECTED"
        assert "message" in data
        assert isinstance(data["message"], str)
        assert len(data["message"]) > 0

    def test_no_fake_risk_score(self, client):
        """Phase 2 must NOT return a risk score or verdict."""
        res = post_scan(client, {"url": "https://paypal.com"})
        data = res.get_json()
        assert "score" not in data
        assert "verdict" not in data

    def test_http_url_accepted(self, client):
        """Plain http:// URLs are also valid."""
        res = post_scan(client, {"url": "http://example.com"})
        assert res.status_code == 200
        assert res.get_json()["success"] is True

    def test_bare_domain_auto_prefixed(self, client):
        """Bare domain without scheme should be accepted (https:// prepended)."""
        res = post_scan(client, {"url": "github.com"})
        data = res.get_json()
        assert res.status_code == 200
        assert data["success"] is True
        assert data["url"].startswith("https://")

    def test_url_with_path(self, client):
        """URL with path and query string is valid."""
        res = post_scan(client, {"url": "https://example.com/login?ref=home"})
        assert res.status_code == 200
        assert res.get_json()["success"] is True


# ---------------------------------------------------------------------------
# POST /api/scan — invalid URLs
# ---------------------------------------------------------------------------

class TestScanInvalidURL:
    def test_empty_string(self, client):
        """Empty string URL must return 400."""
        res = post_scan(client, {"url": ""})
        assert res.status_code == 400
        data = res.get_json()
        assert data["success"] is False
        assert "error" in data

    def test_whitespace_only(self, client):
        """Whitespace-only URL must return 400."""
        res = post_scan(client, {"url": "   "})
        assert res.status_code == 400
        assert res.get_json()["success"] is False

    def test_unsupported_scheme_ftp(self, client):
        """ftp:// URLs are not supported and must return 400."""
        res = post_scan(client, {"url": "ftp://example.com/file.txt"})
        assert res.status_code == 400
        assert res.get_json()["success"] is False

    def test_unsupported_scheme_javascript(self, client):
        """javascript: URLs must be rejected."""
        res = post_scan(client, {"url": "javascript:alert(1)"})
        assert res.status_code == 400
        assert res.get_json()["success"] is False

    def test_no_dot_in_domain(self, client):
        """Single-label hostname without dot must be rejected."""
        res = post_scan(client, {"url": "https://localhost"})
        assert res.status_code == 400
        assert res.get_json()["success"] is False

    def test_missing_domain(self, client):
        """URL with scheme but no domain must be rejected."""
        res = post_scan(client, {"url": "https://"})
        assert res.status_code == 400
        assert res.get_json()["success"] is False


# ---------------------------------------------------------------------------
# POST /api/scan — malformed request body
# ---------------------------------------------------------------------------

class TestScanMalformedBody:
    def test_missing_url_field(self, client):
        """Body without 'url' key must return 400."""
        res = post_scan(client, {"link": "https://example.com"})
        assert res.status_code == 400
        data = res.get_json()
        assert data["success"] is False
        assert "error" in data

    def test_non_json_body(self, client):
        """Non-JSON content-type body must return 400."""
        res = client.post(
            "/api/scan",
            data="url=https://example.com",
            content_type="application/x-www-form-urlencoded",
        )
        assert res.status_code == 400
        assert res.get_json()["success"] is False

    def test_null_url_value(self, client):
        """JSON null for url value must return 400."""
        res = post_scan(client, {"url": None})
        assert res.status_code == 400
        assert res.get_json()["success"] is False

    def test_numeric_url_value(self, client):
        """Non-string url value must return 400."""
        res = post_scan(client, {"url": 12345})
        assert res.status_code == 400
        assert res.get_json()["success"] is False

    def test_empty_body(self, client):
        """Empty JSON object must return 400."""
        res = post_scan(client, {})
        assert res.status_code == 400
        assert res.get_json()["success"] is False


# ---------------------------------------------------------------------------
# Error handling — routing
# ---------------------------------------------------------------------------

class TestErrorHandling:
    def test_404_unknown_route(self, client):
        """Unknown route must return 404 JSON error."""
        res = client.get("/api/unknown-endpoint")
        assert res.status_code == 404
        data = res.get_json()
        assert data["success"] is False
        assert "error" in data

    def test_405_get_on_scan(self, client):
        """GET on /api/scan must return 405 JSON error."""
        res = client.get("/api/scan")
        assert res.status_code == 405
        data = res.get_json()
        assert data["success"] is False

    def test_405_post_on_health(self, client):
        """POST on /api/health must return 405 JSON error."""
        res = client.post("/api/health")
        assert res.status_code == 405
        data = res.get_json()
        assert data["success"] is False
