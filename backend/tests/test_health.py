"""Phase 0 smoke tests for health API, static dashboard, and security headers."""

from fastapi.testclient import TestClient

from backend.app.main import create_app

REQUIRED_SECURITY_HEADERS = (
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Content-Security-Policy",
)


def test_health_endpoint_returns_ok_and_db_up() -> None:
    """GET /api/health returns 200 with healthy database metadata."""
    client = TestClient(create_app())
    response = client.get("/api/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["version"] == "1.0.0"
    assert payload["database"]["status"] == "up"
    assert payload["database"]["dialect"] in {"sqlite", "postgresql"}

    for header in REQUIRED_SECURITY_HEADERS:
        assert header in response.headers, f"Missing security header: {header}"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"


def test_dashboard_root_serves_html_with_security_headers() -> None:
    """GET / serves the Phase 0 dashboard HTML shell with security headers."""
    client = TestClient(create_app())
    response = client.get("/")

    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert "OWASP Top 10" in response.text
    assert "Phase 0" in response.text

    for header in REQUIRED_SECURITY_HEADERS:
        assert header in response.headers, f"Missing security header: {header}"
