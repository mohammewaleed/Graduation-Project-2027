"""End-to-end Phase 4 integration tests for REST API, worker, SSE, diffs, and reports.

Exercises the full FastAPI application created via ``create_app(database_url=...)``
backed by isolated temporary SQLite databases against an ephemeral local
``ThreadingHTTPServer`` target.
"""

from __future__ import annotations

import html
import json
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from backend.app.main import create_app

REQUIRED_SECURITY_HEADERS: tuple[str, ...] = (
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Content-Security-Policy",
)


class _VulnerableTestServer(ThreadingHTTPServer):
    """Ephemeral local HTTP server with toggleable seeded OWASP vulnerabilities."""

    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int]) -> None:
        self.sqli_enabled: bool = True
        self.xss_enabled: bool = True
        self.expose_env: bool = True
        self.request_delay: float = 0.0
        super().__init__(server_address, _VulnerableTestHandler)

    @property
    def base_url(self) -> str:
        host, port = self.server_address[:2]
        return f"http://{host}:{port}"

    def reset_flags(self) -> None:
        self.sqli_enabled = True
        self.xss_enabled = True
        self.expose_env = True
        self.request_delay = 0.0


class _VulnerableTestHandler(BaseHTTPRequestHandler):
    """Deterministic vulnerable local web app for integration testing."""

    server: _VulnerableTestServer

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def _send_security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; frame-ancestors 'none'; object-src 'none'",
        )

    def _write_response(
        self,
        status_code: int,
        body: str,
        *,
        content_type: str = "text/html; charset=utf-8",
    ) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self._send_security_headers()
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802
        delay = float(getattr(self.server, "request_delay", 0.0) or 0.0)
        if delay > 0:
            time.sleep(delay)

        parsed = urlsplit(self.path)
        path = parsed.path or "/"
        params = parse_qs(parsed.query, keep_blank_values=True)

        if path == "/":
            self._write_response(
                200,
                (
                    "<!DOCTYPE html><html><head><title>VulnLab Demo</title></head>"
                    "<body><h1>VulnLab Local App</h1>"
                    "<nav>"
                    '<a href="/item?id=1">Inspect Item 1</a>'
                    '<a href="/search?q=welcome">Search Catalog</a>'
                    "</nav></body></html>"
                ),
            )
            return

        if path == "/item":
            item_id = (params.get("id") or ["1"])[0]
            if self.server.sqli_enabled and ("'" in item_id or '"' in item_id):
                self._write_response(
                    500,
                    (
                        "<html><body><h1>Internal Server Error</h1>"
                        "<pre>sqlite3.OperationalError: near \"'\": syntax error</pre>"
                        "</body></html>"
                    ),
                )
                return
            safe_id = html.escape(item_id, quote=True)
            self._write_response(
                200,
                (
                    "<!DOCTYPE html><html><body>"
                    f"<h1>Item Detail</h1><p>Showing catalog record #{safe_id}.</p>"
                    "</body></html>"
                ),
            )
            return

        if path == "/search":
            query_text = (params.get("q") or [""])[0]
            rendered = (
                query_text
                if self.server.xss_enabled
                else html.escape(query_text, quote=True)
            )
            self._write_response(
                200,
                (
                    "<!DOCTYPE html><html><body>"
                    f"<h1>Search</h1><p>Results for: {rendered}</p>"
                    "</body></html>"
                ),
            )
            return

        if path == "/.env":
            if self.server.expose_env:
                self._write_response(
                    200,
                    "APP_ENV=local\nDB_PASSWORD=integration_test_secret\n",
                    content_type="text/plain; charset=utf-8",
                )
                return
            self._write_response(
                404,
                "Not Found",
                content_type="text/plain; charset=utf-8",
            )
            return

        self._write_response(
            404,
            f"Resource {html.escape(path)} not found",
            content_type="text/plain; charset=utf-8",
        )


@pytest.fixture(scope="module")
def vuln_server() -> Iterator[_VulnerableTestServer]:
    """Start an ephemeral local ThreadingHTTPServer bound to 127.0.0.1."""
    server = _VulnerableTestServer(("127.0.0.1", 0))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture()
def api_client(tmp_path: Path) -> Iterator[TestClient]:
    """Create an isolated FastAPI TestClient backed by a temp SQLite database."""
    db_path = tmp_path / "phase4_e2e.db"
    database_url = f"sqlite:///{db_path.as_posix()}"
    app = create_app(database_url=database_url)
    try:
        with TestClient(app) as client:
            yield client
    finally:
        app.state.db_engine.dispose()


def _create_local_project(
    client: TestClient,
    base_url: str,
    *,
    name: str = "Local VulnLab Target",
    target_stack: str = "express",
) -> dict[str, Any]:
    response = client.post(
        "/api/projects",
        json={
            "name": name,
            "base_url": base_url,
            "target_stack": target_stack,
            "authorized_confirmed": True,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _stream_sse_events(client: TestClient, scan_id: str) -> list[dict[str, Any]]:
    """Consume all JSON SSE frames from ``/api/scans/{scan_id}/stream`` until completion."""
    events: list[dict[str, Any]] = []
    with client.stream("GET", f"/api/scans/{scan_id}/stream") as response:
        assert response.status_code == 200
        assert "text/event-stream" in response.headers.get("content-type", "")
        for raw_line in response.iter_lines():
            line = raw_line.strip()
            if not line or not line.startswith("data:"):
                continue
            payload_text = line[len("data:") :].strip()
            if not payload_text:
                continue
            event = json.loads(payload_text)
            assert isinstance(event, dict)
            events.append(event)
            if event.get("type") == "status" and event.get("status") in {
                "completed",
                "failed",
                "cancelled",
            }:
                break
    return events


def _wait_for_terminal_scan(
    client: TestClient,
    scan_id: str,
    *,
    timeout_s: float = 15.0,
) -> dict[str, Any]:
    """Poll ``GET /api/scans/{scan_id}`` until a terminal status is persisted."""
    deadline = time.monotonic() + timeout_s
    last_payload: dict[str, Any] = {}
    while time.monotonic() < deadline:
        resp = client.get(f"/api/scans/{scan_id}")
        assert resp.status_code == 200
        last_payload = resp.json()
        if last_payload["status"] in {"completed", "failed", "cancelled"}:
            return last_payload
        time.sleep(0.05)
    pytest.fail(
        f"Scan {scan_id} did not reach a terminal status within {timeout_s}s; "
        f"last state: {last_payload}"
    )


@pytest.fixture(scope="module")
def primary_scan_bundle(
    tmp_path_factory: pytest.TempPathFactory,
    vuln_server: _VulnerableTestServer,
) -> Iterator[dict[str, Any]]:
    """Run one complete full-profile standard scan shared by read-only E2E assertions."""
    vuln_server.reset_flags()
    db_dir = tmp_path_factory.mktemp("phase4_primary")
    db_path = db_dir / "primary_scan.db"
    app = create_app(database_url=f"sqlite:///{db_path.as_posix()}")
    try:
        with TestClient(app) as client:
            project = _create_local_project(
                client,
                vuln_server.base_url,
                name="Primary E2E App",
                target_stack="express",
            )
            start_resp = client.post(
                f"/api/projects/{project['id']}/scans",
                json={"profile": "standard"},
            )
            assert start_resp.status_code == 201, start_resp.text
            started_scan = start_resp.json()
            assert started_scan["status"] in {
                "queued",
                "crawling",
                "scanning",
                "completed",
            }

            sse_events = _stream_sse_events(client, started_scan["id"])
            completed_scan = _wait_for_terminal_scan(client, started_scan["id"])

            yield {
                "client": client,
                "project": project,
                "started_scan": started_scan,
                "completed_scan": completed_scan,
                "sse_events": sse_events,
            }
    finally:
        app.state.db_engine.dispose()


def test_health_and_security_headers(api_client: TestClient) -> None:
    """Requirement 1: GET /api/health returns 200, DB up, and required security headers."""
    response = api_client.get("/api/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["database"]["status"] == "up"

    for header in REQUIRED_SECURITY_HEADERS:
        assert header in response.headers, f"Missing required header: {header}"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"


def test_checks_catalog_returns_all_17_checks(api_client: TestClient) -> None:
    """Requirement 2: GET /api/checks returns all 17 registered OWASP checks with valid metadata."""
    response = api_client.get("/api/checks")

    assert response.status_code == 200
    checks = response.json()
    assert isinstance(checks, list)
    assert len(checks) == 17

    ids = [item["id"] for item in checks]
    assert len(set(ids)) == 17
    for expected_id in (
        "missing_security_headers",
        "sqli_error_based",
        "xss_reflected",
        "sensitive_files",
    ):
        assert expected_id in ids

    for item in checks:
        assert item["name"]
        assert item["owasp_category"]
        assert item["cwe_id"].startswith("CWE-")
        assert item["kind"] in {"passive", "active", "discovery"}
        assert item["default_severity"] in {"critical", "high", "medium", "low", "info"}
        assert isinstance(item["profiles"], list) and len(item["profiles"]) >= 1
        assert item["description"]


def test_project_crud_and_scope_guardrail(
    api_client: TestClient,
    vuln_server: _VulnerableTestServer,
) -> None:
    """Requirement 3: Authorization confirmation (400), scope guardrail (403), and CRUD (201/200/404)."""
    # 1. Missing authorization confirmation -> 400 AUTHORIZATION_REQUIRED
    unauth_resp = api_client.post(
        "/api/projects",
        json={
            "name": "Unauthorized Target",
            "base_url": vuln_server.base_url,
            "target_stack": "fastapi",
            "authorized_confirmed": False,
        },
    )
    assert unauth_resp.status_code == 400
    unauth_body = unauth_resp.json()
    assert unauth_body["error"]["code"] == "AUTHORIZATION_REQUIRED"
    assert unauth_body["error"]["message"]

    # 2. Public target blocked by ScopeGuardrail -> 403 TARGET_NOT_ALLOWED
    blocked_resp = api_client.post(
        "/api/projects",
        json={
            "name": "Public Target Blocked",
            "base_url": "https://google.com",
            "target_stack": "fastapi",
            "authorized_confirmed": True,
        },
    )
    assert blocked_resp.status_code == 403
    blocked_body = blocked_resp.json()
    assert blocked_body["error"]["code"] == "TARGET_NOT_ALLOWED"
    assert blocked_body["error"]["message"]

    # 3. Valid authorized local target -> 201, listed in GET /api/projects, fetched by ID
    created = _create_local_project(
        api_client,
        vuln_server.base_url,
        name="Authorized Local App",
        target_stack="flask",
    )
    assert created["name"] == "Authorized Local App"
    assert created["target_stack"] == "flask"
    assert created["authorized_confirmed"] is True

    list_resp = api_client.get("/api/projects")
    assert list_resp.status_code == 200
    projects = list_resp.json()
    assert any(p["id"] == created["id"] for p in projects)

    get_resp = api_client.get(f"/api/projects/{created['id']}")
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == created["id"]
    assert get_resp.json()["base_url"] == created["base_url"]

    # 4. Uniform 404 envelope for unknown project
    missing_resp = api_client.get("/api/projects/nonexistent-project-id")
    assert missing_resp.status_code == 404
    assert missing_resp.json()["error"]["code"] == "PROJECT_NOT_FOUND"


def test_full_scan_lifecycle_sse_and_telemetry(
    primary_scan_bundle: dict[str, Any],
) -> None:
    """Requirement 4a: Full async scan lifecycle, valid SSE stream, and completed telemetry."""
    client: TestClient = primary_scan_bundle["client"]
    started_scan: dict[str, Any] = primary_scan_bundle["started_scan"]
    sse_events: list[dict[str, Any]] = primary_scan_bundle["sse_events"]
    scan_id = started_scan["id"]

    # SSE stream delivered valid JSON events ending with terminal completed status
    assert len(sse_events) >= 1
    terminal_event = sse_events[-1]
    assert terminal_event["type"] == "status"
    assert terminal_event["scan_id"] == scan_id
    assert terminal_event["status"] == "completed"
    assert terminal_event["risk_score"] > 0

    # GET /api/scans/{scan_id} reflects completed status, risk_score > 0, crawl & request counts
    scan_resp = client.get(f"/api/scans/{scan_id}")
    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()
    assert scan_data["status"] == "completed"
    assert scan_data["progress_pct"] == 100
    assert scan_data["risk_score"] > 0
    assert scan_data["pages_crawled"] > 0
    assert scan_data["requests_sent"] > 0
    assert scan_data["finished_at"] is not None


def test_scan_endpoints_findings_filters_and_stack_fix(
    primary_scan_bundle: dict[str, Any],
) -> None:
    """Requirement 4b: Persisted endpoints, finding query filters, and preferred stack fix order."""
    client: TestClient = primary_scan_bundle["client"]
    project: dict[str, Any] = primary_scan_bundle["project"]
    scan_id: str = primary_scan_bundle["started_scan"]["id"]

    # Persisted endpoints
    ep_resp = client.get(f"/api/scans/{scan_id}/endpoints")
    assert ep_resp.status_code == 200
    endpoints = ep_resp.json()
    assert len(endpoints) >= 2
    ep_urls = [ep["url"] for ep in endpoints]
    assert any("/item" in url for url in ep_urls)
    assert any("/search" in url for url in ep_urls)

    # All findings
    all_resp = client.get(f"/api/scans/{scan_id}/findings")
    assert all_resp.status_code == 200
    findings = all_resp.json()
    assert len(findings) >= 3
    check_ids = {f["check_id"] for f in findings}
    assert {"sqli_error_based", "xss_reflected", "sensitive_files"}.issubset(check_ids)

    # Filter: ?severity=critical
    crit_resp = client.get(f"/api/scans/{scan_id}/findings", params={"severity": "critical"})
    assert crit_resp.status_code == 200
    crit_findings = crit_resp.json()
    assert len(crit_findings) >= 1
    assert all(f["severity"] == "critical" for f in crit_findings)
    assert any(f["check_id"] == "sqli_error_based" for f in crit_findings)

    # Filter: ?q=item
    q_resp = client.get(f"/api/scans/{scan_id}/findings", params={"q": "item"})
    assert q_resp.status_code == 200
    q_findings = q_resp.json()
    assert len(q_findings) >= 1
    assert all(
        "item" in (f["endpoint_url"] or "").lower()
        or "item" in (f["title"] or "").lower()
        or "item" in (f["parameter"] or "").lower()
        or "item" in (f["check_id"] or "").lower()
        for f in q_findings
    )

    # Filter: ?triage_status=open
    open_resp = client.get(f"/api/scans/{scan_id}/findings", params={"triage_status": "open"})
    assert open_resp.status_code == 200
    open_findings = open_resp.json()
    assert len(open_findings) == len(findings)
    assert all(f["triage_status"] == "open" for f in open_findings)

    # Finding detail: fix.snippets[0].stack == project.target_stack ("express")
    sqli_finding = next(f for f in findings if f["check_id"] == "sqli_error_based")
    detail_resp = client.get(f"/api/findings/{sqli_finding['id']}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["id"] == sqli_finding["id"]
    assert detail["explanation"]
    assert detail["evidence"]
    snippets = detail["fix"]["snippets"]
    assert isinstance(snippets, list) and len(snippets) >= 1
    assert snippets[0]["stack"] == project["target_stack"]
    assert snippets[0]["before"]
    assert snippets[0]["after"]


def test_finding_triage_and_risk_score_recalculation(
    api_client: TestClient,
    vuln_server: _VulnerableTestServer,
) -> None:
    """Requirement 5: PATCH /api/findings/{id} to false_positive reduces parent scan risk_score."""
    vuln_server.reset_flags()
    project = _create_local_project(
        api_client,
        vuln_server.base_url,
        name="Triage Test App",
        target_stack="fastapi",
    )

    start_resp = api_client.post(
        f"/api/projects/{project['id']}/scans",
        json={
            "profile": "standard",
            "enabled_checks": ["sqli_error_based", "xss_reflected", "sensitive_files"],
        },
    )
    assert start_resp.status_code == 201
    scan_id = start_resp.json()["id"]
    _stream_sse_events(api_client, scan_id)

    before_scan = api_client.get(f"/api/scans/{scan_id}").json()
    assert before_scan["status"] == "completed"
    initial_risk_score = before_scan["risk_score"]
    assert initial_risk_score > 0

    findings = api_client.get(f"/api/scans/{scan_id}/findings").json()
    critical_finding = next(f for f in findings if f["severity"] == "critical")

    patch_resp = api_client.patch(
        f"/api/findings/{critical_finding['id']}",
        json={
            "triage_status": "false_positive",
            "triage_note": "Verified benign",
        },
    )
    assert patch_resp.status_code == 200
    patched = patch_resp.json()
    assert patched["triage_status"] == "false_positive"
    assert patched["triage_note"] == "Verified benign"

    after_scan = api_client.get(f"/api/scans/{scan_id}").json()
    assert after_scan["risk_score"] < initial_risk_score

    # Confirm ?triage_status=false_positive filter finds the triaged finding
    fp_resp = api_client.get(
        f"/api/scans/{scan_id}/findings",
        params={"triage_status": "false_positive"},
    )
    assert fp_resp.status_code == 200
    fp_ids = [f["id"] for f in fp_resp.json()]
    assert critical_finding["id"] in fp_ids


def test_scan_comparison_detects_fixed_and_unchanged(
    api_client: TestClient,
    vuln_server: _VulnerableTestServer,
) -> None:
    """Requirement 6: GET /api/scans/compare classifies fixed vs unchanged findings after remediation."""
    vuln_server.reset_flags()
    project = _create_local_project(
        api_client,
        vuln_server.base_url,
        name="Compare Regression App",
        target_stack="fastapi",
    )
    selected_checks = ["sqli_error_based", "xss_reflected", "sensitive_files"]

    # Baseline scan_a with /.env exposed
    resp_a = api_client.post(
        f"/api/projects/{project['id']}/scans",
        json={"profile": "standard", "enabled_checks": selected_checks},
    )
    assert resp_a.status_code == 201
    scan_a_id = resp_a.json()["id"]
    _stream_sse_events(api_client, scan_a_id)
    scan_a = _wait_for_terminal_scan(api_client, scan_a_id)
    assert scan_a["status"] == "completed"

    try:
        # Fix the exposed /.env file on the local server while keeping SQLi & XSS vulnerable
        vuln_server.expose_env = False

        resp_b = api_client.post(
            f"/api/projects/{project['id']}/scans",
            json={"profile": "standard", "enabled_checks": selected_checks},
        )
        assert resp_b.status_code == 201
        scan_b_id = resp_b.json()["id"]
        _stream_sse_events(api_client, scan_b_id)
        scan_b = _wait_for_terminal_scan(api_client, scan_b_id)
        assert scan_b["status"] == "completed"
    finally:
        vuln_server.reset_flags()

    compare_resp = api_client.get(
        "/api/scans/compare",
        params={"base": scan_a_id, "head": scan_b_id},
    )
    assert compare_resp.status_code == 200, compare_resp.text
    diff = compare_resp.json()
    assert diff["base_scan_id"] == scan_a_id
    assert diff["head_scan_id"] == scan_b_id

    fixed_checks = {item["check_id"] for item in diff["fixed"]}
    unchanged_checks = {item["check_id"] for item in diff["unchanged"]}
    assert "sensitive_files" in fixed_checks
    assert {"sqli_error_based", "xss_reflected"}.issubset(unchanged_checks)
    assert diff["counts"]["fixed"] == len(diff["fixed"]) >= 1
    assert diff["counts"]["unchanged"] == len(diff["unchanged"]) >= 2
    assert diff["counts"]["new"] == len(diff["new"]) == 0


def test_scan_cancellation(
    api_client: TestClient,
    vuln_server: _VulnerableTestServer,
) -> None:
    """Requirement 7: POST /api/scans/{scan_id}/cancel stops an active scan cleanly."""
    vuln_server.reset_flags()
    vuln_server.request_delay = 0.15
    try:
        project = _create_local_project(
            api_client,
            vuln_server.base_url,
            name="Cancellation Target",
            target_stack="fastapi",
        )
        start_resp = api_client.post(
            f"/api/projects/{project['id']}/scans",
            json={"profile": "deep"},
        )
        assert start_resp.status_code == 201
        scan_id = start_resp.json()["id"]

        # Wait briefly until the worker transitions from queued into crawling/scanning
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            cur = api_client.get(f"/api/scans/{scan_id}").json()
            if cur["status"] in {"crawling", "scanning"}:
                break
            time.sleep(0.05)

        cancel_resp = api_client.post(f"/api/scans/{scan_id}/cancel")
        assert cancel_resp.status_code == 200
        assert cancel_resp.json()["id"] == scan_id

        final_scan = _wait_for_terminal_scan(api_client, scan_id, timeout_s=10.0)
        assert final_scan["status"] == "cancelled"
    finally:
        vuln_server.reset_flags()


def test_report_export_json_and_autoescaped_html(
    primary_scan_bundle: dict[str, Any],
) -> None:
    """Requirement 8: JSON report bundle & standalone autoescaped HTML report export."""
    client: TestClient = primary_scan_bundle["client"]
    project: dict[str, Any] = primary_scan_bundle["project"]
    completed_scan: dict[str, Any] = primary_scan_bundle["completed_scan"]
    scan_id = completed_scan["id"]

    # 1. JSON Report
    json_resp = client.get(
        f"/api/scans/{scan_id}/report",
        params={"format": "json", "download": "true"},
    )
    assert json_resp.status_code == 200
    assert "application/json" in json_resp.headers.get("content-type", "")
    assert "attachment" in json_resp.headers.get("content-disposition", "")
    report_json = json_resp.json()
    for top_key in ("project", "scan", "endpoints", "findings"):
        assert top_key in report_json
    assert report_json["project"]["id"] == project["id"]
    assert report_json["scan"]["id"] == scan_id
    assert len(report_json["endpoints"]) >= 2
    assert len(report_json["findings"]) >= 3

    # Confirm XSS finding evidence contains the raw '<x9' canary so HTML escaping is genuinely exercised
    xss_finding = next(
        f for f in report_json["findings"] if f["check_id"] == "xss_reflected"
    )
    assert "<x9" in json.dumps(xss_finding["evidence"])

    # 2. Standalone Autoescaped HTML Report
    html_resp = client.get(
        f"/api/scans/{scan_id}/report",
        params={"format": "html"},
    )
    assert html_resp.status_code == 200
    assert "text/html" in html_resp.headers.get("content-type", "")
    html_body = html_resp.text

    # Contains Risk Score, endpoint path, and Before/After code fix sections
    assert "Risk Score" in html_body
    assert str(completed_scan["risk_score"]) in html_body
    assert "/item" in html_body
    assert "/search" in html_body
    assert "Before" in html_body
    assert "After" in html_body

    # Raw XSS canary '<x9' in evidence MUST be HTML-escaped as '&lt;x9' with zero script execution
    assert "&lt;x9" in html_body
    assert "<x9" not in html_body
    assert "<script" not in html_body.lower()


def test_project_deletion_cascade(
    api_client: TestClient,
    vuln_server: _VulnerableTestServer,
) -> None:
    """Requirement 9: DELETE /api/projects/{id} returns 204 and cascades deletion to scans & findings."""
    vuln_server.reset_flags()
    project = _create_local_project(
        api_client,
        vuln_server.base_url,
        name="Cascade Delete App",
        target_stack="fastapi",
    )

    start_resp = api_client.post(
        f"/api/projects/{project['id']}/scans",
        json={
            "profile": "standard",
            "enabled_checks": ["sqli_error_based"],
        },
    )
    assert start_resp.status_code == 201
    scan_id = start_resp.json()["id"]
    _stream_sse_events(api_client, scan_id)

    findings = api_client.get(f"/api/scans/{scan_id}/findings").json()
    assert len(findings) >= 1
    finding_id = findings[0]["id"]

    delete_resp = api_client.delete(f"/api/projects/{project['id']}")
    assert delete_resp.status_code == 204

    # Project, scan, and findings must all return 404 with uniform error envelope
    proj_after = api_client.get(f"/api/projects/{project['id']}")
    assert proj_after.status_code == 404
    assert proj_after.json()["error"]["code"] == "PROJECT_NOT_FOUND"

    scan_after = api_client.get(f"/api/scans/{scan_id}")
    assert scan_after.status_code == 404
    assert scan_after.json()["error"]["code"] == "SCAN_NOT_FOUND"

    finding_after = api_client.get(f"/api/findings/{finding_id}")
    assert finding_after.status_code == 404
    assert finding_after.json()["error"]["code"] == "FINDING_NOT_FOUND"


def test_project_update_and_scan_edit_delete(
    api_client: TestClient,
    vuln_server: _VulnerableTestServer,
) -> None:
    """PATCH /api/projects/{id}, PATCH /api/scans/{id}, and DELETE /api/scans/{id} behave cleanly."""
    vuln_server.reset_flags()
    project = _create_local_project(
        api_client,
        vuln_server.base_url,
        name="Editable Local App",
        target_stack="fastapi",
    )

    # 1. PATCH project name & stack succeeds; public URL is still blocked by ScopeGuardrail
    patch_proj = api_client.patch(
        f"/api/projects/{project['id']}",
        json={"name": "Renamed Local App", "target_stack": "express"},
    )
    assert patch_proj.status_code == 200
    assert patch_proj.json()["name"] == "Renamed Local App"
    assert patch_proj.json()["target_stack"] == "express"

    blocked_patch = api_client.patch(
        f"/api/projects/{project['id']}",
        json={"base_url": "https://example.com"},
    )
    assert blocked_patch.status_code == 403
    assert blocked_patch.json()["error"]["code"] == "TARGET_NOT_ALLOWED"

    # 2. Run a quick scan, then PATCH its profile and crawl settings
    start_resp = api_client.post(
        f"/api/projects/{project['id']}/scans",
        json={
            "profile": "quick",
            "max_depth": 2,
            "max_pages": 25,
            "auth_type": "bearer",
            "auth_value": "super-secret-token",
            "enabled_checks": ["missing_security_headers"],
        },
    )
    assert start_resp.status_code == 201
    scan_id = start_resp.json()["id"]
    _stream_sse_events(api_client, scan_id)

    patch_scan = api_client.patch(
        f"/api/scans/{scan_id}",
        json={"profile": "deep", "max_depth": 4, "max_pages": 150},
    )
    assert patch_scan.status_code == 200
    updated = patch_scan.json()
    assert updated["profile"] == "deep"
    assert updated["config"]["max_depth"] == 4
    assert updated["config"]["max_pages"] == 150
    assert "auth_value" not in updated["config"]

    findings = api_client.get(f"/api/scans/{scan_id}/findings").json()
    assert len(findings) >= 1
    finding_id = findings[0]["id"]

    # 3. DELETE /api/scans/{id} cascades findings/endpoints while keeping the parent project
    del_scan = api_client.delete(f"/api/scans/{scan_id}")
    assert del_scan.status_code == 204

    assert api_client.get(f"/api/scans/{scan_id}").status_code == 404
    assert api_client.get(f"/api/findings/{finding_id}").status_code == 404
    assert api_client.get(f"/api/projects/{project['id']}").status_code == 200

    # Cleanup
    assert api_client.delete(f"/api/projects/{project['id']}").status_code == 204
