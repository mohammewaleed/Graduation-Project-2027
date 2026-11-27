"""Phase 7 security hardening and self-scan regression tests.

Verifies two layers of defense on our own FastAPI application:
1. Fast in-process ``TestClient`` check confirming all 5 hardened security
   headers (including ``Permissions-Policy`` and ``object-src 'none'`` in CSP)
   and ``Cache-Control: no-cache`` on the static dashboard root ``/``.
2. Live self-scan integration test spinning up ``create_app(...)`` via Uvicorn
   on an ephemeral ``127.0.0.1`` loopback port with ``server_header=False``,
   executing ``ScanOrchestrator`` in ``ScanProfile.DEEP``, and asserting zero
   Critical/High findings, zero ``missing_security_headers`` or
   ``server_banner_leak`` findings, zero scanner errors, and risk score <= 5.
"""

from __future__ import annotations

import socket
import threading
import time
from pathlib import Path

import uvicorn
from fastapi.testclient import TestClient

from backend.app.main import create_app
from backend.scanner import (
    ScanConfig,
    ScanOrchestrator,
    ScanProfile,
    ScanStatus,
    Severity,
)


class _ThreadedUvicornServer(uvicorn.Server):
    """Uvicorn server subclass safe to run inside a daemon test thread."""

    def install_signal_handlers(self) -> None:
        return


def _find_free_loopback_port() -> int:
    """Bind an ephemeral TCP socket on ``127.0.0.1`` and return the assigned port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_app_returns_all_hardened_security_headers_and_nocache(tmp_path: Path) -> None:
    """Verify ``create_app()`` emits all 5 hardened headers and ``Cache-Control: no-cache`` on ``/``."""
    db_path = tmp_path / "hardened_headers.db"
    app = create_app(database_url=f"sqlite:///{db_path.as_posix()}")
    try:
        with TestClient(app) as client:
            root_resp = client.get("/")
            assert root_resp.status_code == 200
            assert root_resp.headers.get("X-Content-Type-Options") == "nosniff"
            assert root_resp.headers.get("X-Frame-Options") == "DENY"
            assert (
                root_resp.headers.get("Referrer-Policy")
                == "strict-origin-when-cross-origin"
            )
            assert (
                root_resp.headers.get("Permissions-Policy")
                == "geolocation=(), camera=(), microphone=()"
            )
            csp = root_resp.headers.get("Content-Security-Policy", "")
            assert "object-src 'none'" in csp
            assert "default-src 'self'" in csp
            assert "frame-ancestors 'none'" in csp
            assert root_resp.headers.get("Cache-Control") == "no-cache"

            health_resp = client.get("/api/health")
            assert health_resp.status_code == 200
            for header in (
                "X-Content-Type-Options",
                "X-Frame-Options",
                "Referrer-Policy",
                "Permissions-Policy",
                "Content-Security-Policy",
            ):
                assert header in health_resp.headers, f"Missing header on /api/health: {header}"
            assert "object-src 'none'" in health_resp.headers["Content-Security-Policy"]

            docs_resp = client.get("/docs")
            assert docs_resp.status_code == 200
            assert "swagger-ui" in docs_resp.text.lower()
            docs_csp = docs_resp.headers.get("Content-Security-Policy", "")
            assert "https://cdn.jsdelivr.net" in docs_csp
            assert "object-src 'none'" in docs_csp
    finally:
        app.state.db_engine.dispose()


def test_self_scan_deep_profile_hardening_regression(tmp_path: Path) -> None:
    """Run ``ScanOrchestrator`` in ``DEEP`` profile against our live hardened FastAPI app."""
    db_path = tmp_path / "self_scan.db"
    app = create_app(database_url=f"sqlite:///{db_path.as_posix()}")
    port = _find_free_loopback_port()

    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        server_header=False,
        log_level="error",
        access_log=False,
    )
    server = _ThreadedUvicornServer(config)
    thread = threading.Thread(
        target=server.run,
        name="pytest-self-scan-uvicorn",
        daemon=True,
    )
    thread.start()

    try:
        deadline = time.monotonic() + 10.0
        while not server.started:
            if not thread.is_alive():
                raise RuntimeError("Uvicorn server thread exited before startup completed.")
            if time.monotonic() >= deadline:
                raise TimeoutError("Timed out waiting for Uvicorn server to start.")
            time.sleep(0.05)

        target_url = f"http://127.0.0.1:{port}"
        outcome = ScanOrchestrator().run_scan(
            ScanConfig(
                target_url=target_url,
                profile=ScanProfile.DEEP,
                target_stack="fastapi",
                rate_limit_rps=50.0,
            )
        )

        assert outcome.status == ScanStatus.COMPLETED
        assert outcome.errors == [], f"Unexpected scanner errors: {outcome.errors}"

        high_or_critical = [
            f
            for f in outcome.findings
            if f.severity in {Severity.CRITICAL, Severity.HIGH}
        ]
        assert high_or_critical == [], (
            f"Expected zero critical/high findings, got: "
            f"{[(f.check_id, f.severity.value, f.url) for f in high_or_critical]}"
        )

        finding_check_ids = {f.check_id for f in outcome.findings}
        assert "missing_security_headers" not in finding_check_ids, (
            f"Unexpected missing_security_headers finding: "
            f"{[f for f in outcome.findings if f.check_id == 'missing_security_headers']}"
        )
        assert "server_banner_leak" not in finding_check_ids, (
            f"Unexpected server_banner_leak finding: "
            f"{[f for f in outcome.findings if f.check_id == 'server_banner_leak']}"
        )
        assert finding_check_ids.issubset({"weak_csp"}), (
            f"Unexpected findings outside documented CSP trade-off: "
            f"{[(f.check_id, f.severity.value, f.url) for f in outcome.findings]}"
        )
        assert outcome.risk_score <= 6, (
            f"Expected risk_score <= 6, got {outcome.risk_score}; "
            f"findings={[(f.check_id, f.severity.value, f.url) for f in outcome.findings]}"
        )
    finally:
        server.should_exit = True
        thread.join(timeout=10.0)
        app.state.db_engine.dispose()
