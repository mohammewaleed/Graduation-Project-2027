"""Unit tests for backend.scanner.http_client.ScannerHttpClient."""

from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from backend.scanner.http_client import (
    RequestLimitExceededError,
    ScanCancelledError,
    ScannerHttpClient,
)
from backend.scanner.policy import ScopeGuardrail, ScopeViolationError

_SOFT_404_HTML = (
    "<!doctype html><html><head><title>Page Not Found</title></head>"
    "<body><h1>Oops! That page does not exist.</h1>"
    "<p>The resource you requested could not be located on this server. "
    "Please return to the home page or check the URL spelling.</p></body></html>"
)

_UNIQUE_PAGE_HTML = (
    "<!doctype html><html><head><title>User Dashboard</title></head>"
    "<body><h1>Welcome back, Alice</h1>"
    "<ul><li>Order #1001 - Shipped</li><li>Order #1002 - Processing</li></ul>"
    "<form action='/profile' method='post'><input name='bio' value='developer'></form>"
    "</body></html>"
)

_DVWA_CSRF_TOKEN = "csrf_token_abc123xyz"


class _MockTargetHandler(BaseHTTPRequestHandler):
    """Local HTTP fixture server for exercising ScannerHttpClient."""

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return

    def _send(
        self,
        status: int,
        body: str | bytes,
        *,
        content_type: str = "text/html; charset=utf-8",
        headers: dict[str, str] | None = None,
    ) -> None:
        raw = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path

        if path == "/echo-headers":
            payload = {
                "cookie": self.headers.get("Cookie", ""),
                "authorization": self.headers.get("Authorization", ""),
                "x-api-key": self.headers.get("X-Api-Key", ""),
            }
            self._send(200, json.dumps(payload), content_type="application/json")
            return

        if path == "/old":
            self._send(302, "", headers={"Location": "/new"})
            return

        if path == "/new":
            self._send(200, "<h1>Arrived at /new</h1>")
            return

        if path == "/bounce":
            self._send(302, "", headers={"Location": "https://evil.example/steal"})
            return

        if path == "/dashboard":
            self._send(200, _UNIQUE_PAGE_HTML)
            return

        if path == "/login.php":
            html = (
                "<html><body><form method='POST' action='login.php'>"
                "<input type='text' name='username'>"
                "<input type='password' name='password'>"
                f"<input type='hidden' name='user_token' value='{_DVWA_CSRF_TOKEN}'>"
                "<input type='submit' name='Login' value='Login'>"
                "</form></body></html>"
            )
            self._send(
                200,
                html,
                headers={"Set-Cookie": "PHPSESSID=mock_prelogin_sess; Path=/"},
            )
            return

        if path == "/index.php":
            cookie_hdr = self.headers.get("Cookie", "")
            if "PHPSESSID=mock_authed_sess" in cookie_hdr:
                self._send(200, "<html><body>Welcome to DVWA <a href='logout.php'>Logout</a></body></html>")
            else:
                self._send(302, "", headers={"Location": "/login.php"})
            return

        # Everything else returns a custom HTTP 200 Soft-404 page
        self._send(200, _SOFT_404_HTML)

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", errors="replace")

        if path == "/login.php":
            fields = {k: v[0] for k, v in parse_qs(body).items()}
            if (
                fields.get("username") == "admin"
                and fields.get("password") == "password"
                and fields.get("user_token") == _DVWA_CSRF_TOKEN
            ):
                self._send(
                    302,
                    "",
                    headers={
                        "Set-Cookie": "PHPSESSID=mock_authed_sess; Path=/",
                        "Location": "/index.php",
                    },
                )
            else:
                self._send(200, "<html><body>Login failed</body></html>")
            return

        self._send(404, "Not Found")


class TestScannerHttpClient(unittest.TestCase):
    """Integration-style unit tests against an ephemeral local ThreadingHTTPServer."""

    server: ThreadingHTTPServer
    thread: threading.Thread
    base_url: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _MockTargetHandler)
        port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2.0)

    def _make_client(self, **kwargs: object) -> ScannerHttpClient:
        defaults: dict[str, object] = {
            "guardrail": ScopeGuardrail(),
            "rate_limit_rps": 0.0,
            "max_requests": 50,
            "timeout_s": 5.0,
        }
        defaults.update(kwargs)
        return ScannerHttpClient(**defaults)  # type: ignore[arg-type]

    def test_auth_injection_cookie_bearer_and_custom_header(self) -> None:
        with self._make_client(auth_type="cookie", auth_value="session=abc123; security=low") as client:
            resp = client.get(f"{self.base_url}/echo-headers")
            data = resp.json()
            self.assertIn("session=abc123", data["cookie"])
            self.assertIn("security=low", data["cookie"])

        with self._make_client(auth_type="bearer", auth_value="secret-jwt-token") as client:
            resp = client.get(f"{self.base_url}/echo-headers")
            data = resp.json()
            self.assertEqual(data["authorization"], "Bearer secret-jwt-token")

        with self._make_client(auth_type="header", auth_value="X-Api-Key: my-key-999") as client:
            resp = client.get(f"{self.base_url}/echo-headers")
            data = resp.json()
            self.assertEqual(data["x-api-key"], "my-key-999")

    def test_follows_same_origin_relative_redirect(self) -> None:
        with self._make_client() as client:
            resp = client.get(f"{self.base_url}/old")
            self.assertEqual(resp.status_code, 200)
            self.assertIn("Arrived at /new", resp.text)
            self.assertTrue(resp.url.endswith("/new"))
            self.assertEqual(client.requests_sent, 2)

    def test_blocks_cross_origin_redirect_without_contacting_external_host(self) -> None:
        with self._make_client() as client:
            with self.assertRaises(ScopeViolationError):
                client.get(f"{self.base_url}/bounce")
            # Only the initial local /bounce request should have been sent.
            self.assertEqual(client.requests_sent, 1)

    def test_calibrate_soft_404_distinguishes_soft_404_from_unique_page(self) -> None:
        with self._make_client() as client:
            fp = client.calibrate_soft_404(self.base_url)
            self.assertEqual(fp.status_code, 200)

            missing_resp = client.get(f"{self.base_url}/definitely-does-not-exist-xyz")
            self.assertTrue(fp.is_soft_404(missing_resp.status_code, missing_resp.text))

            real_resp = client.get(f"{self.base_url}/dashboard")
            self.assertFalse(fp.is_soft_404(real_resp.status_code, real_resp.text))

    def test_enforces_max_requests_cap(self) -> None:
        with self._make_client(max_requests=2) as client:
            client.get(f"{self.base_url}/new")
            client.get(f"{self.base_url}/new")
            self.assertEqual(client.requests_sent, 2)
            with self.assertRaises(RequestLimitExceededError):
                client.get(f"{self.base_url}/new")

    def test_enforces_cancel_event(self) -> None:
        cancel_event = threading.Event()
        cancel_event.set()
        with self._make_client(cancel_event=cancel_event) as client:
            with self.assertRaises(ScanCancelledError):
                client.get(f"{self.base_url}/new")
            self.assertEqual(client.requests_sent, 0)

    def test_auto_login_dvwa_extracts_csrf_and_sets_cookies(self) -> None:
        with self._make_client() as client:
            ok = client.auto_login_dvwa(self.base_url, username="admin", password="password")
            self.assertTrue(ok)
            self.assertEqual(client.session.cookies.get("PHPSESSID"), "mock_authed_sess")
            self.assertEqual(client.session.cookies.get("security"), "low")

            # Negative case: wrong password returns False
        with self._make_client() as client:
            ok = client.auto_login_dvwa(self.base_url, username="admin", password="wrong")
            self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
