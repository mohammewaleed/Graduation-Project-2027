"""Unit tests for all 9 active and discovery OWASP checks against local HTTP fixtures."""

from __future__ import annotations

import html
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from backend.scanner.checks.active.cors import CORSMisconfigCheck
from backend.scanner.checks.active.idor import IDORHeuristicCheck
from backend.scanner.checks.active.redirect import OpenRedirectCheck
from backend.scanner.checks.active.sqli import (
    SQLiBooleanDiffCheck,
    SQLiErrorBasedCheck,
)
from backend.scanner.checks.active.xss import XSSReflectedCheck
from backend.scanner.checks.base import CheckContext
from backend.scanner.checks.discovery.dir_listing import DirectoryListingCheck
from backend.scanner.checks.discovery.forced_browsing import ForcedBrowsingAdminCheck
from backend.scanner.checks.discovery.sensitive_files import SensitiveFilesCheck
from backend.scanner.crawler import ResponseCache
from backend.scanner.http_client import ScannerHttpClient
from backend.scanner.models import (
    AttackSurface,
    Confidence,
    EndpointRecord,
    OWASPCategory,
    Severity,
)
from backend.scanner.policy import ScopeGuardrail

_LONG_PRODUCT_BODY = (
    "<html><body><h1>Product Catalog Item #1</h1>"
    "<p>Detailed engineering specification for widget alpha-1000. "
    "Includes dimensions, warranty terms, shipping weight, compliance certifications, "
    "and historical pricing analytics across regional warehouses.</p>"
    "<ul><li>SKU: WDG-1000</li><li>Stock: 42 units</li><li>Category: Hardware</li></ul>"
    "</body></html>"
)

_SOFT_404_PAGE = (
    "<!doctype html><html><head><title>App Shell</title></head>"
    "<body><div id='root'>Page not found - SPA catch-all shell response</div></body></html>"
)


class _VulnerableAndSafeHandler(BaseHTTPRequestHandler):
    """Local HTTP server providing both intentionally vulnerable and hardened routes."""

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return

    def _send(
        self,
        status: int,
        body: str,
        *,
        content_type: str = "text/html; charset=utf-8",
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        origin = self.headers.get("Origin", "")

        # --- CORS routes ---
        if path == "/":
            self._send(200, "<html><body>Root</body></html>")
            return

        if path == "/vuln/cors-reflect":
            headers = {}
            if origin:
                headers["Access-Control-Allow-Origin"] = origin
                headers["Access-Control-Allow-Credentials"] = "true"
            self._send(200, '{"ok": true}', content_type="application/json", extra_headers=headers)
            return

        if path == "/vuln/cors-wildcard":
            self._send(
                200,
                '{"ok": true}',
                content_type="application/json",
                extra_headers={"Access-Control-Allow-Origin": "*"},
            )
            return

        if path == "/safe/cors":
            self._send(
                200,
                '{"ok": true}',
                content_type="application/json",
                extra_headers={"Access-Control-Allow-Origin": "https://trusted.local"},
            )
            return

        # --- SQLi Error-Based routes ---
        if path == "/vuln/sqli-err":
            item_id = qs.get("id", ["1"])[0]
            if "'" in item_id or '"' in item_id:
                self._send(
                    500,
                    "<html><body>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near ''' at line 1</body></html>",
                )
                return
            self._send(200, f"<html><body>Item {html.escape(item_id)}</body></html>")
            return

        if path == "/safe/sqli-err":
            item_id = qs.get("id", ["1"])[0]
            self._send(200, f"<html><body>Safe lookup for {html.escape(item_id)}</body></html>")
            return

        if path == "/safe/sqli-baseline-err":
            # False-positive guard: error text is ALREADY in baseline response
            self._send(
                200,
                "<html><body>Docs example: You have an error in your SQL syntax; check the manual</body></html>",
            )
            return

        # --- SQLi Boolean Differential routes ---
        if path == "/vuln/sqli-bool":
            val = qs.get("id", ["1"])[0]
            if "1'='2" in val or "1=2" in val:
                self._send(200, "<html><body>None</body></html>")
                return
            if val == "1" or "1'='1" in val or "1=1" in val:
                self._send(200, _LONG_PRODUCT_BODY)
                return
            self._send(200, "<html><body>None</body></html>")
            return

        if path == "/safe/sqli-bool":
            # Parameterized lookup: only exact "1" returns product; ALL SQL expressions return same "invalid" body
            val = qs.get("id", ["1"])[0]
            if val == "1":
                self._send(200, _LONG_PRODUCT_BODY)
            else:
                self._send(200, "<html><body>Invalid ID</body></html>")
            return

        # --- Reflected XSS routes ---
        if path == "/vuln/xss-body":
            q = qs.get("q", [""])[0]
            self._send(200, f"<html><body><p>Search results for {q}</p></body></html>")
            return

        if path == "/vuln/xss-attr":
            q = qs.get("q", [""])[0]
            self._send(200, f'<html><body><input type="text" value="{q}"></body></html>')
            return

        if path == "/safe/xss-escaped":
            q = qs.get("q", [""])[0]
            self._send(200, f"<html><body><p>Search results for {html.escape(q, quote=True)}</p></body></html>")
            return

        if path == "/safe/xss-json":
            q = qs.get("q", [""])[0]
            self._send(200, json.dumps({"query": q}), content_type="application/json")
            return

        # --- Open Redirect routes ---
        if path == "/vuln/redirect":
            dest = qs.get("next", ["/"])[0]
            self.send_response(302)
            self.send_header("Location", dest)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if path == "/safe/redirect":
            dest = qs.get("next", ["/home"])[0]
            safe_dest = dest if dest.startswith("/") and not dest.startswith("//") else "/home"
            self.send_response(302)
            self.send_header("Location", safe_dest)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        # --- IDOR Heuristic routes ---
        if path == "/vuln/profile":
            uid = qs.get("user_id", ["1"])[0]
            profiles = {
                "1": "<html><body><h1>Alice Profile</h1><p>Email: alice@lab.local</p></body></html>",
                "2": "<html><body><h1>Bob Profile</h1><p>Email: bob@lab.local</p></body></html>",
            }
            if uid in profiles:
                self._send(200, profiles[uid])
                return
            self._send(404, "Not found")
            return

        if path.startswith("/vuln/orders/"):
            order_id = path.rsplit("/", 1)[-1]
            orders = {
                "42": '{"order_id": 42, "owner": "alice", "total": 120.00}',
                "43": '{"order_id": 43, "owner": "bob", "total": 540.00}',
            }
            if order_id in orders:
                self._send(200, orders[order_id], content_type="application/json")
                return
            self._send(404, "Not found")
            return

        if path == "/safe/profile":
            uid = qs.get("user_id", ["1"])[0]
            if uid == "1":
                self._send(200, "<html><body><h1>Alice Profile</h1></body></html>")
            else:
                self._send(403, "<html><body>Forbidden</body></html>")
            return

        if path.startswith("/safe/orders/"):
            order_id = path.rsplit("/", 1)[-1]
            if order_id == "42":
                self._send(200, '{"order_id": 42, "owner": "alice"}', content_type="application/json")
            else:
                self._send(403, '{"error": "forbidden"}', content_type="application/json")
            return

        # --- Discovery vulnerable routes ---
        if path == "/.env":
            self._send(
                200,
                "APP_ENV=development\nDB_PASSWORD=dev_secret\n",
                content_type="text/plain; charset=utf-8",
            )
            return

        if path == "/.git/HEAD":
            self._send(200, "ref: refs/heads/main\n", content_type="text/plain; charset=utf-8")
            return

        if path == "/uploads/":
            self._send(
                200,
                "<html><head><title>Index of /uploads/</title></head><body><h1>Index of /uploads/</h1></body></html>",
            )
            return

        if path == "/admin":
            self._send(
                200,
                "<html><body><h1>Admin Panel</h1><p>User Management & System Settings</p></body></html>",
            )
            return

        if path == "/api/users":
            self._send(
                200,
                json.dumps([{"id": 1, "username": "admin", "role": "admin"}]),
                content_type="application/json",
            )
            return

        self._send(404, "<html><body>404 Not Found</body></html>")


class _Soft404AndHardenedHandler(BaseHTTPRequestHandler):
    """Hardened SPA server returning Soft-404 HTTP 200 on unknown paths and login gate on /dashboard."""

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return

    def _send(
        self,
        status: int,
        body: str,
        *,
        content_type: str = "text/html; charset=utf-8",
    ) -> None:
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path

        if path == "/":
            self._send(200, "<html><body><h1>Clean App</h1></body></html>")
            return

        if path == "/dashboard":
            # Protected admin path rendering a login form -> must NOT be flagged!
            self._send(
                200,
                '<html><head><title>Login</title></head><body><h1>Please log in</h1>'
                '<form method="POST"><input type="text" name="user">'
                '<input type="password" name="pass"></form></body></html>',
            )
            return

        if path == "/api/users":
            self._send(401, '{"error": "authentication required"}', content_type="application/json")
            return

        # Every unknown path (including /.env, /.git/HEAD, /uploads/, /admin) returns Soft-404 HTTP 200
        self._send(200, _SOFT_404_PAGE)


class TestActiveAndDiscoveryChecks(unittest.TestCase):
    """Positive and false-positive guard tests for all 9 active and discovery checks."""

    vuln_server: ThreadingHTTPServer
    vuln_thread: threading.Thread
    vuln_base: str

    safe_server: ThreadingHTTPServer
    safe_thread: threading.Thread
    safe_base: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.vuln_server = ThreadingHTTPServer(("127.0.0.1", 0), _VulnerableAndSafeHandler)
        cls.vuln_base = f"http://127.0.0.1:{cls.vuln_server.server_address[1]}"
        cls.vuln_thread = threading.Thread(target=cls.vuln_server.serve_forever, daemon=True)
        cls.vuln_thread.start()

        cls.safe_server = ThreadingHTTPServer(("127.0.0.1", 0), _Soft404AndHardenedHandler)
        cls.safe_base = f"http://127.0.0.1:{cls.safe_server.server_address[1]}"
        cls.safe_thread = threading.Thread(target=cls.safe_server.serve_forever, daemon=True)
        cls.safe_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        for srv, thread in (
            (cls.vuln_server, cls.vuln_thread),
            (cls.safe_server, cls.safe_thread),
        ):
            srv.shutdown()
            srv.server_close()
            thread.join(timeout=3.0)

    def _build_ctx(
        self,
        base_url: str,
        *,
        endpoints: list[EndpointRecord] | None = None,
        calibrate_soft_404: bool = False,
    ) -> tuple[CheckContext, ScannerHttpClient]:
        guardrail = ScopeGuardrail()
        client = ScannerHttpClient(
            guardrail=guardrail,
            rate_limit_rps=500.0,
            timeout_s=5.0,
        )
        soft_404 = client.calibrate_soft_404(base_url) if calibrate_soft_404 else None
        surface = AttackSurface(
            base_url=base_url,
            endpoints=list(endpoints or []),
        )
        ctx = CheckContext(
            target_url=base_url,
            http_client=client,
            guardrail=guardrail,
            surface=surface,
            responses=ResponseCache(),
            soft_404=soft_404,
        )
        return ctx, client

    # ------------------------------------------------------------------
    # 1. cors_misconfig
    # ------------------------------------------------------------------
    def test_cors_misconfig_positive_reflected_credentials_and_wildcard(self) -> None:
        ctx, client = self._build_ctx(
            self.vuln_base,
            endpoints=[
                EndpointRecord(url=f"{self.vuln_base}/vuln/cors-reflect"),
                EndpointRecord(url=f"{self.vuln_base}/vuln/cors-wildcard"),
            ],
        )
        try:
            findings = CORSMisconfigCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(len(findings), 2)
        by_url = {f.url: f for f in findings}
        reflect_f = by_url[f"{self.vuln_base}/vuln/cors-reflect"]
        self.assertEqual(reflect_f.check_id, "cors_misconfig")
        self.assertEqual(reflect_f.owasp_category, OWASPCategory.A05)
        self.assertEqual(reflect_f.cwe_id, "CWE-942")
        self.assertEqual(reflect_f.severity, Severity.HIGH)

        wildcard_f = by_url[f"{self.vuln_base}/vuln/cors-wildcard"]
        self.assertEqual(wildcard_f.severity, Severity.LOW)

    def test_cors_misconfig_negative_strict_origin_emits_zero_findings(self) -> None:
        ctx, client = self._build_ctx(
            self.vuln_base,
            endpoints=[EndpointRecord(url=f"{self.vuln_base}/safe/cors")],
        )
        try:
            findings = CORSMisconfigCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(findings, [])

    # ------------------------------------------------------------------
    # 2. sqli_error_based
    # ------------------------------------------------------------------
    def test_sqli_error_based_positive_mysql_syntax_error(self) -> None:
        ctx, client = self._build_ctx(
            self.vuln_base,
            endpoints=[EndpointRecord(url=f"{self.vuln_base}/vuln/sqli-err?id=1", params=["id"])],
        )
        try:
            findings = SQLiErrorBasedCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.check_id, "sqli_error_based")
        self.assertEqual(f.owasp_category, OWASPCategory.A03)
        self.assertEqual(f.cwe_id, "CWE-89")
        self.assertEqual(f.severity, Severity.CRITICAL)
        self.assertEqual(f.parameter, "id")
        self.assertIn("/vuln/sqli-err", f.url)

    def test_sqli_error_based_negative_clean_and_baseline_error_fp_guard(self) -> None:
        ctx, client = self._build_ctx(
            self.vuln_base,
            endpoints=[
                EndpointRecord(url=f"{self.vuln_base}/safe/sqli-err?id=1", params=["id"]),
                EndpointRecord(url=f"{self.vuln_base}/safe/sqli-baseline-err?id=1", params=["id"]),
            ],
        )
        try:
            findings = SQLiErrorBasedCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(findings, [])

    # ------------------------------------------------------------------
    # 3. sqli_boolean_diff
    # ------------------------------------------------------------------
    def test_sqli_boolean_diff_positive_true_vs_false_divergence(self) -> None:
        ctx, client = self._build_ctx(
            self.vuln_base,
            endpoints=[EndpointRecord(url=f"{self.vuln_base}/vuln/sqli-bool?id=1", params=["id"])],
        )
        try:
            findings = SQLiBooleanDiffCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.check_id, "sqli_boolean_diff")
        self.assertEqual(f.owasp_category, OWASPCategory.A03)
        self.assertEqual(f.cwe_id, "CWE-89")
        self.assertEqual(f.confidence, Confidence.MEDIUM)
        self.assertEqual(f.parameter, "id")
        self.assertIn("/vuln/sqli-bool", f.url)

    def test_sqli_boolean_diff_negative_parameterized_route_emits_zero_findings(self) -> None:
        ctx, client = self._build_ctx(
            self.vuln_base,
            endpoints=[EndpointRecord(url=f"{self.vuln_base}/safe/sqli-bool?id=1", params=["id"])],
        )
        try:
            findings = SQLiBooleanDiffCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(findings, [])

    # ------------------------------------------------------------------
    # 4. xss_reflected
    # ------------------------------------------------------------------
    def test_xss_reflected_positive_body_and_attribute_contexts(self) -> None:
        ctx, client = self._build_ctx(
            self.vuln_base,
            endpoints=[
                EndpointRecord(url=f"{self.vuln_base}/vuln/xss-body?q=hello", params=["q"]),
                EndpointRecord(url=f"{self.vuln_base}/vuln/xss-attr?q=hello", params=["q"]),
            ],
        )
        try:
            findings = XSSReflectedCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(len(findings), 2)
        contexts = {f.evidence["context"] for f in findings}
        self.assertEqual(contexts, {"html_body", "html_attribute"})
        for f in findings:
            self.assertEqual(f.check_id, "xss_reflected")
            self.assertEqual(f.owasp_category, OWASPCategory.A03)
            self.assertEqual(f.cwe_id, "CWE-79")
            self.assertEqual(f.parameter, "q")

    def test_xss_reflected_negative_escaped_html_and_json_fp_guards(self) -> None:
        ctx, client = self._build_ctx(
            self.vuln_base,
            endpoints=[
                EndpointRecord(url=f"{self.vuln_base}/safe/xss-escaped?q=hello", params=["q"]),
                EndpointRecord(url=f"{self.vuln_base}/safe/xss-json?q=hello", params=["q"]),
            ],
        )
        try:
            findings = XSSReflectedCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(findings, [])

    # ------------------------------------------------------------------
    # 5. open_redirect
    # ------------------------------------------------------------------
    def test_open_redirect_positive_external_location_header(self) -> None:
        ctx, client = self._build_ctx(
            self.vuln_base,
            endpoints=[EndpointRecord(url=f"{self.vuln_base}/vuln/redirect?next=/home", params=["next"])],
        )
        try:
            findings = OpenRedirectCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.check_id, "open_redirect")
        self.assertEqual(f.owasp_category, OWASPCategory.A01)
        self.assertEqual(f.cwe_id, "CWE-601")
        self.assertEqual(f.parameter, "next")
        self.assertEqual(f.url, f"{self.vuln_base}/vuln/redirect")

    def test_open_redirect_negative_safe_relative_redirect(self) -> None:
        ctx, client = self._build_ctx(
            self.vuln_base,
            endpoints=[EndpointRecord(url=f"{self.vuln_base}/safe/redirect?next=/home", params=["next"])],
        )
        try:
            findings = OpenRedirectCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(findings, [])

    # ------------------------------------------------------------------
    # 6. idor_heuristic
    # ------------------------------------------------------------------
    def test_idor_heuristic_positive_query_and_path_tagged_low_confidence(self) -> None:
        ctx, client = self._build_ctx(
            self.vuln_base,
            endpoints=[
                EndpointRecord(url=f"{self.vuln_base}/vuln/profile?user_id=1", params=["user_id"]),
                EndpointRecord(url=f"{self.vuln_base}/vuln/orders/42"),
            ],
            calibrate_soft_404=True,
        )
        try:
            findings = IDORHeuristicCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(len(findings), 2)
        params = {f.parameter for f in findings}
        self.assertEqual(params, {"user_id", "orders_id"})
        for f in findings:
            self.assertEqual(f.check_id, "idor_heuristic")
            self.assertEqual(f.owasp_category, OWASPCategory.A01)
            self.assertEqual(f.cwe_id, "CWE-639")
            # Crucial invariant: IDOR heuristic must ALWAYS be tagged Confidence.LOW
            self.assertEqual(f.confidence, Confidence.LOW)

    def test_idor_heuristic_negative_forbidden_adjacent_ids(self) -> None:
        ctx, client = self._build_ctx(
            self.vuln_base,
            endpoints=[
                EndpointRecord(url=f"{self.vuln_base}/safe/profile?user_id=1", params=["user_id"]),
                EndpointRecord(url=f"{self.vuln_base}/safe/orders/42"),
            ],
            calibrate_soft_404=True,
        )
        try:
            findings = IDORHeuristicCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(findings, [])

    # ------------------------------------------------------------------
    # 7. sensitive_files
    # ------------------------------------------------------------------
    def test_sensitive_files_positive_dotenv_and_git_head(self) -> None:
        ctx, client = self._build_ctx(self.vuln_base, calibrate_soft_404=True)
        try:
            findings = SensitiveFilesCheck().run(ctx)
        finally:
            client.close()

        found_paths = {f.parameter for f in findings}
        self.assertEqual(found_paths, {"/.env", "/.git/HEAD"})
        for f in findings:
            self.assertEqual(f.check_id, "sensitive_files")
            self.assertEqual(f.owasp_category, OWASPCategory.A05)
            self.assertEqual(f.cwe_id, "CWE-538")

    def test_sensitive_files_negative_soft_404_guard(self) -> None:
        ctx, client = self._build_ctx(self.safe_base, calibrate_soft_404=True)
        try:
            findings = SensitiveFilesCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(findings, [])

    # ------------------------------------------------------------------
    # 8. directory_listing
    # ------------------------------------------------------------------
    def test_directory_listing_positive_uploads_index_of(self) -> None:
        ctx, client = self._build_ctx(self.vuln_base, calibrate_soft_404=True)
        try:
            findings = DirectoryListingCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.check_id, "directory_listing")
        self.assertEqual(f.owasp_category, OWASPCategory.A05)
        self.assertEqual(f.cwe_id, "CWE-548")
        self.assertEqual(f.parameter, "/uploads/")
        self.assertEqual(f.url, f"{self.vuln_base}/uploads/")

    def test_directory_listing_negative_soft_404_guard(self) -> None:
        ctx, client = self._build_ctx(self.safe_base, calibrate_soft_404=True)
        try:
            findings = DirectoryListingCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(findings, [])

    # ------------------------------------------------------------------
    # 9. forced_browsing_admin
    # ------------------------------------------------------------------
    def test_forced_browsing_admin_positive_admin_and_api_users(self) -> None:
        ctx, client = self._build_ctx(self.vuln_base, calibrate_soft_404=True)
        try:
            findings = ForcedBrowsingAdminCheck().run(ctx)
        finally:
            client.close()

        found_paths = {f.parameter for f in findings}
        self.assertEqual(found_paths, {"/admin", "/api/users"})
        for f in findings:
            self.assertEqual(f.check_id, "forced_browsing_admin")
            self.assertEqual(f.owasp_category, OWASPCategory.A01)
            self.assertEqual(f.cwe_id, "CWE-425")

    def test_forced_browsing_admin_negative_soft_404_and_login_page_guard(self) -> None:
        ctx, client = self._build_ctx(self.safe_base, calibrate_soft_404=True)
        try:
            findings = ForcedBrowsingAdminCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
