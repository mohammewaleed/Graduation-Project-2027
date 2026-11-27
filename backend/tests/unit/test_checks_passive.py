"""Unit tests for all 8 passive OWASP security checks in backend.scanner.checks.passive."""

from __future__ import annotations

import threading
import unittest

from backend.scanner.checks.base import CheckContext
from backend.scanner.checks.passive.banners import ServerBannerLeakCheck
from backend.scanner.checks.passive.components import OutdatedJSComponentsCheck
from backend.scanner.checks.passive.cookies import InsecureCookiesCheck
from backend.scanner.checks.passive.csrf import CSRFMissingTokenCheck
from backend.scanner.checks.passive.errors import VerboseErrorPagesCheck
from backend.scanner.checks.passive.headers import (
    MissingSecurityHeadersCheck,
    WeakCSPCheck,
)
from backend.scanner.checks.passive.transport import InsecureTransportCheck
from backend.scanner.crawler import ResponseCache
from backend.scanner.http_client import ScannerHttpClient
from backend.scanner.models import (
    AttackSurface,
    CachedResponse,
    FormInput,
    FormRecord,
    OWASPCategory,
    Severity,
)
from backend.scanner.policy import ScopeGuardrail


def _make_context(
    target_url: str = "http://127.0.0.1:8080/",
    *,
    responses: list[CachedResponse] | None = None,
    forms: list[FormRecord] | None = None,
    scripts: list[str] | None = None,
    cancelled: bool = False,
) -> tuple[CheckContext, ScannerHttpClient]:
    """Build an isolated CheckContext backed by cached responses (zero network I/O)."""
    guardrail = ScopeGuardrail()
    http_client = ScannerHttpClient(guardrail=guardrail)
    cache = ResponseCache()
    for resp in responses or []:
        cache.add(resp)

    surface = AttackSurface(
        base_url=target_url,
        forms=list(forms or []),
        scripts=list(scripts or []),
    )
    cancel_event = threading.Event()
    if cancelled:
        cancel_event.set()

    ctx = CheckContext(
        target_url=target_url,
        http_client=http_client,
        guardrail=guardrail,
        surface=surface,
        responses=cache,
        cancel_event=cancel_event,
    )
    return ctx, http_client


class TestMissingSecurityHeadersCheck(unittest.TestCase):
    """Tests for MissingSecurityHeadersCheck (missing_security_headers)."""

    def test_positive_missing_all_baseline_headers(self) -> None:
        resp = CachedResponse(
            url="http://127.0.0.1:8080/",
            status_code=200,
            headers={"Content-Type": "text/html; charset=utf-8"},
            body="<html><body>Hello</body></html>",
            content_type="text/html; charset=utf-8",
        )
        ctx, client = _make_context(responses=[resp])
        try:
            findings = MissingSecurityHeadersCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.check_id, "missing_security_headers")
        self.assertEqual(finding.owasp_category, OWASPCategory.A05)
        self.assertEqual(finding.cwe_id, "CWE-693")
        self.assertEqual(finding.severity, Severity.MEDIUM)
        for header in (
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ):
            self.assertIn(header, finding.evidence["missing_headers"])

    def test_negative_hardened_headers_emit_zero_findings(self) -> None:
        resp = CachedResponse(
            url="http://127.0.0.1:8080/",
            status_code=200,
            headers={
                "Content-Type": "text/html",
                "Content-Security-Policy": "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "geolocation=(), camera=()",
            },
            body="<html><body>Hardened</body></html>",
            content_type="text/html",
        )
        ctx, client = _make_context(responses=[resp])
        try:
            findings = MissingSecurityHeadersCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(findings, [])

    def test_negative_csp_frame_ancestors_satisfies_clickjacking_defense(self) -> None:
        resp = CachedResponse(
            url="http://127.0.0.1:8080/",
            status_code=200,
            headers={
                "Content-Type": "text/html",
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "microphone=()",
            },
            body="<html><body>OK</body></html>",
            content_type="text/html",
        )
        ctx, client = _make_context(responses=[resp])
        try:
            findings = MissingSecurityHeadersCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(findings, [])


class TestWeakCSPCheck(unittest.TestCase):
    """Tests for WeakCSPCheck (weak_csp)."""

    def test_positive_unsafe_inline_eval_and_wildcard(self) -> None:
        resp = CachedResponse(
            url="http://127.0.0.1:8080/",
            status_code=200,
            headers={
                "Content-Type": "text/html",
                "Content-Security-Policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval'; script-src *",
            },
            body="<html><body>Weak CSP</body></html>",
            content_type="text/html",
        )
        ctx, client = _make_context(responses=[resp])
        try:
            findings = WeakCSPCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.check_id, "weak_csp")
        self.assertEqual(finding.owasp_category, OWASPCategory.A05)
        self.assertEqual(finding.cwe_id, "CWE-693")
        self.assertIn("unsafe-inline", finding.evidence["issues"])
        self.assertIn("unsafe-eval", finding.evidence["issues"])
        self.assertIn("Wildcard", finding.evidence["issues"])

    def test_positive_missing_default_and_object_src(self) -> None:
        resp = CachedResponse(
            url="http://127.0.0.1:8080/",
            status_code=200,
            headers={
                "Content-Type": "text/html",
                "Content-Security-Policy": "img-src 'self'",
            },
            body="<html><body>Incomplete CSP</body></html>",
            content_type="text/html",
        )
        ctx, client = _make_context(responses=[resp])
        try:
            findings = WeakCSPCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(len(findings), 1)
        self.assertIn("default-src", findings[0].evidence["issues"])

    def test_negative_strong_csp_emits_zero_findings(self) -> None:
        resp = CachedResponse(
            url="http://127.0.0.1:8080/",
            status_code=200,
            headers={
                "Content-Type": "text/html",
                "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
            },
            body="<html><body>Strong CSP</body></html>",
            content_type="text/html",
        )
        ctx, client = _make_context(responses=[resp])
        try:
            findings = WeakCSPCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(findings, [])


class TestServerBannerLeakCheck(unittest.TestCase):
    """Tests for ServerBannerLeakCheck (server_banner_leak)."""

    def test_positive_versioned_server_and_powered_by_headers(self) -> None:
        resp = CachedResponse(
            url="http://127.0.0.1:8080/",
            status_code=200,
            headers={
                "Server": "Apache/2.4.57 (Debian)",
                "X-Powered-By": "PHP/8.1.12",
            },
            body="<html></html>",
            content_type="text/html",
        )
        ctx, client = _make_context(responses=[resp])
        try:
            findings = ServerBannerLeakCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(len(findings), 2)
        params = {f.parameter for f in findings}
        self.assertEqual(params, {"Server", "X-Powered-By"})
        for finding in findings:
            self.assertEqual(finding.check_id, "server_banner_leak")
            self.assertEqual(finding.owasp_category, OWASPCategory.A05)
            self.assertEqual(finding.cwe_id, "CWE-200")
            self.assertEqual(finding.severity, Severity.LOW)

    def test_negative_clean_banner_without_version_emits_zero_findings(self) -> None:
        resp = CachedResponse(
            url="http://127.0.0.1:8080/",
            status_code=200,
            headers={"Server": "nginx"},
            body="<html></html>",
            content_type="text/html",
        )
        ctx, client = _make_context(responses=[resp])
        try:
            findings = ServerBannerLeakCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(findings, [])


class TestVerboseErrorPagesCheck(unittest.TestCase):
    """Tests for VerboseErrorPagesCheck (verbose_error_pages)."""

    def test_positive_python_traceback_and_php_fatal_error(self) -> None:
        py_resp = CachedResponse(
            url="http://127.0.0.1:8080/crash-py",
            status_code=500,
            headers={"Content-Type": "text/html"},
            body=(
                "<html><body><pre>Traceback (most recent call last):\n"
                '  File "/app/views.py", line 42, in index\n'
                "ZeroDivisionError: division by zero</pre></body></html>"
            ),
            content_type="text/html",
        )
        php_resp = CachedResponse(
            url="http://127.0.0.1:8080/crash-php",
            status_code=500,
            headers={"Content-Type": "text/html"},
            body="<b>Fatal error</b>: Uncaught Error: Call to undefined function foo() in /var/www/index.php on line 10",
            content_type="text/html",
        )
        ctx, client = _make_context(responses=[py_resp, php_resp])
        try:
            findings = VerboseErrorPagesCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(len(findings), 2)
        for finding in findings:
            self.assertEqual(finding.check_id, "verbose_error_pages")
            self.assertEqual(finding.owasp_category, OWASPCategory.A05)
            self.assertEqual(finding.cwe_id, "CWE-209")
            self.assertIn("snippet", finding.evidence)

    def test_negative_clean_generic_error_page_emits_zero_findings(self) -> None:
        resp = CachedResponse(
            url="http://127.0.0.1:8080/error",
            status_code=500,
            headers={"Content-Type": "text/html"},
            body="<html><body><h1>500 Internal Server Error</h1><p>Something went wrong. Please retry later.</p></body></html>",
            content_type="text/html",
        )
        ctx, client = _make_context(responses=[resp])
        try:
            findings = VerboseErrorPagesCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(findings, [])


class TestInsecureCookiesCheck(unittest.TestCase):
    """Tests for InsecureCookiesCheck (insecure_cookies)."""

    def test_positive_session_cookie_missing_flags_on_https(self) -> None:
        resp = CachedResponse(
            url="https://127.0.0.1:8443/login",
            status_code=200,
            headers={
                "Content-Type": "text/html",
                "Set-Cookie": "PHPSESSID=supersecretvalue123; Path=/",
            },
            body="<html>Logged in</html>",
            content_type="text/html",
        )
        ctx, client = _make_context(
            target_url="https://127.0.0.1:8443/",
            responses=[resp],
        )
        try:
            findings = InsecureCookiesCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.check_id, "insecure_cookies")
        self.assertEqual(finding.owasp_category, OWASPCategory.A07)
        self.assertEqual(finding.cwe_id, "CWE-614")
        self.assertEqual(finding.parameter, "PHPSESSID")
        self.assertIn("HttpOnly", finding.evidence["missing_flags"])
        self.assertIn("SameSite", finding.evidence["missing_flags"])
        self.assertIn("Secure", finding.evidence["missing_flags"])
        # Raw cookie secret must be redacted in evidence
        self.assertNotIn("supersecretvalue123", finding.evidence["set_cookie"])

    def test_negative_hardened_session_cookie_and_non_session_cookie(self) -> None:
        resp = CachedResponse(
            url="https://127.0.0.1:8443/login",
            status_code=200,
            headers={
                "Content-Type": "text/html",
                "Set-Cookie": (
                    "session_id=tok123; Path=/; HttpOnly; Secure; SameSite=Lax, "
                    "theme=dark; Path=/"
                ),
            },
            body="<html>OK</html>",
            content_type="text/html",
        )
        ctx, client = _make_context(
            target_url="https://127.0.0.1:8443/",
            responses=[resp],
        )
        try:
            findings = InsecureCookiesCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(findings, [])


class TestInsecureTransportCheck(unittest.TestCase):
    """Tests for InsecureTransportCheck (insecure_transport)."""

    def test_positive_password_form_over_http(self) -> None:
        login_form = FormRecord(
            action_url="http://127.0.0.1:8080/login",
            method="POST",
            inputs=[
                FormInput(name="username", input_type="text"),
                FormInput(name="password", input_type="password"),
            ],
            source_url="http://127.0.0.1:8080/login",
        )
        ctx, client = _make_context(
            target_url="http://127.0.0.1:8080/",
            forms=[login_form],
        )
        try:
            findings = InsecureTransportCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.check_id, "insecure_transport")
        self.assertEqual(finding.owasp_category, OWASPCategory.A02)
        self.assertEqual(finding.cwe_id, "CWE-319")
        self.assertEqual(finding.parameter, "password")
        self.assertEqual(finding.evidence["issue"], "password_over_http")

    def test_positive_https_origin_missing_hsts(self) -> None:
        resp = CachedResponse(
            url="https://127.0.0.1:8443/",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body="<html>No HSTS</html>",
            content_type="text/html",
        )
        ctx, client = _make_context(
            target_url="https://127.0.0.1:8443/",
            responses=[resp],
        )
        try:
            findings = InsecureTransportCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].check_id, "insecure_transport")
        self.assertEqual(findings[0].evidence["issue"], "missing_hsts")

    def test_negative_https_with_hsts_and_https_password_form(self) -> None:
        resp = CachedResponse(
            url="https://127.0.0.1:8443/login",
            status_code=200,
            headers={
                "Content-Type": "text/html",
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            },
            body="<html>Secure Login</html>",
            content_type="text/html",
        )
        login_form = FormRecord(
            action_url="https://127.0.0.1:8443/login",
            method="POST",
            inputs=[
                FormInput(name="username", input_type="text"),
                FormInput(name="password", input_type="password"),
            ],
            source_url="https://127.0.0.1:8443/login",
        )
        ctx, client = _make_context(
            target_url="https://127.0.0.1:8443/",
            responses=[resp],
            forms=[login_form],
        )
        try:
            findings = InsecureTransportCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(findings, [])


class TestCSRFMissingTokenCheck(unittest.TestCase):
    """Tests for CSRFMissingTokenCheck (csrf_missing_token)."""

    def test_positive_post_form_without_csrf_token(self) -> None:
        form = FormRecord(
            action_url="http://127.0.0.1:8080/profile/update",
            method="POST",
            inputs=[
                FormInput(name="display_name", input_type="text"),
                FormInput(name="email", input_type="email"),
            ],
            source_url="http://127.0.0.1:8080/profile",
        )
        ctx, client = _make_context(forms=[form])
        try:
            findings = CSRFMissingTokenCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.check_id, "csrf_missing_token")
        self.assertEqual(finding.owasp_category, OWASPCategory.A01)
        self.assertEqual(finding.cwe_id, "CWE-352")
        self.assertEqual(finding.method, "POST")
        self.assertEqual(finding.url, "http://127.0.0.1:8080/profile/update")

    def test_negative_post_form_with_csrf_token_emits_zero_findings(self) -> None:
        form = FormRecord(
            action_url="http://127.0.0.1:8080/profile/update",
            method="POST",
            inputs=[
                FormInput(name="display_name", input_type="text"),
                FormInput(name="csrf_token", input_type="hidden", value="random-nonce"),
            ],
            source_url="http://127.0.0.1:8080/profile",
        )
        get_form = FormRecord(
            action_url="http://127.0.0.1:8080/search",
            method="GET",
            inputs=[FormInput(name="q", input_type="text")],
            source_url="http://127.0.0.1:8080/",
        )
        ctx, client = _make_context(forms=[form, get_form])
        try:
            findings = CSRFMissingTokenCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(findings, [])

    def test_negative_samesite_strict_session_cookie_suppresses_csrf_finding(self) -> None:
        resp = CachedResponse(
            url="http://127.0.0.1:8080/",
            status_code=200,
            headers={
                "Content-Type": "text/html",
                "Set-Cookie": "session_id=abc; HttpOnly; SameSite=Strict",
            },
            body="<html></html>",
            content_type="text/html",
        )
        form = FormRecord(
            action_url="http://127.0.0.1:8080/settings",
            method="POST",
            inputs=[FormInput(name="bio", input_type="text")],
            source_url="http://127.0.0.1:8080/settings",
        )
        ctx, client = _make_context(responses=[resp], forms=[form])
        try:
            findings = CSRFMissingTokenCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(findings, [])


class TestOutdatedJSComponentsCheck(unittest.TestCase):
    """Tests for OutdatedJSComponentsCheck (outdated_js_components)."""

    def test_positive_outdated_jquery_and_lodash(self) -> None:
        ctx, client = _make_context(
            scripts=[
                "http://127.0.0.1:8080/static/jquery-3.4.1.min.js",
                "http://127.0.0.1:8080/ajax/libs/lodash.js/4.17.15/lodash.min.js",
            ]
        )
        try:
            findings = OutdatedJSComponentsCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(len(findings), 2)
        libs = {f.parameter for f in findings}
        self.assertEqual(libs, {"jquery", "lodash"})
        for finding in findings:
            self.assertEqual(finding.check_id, "outdated_js_components")
            self.assertEqual(finding.owasp_category, OWASPCategory.A06)
            self.assertEqual(finding.cwe_id, "CWE-1104")

    def test_negative_up_to_date_libraries_emit_zero_findings(self) -> None:
        resp = CachedResponse(
            url="http://127.0.0.1:8080/",
            status_code=200,
            headers={"Content-Type": "text/html"},
            body=(
                '<html><head>'
                '<script src="/static/jquery-3.7.1.min.js"></script>'
                '<script src="/static/bootstrap-5.3.3.bundle.min.js"></script>'
                '<script src="/static/lodash-4.17.21.min.js"></script>'
                "</head><body>Clean</body></html>"
            ),
            content_type="text/html",
        )
        ctx, client = _make_context(
            responses=[resp],
            scripts=["http://127.0.0.1:8080/static/jquery-3.7.1.min.js"],
        )
        try:
            findings = OutdatedJSComponentsCheck().run(ctx)
        finally:
            client.close()

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
