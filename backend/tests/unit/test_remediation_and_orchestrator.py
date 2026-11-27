"""Unit tests for RemediationKB, scoring/deduplication, and ScanOrchestrator."""

from __future__ import annotations

import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from backend.scanner.checks import (
    BaseCheck,
    CheckContext,
    get_checks_for_profile,
    list_check_catalog,
    load_all_checks,
)
from backend.scanner.models import (
    CheckKind,
    Confidence,
    EnrichedFinding,
    OWASPCategory,
    RawFinding,
    RemediationFix,
    ScanConfig,
    ScanProfile,
    ScanProgress,
    ScanStatus,
    Severity,
    TriageStatus,
)
from backend.scanner.orchestrator import ScanOrchestrator
from backend.scanner.policy import ScopeViolationError
from backend.scanner.remediation import RemediationKB, SUPPORTED_STACKS
from backend.scanner.scoring import (
    calculate_risk_score,
    compute_fingerprint,
    deduplicate_findings,
    summarize_findings,
)

EXPECTED_CHECK_IDS: frozenset[str] = frozenset(
    {
        # 8 Passive
        "missing_security_headers",
        "weak_csp",
        "server_banner_leak",
        "verbose_error_pages",
        "insecure_cookies",
        "insecure_transport",
        "csrf_missing_token",
        "outdated_js_components",
        # 6 Active (5 standard + 1 deep heuristic)
        "cors_misconfig",
        "sqli_error_based",
        "sqli_boolean_diff",
        "xss_reflected",
        "open_redirect",
        "idor_heuristic",
        # 3 Discovery
        "sensitive_files",
        "directory_listing",
        "forced_browsing_admin",
    }
)


class _VulnerableE2EHandler(BaseHTTPRequestHandler):
    """Minimal local vulnerable web app exercising passive, active, and discovery checks."""

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
        self.send_header("Server", "Apache/2.4.52 (Ubuntu)")
        self.send_header("X-Powered-By", "PHP/8.1.2")
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == "/":
            html = """<!doctype html>
<html>
<head>
  <title>Vulnerable Lab App</title>
  <script src="/static/jquery-3.4.1.min.js"></script>
</head>
<body>
  <h1>Lab Home</h1>
  <a href="/search?q=hello">Search</a>
  <a href="/item?id=1">Item 1</a>
  <a href="/redirect?next=/home">Go Home</a>
  <form action="/login" method="POST">
    <input type="text" name="username">
    <input type="password" name="password">
  </form>
</body>
</html>"""
            self._send(
                200,
                html,
                extra_headers={
                    "Set-Cookie": "PHPSESSID=testtoken123; Path=/",
                    "Content-Security-Policy": "default-src * 'unsafe-inline'",
                },
            )
            return

        if path == "/search":
            q = qs.get("q", [""])[0]
            # Intentionally reflects raw input without HTML escaping (XSS)
            self._send(200, f"<html><body><h1>Results for: {q}</h1></body></html>")
            return

        if path == "/item":
            item_id = qs.get("id", ["1"])[0]
            if "'" in item_id or '"' in item_id:
                self._send(
                    500,
                    "<html><body>You have an error in your SQL syntax; check the manual near ''' at line 1</body></html>",
                )
                return
            self._send(
                200,
                f"<html><body><h2>Item #{item_id}</h2><p>Details for record {item_id}</p></body></html>",
            )
            return

        if path == "/redirect":
            target = qs.get("next", ["/"])[0]
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if path == "/.env":
            self._send(
                200,
                "APP_ENV=local\nDB_PASSWORD=super_secret_pw\nSECRET_KEY=devkey123\n",
                content_type="text/plain; charset=utf-8",
            )
            return

        if path == "/admin":
            self._send(
                200,
                "<html><body><h1>Admin Panel</h1><p>Manage Users & System Settings</p></body></html>",
            )
            return

        self._send(404, "<html><body>Not Found</body></html>")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        if length > 0:
            self.rfile.read(length)
        self._send(200, "<html><body>Submitted</body></html>")


class _MockFailingCheck(BaseCheck):
    """Test helper check that raises RuntimeError without polluting BaseCheck.registry."""

    # Note: intentionally omit class-level `id` so BaseCheck.__init_subclass__ does NOT register it.
    name = "Mock Failing Check"
    owasp_category = OWASPCategory.A05
    cwe_id = "CWE-703"
    kind = CheckKind.PASSIVE
    default_severity = Severity.LOW
    profiles = frozenset({ScanProfile.QUICK, ScanProfile.STANDARD, ScanProfile.DEEP})

    def __init__(self) -> None:
        self.id = "mock_failing_check"

    def run(self, ctx: CheckContext) -> list[RawFinding]:
        raise RuntimeError("Simulated plugin crash")


class _MockHealthyCheck(BaseCheck):
    """Test helper check that emits one finding without polluting BaseCheck.registry."""

    name = "Mock Healthy Check"
    owasp_category = OWASPCategory.A05
    cwe_id = "CWE-693"
    kind = CheckKind.PASSIVE
    default_severity = Severity.MEDIUM
    profiles = frozenset({ScanProfile.QUICK, ScanProfile.STANDARD, ScanProfile.DEEP})

    def __init__(self) -> None:
        self.id = "missing_security_headers"

    def run(self, ctx: CheckContext) -> list[RawFinding]:
        return [
            RawFinding(
                check_id="missing_security_headers",
                title="Missing Security Headers (test)",
                owasp_category=OWASPCategory.A05,
                cwe_id="CWE-693",
                severity=Severity.MEDIUM,
                url=ctx.target_url,
                method="GET",
            )
        ]


class TestRegistryAndRemediationKB(unittest.TestCase):
    """Verifies 100% 17-check registry and RemediationKB completeness and formatting."""

    def test_registry_has_all_17_checks_and_100_percent_kb_coverage(self) -> None:
        registered = load_all_checks()
        self.assertEqual(len(BaseCheck.registry), 17)
        self.assertEqual(set(registered.keys()), EXPECTED_CHECK_IDS)

        kb = RemediationKB()
        for check_id in registered:
            self.assertTrue(
                kb.has_rule(check_id),
                f"RemediationKB is missing rule for registered check '{check_id}'",
            )
            rule = kb.get_rule(check_id)
            self.assertIsNotNone(rule)
            assert rule is not None

            self.assertTrue(str(rule.get("summary", "")).strip(), f"{check_id}: empty summary")
            self.assertTrue(
                str(rule.get("root_cause_template", "")).strip(),
                f"{check_id}: empty root_cause_template",
            )

            snippets = rule.get("snippets") or []
            stacks_present: dict[str, dict[str, str]] = {}
            for snippet in snippets:
                stack = str(snippet.get("stack", "")).strip().lower()
                stacks_present[stack] = snippet

            for required_stack in SUPPORTED_STACKS:
                self.assertIn(
                    required_stack,
                    stacks_present,
                    f"{check_id}: missing stack '{required_stack}'",
                )
                self.assertTrue(
                    str(stacks_present[required_stack].get("before", "")).strip(),
                    f"{check_id}/{required_stack}: empty before snippet",
                )
                self.assertTrue(
                    str(stacks_present[required_stack].get("after", "")).strip(),
                    f"{check_id}/{required_stack}: empty after snippet",
                )

            refs = rule.get("references") or []
            self.assertGreaterEqual(
                len(refs),
                2,
                f"{check_id}: expected >= 2 authoritative references",
            )

    def test_profile_filtering_and_catalog(self) -> None:
        quick_ids = {c.id for c in get_checks_for_profile(ScanProfile.QUICK)}
        standard_ids = {c.id for c in get_checks_for_profile(ScanProfile.STANDARD)}
        deep_ids = {c.id for c in get_checks_for_profile(ScanProfile.DEEP)}

        self.assertEqual(len(quick_ids), 8)
        self.assertEqual(len(standard_ids), 14)
        self.assertEqual(len(deep_ids), 17)
        self.assertTrue(quick_ids.issubset(standard_ids))
        self.assertTrue(standard_ids.issubset(deep_ids))

        catalog = list_check_catalog()
        self.assertEqual(len(catalog), 17)

    def test_remediation_interpolation_and_express_stack_ordering(self) -> None:
        kb = RemediationKB()
        raw = RawFinding(
            check_id="sqli_error_based",
            title="Error-Based SQL Injection",
            owasp_category=OWASPCategory.A03,
            cwe_id="CWE-89",
            severity=Severity.CRITICAL,
            url="http://127.0.0.1:8000/api/login?debug=1",
            method="POST",
            parameter="user",
        )

        explanation, fix = kb.build_remediation(raw, target_stack="express")

        self.assertIn("POST", explanation)
        self.assertIn("/api/login", explanation)
        self.assertIn("user", explanation)
        self.assertEqual(explanation, fix.root_cause)
        self.assertEqual(len(fix.snippets), 5)
        self.assertEqual(fix.snippets[0].stack, "express")
        self.assertGreaterEqual(len(fix.references), 2)

    def test_remediation_unknown_check_fallback(self) -> None:
        kb = RemediationKB()
        raw = RawFinding(
            check_id="nonexistent_check",
            title="Custom Issue",
            owasp_category=OWASPCategory.A05,
            cwe_id="CWE-16",
            severity=Severity.LOW,
            url="http://127.0.0.1:8000/status",
            method="GET",
            parameter=None,
        )
        explanation, fix = kb.build_remediation(raw, target_stack="flask")
        self.assertIn("GET /status", explanation)
        self.assertIn("endpoint response", explanation)
        self.assertTrue(fix.summary)


class TestScoringAndDeduplication(unittest.TestCase):
    """Verifies SHA-1 fingerprinting, deduplication, and bounded 0-100 risk scoring."""

    @staticmethod
    def _make_finding(
        *,
        check_id: str = "xss_reflected",
        method: str = "GET",
        url: str = "http://127.0.0.1:8000/search",
        parameter: str | None = "q",
        severity: Severity = Severity.HIGH,
        confidence: Confidence = Confidence.HIGH,
        triage_status: TriageStatus = TriageStatus.OPEN,
    ) -> EnrichedFinding:
        fp = compute_fingerprint(check_id, method, url, parameter)
        return EnrichedFinding(
            check_id=check_id,
            title=f"{check_id} finding",
            owasp_category=OWASPCategory.A03,
            cwe_id="CWE-79",
            severity=severity,
            url=url,
            method=method,
            parameter=parameter,
            explanation="Test explanation",
            fix=RemediationFix(summary="Fix it", root_cause="Root cause"),
            fingerprint=fp,
            confidence=confidence,
            triage_status=triage_status,
        )

    def test_fingerprint_stability_and_normalization(self) -> None:
        fp1 = compute_fingerprint("XSS_Reflected", "get", "http://127.0.0.1:8000/search/?a=1", "Q")
        fp2 = compute_fingerprint("xss_reflected", "GET", "http://127.0.0.1:8000/search?b=2", "q")
        fp3 = compute_fingerprint("xss_reflected", "POST", "http://127.0.0.1:8000/search", "q")

        self.assertEqual(len(fp1), 40)
        self.assertEqual(fp1, fp2)
        self.assertNotEqual(fp1, fp3)

    def test_deduplicate_collapses_duplicates_keeping_highest_severity_and_confidence(self) -> None:
        low_conf = self._make_finding(severity=Severity.MEDIUM, confidence=Confidence.LOW)
        high_sev = self._make_finding(severity=Severity.HIGH, confidence=Confidence.MEDIUM)
        high_both = self._make_finding(severity=Severity.HIGH, confidence=Confidence.HIGH)
        distinct = self._make_finding(parameter="page", severity=Severity.LOW)

        deduped = deduplicate_findings([low_conf, high_sev, high_both, distinct])
        self.assertEqual(len(deduped), 2)
        self.assertEqual(deduped[0].severity, Severity.HIGH)
        self.assertEqual(deduped[0].confidence, Confidence.HIGH)
        self.assertEqual(deduped[1].parameter, "page")

    def test_risk_score_excludes_false_positives_and_caps_at_100(self) -> None:
        findings = [
            self._make_finding(parameter="p1", severity=Severity.CRITICAL),  # 10
            self._make_finding(parameter="p2", severity=Severity.HIGH),      # 6
            self._make_finding(parameter="p3", severity=Severity.MEDIUM),    # 3
            self._make_finding(parameter="p4", severity=Severity.LOW),       # 1
            self._make_finding(parameter="p5", severity=Severity.INFO),      # 0
            self._make_finding(
                parameter="p6",
                severity=Severity.CRITICAL,
                triage_status=TriageStatus.FALSE_POSITIVE,
            ),  # excluded
        ]
        summary = summarize_findings(findings)
        self.assertEqual(summary["critical"], 1)
        self.assertEqual(summary["high"], 1)
        self.assertEqual(summary["medium"], 1)
        self.assertEqual(summary["low"], 1)
        self.assertEqual(summary["info"], 1)
        self.assertEqual(calculate_risk_score(findings), 20)

        # Verify 0-100 cap with 15 critical findings (raw = 150 -> capped at 100)
        many_critical = [
            self._make_finding(parameter=f"c{i}", severity=Severity.CRITICAL)
            for i in range(15)
        ]
        self.assertEqual(calculate_risk_score(many_critical), 100)
        self.assertEqual(calculate_risk_score([]), 0)


class TestScanOrchestrator(unittest.TestCase):
    """End-to-end and lifecycle tests for ScanOrchestrator."""

    server: ThreadingHTTPServer
    server_thread: threading.Thread
    base_url: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _VulnerableE2EHandler)
        port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{port}"
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=3.0)

    def test_full_deep_scan_completes_with_multiple_owasp_categories_and_fixes(self) -> None:
        orchestrator = ScanOrchestrator()
        progress_events: list[ScanProgress] = []
        streamed_findings: list[EnrichedFinding] = []

        config = ScanConfig(
            target_url=self.base_url,
            profile=ScanProfile.DEEP,
            target_stack="express",
            rate_limit_rps=500.0,
            max_pages=25,
            timeout_s=5.0,
        )
        outcome = orchestrator.run_scan(
            config,
            scan_id="test-e2e-deep",
            progress_callback=progress_events.append,
            finding_callback=streamed_findings.append,
        )

        self.assertEqual(outcome.status, ScanStatus.COMPLETED)
        self.assertEqual(outcome.scan_id, "test-e2e-deep")
        self.assertGreater(len(outcome.endpoints), 0)
        self.assertGreater(outcome.risk_score, 0)
        self.assertGreater(len(outcome.findings), 0)
        self.assertGreater(len(streamed_findings), 0)

        # Confirm multiple distinct OWASP categories detected and fixes attached
        categories = {f.owasp_category for f in outcome.findings}
        self.assertGreaterEqual(len(categories), 3)
        for finding in outcome.findings:
            self.assertTrue(finding.explanation)
            self.assertTrue(finding.fix.summary)
            self.assertEqual(finding.fix.snippets[0].stack, "express")
            self.assertEqual(len(finding.fingerprint), 40)

        # Progress callback must finish at 100%
        self.assertTrue(progress_events)
        self.assertEqual(progress_events[-1].percent, 100)

    def test_out_of_scope_public_url_raises_scope_violation(self) -> None:
        orchestrator = ScanOrchestrator()
        config = ScanConfig(target_url="https://example.com/")
        with self.assertRaises(ScopeViolationError):
            orchestrator.run_scan(config)

    def test_unreachable_local_port_returns_failed_status(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            unused_port = sock.getsockname()[1]

        orchestrator = ScanOrchestrator()
        config = ScanConfig(
            target_url=f"http://127.0.0.1:{unused_port}/",
            timeout_s=1.0,
            rate_limit_rps=100.0,
        )
        outcome = orchestrator.run_scan(config)

        self.assertEqual(outcome.status, ScanStatus.FAILED)
        self.assertTrue(outcome.errors)
        self.assertTrue(
            any("unreachable" in err.lower() for err in outcome.errors),
            f"Expected clear unreachable error, got: {outcome.errors}",
        )

    def test_preset_cancel_event_returns_cancelled_cleanly(self) -> None:
        orchestrator = ScanOrchestrator()
        cancel_event = threading.Event()
        cancel_event.set()

        config = ScanConfig(target_url=self.base_url, profile=ScanProfile.QUICK)
        outcome = orchestrator.run_scan(config, cancel_event=cancel_event)

        self.assertEqual(outcome.status, ScanStatus.CANCELLED)
        self.assertEqual(outcome.requests_sent, 0)

    def test_per_check_error_isolation_logs_error_and_completes(self) -> None:
        orchestrator = ScanOrchestrator()
        config = ScanConfig(
            target_url=self.base_url,
            profile=ScanProfile.QUICK,
            rate_limit_rps=500.0,
            max_pages=5,
        )
        outcome = orchestrator.run_scan(
            config,
            checks=[_MockFailingCheck(), _MockHealthyCheck()],
        )

        self.assertEqual(outcome.status, ScanStatus.COMPLETED)
        self.assertTrue(
            any("mock_failing_check" in err and "Simulated plugin crash" in err for err in outcome.errors),
            f"Expected isolated check error in outcome.errors, got: {outcome.errors}",
        )
        self.assertEqual(len(outcome.findings), 1)
        self.assertEqual(outcome.findings[0].check_id, "missing_security_headers")


if __name__ == "__main__":
    unittest.main()
