"""Passive check for cleartext password forms and missing HTTPS HSTS headers."""

from __future__ import annotations

import re
from typing import ClassVar

from backend.scanner.checks.base import BaseCheck, CheckContext
from backend.scanner.checks.passive._helpers import (
    ALL_PROFILES,
    get_header,
    url_scheme,
)
from backend.scanner.models import (
    CheckKind,
    Confidence,
    OWASPCategory,
    RawFinding,
    ScanProfile,
    Severity,
)

_MAX_AGE_RE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)


def _has_valid_hsts(hsts_value: str | None) -> bool:
    """Return True when an HSTS header is present with a positive max-age."""
    if not hsts_value or not hsts_value.strip():
        return False
    match = _MAX_AGE_RE.search(hsts_value)
    if match is None:
        return False
    return int(match.group(1)) > 0


class InsecureTransportCheck(BaseCheck):
    """Flags HTTP password forms and HTTPS origins lacking HSTS."""

    id: ClassVar[str] = "insecure_transport"
    name: ClassVar[str] = "Insecure Transport (HTTP Credentials / Missing HSTS)"
    owasp_category: ClassVar[str] = OWASPCategory.A02
    cwe_id: ClassVar[str] = "CWE-319"
    kind: ClassVar[CheckKind] = CheckKind.PASSIVE
    default_severity: ClassVar[Severity] = Severity.MEDIUM
    profiles: ClassVar[frozenset[ScanProfile]] = ALL_PROFILES
    description: ClassVar[str] = (
        "Flags HTML forms containing password inputs submitted over unencrypted "
        "HTTP, and HTTPS origin responses missing Strict-Transport-Security."
    )

    def run(self, ctx: CheckContext) -> list[RawFinding]:
        if ctx.is_cancelled():
            return []

        findings: list[RawFinding] = []
        seen_forms: set[tuple[str, str]] = set()

        # 1. Password forms submitted over cleartext http://
        for form in ctx.surface.forms:
            password_input = next(
                (inp for inp in form.inputs if inp.input_type.strip().lower() == "password"),
                None,
            )
            if password_input is None:
                continue

            action_url = form.action_url or form.source_url or ctx.target_url
            scheme = url_scheme(action_url) or url_scheme(form.source_url) or url_scheme(ctx.target_url)
            if scheme != "http":
                continue

            method = (form.method or "GET").strip().upper() or "GET"
            form_key = (method, action_url)
            if form_key in seen_forms:
                continue
            seen_forms.add(form_key)

            findings.append(
                RawFinding(
                    check_id=self.id,
                    title="Password Form Submitted Over Unencrypted HTTP",
                    owasp_category=self.owasp_category,
                    cwe_id=self.cwe_id,
                    severity=self.default_severity,
                    url=action_url,
                    method=method,
                    parameter=password_input.name or "password",
                    evidence={
                        "issue": "password_over_http",
                        "action_url": action_url,
                        "source_url": form.source_url or ctx.target_url,
                        "password_field": password_input.name or "password",
                        "note": (
                            "Form submits a password field over cleartext http://. "
                            "Enforce HTTPS in staging/production (acceptable only on local loopback development)."
                        ),
                    },
                    confidence=Confidence.HIGH,
                )
            )

        # 2. HTTPS origin responses missing Strict-Transport-Security
        https_responses = [
            resp
            for resp in ctx.responses.by_origin(ctx.target_url)
            if url_scheme(resp.url) == "https"
        ]
        if https_responses:
            missing_hsts_resp = next(
                (
                    resp
                    for resp in https_responses
                    if not _has_valid_hsts(
                        get_header(resp.headers, "Strict-Transport-Security")
                    )
                ),
                None,
            )
            if missing_hsts_resp is not None:
                raw_hsts = get_header(
                    missing_hsts_resp.headers, "Strict-Transport-Security"
                )
                findings.append(
                    RawFinding(
                        check_id=self.id,
                        title="Missing Strict-Transport-Security (HSTS) Header on HTTPS Origin",
                        owasp_category=self.owasp_category,
                        cwe_id=self.cwe_id,
                        severity=self.default_severity,
                        url=missing_hsts_resp.url,
                        method="GET",
                        parameter="Strict-Transport-Security",
                        evidence={
                            "issue": "missing_hsts",
                            "url": missing_hsts_resp.url,
                            "observed_header": raw_hsts or "(absent)",
                        },
                        confidence=Confidence.HIGH,
                    )
                )

        return findings


__all__ = ["InsecureTransportCheck"]
