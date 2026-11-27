"""Passive check for state-changing POST forms missing anti-CSRF tokens."""

from __future__ import annotations

from typing import ClassVar

from backend.scanner.checks.base import BaseCheck, CheckContext
from backend.scanner.checks.passive._helpers import (
    ALL_PROFILES,
    get_all_headers,
    is_session_cookie,
    parse_set_cookie,
    split_set_cookie_header,
)
from backend.scanner.models import (
    CheckKind,
    Confidence,
    OWASPCategory,
    RawFinding,
    ScanProfile,
    Severity,
)

_CSRF_TOKEN_INDICATORS: tuple[str, ...] = (
    "csrf",
    "xsrf",
    "_token",
    "user_token",
    "authenticity_token",
    "__requestverificationtoken",
)


def _has_csrf_field(input_names: list[str]) -> bool:
    """Return True if any form input name looks like an anti-CSRF token field."""
    for name in input_names:
        lowered = name.strip().lower()
        if not lowered:
            continue
        if any(indicator in lowered for indicator in _CSRF_TOKEN_INDICATORS):
            return True
    return False


def _origin_enforces_samesite_strict(ctx: CheckContext) -> bool:
    """Return True iff session cookies were observed and all enforce SameSite=Strict."""
    observed_session_cookies = 0
    for resp in ctx.responses.by_origin(ctx.target_url):
        for raw_header in get_all_headers(resp.headers, "Set-Cookie"):
            for raw_cookie in split_set_cookie_header(raw_header):
                name, _value, attrs = parse_set_cookie(raw_cookie)
                if not is_session_cookie(name):
                    continue
                observed_session_cookies += 1
                if attrs.get("samesite") != "strict":
                    return False
    return observed_session_cookies > 0


class CSRFMissingTokenCheck(BaseCheck):
    """Flags POST forms lacking anti-CSRF tokens without SameSite=Strict cookies."""

    id: ClassVar[str] = "csrf_missing_token"
    name: ClassVar[str] = "Missing Anti-CSRF Token on POST Form"
    owasp_category: ClassVar[str] = OWASPCategory.A01
    cwe_id: ClassVar[str] = "CWE-352"
    kind: ClassVar[CheckKind] = CheckKind.PASSIVE
    default_severity: ClassVar[Severity] = Severity.MEDIUM
    profiles: ClassVar[frozenset[ScanProfile]] = ALL_PROFILES
    description: ClassVar[str] = (
        "Detects HTML POST forms lacking an anti-CSRF token input when the origin "
        "does not enforce SameSite=Strict on session cookies."
    )

    def run(self, ctx: CheckContext) -> list[RawFinding]:
        if ctx.is_cancelled():
            return []

        if _origin_enforces_samesite_strict(ctx):
            return []

        findings: list[RawFinding] = []
        seen_actions: set[str] = set()

        for form in ctx.surface.forms:
            method = (form.method or "GET").strip().upper()
            if method != "POST":
                continue

            input_names = [inp.name for inp in form.inputs if inp.name]
            if _has_csrf_field(input_names):
                continue

            action_url = form.action_url or form.source_url or ctx.target_url
            if action_url in seen_actions:
                continue
            seen_actions.add(action_url)

            findings.append(
                RawFinding(
                    check_id=self.id,
                    title="POST Form Missing Anti-CSRF Token",
                    owasp_category=self.owasp_category,
                    cwe_id=self.cwe_id,
                    severity=self.default_severity,
                    url=action_url,
                    method="POST",
                    parameter=None,
                    evidence={
                        "action_url": action_url,
                        "source_url": form.source_url or ctx.target_url,
                        "fields": ", ".join(input_names) if input_names else "(none)",
                        "samesite_strict_enforced": "false",
                    },
                    confidence=Confidence.MEDIUM,
                )
            )

        return findings


__all__ = ["CSRFMissingTokenCheck"]
