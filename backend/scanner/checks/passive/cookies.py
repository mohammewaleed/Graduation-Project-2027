"""Passive check for session cookies missing HttpOnly, SameSite, or Secure."""

from __future__ import annotations

from typing import ClassVar

from backend.scanner.checks.base import BaseCheck, CheckContext
from backend.scanner.checks.passive._helpers import (
    ALL_PROFILES,
    get_all_headers,
    is_session_cookie,
    parse_set_cookie,
    redact_set_cookie,
    split_set_cookie_header,
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


class InsecureCookiesCheck(BaseCheck):
    """Flags session-like Set-Cookie headers missing security attributes."""

    id: ClassVar[str] = "insecure_cookies"
    name: ClassVar[str] = "Insecure Session Cookie Attributes"
    owasp_category: ClassVar[str] = OWASPCategory.A07
    cwe_id: ClassVar[str] = "CWE-614"
    kind: ClassVar[CheckKind] = CheckKind.PASSIVE
    default_severity: ClassVar[Severity] = Severity.MEDIUM
    profiles: ClassVar[frozenset[ScanProfile]] = ALL_PROFILES
    description: ClassVar[str] = (
        "Inspects Set-Cookie headers for session-like cookies missing HttpOnly, "
        "SameSite, or (on HTTPS origins) Secure attributes."
    )

    def run(self, ctx: CheckContext) -> list[RawFinding]:
        if ctx.is_cancelled():
            return []

        origin_responses = ctx.responses.by_origin(ctx.target_url)
        if not origin_responses:
            return []

        findings: list[RawFinding] = []
        seen: set[tuple[str, tuple[str, ...]]] = set()

        for resp in origin_responses:
            raw_headers = get_all_headers(resp.headers, "Set-Cookie")
            if not raw_headers:
                continue

            is_https = url_scheme(resp.url) == "https"

            for raw_header in raw_headers:
                for raw_cookie in split_set_cookie_header(raw_header):
                    name, _value, attrs = parse_set_cookie(raw_cookie)
                    if not is_session_cookie(name):
                        continue

                    missing_flags: list[str] = []
                    if "httponly" not in attrs:
                        missing_flags.append("HttpOnly")
                    if not attrs.get("samesite"):
                        missing_flags.append("SameSite")
                    if is_https and "secure" not in attrs:
                        missing_flags.append("Secure")

                    if not missing_flags:
                        continue

                    dedup_key = (name.lower(), tuple(missing_flags))
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    missing_str = ", ".join(missing_flags)
                    findings.append(
                        RawFinding(
                            check_id=self.id,
                            title=f"Session Cookie '{name}' Missing {missing_str}",
                            owasp_category=self.owasp_category,
                            cwe_id=self.cwe_id,
                            severity=self.default_severity,
                            url=resp.url,
                            method="GET",
                            parameter=name,
                            evidence={
                                "cookie": name,
                                "missing_flags": missing_str,
                                "set_cookie": redact_set_cookie(raw_cookie),
                            },
                            confidence=Confidence.HIGH,
                        )
                    )

        return findings


__all__ = ["InsecureCookiesCheck"]
