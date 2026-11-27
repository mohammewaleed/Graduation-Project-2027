"""Active input-validation check for reflected HTML output encoding (CWE-79).

Submits a harmless, non-executing verification token containing HTML angle
brackets and quote characters (``owlscan<x9"'>``) to discovered query
parameters and HTML form fields. Flags an issue only when an HTML response
echoes the unescaped token verbatim, classifying the reflection context as
``html_body``, ``html_attribute``, or ``script_block``.

Pure Python (standard library + ``requests`` via ``ctx.http_client``) with zero
FastAPI, SQLAlchemy, Starlette, or Pydantic dependencies.
"""

from __future__ import annotations

import re
from typing import ClassVar

from backend.scanner.checks.active.sqli import (
    ACTIVE_PROFILES,
    _collect_parameter_targets,
    _extract_excerpt,
    _send_target_request,
)
from backend.scanner.checks.base import BaseCheck, CheckContext
from backend.scanner.models import (
    CheckKind,
    Confidence,
    OWASPCategory,
    RawFinding,
    ScanProfile,
    Severity,
)

XSS_CANARY: str = 'owlscan<x9"\'>'

_SCRIPT_BLOCK_RE = re.compile(
    r"<script\b[^>]*>(.*?)</script>",
    re.IGNORECASE | re.DOTALL,
)

_NON_HTML_MEDIA_TYPES: frozenset[str] = frozenset(
    {
        "application/json",
        "text/json",
        "text/plain",
        "text/css",
        "text/csv",
        "application/javascript",
        "text/javascript",
        "application/xml",
        "text/xml",
        "application/octet-stream",
    }
)


def _get_media_type(headers: dict[str, str]) -> str:
    """Extract the lowercased MIME media type from response headers."""
    for key, value in headers.items():
        if key.lower() == "content-type":
            return (value or "").split(";", 1)[0].strip().lower()
    return ""


def _is_html_response(headers: dict[str, str]) -> bool:
    """Return True if headers indicate an HTML (or untyped non-JSON) response."""
    media_type = _get_media_type(headers)
    if not media_type:
        return True
    if media_type in ("text/html", "application/xhtml+xml"):
        return True
    if media_type in _NON_HTML_MEDIA_TYPES or media_type.endswith("+json") or media_type.endswith("+xml"):
        return False
    return False


def _classify_reflection_context(body: str, canary: str) -> str:
    """Classify where ``canary`` is reflected: ``script_block``, ``html_attribute``, or ``html_body``."""
    for match in _SCRIPT_BLOCK_RE.finditer(body):
        if canary in (match.group(1) or ""):
            return "script_block"

    idx = body.find(canary)
    if idx != -1:
        prefix = body[:idx]
        last_open = prefix.rfind("<")
        last_close = prefix.rfind(">")
        if last_open > last_close:
            return "html_attribute"

    return "html_body"


class XSSReflectedCheck(BaseCheck):
    """Detects unescaped reflection of HTML syntax characters in HTML responses."""

    id: ClassVar[str] = "xss_reflected"
    name: ClassVar[str] = "Reflected Cross-Site Scripting (XSS)"
    owasp_category: ClassVar[str] = OWASPCategory.A03
    cwe_id: ClassVar[str] = "CWE-79"
    kind: ClassVar[CheckKind] = CheckKind.ACTIVE
    default_severity: ClassVar[Severity] = Severity.HIGH
    profiles: ClassVar[frozenset[ScanProfile]] = ACTIVE_PROFILES
    description: ClassVar[str] = (
        "Sends a harmless verification token containing HTML angle-bracket and "
        "quote characters to query parameters and form fields, flagging "
        "unescaped reflections in HTML responses."
    )

    CANARY: ClassVar[str] = XSS_CANARY

    def run(self, ctx: CheckContext) -> list[RawFinding]:
        if ctx.is_cancelled():
            return []

        targets = _collect_parameter_targets(ctx)
        if not targets:
            return []

        findings: list[RawFinding] = []

        for target in targets:
            if ctx.is_cancelled():
                break

            resp = _send_target_request(ctx, target, override_value=self.CANARY)
            if resp is None:
                continue

            if not _is_html_response(dict(resp.headers)):
                continue

            body = resp.text or ""
            if self.CANARY not in body:
                continue

            idx = body.find(self.CANARY)
            context = _classify_reflection_context(body, self.CANARY)
            snippet = _extract_excerpt(body, idx, idx + len(self.CANARY))

            findings.append(
                RawFinding(
                    check_id=self.id,
                    title="Reflected Cross-Site Scripting (XSS)",
                    owasp_category=self.owasp_category,
                    cwe_id=self.cwe_id,
                    severity=self.default_severity,
                    url=target.action_url if target.method == "POST" else target.url,
                    method=target.method,
                    parameter=target.param_name,
                    evidence={
                        "context": context,
                        "probe": self.CANARY,
                        "status_code": str(resp.status_code),
                        "content_type": _get_media_type(dict(resp.headers)) or "text/html",
                        "snippet": snippet,
                    },
                    confidence=Confidence.HIGH,
                )
            )

        return findings


__all__ = [
    "XSSReflectedCheck",
    "XSS_CANARY",
]
