"""Passive check for verbose error pages, debuggers, and stack traces."""

from __future__ import annotations

import re
from typing import ClassVar

from backend.scanner.checks.base import BaseCheck, CheckContext
from backend.scanner.checks.passive._helpers import ALL_PROFILES
from backend.scanner.models import (
    CheckKind,
    Confidence,
    OWASPCategory,
    RawFinding,
    ScanProfile,
    Severity,
)

# Ordered list of (framework_label, compiled_regex) signatures.
_ERROR_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "Python / Werkzeug",
        re.compile(r"Traceback \(most recent call last\):"),
    ),
    (
        "Python / Werkzeug",
        re.compile(r"Werkzeug Debugger", re.IGNORECASE),
    ),
    (
        "Django",
        re.compile(
            r"Django Version:|You['\u2019]re seeing this error because you have\s+(?:<code>)?DEBUG\s*=\s*True",
            re.IGNORECASE,
        ),
    ),
    (
        "FastAPI / Starlette",
        re.compile(
            r"(?:starlette|fastapi|uvicorn).{0,300}(?:File\s+\"[^\"]+\.py\",\s+line\s+\d+|Traceback)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "Python",
        re.compile(r'File "[^"]+\.py",\s+line\s+\d+,\s+in\s+\S+'),
    ),
    (
        "PHP",
        re.compile(
            r"(?:<b>)?(?:Fatal error|Parse error)(?:</b>)?\s*:|\bStack trace\s*:",
            re.IGNORECASE,
        ),
    ),
    (
        "Express / Node.js",
        re.compile(
            r"at Function\.handle\b|at Layer\.handle\b.{0,250}\.js:|(?:ReferenceError|TypeError|SyntaxError):.{0,300}\.js:",
            re.DOTALL,
        ),
    ),
)


def _extract_excerpt(body: str, start: int, end: int, radius: int = 120) -> str:
    """Return a clean, bounded snippet centered on the matched error signature."""
    snippet_start = max(0, start - 40)
    snippet_end = min(len(body), end + radius)
    excerpt = body[snippet_start:snippet_end]
    return " ".join(excerpt.split())[:300]


class VerboseErrorPagesCheck(BaseCheck):
    """Detects unhandled stack traces and debug error pages in cached responses."""

    id: ClassVar[str] = "verbose_error_pages"
    name: ClassVar[str] = "Verbose Error Pages / Stack Trace Disclosure"
    owasp_category: ClassVar[str] = OWASPCategory.A05
    cwe_id: ClassVar[str] = "CWE-209"
    kind: ClassVar[CheckKind] = CheckKind.PASSIVE
    default_severity: ClassVar[Severity] = Severity.MEDIUM
    profiles: ClassVar[frozenset[ScanProfile]] = ALL_PROFILES
    description: ClassVar[str] = (
        "Inspects cached HTTP responses for Python/Werkzeug, Django, "
        "FastAPI/Starlette, PHP, and Express/Node.js stack traces or debug pages."
    )

    def run(self, ctx: CheckContext) -> list[RawFinding]:
        if ctx.is_cancelled():
            return []

        origin_responses = ctx.responses.by_origin(ctx.target_url)
        if not origin_responses:
            return []

        findings: list[RawFinding] = []
        seen_urls: set[str] = set()

        for resp in origin_responses:
            if resp.url in seen_urls or not resp.body:
                continue

            for framework, pattern in _ERROR_SIGNATURES:
                match = pattern.search(resp.body)
                if match is None:
                    continue

                seen_urls.add(resp.url)
                snippet = _extract_excerpt(resp.body, match.start(), match.end())
                findings.append(
                    RawFinding(
                        check_id=self.id,
                        title=f"Verbose Error Page ({framework} Stack Trace Exposed)",
                        owasp_category=self.owasp_category,
                        cwe_id=self.cwe_id,
                        severity=self.default_severity,
                        url=resp.url,
                        method="GET",
                        parameter=None,
                        evidence={
                            "framework": framework,
                            "status_code": str(resp.status_code),
                            "snippet": snippet,
                        },
                        confidence=Confidence.HIGH,
                    )
                )
                break

        return findings


__all__ = ["VerboseErrorPagesCheck"]
