"""Passive check for version-disclosing Server and X-Powered-By banners."""

from __future__ import annotations

import re
from typing import ClassVar

from backend.scanner.checks.base import BaseCheck, CheckContext
from backend.scanner.checks.passive._helpers import ALL_PROFILES, get_header
from backend.scanner.models import (
    CheckKind,
    Confidence,
    OWASPCategory,
    RawFinding,
    ScanProfile,
    Severity,
)

_VERSION_RE = re.compile(r"\d+\.\d+")
_BANNER_HEADERS: tuple[str, ...] = (
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
)


class ServerBannerLeakCheck(BaseCheck):
    """Detects HTTP Server and X-Powered-By headers leaking version numbers."""

    id: ClassVar[str] = "server_banner_leak"
    name: ClassVar[str] = "Server Banner Version Disclosure"
    owasp_category: ClassVar[str] = OWASPCategory.A05
    cwe_id: ClassVar[str] = "CWE-200"
    kind: ClassVar[CheckKind] = CheckKind.PASSIVE
    default_severity: ClassVar[Severity] = Severity.LOW
    profiles: ClassVar[frozenset[ScanProfile]] = ALL_PROFILES
    description: ClassVar[str] = (
        "Inspects Server and X-Powered-By response headers for specific software "
        "version strings that aid targeted fingerprinting."
    )

    def run(self, ctx: CheckContext) -> list[RawFinding]:
        if ctx.is_cancelled():
            return []

        origin_responses = ctx.responses.by_origin(ctx.target_url)
        if not origin_responses:
            return []

        findings: list[RawFinding] = []
        seen: set[tuple[str, str]] = set()

        for resp in origin_responses:
            for header_name in _BANNER_HEADERS:
                raw_val = (get_header(resp.headers, header_name) or "").strip()
                if not raw_val:
                    continue
                if not _VERSION_RE.search(raw_val):
                    continue

                dedup_key = (header_name.lower(), raw_val)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                findings.append(
                    RawFinding(
                        check_id=self.id,
                        title=f"Version Information Disclosed in {header_name} Header",
                        owasp_category=self.owasp_category,
                        cwe_id=self.cwe_id,
                        severity=self.default_severity,
                        url=resp.url,
                        method="GET",
                        parameter=header_name,
                        evidence={
                            "header": header_name,
                            "value": raw_val[:200],
                        },
                        confidence=Confidence.HIGH,
                    )
                )

        return findings


__all__ = ["ServerBannerLeakCheck"]
