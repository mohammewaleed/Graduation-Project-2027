"""Discovery check for web server automatic directory indexing.

Pure Python (standard library + requests via ``ctx.http_client``) with zero
FastAPI, SQLAlchemy, Starlette, or Pydantic dependencies.
"""

from __future__ import annotations

from typing import ClassVar
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests

from backend.scanner.checks.base import BaseCheck, CheckContext
from backend.scanner.models import (
    CheckKind,
    Confidence,
    OWASPCategory,
    RawFinding,
    ScanProfile,
    Severity,
)
from backend.scanner.policy import ScopeViolationError

_COMMON_DIRECTORY_PATHS: tuple[str, ...] = (
    "/static/",
    "/uploads/",
    "/backup/",
    "/assets/",
)

_LISTING_MARKERS: tuple[str, ...] = (
    "Index of /",
    "Directory listing for /",
)


def _detect_listing_marker(body: str) -> str | None:
    """Return the matched directory-listing marker if present in ``body``."""
    if not body:
        return None
    lowered = body.lower()
    for marker in _LISTING_MARKERS:
        if marker.lower() in lowered:
            return marker
    return None


def _origin_root(url: str) -> str:
    parsed = urlsplit(url.strip())
    return urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))


class DirectoryListingCheck(BaseCheck):
    """Detects enabled directory auto-indexing on cached and common static paths."""

    id: ClassVar[str] = "directory_listing"
    name: ClassVar[str] = "Web Server Directory Listing Enabled"
    owasp_category: ClassVar[str] = OWASPCategory.A05
    cwe_id: ClassVar[str] = "CWE-548"
    kind: ClassVar[CheckKind] = CheckKind.DISCOVERY
    default_severity: ClassVar[Severity] = Severity.MEDIUM
    profiles: ClassVar[frozenset[ScanProfile]] = frozenset({ScanProfile.DEEP})
    description: ClassVar[str] = (
        "Inspects cached responses and probes /static/, /uploads/, /backup/, "
        "and /assets/ (with follow_redirects=False and Soft-404 filtering) "
        "for 'Index of /' or 'Directory listing for /' auto-indexing pages."
    )

    def run(self, ctx: CheckContext) -> list[RawFinding]:
        if ctx.is_cancelled():
            return []

        findings: list[RawFinding] = []
        seen_paths: set[str] = set()
        base_url = (ctx.surface.base_url or ctx.target_url).strip()
        root = _origin_root(base_url)

        def _record_if_listing(url: str, status_code: int, body: str) -> None:
            if status_code != 200:
                return
            if ctx.soft_404 is not None and ctx.soft_404.is_soft_404(
                status_code, body
            ):
                return
            marker = _detect_listing_marker(body)
            if not marker:
                return

            path = urlsplit(url).path or "/"
            dedup_path = path.rstrip("/") or "/"
            if dedup_path in seen_paths:
                return
            seen_paths.add(dedup_path)

            findings.append(
                RawFinding(
                    check_id=self.id,
                    title=f"Web Server Directory Listing Enabled ({path})",
                    owasp_category=self.owasp_category,
                    cwe_id=self.cwe_id,
                    severity=self.default_severity,
                    url=url,
                    method="GET",
                    parameter=path,
                    evidence={
                        "path": path,
                        "status_code": str(status_code),
                        "marker": marker,
                    },
                    confidence=Confidence.HIGH,
                )
            )

        # 1. Inspect already-cached responses on the target origin
        for cached in ctx.responses.by_origin(base_url):
            if ctx.is_cancelled():
                return findings
            _record_if_listing(cached.url, cached.status_code, cached.body)

        # 2. Actively probe common asset/upload/backup directory paths
        for rel_dir in _COMMON_DIRECTORY_PATHS:
            if ctx.is_cancelled():
                break

            dedup_path = rel_dir.rstrip("/") or "/"
            if dedup_path in seen_paths:
                continue

            probe_url = urljoin(root, rel_dir.lstrip("/"))
            if ctx.guardrail.is_destructive_path(probe_url):
                continue

            try:
                resp = ctx.http_client.get(probe_url, follow_redirects=False)
            except (requests.RequestException, ScopeViolationError):
                continue

            _record_if_listing(probe_url, resp.status_code, resp.text or "")

        return findings


__all__ = [
    "DirectoryListingCheck",
]
