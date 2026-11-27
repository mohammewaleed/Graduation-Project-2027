"""Discovery check for unauthenticated administrative and user-listing endpoints.

Pure Python (standard library + requests via ``ctx.http_client``) with zero
FastAPI, SQLAlchemy, Starlette, or Pydantic dependencies.
"""

from __future__ import annotations

import json
import re
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

_ADMIN_PATHS: tuple[str, ...] = (
    "/admin",
    "/admin/",
    "/dashboard",
    "/admin-panel",
    "/api/users",
)

_PASSWORD_INPUT_RE = re.compile(
    r"<input[^>]+type=[\"']?password[\"']?",
    re.IGNORECASE,
)

_LOGIN_PAGE_MARKERS: tuple[str, ...] = (
    "please log in",
    "please sign in",
    "sign in to your account",
    "login required",
    "authentication required",
    "<title>login",
    "<title>sign in",
)

_ADMIN_AND_USER_MARKERS: tuple[str, ...] = (
    "admin",
    "dashboard",
    "manage users",
    "user management",
    "control panel",
    "admin panel",
    "system settings",
    "users",
    "username",
    "email",
    "role",
    "permissions",
)


def _is_login_page(body: str) -> bool:
    """Return True if ``body`` appears to be an unauthenticated login form."""
    if not body:
        return False
    if _PASSWORD_INPUT_RE.search(body):
        return True
    lowered = body.lower()
    return any(marker in lowered for marker in _LOGIN_PAGE_MARKERS)


def _detect_privileged_exposure(path: str, body: str) -> str | None:
    """Return an evidence description if ``body`` exposes admin controls or user listings."""
    if not body or not body.strip():
        return None

    # Check structured JSON responses (e.g. /api/users)
    try:
        parsed = json.loads(body)
    except ValueError:
        parsed = None

    if isinstance(parsed, list) and len(parsed) > 0:
        first = parsed[0]
        if isinstance(first, dict) and any(
            k in first
            for k in ("id", "user_id", "username", "email", "role", "name", "is_admin")
        ):
            return f"JSON user listing array ({len(parsed)} records)"
        if path == "/api/users":
            return f"JSON array returned by {path} ({len(parsed)} items)"
    elif isinstance(parsed, dict) and len(parsed) > 0:
        for key in ("users", "accounts", "admins", "data", "items", "role", "username"):
            if key in parsed:
                return f"JSON privileged resource object (key '{key}')"

    lowered = body.lower()
    for marker in _ADMIN_AND_USER_MARKERS:
        if marker in lowered:
            return f"Exposed administrative or user listing content ('{marker}')"

    return None


def _origin_root(url: str) -> str:
    parsed = urlsplit(url.strip())
    return urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))


class ForcedBrowsingAdminCheck(BaseCheck):
    """Detects unauthenticated HTTP 200 access to admin panels or user listings."""

    id: ClassVar[str] = "forced_browsing_admin"
    name: ClassVar[str] = (
        "Unauthenticated Access to Administrative or Privileged Endpoint"
    )
    owasp_category: ClassVar[str] = OWASPCategory.A01
    cwe_id: ClassVar[str] = "CWE-425"
    kind: ClassVar[CheckKind] = CheckKind.DISCOVERY
    default_severity: ClassVar[Severity] = Severity.HIGH
    profiles: ClassVar[frozenset[ScanProfile]] = frozenset({ScanProfile.DEEP})
    description: ClassVar[str] = (
        "Checks /admin, /admin/, /dashboard, /admin-panel, and /api/users "
        "with follow_redirects=False, Soft-404 filtering, and login-page "
        "exclusion to detect unauthenticated administrative exposure."
    )

    def run(self, ctx: CheckContext) -> list[RawFinding]:
        if ctx.is_cancelled():
            return []

        findings: list[RawFinding] = []
        root = _origin_root(ctx.surface.base_url or ctx.target_url)

        for rel_path in _ADMIN_PATHS:
            if ctx.is_cancelled():
                break

            probe_url = urljoin(root, rel_path.lstrip("/"))
            if ctx.guardrail.is_destructive_path(probe_url):
                continue

            try:
                resp = ctx.http_client.get(probe_url, follow_redirects=False)
            except (requests.RequestException, ScopeViolationError):
                continue

            if resp.status_code != 200:
                continue

            body = resp.text or ""
            if ctx.soft_404 is not None and ctx.soft_404.is_soft_404(
                resp.status_code, body
            ):
                continue

            if _is_login_page(body):
                continue

            exposure = _detect_privileged_exposure(rel_path, body)
            if not exposure:
                continue

            findings.append(
                RawFinding(
                    check_id=self.id,
                    title=f"Unauthenticated Access to Administrative Endpoint ({rel_path})",
                    owasp_category=self.owasp_category,
                    cwe_id=self.cwe_id,
                    severity=self.default_severity,
                    url=probe_url,
                    method="GET",
                    parameter=rel_path,
                    evidence={
                        "path": rel_path,
                        "status_code": str(resp.status_code),
                        "exposure": exposure,
                    },
                    confidence=Confidence.HIGH,
                )
            )

        return findings


__all__ = [
    "ForcedBrowsingAdminCheck",
]
