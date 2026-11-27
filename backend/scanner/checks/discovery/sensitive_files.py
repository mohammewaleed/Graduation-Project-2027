"""Discovery check for accidentally exposed development and configuration files.

Pure Python (standard library + requests via ``ctx.http_client``) with zero
FastAPI, SQLAlchemy, Starlette, or Pydantic dependencies.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
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

_ENV_KEY_VALUE_RE = re.compile(r"(?m)^[A-Za-z_][A-Za-z0-9_]*\s*=\s*\S*")
_GIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


def _looks_like_html(body: str) -> bool:
    lowered = (body or "").lstrip()[:512].lower()
    return (
        lowered.startswith("<!doctype html")
        or lowered.startswith("<html")
        or "<html" in lowered
    )


def _match_env_file(body: str) -> str | None:
    if not body or _looks_like_html(body):
        return None
    match = _ENV_KEY_VALUE_RE.search(body)
    if match:
        key_name = match.group(0).split("=", 1)[0].strip()
        return f"Environment variable assignment '{key_name}=...'"
    return None


def _match_git_head(body: str) -> str | None:
    if not body or _looks_like_html(body):
        return None
    stripped = body.strip()
    if stripped.startswith("ref: refs/"):
        return f"Git HEAD reference '{stripped.splitlines()[0][:80]}'"
    first_line = stripped.splitlines()[0].strip() if stripped else ""
    if _GIT_SHA_RE.fullmatch(first_line):
        return "Detached Git commit SHA in HEAD"
    return None


def _match_phpinfo(body: str) -> str | None:
    lowered = (body or "").lower()
    for token in ("phpinfo()", "php version", "php credits", "zend engine"):
        if token in lowered:
            return f"PHP diagnostic signature '{token}'"
    return None


def _match_sql_backup(body: str) -> str | None:
    if not body or _looks_like_html(body):
        return None
    lowered = body.lower()
    for token in (
        "create table",
        "insert into",
        "mysqldump",
        "postgresql database dump",
        "sqlite format",
        "drop table",
    ):
        if token in lowered:
            return f"SQL dump statement '{token.upper()}'"
    return None


def _match_swagger_json(body: str) -> str | None:
    if not body or _looks_like_html(body):
        return None
    try:
        parsed = json.loads(body)
    except ValueError:
        parsed = None

    if isinstance(parsed, dict):
        if "openapi" in parsed:
            return f"OpenAPI specification (version {parsed.get('openapi')})"
        if "swagger" in parsed:
            return f"Swagger specification (version {parsed.get('swagger')})"

    if '"openapi"' in body or '"swagger"' in body:
        return "OpenAPI / Swagger JSON specification signature"
    return None


def _match_config_json(body: str) -> str | None:
    if not body or _looks_like_html(body):
        return None
    try:
        parsed = json.loads(body)
    except ValueError:
        return None

    if isinstance(parsed, dict) and len(parsed) > 0:
        sample_keys = ", ".join(sorted(str(k) for k in list(parsed.keys())[:5]))
        return f"JSON configuration object (keys: {sample_keys})"
    return None


_SENSITIVE_FILE_SPECS: tuple[tuple[str, str, Callable[[str], str | None]], ...] = (
    ("/.env", "Dotenv Environment File (/.env)", _match_env_file),
    ("/.git/HEAD", "Git Repository Metadata (/.git/HEAD)", _match_git_head),
    ("/phpinfo.php", "PHP Diagnostic Page (/phpinfo.php)", _match_phpinfo),
    ("/backup.sql", "Database Backup Dump (/backup.sql)", _match_sql_backup),
    ("/swagger.json", "OpenAPI / Swagger Spec (/swagger.json)", _match_swagger_json),
    ("/config.json", "Application Configuration (/config.json)", _match_config_json),
)


def _origin_root(url: str) -> str:
    parsed = urlsplit(url.strip())
    return urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))


class SensitiveFilesCheck(BaseCheck):
    """Probes common exposed developer, backup, and configuration artifacts."""

    id: ClassVar[str] = "sensitive_files"
    name: ClassVar[str] = "Exposed Sensitive Configuration, Source, or Backup File"
    owasp_category: ClassVar[str] = OWASPCategory.A05
    cwe_id: ClassVar[str] = "CWE-538"
    kind: ClassVar[CheckKind] = CheckKind.DISCOVERY
    default_severity: ClassVar[Severity] = Severity.HIGH
    profiles: ClassVar[frozenset[ScanProfile]] = frozenset(
        {ScanProfile.STANDARD, ScanProfile.DEEP}
    )
    description: ClassVar[str] = (
        "Checks common accidentally exposed development files (/.env, "
        "/.git/HEAD, /phpinfo.php, /backup.sql, /swagger.json, /config.json) "
        "with Soft-404 filtering and file-type signature verification."
    )

    def run(self, ctx: CheckContext) -> list[RawFinding]:
        if ctx.is_cancelled():
            return []

        findings: list[RawFinding] = []
        root = _origin_root(ctx.surface.base_url or ctx.target_url)

        for rel_path, label, matcher in _SENSITIVE_FILE_SPECS:
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

            signature = matcher(body)
            if not signature:
                continue

            findings.append(
                RawFinding(
                    check_id=self.id,
                    title=f"Exposed Sensitive File ({rel_path})",
                    owasp_category=self.owasp_category,
                    cwe_id=self.cwe_id,
                    severity=self.default_severity,
                    url=probe_url,
                    method="GET",
                    parameter=rel_path,
                    evidence={
                        "path": rel_path,
                        "artifact": label,
                        "status_code": str(resp.status_code),
                        "signature": signature,
                    },
                    confidence=Confidence.HIGH,
                )
            )

        return findings


__all__ = [
    "SensitiveFilesCheck",
]
