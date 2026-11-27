"""Active check for permissive Cross-Origin Resource Sharing (CORS) policies.

Pure Python (standard library + requests via ``ctx.http_client``) with zero
FastAPI, SQLAlchemy, Starlette, or Pydantic dependencies.
"""

from __future__ import annotations

from typing import ClassVar
from urllib.parse import urlsplit, urlunsplit

import requests

from backend.scanner.checks.base import BaseCheck, CheckContext
from backend.scanner.checks.passive._helpers import get_header
from backend.scanner.models import (
    CheckKind,
    Confidence,
    OWASPCategory,
    RawFinding,
    ScanProfile,
    Severity,
)
from backend.scanner.policy import ScopeViolationError

_UNTRUSTED_ORIGIN = "https://untrusted.example"
_MAX_DISCOVERED_PATHS = 10


def _strip_query_and_fragment(url: str) -> str:
    """Return ``url`` without query string or fragment for path-level probing."""
    parsed = urlsplit(url.strip())
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


class CORSMisconfigCheck(BaseCheck):
    """Detects overly permissive CORS response headers on the target origin."""

    id: ClassVar[str] = "cors_misconfig"
    name: ClassVar[str] = "Permissive Cross-Origin Resource Sharing (CORS) Policy"
    owasp_category: ClassVar[str] = OWASPCategory.A05
    cwe_id: ClassVar[str] = "CWE-942"
    kind: ClassVar[CheckKind] = CheckKind.ACTIVE
    default_severity: ClassVar[Severity] = Severity.HIGH
    profiles: ClassVar[frozenset[ScanProfile]] = frozenset(
        {ScanProfile.STANDARD, ScanProfile.DEEP}
    )
    description: ClassVar[str] = (
        "Sends an untrusted Origin header to the target root and up to 10 "
        "unique discovered paths to detect arbitrary origin reflection, null "
        "origin trust, or wildcard Access-Control-Allow-Origin headers."
    )

    @staticmethod
    def _collect_target_urls(ctx: CheckContext) -> list[str]:
        """Return target root plus up to 10 unique non-destructive discovered paths."""
        base_url = (ctx.surface.base_url or ctx.target_url).strip()
        root_url = _strip_query_and_fragment(base_url)

        candidates: list[str] = []
        seen_paths: set[str] = set()

        def _try_add(raw_url: str, *, count_toward_cap: bool) -> bool:
            if not raw_url:
                return False
            cleaned = _strip_query_and_fragment(raw_url)
            if not ctx.guardrail.is_same_origin(base_url, cleaned):
                return False
            if ctx.guardrail.is_destructive_path(cleaned):
                return False
            path_key = urlsplit(cleaned).path or "/"
            if path_key in seen_paths:
                return False
            if count_toward_cap and discovered_added >= _MAX_DISCOVERED_PATHS:
                return False
            seen_paths.add(path_key)
            candidates.append(cleaned)
            return True

        discovered_added = 0
        _try_add(root_url, count_toward_cap=False)

        for endpoint in ctx.surface.endpoints:
            if discovered_added >= _MAX_DISCOVERED_PATHS:
                break
            if _try_add(endpoint.url, count_toward_cap=True):
                discovered_added += 1

        return candidates

    def run(self, ctx: CheckContext) -> list[RawFinding]:
        if ctx.is_cancelled():
            return []

        findings: list[RawFinding] = []
        target_urls = self._collect_target_urls(ctx)

        for url in target_urls:
            if ctx.is_cancelled():
                break
            if ctx.guardrail.is_destructive_path(url):
                continue

            try:
                resp = ctx.http_client.get(
                    url,
                    headers={"Origin": _UNTRUSTED_ORIGIN},
                    follow_redirects=False,
                )
            except (requests.RequestException, ScopeViolationError):
                continue

            headers = dict(resp.headers)
            acao = (get_header(headers, "Access-Control-Allow-Origin") or "").strip()
            if not acao:
                continue

            acac_raw = (
                get_header(headers, "Access-Control-Allow-Credentials") or ""
            ).strip()
            allow_credentials = acac_raw.lower() == "true"
            acao_lower = acao.lower()

            severity: Severity | None = None
            issue = ""

            if acao_lower == _UNTRUSTED_ORIGIN:
                severity = Severity.HIGH
                if allow_credentials:
                    issue = (
                        "Reflects untrusted Origin with "
                        "Access-Control-Allow-Credentials: true"
                    )
                else:
                    issue = "Reflects arbitrary untrusted Origin header"
            elif acao_lower == "null":
                severity = Severity.HIGH
                if allow_credentials:
                    issue = (
                        "Allows 'null' Origin with "
                        "Access-Control-Allow-Credentials: true"
                    )
                else:
                    issue = "Allows 'null' Origin in Access-Control-Allow-Origin"
            elif acao == "*":
                if allow_credentials:
                    severity = Severity.HIGH
                    issue = (
                        "Combines wildcard Access-Control-Allow-Origin: * with "
                        "Access-Control-Allow-Credentials: true"
                    )
                else:
                    severity = Severity.LOW
                    issue = "Uses wildcard Access-Control-Allow-Origin: *"

            if severity is None:
                continue

            findings.append(
                RawFinding(
                    check_id=self.id,
                    title="Permissive Cross-Origin Resource Sharing (CORS) Policy",
                    owasp_category=self.owasp_category,
                    cwe_id=self.cwe_id,
                    severity=severity,
                    url=url,
                    method="GET",
                    parameter="Access-Control-Allow-Origin",
                    evidence={
                        "origin_sent": _UNTRUSTED_ORIGIN,
                        "access_control_allow_origin": acao[:200],
                        "access_control_allow_credentials": (
                            "true" if allow_credentials else (acac_raw[:50] or "false")
                        ),
                        "issue": issue,
                    },
                    confidence=Confidence.HIGH,
                )
            )

        return findings


__all__ = [
    "CORSMisconfigCheck",
]
