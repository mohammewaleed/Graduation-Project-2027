"""Active check for unvalidated open redirects on redirect-named parameters.

Pure Python (standard library + requests via ``ctx.http_client``) with zero
FastAPI, SQLAlchemy, Starlette, or Pydantic dependencies.
"""

from __future__ import annotations

from typing import ClassVar
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

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

_REDIRECT_PARAM_NAMES: frozenset[str] = frozenset(
    {
        "next",
        "url",
        "redirect",
        "redirect_url",
        "return",
        "return_to",
        "goto",
        "dest",
        "continue",
    }
)

_REDIRECT_TARGET_HOST = "untrusted.example"
_REDIRECT_PROBE_URL = "https://untrusted.example/check"


def _replace_query_param(url: str, param_name: str, new_value: str) -> str:
    """Return ``url`` with query parameter ``param_name`` set to ``new_value``."""
    parsed = urlsplit(url)
    existing_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    updated_pairs: list[tuple[str, str]] = []

    for key, val in existing_pairs:
        if key == param_name:
            if not replaced:
                updated_pairs.append((key, new_value))
                replaced = True
        else:
            updated_pairs.append((key, val))

    if not replaced:
        updated_pairs.append((param_name, new_value))

    new_query = urlencode(updated_pairs)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", new_query, ""))


def _strip_query(url: str) -> str:
    """Return ``url`` without query string or fragment."""
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))


def _targets_untrusted_host(location: str) -> bool:
    """Return True if a redirect ``Location`` header targets ``untrusted.example``."""
    cleaned = (location or "").strip()
    if not cleaned:
        return False

    try:
        parsed = urlsplit(cleaned)
    except ValueError:
        return False

    hostname = (parsed.hostname or "").lower()
    if hostname == _REDIRECT_TARGET_HOST:
        return True

    lowered = cleaned.lower()
    return lowered.startswith(
        (
            f"https://{_REDIRECT_TARGET_HOST}",
            f"http://{_REDIRECT_TARGET_HOST}",
            f"//{_REDIRECT_TARGET_HOST}",
        )
    )


class OpenRedirectCheck(BaseCheck):
    """Detects unvalidated open redirects on endpoints and HTML forms."""

    id: ClassVar[str] = "open_redirect"
    name: ClassVar[str] = "Unvalidated Open Redirect"
    owasp_category: ClassVar[str] = OWASPCategory.A01
    cwe_id: ClassVar[str] = "CWE-601"
    kind: ClassVar[CheckKind] = CheckKind.ACTIVE
    default_severity: ClassVar[Severity] = Severity.MEDIUM
    profiles: ClassVar[frozenset[ScanProfile]] = frozenset(
        {ScanProfile.STANDARD, ScanProfile.DEEP}
    )
    description: ClassVar[str] = (
        "Tests redirect-oriented query and form parameters with an external "
        "canary destination (follow_redirects=False) and flags 3xx responses "
        "whose Location header redirects to the untrusted domain."
    )

    def run(self, ctx: CheckContext) -> list[RawFinding]:
        if ctx.is_cancelled():
            return []

        findings: list[RawFinding] = []
        seen_probes: set[tuple[str, str, str]] = set()
        base_url = (ctx.surface.base_url or ctx.target_url).strip()

        # 1. Inspect discovered endpoints (plus ctx.target_url if it has query params)
        endpoint_candidates: list[tuple[str, list[str]]] = []
        for ep in ctx.surface.endpoints:
            query_keys = [
                k for k, _ in parse_qsl(urlsplit(ep.url).query, keep_blank_values=True) if k
            ]
            merged_params = list(dict.fromkeys([*ep.params, *query_keys]))
            endpoint_candidates.append((ep.url, merged_params))

        target_query_keys = [
            k
            for k, _ in parse_qsl(urlsplit(ctx.target_url).query, keep_blank_values=True)
            if k
        ]
        if target_query_keys:
            endpoint_candidates.append((ctx.target_url, target_query_keys))

        for ep_url, params in endpoint_candidates:
            if ctx.is_cancelled():
                break
            if not ctx.guardrail.is_same_origin(base_url, ep_url):
                continue
            if ctx.guardrail.is_destructive_path(ep_url):
                continue

            clean_url = _strip_query(ep_url)
            for param in params:
                if ctx.is_cancelled():
                    break
                if param.strip().lower() not in _REDIRECT_PARAM_NAMES:
                    continue

                probe_key = ("GET", clean_url, param.strip().lower())
                if probe_key in seen_probes:
                    continue
                seen_probes.add(probe_key)

                probe_url = _replace_query_param(ep_url, param, _REDIRECT_PROBE_URL)
                try:
                    resp = ctx.http_client.get(probe_url, follow_redirects=False)
                except (requests.RequestException, ScopeViolationError):
                    continue

                if 300 <= resp.status_code < 400:
                    location = (
                        get_header(dict(resp.headers), "Location") or ""
                    ).strip()
                    if _targets_untrusted_host(location):
                        findings.append(
                            RawFinding(
                                check_id=self.id,
                                title="Unvalidated Open Redirect",
                                owasp_category=self.owasp_category,
                                cwe_id=self.cwe_id,
                                severity=self.default_severity,
                                url=clean_url,
                                method="GET",
                                parameter=param,
                                evidence={
                                    "parameter": param,
                                    "probe": _REDIRECT_PROBE_URL,
                                    "status_code": str(resp.status_code),
                                    "location": location[:300],
                                },
                                confidence=Confidence.HIGH,
                            )
                        )

        # 2. Inspect discovered HTML forms
        for form in ctx.surface.forms:
            if ctx.is_cancelled():
                break
            action_url = form.action_url
            if not ctx.guardrail.is_same_origin(base_url, action_url):
                continue
            if ctx.guardrail.is_destructive_path(action_url):
                continue

            method = (form.method or "GET").strip().upper()
            clean_action = _strip_query(action_url)

            for target_input in form.inputs:
                if ctx.is_cancelled():
                    break
                param_name = (target_input.name or "").strip()
                if not param_name or param_name.lower() not in _REDIRECT_PARAM_NAMES:
                    continue

                probe_key = (method, clean_action, param_name.lower())
                if probe_key in seen_probes:
                    continue
                seen_probes.add(probe_key)

                form_data: dict[str, str] = {}
                for inp in form.inputs:
                    if not inp.name:
                        continue
                    if inp.name == param_name:
                        form_data[inp.name] = _REDIRECT_PROBE_URL
                    else:
                        form_data[inp.name] = inp.value or "test"

                try:
                    if method == "POST":
                        resp = ctx.http_client.post(
                            action_url,
                            data=form_data,
                            follow_redirects=False,
                        )
                    else:
                        query_str = urlencode(form_data)
                        parsed_action = urlsplit(action_url)
                        get_url = urlunsplit(
                            (
                                parsed_action.scheme,
                                parsed_action.netloc,
                                parsed_action.path or "/",
                                query_str,
                                "",
                            )
                        )
                        resp = ctx.http_client.get(get_url, follow_redirects=False)
                except (requests.RequestException, ScopeViolationError):
                    continue

                if 300 <= resp.status_code < 400:
                    location = (
                        get_header(dict(resp.headers), "Location") or ""
                    ).strip()
                    if _targets_untrusted_host(location):
                        findings.append(
                            RawFinding(
                                check_id=self.id,
                                title="Unvalidated Open Redirect",
                                owasp_category=self.owasp_category,
                                cwe_id=self.cwe_id,
                                severity=self.default_severity,
                                url=clean_action,
                                method=method,
                                parameter=param_name,
                                evidence={
                                    "parameter": param_name,
                                    "probe": _REDIRECT_PROBE_URL,
                                    "status_code": str(resp.status_code),
                                    "location": location[:300],
                                },
                                confidence=Confidence.HIGH,
                            )
                        )

        return findings


__all__ = [
    "OpenRedirectCheck",
]
