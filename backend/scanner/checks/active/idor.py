"""Active heuristic check for Potential Insecure Direct Object References (IDOR).

Inspects discovered endpoints containing numeric identifier query parameters
(``id``, ``user_id``, ``account_id``, ``order_id``, ``profile_id``) or numeric
URL path segments (such as ``/users/1`` or ``/api/orders/42``). Requests an
adjacent integer (``id + 1`` or ``id - 1``) and records a low-confidence
(tentative) finding when an HTTP 200 response returns a distinct, non-empty,
non-Soft-404 record so developers can manually verify object-level ownership
enforcement.

Pure Python (standard library + ``requests`` via ``ctx.http_client``) with zero
FastAPI, SQLAlchemy, Starlette, or Pydantic dependencies.
"""

from __future__ import annotations

import re
from typing import ClassVar
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

from backend.scanner.checks.base import BaseCheck, CheckContext
from backend.scanner.http_client import (
    RequestLimitExceededError,
    ScanCancelledError,
)
from backend.scanner.models import (
    CheckKind,
    Confidence,
    OWASPCategory,
    RawFinding,
    ScanProfile,
    Severity,
)
from backend.scanner.policy import ScopeViolationError

ID_PARAM_NAMES: frozenset[str] = frozenset(
    {
        "id",
        "user_id",
        "userid",
        "account_id",
        "accountid",
        "order_id",
        "orderid",
        "profile_id",
        "profileid",
        "item_id",
        "doc_id",
        "record_id",
        "uid",
    }
)

_NUMERIC_SEGMENT_RE = re.compile(r"^\d+$")


def _is_id_param_name(name: str) -> bool:
    """Return True if ``name`` matches a common object identifier parameter name."""
    lowered = (name or "").strip().lower()
    if not lowered:
        return False
    return lowered in ID_PARAM_NAMES or lowered.endswith("_id")


def _is_soft_404(ctx: CheckContext, status_code: int, body: str) -> bool:
    """Return True if the response matches a 404 or the calibrated Soft-404 fingerprint."""
    if status_code == 404:
        return True
    if ctx.soft_404 is not None and ctx.soft_404.is_soft_404(status_code, body):
        return True
    return False


def _adjacent_ids(orig_id: int) -> tuple[int, ...]:
    """Return adjacent integer candidates to probe for ``orig_id``."""
    if orig_id > 1:
        return (orig_id + 1, orig_id - 1)
    if orig_id == 1:
        return (2,)
    return (orig_id + 1,)


def _fetch_get(ctx: CheckContext, url: str) -> requests.Response | None:
    """Send a scope-validated GET request, returning None on transient network error."""
    try:
        return ctx.http_client.get(url, follow_redirects=True)
    except (ScanCancelledError, RequestLimitExceededError):
        raise
    except (ScopeViolationError, requests.RequestException):
        return None


def _get_baseline_body(ctx: CheckContext, url: str) -> tuple[int, str] | None:
    """Return ``(status_code, stripped_body)`` from cache or a live GET request."""
    cached = ctx.responses.get(url)
    if cached is not None:
        return (cached.status_code, (cached.body or "").strip())
    resp = _fetch_get(ctx, url)
    if resp is None:
        return None
    return (resp.status_code, (resp.text or "").strip())


class IDORHeuristicCheck(BaseCheck):
    """Probes adjacent numeric IDs in query parameters and path segments."""

    id: ClassVar[str] = "idor_heuristic"
    name: ClassVar[str] = "Potential Insecure Direct Object Reference (IDOR)"
    owasp_category: ClassVar[str] = OWASPCategory.A01
    cwe_id: ClassVar[str] = "CWE-639"
    kind: ClassVar[CheckKind] = CheckKind.ACTIVE
    default_severity: ClassVar[Severity] = Severity.MEDIUM
    profiles: ClassVar[frozenset[ScanProfile]] = frozenset({ScanProfile.DEEP})
    description: ClassVar[str] = (
        "Tests adjacent numeric identifiers (id + 1 / id - 1) on discovered "
        "query parameters and URL path segments, emitting a low-confidence "
        "tentative finding when a distinct HTTP 200 record is returned."
    )

    def run(self, ctx: CheckContext) -> list[RawFinding]:
        if ctx.is_cancelled():
            return []

        candidate_urls: list[tuple[str, list[str]]] = []
        seen_urls: set[str] = set()

        for ep in ctx.surface.endpoints:
            if (ep.method or "GET").strip().upper() != "GET":
                continue
            if not ep.url or ep.url in seen_urls:
                continue
            if not ctx.guardrail.is_same_origin(ctx.target_url, ep.url):
                continue
            if ctx.guardrail.is_destructive_path(ep.url):
                continue
            seen_urls.add(ep.url)
            candidate_urls.append((ep.url, list(ep.params)))

        for cached in ctx.responses.by_origin(ctx.target_url):
            if not cached.url or cached.url in seen_urls:
                continue
            if not ctx.guardrail.is_same_origin(ctx.target_url, cached.url):
                continue
            if ctx.guardrail.is_destructive_path(cached.url):
                continue
            seen_urls.add(cached.url)
            candidate_urls.append((cached.url, []))

        findings: list[RawFinding] = []
        seen_targets: set[tuple[str, str]] = set()

        for raw_url, declared_params in candidate_urls:
            if ctx.is_cancelled():
                break

            parsed = urlsplit(raw_url)
            norm_path = parsed.path or "/"

            # 1. Check numeric ID query parameters
            query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
            param_map: dict[str, str] = {}
            for k, v in query_pairs:
                if k:
                    param_map[k] = v if v != "" else "1"
            for p in declared_params:
                if p and p not in param_map and _is_id_param_name(p):
                    param_map[p] = "1"

            for param_name, raw_val in param_map.items():
                if ctx.is_cancelled():
                    break
                if not _is_id_param_name(param_name):
                    continue
                if not _NUMERIC_SEGMENT_RE.match(raw_val.strip()):
                    continue

                target_key = (norm_path, param_name.lower())
                if target_key in seen_targets:
                    continue
                seen_targets.add(target_key)

                orig_id = int(raw_val.strip())
                base_url = urlunsplit(
                    (
                        parsed.scheme,
                        parsed.netloc,
                        norm_path,
                        urlencode(list(param_map.items())),
                        "",
                    )
                )
                baseline = _get_baseline_body(ctx, base_url)
                if baseline is None:
                    continue
                base_status, base_body = baseline
                if (
                    base_status != 200
                    or not base_body
                    or _is_soft_404(ctx, base_status, base_body)
                ):
                    continue

                for adj_id in _adjacent_ids(orig_id):
                    if ctx.is_cancelled():
                        break
                    mutated_map = dict(param_map)
                    mutated_map[param_name] = str(adj_id)
                    adj_url = urlunsplit(
                        (
                            parsed.scheme,
                            parsed.netloc,
                            norm_path,
                            urlencode(list(mutated_map.items())),
                            "",
                        )
                    )
                    resp = _fetch_get(ctx, adj_url)
                    if resp is None or resp.status_code != 200:
                        continue

                    adj_body = (resp.text or "").strip()
                    if (
                        not adj_body
                        or adj_body == base_body
                        or _is_soft_404(ctx, resp.status_code, adj_body)
                    ):
                        continue

                    findings.append(
                        RawFinding(
                            check_id=self.id,
                            title=(
                                "Potential Insecure Direct Object Reference "
                                "(IDOR — Manual Verification Needed)"
                            ),
                            owasp_category=self.owasp_category,
                            cwe_id=self.cwe_id,
                            severity=self.default_severity,
                            url=raw_url,
                            method="GET",
                            parameter=param_name,
                            evidence={
                                "original_id": str(orig_id),
                                "probed_id": str(adj_id),
                                "probed_url": adj_url,
                                "status_code": str(resp.status_code),
                                "note": (
                                    "Adjacent numeric ID returned a distinct HTTP 200 "
                                    "response. Manually verify object-level ownership checks."
                                ),
                            },
                            confidence=Confidence.LOW,
                        )
                    )
                    break

            # 2. Check numeric path segments (e.g. /users/1 or /api/orders/42)
            segments = norm_path.split("/")
            for seg_idx, segment in enumerate(segments):
                if ctx.is_cancelled():
                    break
                if not _NUMERIC_SEGMENT_RE.match(segment):
                    continue

                orig_id = int(segment)
                pattern_segments = list(segments)
                pattern_segments[seg_idx] = "{id}"
                pattern_path = "/".join(pattern_segments)
                target_key = (pattern_path, f"path_segment_{seg_idx}")
                if target_key in seen_targets:
                    continue
                seen_targets.add(target_key)

                baseline = _get_baseline_body(ctx, raw_url)
                if baseline is None:
                    continue
                base_status, base_body = baseline
                if (
                    base_status != 200
                    or not base_body
                    or _is_soft_404(ctx, base_status, base_body)
                ):
                    continue

                prev_segment = segments[seg_idx - 1] if seg_idx > 0 and segments[seg_idx - 1] else "id"
                param_label = f"{prev_segment}_id" if prev_segment != "id" else "id"

                for adj_id in _adjacent_ids(orig_id):
                    if ctx.is_cancelled():
                        break
                    adj_segments = list(segments)
                    adj_segments[seg_idx] = str(adj_id)
                    adj_path = "/".join(adj_segments)
                    adj_url = urlunsplit(
                        (
                            parsed.scheme,
                            parsed.netloc,
                            adj_path,
                            parsed.query,
                            "",
                        )
                    )
                    if ctx.guardrail.is_destructive_path(adj_url):
                        continue

                    resp = _fetch_get(ctx, adj_url)
                    if resp is None or resp.status_code != 200:
                        continue

                    adj_body = (resp.text or "").strip()
                    if (
                        not adj_body
                        or adj_body == base_body
                        or _is_soft_404(ctx, resp.status_code, adj_body)
                    ):
                        continue

                    findings.append(
                        RawFinding(
                            check_id=self.id,
                            title=(
                                "Potential Insecure Direct Object Reference "
                                "(IDOR — Manual Verification Needed)"
                            ),
                            owasp_category=self.owasp_category,
                            cwe_id=self.cwe_id,
                            severity=self.default_severity,
                            url=raw_url,
                            method="GET",
                            parameter=param_label,
                            evidence={
                                "original_id": str(orig_id),
                                "probed_id": str(adj_id),
                                "probed_url": adj_url,
                                "status_code": str(resp.status_code),
                                "note": (
                                    "Adjacent numeric path ID returned a distinct HTTP 200 "
                                    "response. Manually verify object-level ownership checks."
                                ),
                            },
                            confidence=Confidence.LOW,
                        )
                    )
                    break

        return findings


__all__ = [
    "IDORHeuristicCheck",
    "ID_PARAM_NAMES",
]
