"""Passive checks for missing HTTP security headers and weak CSP policies."""

from __future__ import annotations

from typing import ClassVar

from backend.scanner.checks.base import BaseCheck, CheckContext
from backend.scanner.checks.passive._helpers import (
    ALL_PROFILES,
    get_header,
    select_primary_responses,
)
from backend.scanner.models import (
    CheckKind,
    Confidence,
    OWASPCategory,
    RawFinding,
    ScanProfile,
    Severity,
)

_CANONICAL_HEADERS: tuple[str, ...] = (
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)


def _parse_csp_directives(csp_value: str) -> dict[str, list[str]]:
    """Parse a Content-Security-Policy header into ``{directive: [tokens]}``."""
    directives: dict[str, list[str]] = {}
    for raw_directive in csp_value.split(";"):
        parts = raw_directive.strip().split()
        if not parts:
            continue
        name = parts[0].lower()
        tokens = [tok.lower() for tok in parts[1:]]
        directives.setdefault(name, []).extend(tokens)
    return directives


class MissingSecurityHeadersCheck(BaseCheck):
    """Flags origins missing baseline defensive HTTP security headers."""

    id: ClassVar[str] = "missing_security_headers"
    name: ClassVar[str] = "Missing Security Headers"
    owasp_category: ClassVar[str] = OWASPCategory.A05
    cwe_id: ClassVar[str] = "CWE-693"
    kind: ClassVar[CheckKind] = CheckKind.PASSIVE
    default_severity: ClassVar[Severity] = Severity.MEDIUM
    profiles: ClassVar[frozenset[ScanProfile]] = ALL_PROFILES
    description: ClassVar[str] = (
        "Checks per-origin HTTP responses for missing Content-Security-Policy, "
        "X-Frame-Options (or CSP frame-ancestors), X-Content-Type-Options, "
        "Referrer-Policy, and Permissions-Policy headers."
    )

    def run(self, ctx: CheckContext) -> list[RawFinding]:
        if ctx.is_cancelled():
            return []

        origin_responses = ctx.responses.by_origin(ctx.target_url)
        if not origin_responses:
            return []

        target_responses = select_primary_responses(origin_responses)
        missing_set: set[str] = set()
        sample_url: str | None = None

        for resp in target_responses:
            csp = (get_header(resp.headers, "Content-Security-Policy") or "").strip()
            csp_directives = _parse_csp_directives(csp) if csp else {}
            xfo = (get_header(resp.headers, "X-Frame-Options") or "").strip()
            xcto = (get_header(resp.headers, "X-Content-Type-Options") or "").strip()
            referrer = (get_header(resp.headers, "Referrer-Policy") or "").strip()
            permissions = (get_header(resp.headers, "Permissions-Policy") or "").strip()

            resp_missing: list[str] = []
            if not csp:
                resp_missing.append("Content-Security-Policy")

            has_frame_ancestors = bool(csp_directives.get("frame-ancestors"))
            if not xfo and not has_frame_ancestors:
                resp_missing.append("X-Frame-Options")

            if "nosniff" not in xcto.lower():
                resp_missing.append("X-Content-Type-Options")

            if not referrer:
                resp_missing.append("Referrer-Policy")

            if not permissions:
                resp_missing.append("Permissions-Policy")

            if resp_missing:
                if sample_url is None:
                    sample_url = resp.url
                missing_set.update(resp_missing)

        if not missing_set:
            return []

        ordered_missing = [h for h in _CANONICAL_HEADERS if h in missing_set]
        missing_summary = ", ".join(ordered_missing)

        return [
            RawFinding(
                check_id=self.id,
                title=f"Missing Security Headers ({missing_summary})",
                owasp_category=self.owasp_category,
                cwe_id=self.cwe_id,
                severity=self.default_severity,
                url=sample_url or ctx.target_url,
                method="GET",
                parameter=None,
                evidence={
                    "missing_headers": missing_summary,
                    "sample_url": sample_url or ctx.target_url,
                },
                confidence=Confidence.HIGH,
            )
        ]


class WeakCSPCheck(BaseCheck):
    """Flags permissive or incomplete Content-Security-Policy headers."""

    id: ClassVar[str] = "weak_csp"
    name: ClassVar[str] = "Weak Content Security Policy (CSP)"
    owasp_category: ClassVar[str] = OWASPCategory.A05
    cwe_id: ClassVar[str] = "CWE-693"
    kind: ClassVar[CheckKind] = CheckKind.PASSIVE
    default_severity: ClassVar[Severity] = Severity.MEDIUM
    profiles: ClassVar[frozenset[ScanProfile]] = ALL_PROFILES
    description: ClassVar[str] = (
        "Evaluates present Content-Security-Policy headers for unsafe-inline, "
        "unsafe-eval, wildcard '*' in script-src/default-src, or missing both "
        "default-src and object-src."
    )

    def run(self, ctx: CheckContext) -> list[RawFinding]:
        if ctx.is_cancelled():
            return []

        origin_responses = ctx.responses.by_origin(ctx.target_url)
        if not origin_responses:
            return []

        findings: list[RawFinding] = []
        seen_policies: set[str] = set()

        for resp in origin_responses:
            csp = (get_header(resp.headers, "Content-Security-Policy") or "").strip()
            if not csp:
                continue

            normalized_policy = " ".join(csp.split())
            if normalized_policy in seen_policies:
                continue

            directives = _parse_csp_directives(csp)
            issues: list[str] = []

            all_tokens = [
                tok.strip("'\"")
                for token_list in directives.values()
                for tok in token_list
            ]
            if "unsafe-inline" in all_tokens:
                issues.append("Allows 'unsafe-inline'")
            if "unsafe-eval" in all_tokens:
                issues.append("Allows 'unsafe-eval'")

            wildcard_dirs: list[str] = []
            for directive_name in ("script-src", "default-src"):
                tokens = directives.get(directive_name, [])
                if any(tok in ("*", "http://*", "https://*") for tok in tokens):
                    wildcard_dirs.append(directive_name)
            if wildcard_dirs:
                issues.append(f"Wildcard '*' in {', '.join(wildcard_dirs)}")

            if "default-src" not in directives and "object-src" not in directives:
                issues.append("Missing both default-src and object-src directives")

            if issues:
                seen_policies.add(normalized_policy)
                findings.append(
                    RawFinding(
                        check_id=self.id,
                        title="Weak Content-Security-Policy Configuration",
                        owasp_category=self.owasp_category,
                        cwe_id=self.cwe_id,
                        severity=self.default_severity,
                        url=resp.url,
                        method="GET",
                        parameter="Content-Security-Policy",
                        evidence={
                            "header": "Content-Security-Policy",
                            "value": normalized_policy[:400],
                            "issues": "; ".join(issues),
                        },
                        confidence=Confidence.HIGH,
                    )
                )

        return findings


__all__ = [
    "MissingSecurityHeadersCheck",
    "WeakCSPCheck",
]
