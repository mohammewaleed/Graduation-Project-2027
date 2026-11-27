"""Passive check for outdated client-side JavaScript libraries."""

from __future__ import annotations

import re
from typing import ClassVar
from urllib.parse import parse_qsl, urljoin, urlsplit

from bs4 import BeautifulSoup
from packaging.version import InvalidVersion, Version

from backend.scanner.checks.base import BaseCheck, CheckContext
from backend.scanner.checks.passive._helpers import ALL_PROFILES, extract_media_type
from backend.scanner.models import (
    CheckKind,
    Confidence,
    OWASPCategory,
    RawFinding,
    ScanProfile,
    Severity,
)

try:
    import lxml.etree as _lxml_etree  # noqa: F401

    _BS4_PARSER = "lxml"
except ImportError:
    _BS4_PARSER = "html.parser"

# Bundled minimum safe versions for widely used client-side JS libraries.
MIN_SAFE_JS_VERSIONS: dict[str, tuple[str, str]] = {
    "jquery": ("jQuery", "3.5.0"),
    "lodash": ("Lodash", "4.17.21"),
    "bootstrap": ("Bootstrap", "4.6.2"),
    "angular": ("AngularJS", "1.8.3"),
    "moment": ("Moment.js", "2.29.4"),
}

_LIB_ALIAS_MAP: dict[str, str] = {
    "jquery": "jquery",
    "lodash": "lodash",
    "lodash.js": "lodash",
    "bootstrap": "bootstrap",
    "twitter-bootstrap": "bootstrap",
    "angular": "angular",
    "angularjs": "angular",
    "angular.js": "angular",
    "moment": "moment",
    "moment.js": "moment",
}

# Matches filename or @version CDN formats, e.g.:
#   jquery-3.4.1.min.js, lodash@4.17.15/lodash.min.js, bootstrap-4.5.0.bundle.min.js
_SCRIPT_DIRECT_RE = re.compile(
    r"(?:^|[/\\])(?:twitter-)?(jquery|bootstrap|angular(?:js)?|lodash|moment)"
    r"(?:\.js)?[-@._]+v?(\d+\.\d+(?:\.\d+)?)(?=[.\-_/@?#]|$)",
    re.IGNORECASE,
)

# Matches CDN directory path formats, e.g.:
#   /ajax/libs/jquery/3.4.1/jquery.min.js
#   /ajax/libs/angular.js/1.7.9/angular.min.js
_SCRIPT_CDN_PATH_RE = re.compile(
    r"/(?:twitter-)?(jquery|bootstrap|angular(?:\.js|js)?|lodash(?:\.js)?|moment(?:\.js)?)"
    r"/v?(\d+\.\d+(?:\.\d+)?)/",
    re.IGNORECASE,
)

# Matches unversioned library filename when version is supplied via ?v= / ?ver=
_SCRIPT_FILENAME_RE = re.compile(
    r"(?:^|[/\\])(?:twitter-)?(jquery|bootstrap|angular(?:js)?|lodash|moment)"
    r"(?:\.bundle)?(?:\.min)?\.js$",
    re.IGNORECASE,
)

_SEMVER_RE = re.compile(r"^v?(\d+\.\d+(?:\.\d+)?)$", re.IGNORECASE)

# Optional header comment banner patterns inside cached JS files.
_JS_BANNER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("jquery", re.compile(r"jQuery\s+(?:JavaScript\s+Library\s+)?v(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("bootstrap", re.compile(r"Bootstrap\s+v(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("angular", re.compile(r"AngularJS\s+v(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("lodash", re.compile(r"Lo-?Dash\s+v?(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("moment", re.compile(r"moment\.js\s*(?:\r?\n)?\s*(?://!?\s*)?version\s*:\s*(\d+\.\d+\.\d+)", re.IGNORECASE)),
)


def _normalize_lib(raw_name: str) -> str | None:
    return _LIB_ALIAS_MAP.get(raw_name.strip().lower())


def _extract_library_from_url(script_url: str) -> tuple[str, str] | None:
    """Extract ``(canonical_lib, version_str)`` from a script URL or path."""
    if not script_url:
        return None

    parsed = urlsplit(script_url)
    path = parsed.path or script_url

    for pattern in (_SCRIPT_CDN_PATH_RE, _SCRIPT_DIRECT_RE):
        match = pattern.search(path)
        if match is not None:
            lib = _normalize_lib(match.group(1))
            if lib is not None:
                return (lib, match.group(2))

    fname_match = _SCRIPT_FILENAME_RE.search(path)
    if fname_match is not None and parsed.query:
        lib = _normalize_lib(fname_match.group(1))
        if lib is not None:
            for key, val in parse_qsl(parsed.query, keep_blank_values=False):
                if key.lower() in ("v", "ver", "version"):
                    ver_match = _SEMVER_RE.match(val.strip())
                    if ver_match is not None:
                        return (lib, ver_match.group(1))

    return None


class OutdatedJSComponentsCheck(BaseCheck):
    """Detects known-vulnerable versions of common client-side JS libraries."""

    id: ClassVar[str] = "outdated_js_components"
    name: ClassVar[str] = "Outdated Client-Side JavaScript Component"
    owasp_category: ClassVar[str] = OWASPCategory.A06
    cwe_id: ClassVar[str] = "CWE-1104"
    kind: ClassVar[CheckKind] = CheckKind.PASSIVE
    default_severity: ClassVar[Severity] = Severity.MEDIUM
    profiles: ClassVar[frozenset[ScanProfile]] = ALL_PROFILES
    description: ClassVar[str] = (
        "Extracts versions of jQuery, Bootstrap, AngularJS, Lodash, and Moment.js "
        "from script references and flags versions below known-safe thresholds."
    )

    def run(self, ctx: CheckContext) -> list[RawFinding]:
        if ctx.is_cancelled():
            return []

        # Collect (script_url, source_page_url) candidates from surface and cached HTML.
        candidates: list[tuple[str, str]] = [
            (script_url, script_url) for script_url in ctx.surface.scripts
        ]

        origin_responses = ctx.responses.by_origin(ctx.target_url)
        for resp in origin_responses:
            if not resp.body:
                continue
            media = extract_media_type(resp)
            if not media or media in ("text/html", "application/xhtml+xml"):
                soup = BeautifulSoup(resp.body, _BS4_PARSER)
                for tag in soup.find_all("script", src=True):
                    raw_src = str(tag.get("src") or "").strip()
                    if not raw_src:
                        continue
                    resolved = urljoin(resp.url, raw_src)
                    candidates.append((resolved, resp.url))

        findings: list[RawFinding] = []
        seen: set[tuple[str, str]] = set()

        def maybe_record(
            lib: str,
            version_str: str,
            script_url: str,
            source_url: str,
        ) -> None:
            threshold = MIN_SAFE_JS_VERSIONS.get(lib)
            if threshold is None:
                return
            display_name, min_safe_str = threshold
            try:
                detected_ver = Version(version_str)
                min_safe_ver = Version(min_safe_str)
            except InvalidVersion:
                return

            if detected_ver >= min_safe_ver:
                return

            dedup_key = (lib, str(detected_ver))
            if dedup_key in seen:
                return
            seen.add(dedup_key)

            findings.append(
                RawFinding(
                    check_id=self.id,
                    title=f"Outdated JavaScript Library: {display_name} {detected_ver}",
                    owasp_category=self.owasp_category,
                    cwe_id=self.cwe_id,
                    severity=self.default_severity,
                    url=source_url,
                    method="GET",
                    parameter=lib,
                    evidence={
                        "library": display_name,
                        "detected_version": str(detected_ver),
                        "minimum_safe_version": min_safe_str,
                        "script_url": script_url[:300],
                    },
                    confidence=Confidence.HIGH,
                )
            )

        for script_url, source_url in candidates:
            extracted = _extract_library_from_url(script_url)
            if extracted is not None:
                lib, ver_str = extracted
                maybe_record(lib, ver_str, script_url, source_url)

        # Fallback: inspect cached JavaScript bodies for library version banners.
        for resp in origin_responses:
            media = extract_media_type(resp)
            if media not in ("text/javascript", "application/javascript") or not resp.body:
                continue
            head = resp.body[:2048]
            for lib, pattern in _JS_BANNER_PATTERNS:
                match = pattern.search(head)
                if match is not None:
                    maybe_record(lib, match.group(1), resp.url, resp.url)

        return findings


__all__ = [
    "MIN_SAFE_JS_VERSIONS",
    "OutdatedJSComponentsCheck",
]
