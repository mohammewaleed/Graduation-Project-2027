"""Shared pure-Python parsing helpers for passive OWASP security checks."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from backend.scanner.models import CachedResponse, ScanProfile

ALL_PROFILES: frozenset[ScanProfile] = frozenset(
    {ScanProfile.QUICK, ScanProfile.STANDARD, ScanProfile.DEEP}
)

SESSION_COOKIE_TOKENS: tuple[str, ...] = (
    "session",
    "sess",
    "sid",
    "phpsessid",
    "token",
    "auth",
    "jwt",
    "jsessionid",
)

# Split comma-joined Set-Cookie headers without splitting Expires=Wed, 21 Oct ...
_SET_COOKIE_SPLIT_RE = re.compile(r",\s*(?=[^;,\s=]+=)")


def get_header(headers: dict[str, str], name: str) -> str | None:
    """Case-insensitively fetch the first matching HTTP header value."""
    target = name.lower()
    for key, value in headers.items():
        if key.lower() == target:
            return value
    return None


def get_all_headers(headers: dict[str, str], name: str) -> list[str]:
    """Case-insensitively fetch all matching HTTP header values."""
    target = name.lower()
    return [value for key, value in headers.items() if key.lower() == target]


def extract_media_type(resp: CachedResponse) -> str:
    """Return the lowercased MIME media type for a cached response."""
    raw = resp.content_type or get_header(resp.headers, "Content-Type") or ""
    return raw.split(";", 1)[0].strip().lower()


def select_primary_responses(responses: list[CachedResponse]) -> list[CachedResponse]:
    """Prefer HTML or untyped responses when present, else return all responses."""
    html_like = [
        resp
        for resp in responses
        if not extract_media_type(resp)
        or extract_media_type(resp) in ("text/html", "application/xhtml+xml")
    ]
    return html_like if html_like else responses


def split_set_cookie_header(raw_header: str) -> list[str]:
    """Split a raw (possibly comma- or newline-joined) Set-Cookie header value."""
    if not raw_header or not raw_header.strip():
        return []
    cookies: list[str] = []
    for line in raw_header.splitlines():
        line = line.strip()
        if not line:
            continue
        for part in _SET_COOKIE_SPLIT_RE.split(line):
            cleaned = part.strip()
            if cleaned and "=" in cleaned.split(";", 1)[0]:
                cookies.append(cleaned)
    return cookies


def parse_set_cookie(raw_cookie: str) -> tuple[str, str, dict[str, str]]:
    """Parse a single Set-Cookie value into ``(name, value, attributes)``.

    Attribute keys are lowercased; flag attributes (e.g., ``HttpOnly``,
    ``Secure``) map to ``""`` while key=value attributes (e.g., ``SameSite``)
    map to their stripped, lowercased value.
    """
    segments = [seg.strip() for seg in raw_cookie.split(";") if seg.strip()]
    if not segments or "=" not in segments[0]:
        return ("", "", {})

    name, value = segments[0].split("=", 1)
    attrs: dict[str, str] = {}
    for attr in segments[1:]:
        if "=" in attr:
            k, v = attr.split("=", 1)
            attrs[k.strip().lower()] = v.strip().lower()
        else:
            attrs[attr.strip().lower()] = ""
    return (name.strip(), value.strip(), attrs)


def is_session_cookie(cookie_name: str) -> bool:
    """Return True if ``cookie_name`` resembles a session or auth cookie."""
    lowered = cookie_name.strip().lower()
    if not lowered:
        return False
    return any(token in lowered for token in SESSION_COOKIE_TOKENS)


def redact_set_cookie(raw_cookie: str, max_len: int = 300) -> str:
    """Redact the cookie value in a Set-Cookie string for safe evidence storage."""
    segments = [seg.strip() for seg in raw_cookie.split(";") if seg.strip()]
    if not segments:
        return ""
    head = segments[0]
    if "=" in head:
        name, _ = head.split("=", 1)
        redacted_head = f"{name.strip()}=<redacted>"
    else:
        redacted_head = head
    rebuilt = "; ".join([redacted_head, *segments[1:]])
    return rebuilt[:max_len]


def url_scheme(url: str) -> str:
    """Return lowercased URL scheme (e.g. 'http' or 'https'), or '' on error."""
    try:
        return urlsplit(url).scheme.lower()
    except ValueError:
        return ""


__all__ = [
    "ALL_PROFILES",
    "SESSION_COOKIE_TOKENS",
    "extract_media_type",
    "get_all_headers",
    "get_header",
    "is_session_cookie",
    "parse_set_cookie",
    "redact_set_cookie",
    "select_primary_responses",
    "split_set_cookie_header",
    "url_scheme",
]
