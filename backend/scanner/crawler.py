"""Bounded BFS web crawler, URL normalizer, and response cache.

Pure Python (standard library + BeautifulSoup4) with zero FastAPI or
SQLAlchemy dependencies. Discovers same-origin endpoints, HTML forms,
scripts, ``robots.txt`` / ``sitemap.xml`` entries, and inline JS API route
hints while strictly enforcing scope guardrails, destructive-path filtering,
depth/page/time limits, and cooperative cancellation.
"""

from __future__ import annotations

import re
import time
import xml.etree.ElementTree as ET
from collections import deque
from collections.abc import Callable
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import requests
from bs4 import BeautifulSoup

from backend.scanner.http_client import (
    RequestLimitExceededError,
    ScanCancelledError,
    ScannerHttpClient,
)
from backend.scanner.models import (
    AttackSurface,
    CachedResponse,
    EndpointRecord,
    FormInput,
    FormRecord,
)
from backend.scanner.policy import ScopeGuardrail, ScopeViolationError

try:
    import lxml.etree as _lxml_etree  # noqa: F401

    _BS4_PARSER = "lxml"
except ImportError:
    _BS4_PARSER = "html.parser"

_BINARY_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".webp",
        ".pdf",
        ".zip",
        ".woff",
        ".woff2",
        ".ttf",
        ".css",
        ".mp4",
        ".mp3",
    }
)

_PARSEABLE_CONTENT_TYPES: frozenset[str] = frozenset(
    {
        "text/html",
        "application/xhtml+xml",
        "text/javascript",
        "application/javascript",
    }
)

_HTML_CONTENT_TYPES: frozenset[str] = frozenset(
    {
        "text/html",
        "application/xhtml+xml",
    }
)

_JS_CONTENT_TYPES: frozenset[str] = frozenset(
    {
        "text/javascript",
        "application/javascript",
    }
)

_JS_API_ROUTE_RE = re.compile(r"/api/[A-Za-z0-9_./-]+")
_SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)

ProgressCallback = Callable[[int, int, str], None]


def normalize_url(url: str, base_url: str | None = None) -> str:
    """Resolve and canonicalize an HTTP(S) URL.

    Resolves relative URLs against ``base_url``, strips fragments, lowercases
    scheme and hostname, drops default ports (80 for http, 443 for https),
    normalizes an empty path to ``/``, and sorts query parameters
    deterministically.
    """
    raw = (url or "").strip()
    if base_url:
        raw = urljoin(base_url, raw)

    parsed = urlsplit(raw)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        return urlunsplit((scheme, parsed.netloc, parsed.path, parsed.query, ""))

    hostname = (parsed.hostname or "").lower()
    try:
        port = parsed.port
    except ValueError:
        port = None

    if ":" in hostname and not hostname.startswith("["):
        host_part = f"[{hostname}]"
    else:
        host_part = hostname

    if port is not None and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        netloc = f"{host_part}:{port}"
    else:
        netloc = host_part

    path = parsed.path or "/"
    query_pairs = sorted(parse_qsl(parsed.query, keep_blank_values=True))
    query = urlencode(query_pairs)

    return urlunsplit((scheme, netloc, path, query, ""))


def _origin_tuple(url: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https") or not parsed.hostname:
        return None
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError:
        return None
    return (scheme, parsed.hostname.lower(), port)


def _extract_media_type(content_type: str) -> str:
    return (content_type or "").split(";", 1)[0].strip().lower()


def _is_binary_asset_url(url: str) -> bool:
    path = (urlsplit(url).path or "").lower()
    return any(path.endswith(ext) for ext in _BINARY_EXTENSIONS)


def _is_cacheable_media_type(media_type: str) -> bool:
    if not media_type:
        return True
    if media_type in _PARSEABLE_CONTENT_TYPES:
        return True
    if media_type.startswith("text/"):
        return True
    return media_type in ("application/json", "application/xml")


class ResponseCache:
    """In-memory bounded cache of HTTP responses keyed by normalized URL."""

    def __init__(
        self,
        max_body_bytes: int = 200_000,
        max_entries: int = 500,
    ) -> None:
        self.max_body_bytes = max(0, int(max_body_bytes))
        self.max_entries = max(0, int(max_entries))
        self._entries: dict[str, CachedResponse] = {}

    def add(self, resp: CachedResponse) -> None:
        """Store ``resp`` keyed by normalized URL, truncating body if needed."""
        key = normalize_url(resp.url)
        if key not in self._entries and len(self._entries) >= self.max_entries:
            return

        body = resp.body or ""
        encoded = body.encode("utf-8", errors="ignore")
        if len(encoded) > self.max_body_bytes:
            body = encoded[: self.max_body_bytes].decode("utf-8", errors="ignore")

        self._entries[key] = CachedResponse(
            url=key,
            status_code=resp.status_code,
            headers=dict(resp.headers),
            body=body,
            content_type=resp.content_type,
        )

    def get(self, url: str) -> CachedResponse | None:
        """Retrieve a cached response by URL (normalized automatically)."""
        return self._entries.get(normalize_url(url))

    def all(self) -> list[CachedResponse]:
        """Return all cached responses in insertion order."""
        return list(self._entries.values())

    def by_origin(self, base_url: str) -> list[CachedResponse]:
        """Return all cached responses matching the origin of ``base_url``."""
        target_origin = _origin_tuple(base_url)
        if target_origin is None:
            return []
        return [
            entry
            for entry in self._entries.values()
            if _origin_tuple(entry.url) == target_origin
        ]

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, url: str) -> bool:
        return normalize_url(url) in self._entries


class WebCrawler:
    """Bounded breadth-first crawler for mapping a local target's attack surface."""

    def __init__(
        self,
        http_client: ScannerHttpClient,
        guardrail: ScopeGuardrail,
        max_depth: int = 3,
        max_pages: int = 150,
        max_duration_s: float = 300.0,
        progress_callback: ProgressCallback | None = None,
    ) -> None:
        self.http_client = http_client
        self.guardrail = guardrail
        self.max_depth = max(0, int(max_depth))
        self.max_pages = max(0, int(max_pages))
        self.max_duration_s = float(max_duration_s)
        self.progress_callback = progress_callback

    def _is_cancelled(self) -> bool:
        event = self.http_client.cancel_event
        return event is not None and event.is_set()

    def _is_crawlable(self, base_url: str, candidate_url: str) -> bool:
        parsed = urlsplit(candidate_url)
        if parsed.scheme.lower() not in ("http", "https"):
            return False
        if not self.guardrail.is_same_origin(base_url, candidate_url):
            return False
        if self.guardrail.is_destructive_path(candidate_url):
            return False
        if _is_binary_asset_url(candidate_url):
            return False
        return True

    def _seed_from_robots_and_sitemap(
        self,
        origin_root: str,
        normalized_base: str,
        enqueue: Callable[[str, int, str], None],
        deadline: float,
    ) -> None:
        if self.max_depth < 1:
            return

        sitemap_urls: list[str] = [normalize_url("/sitemap.xml", origin_root)]
        seen_sitemaps: set[str] = set()

        # 1. Fetch and parse /robots.txt
        if not self._is_cancelled() and time.monotonic() < deadline:
            robots_url = normalize_url("/robots.txt", origin_root)
            try:
                resp = self.http_client.get(robots_url, follow_redirects=True)
            except (ScanCancelledError, RequestLimitExceededError):
                return
            except (ScopeViolationError, requests.RequestException):
                resp = None

            if resp is not None and resp.status_code == 200:
                media_type = _extract_media_type(resp.headers.get("Content-Type", ""))
                if not media_type or media_type.startswith("text/"):
                    for raw_line in (resp.text or "").splitlines():
                        line = raw_line.split("#", 1)[0].strip()
                        if not line or ":" not in line:
                            continue
                        directive, value = line.split(":", 1)
                        directive_lc = directive.strip().lower()
                        value = value.strip()
                        if not value:
                            continue

                        if directive_lc in ("disallow", "allow"):
                            cleaned = value.rstrip("*")
                            if not cleaned or "*" in cleaned:
                                continue
                            candidate = normalize_url(cleaned, origin_root)
                            if self._is_crawlable(normalized_base, candidate):
                                enqueue(candidate, 1, "robots")
                        elif directive_lc == "sitemap":
                            sm_url = normalize_url(value, origin_root)
                            if self.guardrail.is_same_origin(normalized_base, sm_url):
                                sitemap_urls.append(sm_url)

        # 2. Fetch and parse sitemap(s)
        for sm_url in sitemap_urls:
            if sm_url in seen_sitemaps:
                continue
            seen_sitemaps.add(sm_url)

            if self._is_cancelled() or time.monotonic() >= deadline:
                return

            try:
                resp = self.http_client.get(sm_url, follow_redirects=True)
            except (ScanCancelledError, RequestLimitExceededError):
                return
            except (ScopeViolationError, requests.RequestException):
                continue

            if resp.status_code != 200 or not resp.text:
                continue

            for loc in self._parse_sitemap_locs(resp.text):
                candidate = normalize_url(loc, origin_root)
                if self._is_crawlable(normalized_base, candidate):
                    enqueue(candidate, 1, "sitemap")

    @staticmethod
    def _parse_sitemap_locs(xml_text: str) -> list[str]:
        locs: list[str] = []
        try:
            root = ET.fromstring(xml_text)
            for elem in root.iter():
                tag = elem.tag.split("}", 1)[-1].lower()
                if tag == "loc" and elem.text and elem.text.strip():
                    locs.append(elem.text.strip())
        except ET.ParseError:
            locs.extend(match.group(1).strip() for match in _SITEMAP_LOC_RE.finditer(xml_text))
        return locs

    @staticmethod
    def _extract_js_api_hints(script_text: str) -> list[str]:
        if not script_text:
            return []
        hints: list[str] = []
        for match in _JS_API_ROUTE_RE.finditer(script_text):
            route = match.group(0).rstrip(".")
            if len(route) > len("/api/"):
                hints.append(route)
        return hints

    @staticmethod
    def _extract_form_inputs(form_tag: BeautifulSoup) -> list[FormInput]:
        inputs: list[FormInput] = []

        for tag in form_tag.find_all("input"):
            name = (tag.get("name") or "").strip()
            if not name:
                continue
            input_type = (tag.get("type") or "text").strip().lower()
            value = str(tag.get("value") or "")
            inputs.append(FormInput(name=name, input_type=input_type, value=value))

        for tag in form_tag.find_all("select"):
            name = (tag.get("name") or "").strip()
            if not name:
                continue
            selected = tag.find("option", selected=True) or tag.find("option")
            if selected is not None:
                value = str(
                    selected.get("value")
                    if selected.get("value") is not None
                    else selected.get_text(strip=True)
                )
            else:
                value = ""
            inputs.append(FormInput(name=name, input_type="select", value=value))

        for tag in form_tag.find_all("textarea"):
            name = (tag.get("name") or "").strip()
            if not name:
                continue
            value = tag.get_text() or ""
            inputs.append(FormInput(name=name, input_type="textarea", value=value))

        return inputs

    def crawl(self, base_url: str) -> tuple[AttackSurface, ResponseCache]:
        """Run a bounded BFS crawl starting at ``base_url``."""
        validated_base = self.guardrail.validate_url(base_url)
        normalized_base = normalize_url(validated_base)

        parsed_base = urlsplit(normalized_base)
        origin_root = urlunsplit((parsed_base.scheme, parsed_base.netloc, "/", "", ""))

        surface = AttackSurface(base_url=normalized_base)
        cache = ResponseCache()

        deadline = time.monotonic() + self.max_duration_s
        queue: deque[tuple[str, int, str]] = deque()
        queued: set[str] = set()
        visited: set[str] = set()

        seen_endpoints: set[tuple[str, str, tuple[str, ...]]] = set()
        seen_forms: set[tuple[str, str, tuple[str, ...]]] = set()
        seen_scripts: set[str] = set()

        def enqueue(url: str, depth: int, source: str) -> None:
            if depth > self.max_depth:
                return
            if url in visited or url in queued:
                return
            queued.add(url)
            queue.append((url, depth, source))

        def record_endpoint(
            url: str,
            *,
            method: str = "GET",
            params: list[str] | None = None,
            source: str = "link",
            status_code: int = 0,
        ) -> None:
            parsed = urlsplit(url)
            norm_path = parsed.path or "/"
            if params is None:
                extracted_params = sorted(
                    {k for k, _ in parse_qsl(parsed.query, keep_blank_values=True) if k}
                )
            else:
                extracted_params = sorted({p for p in params if p})

            dedup_key = (method.upper(), norm_path, tuple(extracted_params))
            if dedup_key in seen_endpoints:
                return
            seen_endpoints.add(dedup_key)
            surface.endpoints.append(
                EndpointRecord(
                    url=url,
                    method=method.upper(),
                    params=extracted_params,
                    source=source,
                    status_code=status_code,
                )
            )

        enqueue(normalized_base, 0, "seed")
        self._seed_from_robots_and_sitemap(origin_root, normalized_base, enqueue, deadline)

        pages_crawled = 0

        while queue:
            if pages_crawled >= self.max_pages:
                break
            if self._is_cancelled():
                break
            if time.monotonic() >= deadline:
                break

            current_url, depth, source = queue.popleft()
            if current_url in visited:
                continue
            visited.add(current_url)

            try:
                resp = self.http_client.get(current_url, follow_redirects=True)
            except (ScanCancelledError, RequestLimitExceededError):
                break
            except (ScopeViolationError, requests.RequestException):
                continue

            pages_crawled += 1
            if self.progress_callback is not None:
                self.progress_callback(
                    pages_crawled,
                    self.http_client.requests_sent,
                    current_url,
                )

            final_url = normalize_url(resp.url) if resp.url else current_url
            if self.guardrail.is_same_origin(normalized_base, final_url):
                visited.add(final_url)
            else:
                final_url = current_url

            raw_content_type = resp.headers.get("Content-Type", "")
            media_type = _extract_media_type(raw_content_type)

            record_endpoint(
                current_url,
                method="GET",
                source=source,
                status_code=resp.status_code,
            )

            if not _is_cacheable_media_type(media_type):
                continue

            body_text = resp.text or ""
            cache.add(
                CachedResponse(
                    url=current_url,
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    body=body_text,
                    content_type=raw_content_type,
                )
            )

            if media_type not in _PARSEABLE_CONTENT_TYPES:
                continue

            if media_type in _JS_CONTENT_TYPES:
                if depth < self.max_depth:
                    for route in self._extract_js_api_hints(body_text):
                        candidate = normalize_url(route, origin_root)
                        if self._is_crawlable(normalized_base, candidate):
                            enqueue(candidate, depth + 1, "js_hint")
                continue

            # HTML / XHTML parsing
            soup = BeautifulSoup(body_text, _BS4_PARSER)

            # 1. Anchor links
            if depth < self.max_depth:
                for anchor in soup.find_all("a", href=True):
                    href = str(anchor.get("href") or "").strip()
                    if not href:
                        continue
                    candidate = normalize_url(href, final_url)
                    if self._is_crawlable(normalized_base, candidate):
                        enqueue(candidate, depth + 1, "link")

                # 2. <iframe src>
                for iframe in soup.find_all("iframe", src=True):
                    src = str(iframe.get("src") or "").strip()
                    if not src:
                        continue
                    candidate = normalize_url(src, final_url)
                    if self._is_crawlable(normalized_base, candidate):
                        enqueue(candidate, depth + 1, "iframe")

                # 3. Non-stylesheet <link href>
                for link_tag in soup.find_all("link", href=True):
                    rel_attr = link_tag.get("rel") or []
                    if isinstance(rel_attr, str):
                        rels = {rel_attr.lower()}
                    else:
                        rels = {str(item).lower() for item in rel_attr}
                    if "stylesheet" in rels:
                        continue
                    href = str(link_tag.get("href") or "").strip()
                    if not href:
                        continue
                    candidate = normalize_url(href, final_url)
                    if self._is_crawlable(normalized_base, candidate):
                        enqueue(candidate, depth + 1, "link_tag")

            # 4. <form action method> + inputs/selects/textareas
            for form_tag in soup.find_all("form"):
                raw_action = str(form_tag.get("action") or "").strip()
                action_url = normalize_url(raw_action, final_url)
                if not self.guardrail.is_same_origin(normalized_base, action_url):
                    continue
                if self.guardrail.is_destructive_path(action_url):
                    continue

                method = (str(form_tag.get("method") or "GET")).strip().upper() or "GET"
                inputs = self._extract_form_inputs(form_tag)
                input_names = tuple(sorted(inp.name for inp in inputs))

                form_key = (method, action_url, input_names)
                if form_key not in seen_forms:
                    seen_forms.add(form_key)
                    surface.forms.append(
                        FormRecord(
                            action_url=action_url,
                            method=method,
                            inputs=inputs,
                            source_url=final_url,
                        )
                    )

            # 5. <script src> and inline <script> JS API hints
            for script_tag in soup.find_all("script"):
                src = str(script_tag.get("src") or "").strip()
                if src:
                    script_url = normalize_url(src, final_url)
                    if (
                        urlsplit(script_url).scheme in ("http", "https")
                        and self.guardrail.is_same_origin(normalized_base, script_url)
                        and script_url not in seen_scripts
                    ):
                        seen_scripts.add(script_url)
                        surface.scripts.append(script_url)
                else:
                    inline_js = script_tag.string or script_tag.get_text() or ""
                    if inline_js and depth < self.max_depth:
                        for route in self._extract_js_api_hints(inline_js):
                            candidate = normalize_url(route, origin_root)
                            if self._is_crawlable(normalized_base, candidate):
                                enqueue(candidate, depth + 1, "js_hint")

        return surface, cache


__all__ = [
    "ProgressCallback",
    "ResponseCache",
    "WebCrawler",
    "normalize_url",
]
