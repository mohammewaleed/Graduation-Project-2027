"""Unit tests for backend.scanner.crawler (normalize_url, ResponseCache, WebCrawler)."""

from __future__ import annotations

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from backend.scanner.crawler import ResponseCache, WebCrawler, normalize_url
from backend.scanner.http_client import ScannerHttpClient
from backend.scanner.models import CachedResponse
from backend.scanner.policy import ScopeGuardrail

_LARGE_BODY_PREFIX = "<html><body><h1>Oversized</h1><p>"
_LARGE_BODY_SUFFIX = "</p></body></html>"
_LARGE_BODY_HTML = _LARGE_BODY_PREFIX + ("A" * 260_000) + _LARGE_BODY_SUFFIX


class _CrawlFixtureHandler(BaseHTTPRequestHandler):
    """Local HTTP fixture server exposing HTML pages, forms, robots.txt, and inline JS."""

    requested_paths: list[str] = []

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return

    def _send(
        self,
        status: int,
        body: str,
        *,
        content_type: str = "text/html; charset=utf-8",
    ) -> None:
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        type(self).requested_paths.append(self.path)

        if path == "/robots.txt":
            self._send(
                200,
                "User-agent: *\nDisallow: /hidden-admin\nAllow: /public-info\n",
                content_type="text/plain; charset=utf-8",
            )
            return

        if path == "/sitemap.xml":
            self._send(404, "Not Found", content_type="text/plain")
            return

        if path == "/":
            html = """<!doctype html>
<html>
<head>
  <link rel="stylesheet" href="/style.css">
  <script src="/static/app.js"></script>
</head>
<body>
  <a href="/search?b=2&a=1#results">Search 1</a>
  <a href="/search?a=1&b=2#top">Search Duplicate</a>
  <a href="/depth1">Depth 1</a>
  <a href="/huge">Oversized Page</a>
  <a href="https://example.com/out">External Link</a>
  <a href="/logout">Logout</a>
  <a href="/delete">Delete</a>
  <a href="/logo.png">Logo</a>
  <a href="/style.css">CSS</a>

  <form action="/search" method="GET">
    <input type="text" name="q" value="hello">
    <select name="category">
      <option value="all" selected>All</option>
      <option value="books">Books</option>
    </select>
  </form>

  <form action="/feedback" method="POST">
    <input type="text" name="author" value="alice">
    <textarea name="comment">Great app</textarea>
    <input type="hidden" name="csrf" value="tok123">
  </form>

  <script>
    fetch('/api/v1/users');
    const url = "/api/v1/orders";
  </script>
</body>
</html>"""
            self._send(200, html)
            return

        if path == "/search":
            self._send(200, "<html><body><h1>Search Results</h1></body></html>")
            return

        if path == "/depth1":
            self._send(200, '<html><body><a href="/depth2">Go to depth 2</a></body></html>')
            return

        if path == "/depth2":
            self._send(200, '<html><body><a href="/depth3">Go to depth 3</a></body></html>')
            return

        if path == "/depth3":
            self._send(200, "<html><body><h1>Depth 3 Reached</h1></body></html>")
            return

        if path == "/hidden-admin":
            self._send(200, "<html><body><h1>Hidden Admin</h1></body></html>")
            return

        if path == "/public-info":
            self._send(200, "<html><body><h1>Public Info</h1></body></html>")
            return

        if path == "/api/v1/users":
            self._send(200, '{"users": ["alice"]}', content_type="application/json")
            return

        if path == "/api/v1/orders":
            self._send(200, '{"orders": [1, 2]}', content_type="application/json")
            return

        if path == "/huge":
            self._send(200, _LARGE_BODY_HTML)
            return

        # Routes that should NEVER be fetched by the crawler
        if path in ("/logout", "/delete", "/logo.png", "/style.css"):
            self._send(200, "SHOULD NOT BE CRAWLED")
            return

        self._send(404, "Not Found")


class TestNormalizeUrlAndCache(unittest.TestCase):
    """Pure unit tests for normalize_url and ResponseCache."""

    def test_normalize_url_strips_fragments_sorts_query_and_normalizes_ports(self) -> None:
        self.assertEqual(
            normalize_url("http://LOCALHOST:80/search?b=2&a=1#frag"),
            "http://localhost/search?a=1&b=2",
        )
        self.assertEqual(
            normalize_url("/items?z=9&m=3#top", base_url="http://127.0.0.1:8080/"),
            "http://127.0.0.1:8080/items?m=3&z=9",
        )
        self.assertEqual(
            normalize_url("https://localhost:443"),
            "https://localhost/",
        )

    def test_response_cache_truncates_large_bodies(self) -> None:
        cache = ResponseCache(max_body_bytes=200_000)
        cache.add(
            CachedResponse(
                url="http://127.0.0.1:8000/huge#frag",
                status_code=200,
                headers={"Content-Type": "text/html"},
                body="X" * 250_000,
                content_type="text/html",
            )
        )
        entry = cache.get("http://127.0.0.1:8000/huge")
        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertLessEqual(len(entry.body.encode("utf-8")), 200_000)


class TestWebCrawler(unittest.TestCase):
    """Tests for WebCrawler against a local ThreadingHTTPServer fixture."""

    server: ThreadingHTTPServer
    thread: threading.Thread
    base_url: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _CrawlFixtureHandler)
        port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2.0)

    def setUp(self) -> None:
        _CrawlFixtureHandler.requested_paths.clear()

    def _run_crawl(
        self,
        *,
        max_depth: int = 3,
        max_pages: int = 100,
    ) -> tuple[object, ResponseCache]:
        guard = ScopeGuardrail()
        with ScannerHttpClient(
            guardrail=guard,
            rate_limit_rps=0.0,
            max_requests=200,
            timeout_s=5.0,
        ) as client:
            crawler = WebCrawler(
                http_client=client,
                guardrail=guard,
                max_depth=max_depth,
                max_pages=max_pages,
                max_duration_s=30.0,
            )
            return crawler.crawl(self.base_url)

    def test_discovers_links_params_forms_scripts_robots_js_hints_and_filters_unsafe(self) -> None:
        surface, cache = self._run_crawl(max_depth=3, max_pages=100)

        endpoint_urls = {ep.url for ep in surface.endpoints}
        endpoint_paths = {urlsplit(ep.url).path for ep in surface.endpoints}

        # Internal links & normalized query params (deduplicated)
        expected_search = f"{self.base_url}/search?a=1&b=2"
        self.assertIn(expected_search, endpoint_urls)
        search_endpoints = [ep for ep in surface.endpoints if urlsplit(ep.url).path == "/search"]
        self.assertEqual(len(search_endpoints), 1)
        self.assertEqual(search_endpoints[0].params, ["a", "b"])

        # robots.txt paths discovered
        self.assertIn("/hidden-admin", endpoint_paths)
        self.assertIn("/public-info", endpoint_paths)

        # Inline JS /api/... route hints discovered
        self.assertIn("/api/v1/users", endpoint_paths)
        self.assertIn("/api/v1/orders", endpoint_paths)

        # <script src> discovered
        self.assertIn(f"{self.base_url}/static/app.js", surface.scripts)

        # GET & POST <form> inputs (input, select, textarea) discovered
        forms_by_key = {(f.method, urlsplit(f.action_url).path): f for f in surface.forms}
        self.assertIn(("GET", "/search"), forms_by_key)
        get_form = forms_by_key[("GET", "/search")]
        get_inputs = {inp.name: inp for inp in get_form.inputs}
        self.assertIn("q", get_inputs)
        self.assertIn("category", get_inputs)
        self.assertEqual(get_inputs["category"].input_type, "select")
        self.assertEqual(get_inputs["category"].value, "all")

        self.assertIn(("POST", "/feedback"), forms_by_key)
        post_form = forms_by_key[("POST", "/feedback")]
        post_inputs = {inp.name: inp for inp in post_form.inputs}
        self.assertIn("author", post_inputs)
        self.assertIn("comment", post_inputs)
        self.assertEqual(post_inputs["comment"].input_type, "textarea")
        self.assertIn("csrf", post_inputs)

        # Never follows external, destructive/logout, or binary asset links
        requested_paths_only = {urlsplit(p).path for p in _CrawlFixtureHandler.requested_paths}
        for forbidden in ("/logout", "/delete", "/logo.png", "/style.css"):
            self.assertNotIn(forbidden, requested_paths_only)
            self.assertNotIn(forbidden, endpoint_paths)
        for url in endpoint_urls:
            self.assertNotIn("example.com", url)

        # ResponseCache populated with truncated body <= 200KB
        huge_entry = cache.get(f"{self.base_url}/huge")
        self.assertIsNotNone(huge_entry)
        assert huge_entry is not None
        self.assertLessEqual(len(huge_entry.body.encode("utf-8")), 200_000)
        self.assertGreater(len(huge_entry.body), 0)

    def test_enforces_max_depth(self) -> None:
        surface, _ = self._run_crawl(max_depth=1, max_pages=100)
        endpoint_paths = {urlsplit(ep.url).path for ep in surface.endpoints}
        self.assertIn("/", endpoint_paths)
        self.assertIn("/depth1", endpoint_paths)
        self.assertNotIn("/depth2", endpoint_paths)
        self.assertNotIn("/depth3", endpoint_paths)

    def test_enforces_max_pages(self) -> None:
        surface, cache = self._run_crawl(max_depth=3, max_pages=3)
        self.assertLessEqual(len(surface.endpoints), 3)
        self.assertLessEqual(len(cache), 3)


if __name__ == "__main__":
    unittest.main()
