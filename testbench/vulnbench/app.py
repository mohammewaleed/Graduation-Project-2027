"""Deterministic local HTTP test application (VulnBench) for scanner evaluation.

Implemented using only the Python 3.12 standard library (``http.server``,
``sqlite3``, ``html``, ``json``, ``urllib.parse``, ``argparse``) with zero
third-party dependencies. Binds to ``127.0.0.1`` by default and maintains all
relational test data in a read-only/ephemeral in-memory SQLite database.
"""

from __future__ import annotations

import argparse
import html
import json
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

DEFAULT_HOST: str = "127.0.0.1"
DEFAULT_PORT: int = 5050

_SAFE_REDIRECT_ALLOWLIST: frozenset[str] = frozenset({"/home", "/about"})

_STRICT_SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    (
        "Content-Security-Policy",
        "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'",
    ),
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "geolocation=(), microphone=(), camera=()"),
)


def _init_in_memory_db() -> sqlite3.Connection:
    """Create and seed an in-memory SQLite database for deterministic test queries."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE items (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            price REAL NOT NULL
        )
        """
    )
    cursor.execute(
        """
        INSERT INTO items (id, name, description, price)
        VALUES (1, 'Developer Workstation', '16-core local benchmark notebook', 1299.00)
        """
    )

    cursor.execute(
        """
        CREATE TABLE catalog (
            id INTEGER PRIMARY KEY,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            author TEXT NOT NULL,
            price REAL NOT NULL
        )
        """
    )
    catalog_rows = [
        (1, "books", "Web Application Architecture", "A. Researcher", 45.00),
        (2, "books", "Defensive HTTP Headers Guide", "B. Engineer", 39.50),
        (3, "books", "Parameterized Query Patterns", "C. Architect", 52.00),
        (4, "books", "Browser Content Security Policy", "D. Analyst", 41.00),
        (5, "books", "Automated Security Verification", "E. Reviewer", 48.75),
    ]
    cursor.executemany(
        "INSERT INTO catalog (id, category, title, author, price) VALUES (?, ?, ?, ?, ?)",
        catalog_rows,
    )

    cursor.execute(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            full_name TEXT NOT NULL,
            department TEXT NOT NULL,
            email TEXT NOT NULL
        )
        """
    )
    user_rows = [
        (1, "alice_dev", "Alice Henderson", "Platform Engineering", "alice@vulnbench.local"),
        (2, "bob_ops", "Bob Martinez", "Infrastructure Operations", "bob@vulnbench.local"),
        (3, "charlie_qa", "Charlie Kim", "Quality Assurance", "charlie@vulnbench.local"),
    ]
    cursor.executemany(
        "INSERT INTO users (id, username, full_name, department, email) VALUES (?, ?, ?, ?, ?)",
        user_rows,
    )
    conn.commit()
    return conn


class VulnBenchHTTPServer(ThreadingHTTPServer):
    """Threaded HTTP server carrying an in-memory SQLite connection and lock."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        RequestHandlerClass: type[BaseHTTPRequestHandler],
    ) -> None:
        super().__init__(server_address, RequestHandlerClass)
        self.db_conn: sqlite3.Connection = _init_in_memory_db()
        self.db_lock: threading.Lock = threading.Lock()

    def server_close(self) -> None:
        try:
            self.db_conn.close()
        except Exception:
            pass
        super().server_close()


class VulnBenchRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler serving seeded test cases and clean control routes."""

    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        """Silence default stderr access logging during automated benchmark runs."""
        return

    def version_string(self) -> str:
        """Return a versioned Server banner only on '/' for deterministic checking."""
        path = urlsplit(self.path).path or "/"
        if path == "/":
            return "Apache/2.4.49 (Unix)"
        return "VulnBench"

    @property
    def _vb_server(self) -> VulnBenchHTTPServer:
        return self.server  # type: ignore[return-value]

    def _send_body(
        self,
        status_code: int,
        body: str,
        *,
        content_type: str = "text/html; charset=utf-8",
        include_strict_headers: bool = True,
        extra_headers: list[tuple[str, str]] | None = None,
    ) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Connection", "close")
        if include_strict_headers:
            for h_name, h_val in _STRICT_SECURITY_HEADERS:
                self.send_header(h_name, h_val)
        if extra_headers:
            for h_name, h_val in extra_headers:
                self.send_header(h_name, h_val)
        self.end_headers()
        self.wfile.write(encoded)

    def _send_redirect(
        self,
        location: str,
        *,
        include_strict_headers: bool = True,
    ) -> None:
        body = (
            "<!DOCTYPE html><html><head><title>Redirecting</title></head>"
            f"<body><p>Redirecting to {html.escape(location, quote=True)}</p></body></html>"
        )
        self._send_body(
            302,
            body,
            include_strict_headers=include_strict_headers,
            extra_headers=[("Location", location)],
        )

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        path = parsed.path or "/"
        query = parse_qs(parsed.query, keep_blank_values=True)

        if path == "/":
            self._handle_landing()
        elif path == "/home":
            self._handle_home()
        elif path == "/about":
            self._handle_about()
        elif path == "/static/jquery-3.4.1.min.js":
            self._handle_jquery_asset()
        elif path == "/weak-csp":
            self._handle_weak_csp()
        elif path == "/debug-error":
            self._handle_debug_error()
        elif path == "/login":
            self._handle_login_get()
        elif path == "/api/profile":
            self._handle_api_profile()
        elif path == "/items":
            self._handle_items(query)
        elif path == "/catalog":
            self._handle_catalog(query)
        elif path == "/search":
            self._handle_search(query)
        elif path == "/redirect":
            self._handle_redirect(query)
        elif path == "/users":
            self._handle_users(query)
        elif path == "/.env":
            self._handle_dotenv()
        elif path == "/.git/HEAD":
            self._handle_git_head()
        elif path in ("/uploads", "/uploads/"):
            self._handle_uploads_listing()
        elif path == "/admin":
            self._handle_admin()
        elif path == "/safe/search":
            self._handle_safe_search(query)
        elif path == "/safe/item":
            self._handle_safe_item(query)
        elif path == "/safe/redirect":
            self._handle_safe_redirect(query)
        elif path == "/safe/form":
            self._handle_safe_form_get()
        else:
            self._handle_not_found()

    def do_POST(self) -> None:
        parsed = urlsplit(self.path)
        path = parsed.path or "/"
        content_len = int(self.headers.get("Content-Length", "0") or "0")
        if content_len > 0:
            _ = self.rfile.read(min(content_len, 65536))

        if path == "/login":
            self._handle_login_post()
        elif path == "/safe/form":
            self._handle_safe_form_post()
        else:
            self._handle_not_found()

    def _handle_landing(self) -> None:
        """Landing page linking all test routes and clean control routes.

        Seeds:
        - missing_security_headers (omits CSP, XFO, XCTO, Referrer-Policy, Permissions-Policy)
        - server_banner_leak (Server: Apache/2.4.49 (Unix) + X-Powered-By: PHP/8.1.2)
        - insecure_cookies (Set-Cookie: session_id=vb_demo_001; Path=/)
        - outdated_js_components (<script src="/static/jquery-3.4.1.min.js">)
        """
        body = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>VulnBench Test Application</title>
  <script src="/static/jquery-3.4.1.min.js"></script>
</head>
<body>
  <h1>VulnBench Local Verification Suite</h1>
  <p>Deterministic local testbench for automated security check evaluation.</p>
  <h2>Test Endpoints</h2>
  <ul>
    <li><a href="/api/profile">API Profile Endpoint</a></li>
    <li><a href="/weak-csp">Permissive CSP Endpoint</a></li>
    <li><a href="/debug-error">Diagnostic Error Page</a></li>
    <li><a href="/login">User Sign-In Form</a></li>
    <li><a href="/items?id=1">Item Detail Query</a></li>
    <li><a href="/catalog?cat=books">Product Catalog Filter</a></li>
    <li><a href="/search?q=laptop">Catalog Search</a></li>
    <li><a href="/redirect?next=/home">Navigation Redirect</a></li>
    <li><a href="/users?id=1">User Directory Profile</a></li>
  </ul>
  <h2>Clean Control Endpoints</h2>
  <ul>
    <li><a href="/safe/search?q=hello">Safe Escaped Search</a></li>
    <li><a href="/safe/item?id=1">Safe Parameterized Item</a></li>
    <li><a href="/safe/redirect?next=/home">Safe Allowlisted Redirect</a></li>
    <li><a href="/safe/form">Safe CSRF-Protected Form</a></li>
    <li><a href="/home">Home Portal</a></li>
  </ul>
</body>
</html>"""
        self._send_body(
            200,
            body,
            include_strict_headers=False,
            extra_headers=[
                ("X-Powered-By", "PHP/8.1.2"),
                ("Set-Cookie", "session_id=vb_demo_001; Path=/"),
            ],
        )

    def _handle_home(self) -> None:
        body = (
            "<!DOCTYPE html><html><head><title>VulnBench Home</title></head>"
            "<body><h1>Home Portal</h1><p>Welcome to the local benchmark home page.</p></body></html>"
        )
        self._send_body(200, body, include_strict_headers=True)

    def _handle_about(self) -> None:
        body = (
            "<!DOCTYPE html><html><head><title>About VulnBench</title></head>"
            "<body><h1>About VulnBench</h1><p>Synthetic evaluation target.</p></body></html>"
        )
        self._send_body(200, body, include_strict_headers=True)

    def _handle_jquery_asset(self) -> None:
        js_body = "/*! jQuery v3.4.1 | (c) JS Foundation and other contributors */\nwindow.jQuery = {};\n"
        self._send_body(
            200,
            js_body,
            content_type="application/javascript; charset=utf-8",
            include_strict_headers=True,
        )

    def _handle_weak_csp(self) -> None:
        """Seeds weak_csp via wildcard and unsafe-inline / unsafe-eval directives."""
        body = (
            "<!DOCTYPE html><html><head><title>Weak CSP Policy Page</title></head>"
            "<body><h1>CSP Test Route</h1><p>Configured with permissive CSP header.</p></body></html>"
        )
        headers = [
            (
                "Content-Security-Policy",
                "default-src * 'unsafe-inline' 'unsafe-eval'",
            ),
            ("X-Frame-Options", "DENY"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
            ("Permissions-Policy", "geolocation=(), microphone=(), camera=()"),
        ]
        self._send_body(
            200,
            body,
            include_strict_headers=False,
            extra_headers=headers,
        )

    def _handle_debug_error(self) -> None:
        """Seeds verbose_error_pages via HTTP 500 with a Python stack trace."""
        body = """<!DOCTYPE html>
<html>
<head><title>500 Internal Server Error</title></head>
<body>
<h1>Internal Server Error</h1>
<pre>Traceback (most recent call last):
  File "app.py", line 214, in _handle_debug_error
    result = compute_diagnostic_state()
  File "app.py", line 198, in compute_diagnostic_state
    raise RuntimeError("Debug configuration state dump triggered")
RuntimeError: Debug configuration state dump triggered
</pre>
</body>
</html>"""
        self._send_body(500, body, include_strict_headers=True)

    def _handle_login_get(self) -> None:
        """Seeds insecure_transport (password over HTTP) and csrf_missing_token."""
        body = """<!DOCTYPE html>
<html>
<head><title>Sign In</title></head>
<body>
  <h1>Account Sign In</h1>
  <form action="/login" method="POST">
    <label>Username: <input type="text" name="username" value="demo_user" /></label>
    <label>Password: <input type="password" name="password" value="demo_pass" /></label>
    <input type="submit" value="Sign In" />
  </form>
</body>
</html>"""
        self._send_body(200, body, include_strict_headers=True)

    def _handle_login_post(self) -> None:
        body = (
            "<!DOCTYPE html><html><head><title>Sign In Result</title></head>"
            "<body><h1>Sign In Notice</h1><p>Authentication processed in demo mode.</p></body></html>"
        )
        self._send_body(200, body, include_strict_headers=True)

    def _handle_api_profile(self) -> None:
        """Seeds cors_misconfig by reflecting Origin with Allow-Credentials: true."""
        origin = (self.headers.get("Origin") or "").strip()
        extra: list[tuple[str, str]] = []
        if origin:
            extra.append(("Access-Control-Allow-Origin", origin))
            extra.append(("Access-Control-Allow-Credentials", "true"))

        payload = json.dumps(
            {
                "id": 101,
                "username": "bench_operator",
                "role": "auditor",
                "status": "active",
            }
        )
        self._send_body(
            200,
            payload,
            content_type="application/json; charset=utf-8",
            include_strict_headers=True,
            extra_headers=extra,
        )

    def _handle_items(self, query: dict[str, list[str]]) -> None:
        """Seeds sqli_error_based via unparameterized SQLite query on 'id'."""
        raw_id = (query.get("id") or ["1"])[0]

        # Reject multi-token boolean expressions so only syntax-quote error probes fire here.
        if " " in raw_id.strip():
            body = (
                "<!DOCTYPE html><html><head><title>Invalid Item Query</title></head>"
                "<body><h1>400 Bad Request</h1><p>Whitespace not allowed in item id.</p></body></html>"
            )
            self._send_body(400, body, include_strict_headers=True)
            return

        sql = f"SELECT id, name, description, price FROM items WHERE (id = {raw_id})"
        try:
            with self._vb_server.db_lock:
                cursor = self._vb_server.db_conn.cursor()
                row = cursor.execute(sql).fetchone()
        except sqlite3.Error as exc:
            err_body = (
                "<!DOCTYPE html><html><head><title>Database Error</title></head>"
                f"<body><h1>Database Query Error</h1><pre>sqlite3.OperationalError: {html.escape(str(exc))}</pre></body></html>"
            )
            self._send_body(500, err_body, include_strict_headers=True)
            return

        if row is None:
            not_found = (
                "<!DOCTYPE html><html><head><title>Item Not Found</title></head>"
                "<body><h1>404 Item Not Found</h1><p>No item exists for the specified ID.</p></body></html>"
            )
            self._send_body(404, not_found, include_strict_headers=True)
            return

        body = f"""<!DOCTYPE html>
<html>
<head><title>Item #{int(row["id"])}</title></head>
<body>
  <h1>{html.escape(str(row["name"]))}</h1>
  <p>Description: {html.escape(str(row["description"]))}</p>
  <p>Price: ${float(row["price"]):.2f}</p>
</body>
</html>"""
        self._send_body(200, body, include_strict_headers=True)

    def _handle_catalog(self, query: dict[str, list[str]]) -> None:
        """Seeds sqli_boolean_diff via boolean-condition differential on 'cat'."""
        raw_cat = (query.get("cat") or ["books"])[0]
        sql = f"SELECT id, title, author, price FROM catalog WHERE category = '{raw_cat}' ORDER BY id"

        rows: list[sqlite3.Row] = []
        try:
            with self._vb_server.db_lock:
                cursor = self._vb_server.db_conn.cursor()
                rows = cursor.execute(sql).fetchall()
        except sqlite3.Error:
            # Suppress raw database error strings so only boolean-differential check fires.
            rows = []

        if rows:
            items_html = "\n".join(
                f"    <li><strong>{html.escape(str(r['title']))}</strong> by "
                f"{html.escape(str(r['author']))} — ${float(r['price']):.2f} "
                f"(Catalog Reference #{int(r['id'])})</li>"
                for r in rows
            )
            body = f"""<!DOCTYPE html>
<html>
<head><title>Product Catalog</title></head>
<body>
  <h1>Product Catalog Listing</h1>
  <p>Showing {len(rows)} matching catalog entries from inventory database:</p>
  <ul>
{items_html}
  </ul>
  <p>All listed publications are available for immediate academic lab dispatch.</p>
</body>
</html>"""
        else:
            body = """<!DOCTYPE html>
<html>
<head><title>Product Catalog</title></head>
<body>
  <h1>Product Catalog Listing</h1>
  <p>No products found.</p>
</body>
</html>"""
        self._send_body(200, body, include_strict_headers=True)

    def _handle_search(self, query: dict[str, list[str]]) -> None:
        """Seeds xss_reflected by echoing 'q' without HTML output encoding."""
        raw_q = (query.get("q") or ["laptop"])[0]
        body = f"""<!DOCTYPE html>
<html>
<head><title>Catalog Search</title></head>
<body>
  <h1>Search Results</h1>
  <p>Results for query: {raw_q}</p>
  <p>Matched 1 item: Developer Workstation.</p>
</body>
</html>"""
        self._send_body(200, body, include_strict_headers=True)

    def _handle_redirect(self, query: dict[str, list[str]]) -> None:
        """Seeds open_redirect by issuing an unvalidated 302 Location redirect."""
        next_target = (query.get("next") or ["/home"])[0]
        self._send_redirect(next_target, include_strict_headers=True)

    def _handle_users(self, query: dict[str, list[str]]) -> None:
        """Seeds idor_heuristic by returning distinct records for adjacent numeric IDs."""
        raw_id = (query.get("id") or ["1"])[0].strip()
        if not raw_id.isdigit():
            body = (
                "<!DOCTYPE html><html><head><title>Invalid User ID</title></head>"
                "<body><h1>400 Bad Request</h1><p>User ID must be a positive integer.</p></body></html>"
            )
            self._send_body(400, body, include_strict_headers=True)
            return

        user_id = int(raw_id)
        with self._vb_server.db_lock:
            cursor = self._vb_server.db_conn.cursor()
            row = cursor.execute(
                "SELECT id, username, full_name, department, email FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()

        if row is None:
            self._handle_not_found()
            return

        body = f"""<!DOCTYPE html>
<html>
<head><title>User Profile #{int(row["id"])}</title></head>
<body>
  <h1>User Profile: {html.escape(str(row["full_name"]))}</h1>
  <ul>
    <li>Account ID: {int(row["id"])}</li>
    <li>Username: {html.escape(str(row["username"]))}</li>
    <li>Department: {html.escape(str(row["department"]))}</li>
    <li>Email: {html.escape(str(row["email"]))}</li>
  </ul>
</body>
</html>"""
        self._send_body(200, body, include_strict_headers=True)

    def _handle_dotenv(self) -> None:
        """Seeds sensitive_files on /.env."""
        body = "APP_ENV=local\nDB_PASSWORD=vulnbench_demo_secret\n"
        self._send_body(
            200,
            body,
            content_type="text/plain; charset=utf-8",
            include_strict_headers=True,
        )

    def _handle_git_head(self) -> None:
        """Seeds sensitive_files on /.git/HEAD."""
        body = "ref: refs/heads/main\n"
        self._send_body(
            200,
            body,
            content_type="text/plain; charset=utf-8",
            include_strict_headers=True,
        )

    def _handle_uploads_listing(self) -> None:
        """Seeds directory_listing on /uploads/."""
        body = """<!DOCTYPE html>
<html>
<head><title>Index of /uploads/</title></head>
<body>
  <h1>Index of /uploads/</h1>
  <a href="../">Parent Directory</a>
  <ul>
    <li><a href="/home">audit-summary-2026.txt</a></li>
  </ul>
</body>
</html>"""
        self._send_body(200, body, include_strict_headers=True)

    def _handle_admin(self) -> None:
        """Seeds forced_browsing_admin on /admin."""
        body = """<!DOCTYPE html>
<html>
<head><title>Admin Dashboard</title></head>
<body>
  <h1>Admin Dashboard</h1>
  <p>User Management Control Panel and System Settings</p>
</body>
</html>"""
        self._send_body(200, body, include_strict_headers=True)

    def _handle_safe_search(self, query: dict[str, list[str]]) -> None:
        """Clean control route: properly HTML-escaped output + strict headers."""
        raw_q = (query.get("q") or ["hello"])[0]
        escaped_q = html.escape(raw_q, quote=True)
        body = f"""<!DOCTYPE html>
<html>
<head><title>Safe Search</title></head>
<body>
  <h1>Safe Search Results</h1>
  <p>Escaped query term: {escaped_q}</p>
</body>
</html>"""
        self._send_body(200, body, include_strict_headers=True)

    def _handle_safe_item(self, query: dict[str, list[str]]) -> None:
        """Clean control route: parameterized query + non-enumerable access check."""
        raw_id = (query.get("id") or ["1"])[0].strip()
        if raw_id != "1":
            body = (
                "<!DOCTYPE html><html><head><title>Item Restricted</title></head>"
                "<body><h1>404 Not Found</h1><p>Requested item record is not available.</p></body></html>"
            )
            self._send_body(404, body, include_strict_headers=True)
            return

        with self._vb_server.db_lock:
            cursor = self._vb_server.db_conn.cursor()
            row = cursor.execute(
                "SELECT id, name, description, price FROM items WHERE id = ?",
                (1,),
            ).fetchone()

        body = f"""<!DOCTYPE html>
<html>
<head><title>Safe Item View</title></head>
<body>
  <h1>Safe Item Record</h1>
  <p>Name: {html.escape(str(row["name"]))}</p>
  <p>Description: {html.escape(str(row["description"]))}</p>
</body>
</html>"""
        self._send_body(200, body, include_strict_headers=True)

    def _handle_safe_redirect(self, query: dict[str, list[str]]) -> None:
        """Clean control route: strict relative-path allowlist for redirect target."""
        next_target = (query.get("next") or ["/home"])[0].strip()
        safe_target = next_target if next_target in _SAFE_REDIRECT_ALLOWLIST else "/home"
        self._send_redirect(safe_target, include_strict_headers=True)

    def _handle_safe_form_get(self) -> None:
        """Clean control route: POST form with anti-CSRF token and no password over HTTP."""
        body = """<!DOCTYPE html>
<html>
<head><title>Safe Feedback Form</title></head>
<body>
  <h1>Submit Feedback</h1>
  <form action="/safe/form" method="POST">
    <input type="hidden" name="csrf_token" value="vb_csrf_token_2026" />
    <label>Feedback Note: <input type="text" name="note" value="Great documentation" /></label>
    <input type="submit" value="Send Feedback" />
  </form>
</body>
</html>"""
        self._send_body(200, body, include_strict_headers=True)

    def _handle_safe_form_post(self) -> None:
        body = (
            "<!DOCTYPE html><html><head><title>Feedback Received</title></head>"
            "<body><h1>Thank You</h1><p>Your feedback submission was recorded safely.</p></body></html>"
        )
        self._send_body(200, body, include_strict_headers=True)

    def _handle_not_found(self) -> None:
        body = (
            "<!DOCTYPE html><html><head><title>404 Not Found</title></head>"
            "<body><h1>404 Not Found</h1><p>The requested resource does not exist on VulnBench.</p></body></html>"
        )
        self._send_body(404, body, include_strict_headers=True)


def create_vulnbench_server(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
) -> VulnBenchHTTPServer:
    """Create and bind a ``VulnBenchHTTPServer`` instance (supports ``port=0``)."""
    return VulnBenchHTTPServer((host, int(port)), VulnBenchRequestHandler)


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint to run the VulnBench HTTP server."""
    parser = argparse.ArgumentParser(
        description="Run the deterministic local VulnBench test server."
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=f"Bind address (default: {DEFAULT_HOST}).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Bind TCP port (default: {DEFAULT_PORT}).",
    )
    args = parser.parse_args(argv)

    server = create_vulnbench_server(host=args.host, port=args.port)
    bound_host, bound_port = server.server_address[:2]
    print(f"VulnBench listening on http://{bound_host}:{bound_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
