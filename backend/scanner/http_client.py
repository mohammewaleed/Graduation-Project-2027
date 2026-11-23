"""Scope-enforcing, rate-limited HTTP client for the OWASP Lite scanner.

Wraps ``requests.Session`` with pre-request scope validation, manual
same-origin redirect handling, token-bucket rate limiting, request caps,
cooperative cancellation, Soft-404 calibration, and DVWA lab auto-login.
"""

from __future__ import annotations

import difflib
import re
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import requests

from backend.scanner.policy import ScopeGuardrail, ScopeViolationError

SCANNER_USER_AGENT = "OWASP-Lite-Scanner/0.1 (+educational-local)"

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_DVWA_TOKEN_RE_1 = re.compile(
    r"<input[^>]+name=[\"']user_token[\"'][^>]+value=[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
_DVWA_TOKEN_RE_2 = re.compile(
    r"<input[^>]+value=[\"']([^\"']+)[\"'][^>]+name=[\"']user_token[\"']",
    re.IGNORECASE,
)


class ScanCancelledError(RuntimeError):
    """Raised when a scan is cancelled via its cooperative ``threading.Event``."""


class RequestLimitExceededError(RuntimeError):
    """Raised when a scan reaches its configured ``max_requests`` budget."""


@dataclass(slots=True)
class Soft404Fingerprint:
    """Baseline response fingerprint for detecting custom HTTP 200 Soft-404 pages."""

    status_code: int
    content_length: int
    body_sample: str
    similarity_threshold: float = 0.85

    def is_soft_404(self, status_code: int, body: str) -> bool:
        """Return True if a response matches a 404 or the calibrated Soft-404 page."""
        if status_code == 404:
            return True

        # If the server returns genuine 404s for missing routes, a non-404 is not a soft-404.
        if self.status_code == 404:
            return False

        if status_code != self.status_code:
            return False

        sample = (body or "")[:4096]
        baseline = (self.body_sample or "")[:4096]
        if not baseline and not sample:
            return True

        ratio = difflib.SequenceMatcher(None, baseline, sample).ratio()
        return ratio >= self.similarity_threshold


class ScannerHttpClient:
    """HTTP client enforcing scope guardrails, rate limits, and request caps."""

    def __init__(
        self,
        guardrail: ScopeGuardrail,
        rate_limit_rps: float = 10.0,
        max_requests: int = 2000,
        timeout_s: float = 10.0,
        cancel_event: threading.Event | None = None,
        auth_type: str = "none",
        auth_value: str = "",
        max_redirects: int = 5,
    ) -> None:
        self.guardrail = guardrail
        self.rate_limit_rps = float(rate_limit_rps)
        self.max_requests = int(max_requests)
        self.timeout_s = float(timeout_s)
        self.cancel_event = cancel_event
        self.max_redirects = int(max_redirects)

        self.requests_sent: int = 0
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": SCANNER_USER_AGENT})

        self._lock = threading.Lock()
        self._bucket_capacity = max(1.0, min(self.rate_limit_rps, 5.0)) if self.rate_limit_rps > 0 else 1.0
        self._tokens: float = 1.0
        self._last_refill: float = time.monotonic()

        self._configure_auth(auth_type, auth_value)

    def _configure_auth(self, auth_type: str, auth_value: str) -> None:
        mode = (auth_type or "none").strip().lower()
        value = (auth_value or "").strip()
        if mode == "none" or not value:
            return

        if mode == "cookie":
            parsed_any = False
            for part in value.split(";"):
                chunk = part.strip()
                if "=" in chunk:
                    name, cookie_val = chunk.split("=", 1)
                    name = name.strip()
                    if name:
                        self.session.cookies.set(name, cookie_val.strip())
                        parsed_any = True
            if not parsed_any:
                self.session.headers["Cookie"] = value
        elif mode == "bearer":
            token = value[7:].strip() if value.lower().startswith("bearer ") else value
            self.session.headers["Authorization"] = f"Bearer {token}"
        elif mode in ("header", "custom_header"):
            if ":" in value:
                header_name, header_val = value.split(":", 1)
                if header_name.strip():
                    self.session.headers[header_name.strip()] = header_val.strip()

    def _check_cancelled(self) -> None:
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise ScanCancelledError("Scan execution was cancelled.")

    def _acquire_rate_token(self) -> None:
        if self.rate_limit_rps <= 0:
            return

        while True:
            self._check_cancelled()
            with self._lock:
                now = time.monotonic()
                elapsed = max(0.0, now - self._last_refill)
                self._tokens = min(
                    self._bucket_capacity,
                    self._tokens + elapsed * self.rate_limit_rps,
                )
                self._last_refill = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                wait_s = (1.0 - self._tokens) / self.rate_limit_rps

            if self.cancel_event is not None:
                if self.cancel_event.wait(timeout=wait_s):
                    raise ScanCancelledError("Scan execution was cancelled.")
            else:
                time.sleep(wait_s)

    def _reserve_request_slot(self) -> None:
        with self._lock:
            if self.requests_sent >= self.max_requests:
                raise RequestLimitExceededError(
                    f"Request budget exhausted ({self.max_requests} requests)."
                )
            self.requests_sent += 1

    def request(
        self,
        method: str,
        url: str,
        *,
        follow_redirects: bool = True,
        **kwargs: Any,
    ) -> requests.Response:
        """Send an HTTP request after scope, cancellation, budget, and rate checks."""
        request_kwargs = dict(kwargs)
        request_kwargs.pop("allow_redirects", None)
        request_kwargs.setdefault("timeout", self.timeout_s)

        origin_url = self.guardrail.validate_url(url)
        current_url = origin_url
        current_method = method.upper()

        resp: requests.Response | None = None
        for _ in range(self.max_redirects + 1):
            self._check_cancelled()
            current_url = self.guardrail.validate_url(current_url)
            if self.requests_sent >= self.max_requests:
                raise RequestLimitExceededError(
                    f"Request budget exhausted ({self.max_requests} requests)."
                )
            self._acquire_rate_token()
            self._reserve_request_slot()

            resp = self.session.request(
                current_method,
                current_url,
                allow_redirects=False,
                **request_kwargs,
            )

            if (
                not follow_redirects
                or resp.status_code not in _REDIRECT_STATUSES
                or "location" not in resp.headers
            ):
                return resp

            next_url = urljoin(current_url, resp.headers["location"])
            next_url = self.guardrail.validate_url(next_url)
            if not self.guardrail.is_same_origin(origin_url, next_url):
                raise ScopeViolationError(
                    f"Redirect to '{next_url}' escaped target origin '{origin_url}'."
                )

            # Follow standard HTTP redirect method transitions
            if resp.status_code in (301, 302, 303) and current_method not in ("GET", "HEAD"):
                current_method = "GET"
                request_kwargs.pop("data", None)
                request_kwargs.pop("json", None)

            current_url = next_url

        assert resp is not None
        return resp

    def get(
        self,
        url: str,
        *,
        follow_redirects: bool = True,
        **kwargs: Any,
    ) -> requests.Response:
        """Send a scope-validated HTTP GET request."""
        return self.request("GET", url, follow_redirects=follow_redirects, **kwargs)

    def post(
        self,
        url: str,
        *,
        follow_redirects: bool = True,
        **kwargs: Any,
    ) -> requests.Response:
        """Send a scope-validated HTTP POST request."""
        return self.request("POST", url, follow_redirects=follow_redirects, **kwargs)

    def calibrate_soft_404(self, base_url: str) -> Soft404Fingerprint:
        """Probe a random nonexistent path to fingerprint custom Soft-404 responses."""
        validated = self.guardrail.validate_url(base_url)
        probe_path = f"__owasp_lite_soft404_{uuid.uuid4().hex[:12]}"
        probe_url = urljoin(validated.rstrip("/") + "/", probe_path)
        resp = self.get(probe_url, follow_redirects=True)
        body = resp.text or ""
        return Soft404Fingerprint(
            status_code=resp.status_code,
            content_length=len(body),
            body_sample=body[:4096],
        )

    def auto_login_dvwa(
        self,
        base_url: str,
        username: str = "admin",
        password: str = "password",
    ) -> bool:
        """Authenticate against a local DVWA lab instance and set ``security=low``."""
        validated = self.guardrail.validate_url(base_url)
        login_url = urljoin(validated.rstrip("/") + "/", "login.php")
        get_resp = self.get(login_url, follow_redirects=True)

        body = get_resp.text or ""
        match = _DVWA_TOKEN_RE_1.search(body) or _DVWA_TOKEN_RE_2.search(body)
        payload: dict[str, str] = {
            "username": username,
            "password": password,
            "Login": "Login",
        }
        if match:
            payload["user_token"] = match.group(1)

        post_resp = self.post(login_url, data=payload, follow_redirects=True)
        self.session.cookies.set("security", "low")

        final_url = (post_resp.url or "").lower()
        final_body = (post_resp.text or "").lower()
        if post_resp.status_code >= 400:
            return False
        if "login failed" in final_body:
            return False
        if final_url.endswith("/login.php") and "logout" not in final_body:
            return False
        return True

    def close(self) -> None:
        """Close the underlying ``requests.Session``."""
        self.session.close()

    def __enter__(self) -> ScannerHttpClient:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()


__all__ = [
    "RequestLimitExceededError",
    "SCANNER_USER_AGENT",
    "ScanCancelledError",
    "ScannerHttpClient",
    "Soft404Fingerprint",
]
