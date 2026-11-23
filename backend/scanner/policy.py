"""Authorized-target scope guardrail and safety policies.

Enforces that the scanner only ever contacts explicitly authorized local,
loopback, RFC1918 private, or local Docker lab targets. Re-resolves DNS
before every request to defeat DNS rebinding to public IP addresses.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
from collections.abc import Callable, Iterable
from typing import Any
from urllib.parse import urlsplit

DEFAULT_ALLOWLIST: frozenset[str] = frozenset(
    {
        "localhost",
        "127.0.0.1",
        "::1",
        "host.docker.internal",
        "dvwa",
        "juice-shop",
        "vulnbench",
    }
)

_DESTRUCTIVE_PATH_RE = re.compile(
    r"(?:^|/)(?:logout|signout|sign-out|log-out|delete|remove|destroy|drop)(?:/|$|\.)",
    re.IGNORECASE,
)

ResolverFn = Callable[[str, int], list[tuple[Any, ...]]]


class ScopeViolationError(ValueError):
    """Raised when a target URL or redirect violates the local-only scope policy."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "TARGET_NOT_ALLOWED",
    ) -> None:
        self.code = code
        super().__init__(message)


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _is_allowed_ip(ip_str: str) -> bool:
    """Return True iff ``ip_str`` is a loopback or private RFC1918/ULA address."""
    cleaned = ip_str.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(cleaned)
    except ValueError:
        return False

    if addr.is_loopback:
        return True

    # Allow private LAN/Docker addresses (RFC1918 / IPv6 ULA), while rejecting
    # link-local (e.g. cloud metadata 169.254.169.254), unspecified, and multicast.
    return (
        addr.is_private
        and not addr.is_link_local
        and not addr.is_unspecified
        and not addr.is_multicast
    )


class ScopeGuardrail:
    """Validates target URLs, DNS resolutions, origins, and destructive paths."""

    def __init__(
        self,
        allowlist: Iterable[str] | None = None,
        resolver: ResolverFn | None = None,
        allow_unresolved_docker_hosts: bool = True,
    ) -> None:
        hosts: set[str] = set(DEFAULT_ALLOWLIST)

        env_hosts = os.environ.get("SCAN_ALLOWLIST", "")
        for item in env_hosts.split(","):
            normalized = item.strip().lower()
            if normalized:
                hosts.add(normalized)

        if allowlist is not None:
            for item in allowlist:
                normalized = item.strip().lower()
                if normalized:
                    hosts.add(normalized)

        self.allowlist: frozenset[str] = frozenset(hosts)
        self._resolver: ResolverFn = resolver or socket.getaddrinfo
        self._allow_unresolved_docker_hosts = allow_unresolved_docker_hosts

    def _is_hostname_allowlisted(self, hostname: str) -> bool:
        return hostname in self.allowlist or hostname.endswith(".local")

    def validate_url(self, url: str) -> str:
        """Validate that ``url`` is an authorized local/private HTTP(S) target.

        Raises ``ScopeViolationError`` on disallowed schemes, embedded
        credentials, non-allowlisted hosts, or DNS resolutions that yield any
        public / non-local IP address.
        """
        if not isinstance(url, str) or not url.strip():
            raise ScopeViolationError("Target URL must be a non-empty string.")

        parsed = urlsplit(url.strip())
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            raise ScopeViolationError(
                f"Unsupported URL scheme '{parsed.scheme}'; only http and https are allowed."
            )

        if parsed.username is not None or parsed.password is not None:
            raise ScopeViolationError(
                "Embedded credentials in target URLs are not permitted."
            )

        hostname = parsed.hostname
        if not hostname:
            raise ScopeViolationError("Target URL must include a valid hostname.")
        hostname = hostname.lower()

        try:
            port = parsed.port or _default_port(scheme)
        except ValueError as exc:
            raise ScopeViolationError(f"Invalid port in target URL: {exc}") from exc

        # Case 1: Literal IP address (IPv4 or IPv6)
        try:
            ipaddress.ip_address(hostname)
            is_literal_ip = True
        except ValueError:
            is_literal_ip = False

        if is_literal_ip:
            if not _is_allowed_ip(hostname):
                raise ScopeViolationError(
                    f"Target IP '{hostname}' is outside permitted loopback/private ranges."
                )
            return url.strip()

        # Case 2: Hostname — must be allowlisted (or *.local) AND resolve only to local IPs
        if not self._is_hostname_allowlisted(hostname):
            raise ScopeViolationError(
                f"Target host '{hostname}' is not in the authorized local scan allowlist."
            )

        try:
            addrinfos = self._resolver(hostname, port)
        except OSError as exc:
            if self._allow_unresolved_docker_hosts and hostname in self.allowlist:
                return url.strip()
            raise ScopeViolationError(
                f"Unable to resolve target host '{hostname}': {exc}"
            ) from exc

        if not addrinfos:
            if self._allow_unresolved_docker_hosts and hostname in self.allowlist:
                return url.strip()
            raise ScopeViolationError(
                f"Target host '{hostname}' resolved to no IP addresses."
            )

        for entry in addrinfos:
            sockaddr = entry[4]
            resolved_ip = str(sockaddr[0])
            if not _is_allowed_ip(resolved_ip):
                raise ScopeViolationError(
                    f"Target host '{hostname}' resolved to non-local IP '{resolved_ip}'."
                )

        return url.strip()

    def is_same_origin(self, base_url: str, candidate_url: str) -> bool:
        """Return True iff both URLs share scheme, hostname, and normalized port."""
        try:
            base = urlsplit(base_url)
            cand = urlsplit(candidate_url)
        except ValueError:
            return False

        base_scheme = base.scheme.lower()
        cand_scheme = cand.scheme.lower()
        if base_scheme not in ("http", "https") or cand_scheme not in ("http", "https"):
            return False

        if not base.hostname or not cand.hostname:
            return False

        try:
            base_port = base.port or _default_port(base_scheme)
            cand_port = cand.port or _default_port(cand_scheme)
        except ValueError:
            return False

        return (
            base_scheme == cand_scheme
            and base.hostname.lower() == cand.hostname.lower()
            and base_port == cand_port
        )

    def is_destructive_path(self, url: str) -> bool:
        """Return True if ``url`` points to a logout or destructive state-changing path."""
        try:
            path = urlsplit(url).path or ""
        except ValueError:
            return False
        return bool(_DESTRUCTIVE_PATH_RE.search(path))


__all__ = [
    "DEFAULT_ALLOWLIST",
    "ResolverFn",
    "ScopeGuardrail",
    "ScopeViolationError",
]
