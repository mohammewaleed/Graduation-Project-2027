"""Unit tests for backend.scanner.policy.ScopeGuardrail."""

from __future__ import annotations

import socket
import unittest
from typing import Any

from backend.scanner.policy import ScopeGuardrail, ScopeViolationError


def _fake_addrinfo(ip: str, port: int = 80) -> list[tuple[Any, ...]]:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sockaddr = (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port)
    return [(family, socket.SOCK_STREAM, 6, "", sockaddr)]


class TestScopeGuardrail(unittest.TestCase):
    """Tests for target URL validation, DNS-rebinding defense, origin checks, and destructive paths."""

    def test_allows_local_loopback_private_and_docker_targets(self) -> None:
        # Use a deterministic resolver that returns loopback for allowlisted hostnames
        # so the test never depends on host DNS configuration.
        def local_resolver(host: str, port: int) -> list[tuple[Any, ...]]:
            if host in ("dvwa", "juice-shop", "vulnbench"):
                raise OSError("Docker DNS not active in unit test")
            return _fake_addrinfo("127.0.0.1", port)

        guard = ScopeGuardrail(resolver=local_resolver)
        allowed_urls = [
            "http://localhost:8000",
            "http://127.0.0.1:5050",
            "http://192.168.1.10:8080",
            "http://10.0.0.5",
            "http://host.docker.internal:3000",
            "http://dvwa",
            "http://juice-shop:3000",
            "http://vulnbench:5050",
        ]
        for url in allowed_urls:
            with self.subTest(url=url):
                self.assertEqual(guard.validate_url(url), url)

    def test_rejects_external_hosts_disallowed_schemes_and_embedded_credentials(self) -> None:
        guard = ScopeGuardrail(resolver=lambda host, port: _fake_addrinfo("127.0.0.1", port))
        disallowed_urls = [
            "https://google.com",
            "https://example.com",
            "http://8.8.8.8",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "ftp://localhost/a",
            "http://admin:pass@localhost/",
            "http://user@127.0.0.1:8000/",
            "",
        ]
        for url in disallowed_urls:
            with self.subTest(url=url):
                with self.assertRaises(ScopeViolationError):
                    guard.validate_url(url)

    def test_dns_rebinding_defense_rejects_public_ip_resolution(self) -> None:
        def evil_resolver(host: str, port: int) -> list[tuple[Any, ...]]:
            return _fake_addrinfo("93.184.216.34", port)

        guard = ScopeGuardrail(resolver=evil_resolver)
        for url in ("http://localhost:8000", "http://evil.local/admin"):
            with self.subTest(url=url):
                with self.assertRaises(ScopeViolationError):
                    guard.validate_url(url)

    def test_dns_rebinding_rejects_mixed_local_and_public_resolution(self) -> None:
        def mixed_resolver(host: str, port: int) -> list[tuple[Any, ...]]:
            return _fake_addrinfo("127.0.0.1", port) + _fake_addrinfo("93.184.216.34", port)

        guard = ScopeGuardrail(resolver=mixed_resolver)
        with self.assertRaises(ScopeViolationError):
            guard.validate_url("http://app.local:8080")

    def test_dot_local_hostname_allowed_when_resolving_to_private_ip(self) -> None:
        guard = ScopeGuardrail(resolver=lambda host, port: _fake_addrinfo("192.168.1.42", port))
        self.assertEqual(guard.validate_url("http://myapp.local:8080"), "http://myapp.local:8080")

    def test_is_same_origin_default_port_normalization(self) -> None:
        guard = ScopeGuardrail()
        self.assertTrue(guard.is_same_origin("http://127.0.0.1:80", "http://127.0.0.1"))
        self.assertTrue(guard.is_same_origin("http://127.0.0.1/a", "http://127.0.0.1:80/b"))
        self.assertTrue(guard.is_same_origin("https://localhost:443/x", "https://localhost/y"))
        self.assertTrue(guard.is_same_origin("http://LOCALHOST:8000/", "http://localhost:8000/api"))

    def test_is_same_origin_rejects_cross_port_host_or_scheme(self) -> None:
        guard = ScopeGuardrail()
        self.assertFalse(guard.is_same_origin("http://127.0.0.1:8000", "http://127.0.0.1:8001"))
        self.assertFalse(guard.is_same_origin("http://127.0.0.1:8000", "http://localhost:8000"))
        self.assertFalse(guard.is_same_origin("http://127.0.0.1", "https://127.0.0.1"))
        self.assertFalse(guard.is_same_origin("http://127.0.0.1", "https://example.com"))

    def test_is_destructive_path(self) -> None:
        guard = ScopeGuardrail()
        destructive = [
            "http://127.0.0.1/logout",
            "http://127.0.0.1/user/signout",
            "http://127.0.0.1/items/delete",
            "http://127.0.0.1/account/remove",
            "http://127.0.0.1/logout.php",
            "http://127.0.0.1/admin/destroy/42",
        ]
        for url in destructive:
            with self.subTest(destructive=url):
                self.assertTrue(guard.is_destructive_path(url))

        safe = [
            "http://127.0.0.1/search",
            "http://127.0.0.1/login",
            "http://127.0.0.1/api/users",
            "http://127.0.0.1/items/list",
        ]
        for url in safe:
            with self.subTest(safe=url):
                self.assertFalse(guard.is_destructive_path(url))


if __name__ == "__main__":
    unittest.main()
