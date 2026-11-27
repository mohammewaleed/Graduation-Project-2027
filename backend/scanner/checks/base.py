"""Plugin base class, execution context, and auto-registration registry.

Pure Python (standard library + internal scanner models only) with zero
FastAPI, SQLAlchemy, Starlette, or Pydantic dependencies.
"""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar

from backend.scanner.crawler import ResponseCache
from backend.scanner.http_client import ScannerHttpClient, Soft404Fingerprint
from backend.scanner.models import (
    AttackSurface,
    CheckKind,
    RawFinding,
    ScanConfig,
    ScanProfile,
    Severity,
)
from backend.scanner.policy import ScopeGuardrail


@dataclass
class CheckContext:
    """Shared execution context passed to every security check plugin."""

    target_url: str
    http_client: ScannerHttpClient
    guardrail: ScopeGuardrail
    surface: AttackSurface
    responses: ResponseCache
    soft_404: Soft404Fingerprint | None = None
    cancel_event: threading.Event = field(default_factory=threading.Event)
    config: ScanConfig | None = None

    def is_cancelled(self) -> bool:
        """Return True if cooperative scan cancellation has been requested."""
        return self.cancel_event.is_set()


class BaseCheck(ABC):
    """Abstract base class for all OWASP Lite security check plugins.

    Concrete subclasses that declare a non-empty string ``id`` directly in
    their class body are automatically registered in ``BaseCheck.registry``.
    """

    id: ClassVar[str]
    name: ClassVar[str]
    owasp_category: ClassVar[str]
    cwe_id: ClassVar[str]
    kind: ClassVar[CheckKind]
    default_severity: ClassVar[Severity]
    profiles: ClassVar[frozenset[ScanProfile]]
    description: ClassVar[str] = ""

    registry: ClassVar[dict[str, type[BaseCheck]]] = {}

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        check_id = cls.__dict__.get("id")
        if isinstance(check_id, str) and check_id.strip():
            BaseCheck.registry[check_id] = cls

    @classmethod
    def to_catalog_entry(cls) -> dict[str, object]:
        """Serialize plugin metadata for catalog APIs and diagnostics."""
        return {
            "id": cls.id,
            "name": cls.name,
            "owasp_category": str(cls.owasp_category),
            "cwe_id": cls.cwe_id,
            "kind": str(cls.kind),
            "default_severity": str(cls.default_severity),
            "profiles": sorted(str(profile) for profile in cls.profiles),
            "description": cls.description,
        }

    @abstractmethod
    def run(self, ctx: CheckContext) -> list[RawFinding]:
        """Execute the check against ``ctx`` and return raw findings."""
        ...


__all__ = [
    "BaseCheck",
    "CheckContext",
]
