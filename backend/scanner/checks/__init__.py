"""Check plugin discovery, profile filtering, and catalog metadata helpers.

Auto-discovers and imports all check submodules under ``backend.scanner.checks``
(``passive``, ``active``, ``discovery``) via ``pkgutil.walk_packages`` so every
concrete ``BaseCheck`` subclass self-registers in ``BaseCheck.registry``.
"""

from __future__ import annotations

import importlib
import pkgutil

from backend.scanner.checks.base import BaseCheck, CheckContext
from backend.scanner.models import CheckKind, ScanProfile

_KIND_ORDER: dict[CheckKind, int] = {
    CheckKind.PASSIVE: 0,
    CheckKind.ACTIVE: 1,
    CheckKind.DISCOVERY: 2,
}


def load_all_checks() -> dict[str, type[BaseCheck]]:
    """Auto-import all check submodules and return the registered check map."""
    prefix = f"{__name__}."
    for module_info in pkgutil.walk_packages(__path__, prefix=prefix):
        leaf = module_info.name.rsplit(".", 1)[-1]
        if leaf.startswith("_") or leaf == "base":
            continue
        importlib.import_module(module_info.name)
    return dict(BaseCheck.registry)


def get_registered_checks() -> dict[str, type[BaseCheck]]:
    """Return all registered check classes, auto-loading plugins first."""
    return load_all_checks()


def get_checks_for_profile(
    profile: ScanProfile,
    enabled_checks: list[str] | None = None,
) -> list[BaseCheck]:
    """Return instantiated check plugins enabled for ``profile``.

    When ``enabled_checks`` is provided, only check IDs present in that list
    (and applicable to ``profile``) are returned. Results are ordered
    deterministically: passive checks first, then active, then discovery,
    sorted alphabetically by ``check.id`` within each category.
    """
    target_profile = (
        profile if isinstance(profile, ScanProfile) else ScanProfile(str(profile))
    )
    registered = load_all_checks()
    allowed_ids = set(enabled_checks) if enabled_checks is not None else None

    selected_classes: list[type[BaseCheck]] = []
    for check_id, check_cls in registered.items():
        if target_profile not in check_cls.profiles:
            continue
        if allowed_ids is not None and check_id not in allowed_ids:
            continue
        selected_classes.append(check_cls)

    selected_classes.sort(
        key=lambda cls: (_KIND_ORDER.get(cls.kind, 99), cls.id)
    )
    return [cls() for cls in selected_classes]


def list_check_catalog() -> list[dict[str, object]]:
    """Return sorted metadata dicts for all registered checks (for `/api/checks`)."""
    registered = load_all_checks()
    ordered_classes = sorted(
        registered.values(),
        key=lambda cls: (_KIND_ORDER.get(cls.kind, 99), cls.id),
    )
    return [cls.to_catalog_entry() for cls in ordered_classes]


__all__ = [
    "BaseCheck",
    "CheckContext",
    "get_checks_for_profile",
    "get_registered_checks",
    "list_check_catalog",
    "load_all_checks",
]
