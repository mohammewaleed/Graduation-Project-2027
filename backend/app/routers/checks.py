"""REST API route exposing the live registered OWASP Top 10 security check catalog."""

from __future__ import annotations

from fastapi import APIRouter

from backend.app.schemas import CheckCatalogItemOut
from backend.scanner.checks import list_check_catalog

router = APIRouter(prefix="/api/checks", tags=["checks"])


@router.get("", response_model=list[CheckCatalogItemOut])
def get_checks_catalog() -> list[CheckCatalogItemOut]:
    """Return metadata for all registered OWASP Top 10 vulnerability checks."""
    return [CheckCatalogItemOut.model_validate(entry) for entry in list_check_catalog()]
