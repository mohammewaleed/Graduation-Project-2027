"""Pydantic v2 request and response schemas for the OWASP Lite REST API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.scanner.models import (
    ScanProfile,
    TriageStatus,
)

SUPPORTED_TARGET_STACKS: frozenset[str] = frozenset(
    {"fastapi", "flask", "express", "php", "html"}
)
SUPPORTED_AUTH_TYPES: frozenset[str] = frozenset(
    {"none", "cookie", "bearer", "header", "custom_header"}
)


def _default_summary() -> dict[str, int]:
    return {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }


class ErrorDetail(BaseModel):
    """Structured error body embedded in all 4xx/5xx API responses."""

    code: str
    message: str
    details: Any = None


class ErrorResponse(BaseModel):
    """Uniform top-level API error envelope (SAD Chapter 4)."""

    error: ErrorDetail


class ProjectCreate(BaseModel):
    """Payload for registering a new local project target."""

    name: str = Field(..., min_length=1, max_length=255)
    base_url: str = Field(..., min_length=1, max_length=512)
    target_stack: str = Field(default="fastapi")
    authorized_confirmed: bool = False

    @field_validator("name", "base_url")
    @classmethod
    def _strip_non_empty(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Field must not be blank.")
        return cleaned

    @field_validator("target_stack")
    @classmethod
    def _validate_target_stack(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in SUPPORTED_TARGET_STACKS:
            allowed = ", ".join(sorted(SUPPORTED_TARGET_STACKS))
            raise ValueError(
                f"Unsupported target_stack '{value}'. Must be one of: {allowed}."
            )
        return normalized


class ProjectUpdate(BaseModel):
    """Payload for editing an existing authorized local project target."""

    name: str | None = Field(default=None, min_length=1, max_length=255)
    base_url: str | None = Field(default=None, min_length=1, max_length=512)
    target_stack: str | None = None

    @field_validator("name", "base_url")
    @classmethod
    def _strip_optional_non_empty(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Field must not be blank.")
        return cleaned

    @field_validator("target_stack")
    @classmethod
    def _validate_optional_target_stack(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        if normalized not in SUPPORTED_TARGET_STACKS:
            allowed = ", ".join(sorted(SUPPORTED_TARGET_STACKS))
            raise ValueError(
                f"Unsupported target_stack '{value}'. Must be one of: {allowed}."
            )
        return normalized


class ProjectOut(BaseModel):
    """Serialized project record with aggregate scan telemetry."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    base_url: str
    target_stack: str
    authorized_confirmed: bool
    authorized_at: datetime
    created_at: datetime
    scan_count: int = 0
    latest_risk_score: int | None = None


class ScanCreate(BaseModel):
    """Payload for enqueuing a background vulnerability scan."""

    profile: ScanProfile = ScanProfile.STANDARD
    auth_type: str = "none"
    auth_value: str = ""
    auto_login_dvwa: bool = False
    dvwa_username: str = "admin"
    dvwa_password: str = "password"
    max_depth: int | None = Field(default=None, ge=0, le=10)
    max_pages: int | None = Field(default=None, ge=1, le=2000)
    enabled_checks: list[str] | None = None

    @field_validator("auth_type")
    @classmethod
    def _validate_auth_type(cls, value: str) -> str:
        normalized = (value or "none").strip().lower()
        if normalized not in SUPPORTED_AUTH_TYPES:
            allowed = ", ".join(sorted(SUPPORTED_AUTH_TYPES))
            raise ValueError(
                f"Unsupported auth_type '{value}'. Must be one of: {allowed}."
            )
        return normalized


class ScanUpdate(BaseModel):
    """Payload for editing a scan's profile or saved crawl/check configuration."""

    profile: ScanProfile | None = None
    max_depth: int | None = Field(default=None, ge=0, le=10)
    max_pages: int | None = Field(default=None, ge=1, le=2000)
    enabled_checks: list[str] | None = None


class ScanOut(BaseModel):
    """Serialized scan job state, progress telemetry, and severity rollups."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    project_name: str | None = None
    target_url: str | None = None
    profile: str
    status: str
    progress_pct: int = 0
    current_stage: str = "queued"
    pages_crawled: int = 0
    requests_sent: int = 0
    risk_score: int = 0
    summary: dict[str, int] = Field(default_factory=_default_summary)
    errors: list[str] = Field(default_factory=list)
    config: dict[str, Any] = Field(default_factory=dict)
    started_at: datetime
    finished_at: datetime | None = None
    created_at: datetime


class EndpointOut(BaseModel):
    """Serialized discovered HTTP endpoint from a scan's attack surface."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    url: str
    method: str
    params: list[str] = Field(default_factory=list)
    source: str
    status_code: int = 0


class FindingOut(BaseModel):
    """Serialized vulnerability finding with evidence, explanation, and code fixes."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    check_id: str
    owasp_category: str
    cwe_id: str
    severity: str
    confidence: str
    title: str
    endpoint_url: str
    method: str
    parameter: str | None = None
    evidence: dict[str, str] = Field(default_factory=dict)
    explanation: str = ""
    fix: dict[str, Any] = Field(default_factory=dict)
    triage_status: str = TriageStatus.OPEN.value
    triage_note: str | None = None
    fingerprint: str
    created_at: datetime
    updated_at: datetime


class FindingTriageUpdate(BaseModel):
    """Payload for updating a finding's developer triage status and note."""

    triage_status: TriageStatus
    triage_note: str | None = Field(default=None, max_length=2000)


class ScanCompareCounts(BaseModel):
    """Aggregate diff counts between a baseline and head scan."""

    new: int = 0
    fixed: int = 0
    unchanged: int = 0


class ScanCompareOut(BaseModel):
    """Fingerprint-based regression comparison across two scans."""

    base_scan_id: str
    head_scan_id: str
    counts: ScanCompareCounts
    new: list[FindingOut] = Field(default_factory=list)
    fixed: list[FindingOut] = Field(default_factory=list)
    unchanged: list[FindingOut] = Field(default_factory=list)


class CheckCatalogItemOut(BaseModel):
    """Metadata entry for a registered OWASP Top 10 security check plugin."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    owasp_category: str
    cwe_id: str
    kind: str
    default_severity: str
    profiles: list[str] = Field(default_factory=list)
    description: str = ""


__all__ = [
    "CheckCatalogItemOut",
    "EndpointOut",
    "ErrorDetail",
    "ErrorResponse",
    "FindingOut",
    "FindingTriageUpdate",
    "ProjectCreate",
    "ProjectOut",
    "ProjectUpdate",
    "SUPPORTED_AUTH_TYPES",
    "SUPPORTED_TARGET_STACKS",
    "ScanCompareCounts",
    "ScanCompareOut",
    "ScanCreate",
    "ScanOut",
    "ScanUpdate",
]
