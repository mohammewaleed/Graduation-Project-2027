"""SQLAlchemy 2.0 Third Normal Form (3NF) ORM models for OWASP Lite Scanner.

Portable across both SQLite (WAL mode) and PostgreSQL 16 using UUID v4
``String(36)`` primary keys, ``Text`` JSON payload columns, UTC
``DateTime(timezone=True)`` timestamps, and cascading foreign keys.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.database import Base
from backend.scanner.models import (
    Confidence,
    ScanProfile,
    ScanStatus,
    Severity,
    TriageStatus,
)

DEFAULT_SUMMARY_COUNTS: dict[str, int] = {
    Severity.CRITICAL.value: 0,
    Severity.HIGH.value: 0,
    Severity.MEDIUM.value: 0,
    Severity.LOW.value: 0,
    Severity.INFO.value: 0,
}
DEFAULT_SUMMARY_JSON: str = json.dumps(DEFAULT_SUMMARY_COUNTS)


def utcnow() -> datetime:
    """Return the current timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def _new_uuid() -> str:
    """Generate a canonical lowercase UUID v4 string."""
    return str(uuid.uuid4())


def _safe_json_loads(raw: str | None, fallback: Any) -> Any:
    """Parse a JSON text column, returning ``fallback`` on empty or invalid data."""
    if not raw:
        return fallback
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return fallback
    return parsed if isinstance(parsed, type(fallback)) else fallback


class Project(Base):
    """Registered local web application target authorized for scanning."""

    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=_new_uuid,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    base_url: Mapped[str] = mapped_column(String(512), nullable=False)
    target_stack: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="fastapi",
    )
    authorized_confirmed: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    authorized_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )

    scans: Mapped[list[Scan]] = relationship(
        "Scan",
        back_populates="project",
        cascade="all, delete-orphan",
    )


class Scan(Base):
    """Point-in-time vulnerability scan job and materialized summary rollups."""

    __tablename__ = "scans"
    __table_args__ = (
        Index("ix_scans_project_created", "project_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=_new_uuid,
    )
    project_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    profile: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=ScanProfile.STANDARD.value,
    )
    status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=ScanStatus.QUEUED.value,
        index=True,
    )
    progress_pct: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    current_stage: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default=ScanStatus.QUEUED.value,
    )
    pages_crawled: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    requests_sent: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    risk_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    summary_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default=DEFAULT_SUMMARY_JSON,
    )
    error_log_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="[]",
    )
    config_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="{}",
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        index=True,
    )

    project: Mapped[Project] = relationship("Project", back_populates="scans")
    endpoints: Mapped[list[Endpoint]] = relationship(
        "Endpoint",
        back_populates="scan",
        cascade="all, delete-orphan",
    )
    findings: Mapped[list[Finding]] = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan",
    )

    @property
    def summary(self) -> dict[str, int]:
        """Return parsed severity counts with all five canonical keys present."""
        parsed = _safe_json_loads(self.summary_json, {})
        counts = dict(DEFAULT_SUMMARY_COUNTS)
        for key in counts:
            val = parsed.get(key)
            if isinstance(val, int):
                counts[key] = val
        return counts

    @property
    def errors(self) -> list[str]:
        """Return parsed non-fatal or fatal scan error messages."""
        parsed = _safe_json_loads(self.error_log_json, [])
        return [str(item) for item in parsed]

    @property
    def config(self) -> dict[str, Any]:
        """Return parsed redacted scan configuration snapshot."""
        return _safe_json_loads(self.config_json, {})


class Endpoint(Base):
    """Discovered HTTP endpoint captured during a scan's crawl stage."""

    __tablename__ = "endpoints"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=_new_uuid,
    )
    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    url: Mapped[str] = mapped_column(Text, nullable=False)
    method: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="GET",
    )
    params_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="[]",
    )
    source: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="link",
    )
    status_code: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    scan: Mapped[Scan] = relationship("Scan", back_populates="endpoints")

    @property
    def params(self) -> list[str]:
        """Return parsed list of extracted query or form parameter names."""
        parsed = _safe_json_loads(self.params_json, [])
        return [str(item) for item in parsed]


class Finding(Base):
    """Deduplicated, enriched vulnerability finding with developer triage state."""

    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_scan_severity", "scan_id", "severity"),
        Index("ix_findings_scan_fingerprint", "scan_id", "fingerprint"),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=_new_uuid,
    )
    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    check_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    owasp_category: Mapped[str] = mapped_column(String(128), nullable=False)
    cwe_id: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=Confidence.HIGH.value,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    endpoint_url: Mapped[str] = mapped_column(Text, nullable=False)
    method: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="GET",
    )
    parameter: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        default=None,
    )
    evidence_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="{}",
    )
    explanation: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="",
    )
    fix_json: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="{}",
    )
    triage_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=TriageStatus.OPEN.value,
    )
    triage_note: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        default=None,
    )
    fingerprint: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )

    scan: Mapped[Scan] = relationship("Scan", back_populates="findings")

    @property
    def evidence(self) -> dict[str, str]:
        """Return parsed key/value proof-of-detection evidence dictionary."""
        parsed = _safe_json_loads(self.evidence_json, {})
        return {str(k): str(v) for k, v in parsed.items()}

    @property
    def fix(self) -> dict[str, Any]:
        """Return parsed multi-stack remediation guidance payload."""
        return _safe_json_loads(self.fix_json, {})


__all__ = [
    "DEFAULT_SUMMARY_COUNTS",
    "DEFAULT_SUMMARY_JSON",
    "Endpoint",
    "Finding",
    "Project",
    "Scan",
    "utcnow",
]
