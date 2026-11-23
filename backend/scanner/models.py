"""Core data models, enums, and configuration types for the OWASP Lite scanner.

This module is pure Python (standard library only) with zero FastAPI or
SQLAlchemy dependencies so the scanning engine remains cleanly decoupled
from the web API and persistence layers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    """Normalized vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(StrEnum):
    """Detection confidence assigned to a finding."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ScanProfile(StrEnum):
    """Predefined scan depth and budget profiles."""

    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"


class ScanStatus(StrEnum):
    """Lifecycle states of a scan job."""

    QUEUED = "queued"
    CRAWLING = "crawling"
    SCANNING = "scanning"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TriageStatus(StrEnum):
    """Developer triage states for a reported finding."""

    OPEN = "open"
    FIXED = "fixed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED = "accepted"


class CheckKind(StrEnum):
    """Execution category of a vulnerability check plugin."""

    PASSIVE = "passive"
    ACTIVE = "active"
    DISCOVERY = "discovery"


class OWASPCategory(StrEnum):
    """OWASP Top 10 (2021) vulnerability categories."""

    A01 = "A01:2021 - Broken Access Control"
    A02 = "A02:2021 - Cryptographic Failures"
    A03 = "A03:2021 - Injection"
    A04 = "A04:2021 - Insecure Design"
    A05 = "A05:2021 - Security Misconfiguration"
    A06 = "A06:2021 - Vulnerable and Outdated Components"
    A07 = "A07:2021 - Identification and Authentication Failures"
    A08 = "A08:2021 - Software and Data Integrity Failures"
    A09 = "A09:2021 - Security Logging and Monitoring Failures"
    A10 = "A10:2021 - Server-Side Request Forgery (SSRF)"


PROFILE_LIMITS: dict[ScanProfile, dict[str, int]] = {
    ScanProfile.QUICK: {
        "max_depth": 2,
        "max_pages": 50,
        "max_duration_s": 120,
    },
    ScanProfile.STANDARD: {
        "max_depth": 3,
        "max_pages": 150,
        "max_duration_s": 300,
    },
    ScanProfile.DEEP: {
        "max_depth": 5,
        "max_pages": 400,
        "max_duration_s": 600,
    },
}


@dataclass(slots=True)
class FormInput:
    """Single input, select, or textarea control inside an HTML form."""

    name: str
    input_type: str = "text"
    value: str = ""


@dataclass(slots=True)
class FormRecord:
    """Discovered HTML form and its constituent fields."""

    action_url: str
    method: str = "GET"
    inputs: list[FormInput] = field(default_factory=list)
    source_url: str = ""


@dataclass(slots=True)
class EndpointRecord:
    """Discovered HTTP endpoint and its known query/body parameter names."""

    url: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    source: str = "link"
    status_code: int = 0


@dataclass(slots=True)
class CachedResponse:
    """Lightweight cached HTTP response shared across passive checks."""

    url: str
    status_code: int
    headers: dict[str, str]
    body: str
    content_type: str = ""


@dataclass(slots=True)
class AttackSurface:
    """Aggregated endpoints, forms, and scripts discovered by the crawler."""

    base_url: str
    endpoints: list[EndpointRecord] = field(default_factory=list)
    forms: list[FormRecord] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)


@dataclass(slots=True)
class RawFinding:
    """Unenriched finding emitted directly by an individual security check."""

    check_id: str
    title: str
    owasp_category: str
    cwe_id: str
    severity: Severity
    url: str
    method: str = "GET"
    parameter: str | None = None
    evidence: dict[str, str] = field(default_factory=dict)
    confidence: Confidence = Confidence.HIGH


@dataclass(slots=True)
class FixSnippet:
    """Before/after code snippet illustrating how to remediate a finding."""

    stack: str
    language: str
    before: str
    after: str


@dataclass(slots=True)
class RemediationFix:
    """Structured remediation guidance attached to an enriched finding."""

    summary: str
    root_cause: str
    snippets: list[FixSnippet] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


@dataclass(slots=True)
class EnrichedFinding:
    """Finding enriched with developer explanation, remediation, and fingerprint."""

    check_id: str
    title: str
    owasp_category: str
    cwe_id: str
    severity: Severity
    url: str
    explanation: str
    fix: RemediationFix
    fingerprint: str
    method: str = "GET"
    parameter: str | None = None
    evidence: dict[str, str] = field(default_factory=dict)
    confidence: Confidence = Confidence.HIGH
    triage_status: TriageStatus = TriageStatus.OPEN

    @classmethod
    def from_raw(
        cls,
        raw: RawFinding,
        *,
        explanation: str,
        fix: RemediationFix,
        fingerprint: str,
        triage_status: TriageStatus = TriageStatus.OPEN,
    ) -> EnrichedFinding:
        """Build an ``EnrichedFinding`` from a ``RawFinding`` and remediation data."""
        return cls(
            check_id=raw.check_id,
            title=raw.title,
            owasp_category=raw.owasp_category,
            cwe_id=raw.cwe_id,
            severity=raw.severity,
            url=raw.url,
            method=raw.method,
            parameter=raw.parameter,
            evidence=dict(raw.evidence),
            confidence=raw.confidence,
            explanation=explanation,
            fix=fix,
            fingerprint=fingerprint,
            triage_status=triage_status,
        )


@dataclass(slots=True)
class ScanConfig:
    """Runtime configuration for a single scan execution."""

    target_url: str
    profile: ScanProfile = ScanProfile.STANDARD
    target_stack: str = "fastapi"
    auth_type: str = "none"
    auth_value: str = ""
    auto_login_dvwa: bool = False
    dvwa_username: str = "admin"
    dvwa_password: str = "password"
    max_depth: int | None = None
    max_pages: int | None = None
    rate_limit_rps: float = 10.0
    max_requests: int = 2000
    timeout_s: float = 10.0
    enabled_checks: list[str] | None = None

    @property
    def effective_max_depth(self) -> int:
        """Return configured max crawl depth or the profile default."""
        return (
            self.max_depth
            if self.max_depth is not None
            else PROFILE_LIMITS[self.profile]["max_depth"]
        )

    @property
    def effective_max_pages(self) -> int:
        """Return configured max pages or the profile default."""
        return (
            self.max_pages
            if self.max_pages is not None
            else PROFILE_LIMITS[self.profile]["max_pages"]
        )

    @property
    def effective_max_duration_s(self) -> int:
        """Return max crawl duration for the active scan profile."""
        return PROFILE_LIMITS[self.profile]["max_duration_s"]


@dataclass(slots=True)
class ScanProgress:
    """Progress snapshot reported during crawling and scanning stages."""

    stage: str
    percent: int
    pages_crawled: int = 0
    requests_sent: int = 0
    current_check: str = ""


__all__ = [
    "AttackSurface",
    "CachedResponse",
    "CheckKind",
    "Confidence",
    "EndpointRecord",
    "EnrichedFinding",
    "FixSnippet",
    "FormInput",
    "FormRecord",
    "OWASPCategory",
    "PROFILE_LIMITS",
    "RawFinding",
    "RemediationFix",
    "ScanConfig",
    "ScanProfile",
    "ScanProgress",
    "ScanStatus",
    "Severity",
    "TriageStatus",
]
