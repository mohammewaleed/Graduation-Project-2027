"""Pure Python OWASP Top 10 scanning engine package.

Houses the decoupled data models, local-only scope guardrail, rate-limited
HTTP client, HTML/form crawler, BaseCheck plugin auto-registry, and curated
OWASP Top 10 (2021) security checks.
"""

from backend.scanner.http_client import (
    SCANNER_USER_AGENT,
    RequestLimitExceededError,
    ScanCancelledError,
    ScannerHttpClient,
    Soft404Fingerprint,
)
from backend.scanner.models import (
    PROFILE_LIMITS,
    AttackSurface,
    CachedResponse,
    CheckKind,
    Confidence,
    EndpointRecord,
    EnrichedFinding,
    FixSnippet,
    FormInput,
    FormRecord,
    OWASPCategory,
    RawFinding,
    RemediationFix,
    ScanConfig,
    ScanProfile,
    ScanProgress,
    ScanStatus,
    Severity,
    TriageStatus,
)
from backend.scanner.policy import (
    DEFAULT_ALLOWLIST,
    ResolverFn,
    ScopeGuardrail,
    ScopeViolationError,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "AttackSurface",
    "CachedResponse",
    "CheckKind",
    "Confidence",
    "DEFAULT_ALLOWLIST",
    "EndpointRecord",
    "EnrichedFinding",
    "FixSnippet",
    "FormInput",
    "FormRecord",
    "OWASPCategory",
    "PROFILE_LIMITS",
    "RawFinding",
    "RemediationFix",
    "RequestLimitExceededError",
    "ResolverFn",
    "SCANNER_USER_AGENT",
    "ScanCancelledError",
    "ScanConfig",
    "ScanProfile",
    "ScanProgress",
    "ScanStatus",
    "ScannerHttpClient",
    "ScopeGuardrail",
    "ScopeViolationError",
    "Severity",
    "Soft404Fingerprint",
    "TriageStatus",
]
