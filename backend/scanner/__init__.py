"""Pure Python OWASP Top 10 scanning engine package.

Houses the decoupled data models, local-only scope guardrail, rate-limited
HTTP client, bounded BFS crawler, BaseCheck plugin auto-registry, curated
OWASP Top 10 (2021) security checks, multi-stack Remediation KB, deterministic
scoring/deduplication engine, and end-to-end ScanOrchestrator.
"""

from backend.scanner.checks import (
    BaseCheck,
    CheckContext,
    get_checks_for_profile,
    get_registered_checks,
    list_check_catalog,
    load_all_checks,
)
from backend.scanner.crawler import (
    ResponseCache,
    WebCrawler,
    normalize_url,
)
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
from backend.scanner.orchestrator import (
    ScanOrchestrator,
    ScanOutcome,
)
from backend.scanner.policy import (
    DEFAULT_ALLOWLIST,
    ResolverFn,
    ScopeGuardrail,
    ScopeViolationError,
)
from backend.scanner.remediation import RemediationKB
from backend.scanner.scoring import (
    calculate_risk_score,
    compute_fingerprint,
    deduplicate_findings,
    summarize_findings,
)

__version__ = "1.0.0"

__all__ = [
    "__version__",
    "AttackSurface",
    "BaseCheck",
    "CachedResponse",
    "CheckContext",
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
    "RemediationKB",
    "RequestLimitExceededError",
    "ResolverFn",
    "ResponseCache",
    "SCANNER_USER_AGENT",
    "ScanCancelledError",
    "ScanConfig",
    "ScanOrchestrator",
    "ScanOutcome",
    "ScanProfile",
    "ScanProgress",
    "ScanStatus",
    "ScannerHttpClient",
    "ScopeGuardrail",
    "ScopeViolationError",
    "Severity",
    "Soft404Fingerprint",
    "TriageStatus",
    "WebCrawler",
    "calculate_risk_score",
    "compute_fingerprint",
    "deduplicate_findings",
    "get_checks_for_profile",
    "get_registered_checks",
    "list_check_catalog",
    "load_all_checks",
    "normalize_url",
    "summarize_findings",
]
