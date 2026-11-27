"""Deterministic finding fingerprinting, deduplication, and risk scoring engine.

Implements the exact SHA-1 fingerprint and bounded 0-100 risk score formulas
defined in SAD Chapter 4 (Data Model, REST/SSE API, and Remediation KB Design).
Pure Python (standard library only).
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit

from backend.scanner.models import (
    Confidence,
    EnrichedFinding,
    Severity,
    TriageStatus,
)

_MULTI_SLASH_RE = re.compile(r"/{2,}")

SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

CONFIDENCE_RANK: dict[Confidence, int] = {
    Confidence.HIGH: 3,
    Confidence.MEDIUM: 2,
    Confidence.LOW: 1,
}

RISK_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 6,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def _normalize_fingerprint_path(url: str) -> str:
    """Extract and normalize the URL path component for deterministic hashing."""
    parsed = urlsplit((url or "").strip())
    path = parsed.path or "/"
    path = _MULTI_SLASH_RE.sub("/", path)
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    return path


def compute_fingerprint(
    check_id: str,
    method: str,
    url: str,
    parameter: str | None = None,
) -> str:
    """Compute the canonical 40-character lowercase SHA-1 finding fingerprint.

    Formula (SAD Chapter 4):
        SHA1(lower(check_id) + "|" + upper(method) + "|" + normalized_path + "|" + lower(parameter or ""))
    """
    norm_check = (check_id or "").strip().lower()
    norm_method = (method or "GET").strip().upper()
    norm_path = _normalize_fingerprint_path(url)
    norm_param = (parameter or "").strip().lower()
    raw_key = f"{norm_check}|{norm_method}|{norm_path}|{norm_param}"
    return hashlib.sha1(raw_key.encode("utf-8")).hexdigest()


def _finding_rank(finding: EnrichedFinding) -> tuple[int, int]:
    """Return comparable ``(severity_rank, confidence_rank)`` for dedup selection."""
    try:
        sev = Severity(finding.severity)
    except ValueError:
        sev = Severity.INFO
    try:
        conf = Confidence(finding.confidence)
    except ValueError:
        conf = Confidence.LOW
    return (SEVERITY_RANK[sev], CONFIDENCE_RANK[conf])


def deduplicate_findings(findings: list[EnrichedFinding]) -> list[EnrichedFinding]:
    """Merge duplicate findings by ``fingerprint``, keeping highest severity & confidence."""
    by_fp: dict[str, EnrichedFinding] = {}
    order: list[str] = []

    for finding in findings:
        fp = finding.fingerprint or compute_fingerprint(
            finding.check_id,
            finding.method,
            finding.url,
            finding.parameter,
        )
        existing = by_fp.get(fp)
        if existing is None:
            by_fp[fp] = finding
            order.append(fp)
        elif _finding_rank(finding) > _finding_rank(existing):
            by_fp[fp] = finding

    return [by_fp[fp] for fp in order]


def sort_findings_by_severity(findings: list[EnrichedFinding]) -> list[EnrichedFinding]:
    """Return findings sorted highest severity & confidence first."""
    return sorted(
        findings,
        key=lambda f: (
            -_finding_rank(f)[0],
            -_finding_rank(f)[1],
            f.check_id,
            f.url,
            f.parameter or "",
        ),
    )


def summarize_findings(findings: list[EnrichedFinding]) -> dict[str, int]:
    """Count active (non-``false_positive``) findings across all five severity levels."""
    counts: dict[str, int] = {
        Severity.CRITICAL.value: 0,
        Severity.HIGH.value: 0,
        Severity.MEDIUM.value: 0,
        Severity.LOW.value: 0,
        Severity.INFO.value: 0,
    }
    for finding in findings:
        if finding.triage_status == TriageStatus.FALSE_POSITIVE:
            continue
        key = str(finding.severity).lower()
        if key in counts:
            counts[key] += 1
    return counts


def calculate_risk_score(findings: list[EnrichedFinding]) -> int:
    """Compute the SAD Chapter 4 bounded 0-100 risk score.

    Formula:
        risk_score = min(100, 10 * N_critical + 6 * N_high + 3 * N_medium + 1 * N_low)
    Findings marked ``TriageStatus.FALSE_POSITIVE`` are excluded; ``info``
    carries weight 0.
    """
    counts = summarize_findings(findings)
    raw_score = (
        RISK_WEIGHTS[Severity.CRITICAL] * counts[Severity.CRITICAL.value]
        + RISK_WEIGHTS[Severity.HIGH] * counts[Severity.HIGH.value]
        + RISK_WEIGHTS[Severity.MEDIUM] * counts[Severity.MEDIUM.value]
        + RISK_WEIGHTS[Severity.LOW] * counts[Severity.LOW.value]
    )
    return min(100, max(0, raw_score))


__all__ = [
    "CONFIDENCE_RANK",
    "RISK_WEIGHTS",
    "SEVERITY_RANK",
    "calculate_risk_score",
    "compute_fingerprint",
    "deduplicate_findings",
    "sort_findings_by_severity",
    "summarize_findings",
]
