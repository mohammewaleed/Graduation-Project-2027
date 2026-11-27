"""Active input-validation checks for SQL parameterization and error handling.

Implements two non-destructive verification plugins:
- ``SQLiErrorBasedCheck`` (``sqli_error_based``): submits single syntax-quote
  characters to discovered query parameters and HTML form fields to detect
  unhandled DBMS syntax error traces absent from the baseline response.
- ``SQLiBooleanDiffCheck`` (``sqli_boolean_diff``): compares response similarity
  between benign true and false boolean conditions relative to a baseline
  response using ``difflib.SequenceMatcher``.

Pure Python (standard library + ``requests`` via ``ctx.http_client``) with zero
FastAPI, SQLAlchemy, Starlette, or Pydantic dependencies.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass
from typing import ClassVar
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

from backend.scanner.checks.base import BaseCheck, CheckContext
from backend.scanner.http_client import (
    RequestLimitExceededError,
    ScanCancelledError,
)
from backend.scanner.models import (
    CheckKind,
    Confidence,
    OWASPCategory,
    RawFinding,
    ScanProfile,
    Severity,
)
from backend.scanner.policy import ScopeViolationError

ACTIVE_PROFILES: frozenset[ScanProfile] = frozenset(
    {ScanProfile.STANDARD, ScanProfile.DEEP}
)

# Non-destructive single-character syntax probes for DBMS error trace detection.
SYNTAX_PROBES: tuple[str, ...] = ("'", '"', "')")

# Non-mutable form input types and CSRF fields that should not be mutated as targets.
_SKIP_INPUT_TYPES: frozenset[str] = frozenset(
    {"submit", "button", "image", "reset"}
)
_CSRF_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "csrf",
        "csrf_token",
        "_csrf",
        "xsrf",
        "xsrf_token",
        "_token",
        "user_token",
        "authenticity_token",
        "__requestverificationtoken",
    }
)

# Compiled DBMS driver and syntax error signatures across 5 major relational engines.
DBMS_ERROR_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "MySQL",
        re.compile(
            r"You have an error in your SQL syntax|"
            r"check the manual that corresponds to your (?:MySQL|MariaDB) server version|"
            r"MySQLSyntaxErrorException|"
            r"Warning:\s+mysql(?:i)?_|"
            r"valid MySQL result|"
            r"pymysql\.err\.(?:ProgrammingError|OperationalError)|"
            r"mysql\.connector\.errors",
            re.IGNORECASE,
        ),
    ),
    (
        "PostgreSQL",
        re.compile(
            r"PostgreSQL.*ERROR|"
            r"ERROR:\s+syntax error at or near|"
            r"ERROR:\s+unterminated quoted string at or near|"
            r"pg_query\(\)\s*:|"
            r"pg_exec\(\)\s*:|"
            r"psycopg2(?:\.errors)?\.(?:SyntaxError|ProgrammingError)|"
            r"org\.postgresql\.util\.PSQLException|"
            r"valid PostgreSQL result",
            re.IGNORECASE,
        ),
    ),
    (
        "SQLite",
        re.compile(
            r"SQLite/JDBCDriver|"
            r"SQLite\.Exception|"
            r"System\.Data\.SQLite\.SQLiteException|"
            r"sqlite3\.(?:OperationalError|ProgrammingError|Warning):|"
            r"SQLITE_ERROR|"
            r"unrecognized token:|"
            r'near\s+"[^"]*":\s+syntax error|'
            r"incomplete input",
            re.IGNORECASE,
        ),
    ),
    (
        "Microsoft SQL Server",
        re.compile(
            r"Driver.*SQL[\-\_\ ]*Server|"
            r"OLE DB.*SQL Server|"
            r"Unclosed quotation mark after the character string|"
            r"Microsoft SQL Native Client error|"
            r"\[Microsoft\]\[ODBC SQL Server Driver\]|"
            r"\[SQL Server\]|"
            r"Incorrect syntax near|"
            r"System\.Data\.SqlClient\.SqlException",
            re.IGNORECASE,
        ),
    ),
    (
        "Oracle",
        re.compile(
            r"\bORA-(?:00933|00936|01756|00904|00907|00921|01722|\d{5})\b|"
            r"Oracle error|"
            r"Oracle.*Driver|"
            r"quoted string not properly terminated|"
            r"java\.sql\.SQLException:\s*ORA-",
            re.IGNORECASE,
        ),
    ),
)


@dataclass(slots=True)
class _ParameterTarget:
    """Normalized query or form parameter target for active input checks."""

    url: str
    action_url: str
    method: str
    param_name: str
    baseline_params: dict[str, str]


def _extract_excerpt(body: str, start: int, end: int, radius: int = 120) -> str:
    """Return a whitespace-normalized excerpt around a matched signature."""
    snippet_start = max(0, start - 40)
    snippet_end = min(len(body), end + radius)
    excerpt = body[snippet_start:snippet_end]
    return " ".join(excerpt.split())[:300]


def _match_dbms_error(body: str) -> tuple[str, re.Match[str]] | None:
    """Return ``(dbms_name, match)`` if ``body`` contains any known SQL error signature."""
    if not body:
        return None
    for dbms, pattern in DBMS_ERROR_SIGNATURES:
        match = pattern.search(body)
        if match is not None:
            return (dbms, match)
    return None


def _build_url_with_query(base_url: str, params: dict[str, str]) -> str:
    """Rebuild ``base_url`` replacing its query string with ``params``."""
    parsed = urlsplit(base_url)
    query = urlencode(list(params.items()))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", query, ""))


def _strip_query(url: str) -> str:
    """Return ``url`` without query parameters or fragments."""
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))


def _collect_parameter_targets(ctx: CheckContext) -> list[_ParameterTarget]:
    """Collect deduplicated query-parameter and HTML-form parameter targets."""
    targets: list[_ParameterTarget] = []
    seen_keys: set[tuple[str, str, str]] = set()

    def add_query_endpoint(raw_url: str, declared_params: list[str] | None = None) -> None:
        if not raw_url:
            return
        if not ctx.guardrail.is_same_origin(ctx.target_url, raw_url):
            return
        if ctx.guardrail.is_destructive_path(raw_url):
            return

        parsed = urlsplit(raw_url)
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        baseline_map: dict[str, str] = {}
        for k, v in query_pairs:
            if k:
                baseline_map[k] = v if v != "" else "1"
        for p in declared_params or []:
            if p and p not in baseline_map:
                baseline_map[p] = "1"

        if not baseline_map:
            return

        clean_action = _strip_query(raw_url)
        norm_path = parsed.path or "/"
        for param_name in baseline_map:
            dedup_key = ("GET", norm_path, param_name.lower())
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)
            targets.append(
                _ParameterTarget(
                    url=raw_url,
                    action_url=clean_action,
                    method="GET",
                    param_name=param_name,
                    baseline_params=dict(baseline_map),
                )
            )

    for ep in ctx.surface.endpoints:
        if (ep.method or "GET").strip().upper() == "GET":
            add_query_endpoint(ep.url, ep.params)

    for cached in ctx.responses.by_origin(ctx.target_url):
        add_query_endpoint(cached.url)

    for form in ctx.surface.forms:
        action_url = form.action_url or form.source_url or ctx.target_url
        if not ctx.guardrail.is_same_origin(ctx.target_url, action_url):
            continue
        if ctx.guardrail.is_destructive_path(action_url):
            continue

        method = (form.method or "GET").strip().upper() or "GET"
        if method not in ("GET", "POST"):
            continue

        baseline_form: dict[str, str] = {}
        mutable_fields: list[str] = []
        for inp in form.inputs:
            name = (inp.name or "").strip()
            if not name:
                continue
            itype = (inp.input_type or "text").strip().lower()
            default_val = inp.value if inp.value != "" else ("1" if itype == "number" else "test")
            baseline_form[name] = default_val
            if itype not in _SKIP_INPUT_TYPES and name.lower() not in _CSRF_FIELD_NAMES:
                mutable_fields.append(name)

        clean_action = _strip_query(action_url) if method == "GET" else action_url
        norm_path = urlsplit(action_url).path or "/"
        for field_name in mutable_fields:
            dedup_key = (method, norm_path, field_name.lower())
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)
            targets.append(
                _ParameterTarget(
                    url=action_url,
                    action_url=clean_action,
                    method=method,
                    param_name=field_name,
                    baseline_params=dict(baseline_form),
                )
            )

    return targets


def _send_target_request(
    ctx: CheckContext,
    target: _ParameterTarget,
    override_value: str | None = None,
) -> requests.Response | None:
    """Dispatch a GET or POST request for ``target`` with optional parameter override."""
    params = dict(target.baseline_params)
    if override_value is not None:
        params[target.param_name] = override_value

    try:
        if target.method == "POST":
            return ctx.http_client.post(
                target.action_url,
                data=params,
                follow_redirects=True,
            )
        request_url = _build_url_with_query(target.action_url, params)
        return ctx.http_client.get(request_url, follow_redirects=True)
    except (ScanCancelledError, RequestLimitExceededError):
        raise
    except (ScopeViolationError, requests.RequestException):
        return None


def _normalize_body_for_similarity(body: str, probe_value: str, base_value: str) -> str:
    """Remove direct probe reflections before computing structural similarity."""
    if not body:
        return ""
    cleaned = body
    if probe_value:
        cleaned = cleaned.replace(probe_value, base_value)
    return cleaned[:16384]


class SQLiErrorBasedCheck(BaseCheck):
    """Detects unhandled database driver error traces triggered by syntax quotes."""

    id: ClassVar[str] = "sqli_error_based"
    name: ClassVar[str] = "Error-Based SQL Injection"
    owasp_category: ClassVar[str] = OWASPCategory.A03
    cwe_id: ClassVar[str] = "CWE-89"
    kind: ClassVar[CheckKind] = CheckKind.ACTIVE
    default_severity: ClassVar[Severity] = Severity.CRITICAL
    profiles: ClassVar[frozenset[ScanProfile]] = ACTIVE_PROFILES
    description: ClassVar[str] = (
        "Submits non-destructive syntax quote characters to discovered query "
        "parameters and form fields, checking for MySQL, PostgreSQL, SQLite, "
        "MSSQL, or Oracle driver error traces absent from the baseline response."
    )

    def run(self, ctx: CheckContext) -> list[RawFinding]:
        if ctx.is_cancelled():
            return []

        targets = _collect_parameter_targets(ctx)
        if not targets:
            return []

        findings: list[RawFinding] = []
        baseline_cache: dict[tuple[str, str], str] = {}

        for target in targets:
            if ctx.is_cancelled():
                break

            base_key = (target.method, target.url)
            if base_key in baseline_cache:
                baseline_body = baseline_cache[base_key]
            else:
                cached = (
                    ctx.responses.get(target.url)
                    if target.method == "GET"
                    else None
                )
                if cached is not None:
                    baseline_body = cached.body or ""
                else:
                    base_resp = _send_target_request(ctx, target, override_value=None)
                    if base_resp is None:
                        continue
                    baseline_body = base_resp.text or ""
                baseline_cache[base_key] = baseline_body

            base_val = target.baseline_params.get(target.param_name, "1")
            candidate_probes: list[str] = []
            for probe in (*SYNTAX_PROBES, f"{base_val}'", f'{base_val}"'):
                if probe not in candidate_probes:
                    candidate_probes.append(probe)

            for probe_val in candidate_probes:
                if ctx.is_cancelled():
                    break

                resp = _send_target_request(ctx, target, override_value=probe_val)
                if resp is None:
                    continue

                probe_body = resp.text or ""
                matched = _match_dbms_error(probe_body)
                if matched is None:
                    continue

                dbms, match = matched
                # Verify that the matched signature was NOT already present in baseline
                if match.re.search(baseline_body) is not None:
                    continue

                snippet = _extract_excerpt(probe_body, match.start(), match.end())
                findings.append(
                    RawFinding(
                        check_id=self.id,
                        title=f"Error-Based SQL Injection ({dbms})",
                        owasp_category=self.owasp_category,
                        cwe_id=self.cwe_id,
                        severity=self.default_severity,
                        url=target.action_url if target.method == "POST" else target.url,
                        method=target.method,
                        parameter=target.param_name,
                        evidence={
                            "dbms": dbms,
                            "probe": probe_val,
                            "status_code": str(resp.status_code),
                            "signature": match.group(0)[:120],
                            "snippet": snippet,
                        },
                        confidence=Confidence.HIGH,
                    )
                )
                break

        return findings


class SQLiBooleanDiffCheck(BaseCheck):
    """Detects boolean-condition response differentials relative to baseline."""

    id: ClassVar[str] = "sqli_boolean_diff"
    name: ClassVar[str] = "Boolean-Based Blind SQL Injection"
    owasp_category: ClassVar[str] = OWASPCategory.A03
    cwe_id: ClassVar[str] = "CWE-89"
    kind: ClassVar[CheckKind] = CheckKind.ACTIVE
    default_severity: ClassVar[Severity] = Severity.HIGH
    profiles: ClassVar[frozenset[ScanProfile]] = ACTIVE_PROFILES
    description: ClassVar[str] = (
        "Compares response similarity between benign true and false boolean "
        "predicates relative to a clean baseline response using SequenceMatcher."
    )

    TRUE_THRESHOLD: ClassVar[float] = 0.85
    FALSE_THRESHOLD: ClassVar[float] = 0.70

    def run(self, ctx: CheckContext) -> list[RawFinding]:
        if ctx.is_cancelled():
            return []

        targets = _collect_parameter_targets(ctx)
        if not targets:
            return []

        findings: list[RawFinding] = []

        for target in targets:
            if ctx.is_cancelled():
                break

            base_resp = _send_target_request(ctx, target, override_value=None)
            if base_resp is None or base_resp.status_code >= 500:
                continue

            baseline_body = (base_resp.text or "").strip()
            if not baseline_body or _match_dbms_error(baseline_body) is not None:
                continue

            base_val = target.baseline_params.get(target.param_name, "1") or "1"
            raw_pairs = [
                (f"{base_val}' AND '1'='1", f"{base_val}' AND '1'='2"),
                ("' AND '1'='1", "' AND '1'='2"),
                (f"{base_val} AND 1=1", f"{base_val} AND 1=2"),
                ("1 AND 1=1", "1 AND 1=2"),
            ]
            probe_pairs: list[tuple[str, str]] = []
            for pair in raw_pairs:
                if pair not in probe_pairs:
                    probe_pairs.append(pair)

            for true_probe, false_probe in probe_pairs:
                if ctx.is_cancelled():
                    break

                true_resp = _send_target_request(ctx, target, override_value=true_probe)
                if true_resp is None or true_resp.status_code != base_resp.status_code:
                    continue

                true_body = (true_resp.text or "").strip()
                if not true_body or _match_dbms_error(true_body) is not None:
                    continue

                norm_base = _normalize_body_for_similarity(baseline_body, "", base_val)
                norm_true = _normalize_body_for_similarity(true_body, true_probe, base_val)
                true_ratio = difflib.SequenceMatcher(None, norm_base, norm_true).ratio()
                if true_ratio < self.TRUE_THRESHOLD:
                    continue

                false_resp = _send_target_request(ctx, target, override_value=false_probe)
                if false_resp is None:
                    continue

                false_body = (false_resp.text or "").strip()
                if _match_dbms_error(false_body) is not None:
                    continue

                norm_false = _normalize_body_for_similarity(false_body, false_probe, base_val)
                false_ratio = difflib.SequenceMatcher(None, norm_base, norm_false).ratio()

                if false_ratio < self.FALSE_THRESHOLD:
                    findings.append(
                        RawFinding(
                            check_id=self.id,
                            title="Boolean-Based Blind SQL Injection",
                            owasp_category=self.owasp_category,
                            cwe_id=self.cwe_id,
                            severity=self.default_severity,
                            url=target.action_url if target.method == "POST" else target.url,
                            method=target.method,
                            parameter=target.param_name,
                            evidence={
                                "true_probe": true_probe,
                                "false_probe": false_probe,
                                "true_similarity": f"{true_ratio:.3f}",
                                "false_similarity": f"{false_ratio:.3f}",
                                "baseline_length": str(len(baseline_body)),
                                "true_length": str(len(true_body)),
                                "false_length": str(len(false_body)),
                            },
                            confidence=Confidence.MEDIUM,
                        )
                    )
                    break

        return findings


__all__ = [
    "DBMS_ERROR_SIGNATURES",
    "SQLiBooleanDiffCheck",
    "SQLiErrorBasedCheck",
    "SYNTAX_PROBES",
]
