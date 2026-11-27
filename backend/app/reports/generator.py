"""JSON and standalone offline HTML5 Developer Report generator.

Generates structured JSON audit bundles and 100% self-contained offline HTML5
reports using Jinja2 with strict HTML autoescaping enabled for ``.j2``
templates so untrusted target evidence can never execute as active markup.
"""

from __future__ import annotations

from datetime import datetime, timezone
import difflib
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlparse

from jinja2 import Environment, FileSystemLoader, select_autoescape

from backend.app.config import settings
from backend.app.db_models import Endpoint, Finding, Project, Scan
from backend.scanner.models import Confidence, Severity, TriageStatus
from backend.scanner.scoring import CONFIDENCE_RANK, SEVERITY_RANK

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
REPORT_TEMPLATE_NAME = "report.html.j2"

# Explicit autoescape including ".j2" guarantees untrusted evidence is escaped.
_JINJA_ENV = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html", "j2", "xml"]),
    trim_blocks=True,
    lstrip_blocks=True,
)

_SEVERITY_ORDER: tuple[str, ...] = (
    Severity.CRITICAL.value,
    Severity.HIGH.value,
    Severity.MEDIUM.value,
    Severity.LOW.value,
    Severity.INFO.value,
)

_SEVERITY_COLORS: dict[str, str] = {
    Severity.CRITICAL.value: "#dc2626",
    Severity.HIGH.value: "#ea580c",
    Severity.MEDIUM.value: "#d97706",
    Severity.LOW.value: "#2563eb",
    Severity.INFO.value: "#64748b",
}

_STACK_LABELS: dict[str, str] = {
    "fastapi": "Python (FastAPI)",
    "flask": "Python (Flask)",
    "express": "Node.js (Express)",
    "php": "PHP",
    "html": "HTML / Frontend",
}

_STACK_FILENAMES: dict[str, str] = {
    "fastapi": "app.py",
    "flask": "app.py",
    "express": "server.js",
    "php": "index.php",
    "html": "index.html",
}

_CTRL_KEYWORDS: frozenset[str] = frozenset(
    {
        "import",
        "from",
        "as",
        "return",
        "if",
        "elif",
        "else",
        "for",
        "while",
        "try",
        "except",
        "finally",
        "raise",
        "with",
        "await",
        "yield",
        "break",
        "continue",
        "pass",
        "throw",
        "catch",
        "export",
        "default",
        "switch",
        "case",
        "require",
        "include",
        "use",
    }
)

_DECL_KEYWORDS: frozenset[str] = frozenset(
    {
        "def",
        "async",
        "class",
        "lambda",
        "del",
        "in",
        "is",
        "not",
        "and",
        "or",
        "None",
        "True",
        "False",
        "const",
        "let",
        "var",
        "function",
        "new",
        "typeof",
        "true",
        "false",
        "null",
        "undefined",
        "echo",
        "public",
        "private",
        "protected",
        "static",
        "On",
        "Off",
    }
)

_CODE_TOKEN_RE = re.compile(
    r"""
    (?P<comment>\#[^\n]*|//[^\n]*|/\*.*?\*/|<!--.*?-->|^\s*;[^\n]*)
    |(?P<php_tag><\?php|\?>)
    |(?P<decorator>@[A-Za-z_][A-Za-z0-9_.]*)
    |(?P<string>(?:[fFrRbBuU]{0,2})(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`))
    |(?P<php_var>\$[A-Za-z_][A-Za-z0-9_]*)
    |(?P<number>\b\d+(?:\.\d+)?\b)
    |(?P<func>\b[A-Za-z_][A-Za-z0-9_]*(?=\s*\())
    |(?P<ident>\b[A-Za-z_][A-Za-z0-9_]*\b)
    """,
    re.VERBOSE,
)

_HTML_TOKEN_RE = re.compile(
    r"""
    (?P<comment><!--.*?-->)
    |(?P<tag></?[A-Za-z][A-Za-z0-9:-]*|/?>)
    |(?P<string>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')
    |(?P<attr>\b[A-Za-z_:][A-Za-z0-9_.:-]*(?=\s*=))
    """,
    re.VERBOSE,
)


def _snippet_filename(stack: str, language: str) -> str:
    """Return a realistic VS Code editor tab filename for a remediation snippet."""
    stack_key = (stack or "").strip().lower()
    if stack_key in _STACK_FILENAMES:
        return _STACK_FILENAMES[stack_key]
    lang = (language or "").strip().lower()
    ext_map = {
        "python": "app.py",
        "javascript": "server.js",
        "typescript": "server.ts",
        "php": "index.php",
        "html": "index.html",
        "nginx": "nginx.conf",
        "bash": "fix.sh",
    }
    return ext_map.get(lang, "snippet.txt")


def _tokenize_line(line: str, language: str) -> list[dict[str, str]]:
    """Split a single source line into VS Code Dark+ syntax tokens (autoescape-safe)."""
    if not line:
        return [{"cls": "tok-plain", "text": " "}]

    lang = (language or "").strip().lower()
    pattern = _HTML_TOKEN_RE if lang in {"html", "xml"} else _CODE_TOKEN_RE

    tokens: list[dict[str, str]] = []
    pos = 0
    for match in pattern.finditer(line):
        start, end = match.span()
        if start > pos:
            tokens.append({"cls": "tok-plain", "text": line[pos:start]})
        kind = match.lastgroup or "plain"
        text = match.group(0)
        if kind == "comment":
            cls = "tok-comment"
        elif kind == "string":
            cls = "tok-str"
        elif kind == "decorator":
            cls = "tok-dec"
        elif kind == "php_tag":
            cls = "tok-kw"
        elif kind == "php_var":
            cls = "tok-attr"
        elif kind == "number":
            cls = "tok-num"
        elif kind == "tag":
            cls = "tok-tag"
        elif kind == "attr":
            cls = "tok-attr"
        elif kind == "func":
            if text in _CTRL_KEYWORDS:
                cls = "tok-ctrl"
            elif text in _DECL_KEYWORDS:
                cls = "tok-kw"
            else:
                cls = "tok-fn"
        elif kind == "ident":
            if text in _CTRL_KEYWORDS:
                cls = "tok-ctrl"
            elif text in _DECL_KEYWORDS:
                cls = "tok-kw"
            else:
                cls = "tok-plain"
        else:
            cls = "tok-plain"
        tokens.append({"cls": cls, "text": text})
        pos = end

    if pos < len(line):
        tokens.append({"cls": "tok-plain", "text": line[pos:]})
    return tokens


def _tokenize_diff_pair(
    before_code: str,
    after_code: str,
    language: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Tokenize Before & After code and tag exact changed lines ('del'/'add'/'ctx')."""
    before_raw = (before_code or "").splitlines() or [""]
    after_raw = (after_code or "").splitlines() or [""]

    before_tags = ["ctx"] * len(before_raw)
    after_tags = ["ctx"] * len(after_raw)

    matcher = difflib.SequenceMatcher(None, before_raw, after_raw)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag in {"replace", "delete"}:
            for i in range(i1, i2):
                if before_raw[i].strip():
                    before_tags[i] = "del"
        if tag in {"replace", "insert"}:
            for j in range(j1, j2):
                if after_raw[j].strip():
                    after_tags[j] = "add"

    before_lines = [
        {
            "num": idx,
            "diff": before_tags[idx - 1],
            "marker": "-" if before_tags[idx - 1] == "del" else " ",
            "tokens": _tokenize_line(line, language),
        }
        for idx, line in enumerate(before_raw, start=1)
    ]
    after_lines = [
        {
            "num": idx,
            "diff": after_tags[idx - 1],
            "marker": "+" if after_tags[idx - 1] == "add" else " ",
            "tokens": _tokenize_line(line, language),
        }
        for idx, line in enumerate(after_raw, start=1)
    ]
    return before_lines, after_lines


def _build_code_locator(
    method: str,
    endpoint_url: str,
    parameter: str | None,
) -> dict[str, str]:
    """Build a developer-friendly codebase search hint from DAST HTTP evidence."""
    parsed = urlparse(endpoint_url or "")
    path = parsed.path or "/"
    verb = (method or "GET").strip().upper()
    if parameter:
        search_hint = f'Search your route handler for "{path}" and input "{parameter}"'
    else:
        search_hint = f'Search your route/middleware handler for "{path}"'
    return {
        "route": f"{verb} {path}",
        "parameter": parameter or "",
        "search_hint": search_hint,
    }


def _format_reference_item(url: str) -> dict[str, str]:
    """Turn a reference URL into a clean card title + domain badge."""
    parsed = urlparse(url)
    host = (parsed.netloc or "").replace("www.", "")
    path_parts = [p for p in (parsed.path or "").strip("/").split("/") if p]
    slug = path_parts[-1] if path_parts else host
    slug = re.sub(r"\.(html?|php|md)$", "", slug, flags=re.IGNORECASE)
    pretty = slug.replace("_", " ").replace("-", " ").strip()

    if "cheatsheetseries.owasp.org" in host:
        title = f"OWASP {pretty}" if not pretty.lower().startswith("owasp") else pretty
        category = "Cheat Sheet"
    elif "owasp.org" in host and "top10" in (parsed.path or "").lower():
        title = f"OWASP Top 10 — {pretty}"
        category = "OWASP Top 10"
    elif "developer.mozilla.org" in host:
        title = f"MDN Web Docs — {pretty}"
        category = "MDN Docs"
    elif "cwe.mitre.org" in host:
        title = f"MITRE CWE — {pretty}"
        category = "CWE Reference"
    else:
        title = pretty or host
        category = "Security Guide"

    return {
        "url": url,
        "title": title,
        "domain": host,
        "category": category,
    }


def _iso_utc(dt: datetime | None) -> str | None:
    """Format a datetime as an ISO-8601 UTC string."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _format_display_dt(dt: datetime | None) -> str:
    """Format a datetime for human-readable HTML report display."""
    if dt is None:
        return "N/A"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _risk_level_meta(risk_score: int) -> dict[str, str]:
    """Return human-readable risk level label and accent palette for a 0-100 score."""
    if risk_score >= 75:
        return {"label": "Critical Risk", "slug": "critical", "color": "#dc2626"}
    if risk_score >= 50:
        return {"label": "High Risk", "slug": "high", "color": "#ea580c"}
    if risk_score >= 25:
        return {"label": "Moderate Risk", "slug": "medium", "color": "#d97706"}
    if risk_score >= 1:
        return {"label": "Low Risk", "slug": "low", "color": "#2563eb"}
    return {"label": "Minimal Risk", "slug": "clean", "color": "#16a34a"}


def _severity_rank_value(severity: str) -> int:
    try:
        return SEVERITY_RANK[Severity(str(severity).lower())]
    except ValueError:
        return 0


def _confidence_rank_value(confidence: str) -> int:
    try:
        return CONFIDENCE_RANK[Confidence(str(confidence).lower())]
    except ValueError:
        return 0


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    """Sort ORM findings highest severity & confidence first."""
    return sorted(
        findings,
        key=lambda f: (
            -_severity_rank_value(f.severity),
            -_confidence_rank_value(f.confidence),
            f.check_id or "",
            f.endpoint_url or "",
            f.parameter or "",
        ),
    )


def _format_endpoint_banner(method: str, endpoint_url: str, parameter: str | None) -> str:
    """Build the exact endpoint banner string, e.g. ``POST /api/login · parameter: user``."""
    parsed = urlparse(endpoint_url or "")
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    verb = (method or "GET").strip().upper()
    if parameter:
        return f"{verb} {path} · parameter: {parameter}"
    return f"{verb} {path}"


def _is_safe_http_url(url: str) -> bool:
    """Allow only http/https reference links to prevent javascript: URI injection."""
    parsed = urlparse((url or "").strip())
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _normalize_fix_payload(
    raw_fix: dict[str, Any],
    preferred_stack: str,
) -> dict[str, Any]:
    """Normalize remediation fix payload and order snippets with preferred stack first."""
    preferred = (preferred_stack or "fastapi").strip().lower()
    raw_snippets = raw_fix.get("snippets")
    normalized_snippets: list[dict[str, Any]] = []

    if isinstance(raw_snippets, list):
        for item in raw_snippets:
            if not isinstance(item, dict):
                continue
            stack = str(item.get("stack", "")).strip().lower()
            normalized_snippets.append(
                {
                    "stack": stack,
                    "label": _STACK_LABELS.get(stack, stack.upper() if stack else "Generic"),
                    "language": str(item.get("language", "")).strip().lower(),
                    "before": str(item.get("before", "")),
                    "after": str(item.get("after", "")),
                    "is_preferred": stack == preferred,
                }
            )
    elif isinstance(raw_fix.get("stacks"), dict):
        for stack_key, item in raw_fix["stacks"].items():
            if not isinstance(item, dict):
                continue
            stack = str(stack_key).strip().lower()
            normalized_snippets.append(
                {
                    "stack": stack,
                    "label": str(item.get("label") or _STACK_LABELS.get(stack, stack.upper())),
                    "language": str(item.get("language", "")).strip().lower(),
                    "before": str(item.get("before", "")),
                    "after": str(item.get("after", "")),
                    "is_preferred": stack == preferred,
                }
            )

    preferred_items = [s for s in normalized_snippets if s["is_preferred"]]
    other_items = [s for s in normalized_snippets if not s["is_preferred"]]
    ordered_snippets = preferred_items + other_items

    raw_refs = raw_fix.get("references") or []
    references = [str(ref).strip() for ref in raw_refs if isinstance(ref, str) and ref.strip()]

    return {
        "summary": str(raw_fix.get("summary") or ""),
        "root_cause": str(raw_fix.get("root_cause") or ""),
        "snippets": ordered_snippets,
        "references": references,
        "safe_references": [ref for ref in references if _is_safe_http_url(ref)],
    }


def _compute_breakdowns(
    sorted_findings: list[Finding],
) -> tuple[dict[str, int], dict[str, int], list[dict[str, Any]]]:
    """Compute active severity counts, triage status counts, and OWASP breakdown."""
    severity_counts: dict[str, int] = {sev: 0 for sev in _SEVERITY_ORDER}
    triage_counts: dict[str, int] = {
        TriageStatus.OPEN.value: 0,
        TriageStatus.FIXED.value: 0,
        TriageStatus.FALSE_POSITIVE.value: 0,
        TriageStatus.ACCEPTED.value: 0,
    }
    owasp_map: dict[str, dict[str, Any]] = {}

    for finding in sorted_findings:
        sev = str(finding.severity or Severity.INFO.value).lower()
        triage = str(finding.triage_status or TriageStatus.OPEN.value).lower()
        is_fp = triage == TriageStatus.FALSE_POSITIVE.value

        if triage in triage_counts:
            triage_counts[triage] += 1
        else:
            triage_counts[triage] = triage_counts.get(triage, 0) + 1

        if not is_fp and sev in severity_counts:
            severity_counts[sev] += 1

        category = finding.owasp_category or "Uncategorized"
        entry = owasp_map.get(category)
        if entry is None:
            entry = {
                "category": category,
                "total": 0,
                "active": 0,
                "highest_severity": sev,
            }
            owasp_map[category] = entry

        entry["total"] += 1
        if not is_fp:
            entry["active"] += 1
        if _severity_rank_value(sev) > _severity_rank_value(entry["highest_severity"]):
            entry["highest_severity"] = sev

    owasp_breakdown = sorted(
        owasp_map.values(),
        key=lambda row: (
            -row["active"],
            -_severity_rank_value(row["highest_severity"]),
            row["category"],
        ),
    )
    return severity_counts, triage_counts, owasp_breakdown


def _build_svg_chart_rows(severity_counts: dict[str, int]) -> list[dict[str, Any]]:
    """Precompute geometry for the inline SVG horizontal severity bar chart."""
    max_count = max(severity_counts.values(), default=0)
    max_bar_width = 270.0
    rows: list[dict[str, Any]] = []
    for idx, sev in enumerate(_SEVERITY_ORDER):
        count = severity_counts.get(sev, 0)
        bar_width = (count / max_count) * max_bar_width if max_count > 0 else 0.0
        if count > 0 and bar_width < 6.0:
            bar_width = 6.0
        y = 14 + idx * 32
        rows.append(
            {
                "severity": sev,
                "label": sev.capitalize(),
                "count": count,
                "color": _SEVERITY_COLORS[sev],
                "y": y,
                "bar_width": round(bar_width, 1),
                "label_y": y + 15,
                "count_x": round(96 + bar_width + 8, 1),
            }
        )
    return rows


def build_json_report(
    project: Project,
    scan: Scan,
    endpoints: list[Endpoint],
    findings: list[Finding],
) -> dict[str, Any]:
    """Build the complete structured JSON developer audit report (SAD Chapter 4)."""
    generated_at = datetime.now(timezone.utc)
    sorted_findings = _sort_findings(list(findings))
    severity_counts, triage_counts, owasp_breakdown = _compute_breakdowns(sorted_findings)
    risk_meta = _risk_level_meta(scan.risk_score)

    duration_seconds: float | None = None
    if scan.started_at is not None and scan.finished_at is not None:
        start_dt = (
            scan.started_at
            if scan.started_at.tzinfo is not None
            else scan.started_at.replace(tzinfo=timezone.utc)
        )
        end_dt = (
            scan.finished_at
            if scan.finished_at.tzinfo is not None
            else scan.finished_at.replace(tzinfo=timezone.utc)
        )
        duration_seconds = round(max(0.0, (end_dt - start_dt).total_seconds()), 2)

    active_findings = sum(severity_counts.values())
    false_positives = triage_counts.get(TriageStatus.FALSE_POSITIVE.value, 0)

    serialized_endpoints = [
        {
            "id": ep.id,
            "scan_id": ep.scan_id,
            "url": ep.url,
            "method": (ep.method or "GET").upper(),
            "params": ep.params,
            "source": ep.source,
            "status_code": ep.status_code,
        }
        for ep in endpoints
    ]

    serialized_findings: list[dict[str, Any]] = []
    for finding in sorted_findings:
        normalized_fix = _normalize_fix_payload(finding.fix, project.target_stack)
        serialized_findings.append(
            {
                "id": finding.id,
                "scan_id": finding.scan_id,
                "check_id": finding.check_id,
                "owasp_category": finding.owasp_category,
                "cwe_id": finding.cwe_id,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "title": finding.title,
                "endpoint_url": finding.endpoint_url,
                "method": (finding.method or "GET").upper(),
                "parameter": finding.parameter,
                "endpoint_banner": _format_endpoint_banner(
                    finding.method,
                    finding.endpoint_url,
                    finding.parameter,
                ),
                "evidence": finding.evidence,
                "explanation": finding.explanation,
                "fix": {
                    "summary": normalized_fix["summary"],
                    "root_cause": normalized_fix["root_cause"],
                    "snippets": [
                        {
                            "stack": s["stack"],
                            "language": s["language"],
                            "before": s["before"],
                            "after": s["after"],
                        }
                        for s in normalized_fix["snippets"]
                    ],
                    "references": normalized_fix["references"],
                },
                "triage_status": finding.triage_status,
                "triage_note": finding.triage_note,
                "fingerprint": finding.fingerprint,
                "created_at": _iso_utc(finding.created_at),
                "updated_at": _iso_utc(finding.updated_at),
            }
        )

    return {
        "metadata": {
            "schema_version": "1.0",
            "generator": settings.app_name,
            "generator_version": settings.app_version,
            "generated_at": _iso_utc(generated_at),
        },
        "project": {
            "id": project.id,
            "name": project.name,
            "base_url": project.base_url,
            "target_stack": project.target_stack,
            "authorized_confirmed": project.authorized_confirmed,
            "authorized_at": _iso_utc(project.authorized_at),
            "created_at": _iso_utc(project.created_at),
        },
        "scan": {
            "id": scan.id,
            "project_id": scan.project_id,
            "profile": scan.profile,
            "status": scan.status,
            "progress_pct": scan.progress_pct,
            "current_stage": scan.current_stage,
            "pages_crawled": scan.pages_crawled,
            "requests_sent": scan.requests_sent,
            "risk_score": scan.risk_score,
            "risk_level": risk_meta["label"],
            "started_at": _iso_utc(scan.started_at),
            "finished_at": _iso_utc(scan.finished_at),
            "created_at": _iso_utc(scan.created_at),
            "duration_seconds": duration_seconds,
            "errors": scan.errors,
            "config": scan.config,
        },
        "summary": {
            "total_findings": len(sorted_findings),
            "active_findings": active_findings,
            "false_positives": false_positives,
            "endpoints_discovered": len(serialized_endpoints),
            "pages_crawled": scan.pages_crawled,
            "requests_sent": scan.requests_sent,
            "risk_score": scan.risk_score,
            "risk_level": risk_meta["label"],
            "severity_counts": severity_counts,
            "triage_counts": triage_counts,
            "owasp_breakdown": owasp_breakdown,
        },
        "endpoints": serialized_endpoints,
        "findings": serialized_findings,
    }


def build_html_report(
    project: Project,
    scan: Scan,
    endpoints: list[Endpoint],
    findings: list[Finding],
) -> str:
    """Render a 100% self-contained offline HTML5 developer report via Jinja2.

    Jinja2 autoescaping is strictly enabled for ``.j2`` templates so all target
    evidence, endpoint URLs, and code snippets are safely HTML-escaped.
    """
    generated_at = datetime.now(timezone.utc)
    sorted_findings = _sort_findings(list(findings))
    severity_counts, triage_counts, owasp_breakdown = _compute_breakdowns(sorted_findings)
    risk_meta = _risk_level_meta(scan.risk_score)
    svg_chart_rows = _build_svg_chart_rows(severity_counts)

    template_findings: list[dict[str, Any]] = []
    for idx, finding in enumerate(sorted_findings, start=1):
        normalized_fix = _normalize_fix_payload(finding.fix, project.target_stack)
        evidence_items = list(finding.evidence.items())
        snippets = []
        for snip in normalized_fix["snippets"]:
            before_lines, after_lines = _tokenize_diff_pair(
                snip["before"], snip["after"], snip["language"]
            )
            snippets.append(
                {
                    **snip,
                    "filename": _snippet_filename(snip["stack"], snip["language"]),
                    "before_lines": before_lines,
                    "after_lines": after_lines,
                }
            )
        primary_snippet = snippets[0] if snippets else None
        secondary_snippets = snippets[1:] if len(snippets) > 1 else []
        reference_cards = [
            _format_reference_item(ref) for ref in normalized_fix["safe_references"]
        ]
        code_locator = _build_code_locator(
            finding.method,
            finding.endpoint_url,
            finding.parameter,
        )
        template_findings.append(
            {
                "index": idx,
                "id": finding.id,
                "check_id": finding.check_id,
                "owasp_category": finding.owasp_category,
                "cwe_id": finding.cwe_id,
                "severity": str(finding.severity or Severity.INFO.value).lower(),
                "confidence": str(finding.confidence or Confidence.HIGH.value).lower(),
                "triage_status": str(finding.triage_status or TriageStatus.OPEN.value).lower(),
                "triage_note": finding.triage_note,
                "title": finding.title,
                "endpoint_url": finding.endpoint_url,
                "method": (finding.method or "GET").upper(),
                "parameter": finding.parameter,
                "endpoint_banner": _format_endpoint_banner(
                    finding.method,
                    finding.endpoint_url,
                    finding.parameter,
                ),
                "code_locator": code_locator,
                "explanation": finding.explanation,
                "evidence_items": evidence_items,
                "fix_summary": normalized_fix["summary"],
                "primary_snippet": primary_snippet,
                "secondary_snippets": secondary_snippets,
                "references": normalized_fix["safe_references"],
                "reference_cards": reference_cards,
                "fingerprint": finding.fingerprint,
            }
        )

    template_endpoints = [
        {
            "method": (ep.method or "GET").upper(),
            "url": ep.url,
            "params": ep.params,
            "source": ep.source,
            "status_code": ep.status_code,
        }
        for ep in endpoints
    ]

    template = _JINJA_ENV.get_template(REPORT_TEMPLATE_NAME)
    return template.render(
        app_name=settings.app_name,
        app_version=settings.app_version,
        generated_at_display=_format_display_dt(generated_at),
        started_at_display=_format_display_dt(scan.started_at),
        finished_at_display=_format_display_dt(scan.finished_at),
        project={
            "id": project.id,
            "name": project.name,
            "base_url": project.base_url,
            "target_stack": project.target_stack,
            "target_stack_label": _STACK_LABELS.get(
                (project.target_stack or "").lower(),
                project.target_stack,
            ),
        },
        scan={
            "id": scan.id,
            "profile": scan.profile,
            "status": scan.status,
            "risk_score": scan.risk_score,
            "risk_label": risk_meta["label"],
            "risk_slug": risk_meta["slug"],
            "risk_color": risk_meta["color"],
            "pages_crawled": scan.pages_crawled,
            "requests_sent": scan.requests_sent,
            "errors": scan.errors,
        },
        summary={
            "total_findings": len(sorted_findings),
            "active_findings": sum(severity_counts.values()),
            "false_positives": triage_counts.get(TriageStatus.FALSE_POSITIVE.value, 0),
            "endpoints_discovered": len(template_endpoints),
            "severity_counts": severity_counts,
            "owasp_breakdown": owasp_breakdown,
        },
        svg_chart_rows=svg_chart_rows,
        findings=template_findings,
        endpoints=template_endpoints,
    )


__all__ = [
    "REPORT_TEMPLATE_NAME",
    "TEMPLATES_DIR",
    "build_html_report",
    "build_json_report",
]
