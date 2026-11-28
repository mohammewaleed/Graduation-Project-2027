#!/usr/bin/env python3
"""
Build ONE unified 30-Slide Full Graduation Defense Presentation
(Part 1: Software Architecture Document [SAD] + Part 2: Technical Implementation & Empirical Results v1.0.0)
in all three formats:
  1. docs/presentations/html/Full_Graduation_Defense.html  (100% offline single-file HTML5 + interactive fixed-box SVG Zoom & Pan Viewer)
  2. docs/presentations/pptx/Full_Graduation_Defense.pptx  (100% valid 16:9 OOXML PowerPoint with all 19 original high-DPI PNGs)
  3. docs/presentations/pdf/Full_Graduation_Defense.pdf    (30-page 16:9 widescreen PDF via headless Chrome)

Usage:
    py -3.12 scripts/build_full_defense.py
"""

from __future__ import annotations

import html
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = ROOT / "docs"
SVG_DIR = DOCS_DIR / "diagrams" / "svg"
PNG_DIR = DOCS_DIR / "diagrams" / "png"
PRES_DIR = DOCS_DIR / "presentations"

OUT_HTML = PRES_DIR / "html" / "Full_Graduation_Defense.html"
OUT_PDF = PRES_DIR / "pdf" / "Full_Graduation_Defense.pdf"
OUT_PPTX = PRES_DIR / "pptx" / "Full_Graduation_Defense.pptx"

CHROME_PATH = Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")

TOTAL_SLIDES = 30
FOOTER_P1 = "Developing a Lightweight OWASP Top 10 Vulnerability Scanner — Part 1: Software Architecture Document (SAD) · Prepared for Dr. Samar"
FOOTER_P2 = "Developing a Lightweight OWASP Top 10 Vulnerability Scanner v1.0.0 — Part 2: Technical Implementation & Results · Prepared for Dr. Samar"

# =============================================================================
# ALL 19 ORIGINAL DIAGRAMS (docs/diagrams/images/01_* .. 19_*)
# =============================================================================

FIGURES: dict[str, tuple[str, str, str]] = {
    "fig01": ("01_as_is_vs_to_be", "Fig. 1", "Figure 1: AS-IS Enterprise DAST vs. TO-BE Developer-First Workflow"),
    "fig02": ("02_master_scanner_pipeline", "Fig. 2", "Figure 2: Master 4-Phase Scanner Pipeline Architecture"),
    "fig03": ("03_use_case_diagram", "Fig. 3", "Figure 3: System Use Case Diagram (UC-01 – UC-06)"),
    "fig04": ("04_c4_l1_context", "Fig. 4", "Figure 4: C4 Level 1 — System Context Diagram"),
    "fig05": ("05_c4_l2_containers", "Fig. 5", "Figure 5: C4 Level 2 — Container Architecture"),
    "fig06": ("06_c4_l3_scanner_components", "Fig. 6", "Figure 6: C4 Level 3 — Pure-Python Scanner Engine Components"),
    "fig07": ("07_dfd_l0_context", "Fig. 7", "Figure 7: DFD Level 0 — System Context Data Flows"),
    "fig08": ("08_dfd_l1_trust_boundaries", "Fig. 8", "Figure 8: DFD Level 1 — Trust Boundaries & STRIDE Controls"),
    "fig09": ("09_docker_deployment", "Fig. 9", "Figure 9: Multi-Container Docker & Local Testbench Deployment"),
    "fig10": ("10_scan_lifecycle_sequence", "Fig. 10", "Figure 10: End-to-End Scan Lifecycle & Live SSE Sequence"),
    "fig11": ("11_cancel_error_isolation_sequence", "Fig. 11", "Figure 11: Cooperative Cancellation & Per-Check Error Isolation"),
    "fig12": ("12_scan_state_machine", "Fig. 12", "Figure 12: 6-State Scan Lifecycle Finite State Machine"),
    "fig13": ("13_swimlane_activity", "Fig. 13", "Figure 13: Cross-Functional Swimlane Activity Workflow"),
    "fig14": ("14_scanner_plugin_class_diagram", "Fig. 14", "Figure 14: Modular Plugin Engine (BaseCheck) & 5-Stack Fix KB"),
    "fig15": ("15_erd_3nf", "Fig. 15", "Figure 15: 3NF Relational Entity-Relationship Diagram"),
    "fig16": ("16_scope_guardrail_flow", "Fig. 16", "Figure 16: Scope Guardrail & Safe Non-Destructive Scanning Flow"),
    "fig17": ("17_accuracy_benchmark_chart", "Fig. 17", "Figure 17: Empirical Precision, Recall & F1-Score Benchmark Chart"),
    "fig18": ("18_coverage_latency_chart", "Fig. 18", "Figure 18: Scan Latency SLAs & Crawler Route Coverage Chart"),
    "fig19": ("19_master_system_flowchart", "Fig. 19", "Figure 19: Master System Execution Flowchart (ISO 5807)"),
}

# =============================================================================
# VERIFIED STRUCTURED CONTENT DATA (PART 1: SAD & PART 2: TECHNICAL v1.0.0)
# =============================================================================

TEAM_ROSTER = [
    ("Ahmed Ashraf Ammar", "235204", "Team Lead — FastAPI REST/SSE API, ScanJobManager & Phase 7 Hardening"),
    ("Islam Mohammed", "235164", "Core Engine — ScopeGuardrail, ScannerHttpClient & Bounded BFS WebCrawler"),
    ("Abdelrhman Mohamed AbdEl-latif", "235216", "Security Checks — 6 Safe Active & Injection Checks (sqli_*, xss, cors, idor)"),
    ("Ahmed Waleed Mokthar", "235052", "Security Checks — 8 Passive & 3 Discovery Checks + 5-Stack Fix KB (kb.json)"),
    ("Mohamed Waleed Mokthar", "235051", "Data & Reporting — 3NF DB, SHA-1 Scan Diff & Offline Dark+ HTML5/JSON Reports"),
    ("Mohamed Ibrahim Elsayed", "235401", "Frontend UI — 6-View Workbench, SVG Charts, Dark/Light Themes & Fix Modal"),
    ("Ali Ibrahim Elsayed", "235332", "DevOps & QA — Multi-Stage Docker, VulnBench, evaluate.py & 3-Job GitHub CI"),
]

COVER_KPIS = [
    ("19 / 19", "Original Diagrams", "Full-detail vector SVGs + interactive zoom/pan", "teal"),
    ("17 × 5", "OWASP Checks × Stacks", "8 Passive · 6 Active · 3 Discovery · 85 Fixes", "sky"),
    ("100%", "Deep VulnBench F1", "19/19 TP · 0 FP · 0 FN · 0 /safe/* FPs", "green"),
    ("88 / 88", "Tests + 3-Job CI", "+ 29 subtests in 24.71s · Self-Scan Risk 6 → 3", "emerald"),
]

SAD_CHAPTERS = [
    ("Ch. 1", "Introduction & Scope", "Problem statement, AS-IS vs. TO-BE shift-left workflow, ethical guardrails & 7-member ownership."),
    ("Ch. 2", "Formal SRS", "15 Functional Reqs (FR-01..15), 9 Quantitative NFRs (NFR-01..09) & 6 Use Cases (UC-01..06)."),
    ("Ch. 3", "Architecture Views", "C4 L1–L3, DFD L0–L1, UML Use Case, Class, Sequence, State, Swimlane & ISO 5807 Flowchart."),
    ("Ch. 4", "Data & API Design", "3NF relational schema (projects, scans, endpoints, findings) & 14 typed REST/SSE routes."),
    ("Ch. 5", "Security & ADRs", "STRIDE threat model, NIST SSDF (SP 800-218) mapping, 4-layer Guardrail & 5 Formal ADRs."),
    ("Ch. 6", "Validation Plan", "15 test cases (TC-01..15), 3-tier testbench (VulnBench, DVWA, Juice Shop) & NFR-08 gates."),
]

SLIDE3_AS_IS = [
    ("Heavy Proxy & CA Friction:", "Enterprise tools (ZAP/Burp) require browser proxies, root CA certs & complex policy tuning."),
    ("Opaque Late-Stage Dumps:", "Raw HTTP/CWE reports push security checks into final release week when fixes are riskiest."),
]
SLIDE3_TO_BE = [
    ("3-Min Zero-Proxy DX:", "One command (docker compose up or uvicorn) launches 17 curated, non-destructive checks."),
    ("Exact Coords & 5-Stack Fixes:", "Pinpoints METHOD /path · param with plain-English root cause & copy-ready 5-stack patches."),
]

SLIDE4_PHASES = [
    ("01", "Intake & Guardrail", "Validates mandatory consent, RFC1918 allow-list, pre-DNS SSRF guard & scan profile."),
    ("02", "Soft-404 & BFS", "Calibrates UUID Soft-404 baseline and maps same-origin links, forms & JS /api/ routes."),
    ("03", "17-Check Engine", "Runs 8 Passive, 6 Safe Active & 3 Discovery checks in per-check fault isolation."),
    ("04", "Fixes & Reports", "SHA-1 dedup, 0–100 risk score, 5-stack kb.json patches, live SSE & HTML5/JSON."),
]

SLIDE5_USE_CASES = [
    ("UC-01", "Auth Project", "Local URL + mandatory ownership consent."),
    ("UC-02", "Run & Stream", "Quick/Standard/Deep + live SSE stream."),
    ("UC-03", "Cancel Scan", "Cooperative threading.Event halt <= 5s."),
    ("UC-04", "Copy Fix", "Param coords + 5-stack Before/After code."),
    ("UC-05", "Triage & Diff", "Status updates + deterministic SHA-1 diff."),
    ("UC-06", "Export", "Offline JSON & auto-escaped HTML5 report."),
]
SLIDE5_OWASP = [
    ("A01", "Access", "4"),
    ("A02", "Crypto", "1"),
    ("A03", "Inject", "3"),
    ("A05", "Misconf", "7"),
    ("A06", "OutJS", "1"),
    ("A07", "Auth", "1"),
]

SLIDE6_FRS = [
    ("FR-01–02", "Project Auth & Guardrail", "Mandatory authorized_confirmed=true; hardcoded local/RFC1918 allow-list & DNS/redirect checks."),
    ("FR-03", "3 Scan Profiles", "Quick (8 passive), Standard (14 passive+active+discovery), Deep (all 17 incl. IDOR & admin)."),
    ("FR-04", "Bounded BFS Crawler", "Same-origin links, forms, query params & JS routes; Soft-404 calibration; skips /logout & /delete."),
    ("FR-05, 15", "17 OWASP Checks & API", "Modular BaseCheck plugins (8 Passive, 6 Safe Active, 3 Discovery) + GET /api/checks catalog."),
    ("FR-06–07", "Live SSE & Cancellation", "Real-time GET /api/scans/{id}/stream telemetry & cooperative POST .../cancel via threading.Event."),
    ("FR-08–09", "Coordinates & 5-Stack Fixes", "Exact method/path/param pinpointing + plain-language root cause + FastAPI/Flask/Express/PHP/HTML fixes."),
    ("FR-10, 13", "Dashboard & Triage", "Risk score 0–100, Pure Inline SVG Charts & triage (open/fixed/false_positive/accepted)."),
    ("FR-11", "SHA-1 Scan Comparison", "Deterministic 40-char SHA-1 fingerprints partitioning scans into New, Fixed & Unchanged findings."),
    ("FR-12, 14", "Offline Reports & Auth", "Auto-escaped Jinja2 HTML5 + JSON exports; volatile in-memory Cookie/Bearer/DVWA scan auth."),
]
SLIDE6_NFRS = [
    ("NFR-01", "Zero-Config Setup", "< 3 min clone-to-first-scan via docker compose up or venv; zero proxy/CA setup."),
    ("NFR-02", "Latency & Memory SLAs", "VulnBench: Quick <= 15s, Standard <= 45s, Deep <= 90s; steady RAM <= 512 MB."),
    ("NFR-03", "Ethical Safety Bounds", "Hardcoded allow-list, DNS/SSRF guard, 10 req/s throttle & 2,000 req/scan hard cap."),
    ("NFR-04", "Self-Security Hardening", "Pydantic v2, strict CSP, zero innerHTML, Jinja2 autoescape, parameterized ORM & non-root Docker."),
    ("NFR-05", "Dual Runtime Portability", "Windows/macOS/Linux via Docker (SQLite/Postgres 16) or native Python 3.12 venv."),
    ("NFR-06–07", "Extensibility & Isolation", "1-file BaseCheck auto-registry; per-check try/except isolation & SQLite WAL concurrency."),
    ("NFR-08", "Empirical Accuracy Gates", "Precision >= 85%, Recall >= 80%, F1 >= 82%, and 0 false positives on /safe/* controls."),
    ("NFR-09", "Clean Modularity & QA", "Zero backend/app imports in backend/scanner; full automated pytest + CI security gate."),
]

SLIDE7_C4L1 = [
    ("Primary & Review Actors", "Developer launches scans & copies 5-stack fixes (:8000); Instructor/Dr. Samar reviews risk trends & reports."),
    ("Local-Only Scanner System", "Zero-proxy Docker or Python 3.12 venv deployment housing FastAPI + decoupled pure-Python engine."),
    ("Local Targets & Persistence", "Probes only authorized localhost/Docker labs (VulnBench, DVWA, Juice Shop); stores 3NF SQLite WAL / PG 16."),
    ("Hard Public Internet Block", "ScopeGuardrail blocks all external domains, public IPs & cloud metadata 169.254.169.254 (HTTP 403)."),
]

SLIDE8_LAYERS = [
    ("Zero-Build Web UI", "6-view Tailwind SPA, Pure Inline SVG Charts, Dark/Light themes & live SSE."),
    ("FastAPI + SSE Server", "14 typed REST/SSE endpoints, Pydantic v2, ScanJobManager & <= 5s cancel."),
    ("Pure Scanner Core", "30/30 AST-verified modules — zero web/DB imports, 100% decoupled."),
    ("SQLAlchemy 2.0 ORM", "SQLite WAL default + seamless 1-switch PostgreSQL 16 (--profile postgres)."),
    ("Multi-Stage Docker", "Non-root Python 3.12 (--no-server-header) + host.docker.internal bridge."),
    ("Local Testbench Stack", "Loopback VulnBench (:5050), DVWA (:8080) & OWASP Juice Shop (:3000)."),
]

SLIDE9_COMPONENTS = [
    ("ScopeGuardrail (policy.py)", "Localhost/RFC1918 only; pre-DNS anti-rebinding, blocks 169.254.169.254 & /logout."),
    ("ScannerHttpClient", "Token-bucket 10 req/s throttle, 2,000-req cap, Soft-404 baseline & DVWA CSRF login."),
    ("Bounded BFS Crawler", "Same-origin BS4 HTML/form extraction + inline JS /api/ route discovery & 200KB cache."),
    ("30/30 AST Isolated Core", "CI AST check guarantees 0 FastAPI/SQLAlchemy imports inside backend/scanner/."),
]

SLIDE10_FLOWS = [
    ("IN", "Developer -> 0.0", "Submits local target URL, ownership consent, scan profile, volatile auth & triage."),
    ("OUT", "0.0 -> Developer", "Streams live SSE progress, 5-stack code fixes & offline auto-escaped HTML5/JSON."),
    ("HTTP", "0.0 <-> Local Target", "Sends <= 10 req/s non-destructive probes; parses status, headers, cookies & forms."),
    ("D1", "0.0 <-> SQLite / PG16", "Persists 3NF projects, scans, endpoints & findings; serves history & SHA-1 diffs."),
]

SLIDE11_STRIDE = [
    ("Spoofing / Tampering", "Pydantic v2 schemas, authorized_confirmed=true & parameterized ORM."),
    ("XSS / Elevation", "Strict CSP, textContent DOM, Jinja2 autoescape & non-root container."),
    ("SSRF & Rebinding", "Pre-DNS getaddrinfo() blocks public IPs & 169.254.169.254 metadata."),
    ("Info Disclosure", "Volatile in-memory auth only; secrets redacted in DB & exports."),
    ("Denial of Service", "10 req/s rate limit, 2,000-req cap & 10s per-request socket timeout."),
]
SLIDE11_SSDF = [
    ("PO", "Prepare", "FR/NFR baselines & loopback Docker."),
    ("PW.1", "Design", "C4 L1–L3, DFD TB1–TB3 & 5 ADRs."),
    ("PS/PW.5", "Code", "CSP, textContent, autoescape & pure core."),
    ("PW.8/RV", "Verify", "TC-01..15, evaluate.py & 3-job CI."),
]

SLIDE12_LAYERS = [
    ("L1", "Local Allow-List & Consent Gate", "Mandates authorized_confirmed=true and http(s) only. Permits localhost, 127.0.0.1, ::1 & RFC1918; blocks all public hosts (403)."),
    ("L2", "Pre-Request DNS & Anti-Rebinding", "Resolves hostnames via socket.getaddrinfo() before connect — unconditionally blocking public IPs & cloud metadata 169.254.169.254."),
    ("L3", "Manual Same-Origin Redirect Guard", "Runs allow_redirects=False and validates 3xx Location headers manually (<= 5 same-origin hops), never following external redirects."),
    ("L4", "Destructive Denylist & Budgets", "Skips /logout, /delete, /reset & /purge to protect local state. Enforces 10 req/s throttle, 2,000 cap, 10s timeout & <= 5s cancel."),
]

SLIDE13_STAGES = [
    ("01", "Target Authorization", "ScopeGuardrail validates localhost/RFC1918/Docker target and requires explicit ownership consent."),
    ("02", "Reachability & Volatile Auth", "Verifies connectivity, sets Cookie/Bearer/DVWA CSRF session in RAM only, captures baseline headers."),
    ("03", "Soft-404 & Bounded BFS Crawl", "Fingerprints UUID Soft-404 pages and crawls same-origin links, forms, params & inline JS /api/ routes."),
    ("04", "Profile-Driven OWASP Checks", "Runs non-destructive passive, active safe & discovery plugins per Quick/Standard/Deep profile."),
    ("05", "SHA-1 Dedup, Scoring & Fixes", "Deduplicates via 40-char SHA-1, computes 0–100 weighted risk score, attaches 5-stack kb.json patches."),
    ("06", "Live SSE Stream & Export", "Streams progress events to 6-view UI and exports standalone offline JSON & Dark+ HTML5 reports."),
]

SLIDE14_LANES = [
    ("L1", "Developer Browser", "Confirms ownership, watches live SSE stream, copies 5-stack patches & exports reports."),
    ("L2", "FastAPI API + SSE", "Runs Pydantic v2 & Guardrail (403 vs 201), streams /stream & serves diff/export routes."),
    ("L3", "Scanner Engine", "Calibrates Soft-404, crawls same-origin BFS & executes 17 isolated checks (<= 5s cancel)."),
    ("L4", "SQLAlchemy DB + KB", "Persists 3NF scan/endpoint rows, joins kb.json 5-stack fixes & commits 0–100 risk."),
]

SLIDE15_FSM = [
    ("201", "Happy Path Flow", "POST /api/projects/{id}/scans returns 201 Created (queued) -> crawling -> scanning -> completed."),
    ("SSE", "Live Stream Sync", "GET /api/scans/{id}/stream pushes state transitions, progress metrics & terminal status."),
    ("<= 5s", "Graceful CANCELLED", "cancel_event.set() halts probing within <= 5s from any active state, keeping partial findings."),
    ("SAFE", "Isolated vs. FAILED", "Plugin errors emit non-fatal check_warning; only 403, unreachable target or DB fault fails."),
]

SLIDE16_SEQ_CARDS = [
    ("201 Created Async Launch", "POST /api/projects/{id}/scans validates ScopeGuardrail, creates queued DB row & submits worker to ScanJobManager."),
    ("Live /api/scans/{id}/stream", "FastAPI StreamingResponse emits typed SSE events: status, crawl_progress, check_started, finding_found & scan_completed."),
    ("Volatile In-Memory Auth", "Cookie, Bearer token, or DVWA CSRF credentials stay strictly in worker RAM and are wiped at scan completion."),
    ("Atomic Risk & Report Ready", "Orchestrator persists SHA-1 deduplicated findings, commits weighted 0–100 risk_score & unlocks instant Dark+ HTML5/JSON export."),
]

SLIDE17_CANCEL = [
    ("Immediate Ack (200 OK):", "POST /api/scans/{id}/cancel sets thread-safe threading.Event on the active worker immediately."),
    ("Graceful <= 5s Halt:", "Crawler & checks poll cancel_event between probes, preserving partial findings and emitting SSE scan_cancelled."),
]
SLIDE17_ISOLATION = [
    ("Per-Check try/except:", "A ReadTimeout, malformed HTML, or runtime error inside one plugin never aborts the scan."),
    ("Non-Fatal Telemetry:", "Orchestrator logs the fault, emits SSE check_warning badge & continues all remaining OWASP checks."),
]

SLIDE18_CARDS = [
    ("1-File BaseCheck Auto-Registry (NFR-06)", "NAVY", "17 PLUGINS", [
        "Hierarchy: 8 Passive, 6 Safe Active (incl. Deep IDOR), 3 Discovery.",
        "__init_subclass__ + pkgutil auto-registers plugins with zero orchestrator edits.",
    ]),
    ("Per-Check Fault Isolation (NFR-07)", "TEAL", "FAULT-SAFE", [
        "Each plugin executes inside try/except so timeouts or bad HTML never crash a scan.",
        "Emits check_warning SSE events & polls cancel_event between HTTP probes.",
    ]),
    ("kb.json 5-Stack Fix Engine (FR-09)", "NAVY", "85 PATCHES", [
        "Interpolates exact METHOD /path · param into plain-language root causes.",
        "Copy-ready Before/After code fixes for FastAPI, Flask, Express, PHP & HTML.",
    ]),
]

SLIDE19_TABLES = [
    ("projects", "UUID PK · base_url, target_stack, authorized_confirmed"),
    ("scans", "FK project_id (CASCADE), profile, 6-state FSM, risk_score"),
    ("endpoints", "FK scan_id (CASCADE), method, norm_path, params JSON"),
    ("findings", "FK scan_id, endpoint_id (SET NULL), SHA-1, status, kb JSON"),
]
SLIDE19_ENDPOINTS = [
    ("GET /api/health  |  /api/checks", "Service/DB health & live 17-plugin catalog"),
    ("POST|GET|PATCH|DEL /api/projects[/{id}]", "Guardrailed create, list, edit & cascade delete"),
    ("POST|GET /api/projects/{id}/scans", "Start scan via POST .../scans (201) & history"),
    ("GET|POST /api/scans/{id}[/cancel|/stream]", "Metrics, <= 5s cancel & live SSE telemetry"),
    ("GET /api/scans/{id}/{endpoints,findings}", "Discovered attack surface & filtered findings"),
    ("PATCH /api/findings/{id} | compare | report", "Triage re-score, SHA-1 diff & JSON/HTML5"),
]

SLIDE20_ADRS = [
    ("ADR-01", "FastAPI + SSE + ThreadPoolExecutor", "Native ASGI async SSE streaming & Pydantic v2 validation over WSGI Flask/Django with zero Redis/Celery broker overhead."),
    ("ADR-02", "SQLAlchemy 2.0: SQLite WAL + PG 16", "Zero-config local SQLite WAL file out of the box plus seamless 1-switch PostgreSQL 16 portability (--profile postgres)."),
    ("ADR-03", "Pure-Python Decoupled Scanner Core", "Zero backend/app imports in backend/scanner/; 1-file BaseCheck auto-registry & isolated per-check unit tests."),
    ("ADR-04", "Zero-Build HTML5 / Tailwind / ES Modules", "6-view dashboard served directly by FastAPI with Pure Inline SVG Charts & SSE; zero Node.js, npm, or bundler bloat."),
    ("ADR-05", "Guardrail, Soft-404 & Autoescaped HTML5", "Hardcoded 4-layer safety, UUID Soft-404 suppression & offline auto-escaped Jinja2 HTML5 developer reports."),
]
SLIDE20_TIERS = [
    ("TIER 1 · GROUND TRUTH", "VulnBench (127.0.0.1:5050)", "Python stdlib + SQLite app with 19 seeded bugs + 4 hardened /safe/* controls. Automated scripts/evaluate.py enforces Precision >= 85%, Recall >= 80%, F1 >= 82% & 0 /safe/* FPs (TC-01..15).", "GREEN"),
    ("TIER 2 · SERVER-RENDERED", "DVWA (127.0.0.1:8080)", "PHP + Apache + MySQL academic standard. Validates authenticated CSRF form login, BFS HTML form discovery, SQLi/XSS/header detection & /logout.php denylist preservation.", "TEAL"),
    ("TIER 3 · MODERN SPA", "OWASP Juice Shop (127.0.0.1:3000)", "Node.js + Express + Angular SPA. Validates Soft-404 catch-all index.html suppression, CORS/header/outdated-JS checks, and transparently documents ~35% non-headless SPA coverage bounds.", "NAVY"),
]

ROADMAP_ROWS = [
    ("Phase 0", "DONE", "Non-root Docker, SQLite WAL + optional Postgres 16, FastAPI /api/health", "2 health"),
    ("Phase 1", "DONE", "6-Chapter IEEE SAD (Sem 1 & 2 books) + 19 Mermaid/PNG/SVG diagrams", "Docs & 19 figs"),
    ("Phase 2", "DONE", "ScopeGuardrail (DNS guard), ScannerHttpClient (10 req/s, DVWA), BFS crawler", "20 core unit"),
    ("Phase 3", "DONE", "17 OWASP BaseCheck plugins, 5-stack kb.json, SHA-1 dedup, 0–100 risk", "70 unit total"),
    ("Phase 4", "DONE", "14 FastAPI REST/SSE routes, ScanJobManager, SHA-1 diff, Dark+ HTML5/JSON", "82 tests total"),
    ("Phase 5", "DONE", "6-view Workbench, Dark/Light themes, SVG charts, Fix Modal (0 XSS)", "9/9 ES modules"),
    ("Phase 6", "DONE", "Deterministic VulnBench (19 flaws + 4 /safe/*), evaluate.py, 100% Deep F1", "86 tests total"),
    ("Phase 7", "DONE", "Live Deep self-scan audit (Risk 6 -> 3/100), hardening & 3-job GitHub CI", "88 + 29 sub"),
]

PASSIVE_CHECKS = [
    ("missing_security_headers", "A05"),
    ("weak_csp", "A05"),
    ("server_banner_leak", "A05"),
    ("verbose_error_pages", "A05"),
    ("insecure_cookies", "A07"),
    ("insecure_transport", "A02"),
    ("csrf_missing_token", "A01"),
    ("outdated_js_components", "A06"),
]
ACTIVE_CHECKS = [
    ("sqli_error_based", "A03"),
    ("sqli_boolean_diff", "A03"),
    ("xss_reflected", "A03"),
    ("open_redirect", "A01"),
    ("cors_misconfig", "A05"),
    ("idor_heuristic (Deep · low conf.)", "A01"),
]
DISCOVERY_CHECKS = [
    ("sensitive_files (Std+)", "A05"),
    ("directory_listing (Deep)", "A05"),
    ("forced_browsing_admin (Deep)", "A01"),
]
P3_ENGINE_CARDS = [
    ("1-File Auto-Registry", "New BaseCheck subclasses self-register into Quick (8), Standard (14) & Deep (17) profiles."),
    ("17×5 = 85 Fix Patches", "kb.json delivers Before/After fixes for FastAPI, Flask, Express, PHP & HTML."),
    ("SHA-1 Dedup & 0–100 Risk", "SHA-1 collapses duplicates; 10·C + 6·H + 3·M + 1·L excludes false_positive."),
    ("Isolated ScanOrchestrator", "Per-check try/except isolation + thread-safe cancel_event stops scans in <= 5s."),
]

P5_VIEWS = [
    ("01", "Dashboard", "KPI cards, pure inline SVG Risk Gauge, Severity Donut & OWASP Bar charts, plus project/scan history."),
    ("02", "Scan Launcher", "3-step setup (Project, Quick/Standard/Deep, Cookie/Bearer/DVWA auth) with high-contrast popover dropdowns."),
    ("03", "Live Scan", "Real-time SSE progress bar, active check telemetry, live finding/request counters, and 1-click Cancel."),
    ("04", "Findings Explorer", "Severity/OWASP/status filters, instant triage risk recalc, and VS Code Dark+ Fix Modal with 5-stack tabs."),
    ("05", "Compare Scans", "SHA-1 regression diff (New / Fixed / Unchanged), risk delta badge, and 1-click Swap & Reset controls."),
    ("06", "Check Catalog", "Searchable reference of all 17 OWASP checks, profile tiers, CWE IDs, and non-destructive safety notes."),
]
P5_PILLS = [
    ("Dark/Light + Popover Selects", "Full Dark & Light themes with custom high-contrast popover dropdowns & pure inline SVG charts."),
    ("9 / 9 ES Modules · 0 innerHTML", "All 9 JS modules pass Node 20 --check in CI; 100% createElement() + textContent DOM (0 XSS sinks)."),
    ("Offline Dark+ HTML5 Reports", "Jinja2 strict autoescaping — 0 |safe filters, 0 <script> tags, VS Code Dark+ difflib +/- diffs."),
]

NFR08_GATES = [
    ("100.0%", "Deep Precision", "Gate >= 85% · 19/19 TP, 0 FP", 100),
    ("100.0%", "Deep Recall & F1", "Gate >= 80% / 82% · 0 FN", 100),
    ("0 FPs", "Clean /safe/* Routes", "Gate = 0 · 4 Negative Controls", 100),
    ("21.42s", "Duration & Coverage", "<= 90s SLA · 93.3% (14/15) · 0 err", 93),
]
VULNBENCH_ROWS = [
    ["Quick", "8 / 17", "9 / 0 / 10", "100.0%", "47.4%", "64.3%", "0", "93.3% (14/15)", "1.92s (<= 15s)"],
    ["Standard", "14 / 17", "16 / 0 / 3", "100.0%", "84.2%", "91.4%", "0", "93.3% (14/15)", "20.22s (<= 45s)"],
    ["Deep (NFR-08)", "17 / 17", "19 / 0 / 0", "100.0%", "100.0%", "100.0%", "0", "93.3% (14/15)", "21.42s (<= 90s)"],
]

FIG17_CARDS = [
    ("Live Deep: 100.0% Prec / Rec / F1", "Observed 19/19 TP, 0 FP, 0 FN — exceeding SAD Ch. 6 targets (+15% Prec, +20% Rec, +18% F1).", "green"),
    ("100.0% Precision Across All Profiles", "Zero false positives across Quick (9 TP), Standard (16 TP) & Deep (19 TP) — 0 FPs on all 4 /safe/* routes.", "teal"),
    ("All 6 OWASP Categories 100%", "Observed 100% across A01 (4/4), A02 (1/1), A03 (3/3), A05 (9/9), A06 (1/1) & A07 (1/1).", "navy"),
]
FIG18_CARDS = [
    ("55%–87% Faster Than NFR-02 SLAs", "Live observed: Quick 1.92s (vs. 15s), Standard 20.22s (vs. 45s) & Deep 21.42s (vs. 90s).", "teal"),
    ("93.3% Route Coverage & 0 Clean FPs", "Bounded BFS discovers 14/15 VulnBench routes (>= 80% FR-04 gate) with 0/4 false positives on /safe/*.", "green"),
    ("Transparent ~35% SPA Ceiling", "Lightweight requests + BS4 avoids browser bloat; Angular/React SPAs (Juice Shop) hit ~35% auto-crawl.", "amber"),
]

DX_ROWS = [
    ("1. Setup Time", "10–20 min (JVM/Desktop, proxy CA cert, context config)", "< 3 min (docker compose up or uvicorn; zero proxy CA)"),
    ("2. Config Steps", "6–10+ steps (mode, spider, active policy, alert thresholds)", "<= 3 steps (create project + confirm, choose profile, launch)"),
    ("3. Finding Clarity", "Raw HTTP traces, WASC/CWE jargon, analyst-oriented text", "Plain-English root cause + exact METHOD /path · param badges"),
    ("4. Copy-Ready Fixes", "Conceptual guidance paragraphs + external OWASP/CWE links", "5-Stack Before/After code tabs (FastAPI, Flask, Express, PHP, HTML)"),
    ("5. Time-to-First-Fix", "Manual re-scan & manual alert-list comparison", "1-click re-scan + deterministic SHA-1 diff showing Fixed badges"),
]
BOUNDARY_CARDS = [
    ("DAST vs. SAST Boundary", "Black-box HTTP DAST pinpoints METHOD /path, vulnerable params & 'Where to Patch' hints — not source line numbers."),
    ("Non-Headless SPA (~35%)", "Lightweight requests + BS4 avoids headless browser bloat; JS SPAs hit ~35% auto-crawl, mitigated by JS /api/ hints & Soft-404."),
    ("DVWA & Juice Shop Validity", "VulnBench proves deterministic check contracts; external tests use DVWA & Juice Shop. Public targets stay blocked."),
]

HARDENING_ACTIONS = [
    ("1. Permissions-Policy", "Added geolocation/camera/mic policy in main.py — removes missing_security_headers."),
    ("2. object-src & /docs CSP", "Locked plugins with object-src 'none' and isolated Swagger via dedicated _DOCS_CSP."),
    ("3. Cache-Control: no-cache", "Enforced Cache-Control: no-cache on static UI assets to prevent stale JS execution."),
    ("4. --no-server-header", "Added --no-server-header to Uvicorn CMD in Dockerfile to hide server banners."),
    ("5. test_self_scan_hardening.py", "Added 2 automated regression tests locking headers & Deep self-scan bounds in CI."),
]

TEST_TIERS = [
    ("P0 · Health & Bootstrap", "test_health.py", "2", 14, "teal"),
    ("P2/3 · Core, 17 Checks & KB", "6 unit suites (policy, http, checks)", "70", 100, "navy"),
    ("P4 · REST/SSE & Reports", "test_api_e2e.py", "10", 30, "teal"),
    ("P6 · VulnBench NFR-08", "test_vulnbench_accuracy.py", "4", 20, "green"),
    ("P7 · Self-Scan Hardening", "test_self_scan_hardening.py", "2", 14, "green"),
]
CI_JOBS = [
    ("backend-tests", "Py 3.12 · pytest (88 + 29 subtests)"),
    ("frontend-and-security", "Node 20 9/9 JS + AST (0 XSS/safe)"),
    ("docker-verify", "Compose + live /api/health smoke"),
]

DEMO_STEPS = [
    ("01", "0:00–0:30", "Guardrail 403 & Project", "Block public URL (403); create authorized VulnBench (:5050) project."),
    ("02", "0:30–1:15", "Deep Live SSE Scan", "Run Deep (17/17); watch SSE crawl 14 routes & flag 19 flaws in ~21s."),
    ("03", "1:15–2:00", "Dark+ Fix Modal & Triage", "Inspect 5-stack diff in Fix Modal; toggle triage & watch Risk recalc."),
    ("04", "2:00–2:30", "Offline HTML5 Report", "Export standalone HTML5 report with difflib +/- & 'Where to Patch'."),
    ("05", "2:30–3:00", "Compare Scans Diff", "SHA-1 regression diff (Swap & Reset) showing Fixed/New badges."),
]

# Slide catalog for grouped Grid overview modal
SLIDE_CATALOG = [
    (1, 1, "Cover — Full Graduation Defense"),
    (2, 1, "Part 1 Cover — Software Architecture (SAD)"),
    (3, 1, "Problem & AS-IS vs. TO-BE (Fig. 1)"),
    (4, 1, "Master 4-Phase Pipeline (Fig. 2)"),
    (5, 1, "Ethical Scope & Use Cases (Fig. 3)"),
    (6, 1, "Formal SRS: FR-01..15 & NFR-01..09"),
    (7, 1, "C4 Level 1: System Context (Fig. 4)"),
    (8, 1, "C4 Level 2: Containers & Stack (Fig. 5)"),
    (9, 1, "C4 Level 3: Pure Scanner Core (Fig. 6)"),
    (10, 1, "DFD Level 0: Context Flows (Fig. 7)"),
    (11, 1, "DFD Level 1: STRIDE & SSDF (Fig. 8)"),
    (12, 1, "Scope Guardrail Flow (Fig. 16)"),
    (13, 1, "Master System Flowchart (Fig. 19)"),
    (14, 1, "Cross-Functional Swimlane (Fig. 13)"),
    (15, 1, "6-State Lifecycle FSM (Fig. 12)"),
    (16, 1, "End-to-End & Live SSE Sequence (Fig. 10)"),
    (17, 1, "Cancel & Error Isolation Seq (Fig. 11)"),
    (18, 1, "Plugin Engine & 5-Stack KB (Fig. 14)"),
    (19, 1, "3NF ERD & 14 REST/SSE APIs (Fig. 15)"),
    (20, 1, "ADRs (01–05) & 3-Tier Validation Plan"),
    (21, 2, "Part 2 Cover — Roadmap (Phases 0–7)"),
    (22, 2, "Phase 3 — 17 OWASP Checks & Fix KB"),
    (23, 2, "Phases 4 & 5 — 6-View UI & Dark+ Reports"),
    (24, 2, "Phase 6 — VulnBench NFR-08 Results"),
    (25, 2, "Accuracy Benchmark Chart (Fig. 17)"),
    (26, 2, "Coverage & Latency Chart (Fig. 18)"),
    (27, 2, "DX Benchmark vs. ZAP & Boundaries"),
    (28, 2, "Phase 7 — Self-Scan & Hardening"),
    (29, 2, "Docker, 88-Test Pyramid & CI (Fig. 9)"),
    (30, 2, "Live Demo, Team Ownership & Q&A"),
]


# =============================================================================
# 1. ORIGINAL INLINE SVG LOADER + COLLISION-FREE ID NAMESPACER
# =============================================================================


def load_namespaced_svg(svg_path: Path, prefix: str) -> str:
    """Load original vector SVG, namespace all internal IDs/refs, and normalize root <svg>."""
    if not svg_path.exists():
        raise FileNotFoundError(f"Original SVG missing: {svg_path}")
    raw = svg_path.read_text(encoding="utf-8").strip()
    # Remove XML declaration if present
    raw = re.sub(r"^\s*<\?xml[^>]*\?>\s*", "", raw, flags=re.IGNORECASE)

    # Collect all internal id="..." values
    ids = set(re.findall(r'\bid="([^"]+)"', raw))
    if ids:
        # Sort longest first to avoid partial prefix overlap
        for old_id in sorted(ids, key=len, reverse=True):
            new_id = f"{prefix}_{old_id}"
            raw = raw.replace(f'id="{old_id}"', f'id="{new_id}"')
            raw = raw.replace(f"url(#{old_id})", f"url(#{new_id})")
            raw = raw.replace(f'href="#{old_id}"', f'href="#{new_id}"')
            raw = raw.replace(f'xlink:href="#{old_id}"', f'xlink:href="#{new_id}"')

    # Normalize opening <svg ...> tag: preserve/derive viewBox, strip fixed width/height
    m = re.match(r"<svg\b([^>]*)>", raw, flags=re.IGNORECASE | re.DOTALL)
    if not m:
        raise ValueError(f"Invalid SVG root element in {svg_path}")
    attrs = m.group(1)

    has_vb = re.search(r'\bviewBox="[^"]+"', attrs) is not None
    if not has_vb:
        wm = re.search(r'\bwidth="([0-9.]+)', attrs)
        hm = re.search(r'\bheight="([0-9.]+)', attrs)
        if wm and hm:
            attrs += f' viewBox="0 0 {wm.group(1)} {hm.group(1)}"'

    attrs = re.sub(r'\s*\bwidth="[^"]*"', "", attrs)
    attrs = re.sub(r'\s*\bheight="[^"]*"', "", attrs)
    attrs = re.sub(r'\s*\bpreserveAspectRatio="[^"]*"', "", attrs)
    attrs = re.sub(r'\s*\bclass="[^"]*"', "", attrs)
    new_open = f'<svg{attrs} class="zv-svg" preserveAspectRatio="xMidYMid meet">'
    raw = new_open + raw[m.end():]
    return raw


def load_all_svgs() -> dict[str, str]:
    out: dict[str, str] = {}
    for key, (stem, _, _) in FIGURES.items():
        out[key] = load_namespaced_svg(SVG_DIR / f"{stem}.svg", key)
    return out


# =============================================================================
# 2. HTML PRESENTATION BUILDER (30 SLIDES + FIXED-BOX SVG ZOOM & PAN VIEWER)
# =============================================================================


def diagram_viewer(fig_key: str, svgs: dict[str, str], extra_cls: str = "") -> str:
    _, fig_tag, caption = FIGURES[fig_key]
    cls = f"diagram-viewer {extra_cls}".strip()
    return f"""
    <div class="{cls}" data-fig="{html.escape(fig_key)}" data-caption="{html.escape(caption)}">
      <div class="zv-stage" tabindex="0" aria-label="{html.escape(caption)}">
        <div class="zv-canvas">
          {svgs[fig_key]}
        </div>
      </div>
      <div class="zv-fig-pill">{html.escape(fig_tag)}</div>
      <div class="zv-toolbar" role="toolbar" aria-label="Diagram zoom controls">
        <button type="button" class="zv-btn zv-out" title="Zoom Out (-)">&minus;</button>
        <button type="button" class="zv-btn zv-pct" title="Reset Zoom (0)">100%</button>
        <button type="button" class="zv-btn zv-in" title="Zoom In (+)">+</button>
        <button type="button" class="zv-btn zv-reset" title="Reset View (0)">Reset</button>
        <button type="button" class="zv-btn zv-fs" title="Fullscreen Interactive Viewer">&#x26F6;</button>
      </div>
      <div class="zv-hint">Scroll or +/&minus; to zoom &middot; Drag to pan &middot; Double-click 2.2&times;</div>
    </div>
    """


def slide_header(title: str, subtitle: str, badge: str, part: int = 1) -> str:
    accent_cls = "ha-p1" if part == 1 else "ha-p2"
    badge_cls = "hb-p1" if part == 1 else "hb-p2"
    return f"""
    <div class="slide-header">
      <div class="header-accent {accent_cls}"></div>
      <div class="header-titles">
        <div class="header-title">{html.escape(title)}</div>
        <div class="header-subtitle">{html.escape(subtitle)}</div>
      </div>
      <div class="header-badge {badge_cls}">{html.escape(badge)}</div>
    </div>
    """


def slide_footer(num: int, part: int = 1) -> str:
    ft = FOOTER_P1 if part == 1 else FOOTER_P2
    pt_tag = "PART 1 · SAD" if part == 1 else "PART 2 · TECH v1.0.0"
    pt_cls = "fp-p1" if part == 1 else "fp-p2"
    return f"""
    <div class="slide-footer">
      <span class="sf-left"><span class="sf-part {pt_cls}">{pt_tag}</span> {html.escape(ft)}</span>
      <span class="footer-page">Slide {num:02d} / {TOTAL_SLIDES:02d}</span>
    </div>
    """


def build_html(svgs: dict[str, str]) -> str:
    slides: list[str] = []

    # ---- SLIDE 1: Dark Navy Master Cover ----
    kpi_html = "".join(
        f"""
        <div class="hero-kpi hk-{tone}">
          <div class="hk-val">{html.escape(val)}</div>
          <div class="hk-lbl">{html.escape(lbl)}</div>
          <div class="hk-sub">{html.escape(sub)}</div>
        </div>
        """
        for val, lbl, sub, tone in COVER_KPIS
    )
    team_chips = "".join(
        f'<div class="team-chip"><span class="tc-name">{html.escape(n)}</span><span class="tc-id">{html.escape(sid)}</span></div>'
        for n, sid, _ in TEAM_ROSTER
    )
    slides.append(f"""
    <section class="slide slide-dark" data-slide="1" data-part="1">
      <div class="cover-bg-grid"></div>
      <div class="cover-accent-bar"></div>
      <div class="cover-content">
        <div>
          <div class="cover-pill">FULL GRADUATION DEFENSE &bull; DEPARTMENT OF CYBER SECURITY (2026&ndash;2027) &bull; PREPARED FOR DR. SAMAR</div>
          <h1 class="cover-title">Developing a Lightweight OWASP<br/>Top 10 Vulnerability Scanner</h1>
          <p class="cover-subtitle">Unified Defense: Software Architecture Document (SAD) &amp; Technical Implementation (Phases 0&ndash;7, v1.0.0)</p>
        </div>

        <div class="hero-kpi-row">
          {kpi_html}
        </div>

        <div class="cover-bottom-grid">
          <div class="cover-meta-card">
            <div class="cm-label">SUPERVISOR &amp; DEPARTMENT</div>
            <div class="cm-val">Dr. Samar</div>
            <div class="cm-sub">Department of Cyber Security &bull; 2026&ndash;2027</div>
            <div class="cm-parts">
              <span class="cmp-p1">Part 1: SAD (Slides 1&ndash;20)</span>
              <span class="cmp-p2">Part 2: Technical v1.0.0 (Slides 21&ndash;30)</span>
            </div>
          </div>

          <div class="cover-team-card">
            <div class="cm-label">GRADUATION PROJECT TEAM (7 MEMBERS)</div>
            <div class="team-chips-grid">
              {team_chips}
            </div>
          </div>
        </div>
      </div>
    </section>
    """)

    # ---- SLIDE 2: Part 1 Section Cover (Dark Accent) ----
    ch_cards = "".join(
        f"""
        <div class="sec-ch-card">
          <div class="scc-top"><span class="scc-num">{html.escape(ch)}</span><span class="scc-title">{html.escape(t)}</span></div>
          <div class="scc-desc">{html.escape(d)}</div>
        </div>
        """
        for ch, t, d in SAD_CHAPTERS
    )
    slides.append(f"""
    <section class="slide slide-dark slide-section" data-slide="2" data-part="1">
      <div class="cover-bg-grid"></div>
      <div class="cover-accent-bar"></div>
      <div class="section-content">
        <div class="sec-hdr-row">
          <div>
            <div class="cover-pill">PART 1 OF 2 &bull; SLIDES 01&ndash;20 &bull; IEEE-ALIGNED ARCHITECTURE SPECIFICATION</div>
            <h1 class="sec-title">Part 1: Software Architecture Document (SAD)</h1>
            <p class="sec-sub">Complete 6-chapter formal blueprint covering motivation, SRS, multi-view architecture, 3NF data &amp; API contracts, STRIDE security &amp; validation.</p>
          </div>
          <div class="sec-part-badge">PART 1</div>
        </div>

        <div class="sec-ch-grid">
          {ch_cards}
        </div>

        <div class="sec-metrics-strip">
          <span><strong>19</strong> Original Vector Diagrams</span>
          <span><strong>15</strong> Functional Reqs (FR-01..15)</span>
          <span><strong>9</strong> Quantitative NFRs</span>
          <span><strong>5</strong> Formal ADRs</span>
          <span><strong>15</strong> Verification Test Cases (TC-01..15)</span>
        </div>
      </div>
    </section>
    """)

    # ---- SLIDE 3: Problem Statement & AS-IS vs. TO-BE (Fig. 1) ----
    s3_as = "".join(f'<li><strong>{html.escape(k)}</strong> {html.escape(v)}</li>' for k, v in SLIDE3_AS_IS)
    s3_to = "".join(f'<li><strong>{html.escape(k)}</strong> {html.escape(v)}</li>' for k, v in SLIDE3_TO_BE)
    slides.append(f"""
    <section class="slide slide-light" data-slide="3" data-part="1">
      {slide_header("Problem Statement & AS-IS vs. TO-BE Workflow", "Eliminating enterprise DAST proxy friction with a 3-minute local developer-first OWASP workflow", "CH. 1 · FIGURE 1", 1)}
      <div class="slide-body hero-top-body">
        {diagram_viewer("fig01", svgs, "hero-stage-416")}
        <div class="bottom-2-cards">
          <div class="exec-card">
            <div class="ec-hdr ec-hdr-navy ec-hdr-sm">
              <span>AS-IS: Legacy Enterprise DAST Friction (ZAP / Burp)</span>
              <span class="badge-pill badge-red">PAIN POINTS</span>
            </div>
            <ul class="mini-bullets mb-red">{s3_as}</ul>
          </div>
          <div class="exec-card">
            <div class="ec-hdr ec-hdr-teal ec-hdr-sm">
              <span>TO-BE: OWASP-Lite 3-Minute Zero-Proxy DX</span>
              <span class="badge-pill badge-done">OUR DESIGN</span>
            </div>
            <ul class="mini-bullets mb-teal">{s3_to}</ul>
          </div>
        </div>
      </div>
      {slide_footer(3, 1)}
    </section>
    """)

    # ---- SLIDE 4: Master 4-Phase Scanner Pipeline (Fig. 2) ----
    s4_cards = "".join(
        f"""
        <div class="pipe-tile-4">
          <div class="pt4-top"><span class="pt-num">{html.escape(n)}</span><span class="pt4-title">{html.escape(t)}</span></div>
          <div class="pt4-desc">{html.escape(d)}</div>
        </div>
        """
        for n, t, d in SLIDE4_PHASES
    )
    slides.append(f"""
    <section class="slide slide-light" data-slide="4" data-part="1">
      {slide_header("Master 4-Phase Scanner Pipeline", "End-to-end execution flow from local authorization & BFS discovery to 17-check isolated engine & 5-stack fixes", "CH. 1 · FIGURE 2", 1)}
      <div class="slide-body hero-top-body">
        {diagram_viewer("fig02", svgs, "hero-stage-424")}
        <div class="bottom-4-tiles">{s4_cards}</div>
      </div>
      {slide_footer(4, 1)}
    </section>
    """)

    # ---- SLIDE 5: Ethical Scope & System Use Cases (Fig. 3) ----
    uc_rows = "".join(
        f'<div class="uc-row-sm"><span class="uc-id">{html.escape(u)}</span><div class="uc-txt"><strong>{html.escape(n)}:</strong> {html.escape(d)}</div></div>'
        for u, n, d in SLIDE5_USE_CASES
    )
    ow_chips = "".join(
        f'<div class="ow-chip-sm"><span class="ow-code">{html.escape(c)}</span><span>{html.escape(n)}</span><span class="ow-cnt">({html.escape(cnt)})</span></div>'
        for c, n, cnt in SLIDE5_OWASP
    )
    slides.append(f"""
    <section class="slide slide-light" data-slide="5" data-part="1">
      {slide_header("Ethical Scope & System Use Cases (UC-01 – UC-06)", "Six formal developer use cases, six OWASP Top 10 (2021) categories & strict non-destructive boundaries", "CH. 1–2 · FIGURE 3", 1)}
      <div class="slide-body split-left-760">
        {diagram_viewer("fig03", svgs)}
        <div class="side-col-stack">
          <div class="exec-card">
            <div class="ec-hdr ec-hdr-navy ec-hdr-sm"><span>6 System Use Cases (UC-01 – UC-06)</span><span class="badge-pill badge-teal">SRS</span></div>
            <div class="uc-list-sm">{uc_rows}</div>
          </div>
          <div class="owasp-mini-box">
            <div class="ow-hdr-sm">6 OWASP Top 10 (2021) Categories &middot; 17 Checks</div>
            <div class="ow-grid-2">{ow_chips}</div>
          </div>
          <div class="scope-mini-grid">
            <div class="sm-col sb-in">
              <div class="sb-hdr">&#10003; IN-SCOPE</div>
              <ul><li>Localhost &amp; Docker labs</li><li>17 non-destructive checks</li><li>5-stack fixes &amp; reports</li></ul>
            </div>
            <div class="sm-col sb-out">
              <div class="sb-hdr">&#10007; OUT-OF-SCOPE</div>
              <ul><li>Public internet targets</li><li>Exploitation or DoS</li><li>Headless SPA / SaaS</li></ul>
            </div>
          </div>
        </div>
      </div>
      {slide_footer(5, 1)}
    </section>
    """)

    # ---- SLIDE 6: Formal Software Requirements (FR-01..15 & NFR-01..09) ----
    fr_rows = "".join(
        f'<tr><td class="rq-id">{html.escape(r)}</td><td class="rq-nm">{html.escape(n)}</td><td class="rq-ds">{html.escape(d)}</td></tr>'
        for r, n, d in SLIDE6_FRS
    )
    nfr_rows = "".join(
        f'<tr><td class="rq-id">{html.escape(r)}</td><td class="rq-nm">{html.escape(n)}</td><td class="rq-ds">{html.escape(d)}</td></tr>'
        for r, n, d in SLIDE6_NFRS
    )
    slides.append(f"""
    <section class="slide slide-light" data-slide="6" data-part="1">
      {slide_header("Formal Software Requirements (FR-01..15 & NFR-01..09)", "MoSCoW-prioritized functional capabilities and quantitative quality-attribute acceptance SLAs", "CH. 2 · SRS BASELINE", 1)}
      <div class="slide-body srs-body">
        <div class="srs-tables">
          <div class="req-wrap">
            <div class="ec-hdr ec-hdr-navy ec-hdr-sm"><span>Functional Requirements (FR-01 &ndash; FR-15)</span><span class="badge-pill badge-done">15 MUST/SHOULD</span></div>
            <table class="req-table">
              <thead><tr><th style="width:16%">ID</th><th style="width:27%">Capability</th><th style="width:57%">Formal Specification</th></tr></thead>
              <tbody>{fr_rows}</tbody>
            </table>
          </div>
          <div class="req-wrap">
            <div class="ec-hdr ec-hdr-teal ec-hdr-sm"><span>Quantitative Non-Functional SLAs (NFR-01 &ndash; NFR-09)</span><span class="badge-pill badge-navy-pill">9 SLAs</span></div>
            <table class="req-table">
              <thead><tr><th style="width:16%">ID</th><th style="width:27%">Attribute</th><th style="width:57%">Measurable Acceptance Target</th></tr></thead>
              <tbody>{nfr_rows}</tbody>
            </table>
          </div>
        </div>
        <div class="sla-strip">
          <div class="sla-pill"><strong>&lt; 3 min</strong> Setup</div>
          <div class="sla-pill"><strong>&le; 15s / 45s / 90s</strong> Quick / Std / Deep</div>
          <div class="sla-pill"><strong>&ge; 85%</strong> Prec &bull; <strong>&ge; 80%</strong> Rec &bull; <strong>&ge; 82%</strong> F1</div>
          <div class="sla-pill"><strong>0</strong> /safe/* Control FPs</div>
          <div class="sla-pill"><strong>10 req/s</strong> &bull; <strong>2,000</strong> Req Cap &bull; <strong>Pure SVG Charts</strong></div>
        </div>
      </div>
      {slide_footer(6, 1)}
    </section>
    """)

    # ---- SLIDE 7: C4 Level 1 System Context (Fig. 4) ----
    c4l1_cards = "".join(
        f'<div class="side-accent-card"><div class="sac-t">{html.escape(t)}</div><div class="sac-d">{html.escape(d)}</div></div>'
        for t, d in SLIDE7_C4L1
    )
    slides.append(f"""
    <section class="slide slide-light" data-slide="7" data-part="1">
      {slide_header("C4 Level 1: System Context Diagram", "Actors, local-only scanner boundary, authorized testbench targets & hard public-internet block", "CH. 3 · FIGURE 4", 1)}
      <div class="slide-body split-left-760">
        {diagram_viewer("fig04", svgs)}
        <div class="side-col-even">
          <div class="side-hdr-bar">System Context Boundaries</div>
          {c4l1_cards}
        </div>
      </div>
      {slide_footer(7, 1)}
    </section>
    """)

    # ---- SLIDE 8: C4 Level 2 Container Architecture (Fig. 5) ----
    c4l2_cards = "".join(
        f'<div class="layer-card"><div class="lc-name">{html.escape(n)}</div><div class="lc-desc">{html.escape(d)}</div></div>'
        for n, d in SLIDE8_LAYERS
    )
    slides.append(f"""
    <section class="slide slide-light" data-slide="8" data-part="1">
      {slide_header("C4 Level 2: Container Architecture & 6-Layer Stack", "Modular monolith v1.0.0 — Pure Inline SVG Charts, SQLite WAL / PostgreSQL 16 & non-root Docker", "CH. 3 · FIGURE 5", 1)}
      <div class="slide-body split-left-760">
        {diagram_viewer("fig05", svgs)}
        <div class="side-col-6">
          <div class="side-hdr-bar">6-Layer Technology Stack (v1.0.0)</div>
          {c4l2_cards}
        </div>
      </div>
      {slide_footer(8, 1)}
    </section>
    """)

    # ---- SLIDE 9: C4 Level 3 Pure-Python Scanner Engine Components (Fig. 6) ----
    c4l3_cards = "".join(
        f"""
        <div class="comp-tile{' comp-tile-ast' if i == 3 else ''}">
          <div class="ct-t">{html.escape(t)}</div>
          <div class="ct-d">{html.escape(d)}</div>
        </div>
        """
        for i, (t, d) in enumerate(SLIDE9_COMPONENTS)
    )
    slides.append(f"""
    <section class="slide slide-light" data-slide="9" data-part="1">
      {slide_header("C4 Level 3: Pure-Python Scanner Engine Components", "Decoupled backend/scanner/ core — ScopeGuardrail, HttpClient, BFS Crawler & 17-Check Orchestrator", "CH. 3 · FIG. 6 · 30/30 AST", 1)}
      <div class="slide-body hero-top-body">
        {diagram_viewer("fig06", svgs, "hero-stage-424")}
        <div class="bottom-4-tiles">{c4l3_cards}</div>
      </div>
      {slide_footer(9, 1)}
    </section>
    """)

    # ---- SLIDE 10: DFD Level 0 System Context Data Flows (Fig. 7) ----
    dfd0_cards = "".join(
        f"""
        <div class="pipe-tile-4">
          <div class="pt4-top"><span class="pt-num">{html.escape(k)}</span><span class="pt4-title">{html.escape(t)}</span></div>
          <div class="pt4-desc">{html.escape(d)}</div>
        </div>
        """
        for k, t, d in SLIDE10_FLOWS
    )
    slides.append(f"""
    <section class="slide slide-light" data-slide="10" data-part="1">
      {slide_header("DFD Level 0: System Context Data Flows", "High-level data ingress, live telemetry egress, bounded HTTP target probing & 3NF persistence", "CH. 3 · FIGURE 7", 1)}
      <div class="slide-body hero-top-body">
        {diagram_viewer("fig07", svgs, "hero-stage-424")}
        <div class="bottom-4-tiles">{dfd0_cards}</div>
      </div>
      {slide_footer(10, 1)}
    </section>
    """)

    # ---- SLIDE 11: DFD Level 1 Trust Boundaries, STRIDE & NIST SSDF (Fig. 8) ----
    stride_rows = "".join(
        f'<li><strong>{html.escape(k)}:</strong> {html.escape(v)}</li>' for k, v in SLIDE11_STRIDE
    )
    ssdf_tiles = "".join(
        f'<div class="ssdf-tile"><span class="ssdf-code">{html.escape(c)}</span><div><strong>{html.escape(n)}:</strong> {html.escape(d)}</div></div>'
        for c, n, d in SLIDE11_SSDF
    )
    slides.append(f"""
    <section class="slide slide-light" data-slide="11" data-part="1">
      {slide_header("DFD Level 1: Trust Boundaries, STRIDE & NIST SSDF", "Explicit trust boundaries (TB1–TB3) mapped to STRIDE mitigations and NIST SP 800-218 practices", "CH. 3 & 5 · FIGURE 8", 1)}
      <div class="slide-body split-left-720">
        {diagram_viewer("fig08", svgs)}
        <div class="side-col-stack">
          <div class="exec-card">
            <div class="ec-hdr ec-hdr-navy ec-hdr-sm"><span>STRIDE Threat Mitigations</span><span class="badge-pill badge-red">5 CONTROLS</span></div>
            <ul class="mini-bullets mb-navy">{stride_rows}</ul>
          </div>
          <div class="exec-card">
            <div class="ec-hdr ec-hdr-teal ec-hdr-sm"><span>NIST SSDF (SP 800-218) Alignment</span><span class="badge-pill badge-done">MAPPED</span></div>
            <div class="ssdf-grid">{ssdf_tiles}</div>
          </div>
        </div>
      </div>
      {slide_footer(11, 1)}
    </section>
    """)

    # ---- SLIDE 12: Scope Guardrail & Safe Non-Destructive Scanning Flow (Fig. 16) ----
    l_cards = "".join(
        f"""
        <div class="layer4-card">
          <div class="l4-badge">{html.escape(code)}</div>
          <div>
            <div class="l4-title">{html.escape(t)}</div>
            <div class="l4-desc">{html.escape(d)}</div>
          </div>
        </div>
        """
        for code, t, d in SLIDE12_LAYERS
    )
    slides.append(f"""
    <section class="slide slide-light" data-slide="12" data-part="1">
      {slide_header("Scope Guardrail & Safe Non-Destructive Scanning Flow", "4-layer defense-in-depth gate enforcing local-only ethical scanning and anti-SSRF protection", "CH. 5 · FIGURE 16", 1)}
      <div class="slide-body split-tall-520">
        {diagram_viewer("fig16", svgs)}
        <div class="side-col-even">
          <div class="side-hdr-bar">4 Defense-in-Depth Safety Layers (policy.py)</div>
          {l_cards}
        </div>
      </div>
      {slide_footer(12, 1)}
    </section>
    """)

    # ---- SLIDE 13: Master System Execution Flowchart (ISO 5807) (Fig. 19) ----
    st_cards = "".join(
        f"""
        <div class="stage6-card">
          <div class="st6-num">{html.escape(num)}</div>
          <div>
            <div class="st6-title">{html.escape(t)}</div>
            <div class="st6-desc">{html.escape(d)}</div>
          </div>
        </div>
        """
        for num, t, d in SLIDE13_STAGES
    )
    slides.append(f"""
    <section class="slide slide-light" data-slide="13" data-part="1">
      {slide_header("Master System Execution Flowchart (ISO 5807)", "Complete decision-level control flow — zoom & pan left to inspect every ISO 5807 gate", "CH. 3 · FIGURE 19", 1)}
      <div class="slide-body split-tall-480">
        {diagram_viewer("fig19", svgs)}
        <div class="side-col-6">
          <div class="side-hdr-bar">6 Numbered End-to-End Lifecycle Stages</div>
          {st_cards}
        </div>
      </div>
      {slide_footer(13, 1)}
    </section>
    """)

    # ---- SLIDE 14: Cross-Functional Swimlane Activity Workflow (Fig. 13) ----
    lane_cards = "".join(
        f"""
        <div class="layer4-card">
          <div class="l4-badge">{html.escape(code)}</div>
          <div>
            <div class="l4-title">{html.escape(t)}</div>
            <div class="l4-desc">{html.escape(d)}</div>
          </div>
        </div>
        """
        for code, t, d in SLIDE14_LANES
    )
    slides.append(f"""
    <section class="slide slide-light" data-slide="14" data-part="1">
      {slide_header("Cross-Functional Swimlane Activity Workflow", "Clear handoffs across Developer Browser, FastAPI SSE API, Pure Scanner Core & SQLAlchemy DB", "CH. 3 · FIGURE 13", 1)}
      <div class="slide-body split-left-720">
        {diagram_viewer("fig13", svgs)}
        <div class="side-col-even">
          <div class="side-hdr-bar">4 Architectural Swimlane Responsibilities</div>
          {lane_cards}
        </div>
      </div>
      {slide_footer(14, 1)}
    </section>
    """)

    # ---- SLIDE 15: 6-State Scan Lifecycle State Machine (Fig. 12) ----
    fsm_cards = "".join(
        f"""
        <div class="pipe-tile-4">
          <div class="pt4-top"><span class="pt-num">{html.escape(k)}</span><span class="pt4-title">{html.escape(t)}</span></div>
          <div class="pt4-desc">{html.escape(d)}</div>
        </div>
        """
        for k, t, d in SLIDE15_FSM
    )
    slides.append(f"""
    <section class="slide slide-light" data-slide="15" data-part="1">
      {slide_header("6-State Scan Lifecycle State Machine", "Deterministic scan states (queued, crawling, scanning, completed, cancelled, failed) synced via SSE", "CH. 3 · FIGURE 12", 1)}
      <div class="slide-body hero-top-body">
        {diagram_viewer("fig12", svgs, "hero-stage-424")}
        <div class="bottom-4-tiles">{fsm_cards}</div>
      </div>
      {slide_footer(15, 1)}
    </section>
    """)

    # ---- SLIDE 16: End-to-End Scan Lifecycle & Live SSE Sequence (Fig. 10) ----
    seq_cards = "".join(
        f'<div class="side-accent-card"><div class="sac-t">{html.escape(t)}</div><div class="sac-d">{html.escape(d)}</div></div>'
        for t, d in SLIDE16_SEQ_CARDS
    )
    slides.append(f"""
    <section class="slide slide-light" data-slide="16" data-part="1">
      {slide_header("End-to-End Scan Lifecycle & Live SSE Sequence", "201 Created async job dispatch and real-time /api/scans/{id}/stream telemetry — zoom left to inspect every message", "CH. 3 · FIGURE 10", 1)}
      <div class="slide-body split-tall-480">
        {diagram_viewer("fig10", svgs)}
        <div class="side-col-even">
          <div class="side-hdr-bar">Async Dispatch &amp; Live SSE Protocol</div>
          {seq_cards}
        </div>
      </div>
      {slide_footer(16, 1)}
    </section>
    """)

    # ---- SLIDE 17: Cooperative Cancellation & Per-Check Error Isolation (Fig. 11) ----
    can_li = "".join(f'<li><strong>{html.escape(k)}</strong> {html.escape(v)}</li>' for k, v in SLIDE17_CANCEL)
    iso_li = "".join(f'<li><strong>{html.escape(k)}</strong> {html.escape(v)}</li>' for k, v in SLIDE17_ISOLATION)
    slides.append(f"""
    <section class="slide slide-light" data-slide="17" data-part="1">
      {slide_header("Cooperative Cancellation & Per-Check Error Isolation", "Thread-safe <= 5s graceful halt via threading.Event and non-fatal try/except plugin fault containment", "CH. 3 · FIGURE 11", 1)}
      <div class="slide-body split-left-640">
        {diagram_viewer("fig11", svgs)}
        <div class="side-col-2cards">
          <div class="exec-card">
            <div class="ec-hdr ec-hdr-navy"><span>Cooperative Cancellation (&le; 5s Halt)</span><span class="badge-pill badge-amber">threading.Event</span></div>
            <ul class="resil-bullets">{can_li}</ul>
          </div>
          <div class="exec-card">
            <div class="ec-hdr ec-hdr-teal"><span>Per-Check Error Isolation</span><span class="badge-pill badge-done">check_warning</span></div>
            <ul class="resil-bullets">{iso_li}</ul>
          </div>
        </div>
      </div>
      {slide_footer(17, 1)}
    </section>
    """)

    # ---- SLIDE 18: Modular Plugin Engine (BaseCheck) & 5-Stack Fix KB (Fig. 14) ----
    p_cards = []
    for title, hdr_tone, tag, pts in SLIDE18_CARDS:
        hdr_cls = "ec-hdr-navy" if hdr_tone == "NAVY" else "ec-hdr-teal"
        li_html = "".join(f"<li>{html.escape(p)}</li>" for p in pts)
        p_cards.append(f"""
        <div class="exec-card">
          <div class="ec-hdr {hdr_cls} ec-hdr-sm"><span>{html.escape(title)}</span><span class="badge-pill badge-done">{html.escape(tag)}</span></div>
          <ul class="mini-bullets mb-teal">{li_html}</ul>
        </div>
        """)
    slides.append(f"""
    <section class="slide slide-light" data-slide="18" data-part="1">
      {slide_header("Modular Plugin Engine (BaseCheck) & 5-Stack Fix KB", "Open/Closed 1-file plugin auto-registry paired with interpolated 5-stack code remediation (kb.json)", "CH. 3 · FIGURE 14", 1)}
      <div class="slide-body split-left-720">
        {diagram_viewer("fig14", svgs)}
        <div class="side-col-3cards">
          {''.join(p_cards)}
        </div>
      </div>
      {slide_footer(18, 1)}
    </section>
    """)

    # ---- SLIDE 19: 3NF Data Model & 14 REST/SSE API Contract (Fig. 15) ----
    tbl_rows = "".join(
        f'<div class="erd-row"><code>{html.escape(t)}</code><span>{html.escape(d)}</span></div>'
        for t, d in SLIDE19_TABLES
    )
    ep_rows = "".join(
        f'<div class="ep-row"><code>{html.escape(e)}</code><span>{html.escape(d)}</span></div>'
        for e, d in SLIDE19_ENDPOINTS
    )
    slides.append(f"""
    <section class="slide slide-light" data-slide="19" data-part="1">
      {slide_header("3NF Data Model & 14 REST/SSE API Contract", "Normalized 4-table SQLAlchemy 2.0 schema (SQLite WAL / PG 16) and typed FastAPI endpoint surface", "CH. 4 · FIGURE 15", 1)}
      <div class="slide-body split-left-680">
        {diagram_viewer("fig15", svgs)}
        <div class="side-col-stack">
          <div class="exec-card">
            <div class="ec-hdr ec-hdr-navy ec-hdr-sm"><span>4-Table 3NF Relational Schema</span><span class="badge-pill badge-done">UUID + CASCADE</span></div>
            <div class="erd-list">{tbl_rows}</div>
          </div>
          <div class="exec-card">
            <div class="ec-hdr ec-hdr-teal ec-hdr-sm"><span>14 FastAPI REST / SSE Endpoints (6 Groups)</span><span class="badge-pill badge-navy-pill">OPENAPI</span></div>
            <div class="ep-list">{ep_rows}</div>
          </div>
        </div>
      </div>
      {slide_footer(19, 1)}
    </section>
    """)

    # ---- SLIDE 20: ADRs (01–05) & 3-Tier Validation Plan (TC-01..15) ----
    adr_cards = "".join(
        f"""
        <div class="adr-card">
          <div class="adr-id">{html.escape(aid)}</div>
          <div>
            <div class="adr-t">{html.escape(t)}</div>
            <div class="adr-d">{html.escape(d)}</div>
          </div>
        </div>
        """
        for aid, t, d in SLIDE20_ADRS
    )
    tier_cards = "".join(
        f"""
        <div class="val-tier vt-{tone.lower()}">
          <div class="vt-tag">{html.escape(tag)}</div>
          <div class="vt-name">{html.escape(nm)}</div>
          <div class="vt-desc">{html.escape(desc)}</div>
        </div>
        """
        for tag, nm, desc, tone in SLIDE20_TIERS
    )
    slides.append(f"""
    <section class="slide slide-light" data-slide="20" data-part="1">
      {slide_header("Architecture Decision Records (ADR-01..05) & 3-Tier Validation Plan", "Formal trade-off justifications and 15-case empirical verification strategy (TC-01..15)", "CH. 5–6 · ADRs & PLAN", 1)}
      <div class="slide-body adr-val-body">
        <div class="adr-col">
          <div class="side-hdr-bar">5 Formal Architecture Decision Records (ADR-01 – ADR-05)</div>
          <div class="adr-list">{adr_cards}</div>
        </div>
        <div class="val-col">
          <div class="side-hdr-bar shb-teal">3-Tier Testbench Validation Strategy (TC-01 – TC-15)</div>
          <div class="val-list">{tier_cards}</div>
        </div>
      </div>
      {slide_footer(20, 1)}
    </section>
    """)

    # ---- SLIDE 21: Part 2 Section Cover + Complete Roadmap (Phases 0–7 ALL DONE) ----
    rm_rows = "".join(
        f"""
        <tr>
          <td class="rm-ph">{html.escape(ph)}</td>
          <td><span class="badge-pill badge-done">&#10003; {html.escape(st)}</span></td>
          <td class="rm-deliv">{html.escape(deliv)}</td>
          <td class="rm-test">{html.escape(tst)}</td>
        </tr>
        """
        for ph, st, deliv, tst in ROADMAP_ROWS
    )
    slides.append(f"""
    <section class="slide slide-light" data-slide="21" data-part="2">
      <div class="p2-banner">
        <div class="p2b-accent"></div>
        <div class="p2b-text">
          <div class="p2b-pill">PART 2 OF 2 &bull; SLIDES 21&ndash;30 &bull; TECHNICAL IMPLEMENTATION &amp; EMPIRICAL RESULTS (v1.0.0)</div>
          <h1 class="p2b-title">Complete 8-Phase Engineering Roadmap (Phases 0 &rarr; 7 ALL DONE)</h1>
        </div>
        <div class="p2b-stats">
          <div class="p2bs"><b>8 / 8</b><span>Phases Done</span></div>
          <div class="p2bs"><b>88 + 29</b><span>Tests &amp; Subtests</span></div>
          <div class="p2bs p2bs-green"><b>0</b><span>Defects</span></div>
        </div>
      </div>
      <div class="slide-body p2-rm-body">
        <div class="growth-strip">
          <span><strong>Cumulative Automated Test Growth:</strong> <code>2 (P0) &rarr; 20 (P2) &rarr; 70 (P3) &rarr; 82 (P4) &rarr; 86 (P6) &rarr; 88 + 29 subtests (P7)</code></span>
          <span class="badge-pill badge-done">RELEASE v1.0.0 VERIFIED</span>
        </div>
        <div class="table-card">
          <table class="data-table rm-table">
            <thead>
              <tr><th style="width:11%">Phase</th><th style="width:11%">Status</th><th style="width:62%">Delivered Engineering Milestones</th><th style="width:16%">Verified Proof</th></tr>
            </thead>
            <tbody>{rm_rows}</tbody>
          </table>
        </div>
      </div>
      {slide_footer(21, 2)}
    </section>
    """)

    # ---- SLIDE 22: Phase 3 — All 17 Curated OWASP Checks & 5-Stack Fix KB ----
    def _chk_li(items: list[tuple[str, str]]) -> str:
        return "".join(f'<li><code>{html.escape(c)}</code><span class="ow-tag">{html.escape(o)}</span></li>' for c, o in items)

    p3_bottom = "".join(
        f'<div class="eng-card"><div class="eng-t">{html.escape(t)}</div><div class="eng-d">{html.escape(d)}</div></div>'
        for t, d in P3_ENGINE_CARDS
    )
    slides.append(f"""
    <section class="slide slide-light" data-slide="22" data-part="2">
      {slide_header("Phase 3: All 17 Curated OWASP Top 10 Checks & 5-Stack Fix KB", "Modular 1-file BaseCheck auto-registry, 85 framework patches, SHA-1 dedup & isolated ScanOrchestrator", "PHASE 3 · 17 CHECKS", 2)}
      <div class="slide-body p3-body">
        <div class="check-matrix">
          <div class="exec-card">
            <div class="ec-hdr ec-hdr-navy ec-hdr-sm"><span>8 Passive Checks (Quick+)</span><span class="badge-pill badge-done">ZERO PROBES</span></div>
            <ul class="chk-list">{_chk_li(PASSIVE_CHECKS)}</ul>
          </div>
          <div class="exec-card">
            <div class="ec-hdr ec-hdr-teal ec-hdr-sm"><span>6 Safe Active Checks (Std / Deep)</span><span class="badge-pill badge-amber">NON-DESTRUCTIVE</span></div>
            <ul class="chk-list">{_chk_li(ACTIVE_CHECKS)}</ul>
          </div>
          <div class="exec-card">
            <div class="ec-hdr ec-hdr-slate ec-hdr-sm"><span>3 Discovery Checks (Std / Deep)</span><span class="badge-pill badge-teal">SOFT-404 GUARD</span></div>
            <ul class="chk-list">{_chk_li(DISCOVERY_CHECKS)}</ul>
            <div class="profile-summary">
              <div class="ps-hdr">PROFILE TIERS &amp; 5 FIX STACKS</div>
              <div class="ps-pills"><span>Quick: <b>8</b></span><span>Standard: <b>14</b></span><span>Deep: <b>17</b></span></div>
              <div class="ps-stacks">FastAPI &bull; Flask &bull; Express &bull; PHP &bull; HTML</div>
            </div>
          </div>
        </div>
        <div class="bottom-4-tiles">{p3_bottom}</div>
      </div>
      {slide_footer(22, 2)}
    </section>
    """)

    # ---- SLIDE 23: Phases 4 & 5 — 6-View Developer Workbench & VS Code Dark+ Reports ----
    v_cards = "".join(
        f"""
        <div class="view-card">
          <div class="vc-top"><span class="vc-num">{html.escape(n)}</span><span class="vc-name">{html.escape(nm)}</span></div>
          <p class="vc-desc">{html.escape(d)}</p>
        </div>
        """
        for n, nm, d in P5_VIEWS
    )
    pill_cards = "".join(
        f'<div class="inv-card"><div class="inv-t">{html.escape(t)}</div><div class="inv-d">{html.escape(d)}</div></div>'
        for t, d in P5_PILLS
    )
    slides.append(f"""
    <section class="slide slide-light" data-slide="23" data-part="2">
      {slide_header("Phases 4 & 5: 6-View Developer Workbench & VS Code Dark+ Reports", "Zero-build Vanilla ES6 workbench with live SSE, Swap & Reset scan diff & offline auto-escaped HTML5 exports", "PHASES 4–5 · UI & REPORTS", 2)}
      <div class="slide-body p5-body">
        <div class="views-grid-6">{v_cards}</div>
        <div class="inv-strip-3">{pill_cards}</div>
      </div>
      {slide_footer(23, 2)}
    </section>
    """)

    # ---- SLIDE 24: Phase 6 — Deterministic VulnBench & Live NFR-08 Accuracy Results ----
    g_cards = "".join(
        f"""
        <div class="gate-card">
          <div class="gc-top"><span class="gc-val">{html.escape(val)}</span><span class="badge-pill badge-done">PASS</span></div>
          <div class="gc-lbl">{html.escape(lbl)}</div>
          <div class="gc-bar"><div class="gc-fill" style="width:{pct}%"></div></div>
          <div class="gc-sub">{html.escape(sub)}</div>
        </div>
        """
        for val, lbl, sub, pct in NFR08_GATES
    )
    vb_html = "".join(
        f'<tr class="{"row-highlight" if i == 2 else ""}">' + "".join(f"<td>{html.escape(c)}</td>" for c in row) + "</tr>"
        for i, row in enumerate(VULNBENCH_ROWS)
    )
    slides.append(f"""
    <section class="slide slide-light" data-slide="24" data-part="2">
      {slide_header("Phase 6: Deterministic VulnBench & Live NFR-08 Accuracy Results", "Reproducible empirical evaluation via scripts/evaluate.py across Quick, Standard & Deep profiles", "PHASE 6 · NFR-08 PASS", 2)}
      <div class="slide-body p6-body">
        <div class="gate-grid-4">{g_cards}</div>
        <div class="table-card">
          <table class="data-table vb-table">
            <thead>
              <tr>
                <th>Profile</th><th>Checks</th><th>TP / FP / FN</th><th>Precision</th><th>Recall (All)</th><th>F1 (All)</th><th>Clean FPs</th><th>Route Cov.</th><th>Duration (SLA)</th>
              </tr>
            </thead>
            <tbody>{vb_html}</tbody>
          </table>
        </div>
        <div class="p6-bottom-2">
          <div class="mini-note">
            <div class="mn-title">4 Clean <code>/safe/*</code> Negative Controls &mdash; 0 False Positives</div>
            <div class="mn-desc"><code>/safe/form</code> (CSRF token) &bull; <code>/safe/item</code> (parameterized SQLite) &bull; <code>/safe/redirect</code> (allowlist) &bull; <code>/safe/search</code> (HTML-escaped + strict headers).</div>
          </div>
          <div class="mini-note mn-teal">
            <div class="mn-title">All 6 OWASP 2021 Categories Beat SAD Ch. 6.4.1 Targets</div>
            <div class="mn-desc"><b>100%</b> observed across A01 (4/4), A02 (1/1), A03 (3/3), A05 (9/9), A06 (1/1), A07 (1/1) &bull; 215 Deep requests, Risk 78/100, 0 errors.</div>
          </div>
        </div>
      </div>
      {slide_footer(24, 2)}
    </section>
    """)

    # ---- SLIDE 25: Accuracy Benchmark Visualization (Fig. 17) ----
    f17_html = "".join(
        f'<div class="chart-card cc-{tone}"><div class="cc-title">{html.escape(t)}</div><div class="cc-desc">{html.escape(d)}</div></div>'
        for t, d, tone in FIG17_CARDS
    )
    slides.append(f"""
    <section class="slide slide-light" data-slide="25" data-part="2">
      {slide_header("Accuracy Benchmark Visualization (Figure 17)", "SAD Ch. 6 targets vs. live observed Deep 100.0% Precision / 100.0% Recall / 100.0% F1 (19/19 TP, 0 FP, 0 FN)", "PHASE 6 · FIGURE 17", 2)}
      <div class="slide-body hero-top-body">
        {diagram_viewer("fig17", svgs, "hero-stage-424")}
        <div class="bottom-3-cards">{f17_html}</div>
      </div>
      {slide_footer(25, 2)}
    </section>
    """)

    # ---- SLIDE 26: Coverage & Profile Latency Visualization (Fig. 18) ----
    f18_html = "".join(
        f'<div class="chart-card cc-{tone}"><div class="cc-title">{html.escape(t)}</div><div class="cc-desc">{html.escape(d)}</div></div>'
        for t, d, tone in FIG18_CARDS
    )
    slides.append(f"""
    <section class="slide slide-light" data-slide="26" data-part="2">
      {slide_header("Coverage & Profile Latency Visualization (Figure 18)", "Live observed durations (1.92s / 20.22s / 21.42s) vs. NFR-02 SLAs & 93.3% (14/15) VulnBench coverage", "PHASE 6 · FIGURE 18", 2)}
      <div class="slide-body hero-top-body">
        {diagram_viewer("fig18", svgs, "hero-stage-424")}
        <div class="bottom-3-cards">{f18_html}</div>
      </div>
      {slide_footer(26, 2)}
    </section>
    """)

    # ---- SLIDE 27: DX Benchmark vs. OWASP ZAP & Honest Boundaries ----
    dx_html = "".join(
        f'<tr><td class="dx-dim">{html.escape(dim)}</td><td class="dx-zap">{html.escape(zap)}</td><td class="dx-ours">{html.escape(ours)}</td></tr>'
        for dim, zap, ours in DX_ROWS
    )
    bnd_html = "".join(
        f'<div class="bnd-card"><div class="bnd-t">{html.escape(t)}</div><div class="bnd-d">{html.escape(d)}</div></div>'
        for t, d in BOUNDARY_CARDS
    )
    slides.append(f"""
    <section class="slide slide-light" data-slide="27" data-part="2">
      {slide_header("Developer-Experience (DX) Benchmark vs. OWASP ZAP & Honest Boundaries", "Structured 5-dimension ergonomics comparison plus transparent academic disclosure of technical limits", "EVALUATION · DX & LIMITS", 2)}
      <div class="slide-body dx-body">
        <div class="table-card">
          <table class="data-table dx-table">
            <thead>
              <tr><th style="width:19%">DX Dimension</th><th style="width:39%">OWASP ZAP Baseline</th><th style="width:42%">OWASP-Lite Scanner (This Project)</th></tr>
            </thead>
            <tbody>{dx_html}</tbody>
          </table>
        </div>
        <div class="bnd-wrap">
          <div class="bnd-hdr">HONEST TECHNICAL BOUNDARIES &amp; THREATS TO VALIDITY (ACADEMIC DISCLOSURE)</div>
          <div class="bnd-grid-3">{bnd_html}</div>
        </div>
      </div>
      {slide_footer(27, 2)}
    </section>
    """)

    # ---- SLIDE 28: Phase 7 — Live Self-Scan Audit & Security Hardening ----
    ha_html = "".join(
        f'<div class="ha-item"><div class="ha-t">{html.escape(t)}</div><div class="ha-d">{html.escape(d)}</div></div>'
        for t, d in HARDENING_ACTIONS
    )
    slides.append(f"""
    <section class="slide slide-light" data-slide="28" data-part="2">
      {slide_header("Phase 7: Live Self-Scan Audit & Security Hardening", "Dogfooding our own Deep 17-check scan on http://127.0.0.1:8000 — Risk halved (6 → 3/100) with CI guard", "PHASE 7 · SELF-SCAN", 2)}
      <div class="slide-body p7-body">
        <div class="dogfood-bar">
          <span><strong>Target:</strong> <code>http://127.0.0.1:8000</code></span>
          <span><strong>Profile:</strong> Deep (17/17 checks)</span>
          <span><strong>Telemetry:</strong> 83 HTTP Requests &bull; 0 Errors</span>
          <span class="badge-pill badge-done">0 CRITICAL &bull; 0 HIGH</span>
        </div>
        <div class="ba-row">
          <div class="ba-card ba-before">
            <div class="ba-top"><span class="ba-tag tag-amber">BEFORE HARDENING (BASELINE)</span><span class="ba-score sc-amber">Risk 6 / 100</span></div>
            <ul class="ba-list">
              <li><b>0 Critical &bull; 0 High &bull; 2 Medium</b> (<code>missing_security_headers</code> + <code>weak_csp</code>)</li>
              <li><code>Permissions-Policy</code> header absent; <code>object-src 'none'</code> not explicitly set.</li>
              <li>Default Uvicorn <code>Server</code> banner and static asset caching active.</li>
            </ul>
          </div>
          <div class="ba-arrow">&rarr;</div>
          <div class="ba-card ba-after">
            <div class="ba-top"><span class="ba-tag tag-green">AFTER PHASE 7 HARDENING (&minus;50%)</span><span class="ba-score sc-green">Risk 3 / 100</span></div>
            <ul class="ba-list">
              <li><b>0 Critical &bull; 0 High &bull; 0 <code>missing_security_headers</code> &bull; 0 <code>server_banner_leak</code></b></li>
              <li>16/17 checks pass clean; scoped <code>/docs</code> CSP preserves Swagger while locking app <code>script-src</code>.</li>
              <li>Single Medium (<code>style-src 'unsafe-inline'</code>) transparently documented for zero-build Tailwind UI.</li>
            </ul>
          </div>
        </div>
        <div class="ha-grid-5">{ha_html}</div>
      </div>
      {slide_footer(28, 2)}
    </section>
    """)

    # ---- SLIDE 29: Multi-Container Docker Deployment, 88-Test Pyramid & 3-Job CI (Fig. 9) ----
    tier_rows = "".join(
        f"""
        <div class="tier-row">
          <div class="tr-top"><span class="tr-name">{html.escape(nm)}</span><span class="tr-cnt">{html.escape(cnt)}</span></div>
          <div class="tr-bar-wrap"><div class="tr-bar tb-{tone}" style="width:{pct}%"></div></div>
          <div class="tr-file">{html.escape(src)}</div>
        </div>
        """
        for nm, src, cnt, pct, tone in TEST_TIERS
    )
    ci_rows = "".join(
        f'<div class="ci-col-item"><span class="ci-job">{html.escape(j)}</span><span class="ci-desc">{html.escape(d)}</span></div>'
        for j, d in CI_JOBS
    )
    slides.append(f"""
    <section class="slide slide-light" data-slide="29" data-part="2">
      {slide_header("Multi-Container Docker Deployment, 88-Test Pyramid & 3-Job CI", "Containerized local stack (Figure 9), 5-tier verification pyramid & automated GitHub Actions pipeline", "PHASE 7 · FIG. 9 · 88 TESTS", 2)}
      <div class="slide-body split-p29">
        <div class="left-p29">
          {diagram_viewer("fig09", svgs, "p29-fig")}
          <div class="exec-card ci-card">
            <div class="ec-hdr ec-hdr-navy ec-hdr-sm">
              <span>3-Job GitHub Actions CI (<code>.github/workflows/ci.yml</code>)</span>
              <span class="badge-pill badge-done">3/3 GREEN</span>
            </div>
            <div class="ci-grid-3">{ci_rows}</div>
          </div>
        </div>
        <div class="right-p29">
          <div class="pass-banner">
            <div class="pb-icon">&#10003;</div>
            <div>
              <div class="pb-title">88 Passed + 29 Subtests</div>
              <div class="pb-sub">24.71s &bull; 0 failures &bull; 0 errors</div>
            </div>
          </div>
          <div class="exec-card pyramid-card">
            <div class="ec-hdr ec-hdr-teal ec-hdr-sm"><span>5-Tier Automated Test Pyramid</span><span class="badge-pill badge-done">100%</span></div>
            <div class="tier-list">{tier_rows}</div>
            <div class="pyramid-sum"><strong>Total:</strong> <code>2 + 70 + 10 + 4 + 2 = 88 + 29 subtests</code></div>
          </div>
        </div>
      </div>
      {slide_footer(29, 2)}
    </section>
    """)

    # ---- SLIDE 30: Dark Navy Closing — Live Demo, Team Contributions & Q&A ----
    demo_bar = "".join(
        f"""
        <div class="demo-chip">
          <div class="dc-top"><span class="dc-num">{html.escape(n)}</span><span class="dc-tm">{html.escape(tm)}</span></div>
          <div class="dc-title">{html.escape(t)}</div>
          <div class="dc-desc">{html.escape(d)}</div>
        </div>
        """
        for n, tm, t, d in DEMO_STEPS
    )
    roster_rows = "".join(
        f'<tr><td class="rt-name">{html.escape(n)}</td><td class="rt-id">{html.escape(sid)}</td><td class="rt-mod">{html.escape(mod)}</td></tr>'
        for n, sid, mod in TEAM_ROSTER
    )
    slides.append(f"""
    <section class="slide slide-dark" data-slide="30" data-part="2">
      <div class="cover-bg-grid"></div>
      <div class="cover-accent-bar"></div>
      <div class="closing-content">
        <div class="closing-header">
          <div>
            <div class="cover-pill">FINAL GRADUATION DEFENSE &bull; RELEASE v1.0.0 &bull; ALL 8 PHASES &amp; 19 DIAGRAMS COMPLETE</div>
            <h1 class="closing-title">3-Min Live Demo, Team Contributions &amp; Q&amp;A</h1>
          </div>
          <div class="repo-chip">
            <div class="rc-lbl">GITHUB REPOSITORY</div>
            <div class="rc-url">https://github.com/mohammewaleed/Graduation-Project-2027</div>
          </div>
        </div>

        <div class="demo-bar-5">
          {demo_bar}
        </div>

        <table class="roster-table">
          <thead>
            <tr><th style="width:28%">Team Member</th><th style="width:12%">Student ID</th><th style="width:60%">Role &amp; Delivered Module Ownership</th></tr>
          </thead>
          <tbody>{roster_rows}</tbody>
        </table>

        <div class="approval-banner">
          <div>
            <div class="ab-title">OWASP-Lite Scanner v1.0.0 &mdash; Architected, Verified, Hardened &amp; Ready for Live Defense</div>
            <div class="ab-sub">Department of Cyber Security &bull; Academic Year 2026&ndash;2027 &bull; Prepared for Dr. Samar &bull; 30 Slides &bull; 19/19 Original Diagrams</div>
          </div>
          <div class="qa-badge">Q &amp; A</div>
        </div>
      </div>
    </section>
    """)

    # Grouped Grid Overview Modal cards
    p1_grid_items = "".join(
        f'<button type="button" class="gm-card gm-p1" data-goto="{snum}"><span class="gmc-num">{snum:02d}</span><span class="gmc-title">{html.escape(title)}</span></button>'
        for snum, part, title in SLIDE_CATALOG if part == 1
    )
    p2_grid_items = "".join(
        f'<button type="button" class="gm-card gm-p2" data-goto="{snum}"><span class="gmc-num">{snum:02d}</span><span class="gmc-title">{html.escape(title)}</span></button>'
        for snum, part, title in SLIDE_CATALOG if part == 2
    )

    slides_html = "\n".join(slides)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Full Graduation Defense — Lightweight OWASP Top 10 Vulnerability Scanner (SAD + v1.0.0)</title>
<style>
  :root {{
    --navy: #0F172A;
    --navy-mid: #1E293B;
    --teal: #0D9488;
    --teal-bright: #14B8A6;
    --teal-light: #5EEAD4;
    --teal-soft: #F0FDFA;
    --emerald: #10B981;
    --sky: #0284C7;
    --green: #16A34A;
    --green-dark: #15803D;
    --green-soft: #F0FDF4;
    --amber: #D97706;
    --amber-dark: #B45309;
    --amber-soft: #FFFBEB;
    --red: #DC2626;
    --red-soft: #FEF2F2;
    --slate: #334155;
    --muted: #64748B;
    --border: #CBD5E1;
    --bg-light: #F8FAFC;
    --white: #FFFFFF;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, 'Helvetica Neue', Arial, sans-serif;
    background: #0B1120;
    color: var(--navy);
    overflow: hidden;
  }}

  .deck-stage {{
    width: 100vw;
    height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
  }}

  .slide {{
    display: none;
    width: 1280px;
    height: 720px;
    position: relative;
    overflow: hidden;
    flex-direction: column;
    box-shadow: 0 24px 70px rgba(0, 0, 0, 0.55);
    flex-shrink: 0;
  }}
  .slide.active {{ display: flex; }}
  .slide-dark {{ background: var(--navy); color: var(--white); }}
  .slide-light {{ background: var(--white); color: var(--navy); }}

  /* ---- Dark Cover & Section Slides ---- */
  .cover-bg-grid {{
    position: absolute; inset: 0;
    background-image:
      radial-gradient(circle at 86% 16%, rgba(20, 184, 166, 0.17), transparent 46%),
      radial-gradient(circle at 12% 88%, rgba(2, 132, 199, 0.14), transparent 44%),
      linear-gradient(rgba(148, 163, 184, 0.05) 1px, transparent 1px),
      linear-gradient(90deg, rgba(148, 163, 184, 0.05) 1px, transparent 1px);
    background-size: 100% 100%, 100% 100%, 40px 40px, 40px 40px;
    pointer-events: none;
  }}
  .cover-accent-bar {{
    position: absolute; left: 0; top: 0; bottom: 0; width: 12px;
    background: linear-gradient(180deg, var(--teal-bright), var(--sky));
  }}
  .cover-content {{
    position: relative; z-index: 1;
    flex: 1; display: flex; flex-direction: column; justify-content: space-between;
    padding: 40px 58px 36px 68px;
  }}
  .cover-pill {{
    display: inline-block; padding: 6px 14px; border-radius: 999px;
    background: rgba(20, 184, 166, 0.16); border: 1px solid rgba(94, 234, 212, 0.45);
    color: var(--teal-light); font-size: 11px; font-weight: 700; letter-spacing: 0.07em;
    margin-bottom: 14px;
  }}
  .cover-title {{
    font-size: 46px; font-weight: 800; line-height: 1.08; color: #FFFFFF; letter-spacing: -0.02em;
  }}
  .cover-subtitle {{
    margin-top: 10px; font-size: 17px; color: var(--teal-light); font-weight: 600;
  }}
  .hero-kpi-row {{
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px;
  }}
  .hero-kpi {{
    background: rgba(30, 41, 59, 0.88); border: 1px solid rgba(148, 163, 184, 0.25);
    border-top: 4px solid var(--teal-bright); border-radius: 12px; padding: 15px 18px;
  }}
  .hk-sky {{ border-top-color: #38BDF8; }}
  .hk-green {{ border-top-color: #4ADE80; }}
  .hk-emerald {{ border-top-color: #34D399; }}
  .hk-val {{ font-size: 30px; font-weight: 800; color: #FFFFFF; line-height: 1.1; }}
  .hk-lbl {{ font-size: 13px; font-weight: 700; color: var(--teal-light); margin-top: 4px; }}
  .hk-sub {{ font-size: 11px; color: #CBD5E1; margin-top: 3px; line-height: 1.3; }}

  .cover-bottom-grid {{
    display: grid; grid-template-columns: 390px 1fr; gap: 18px;
  }}
  .cover-meta-card, .cover-team-card {{
    background: rgba(30, 41, 59, 0.86); border: 1px solid rgba(148, 163, 184, 0.25);
    border-radius: 12px; padding: 16px 20px;
  }}
  .cm-label {{ font-size: 10px; font-weight: 800; letter-spacing: 0.08em; color: var(--teal-light); margin-bottom: 6px; }}
  .cm-val {{ font-size: 24px; font-weight: 800; color: #FFFFFF; }}
  .cm-sub {{ font-size: 12px; color: #CBD5E1; margin-top: 3px; }}
  .cm-parts {{ display: flex; gap: 8px; margin-top: 12px; flex-wrap: wrap; }}
  .cmp-p1, .cmp-p2 {{
    font-size: 10.5px; font-weight: 700; padding: 4px 10px; border-radius: 999px;
  }}
  .cmp-p1 {{ background: rgba(20, 184, 166, 0.2); border: 1px solid var(--teal-bright); color: var(--teal-light); }}
  .cmp-p2 {{ background: rgba(16, 185, 129, 0.2); border: 1px solid #34D399; color: #A7F3D0; }}
  .team-chips-grid {{
    display: grid; grid-template-columns: repeat(2, 1fr); gap: 8px 12px;
  }}
  .team-chip {{
    display: flex; justify-content: space-between; align-items: center;
    background: rgba(15, 23, 42, 0.72); border: 1px solid rgba(148, 163, 184, 0.2);
    border-radius: 8px; padding: 6px 10px; font-size: 11.5px;
  }}
  .tc-name {{ color: #F1F5F9; font-weight: 600; }}
  .tc-id {{ color: var(--teal-light); font-family: Consolas, monospace; font-weight: 700; font-size: 11px; }}

  /* ---- Slide 2: Part 1 Section Cover ---- */
  .section-content {{
    position: relative; z-index: 1; flex: 1;
    display: flex; flex-direction: column; justify-content: space-between;
    padding: 42px 58px 40px 68px;
  }}
  .sec-hdr-row {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 24px; }}
  .sec-title {{ font-size: 40px; font-weight: 800; color: #FFFFFF; line-height: 1.12; }}
  .sec-sub {{ margin-top: 8px; font-size: 15px; color: #CBD5E1; max-width: 900px; line-height: 1.4; }}
  .sec-part-badge {{
    padding: 12px 22px; border-radius: 12px; background: rgba(20, 184, 166, 0.18);
    border: 2px solid var(--teal-bright); color: var(--teal-light);
    font-size: 20px; font-weight: 800; letter-spacing: 0.06em; white-space: nowrap;
  }}
  .sec-ch-grid {{
    display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px;
  }}
  .sec-ch-card {{
    background: rgba(30, 41, 59, 0.9); border: 1px solid rgba(148, 163, 184, 0.25);
    border-top: 4px solid var(--teal-bright); border-radius: 12px; padding: 18px 20px;
  }}
  .scc-top {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }}
  .scc-num {{
    background: var(--teal); color: #FFFFFF; font-size: 11px; font-weight: 800;
    padding: 3px 9px; border-radius: 6px; font-family: Consolas, monospace;
  }}
  .scc-title {{ font-size: 16px; font-weight: 700; color: #FFFFFF; }}
  .scc-desc {{ font-size: 12.5px; color: #CBD5E1; line-height: 1.45; }}
  .sec-metrics-strip {{
    display: flex; justify-content: space-between; align-items: center;
    background: rgba(19, 78, 74, 0.55); border: 1px solid rgba(94, 234, 212, 0.4);
    border-radius: 12px; padding: 14px 24px; font-size: 13px; color: #E2E8F0;
  }}
  .sec-metrics-strip strong {{ color: var(--teal-light); font-size: 16px; margin-right: 4px; }}

  /* ---- Standard Slide Header & Footer ---- */
  .slide-header {{
    height: 76px; background: var(--navy); color: #FFFFFF;
    display: flex; align-items: center; padding: 0 28px 0 0; flex-shrink: 0;
  }}
  .header-accent {{ width: 10px; height: 100%; margin-right: 18px; flex-shrink: 0; }}
  .ha-p1 {{ background: var(--teal-bright); }}
  .ha-p2 {{ background: var(--emerald); }}
  .header-titles {{ flex: 1; min-width: 0; }}
  .header-title {{ font-size: 21px; font-weight: 800; color: #FFFFFF; line-height: 1.18; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
  .header-subtitle {{ font-size: 12px; color: #94A3B8; margin-top: 3px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
  .header-badge {{
    padding: 6px 14px; border-radius: 8px; font-size: 10.5px; font-weight: 800; letter-spacing: 0.05em;
    background: var(--navy-mid); white-space: nowrap; margin-left: 14px;
  }}
  .hb-p1 {{ border: 1.5px solid var(--teal-bright); color: var(--teal-light); }}
  .hb-p2 {{ border: 1.5px solid var(--emerald); color: #6EE7B7; }}

  .slide-body {{
    height: 612px; padding: 14px 28px; display: flex; flex-direction: column; overflow: hidden;
  }}

  .slide-footer {{
    height: 32px; background: var(--bg-light); border-top: 1px solid #E2E8F0;
    display: flex; align-items: center; justify-content: space-between;
    padding: 0 28px; font-size: 10.5px; color: var(--muted); flex-shrink: 0;
  }}
  .sf-left {{ display: flex; align-items: center; gap: 8px; }}
  .sf-part {{
    font-size: 9.5px; font-weight: 800; padding: 2px 7px; border-radius: 4px; letter-spacing: 0.04em;
  }}
  .fp-p1 {{ background: #CCFBF1; color: #0F766E; }}
  .fp-p2 {{ background: #DCFCE7; color: #15803D; }}
  .footer-page {{ font-weight: 800; color: var(--navy); font-family: Consolas, monospace; }}

  /* ---- FIXED-BOX INTERACTIVE SVG ZOOM & PAN VIEWER ---- */
  .diagram-viewer {{
    position: relative;
    width: 100%;
    height: 100%;
    min-width: 0;
    min-height: 0;
    background: #FFFFFF;
    border: 1.5px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
    box-shadow: 0 2px 10px rgba(15, 23, 42, 0.05);
    user-select: none;
  }}
  .zv-stage {{
    width: 100%;
    height: 100%;
    overflow: hidden;
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 8px;
    cursor: grab;
    touch-action: none;
    outline: none;
  }}
  .zv-stage.dragging {{ cursor: grabbing; }}
  .zv-canvas {{
    width: 100%;
    height: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    transform-origin: center center;
    transition: transform 0.08s ease-out;
    will-change: transform;
  }}
  .zv-stage.dragging .zv-canvas {{ transition: none; }}
  .zv-svg {{
    width: 100%;
    height: 100%;
    max-width: 100%;
    max-height: 100%;
    display: block;
    pointer-events: none;
  }}
  .zv-fig-pill {{
    position: absolute; top: 8px; left: 8px; z-index: 5;
    background: rgba(15, 23, 42, 0.84); color: var(--teal-light);
    font-size: 10px; font-weight: 800; padding: 3px 9px; border-radius: 6px;
    pointer-events: none; letter-spacing: 0.04em;
  }}
  .zv-toolbar {{
    position: absolute; top: 8px; right: 8px; z-index: 6;
    display: flex; align-items: center; gap: 3px;
    background: rgba(15, 23, 42, 0.84);
    backdrop-filter: blur(8px);
    border: 1px solid rgba(148, 163, 184, 0.3);
    border-radius: 8px; padding: 3px 4px;
    box-shadow: 0 4px 12px rgba(15, 23, 42, 0.25);
  }}
  .zv-btn {{
    background: transparent; border: none; color: #F1F5F9;
    font-size: 11.5px; font-weight: 700; padding: 3px 7px; border-radius: 5px;
    cursor: pointer; line-height: 1.1; font-family: inherit;
    transition: background 0.12s ease, color 0.12s ease;
  }}
  .zv-btn:hover {{ background: rgba(20, 184, 166, 0.28); color: var(--teal-light); }}
  .zv-pct {{
    min-width: 44px; text-align: center; font-family: Consolas, monospace;
    color: var(--teal-light); font-size: 11px;
  }}
  .zv-reset {{ font-size: 10.5px; padding: 3px 7px; border-left: 1px solid rgba(148, 163, 184, 0.25); }}
  .zv-fs {{ font-size: 12.5px; padding: 2px 7px; border-left: 1px solid rgba(148, 163, 184, 0.25); }}
  .zv-hint {{
    position: absolute; bottom: 7px; left: 8px; z-index: 5;
    background: rgba(15, 23, 42, 0.72); color: #E2E8F0;
    font-size: 9.5px; font-weight: 600; padding: 2px 8px; border-radius: 5px;
    pointer-events: none; opacity: 0.88;
  }}

  /* ---- Reusable Slide Layouts ---- */
  .hero-top-body {{ gap: 12px; }}
  .hero-stage-416 {{ height: 418px !important; flex: 0 0 418px; }}
  .hero-stage-424 {{ height: 432px !important; flex: 0 0 432px; }}

  .split-left-760 {{
    display: grid !important; grid-template-columns: 760px 1fr; gap: 16px;
  }}
  .split-left-720 {{
    display: grid !important; grid-template-columns: 720px 1fr; gap: 16px;
  }}
  .split-left-680 {{
    display: grid !important; grid-template-columns: 680px 1fr; gap: 16px;
  }}
  .split-left-640 {{
    display: grid !important; grid-template-columns: 640px 1fr; gap: 16px;
  }}
  .split-tall-520 {{
    display: grid !important; grid-template-columns: 520px 1fr; gap: 16px;
  }}
  .split-tall-480 {{
    display: grid !important; grid-template-columns: 480px 1fr; gap: 16px;
  }}

  .bottom-2-cards {{
    display: grid; grid-template-columns: repeat(2, 1fr); gap: 14px; flex: 1; min-height: 0;
  }}
  .bottom-3-cards {{
    display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; flex: 1; min-height: 0;
  }}
  .bottom-4-tiles {{
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; flex: 1; min-height: 0;
  }}

  /* ---- Shared Cards, Headers & Badges ---- */
  .exec-card {{
    background: var(--bg-light); border: 1px solid #E2E8F0; border-radius: 10px;
    overflow: hidden; display: flex; flex-direction: column;
  }}
  .ec-hdr {{
    padding: 9px 14px; font-size: 12.5px; font-weight: 700; color: #FFFFFF;
    display: flex; align-items: center; justify-content: space-between; gap: 8px;
  }}
  .ec-hdr-sm {{ padding: 7px 12px; font-size: 11.5px; }}
  .ec-hdr-navy {{ background: var(--navy); }}
  .ec-hdr-teal {{ background: var(--teal); }}
  .ec-hdr-slate {{ background: var(--slate); }}
  .ec-hdr code {{ background: rgba(255,255,255,0.14); padding: 1px 5px; border-radius: 4px; font-size: 11px; }}

  .badge-pill {{
    display: inline-block; font-size: 9px; font-weight: 800; padding: 2.5px 8px;
    border-radius: 999px; letter-spacing: 0.04em; white-space: nowrap;
  }}
  .badge-done {{ background: var(--green); color: #FFFFFF; }}
  .badge-red {{ background: var(--red); color: #FFFFFF; }}
  .badge-amber {{ background: var(--amber); color: #FFFFFF; }}
  .badge-teal {{ background: var(--teal); color: #FFFFFF; }}
  .badge-navy-pill {{ background: var(--navy); color: var(--teal-light); }}

  .mini-bullets {{
    list-style: none; padding: 9px 12px; display: flex; flex-direction: column; gap: 7px;
    font-size: 11.5px; line-height: 1.38; color: var(--slate);
  }}
  .mini-bullets li {{ padding-left: 11px; border-left: 3px solid var(--teal); }}
  .mb-red li {{ border-left-color: var(--red); }}
  .mb-navy li {{ border-left-color: var(--navy); }}
  .mini-bullets strong {{ color: var(--navy); }}

  .pipe-tile-4 {{
    background: var(--bg-light); border: 1px solid #E2E8F0; border-top: 3.5px solid var(--teal);
    border-radius: 10px; padding: 10px 12px; display: flex; flex-direction: column; gap: 5px;
  }}
  .pt4-top {{ display: flex; align-items: center; gap: 8px; }}
  .pt-num {{
    background: var(--navy); color: var(--teal-light); font-family: Consolas, monospace;
    font-size: 10.5px; font-weight: 800; padding: 2px 7px; border-radius: 5px;
  }}
  .pt4-title {{ font-size: 12.5px; font-weight: 800; color: var(--navy); }}
  .pt4-desc {{ font-size: 11px; color: var(--slate); line-height: 1.35; }}

  .comp-tile {{
    background: var(--bg-light); border: 1px solid #E2E8F0; border-top: 3.5px solid var(--navy);
    border-radius: 10px; padding: 10px 12px; display: flex; flex-direction: column; gap: 4px;
  }}
  .comp-tile-ast {{ background: var(--green-soft); border-color: #86EFAC; border-top-color: var(--green); }}
  .ct-t {{ font-size: 12px; font-weight: 800; color: var(--navy); }}
  .ct-d {{ font-size: 10.8px; color: var(--slate); line-height: 1.35; }}

  /* ---- Side Columns ---- */
  .side-col-stack {{ display: flex; flex-direction: column; gap: 10px; min-height: 0; }}
  .split-left-720 .side-col-stack .exec-card {{ flex: 1; }}
  .split-left-720 .side-col-stack .mini-bullets {{ gap: 11px; padding: 12px 14px; font-size: 12px; }}
  .split-left-720 .side-col-stack .ssdf-grid {{ flex: 1; padding: 12px 12px; gap: 10px; align-content: stretch; }}
  .side-col-even {{ display: flex; flex-direction: column; gap: 10px; min-height: 0; }}
  .side-col-6 {{ display: flex; flex-direction: column; gap: 8px; min-height: 0; }}
  .side-col-2cards {{ display: flex; flex-direction: column; gap: 14px; justify-content: center; }}
  .side-col-3cards {{ display: flex; flex-direction: column; gap: 12px; min-height: 0; }}
  .side-col-3cards .exec-card {{ flex: 1; }}
  .side-col-3cards .mini-bullets {{ gap: 11px; padding: 13px 14px; font-size: 12.2px; line-height: 1.46; }}

  .side-hdr-bar {{
    background: var(--navy); color: #FFFFFF; font-size: 12px; font-weight: 800;
    padding: 8px 14px; border-radius: 8px; border-left: 5px solid var(--teal-bright);
    flex-shrink: 0;
  }}
  .shb-teal {{ background: var(--teal); border-left-color: var(--navy); }}

  .side-accent-card {{
    flex: 1; background: var(--bg-light); border: 1px solid #E2E8F0; border-left: 4px solid var(--teal);
    border-radius: 9px; padding: 12px 14px; display: flex; flex-direction: column; justify-content: center; gap: 4px;
  }}
  .sac-t {{ font-size: 13px; font-weight: 800; color: var(--navy); }}
  .sac-d {{ font-size: 11.5px; color: var(--slate); line-height: 1.4; }}

  .layer-card {{
    flex: 1; background: var(--bg-light); border: 1px solid #E2E8F0; border-left: 4px solid var(--teal);
    border-radius: 8px; padding: 8px 12px; display: flex; flex-direction: column; justify-content: center;
  }}
  .lc-name {{ font-size: 12px; font-weight: 800; color: var(--navy); }}
  .lc-desc {{ font-size: 10.8px; color: var(--slate); line-height: 1.32; margin-top: 2px; }}

  .layer4-card {{
    flex: 1; background: var(--bg-light); border: 1px solid #E2E8F0; border-left: 4px solid var(--teal);
    border-radius: 9px; padding: 11px 14px; display: flex; align-items: center; gap: 12px;
  }}
  .l4-badge {{
    width: 38px; height: 38px; border-radius: 8px; background: var(--navy); color: var(--teal-light);
    font-family: Consolas, monospace; font-size: 13px; font-weight: 800;
    display: flex; align-items: center; justify-content: center; flex-shrink: 0;
  }}
  .l4-title {{ font-size: 13px; font-weight: 800; color: var(--navy); margin-bottom: 3px; }}
  .l4-desc {{ font-size: 11.2px; color: var(--slate); line-height: 1.38; }}

  .stage6-card {{
    flex: 1; background: var(--bg-light); border: 1px solid #E2E8F0; border-left: 4px solid var(--teal);
    border-radius: 8px; padding: 8px 12px; display: flex; align-items: center; gap: 12px;
  }}
  .st6-num {{
    width: 34px; height: 34px; border-radius: 8px; background: var(--navy); color: var(--teal-light);
    font-family: Consolas, monospace; font-size: 12.5px; font-weight: 800;
    display: flex; align-items: center; justify-content: center; flex-shrink: 0;
  }}
  .st6-title {{ font-size: 12.5px; font-weight: 800; color: var(--navy); }}
  .st6-desc {{ font-size: 11px; color: var(--slate); line-height: 1.32; margin-top: 2px; }}

  /* ---- Slide 5 Use Cases & Scope ---- */
  .uc-list-sm {{ padding: 8px 10px; display: flex; flex-direction: column; gap: 6px; }}
  .uc-row-sm {{ display: flex; align-items: center; gap: 8px; font-size: 11px; color: var(--slate); }}
  .uc-id {{
    background: var(--navy); color: var(--teal-light); font-family: Consolas, monospace;
    font-size: 10px; font-weight: 800; padding: 2px 6px; border-radius: 4px; flex-shrink: 0;
  }}
  .uc-txt strong {{ color: var(--navy); }}
  .owasp-mini-box {{
    background: var(--teal-soft); border: 1px solid #99F6E4; border-radius: 9px; padding: 8px 10px;
  }}
  .ow-hdr-sm {{ font-size: 10.5px; font-weight: 800; color: #0F766E; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.03em; }}
  .ow-grid-2 {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 5px; }}
  .ow-chip-sm {{
    background: #FFFFFF; border: 1px solid #CCFBF1; border-radius: 6px; padding: 4px 6px;
    font-size: 10.5px; display: flex; align-items: center; justify-content: space-between; gap: 3px;
  }}
  .ow-code {{ font-weight: 800; color: var(--navy); font-family: Consolas, monospace; }}
  .ow-cnt {{ color: var(--teal); font-weight: 800; }}
  .scope-mini-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 8px; flex: 1; }}
  .sm-col {{ border-radius: 9px; padding: 8px 10px; font-size: 10.8px; }}
  .sb-in {{ background: var(--green-soft); border: 1px solid #86EFAC; color: #166534; }}
  .sb-out {{ background: var(--red-soft); border: 1px solid #FCA5A5; color: #991B1B; }}
  .sb-hdr {{ font-weight: 800; font-size: 10px; letter-spacing: 0.04em; margin-bottom: 4px; }}
  .sm-col ul {{ padding-left: 15px; display: flex; flex-direction: column; gap: 3px; }}

  /* ---- Slide 6 SRS Tables ---- */
  .srs-body {{ gap: 10px; }}
  .srs-tables {{ display: grid; grid-template-columns: 1fr 1fr; gap: 14px; flex: 1; min-height: 0; }}
  .req-wrap {{
    border: 1px solid #E2E8F0; border-radius: 10px; overflow: hidden; display: flex; flex-direction: column;
    background: #FFFFFF;
  }}
  .req-table {{ width: 100%; border-collapse: collapse; font-size: 10.6px; flex: 1; }}
  .req-table th {{ background: #F1F5F9; color: var(--navy); text-align: left; padding: 6px 8px; font-weight: 800; border-bottom: 1px solid #CBD5E1; }}
  .req-table td {{ padding: 5.5px 8px; border-bottom: 1px solid #E2E8F0; vertical-align: top; line-height: 1.3; }}
  .req-table tr:nth-child(even) {{ background: #F8FAFC; }}
  .rq-id {{ font-family: Consolas, monospace; font-weight: 800; color: var(--teal); white-space: nowrap; }}
  .rq-nm {{ font-weight: 700; color: var(--navy); }}
  .rq-ds {{ color: var(--slate); }}
  .sla-strip {{
    display: flex; justify-content: space-between; align-items: center; gap: 8px;
    background: var(--navy); color: #E2E8F0; border-radius: 9px; padding: 9px 14px; font-size: 11.2px;
  }}
  .sla-pill strong {{ color: var(--teal-light); }}

  /* ---- Slide 11 SSDF ---- */
  .ssdf-grid {{ padding: 8px 10px; display: grid; grid-template-columns: 1fr 1fr; gap: 7px; }}
  .ssdf-tile {{
    background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 7px; padding: 7px 9px;
    font-size: 10.5px; color: var(--slate); display: flex; align-items: flex-start; gap: 7px; line-height: 1.32;
  }}
  .ssdf-code {{
    background: var(--teal); color: #FFFFFF; font-family: Consolas, monospace; font-size: 9.5px;
    font-weight: 800; padding: 2px 5px; border-radius: 4px; flex-shrink: 0;
  }}

  /* ---- Slide 17 Resilience ---- */
  .resil-bullets {{
    list-style: none; padding: 14px 16px; display: flex; flex-direction: column; gap: 14px;
    font-size: 13px; line-height: 1.48; color: var(--slate);
  }}
  .resil-bullets li {{ padding-left: 12px; border-left: 4px solid var(--teal); }}
  .resil-bullets strong {{ color: var(--navy); }}

  /* ---- Slide 19 ERD & Endpoints ---- */
  .erd-list, .ep-list {{ padding: 8px 11px; display: flex; flex-direction: column; gap: 6px; }}
  .erd-row, .ep-row {{
    background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 6px; padding: 6px 9px;
    display: flex; flex-direction: column; gap: 2px;
  }}
  .erd-row code, .ep-row code {{ font-family: Consolas, monospace; font-size: 10.5px; font-weight: 800; color: var(--teal); }}
  .erd-row span, .ep-row span {{ font-size: 10.6px; color: var(--slate); }}

  /* ---- Slide 20 ADRs & Validation ---- */
  .adr-val-body {{ display: grid !important; grid-template-columns: 1.18fr 0.82fr; gap: 16px; }}
  .adr-col, .val-col {{ display: flex; flex-direction: column; gap: 10px; min-height: 0; }}
  .adr-list, .val-list {{ display: flex; flex-direction: column; gap: 9px; flex: 1; }}
  .adr-card {{
    flex: 1; background: var(--bg-light); border: 1px solid #E2E8F0; border-left: 4px solid var(--navy);
    border-radius: 9px; padding: 9px 13px; display: flex; align-items: center; gap: 12px;
  }}
  .adr-id {{
    background: var(--navy); color: var(--teal-light); font-family: Consolas, monospace;
    font-size: 11px; font-weight: 800; padding: 5px 8px; border-radius: 6px; flex-shrink: 0;
  }}
  .adr-t {{ font-size: 12.5px; font-weight: 800; color: var(--navy); }}
  .adr-d {{ font-size: 10.8px; color: var(--slate); line-height: 1.34; margin-top: 2px; }}
  .val-tier {{
    flex: 1; border-radius: 10px; padding: 12px 15px; display: flex; flex-direction: column; justify-content: center; gap: 4px;
    border: 1px solid #E2E8F0; background: var(--bg-light); border-left: 5px solid var(--teal);
  }}
  .vt-green {{ background: var(--green-soft); border-color: #86EFAC; border-left-color: var(--green); }}
  .vt-teal {{ background: var(--teal-soft); border-color: #99F6E4; border-left-color: var(--teal); }}
  .vt-navy {{ background: #F1F5F9; border-color: #CBD5E1; border-left-color: var(--navy); }}
  .vt-tag {{ font-size: 9.5px; font-weight: 800; letter-spacing: 0.06em; color: var(--teal); }}
  .vt-green .vt-tag {{ color: var(--green-dark); }}
  .vt-navy .vt-tag {{ color: var(--navy); }}
  .vt-name {{ font-size: 14.5px; font-weight: 800; color: var(--navy); }}
  .vt-desc {{ font-size: 11.2px; color: var(--slate); line-height: 1.38; }}

  /* ---- Slide 21 Part 2 Banner + Roadmap ---- */
  .p2-banner {{
    height: 112px; background: linear-gradient(135deg, #0F172A 0%, #134E4A 100%);
    color: #FFFFFF; display: flex; align-items: center; padding: 0 28px 0 0; flex-shrink: 0;
  }}
  .p2b-accent {{ width: 12px; height: 100%; background: var(--emerald); margin-right: 20px; flex-shrink: 0; }}
  .p2b-text {{ flex: 1; }}
  .p2b-pill {{
    display: inline-block; font-size: 10px; font-weight: 800; letter-spacing: 0.06em;
    color: #A7F3D0; background: rgba(16, 185, 129, 0.2); border: 1px solid #34D399;
    padding: 3px 10px; border-radius: 999px; margin-bottom: 6px;
  }}
  .p2b-title {{ font-size: 25px; font-weight: 800; color: #FFFFFF; line-height: 1.15; }}
  .p2b-stats {{ display: flex; gap: 10px; }}
  .p2bs {{
    background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(148, 163, 184, 0.3);
    border-radius: 9px; padding: 8px 14px; text-align: center; min-width: 96px;
  }}
  .p2bs b {{ display: block; font-size: 19px; color: var(--teal-light); }}
  .p2bs span {{ font-size: 10px; color: #CBD5E1; font-weight: 600; }}
  .p2bs-green b {{ color: #4ADE80; }}
  .p2-rm-body {{ height: 576px !important; gap: 10px; }}
  .growth-strip {{
    background: var(--teal-soft); border: 1px solid #99F6E4; border-left: 5px solid var(--teal);
    border-radius: 8px; padding: 8px 14px; display: flex; align-items: center; justify-content: space-between;
    font-size: 12px; color: var(--navy);
  }}
  .growth-strip code {{ font-family: Consolas, monospace; font-weight: 800; color: #0F766E; }}

  /* ---- Data Tables ---- */
  .table-card {{
    border: 1px solid #CBD5E1; border-radius: 10px; overflow: hidden; background: #FFFFFF;
  }}
  .data-table {{ width: 100%; border-collapse: collapse; }}
  .data-table th {{
    background: var(--navy); color: var(--teal-light); font-size: 11.8px; font-weight: 800;
    text-align: left; padding: 10px 12px;
  }}
  .data-table td {{
    padding: 13.5px 12px; border-bottom: 1px solid #E2E8F0; font-size: 12.4px; color: var(--slate);
  }}
  .data-table tr:last-child td {{ border-bottom: none; }}
  .data-table tr:nth-child(even) {{ background: #F8FAFC; }}
  .rm-ph {{ font-weight: 800; color: var(--navy); white-space: nowrap; }}
  .rm-test {{ font-family: Consolas, monospace; font-weight: 700; color: #0F766E; font-size: 11.4px; }}

  /* ---- Slide 22 Phase 3 17 Checks ---- */
  .p3-body {{ gap: 12px; }}
  .check-matrix {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; flex: 1; min-height: 0; }}
  .p3-body .bottom-4-tiles {{ flex: 0 0 116px; }}
  .chk-list {{ list-style: none; padding: 8px 11px; display: flex; flex-direction: column; gap: 5px; }}
  .chk-list li {{
    display: flex; align-items: center; justify-content: space-between;
    background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 6px; padding: 5px 9px;
  }}
  .chk-list code {{ font-family: Consolas, monospace; font-size: 11.2px; font-weight: 700; color: var(--navy); }}
  .ow-tag {{
    font-family: Consolas, monospace; font-size: 9.8px; font-weight: 800;
    background: #E0F2FE; color: #0369A1; padding: 1.5px 6px; border-radius: 4px;
  }}
  .profile-summary {{
    margin: auto 11px 11px; background: var(--navy); color: #FFFFFF; border-radius: 8px; padding: 11px 12px;
  }}
  .ps-hdr {{ font-size: 9.5px; font-weight: 800; color: var(--teal-light); letter-spacing: 0.06em; margin-bottom: 7px; }}
  .ps-pills {{ display: flex; justify-content: space-between; font-size: 11.5px; margin-bottom: 7px; }}
  .ps-pills span {{ background: var(--navy-mid); padding: 4px 9px; border-radius: 6px; border: 1px solid #334155; }}
  .ps-pills b {{ color: #4ADE80; }}
  .ps-stacks {{ font-size: 11px; color: #CBD5E1; text-align: center; font-weight: 600; }}
  .eng-card {{
    background: var(--bg-light); border: 1px solid #E2E8F0; border-top: 3.5px solid var(--teal);
    border-radius: 9px; padding: 10px 12px;
  }}
  .eng-t {{ font-size: 12px; font-weight: 800; color: var(--navy); margin-bottom: 4px; }}
  .eng-d {{ font-size: 10.8px; color: var(--slate); line-height: 1.36; }}

  /* ---- Slide 23 Phases 4 & 5 ---- */
  .p5-body {{ gap: 14px; }}
  .views-grid-6 {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; flex: 1; }}
  .view-card {{
    background: var(--bg-light); border: 1px solid #E2E8F0; border-top: 4px solid var(--navy);
    border-radius: 10px; padding: 18px 18px; display: flex; flex-direction: column; justify-content: center; gap: 10px;
  }}
  .vc-top {{ display: flex; align-items: center; gap: 10px; }}
  .vc-num {{
    background: var(--teal); color: #FFFFFF; font-family: Consolas, monospace;
    font-size: 13px; font-weight: 800; padding: 4px 9px; border-radius: 6px;
  }}
  .vc-name {{ font-size: 17px; font-weight: 800; color: var(--navy); }}
  .vc-desc {{ font-size: 13.2px; color: var(--slate); line-height: 1.48; }}
  .inv-strip-3 {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; flex: 0 0 116px; }}
  .inv-card {{
    background: var(--navy); color: #FFFFFF; border-radius: 10px; padding: 14px 16px;
    border-left: 5px solid var(--emerald); display: flex; flex-direction: column; justify-content: center;
  }}
  .inv-t {{ font-size: 13px; font-weight: 800; color: var(--teal-light); margin-bottom: 5px; }}
  .inv-d {{ font-size: 11.4px; color: #CBD5E1; line-height: 1.4; }}

  /* ---- Slide 24 Phase 6 VulnBench ---- */
  .p6-body {{ justify-content: space-between; gap: 14px; }}
  .gate-grid-4 {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; }}
  .gate-card {{
    background: var(--green-soft); border: 1.5px solid #86EFAC; border-radius: 10px; padding: 16px 16px;
  }}
  .gc-top {{ display: flex; justify-content: space-between; align-items: center; }}
  .gc-val {{ font-size: 28px; font-weight: 800; color: var(--green-dark); }}
  .gc-lbl {{ font-size: 13px; font-weight: 800; color: var(--navy); margin-top: 4px; }}
  .gc-bar {{ height: 7px; background: #DCFCE7; border-radius: 99px; margin: 9px 0; overflow: hidden; }}
  .gc-fill {{ height: 100%; background: var(--green); border-radius: 99px; }}
  .gc-sub {{ font-size: 11px; color: var(--slate); }}
  .vb-table th {{ padding: 12px 11px; font-size: 12px; }}
  .vb-table td {{ font-family: Consolas, monospace; font-size: 12.6px; padding: 16px 11px; }}
  .vb-table td:first-child {{ font-family: inherit; font-weight: 800; color: var(--navy); }}
  .vb-table tr.row-highlight td {{ background: #DCFCE7 !important; font-weight: 800; color: #14532D; }}
  .p6-bottom-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }}
  .mini-note {{
    background: var(--bg-light); border: 1px solid #CBD5E1; border-left: 5px solid var(--navy);
    border-radius: 9px; padding: 15px 16px;
  }}
  .mn-teal {{ background: var(--teal-soft); border-color: #99F6E4; border-left-color: var(--teal); }}
  .mn-title {{ font-size: 13.5px; font-weight: 800; color: var(--navy); margin-bottom: 6px; }}
  .mn-desc {{ font-size: 12px; color: var(--slate); line-height: 1.46; }}
  .mn-desc code, .mn-title code {{ font-family: Consolas, monospace; font-size: 11.4px; color: #0F766E; font-weight: 700; }}

  /* ---- Slides 25 & 26 Chart Cards ---- */
  .chart-card {{
    background: var(--bg-light); border: 1px solid #E2E8F0; border-top: 4px solid var(--teal);
    border-radius: 10px; padding: 10px 14px;
  }}
  .cc-green {{ background: var(--green-soft); border-color: #86EFAC; border-top-color: var(--green); }}
  .cc-navy {{ border-top-color: var(--navy); }}
  .cc-amber {{ background: var(--amber-soft); border-color: #FCD34D; border-top-color: var(--amber); }}
  .cc-title {{ font-size: 12.5px; font-weight: 800; color: var(--navy); margin-bottom: 4px; }}
  .cc-desc {{ font-size: 11px; color: var(--slate); line-height: 1.38; }}

  /* ---- Slide 27 DX & Boundaries ---- */
  .dx-body {{ justify-content: space-between; gap: 14px; }}
  .dx-table th {{ padding: 12px 13px; font-size: 12.2px; }}
  .dx-table td {{ padding: 15px 13px; font-size: 12.4px; }}
  .dx-dim {{ font-weight: 800; color: var(--navy); }}
  .dx-zap {{ color: #64748B; }}
  .dx-ours {{ color: #0F766E; font-weight: 700; background: #F0FDFA; }}
  .bnd-wrap {{
    background: var(--amber-soft); border: 1.5px solid #FCD34D; border-radius: 10px; padding: 14px 16px;
  }}
  .bnd-hdr {{ font-size: 11px; font-weight: 800; color: var(--amber-dark); letter-spacing: 0.05em; margin-bottom: 10px; }}
  .bnd-grid-3 {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; }}
  .bnd-card {{ background: #FFFFFF; border: 1px solid #FDE68A; border-radius: 8px; padding: 13px 14px; }}
  .bnd-t {{ font-size: 12.8px; font-weight: 800; color: var(--navy); margin-bottom: 5px; }}
  .bnd-d {{ font-size: 11.6px; color: var(--slate); line-height: 1.44; }}

  /* ---- Slide 28 Phase 7 Self-Scan ---- */
  .p7-body {{ justify-content: space-between; gap: 14px; }}
  .dogfood-bar {{
    background: var(--navy); color: #E2E8F0; border-radius: 9px; padding: 11px 18px;
    display: flex; align-items: center; justify-content: space-between; font-size: 12.8px;
  }}
  .dogfood-bar code {{ color: var(--teal-light); font-family: Consolas, monospace; font-weight: 700; }}
  .ba-row {{ display: grid; grid-template-columns: 1fr 44px 1fr; gap: 10px; align-items: center; }}
  .ba-card {{ border-radius: 11px; padding: 18px 20px; height: 256px; display: flex; flex-direction: column; justify-content: center; gap: 12px; }}
  .ba-before {{ background: var(--amber-soft); border: 2px solid var(--amber); }}
  .ba-after {{ background: var(--green-soft); border: 2px solid var(--green); }}
  .ba-top {{ display: flex; justify-content: space-between; align-items: center; }}
  .ba-tag {{ font-size: 10.8px; font-weight: 800; padding: 4px 10px; border-radius: 6px; }}
  .tag-amber {{ background: var(--amber); color: #FFFFFF; }}
  .tag-green {{ background: var(--green); color: #FFFFFF; }}
  .ba-score {{ font-size: 26px; font-weight: 800; }}
  .sc-amber {{ color: var(--amber-dark); }}
  .sc-green {{ color: var(--green-dark); }}
  .ba-list {{ padding-left: 18px; display: flex; flex-direction: column; gap: 10px; font-size: 12.8px; color: var(--slate); line-height: 1.45; }}
  .ba-list code {{ font-family: Consolas, monospace; font-size: 11.8px; color: var(--navy); font-weight: 700; }}
  .ba-arrow {{ font-size: 34px; font-weight: 800; color: var(--teal); text-align: center; }}
  .ha-grid-5 {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 11px; flex: 0 0 218px; }}
  .ha-item {{
    background: var(--bg-light); border: 1px solid #CBD5E1; border-top: 4px solid var(--teal);
    border-radius: 9px; padding: 14px 13px; display: flex; flex-direction: column; justify-content: flex-start;
  }}
  .ha-t {{ font-size: 12.2px; font-weight: 800; color: var(--navy); margin-bottom: 7px; }}
  .ha-d {{ font-size: 11.4px; color: var(--slate); line-height: 1.46; }}

  /* ---- Slide 29 Docker + 88-Test Pyramid + CI ---- */
  .split-p29 {{ display: grid !important; grid-template-columns: 740px 1fr; gap: 16px; }}
  .left-p29 {{ display: flex; flex-direction: column; gap: 10px; min-height: 0; }}
  .p29-fig {{ flex: 1; min-height: 0; }}
  .ci-card {{ flex-shrink: 0; }}
  .ci-grid-3 {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; padding: 8px 10px; }}
  .ci-col-item {{
    background: #FFFFFF; border: 1px solid #CBD5E1; border-left: 3.5px solid var(--green);
    border-radius: 6px; padding: 6px 8px; display: flex; flex-direction: column; gap: 2px;
  }}
  .ci-job {{ font-family: Consolas, monospace; font-size: 10.5px; font-weight: 800; color: var(--navy); }}
  .ci-desc {{ font-size: 10px; color: var(--slate); }}
  .right-p29 {{ display: flex; flex-direction: column; gap: 10px; min-height: 0; }}
  .pass-banner {{
    background: var(--green-soft); border: 2px solid var(--green); border-radius: 10px;
    padding: 10px 14px; display: flex; align-items: center; gap: 12px;
  }}
  .pb-icon {{
    width: 38px; height: 38px; border-radius: 9px; background: var(--green); color: #FFFFFF;
    font-size: 20px; font-weight: 800; display: flex; align-items: center; justify-content: center; flex-shrink: 0;
  }}
  .pb-title {{ font-size: 17px; font-weight: 800; color: var(--green-dark); }}
  .pb-sub {{ font-size: 11px; color: var(--slate); font-family: Consolas, monospace; font-weight: 700; }}
  .pyramid-card {{ flex: 1; }}
  .tier-list {{ padding: 10px 12px; display: flex; flex-direction: column; gap: 11px; flex: 1; }}
  .tr-top {{ display: flex; justify-content: space-between; font-size: 11.5px; font-weight: 800; color: var(--navy); }}
  .tr-cnt {{ font-family: Consolas, monospace; color: var(--teal); }}
  .tr-bar-wrap {{ height: 9px; background: #E2E8F0; border-radius: 99px; margin: 4px 0; overflow: hidden; }}
  .tr-bar {{ height: 100%; border-radius: 99px; }}
  .tb-teal {{ background: var(--teal); }}
  .tb-navy {{ background: var(--navy); }}
  .tb-green {{ background: var(--green); }}
  .tr-file {{ font-family: Consolas, monospace; font-size: 10px; color: var(--muted); }}
  .pyramid-sum {{
    padding: 8px 12px; background: #F1F5F9; border-top: 1px solid #E2E8F0; font-size: 11px; color: var(--navy);
  }}
  .pyramid-sum code {{ font-family: Consolas, monospace; font-weight: 800; color: var(--green-dark); }}

  /* ---- Slide 30 Closing ---- */
  .closing-content {{
    position: relative; z-index: 1; flex: 1;
    display: flex; flex-direction: column; justify-content: space-between;
    padding: 26px 46px 26px 56px;
  }}
  .closing-header {{ display: flex; justify-content: space-between; align-items: center; gap: 16px; }}
  .closing-title {{ font-size: 28px; font-weight: 800; color: #FFFFFF; }}
  .repo-chip {{
    background: rgba(30, 41, 59, 0.9); border: 1px solid var(--teal-bright); border-radius: 9px;
    padding: 8px 14px; text-align: right;
  }}
  .rc-lbl {{ font-size: 9px; font-weight: 800; color: var(--teal-light); letter-spacing: 0.08em; }}
  .rc-url {{ font-family: Consolas, monospace; font-size: 11px; color: #FFFFFF; margin-top: 2px; }}

  .demo-bar-5 {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 9px; }}
  .demo-chip {{
    background: rgba(30, 41, 59, 0.88); border: 1px solid rgba(148, 163, 184, 0.25);
    border-top: 3px solid var(--teal-bright); border-radius: 8px; padding: 8px 10px;
  }}
  .dc-top {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px; }}
  .dc-num {{ background: var(--teal); color: #FFFFFF; font-family: Consolas, monospace; font-size: 10px; font-weight: 800; padding: 1px 6px; border-radius: 4px; }}
  .dc-tm {{ font-family: Consolas, monospace; font-size: 9.5px; color: var(--teal-light); font-weight: 700; }}
  .dc-title {{ font-size: 11.5px; font-weight: 800; color: #FFFFFF; margin-bottom: 3px; }}
  .dc-desc {{ font-size: 10px; color: #CBD5E1; line-height: 1.3; }}

  .roster-table {{ width: 100%; border-collapse: collapse; border-radius: 9px; overflow: hidden; }}
  .roster-table th {{ background: #134E4A; color: var(--teal-light); text-align: left; padding: 7px 11px; font-size: 11px; font-weight: 800; }}
  .roster-table td {{ padding: 6.5px 11px; font-size: 11.2px; border-bottom: 1px solid rgba(148, 163, 184, 0.16); }}
  .roster-table tr:nth-child(odd) td {{ background: rgba(30, 41, 59, 0.78); }}
  .roster-table tr:nth-child(even) td {{ background: rgba(22, 32, 50, 0.78); }}
  .rt-name {{ color: #FFFFFF; font-weight: 700; }}
  .rt-id {{ color: var(--teal-light); font-family: Consolas, monospace; font-weight: 800; }}
  .rt-mod {{ color: #CBD5E1; }}

  .approval-banner {{
    background: rgba(19, 78, 74, 0.8); border: 1.5px solid var(--teal-bright); border-radius: 10px;
    padding: 12px 18px; display: flex; justify-content: space-between; align-items: center; gap: 16px;
  }}
  .ab-title {{ font-size: 15.5px; font-weight: 800; color: #FFFFFF; }}
  .ab-sub {{ font-size: 11px; color: #CBD5E1; margin-top: 2px; }}
  .qa-badge {{
    background: var(--teal-bright); color: var(--navy); font-size: 18px; font-weight: 900;
    padding: 9px 22px; border-radius: 9px; white-space: nowrap;
  }}

  /* ---- UNIFIED NAVIGATION HUD ---- */
  .hud {{
    position: fixed; bottom: 14px; left: 50%; transform: translateX(-50%); z-index: 100;
    display: flex; align-items: center; gap: 6px;
    background: rgba(15, 23, 42, 0.9); backdrop-filter: blur(10px);
    border: 1px solid rgba(148, 163, 184, 0.3); border-radius: 999px;
    padding: 6px 12px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.45);
  }}
  .hud button {{
    background: transparent; border: 1px solid transparent; color: #E2E8F0;
    font-size: 12px; font-weight: 700; padding: 5px 11px; border-radius: 999px;
    cursor: pointer; font-family: inherit; transition: all 0.14s ease;
  }}
  .hud button:hover {{ background: rgba(255, 255, 255, 0.12); color: #FFFFFF; }}
  .hud .hud-part.active-p1 {{
    background: rgba(20, 184, 166, 0.25); border-color: var(--teal-bright); color: var(--teal-light);
  }}
  .hud .hud-part.active-p2 {{
    background: rgba(16, 185, 129, 0.25); border-color: var(--emerald); color: #6EE7B7;
  }}
  .hud-sep {{ width: 1px; height: 18px; background: rgba(148, 163, 184, 0.3); margin: 0 2px; }}
  .hud-counter {{
    font-family: Consolas, monospace; font-size: 12px; font-weight: 800; color: var(--teal-light);
    min-width: 72px; text-align: center;
  }}

  /* ---- GROUPED GRID OVERVIEW MODAL ---- */
  .grid-modal {{
    position: fixed; inset: 0; z-index: 200;
    background: rgba(11, 17, 32, 0.95); backdrop-filter: blur(8px);
    display: none; flex-direction: column; padding: 24px 36px; overflow-y: auto;
  }}
  .grid-modal.open {{ display: flex; }}
  .gm-top {{
    display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px;
  }}
  .gm-top h2 {{ color: #FFFFFF; font-size: 20px; font-weight: 800; }}
  .gm-close {{
    background: var(--navy-mid); border: 1px solid #475569; color: #FFFFFF;
    padding: 7px 14px; border-radius: 8px; font-weight: 700; cursor: pointer;
  }}
  .gm-group-hdr {{
    font-size: 12px; font-weight: 800; letter-spacing: 0.06em; text-transform: uppercase;
    margin: 12px 0 10px; padding: 6px 12px; border-radius: 7px; display: inline-block;
  }}
  .ggh-p1 {{ background: rgba(20, 184, 166, 0.2); color: var(--teal-light); border-left: 4px solid var(--teal-bright); }}
  .ggh-p2 {{ background: rgba(16, 185, 129, 0.2); color: #6EE7B7; border-left: 4px solid var(--emerald); }}
  .gm-grid {{
    display: grid; grid-template-columns: repeat(auto-fill, minmax(230px, 1fr)); gap: 10px; margin-bottom: 14px;
  }}
  .gm-card {{
    background: var(--navy-mid); border: 1px solid #334155; border-radius: 9px; padding: 11px 13px;
    display: flex; align-items: center; gap: 10px; text-align: left; cursor: pointer;
    color: #F1F5F9; font-family: inherit; transition: border-color 0.14s, transform 0.12s;
  }}
  .gm-card:hover {{ border-color: var(--teal-bright); transform: translateY(-1px); }}
  .gm-card.current {{ border-color: #4ADE80; background: rgba(22, 163, 74, 0.22); }}
  .gmc-num {{
    font-family: Consolas, monospace; font-size: 13px; font-weight: 800;
    padding: 4px 8px; border-radius: 6px; background: var(--navy); color: var(--teal-light); flex-shrink: 0;
  }}
  .gm-p2 .gmc-num {{ color: #6EE7B7; }}
  .gmc-title {{ font-size: 12px; font-weight: 600; line-height: 1.3; }}

  /* ---- FULLSCREEN INTERACTIVE DIAGRAM MODAL ---- */
  .zv-modal {{
    position: fixed; inset: 0; z-index: 300;
    background: rgba(9, 13, 24, 0.94); backdrop-filter: blur(8px);
    display: none; flex-direction: column; padding: 18px 24px;
  }}
  .zv-modal.open {{ display: flex; }}
  .zvm-bar {{
    display: flex; align-items: center; justify-content: space-between; gap: 14px; margin-bottom: 12px;
  }}
  .zvm-title {{ color: #FFFFFF; font-size: 15px; font-weight: 800; }}
  .zvm-controls {{ display: flex; align-items: center; gap: 6px; }}
  .zvm-controls button {{
    background: var(--navy-mid); border: 1px solid #475569; color: #FFFFFF;
    padding: 6px 12px; border-radius: 7px; font-size: 12.5px; font-weight: 700; cursor: pointer;
  }}
  .zvm-controls button:hover {{ border-color: var(--teal-bright); color: var(--teal-light); }}
  .zvm-pct {{ font-family: Consolas, monospace; color: var(--teal-light) !important; min-width: 54px; }}
  .zvm-stage-wrap {{
    flex: 1; background: #FFFFFF; border-radius: 12px; overflow: hidden; position: relative;
    border: 2px solid var(--teal-bright);
  }}
  .zvm-stage {{
    width: 100%; height: 100%; overflow: hidden; display: flex; align-items: center; justify-content: center;
    padding: 16px; cursor: grab; touch-action: none;
  }}
  .zvm-stage.dragging {{ cursor: grabbing; }}
  .zvm-canvas {{
    width: 100%; height: 100%; display: flex; align-items: center; justify-content: center;
    transform-origin: center center; transition: transform 0.08s ease-out;
  }}
  .zvm-stage.dragging .zvm-canvas {{ transition: none; }}

  /* ---- PRINT / PDF EXPORT (EXACT 30 PAGES 16:9, ZERO HUD/TOOLBARS) ---- */
  @page {{ size: 13.3333in 7.5in; margin: 0; }}
  @media print {{
    html, body {{
      width: 13.3333in !important; height: auto !important;
      background: #FFFFFF !important; overflow: visible !important;
      -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important;
    }}
    .hud, .grid-modal, .zv-modal, .zv-toolbar, .zv-hint {{ display: none !important; }}
    .deck-stage {{
      display: block !important; width: 13.3333in !important; height: auto !important;
    }}
    .slide {{
      display: flex !important;
      width: 1280px !important; height: 720px !important;
      transform: none !important; box-shadow: none !important;
      page-break-after: always; break-after: page;
    }}
    .slide:last-child {{ page-break-after: auto; break-after: auto; }}
    .zv-canvas {{ transform: none !important; }}
  }}
</style>
</head>
<body>
  <main class="deck-stage" id="deckStage">
    {slides_html}
  </main>

  <nav class="hud" aria-label="Presentation Navigation">
    <button type="button" class="hud-part" id="btnPart1" title="Jump to Part 1: SAD (Slide 1)">Part 1: SAD (1&ndash;20)</button>
    <button type="button" class="hud-part" id="btnPart2" title="Jump to Part 2: Technical (Slide 21)">Part 2: Technical (21&ndash;30)</button>
    <span class="hud-sep"></span>
    <button type="button" id="btnPrev" title="Previous Slide (Left Arrow)">&larr; Prev</button>
    <span class="hud-counter" id="counter">01 / {TOTAL_SLIDES:02d}</span>
    <button type="button" id="btnNext" title="Next Slide (Right Arrow)">Next &rarr;</button>
    <span class="hud-sep"></span>
    <button type="button" id="btnGrid" title="Slide Overview Grid (G)">Grid (G)</button>
    <button type="button" id="btnFs" title="Toggle Fullscreen (F)">Fullscreen (F)</button>
  </nav>

  <div class="grid-modal" id="gridModal" role="dialog" aria-label="Slide Overview">
    <div class="gm-top">
      <h2>Full Graduation Defense &mdash; 30-Slide Overview</h2>
      <button type="button" class="gm-close" id="btnGridClose">Close (Esc)</button>
    </div>
    <div class="gm-group-hdr ggh-p1">Part 1: Software Architecture Document (SAD) &mdash; Slides 1&ndash;20</div>
    <div class="gm-grid">{p1_grid_items}</div>
    <div class="gm-group-hdr ggh-p2">Part 2: Technical Implementation &amp; Empirical Results (v1.0.0) &mdash; Slides 21&ndash;30</div>
    <div class="gm-grid">{p2_grid_items}</div>
  </div>

  <div class="zv-modal" id="zvModal" role="dialog" aria-label="Fullscreen Interactive Diagram Viewer">
    <div class="zvm-bar">
      <div class="zvm-title" id="zvmTitle">Diagram Viewer</div>
      <div class="zvm-controls">
        <button type="button" id="zvmOut" title="Zoom Out (-)">&minus;</button>
        <button type="button" class="zvm-pct" id="zvmPct" title="Reset (0)">100%</button>
        <button type="button" id="zvmIn" title="Zoom In (+)">+</button>
        <button type="button" id="zvmReset" title="Reset View (0)">Reset</button>
        <button type="button" id="zvmClose" title="Close (Esc)">Close (Esc)</button>
      </div>
    </div>
    <div class="zvm-stage-wrap">
      <div class="zvm-stage" id="zvmStage">
        <div class="zvm-canvas" id="zvmCanvas"></div>
      </div>
    </div>
  </div>

  <script>
    (function() {{
      const slides = Array.from(document.querySelectorAll('.slide'));
      const counter = document.getElementById('counter');
      const btnPart1 = document.getElementById('btnPart1');
      const btnPart2 = document.getElementById('btnPart2');
      const gridModal = document.getElementById('gridModal');
      const gridCards = Array.from(gridModal.querySelectorAll('.gm-card'));
      const zvModal = document.getElementById('zvModal');
      const zvmTitle = document.getElementById('zvmTitle');
      const zvmStage = document.getElementById('zvmStage');
      const zvmCanvas = document.getElementById('zvmCanvas');
      const zvmPct = document.getElementById('zvmPct');

      let idx = 0;
      let slideScale = 1.0;

      // ---- Slide Fit & Navigation ----
      function fitSlide() {{
        slideScale = Math.min(window.innerWidth / 1280, window.innerHeight / 720) * 0.96;
        slides.forEach(s => {{ s.style.transform = 'scale(' + slideScale.toFixed(4) + ')'; }});
      }}

      function show(n) {{
        idx = Math.max(0, Math.min(slides.length - 1, n));
        slides.forEach((s, i) => s.classList.toggle('active', i === idx));
        const num = idx + 1;
        counter.textContent = String(num).padStart(2, '0') + ' / ' + String(slides.length).padStart(2, '0');
        const isP1 = num <= 20;
        btnPart1.classList.toggle('active-p1', isP1);
        btnPart2.classList.toggle('active-p2', !isP1);
        gridCards.forEach(c => c.classList.toggle('current', Number(c.dataset.goto) === num));
        fitSlide();
      }}

      // ---- Interactive Fixed-Box Zoom & Pan Controller ----
      function attachZoomPan(stageEl, canvasEl, pctEl, getCoordScale) {{
        const state = {{ zoom: 1.0, tx: 0, ty: 0, dragging: false, sx: 0, sy: 0, stx: 0, sty: 0 }};

        function apply() {{
          canvasEl.style.transform = 'translate(' + state.tx.toFixed(1) + 'px, ' + state.ty.toFixed(1) + 'px) scale(' + state.zoom.toFixed(3) + ')';
          if (pctEl) pctEl.textContent = Math.round(state.zoom * 100) + '%';
        }}

        function setZoom(nextZoom) {{
          state.zoom = Math.max(0.5, Math.min(5.0, Math.round(nextZoom * 100) / 100));
          if (state.zoom <= 1.0 && Math.abs(state.tx) < 2 && Math.abs(state.ty) < 2) {{
            state.tx = 0; state.ty = 0;
          }}
          apply();
        }}

        function reset() {{
          state.zoom = 1.0; state.tx = 0; state.ty = 0;
          apply();
        }}

        stageEl.addEventListener('wheel', (e) => {{
          e.preventDefault();
          e.stopPropagation();
          const step = e.deltaY < 0 ? 0.25 : -0.25;
          setZoom(state.zoom + step);
        }}, {{ passive: false }});

        stageEl.addEventListener('pointerdown', (e) => {{
          if (e.button !== 0) return;
          e.preventDefault();
          state.dragging = true;
          state.sx = e.clientX;
          state.sy = e.clientY;
          state.stx = state.tx;
          state.sty = state.ty;
          stageEl.classList.add('dragging');
          stageEl.setPointerCapture(e.pointerId);
        }});

        stageEl.addEventListener('pointermove', (e) => {{
          if (!state.dragging) return;
          const sc = getCoordScale();
          state.tx = state.stx + (e.clientX - state.sx) / sc;
          state.ty = state.sty + (e.clientY - state.sy) / sc;
          apply();
        }});

        function endDrag(e) {{
          if (!state.dragging) return;
          state.dragging = false;
          stageEl.classList.remove('dragging');
          try {{ stageEl.releasePointerCapture(e.pointerId); }} catch (_) {{}}
        }}
        stageEl.addEventListener('pointerup', endDrag);
        stageEl.addEventListener('pointercancel', endDrag);

        stageEl.addEventListener('dblclick', (e) => {{
          e.preventDefault();
          e.stopPropagation();
          if (Math.abs(state.zoom - 1.0) < 0.05) {{
            state.zoom = 2.2;
          }} else {{
            state.zoom = 1.0; state.tx = 0; state.ty = 0;
          }}
          apply();
        }});

        apply();
        return {{
          zoomIn: () => setZoom(state.zoom + 0.25),
          zoomOut: () => setZoom(state.zoom - 0.25),
          reset,
        }};
      }}

      // Attach modal controller
      const modalCtrl = attachZoomPan(zvmStage, zvmCanvas, zvmPct, () => 1.0);
      document.getElementById('zvmIn').onclick = modalCtrl.zoomIn;
      document.getElementById('zvmOut').onclick = modalCtrl.zoomOut;
      document.getElementById('zvmReset').onclick = modalCtrl.reset;
      zvmPct.onclick = modalCtrl.reset;
      document.getElementById('zvmClose').onclick = () => {{ zvModal.classList.remove('open'); zvmCanvas.innerHTML = ''; }};

      function openDiagramModal(viewer) {{
        const caption = viewer.dataset.caption || 'Diagram Viewer';
        const svg = viewer.querySelector('svg');
        if (!svg) return;
        // Clone SVG and prefix internal IDs with "mdl_" to keep zero DOM ID collisions
        let markup = svg.outerHTML;
        const idMatches = new Set();
        markup.replace(/\\bid="([^"]+)"/g, (_, id) => {{ idMatches.add(id); return _; }});
        Array.from(idMatches).sort((a, b) => b.length - a.length).forEach(oldId => {{
          const newId = 'mdl_' + oldId;
          markup = markup.split('id="' + oldId + '"').join('id="' + newId + '"');
          markup = markup.split('url(#' + oldId + ')').join('url(#' + newId + ')');
          markup = markup.split('href="#' + oldId + '"').join('href="#' + newId + '"');
        }});
        zvmTitle.textContent = caption;
        zvmCanvas.innerHTML = markup;
        modalCtrl.reset();
        zvModal.classList.add('open');
      }}

      // Attach in-slide viewers
      const viewerMap = new Map();
      document.querySelectorAll('.diagram-viewer').forEach(viewer => {{
        const stageEl = viewer.querySelector('.zv-stage');
        const canvasEl = viewer.querySelector('.zv-canvas');
        const pctEl = viewer.querySelector('.zv-pct');
        const ctrl = attachZoomPan(stageEl, canvasEl, pctEl, () => slideScale || 1.0);
        viewer.querySelector('.zv-in').onclick = (e) => {{ e.stopPropagation(); ctrl.zoomIn(); }};
        viewer.querySelector('.zv-out').onclick = (e) => {{ e.stopPropagation(); ctrl.zoomOut(); }};
        viewer.querySelector('.zv-reset').onclick = (e) => {{ e.stopPropagation(); ctrl.reset(); }};
        pctEl.onclick = (e) => {{ e.stopPropagation(); ctrl.reset(); }};
        viewer.querySelector('.zv-fs').onclick = (e) => {{ e.stopPropagation(); openDiagramModal(viewer); }};
        const parentSlide = viewer.closest('.slide');
        if (parentSlide) viewerMap.set(parentSlide, ctrl);
      }});

      // HUD buttons
      document.getElementById('btnPrev').onclick = () => show(idx - 1);
      document.getElementById('btnNext').onclick = () => show(idx + 1);
      btnPart1.onclick = () => show(0);
      btnPart2.onclick = () => show(20);
      document.getElementById('btnGrid').onclick = () => gridModal.classList.toggle('open');
      document.getElementById('btnGridClose').onclick = () => gridModal.classList.remove('open');
      gridCards.forEach(c => c.addEventListener('click', () => {{
        gridModal.classList.remove('open');
        show(Number(c.dataset.goto) - 1);
      }}));
      document.getElementById('btnFs').onclick = () => {{
        if (!document.fullscreenElement) document.documentElement.requestFullscreen();
        else document.exitFullscreen();
      }};

      // Keyboard shortcuts
      window.addEventListener('keydown', (e) => {{
        if (e.key === 'Escape') {{
          if (zvModal.classList.contains('open')) {{ zvModal.classList.remove('open'); zvmCanvas.innerHTML = ''; return; }}
          if (gridModal.classList.contains('open')) {{ gridModal.classList.remove('open'); return; }}
          return;
        }}
        if (zvModal.classList.contains('open')) {{
          if (e.key === '+' || e.key === '=') {{ e.preventDefault(); modalCtrl.zoomIn(); }}
          else if (e.key === '-' || e.key === '_') {{ e.preventDefault(); modalCtrl.zoomOut(); }}
          else if (e.key === '0') {{ e.preventDefault(); modalCtrl.reset(); }}
          return;
        }}
        if (e.key.toLowerCase() === 'g') {{ e.preventDefault(); gridModal.classList.toggle('open'); return; }}
        if (gridModal.classList.contains('open')) return;

        const activeCtrl = viewerMap.get(slides[idx]);
        if (activeCtrl && (e.key === '+' || e.key === '=')) {{ e.preventDefault(); activeCtrl.zoomIn(); return; }}
        if (activeCtrl && (e.key === '-' || e.key === '_')) {{ e.preventDefault(); activeCtrl.zoomOut(); return; }}
        if (activeCtrl && e.key === '0') {{ e.preventDefault(); activeCtrl.reset(); return; }}

        if (e.key === 'ArrowRight' || e.key === ' ' || e.key === 'PageDown') {{ e.preventDefault(); show(idx + 1); }}
        else if (e.key === 'ArrowLeft' || e.key === 'PageUp') {{ e.preventDefault(); show(idx - 1); }}
        else if (e.key === 'Home') {{ e.preventDefault(); show(0); }}
        else if (e.key === 'End') {{ e.preventDefault(); show(slides.length - 1); }}
        else if (e.key.toLowerCase() === 'f') {{ document.getElementById('btnFs').click(); }}
      }});

      window.addEventListener('resize', fitSlide);
      show(0);
    }})();
  </script>
</body>
</html>
"""


# =============================================================================
# 3. PDF BUILDER (HEADLESS CHROME, 100% OFFLINE)
# =============================================================================


def build_pdf(html_path: Path, pdf_path: Path) -> None:
    if not CHROME_PATH.exists():
        raise FileNotFoundError(f"Headless Chrome not found at {CHROME_PATH}")
    uri = html_path.resolve().as_uri()
    tmp_dir = Path(tempfile.mkdtemp(prefix="full_defense_pdf_"))
    try:
        profile_dir = tmp_dir / "browser_profile"
        cmd = [
            str(CHROME_PATH),
            "--headless",
            "--disable-gpu",
            "--no-sandbox",
            "--disable-crash-reporter",
            "--disable-extensions",
            "--disable-background-networking",
            f"--user-data-dir={profile_dir}",
            "--no-pdf-header-footer",
            f"--print-to-pdf={pdf_path.resolve()}",
            uri,
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=180, check=False)
        if res.returncode != 0 or not pdf_path.exists():
            raise RuntimeError(f"Chrome PDF export failed (rc={res.returncode}): {res.stderr[:500]}")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# =============================================================================
# 4. OOXML PPTX BUILDER (PURE PYTHON STDLIB zipfile + XML + PIL — 30 SLIDES)
# =============================================================================

SLIDE_W = 12192000  # 13.3333 in
SLIDE_H = 6858000   # 7.5 in

NAVY = "0F172A"
NAVY_MID = "1E293B"
TEAL = "0D9488"
TEAL_BRIGHT = "14B8A6"
TEAL_LIGHT = "5EEAD4"
TEAL_SOFT = "F0FDFA"
EMERALD = "10B981"
SKY = "0284C7"
SLATE = "334155"
MUTED = "64748B"
BORDER = "CBD5E1"
BG_LIGHT = "F8FAFC"
WHITE = "FFFFFF"
GREEN = "16A34A"
GREEN_DARK = "15803D"
GREEN_SOFT = "F0FDF4"
GREEN_LIGHT = "86EFAC"
AMBER = "D97706"
AMBER_DARK = "B45309"
AMBER_SOFT = "FFFBEB"
RED = "DC2626"
RED_SOFT = "FEF2F2"


def px(val: float) -> int:
    return int(round(val * 9525))


def esc(text: str) -> str:
    return html.escape(text, quote=True)


class SlideBuilder:
    def __init__(self, slide_num: int, bg_hex: str = WHITE) -> None:
        self.slide_num = slide_num
        self.bg_hex = bg_hex
        self.shapes: list[str] = []
        self.next_id = 2
        self.rels: list[tuple[str, str, str]] = [
            (
                "rId1",
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout",
                "../slideLayouts/slideLayout1.xml",
            )
        ]

    def _alloc_id(self) -> int:
        i = self.next_id
        self.next_id += 1
        return i

    def add_rect(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        fill: str | None = None,
        line: str | None = None,
        line_pt: float = 1.0,
        rounded: bool = False,
        name: str = "Rect",
    ) -> None:
        sid = self._alloc_id()
        geom = "roundRect" if rounded else "rect"
        fill_xml = f'<a:solidFill><a:srgbClr val="{fill}"/></a:solidFill>' if fill else "<a:noFill/>"
        if line:
            ln_w = int(round(line_pt * 12700))
            line_xml = f'<a:ln w="{ln_w}"><a:solidFill><a:srgbClr val="{line}"/></a:solidFill></a:ln>'
        else:
            line_xml = "<a:ln><a:noFill/></a:ln>"
        av = '<a:avLst><a:gd name="adj" fmla="val 6000"/></a:avLst>' if rounded else "<a:avLst/>"
        self.shapes.append(
            f"""<p:sp>
  <p:nvSpPr><p:cNvPr id="{sid}" name="{esc(name)}"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
  <p:spPr>
    <a:xfrm><a:off x="{px(x)}" y="{px(y)}"/><a:ext cx="{px(w)}" cy="{px(h)}"/></a:xfrm>
    <a:prstGeom prst="{geom}">{av}</a:prstGeom>
    {fill_xml}
    {line_xml}
  </p:spPr>
</p:sp>"""
        )

    def add_text(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        paragraphs: list[dict[str, Any]],
        fill: str | None = None,
        line: str | None = None,
        line_pt: float = 1.0,
        rounded: bool = False,
        anchor: str = "t",
        pad_lr: int = 75000,
        pad_tb: int = 35000,
        name: str = "TextBox",
    ) -> None:
        sid = self._alloc_id()
        geom = "roundRect" if rounded else "rect"
        fill_xml = f'<a:solidFill><a:srgbClr val="{fill}"/></a:solidFill>' if fill else "<a:noFill/>"
        if line:
            ln_w = int(round(line_pt * 12700))
            line_xml = f'<a:ln w="{ln_w}"><a:solidFill><a:srgbClr val="{line}"/></a:solidFill></a:ln>'
        else:
            line_xml = "<a:ln><a:noFill/></a:ln>"
        av = '<a:avLst><a:gd name="adj" fmla="val 6000"/></a:avLst>' if rounded else "<a:avLst/>"

        p_xml_parts: list[str] = []
        for p in paragraphs:
            algn = p.get("align", "l")
            spc_after = int(round(p.get("space_after", 3) * 100))
            bullet = p.get("bullet", False)
            if bullet:
                ppr = f'<a:pPr algn="{algn}" marL="180000" indent="-130000"><a:spcAft><a:spcPts val="{spc_after}"/></a:spcAft><a:buChar char="&#x2022;"/></a:pPr>'
            else:
                ppr = f'<a:pPr algn="{algn}"><a:spcAft><a:spcPts val="{spc_after}"/></a:spcAft><a:buNone/></a:pPr>'

            runs = p.get("runs")
            if runs is None:
                runs = [
                    {
                        "text": p.get("text", ""),
                        "size": p.get("size", 11.5),
                        "bold": p.get("bold", False),
                        "color": p.get("color", SLATE),
                        "font": p.get("font", "Segoe UI"),
                    }
                ]
            r_parts = []
            for r in runs:
                sz = int(round(r.get("size", 11.5) * 100))
                b_attr = ' b="1"' if r.get("bold", False) else ""
                clr = r.get("color", SLATE)
                font = r.get("font", "Segoe UI")
                r_parts.append(
                    f'<a:r><a:rPr lang="en-US" sz="{sz}"{b_attr} dirty="0">'
                    f'<a:solidFill><a:srgbClr val="{clr}"/></a:solidFill>'
                    f'<a:latin typeface="{esc(font)}"/></a:rPr>'
                    f"<a:t>{esc(r.get('text', ''))}</a:t></a:r>"
                )
            p_xml_parts.append(f"<a:p>{ppr}{''.join(r_parts)}</a:p>")

        self.shapes.append(
            f"""<p:sp>
  <p:nvSpPr><p:cNvPr id="{sid}" name="{esc(name)}"/><p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr>
  <p:spPr>
    <a:xfrm><a:off x="{px(x)}" y="{px(y)}"/><a:ext cx="{px(w)}" cy="{px(h)}"/></a:xfrm>
    <a:prstGeom prst="{geom}">{av}</a:prstGeom>
    {fill_xml}
    {line_xml}
  </p:spPr>
  <p:txBody>
    <a:bodyPr wrap="square" lIns="{pad_lr}" tIns="{pad_tb}" rIns="{pad_lr}" bIns="{pad_tb}" anchor="{anchor}"/>
    <a:lstStyle/>
    {''.join(p_xml_parts)}
  </p:txBody>
</p:sp>"""
        )

    def add_image_fit(
        self,
        x: float,
        y: float,
        box_w: float,
        box_h: float,
        media_filename: str,
        img_w: int,
        img_h: int,
        caption: str = "",
        name: str = "Diagram",
    ) -> None:
        self.add_rect(x, y, box_w, box_h, fill=WHITE, line=BORDER, line_pt=1.25, rounded=True, name=f"{name}_Frame")
        pad = 8.0
        cap_h = 20.0 if caption else 0.0
        avail_w = box_w - 2 * pad
        avail_h = box_h - 2 * pad - cap_h
        scale = min(avail_w / img_w, avail_h / img_h)
        draw_w = img_w * scale
        draw_h = img_h * scale
        draw_x = x + pad + (avail_w - draw_w) / 2.0
        draw_y = y + pad + (avail_h - draw_h) / 2.0

        rid = f"rId{len(self.rels) + 1}"
        self.rels.append(
            (
                rid,
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image",
                f"../media/{media_filename}",
            )
        )
        sid = self._alloc_id()
        self.shapes.append(
            f"""<p:pic>
  <p:nvPicPr>
    <p:cNvPr id="{sid}" name="{esc(name)}"/>
    <p:cNvPicPr><a:picLocks noChangeAspect="1"/></p:cNvPicPr>
    <p:nvPr/>
  </p:nvPicPr>
  <p:blipFill>
    <a:blip r:embed="{rid}"/>
    <a:stretch><a:fillRect/></a:stretch>
  </p:blipFill>
  <p:spPr>
    <a:xfrm><a:off x="{px(draw_x)}" y="{px(draw_y)}"/><a:ext cx="{px(draw_w)}" cy="{px(draw_h)}"/></a:xfrm>
    <a:prstGeom prst="rect"><a:avLst/></a:prstGeom>
  </p:spPr>
</p:pic>"""
        )
        if caption:
            self.add_text(
                x + 6, y + box_h - cap_h - 2, box_w - 12, cap_h,
                [{"text": caption, "size": 9.5, "bold": True, "color": MUTED, "align": "ctr"}],
                anchor="ctr", pad_lr=0, pad_tb=0, name=f"{name}_Caption",
            )

    def add_table_flex(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        headers: list[str],
        rows: list[list[str]],
        col_ratios: list[float],
        dark: bool = False,
        font_size: float = 10.0,
        mono_cols: set[int] | None = None,
        bold_cols: set[int] | None = None,
        highlight_row: int | None = None,
        name: str = "Table",
    ) -> None:
        mono_cols = mono_cols or set()
        bold_cols = bold_cols or {0}
        sid = self._alloc_id()
        total_w = px(w)
        col_widths = [int(round(total_w * r)) for r in col_ratios]
        col_widths[-1] += total_w - sum(col_widths)
        n_rows = 1 + len(rows)
        row_h = int(round(px(h) / n_rows))
        grid_cols = "".join(f'<a:gridCol w="{cw}"/>' for cw in col_widths)
        border_clr = "334155" if dark else "E2E8F0"

        def make_cell(txt: str, bg: str, color: str, bold: bool, sz: float, font: str = "Segoe UI") -> str:
            b_attr = ' b="1"' if bold else ""
            sz_u = int(round(sz * 100))
            return (
                f'<a:tc>'
                f'<a:txBody><a:bodyPr wrap="square" lIns="65000" tIns="30000" rIns="65000" bIns="30000" anchor="ctr"/>'
                f'<a:lstStyle/>'
                f'<a:p><a:pPr algn="l"/><a:r><a:rPr lang="en-US" sz="{sz_u}"{b_attr} dirty="0">'
                f'<a:solidFill><a:srgbClr val="{color}"/></a:solidFill>'
                f'<a:latin typeface="{font}"/></a:rPr><a:t>{esc(txt)}</a:t></a:r></a:p></a:txBody>'
                f'<a:tcPr anchor="ctr">'
                f'<a:lnL w="6350"><a:solidFill><a:srgbClr val="{border_clr}"/></a:solidFill></a:lnL>'
                f'<a:lnR w="6350"><a:solidFill><a:srgbClr val="{border_clr}"/></a:solidFill></a:lnR>'
                f'<a:lnT w="6350"><a:solidFill><a:srgbClr val="{border_clr}"/></a:solidFill></a:lnT>'
                f'<a:lnB w="6350"><a:solidFill><a:srgbClr val="{border_clr}"/></a:solidFill></a:lnB>'
                f'<a:solidFill><a:srgbClr val="{bg}"/></a:solidFill>'
                f"</a:tcPr></a:tc>"
            )

        tr_parts: list[str] = []
        hdr_bg = "134E4A" if dark else NAVY
        hdr_fg = TEAL_LIGHT
        hdr_cells = "".join(make_cell(h_txt, hdr_bg, hdr_fg, True, font_size) for h_txt in headers)
        tr_parts.append(f'<a:tr h="{row_h}">{hdr_cells}</a:tr>')
        for idx, r in enumerate(rows):
            is_hl = highlight_row is not None and idx == highlight_row
            if dark:
                bg = NAVY_MID if idx % 2 == 0 else "162032"
            elif is_hl:
                bg = "DCFCE7"
            else:
                bg = WHITE if idx % 2 == 0 else BG_LIGHT

            cells = []
            for ci, val in enumerate(r):
                font = "Consolas" if ci in mono_cols else "Segoe UI"
                bld = is_hl or (ci in bold_cols)
                if dark:
                    fg = TEAL_LIGHT if ci in mono_cols else (WHITE if ci == 0 else "CBD5E1")
                elif is_hl:
                    fg = "14532D"
                else:
                    fg = TEAL if ci in mono_cols else (NAVY if ci in bold_cols else SLATE)
                cells.append(make_cell(val, bg, fg, bld, font_size, font))
            tr_parts.append(f'<a:tr h="{row_h}">{"".join(cells)}</a:tr>')

        self.shapes.append(
            f"""<p:graphicFrame>
  <p:nvGraphicFramePr>
    <p:cNvPr id="{sid}" name="{esc(name)}"/>
    <p:cNvGraphicFramePr><a:graphicFrameLocks noGrp="1"/></p:cNvGraphicFramePr>
    <p:nvPr/>
  </p:nvGraphicFramePr>
  <p:xfrm><a:off x="{px(x)}" y="{px(y)}"/><a:ext cx="{px(w)}" cy="{px(h)}"/></p:xfrm>
  <a:graphic>
    <a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/table">
      <a:tbl>
        <a:tblPr firstRow="1" bandRow="1"/>
        <a:tblGrid>{grid_cols}</a:tblGrid>
        {''.join(tr_parts)}
      </a:tbl>
    </a:graphicData>
  </a:graphic>
</p:graphicFrame>"""
        )

    def add_chrome(self, title: str, subtitle: str, badge: str, part: int = 1) -> None:
        accent = TEAL_BRIGHT if part == 1 else EMERALD
        b_fg = TEAL_LIGHT if part == 1 else "6EE7B7"
        ft = FOOTER_P1 if part == 1 else FOOTER_P2
        self.add_rect(0, 0, 1280, 76, fill=NAVY, name="HeaderBG")
        self.add_rect(0, 0, 10, 76, fill=accent, name="HeaderAccent")
        self.add_text(
            26, 10, 960, 32,
            [{"text": title, "size": 18, "bold": True, "color": WHITE}],
            pad_lr=20000, pad_tb=0, name="HeaderTitle",
        )
        self.add_text(
            26, 44, 960, 22,
            [{"text": subtitle, "size": 10, "color": "94A3B8"}],
            pad_lr=20000, pad_tb=0, name="HeaderSubtitle",
        )
        self.add_text(
            1016, 21, 236, 34,
            [{"text": badge, "size": 9, "bold": True, "color": b_fg, "align": "ctr"}],
            fill=NAVY_MID, line=accent, line_pt=1.25, rounded=True, anchor="ctr", pad_lr=10000, pad_tb=0, name="HeaderBadge",
        )
        self.add_rect(0, 688, 1280, 32, fill=BG_LIGHT, name="FooterBG")
        self.add_rect(0, 688, 1280, 1, fill="E2E8F0", name="FooterRule")
        self.add_text(
            28, 692, 1040, 24,
            [{"text": ft, "size": 8.8, "color": MUTED}],
            anchor="ctr", pad_lr=0, pad_tb=0, name="FooterLeft",
        )
        self.add_text(
            1104, 692, 148, 24,
            [{"text": f"Slide {self.slide_num:02d} / {TOTAL_SLIDES:02d}", "size": 9, "bold": True, "color": NAVY, "font": "Consolas", "align": "r"}],
            anchor="ctr", pad_lr=0, pad_tb=0, name="FooterRight",
        )

    def to_slide_xml(self) -> str:
        return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
       xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
       xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld>
    <p:bg><p:bgPr><a:solidFill><a:srgbClr val="{self.bg_hex}"/></a:solidFill><a:effectLst/></p:bgPr></p:bg>
    <p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
      <p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>
      {''.join(self.shapes)}
    </p:spTree>
  </p:cSld>
  <p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr>
</p:sld>"""

    def to_rels_xml(self) -> str:
        items = "".join(
            f'<Relationship Id="{rid}" Type="{rtype}" Target="{target}"/>'
            for rid, rtype, target in self.rels
        )
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f"{items}</Relationships>"
        )


def _add_fig(sb: SlideBuilder, fig_key: str, img_info: dict[str, tuple[str, int, int]], x: float, y: float, w: float, h: float) -> None:
    mname, iw, ih = img_info[fig_key]
    _, _, cap = FIGURES[fig_key]
    sb.add_image_fit(x, y, w, h, mname, iw, ih, cap, name=fig_key)


def _add_bottom_4(sb: SlideBuilder, items: list[tuple[str, str, str]], y: float = 532, h: float = 144, highlight_last: bool = False) -> None:
    for i, (code, title, desc) in enumerate(items):
        cx = 28 + i * 310
        cw = 296
        is_hl = highlight_last and i == 3
        bg = GREEN_SOFT if is_hl else BG_LIGHT
        top = GREEN if is_hl else TEAL
        ln = GREEN_LIGHT if is_hl else "E2E8F0"
        sb.add_rect(cx, y, cw, h, fill=bg, line=ln, line_pt=1.0, rounded=True)
        sb.add_rect(cx, y, cw, 5, fill=top)
        if code:
            sb.add_text(cx + 10, y + 14, 52, 22, [{"text": code, "size": 9, "bold": True, "color": TEAL_LIGHT, "font": "Consolas", "align": "ctr"}], fill=NAVY, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0)
            sb.add_text(cx + 70, y + 14, cw - 80, 24, [{"text": title, "size": 10.5, "bold": True, "color": NAVY}], anchor="ctr", pad_lr=0, pad_tb=0)
            sb.add_text(cx + 10, y + 44, cw - 20, h - 52, [{"text": desc, "size": 9.5, "color": SLATE}], pad_lr=0, pad_tb=0)
        else:
            sb.add_text(
                cx + 12, y + 14, cw - 24, h - 22,
                [
                    {"text": title, "size": 11, "bold": True, "color": NAVY, "space_after": 5},
                    {"text": desc, "size": 9.8, "color": SLATE},
                ],
                pad_lr=0, pad_tb=0,
            )


def _add_bottom_3(sb: SlideBuilder, items: list[tuple[str, str, str]], y: float = 532, h: float = 144) -> None:
    tone_map = {
        "green": (GREEN_SOFT, GREEN_LIGHT, GREEN),
        "teal": (BG_LIGHT, "E2E8F0", TEAL),
        "navy": (BG_LIGHT, "E2E8F0", NAVY),
        "amber": (AMBER_SOFT, "FCD34D", AMBER),
    }
    for i, (title, desc, tone) in enumerate(items):
        cx = 28 + i * 412
        cw = 400
        bg, ln, top = tone_map.get(tone, (BG_LIGHT, "E2E8F0", TEAL))
        sb.add_rect(cx, y, cw, h, fill=bg, line=ln, line_pt=1.0, rounded=True)
        sb.add_rect(cx, y, cw, 5, fill=top)
        sb.add_text(
            cx + 14, y + 14, cw - 28, h - 22,
            [
                {"text": title, "size": 11.5, "bold": True, "color": NAVY, "space_after": 5},
                {"text": desc, "size": 10, "color": SLATE},
            ],
            pad_lr=0, pad_tb=0,
        )


def build_pptx_slides(img_info: dict[str, tuple[str, int, int]]) -> list[SlideBuilder]:
    slides: list[SlideBuilder] = []

    # ---- Slide 1: Dark Navy Master Cover ----
    s1 = SlideBuilder(1, NAVY)
    s1.add_rect(0, 0, 12, 720, fill=TEAL_BRIGHT)
    s1.add_text(
        68, 36, 760, 30,
        [{"text": "FULL GRADUATION DEFENSE • DEPARTMENT OF CYBER SECURITY (2026–2027) • PREPARED FOR DR. SAMAR", "size": 9.5, "bold": True, "color": TEAL_LIGHT, "align": "ctr"}],
        fill="134E4A", line=TEAL_BRIGHT, line_pt=1.0, rounded=True, anchor="ctr",
    )
    s1.add_text(
        68, 80, 1140, 115,
        [
            {"text": "Developing a Lightweight OWASP", "size": 36, "bold": True, "color": WHITE, "space_after": 2},
            {"text": "Top 10 Vulnerability Scanner", "size": 36, "bold": True, "color": WHITE, "space_after": 4},
        ],
        pad_lr=0, pad_tb=0,
    )
    s1.add_text(
        68, 200, 1140, 34,
        [{"text": "Unified Defense: Software Architecture Document (SAD) & Technical Implementation (Phases 0–7, v1.0.0)", "size": 14.5, "bold": True, "color": TEAL_LIGHT}],
        pad_lr=0, pad_tb=0,
    )
    kpi_clrs = {"teal": TEAL_BRIGHT, "sky": "38BDF8", "green": "4ADE80", "emerald": "34D399"}
    for i, (val, lbl, sub, tone) in enumerate(COVER_KPIS):
        kx = 68 + i * 292
        s1.add_rect(kx, 256, 276, 124, fill=NAVY_MID, line="334155", line_pt=1.0, rounded=True)
        s1.add_rect(kx, 256, 276, 5, fill=kpi_clrs[tone])
        s1.add_text(
            kx + 14, 270, 248, 102,
            [
                {"text": val, "size": 24, "bold": True, "color": WHITE, "space_after": 3},
                {"text": lbl, "size": 11.5, "bold": True, "color": TEAL_LIGHT, "space_after": 3},
                {"text": sub, "size": 9.5, "color": "CBD5E1"},
            ],
            pad_lr=0, pad_tb=0,
        )
    s1.add_rect(68, 404, 386, 274, fill=NAVY_MID, line="334155", line_pt=1.0, rounded=True)
    s1.add_text(
        86, 420, 350, 160,
        [
            {"text": "SUPERVISOR & DEPARTMENT", "size": 9, "bold": True, "color": TEAL_LIGHT, "space_after": 8},
            {"text": "Dr. Samar", "size": 22, "bold": True, "color": WHITE, "space_after": 4},
            {"text": "Department of Cyber Security • 2026–2027", "size": 10.5, "color": "CBD5E1", "space_after": 18},
            {"text": "Part 1: Software Architecture (Slides 1–20)", "size": 10, "bold": True, "color": TEAL_LIGHT, "space_after": 6},
            {"text": "Part 2: Technical v1.0.0 (Slides 21–30)", "size": 10, "bold": True, "color": "6EE7B7"},
        ],
        pad_lr=0, pad_tb=0,
    )
    s1.add_rect(472, 404, 750, 274, fill=NAVY_MID, line="334155", line_pt=1.0, rounded=True)
    s1.add_text(490, 418, 700, 22, [{"text": "GRADUATION PROJECT TEAM (7 MEMBERS)", "size": 9, "bold": True, "color": TEAL_LIGHT}], pad_lr=0, pad_tb=0)
    for idx, (nm, sid, _) in enumerate(TEAM_ROSTER):
        col = idx % 2
        row = idx // 2
        tx = 490 + col * 362
        ty = 448 + row * 54
        s1.add_rect(tx, ty, 348, 42, fill=NAVY, line="334155", line_pt=0.8, rounded=True)
        s1.add_text(tx + 10, ty + 8, 250, 26, [{"text": nm, "size": 10, "bold": True, "color": WHITE}], anchor="ctr", pad_lr=0, pad_tb=0)
        s1.add_text(tx + 266, ty + 8, 72, 26, [{"text": sid, "size": 10, "bold": True, "color": TEAL_LIGHT, "font": "Consolas", "align": "r"}], anchor="ctr", pad_lr=0, pad_tb=0)
    slides.append(s1)

    # ---- Slide 2: Part 1 Section Cover ----
    s2 = SlideBuilder(2, NAVY)
    s2.add_rect(0, 0, 12, 720, fill=TEAL_BRIGHT)
    s2.add_text(68, 38, 560, 28, [{"text": "PART 1 OF 2 • SLIDES 01–20 • IEEE-ALIGNED ARCHITECTURE", "size": 9.5, "bold": True, "color": TEAL_LIGHT, "align": "ctr"}], fill="134E4A", line=TEAL_BRIGHT, line_pt=1.0, rounded=True, anchor="ctr")
    s2.add_text(68, 78, 960, 56, [{"text": "Part 1: Software Architecture Document (SAD)", "size": 32, "bold": True, "color": WHITE}], pad_lr=0, pad_tb=0)
    s2.add_text(68, 136, 980, 32, [{"text": "Complete 6-chapter formal blueprint covering motivation, SRS, C4/DFD/UML views, 3NF data & API contracts, STRIDE security & validation.", "size": 12.5, "color": "CBD5E1"}], pad_lr=0, pad_tb=0)
    s2.add_text(1080, 62, 140, 56, [{"text": "PART 1", "size": 18, "bold": True, "color": TEAL_LIGHT, "align": "ctr"}], fill="134E4A", line=TEAL_BRIGHT, line_pt=2.0, rounded=True, anchor="ctr")
    for idx, (ch, title, desc) in enumerate(SAD_CHAPTERS):
        col = idx % 3
        row = idx // 3
        cx = 68 + col * 388
        cy = 196 + row * 206
        s2.add_rect(cx, cy, 370, 186, fill=NAVY_MID, line="334155", line_pt=1.0, rounded=True)
        s2.add_rect(cx, cy, 370, 5, fill=TEAL_BRIGHT)
        s2.add_text(cx + 16, cy + 20, 60, 26, [{"text": ch, "size": 10, "bold": True, "color": WHITE, "font": "Consolas", "align": "ctr"}], fill=TEAL, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0)
        s2.add_text(cx + 86, cy + 20, 268, 28, [{"text": title, "size": 14, "bold": True, "color": WHITE}], anchor="ctr", pad_lr=0, pad_tb=0)
        s2.add_text(cx + 16, cy + 62, 338, 108, [{"text": desc, "size": 11, "color": "CBD5E1"}], pad_lr=0, pad_tb=0)
    s2.add_rect(68, 616, 1146, 56, fill="134E4A", line=TEAL_BRIGHT, line_pt=1.25, rounded=True)
    s2.add_text(88, 628, 1106, 32, [{"text": "19 Original Diagrams   •   15 Functional Reqs (FR-01..15)   •   9 Quantitative NFRs   •   5 Formal ADRs   •   15 Test Cases (TC-01..15)", "size": 12.5, "bold": True, "color": TEAL_LIGHT, "align": "ctr"}], anchor="ctr", pad_lr=0, pad_tb=0)
    slides.append(s2)

    # ---- Slide 3: Fig 1 AS-IS vs TO-BE ----
    s3 = SlideBuilder(3, WHITE)
    s3.add_chrome("Problem Statement & AS-IS vs. TO-BE Workflow", "Eliminating enterprise DAST proxy friction with a 3-minute local developer-first OWASP workflow", "CH. 1 • FIGURE 1", 1)
    _add_fig(s3, "fig01", img_info, 28, 90, 1224, 424)
    for idx, (hdr, bg, tag, tag_bg, pts) in enumerate([
        ("AS-IS: Legacy Enterprise DAST Friction (ZAP / Burp)", NAVY, "PAIN POINTS", RED, SLIDE3_AS_IS),
        ("TO-BE: OWASP-Lite 3-Minute Zero-Proxy DX", TEAL, "OUR DESIGN", GREEN, SLIDE3_TO_BE),
    ]):
        cx = 28 + idx * 620
        s3.add_rect(cx, 528, 604, 148, fill=BG_LIGHT, line="E2E8F0", line_pt=1.0, rounded=True)
        s3.add_rect(cx, 528, 604, 34, fill=bg)
        s3.add_text(cx + 12, 534, 470, 22, [{"text": hdr, "size": 10.5, "bold": True, "color": WHITE}], anchor="ctr", pad_lr=0, pad_tb=0)
        s3.add_text(cx + 500, 535, 92, 20, [{"text": tag, "size": 8, "bold": True, "color": WHITE, "align": "ctr"}], fill=tag_bg, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0)
        paras = [{"bullet": True, "space_after": 6, "runs": [{"text": k + " ", "size": 10, "bold": True, "color": NAVY}, {"text": v, "size": 10, "color": SLATE}]} for k, v in pts]
        s3.add_text(cx + 12, 570, 580, 98, paras, pad_lr=0, pad_tb=0)
    slides.append(s3)

    # ---- Slide 4: Fig 2 Master 4-Phase Scanner Pipeline ----
    s4 = SlideBuilder(4, WHITE)
    s4.add_chrome("Master 4-Phase Scanner Pipeline", "End-to-end execution flow from local authorization & BFS discovery to 17-check isolated engine & 5-stack fixes", "CH. 1 • FIGURE 2", 1)
    _add_fig(s4, "fig02", img_info, 28, 90, 1224, 430)
    _add_bottom_4(s4, SLIDE4_PHASES, y=534, h=142)
    slides.append(s4)

    # ---- Slide 5: Fig 3 Ethical Scope & Use Cases ----
    s5 = SlideBuilder(5, WHITE)
    s5.add_chrome("Ethical Scope & System Use Cases (UC-01 – UC-06)", "Six formal developer use cases, six OWASP Top 10 (2021) categories & strict non-destructive boundaries", "CH. 1–2 • FIGURE 3", 1)
    _add_fig(s5, "fig03", img_info, 28, 90, 760, 586)
    s5.add_rect(804, 90, 448, 282, fill=BG_LIGHT, line="E2E8F0", line_pt=1.0, rounded=True)
    s5.add_rect(804, 90, 448, 32, fill=NAVY)
    s5.add_text(816, 95, 360, 22, [{"text": "6 System Use Cases (UC-01 – UC-06)", "size": 10.5, "bold": True, "color": WHITE}], anchor="ctr", pad_lr=0, pad_tb=0)
    uc_paras = [{"space_after": 6, "runs": [{"text": f"{u} ", "size": 9.8, "bold": True, "color": TEAL, "font": "Consolas"}, {"text": f"{n}: ", "size": 9.8, "bold": True, "color": NAVY}, {"text": d, "size": 9.8, "color": SLATE}]} for u, n, d in SLIDE5_USE_CASES]
    s5.add_text(816, 130, 424, 234, uc_paras, pad_lr=0, pad_tb=0)
    s5.add_rect(804, 384, 448, 124, fill=TEAL_SOFT, line="99F6E4", line_pt=1.0, rounded=True)
    s5.add_text(816, 392, 424, 20, [{"text": "6 OWASP TOP 10 (2021) CATEGORIES • 17 CHECKS", "size": 9, "bold": True, "color": "0F766E"}], pad_lr=0, pad_tb=0)
    for idx, (c, nm, cnt) in enumerate(SLIDE5_OWASP):
        col = idx % 3
        row = idx // 3
        ox = 816 + col * 144
        oy = 420 + row * 40
        s5.add_text(ox, oy, 136, 32, [{"runs": [{"text": f"{c} ", "size": 9.5, "bold": True, "color": NAVY, "font": "Consolas"}, {"text": f"{nm} ({cnt})", "size": 9.2, "color": TEAL, "bold": True}], "align": "ctr"}], fill=WHITE, line="CCFBF1", line_pt=1.0, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0)
    s5.add_rect(804, 520, 218, 156, fill=GREEN_SOFT, line=GREEN_LIGHT, line_pt=1.0, rounded=True)
    s5.add_text(814, 528, 198, 140, [{"text": "✓ IN-SCOPE", "size": 9.5, "bold": True, "color": GREEN_DARK, "space_after": 6}, {"text": "Localhost & Docker labs", "size": 9.5, "color": "166534", "bullet": True, "space_after": 4}, {"text": "17 non-destructive checks", "size": 9.5, "color": "166534", "bullet": True, "space_after": 4}, {"text": "5-stack fixes & reports", "size": 9.5, "color": "166534", "bullet": True}], pad_lr=0, pad_tb=0)
    s5.add_rect(1034, 520, 218, 156, fill=RED_SOFT, line="FCA5A5", line_pt=1.0, rounded=True)
    s5.add_text(1044, 528, 198, 140, [{"text": "✗ OUT-OF-SCOPE", "size": 9.5, "bold": True, "color": RED, "space_after": 6}, {"text": "Public internet targets", "size": 9.5, "color": "991B1B", "bullet": True, "space_after": 4}, {"text": "Exploitation or DoS", "size": 9.5, "color": "991B1B", "bullet": True, "space_after": 4}, {"text": "Headless SPA / SaaS", "size": 9.5, "color": "991B1B", "bullet": True}], pad_lr=0, pad_tb=0)
    slides.append(s5)

    # ---- Slide 6: Formal SRS ----
    s6 = SlideBuilder(6, WHITE)
    s6.add_chrome("Formal Software Requirements (FR-01..15 & NFR-01..09)", "MoSCoW-prioritized functional capabilities and quantitative quality-attribute acceptance SLAs", "CH. 2 • SRS BASELINE", 1)
    s6.add_text(28, 90, 604, 30, [{"text": "Functional Requirements (FR-01 – FR-15)", "size": 11, "bold": True, "color": WHITE}], fill=NAVY, anchor="ctr", pad_lr=80000, pad_tb=0)
    s6.add_table_flex(28, 120, 604, 504, ["ID", "Capability", "Formal Specification"], [[r, n, d] for r, n, d in SLIDE6_FRS], [0.16, 0.27, 0.57], font_size=8.8, mono_cols={0}, bold_cols={0, 1}, name="FRTable")
    s6.add_text(648, 90, 604, 30, [{"text": "Quantitative Non-Functional SLAs (NFR-01 – NFR-09)", "size": 11, "bold": True, "color": WHITE}], fill=TEAL, anchor="ctr", pad_lr=80000, pad_tb=0)
    s6.add_table_flex(648, 120, 604, 504, ["ID", "Attribute", "Measurable Acceptance Target"], [[r, n, d] for r, n, d in SLIDE6_NFRS], [0.16, 0.27, 0.57], font_size=8.8, mono_cols={0}, bold_cols={0, 1}, name="NFRTable")
    s6.add_text(
        28, 634, 1224, 42,
        [{"text": "< 3 min Setup   •   <= 15s / 45s / 90s Quick/Std/Deep   •   >= 85% Prec / >= 80% Rec / >= 82% F1   •   0 /safe/* FPs   •   10 req/s & 2,000 Cap   •   Pure Inline SVG Charts", "size": 9.8, "bold": True, "color": TEAL_LIGHT, "align": "ctr"}],
        fill=NAVY, rounded=True, anchor="ctr", pad_lr=20000, pad_tb=0,
    )
    slides.append(s6)

    # ---- Slide 7: Fig 4 C4 L1 ----
    s7 = SlideBuilder(7, WHITE)
    s7.add_chrome("C4 Level 1: System Context Diagram", "Actors, local-only scanner boundary, authorized testbench targets & hard public-internet block", "CH. 3 • FIGURE 4", 1)
    _add_fig(s7, "fig04", img_info, 28, 90, 760, 586)
    s7.add_text(804, 90, 448, 34, [{"text": "System Context Boundaries", "size": 11, "bold": True, "color": WHITE}], fill=NAVY, rounded=True, anchor="ctr", pad_lr=80000, pad_tb=0)
    for i, (t, d) in enumerate(SLIDE7_C4L1):
        cy = 136 + i * 136
        s7.add_rect(804, cy, 448, 124, fill=BG_LIGHT, line="E2E8F0", line_pt=1.0, rounded=True)
        s7.add_rect(804, cy, 5, 124, fill=TEAL)
        s7.add_text(820, cy + 12, 420, 100, [{"text": t, "size": 11.5, "bold": True, "color": NAVY, "space_after": 4}, {"text": d, "size": 10, "color": SLATE}], pad_lr=0, pad_tb=0)
    slides.append(s7)

    # ---- Slide 8: Fig 5 C4 L2 ----
    s8 = SlideBuilder(8, WHITE)
    s8.add_chrome("C4 Level 2: Container Architecture & 6-Layer Stack", "Modular monolith v1.0.0 — Pure Inline SVG Charts, SQLite WAL / PostgreSQL 16 & non-root Docker", "CH. 3 • FIGURE 5", 1)
    _add_fig(s8, "fig05", img_info, 28, 90, 760, 586)
    s8.add_text(804, 90, 448, 34, [{"text": "6-Layer Technology Stack (v1.0.0)", "size": 11, "bold": True, "color": WHITE}], fill=NAVY, rounded=True, anchor="ctr", pad_lr=80000, pad_tb=0)
    for i, (n, d) in enumerate(SLIDE8_LAYERS):
        cy = 134 + i * 91
        s8.add_rect(804, cy, 448, 82, fill=BG_LIGHT, line="E2E8F0", line_pt=1.0, rounded=True)
        s8.add_rect(804, cy, 5, 82, fill=TEAL)
        s8.add_text(820, cy + 8, 420, 66, [{"text": n, "size": 11, "bold": True, "color": NAVY, "space_after": 3}, {"text": d, "size": 9.5, "color": SLATE}], pad_lr=0, pad_tb=0)
    slides.append(s8)

    # ---- Slide 9: Fig 6 C4 L3 ----
    s9 = SlideBuilder(9, WHITE)
    s9.add_chrome("C4 Level 3: Pure-Python Scanner Engine Components", "Decoupled backend/scanner/ core — ScopeGuardrail, HttpClient, BFS Crawler & 17-Check Orchestrator", "CH. 3 • FIG. 6 • 30/30 AST", 1)
    _add_fig(s9, "fig06", img_info, 28, 90, 1224, 430)
    _add_bottom_4(s9, [("", t, d) for t, d in SLIDE9_COMPONENTS], y=534, h=142, highlight_last=True)
    slides.append(s9)

    # ---- Slide 10: Fig 7 DFD L0 ----
    s10 = SlideBuilder(10, WHITE)
    s10.add_chrome("DFD Level 0: System Context Data Flows", "High-level data ingress, live telemetry egress, bounded HTTP target probing & 3NF persistence", "CH. 3 • FIGURE 7", 1)
    _add_fig(s10, "fig07", img_info, 28, 90, 1224, 430)
    _add_bottom_4(s10, SLIDE10_FLOWS, y=534, h=142)
    slides.append(s10)

    # ---- Slide 11: Fig 8 DFD L1 + STRIDE + SSDF ----
    s11 = SlideBuilder(11, WHITE)
    s11.add_chrome("DFD Level 1: Trust Boundaries, STRIDE & NIST SSDF", "Explicit trust boundaries (TB1–TB3) mapped to STRIDE mitigations and NIST SP 800-218 practices", "CH. 3 & 5 • FIGURE 8", 1)
    _add_fig(s11, "fig08", img_info, 28, 90, 720, 586)
    s11.add_rect(764, 90, 488, 326, fill=BG_LIGHT, line="E2E8F0", line_pt=1.0, rounded=True)
    s11.add_rect(764, 90, 488, 34, fill=NAVY)
    s11.add_text(778, 96, 380, 22, [{"text": "STRIDE Threat Mitigations", "size": 11, "bold": True, "color": WHITE}], anchor="ctr", pad_lr=0, pad_tb=0)
    st_paras = [{"bullet": True, "space_after": 8, "runs": [{"text": f"{k}: ", "size": 10, "bold": True, "color": NAVY}, {"text": v, "size": 10, "color": SLATE}]} for k, v in SLIDE11_STRIDE]
    s11.add_text(778, 134, 460, 272, st_paras, pad_lr=0, pad_tb=0)
    s11.add_rect(764, 430, 488, 246, fill=BG_LIGHT, line="E2E8F0", line_pt=1.0, rounded=True)
    s11.add_rect(764, 430, 488, 34, fill=TEAL)
    s11.add_text(778, 436, 380, 22, [{"text": "NIST SSDF (SP 800-218) Alignment", "size": 11, "bold": True, "color": WHITE}], anchor="ctr", pad_lr=0, pad_tb=0)
    for idx, (code, nm, desc) in enumerate(SLIDE11_SSDF):
        col = idx % 2
        row = idx // 2
        sx = 778 + col * 234
        sy = 476 + row * 94
        s11.add_rect(sx, sy, 224, 84, fill=WHITE, line="E2E8F0", line_pt=1.0, rounded=True)
        s11.add_text(sx + 8, sy + 8, 56, 20, [{"text": code, "size": 8.5, "bold": True, "color": WHITE, "font": "Consolas", "align": "ctr"}], fill=TEAL, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0)
        s11.add_text(sx + 70, sy + 8, 146, 20, [{"text": nm, "size": 10, "bold": True, "color": NAVY}], anchor="ctr", pad_lr=0, pad_tb=0)
        s11.add_text(sx + 8, sy + 34, 208, 44, [{"text": desc, "size": 9.2, "color": SLATE}], pad_lr=0, pad_tb=0)
    slides.append(s11)

    # ---- Slide 12: Fig 16 Scope Guardrail Flow ----
    s12 = SlideBuilder(12, WHITE)
    s12.add_chrome("Scope Guardrail & Safe Non-Destructive Scanning Flow", "4-layer defense-in-depth gate enforcing local-only ethical scanning and anti-SSRF protection", "CH. 5 • FIGURE 16", 1)
    _add_fig(s12, "fig16", img_info, 28, 90, 520, 586)
    s12.add_text(564, 90, 688, 34, [{"text": "4 Defense-in-Depth Safety Layers (policy.py)", "size": 11, "bold": True, "color": WHITE}], fill=NAVY, rounded=True, anchor="ctr", pad_lr=80000, pad_tb=0)
    for i, (code, t, d) in enumerate(SLIDE12_LAYERS):
        cy = 136 + i * 136
        s12.add_rect(564, cy, 688, 124, fill=BG_LIGHT, line="E2E8F0", line_pt=1.0, rounded=True)
        s12.add_rect(564, cy, 6, 124, fill=TEAL)
        s12.add_text(582, cy + 40, 42, 42, [{"text": code, "size": 12.5, "bold": True, "color": TEAL_LIGHT, "font": "Consolas", "align": "ctr"}], fill=NAVY, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0)
        s12.add_text(638, cy + 14, 598, 98, [{"text": t, "size": 12, "bold": True, "color": NAVY, "space_after": 4}, {"text": d, "size": 10.2, "color": SLATE}], pad_lr=0, pad_tb=0)
    slides.append(s12)

    # ---- Slide 13: Fig 19 Master System Flowchart ----
    s13 = SlideBuilder(13, WHITE)
    s13.add_chrome("Master System Execution Flowchart (ISO 5807)", "Complete decision-level control flow from target authorization to copy-ready 5-stack fixes", "CH. 3 • FIGURE 19", 1)
    _add_fig(s13, "fig19", img_info, 28, 90, 480, 586)
    s13.add_text(524, 90, 728, 34, [{"text": "6 Numbered End-to-End Lifecycle Stages", "size": 11, "bold": True, "color": WHITE}], fill=NAVY, rounded=True, anchor="ctr", pad_lr=80000, pad_tb=0)
    for i, (num, t, d) in enumerate(SLIDE13_STAGES):
        cy = 134 + i * 91
        s13.add_rect(524, cy, 728, 82, fill=BG_LIGHT, line="E2E8F0", line_pt=1.0, rounded=True)
        s13.add_rect(524, cy, 5, 82, fill=TEAL)
        s13.add_text(540, cy + 21, 38, 38, [{"text": num, "size": 12, "bold": True, "color": TEAL_LIGHT, "font": "Consolas", "align": "ctr"}], fill=NAVY, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0)
        s13.add_text(590, cy + 8, 650, 66, [{"text": t, "size": 11.5, "bold": True, "color": NAVY, "space_after": 3}, {"text": d, "size": 9.8, "color": SLATE}], pad_lr=0, pad_tb=0)
    slides.append(s13)

    # ---- Slide 14: Fig 13 Swimlane Activity ----
    s14 = SlideBuilder(14, WHITE)
    s14.add_chrome("Cross-Functional Swimlane Activity Workflow", "Clear handoffs across Developer Browser, FastAPI SSE API, Pure Scanner Core & SQLAlchemy DB", "CH. 3 • FIGURE 13", 1)
    _add_fig(s14, "fig13", img_info, 28, 90, 720, 586)
    s14.add_text(764, 90, 488, 34, [{"text": "4 Architectural Swimlane Responsibilities", "size": 11, "bold": True, "color": WHITE}], fill=NAVY, rounded=True, anchor="ctr", pad_lr=80000, pad_tb=0)
    for i, (code, t, d) in enumerate(SLIDE14_LANES):
        cy = 136 + i * 136
        s14.add_rect(764, cy, 488, 124, fill=BG_LIGHT, line="E2E8F0", line_pt=1.0, rounded=True)
        s14.add_rect(764, cy, 5, 124, fill=TEAL)
        s14.add_text(780, cy + 40, 40, 40, [{"text": code, "size": 12, "bold": True, "color": TEAL_LIGHT, "font": "Consolas", "align": "ctr"}], fill=NAVY, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0)
        s14.add_text(832, cy + 14, 408, 98, [{"text": t, "size": 11.5, "bold": True, "color": NAVY, "space_after": 4}, {"text": d, "size": 10, "color": SLATE}], pad_lr=0, pad_tb=0)
    slides.append(s14)

    # ---- Slide 15: Fig 12 State Machine ----
    s15 = SlideBuilder(15, WHITE)
    s15.add_chrome("6-State Scan Lifecycle State Machine", "Deterministic scan states (queued, crawling, scanning, completed, cancelled, failed) synced via SSE", "CH. 3 • FIGURE 12", 1)
    _add_fig(s15, "fig12", img_info, 28, 90, 1224, 430)
    _add_bottom_4(s15, SLIDE15_FSM, y=534, h=142)
    slides.append(s15)

    # ---- Slide 16: Fig 10 End-to-End & Live SSE Sequence ----
    s16 = SlideBuilder(16, WHITE)
    s16.add_chrome("End-to-End Scan Lifecycle & Live SSE Sequence", "201 Created async job dispatch and real-time /api/scans/{id}/stream telemetry", "CH. 3 • FIGURE 10", 1)
    _add_fig(s16, "fig10", img_info, 28, 90, 480, 586)
    s16.add_text(524, 90, 728, 34, [{"text": "Async Dispatch & Live SSE Protocol", "size": 11, "bold": True, "color": WHITE}], fill=NAVY, rounded=True, anchor="ctr", pad_lr=80000, pad_tb=0)
    for i, (t, d) in enumerate(SLIDE16_SEQ_CARDS):
        cy = 136 + i * 136
        s16.add_rect(524, cy, 728, 124, fill=BG_LIGHT, line="E2E8F0", line_pt=1.0, rounded=True)
        s16.add_rect(524, cy, 6, 124, fill=TEAL)
        s16.add_text(544, cy + 14, 692, 98, [{"text": t, "size": 12.5, "bold": True, "color": NAVY, "space_after": 5}, {"text": d, "size": 10.5, "color": SLATE}], pad_lr=0, pad_tb=0)
    slides.append(s16)

    # ---- Slide 17: Fig 11 Cancel & Error Isolation ----
    s17 = SlideBuilder(17, WHITE)
    s17.add_chrome("Cooperative Cancellation & Per-Check Error Isolation", "Thread-safe <= 5s graceful halt via threading.Event and non-fatal try/except plugin fault containment", "CH. 3 • FIGURE 11", 1)
    _add_fig(s17, "fig11", img_info, 28, 90, 640, 586)
    for idx, (hdr, bg, tag, tag_bg, pts) in enumerate([
        ("Cooperative Cancellation (<= 5s Halt)", NAVY, "threading.Event", AMBER, SLIDE17_CANCEL),
        ("Per-Check Error Isolation", TEAL, "check_warning", GREEN, SLIDE17_ISOLATION),
    ]):
        cy = 110 + idx * 282
        s17.add_rect(684, cy, 568, 258, fill=BG_LIGHT, line="E2E8F0", line_pt=1.0, rounded=True)
        s17.add_rect(684, cy, 568, 40, fill=bg)
        s17.add_text(700, cy + 8, 390, 24, [{"text": hdr, "size": 12, "bold": True, "color": WHITE}], anchor="ctr", pad_lr=0, pad_tb=0)
        s17.add_text(1112, cy + 9, 126, 22, [{"text": tag, "size": 8.5, "bold": True, "color": WHITE, "font": "Consolas", "align": "ctr"}], fill=tag_bg, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0)
        paras = [{"bullet": True, "space_after": 14, "runs": [{"text": k + " ", "size": 11.2, "bold": True, "color": NAVY}, {"text": v, "size": 11.2, "color": SLATE}]} for k, v in pts]
        s17.add_text(702, cy + 56, 534, 186, paras, pad_lr=0, pad_tb=0)
    slides.append(s17)

    # ---- Slide 18: Fig 14 Plugin Engine & 5-Stack Fix KB ----
    s18 = SlideBuilder(18, WHITE)
    s18.add_chrome("Modular Plugin Engine (BaseCheck) & 5-Stack Fix KB", "Open/Closed 1-file plugin auto-registry paired with interpolated 5-stack code remediation (kb.json)", "CH. 3 • FIGURE 14", 1)
    _add_fig(s18, "fig14", img_info, 28, 90, 720, 586)
    for idx, (title, tone, tag, pts) in enumerate(SLIDE18_CARDS):
        cy = 90 + idx * 199
        bg = NAVY if tone == "NAVY" else TEAL
        s18.add_rect(764, cy, 488, 186, fill=BG_LIGHT, line="E2E8F0", line_pt=1.0, rounded=True)
        s18.add_rect(764, cy, 488, 34, fill=bg)
        s18.add_text(778, cy + 6, 370, 22, [{"text": title, "size": 10.5, "bold": True, "color": WHITE}], anchor="ctr", pad_lr=0, pad_tb=0)
        s18.add_text(1156, cy + 7, 84, 20, [{"text": tag, "size": 8, "bold": True, "color": WHITE, "align": "ctr"}], fill=GREEN, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0)
        paras = [{"bullet": True, "space_after": 8, "text": p, "size": 10.2, "color": SLATE} for p in pts]
        s18.add_text(778, cy + 44, 460, 132, paras, pad_lr=0, pad_tb=0)
    slides.append(s18)

    # ---- Slide 19: Fig 15 3NF ERD & 14 REST/SSE APIs ----
    s19 = SlideBuilder(19, WHITE)
    s19.add_chrome("3NF Data Model & 14 REST/SSE API Contract", "Normalized 4-table SQLAlchemy 2.0 schema (SQLite WAL / PG 16) and typed FastAPI endpoint surface", "CH. 4 • FIGURE 15", 1)
    _add_fig(s19, "fig15", img_info, 28, 90, 680, 586)
    s19.add_rect(724, 90, 528, 228, fill=BG_LIGHT, line="E2E8F0", line_pt=1.0, rounded=True)
    s19.add_rect(724, 90, 528, 32, fill=NAVY)
    s19.add_text(738, 95, 420, 22, [{"text": "4-Table 3NF Relational Schema", "size": 10.5, "bold": True, "color": WHITE}], anchor="ctr", pad_lr=0, pad_tb=0)
    t_paras = [{"space_after": 6, "runs": [{"text": f"{t}: ", "size": 9.8, "bold": True, "color": TEAL, "font": "Consolas"}, {"text": d, "size": 9.6, "color": SLATE}]} for t, d in SLIDE19_TABLES]
    s19.add_text(738, 130, 500, 180, t_paras, pad_lr=0, pad_tb=0)
    s19.add_rect(724, 332, 528, 344, fill=BG_LIGHT, line="E2E8F0", line_pt=1.0, rounded=True)
    s19.add_rect(724, 332, 528, 32, fill=TEAL)
    s19.add_text(738, 337, 440, 22, [{"text": "14 FastAPI REST / SSE Endpoints (6 Groups)", "size": 10.5, "bold": True, "color": WHITE}], anchor="ctr", pad_lr=0, pad_tb=0)
    ep_paras = []
    for e, d in SLIDE19_ENDPOINTS:
        ep_paras.append({"space_after": 1, "runs": [{"text": e, "size": 9.2, "bold": True, "color": TEAL, "font": "Consolas"}]})
        ep_paras.append({"space_after": 6, "runs": [{"text": d, "size": 9.2, "color": SLATE}]})
    s19.add_text(738, 372, 500, 296, ep_paras, pad_lr=0, pad_tb=0)
    slides.append(s19)

    # ---- Slide 20: ADRs (01–05) & 3-Tier Validation Plan ----
    s20 = SlideBuilder(20, WHITE)
    s20.add_chrome("Architecture Decision Records (ADR-01..05) & 3-Tier Validation Plan", "Formal trade-off justifications and 15-case empirical verification strategy (TC-01..15)", "CH. 5–6 • ADRs & PLAN", 1)
    s20.add_text(28, 90, 710, 34, [{"text": "5 Formal Architecture Decision Records (ADR-01 – ADR-05)", "size": 11, "bold": True, "color": WHITE}], fill=NAVY, rounded=True, anchor="ctr", pad_lr=80000, pad_tb=0)
    for i, (aid, t, d) in enumerate(SLIDE20_ADRS):
        cy = 134 + i * 110
        s20.add_rect(28, cy, 710, 100, fill=BG_LIGHT, line="E2E8F0", line_pt=1.0, rounded=True)
        s20.add_rect(28, cy, 5, 100, fill=NAVY)
        s20.add_text(44, cy + 32, 66, 32, [{"text": aid, "size": 10, "bold": True, "color": TEAL_LIGHT, "font": "Consolas", "align": "ctr"}], fill=NAVY, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0)
        s20.add_text(122, cy + 10, 604, 82, [{"text": t, "size": 11.5, "bold": True, "color": NAVY, "space_after": 3}, {"text": d, "size": 9.8, "color": SLATE}], pad_lr=0, pad_tb=0)
    s20.add_text(754, 90, 498, 34, [{"text": "3-Tier Testbench Validation Strategy (TC-01 – TC-15)", "size": 11, "bold": True, "color": WHITE}], fill=TEAL, rounded=True, anchor="ctr", pad_lr=80000, pad_tb=0)
    vt_map = {"GREEN": (GREEN_SOFT, GREEN_LIGHT, GREEN, GREEN_DARK), "TEAL": (TEAL_SOFT, "99F6E4", TEAL, TEAL), "NAVY": ("F1F5F9", BORDER, NAVY, NAVY)}
    for i, (tag, nm, desc, tone) in enumerate(SLIDE20_TIERS):
        cy = 134 + i * 184
        bg, ln, bar, tclr = vt_map[tone]
        s20.add_rect(754, cy, 498, 172, fill=bg, line=ln, line_pt=1.0, rounded=True)
        s20.add_rect(754, cy, 6, 172, fill=bar)
        s20.add_text(772, cy + 14, 466, 146, [
            {"text": tag, "size": 9, "bold": True, "color": tclr, "space_after": 3},
            {"text": nm, "size": 13, "bold": True, "color": NAVY, "space_after": 6},
            {"text": desc, "size": 10, "color": SLATE},
        ], pad_lr=0, pad_tb=0)
    slides.append(s20)

    # ---- Slide 21: Part 2 Cover + Complete Roadmap ----
    s21 = SlideBuilder(21, WHITE)
    s21.add_rect(0, 0, 1280, 108, fill=NAVY)
    s21.add_rect(0, 0, 12, 108, fill=EMERALD)
    s21.add_text(28, 14, 620, 24, [{"text": "PART 2 OF 2 • SLIDES 21–30 • TECHNICAL IMPLEMENTATION & EMPIRICAL RESULTS (v1.0.0)", "size": 9, "bold": True, "color": "A7F3D0", "align": "ctr"}], fill="134E4A", line=EMERALD, line_pt=1.0, rounded=True, anchor="ctr")
    s21.add_text(28, 46, 860, 48, [{"text": "Complete 8-Phase Engineering Roadmap (Phases 0 → 7 ALL DONE)", "size": 22, "bold": True, "color": WHITE}], pad_lr=0, pad_tb=0)
    for i, (v, l, c) in enumerate([("8 / 8", "Phases Done", TEAL_LIGHT), ("88 + 29", "Tests & Subtests", TEAL_LIGHT), ("0", "Defects", "4ADE80")]):
        bx = 928 + i * 110
        s21.add_rect(bx, 22, 100, 64, fill=NAVY_MID, line="334155", line_pt=1.0, rounded=True)
        s21.add_text(bx + 4, 28, 92, 52, [{"text": v, "size": 16, "bold": True, "color": c, "align": "ctr", "space_after": 2}, {"text": l, "size": 8.5, "color": "CBD5E1", "align": "ctr"}], anchor="ctr", pad_lr=0, pad_tb=0)
    s21.add_rect(28, 120, 1224, 38, fill=TEAL_SOFT, line="99F6E4", line_pt=1.0, rounded=True)
    s21.add_rect(28, 120, 6, 38, fill=TEAL)
    s21.add_text(44, 126, 1180, 26, [{"runs": [{"text": "Cumulative Automated Test Growth: ", "size": 10.5, "bold": True, "color": NAVY}, {"text": "2 (P0) → 20 (P2) → 70 (P3) → 82 (P4) → 86 (P6) → 88 + 29 subtests (P7)   |   RELEASE v1.0.0 VERIFIED", "size": 10.5, "bold": True, "color": "0F766E", "font": "Consolas"}]}], anchor="ctr", pad_lr=0, pad_tb=0)
    s21.add_table_flex(
        28, 170, 1224, 504,
        ["Phase", "Status", "Delivered Engineering Milestones", "Verified Proof"],
        [[p, f"✓ {st}", d, t] for p, st, d, t in ROADMAP_ROWS],
        [0.11, 0.11, 0.62, 0.16],
        font_size=10.2, mono_cols={3}, bold_cols={0, 1}, name="RoadmapTable",
    )
    s21.add_rect(0, 688, 1280, 32, fill=BG_LIGHT)
    s21.add_text(28, 692, 1040, 24, [{"text": FOOTER_P2, "size": 8.8, "color": MUTED}], anchor="ctr", pad_lr=0, pad_tb=0)
    s21.add_text(1104, 692, 148, 24, [{"text": f"Slide 21 / {TOTAL_SLIDES:02d}", "size": 9, "bold": True, "color": NAVY, "font": "Consolas", "align": "r"}], anchor="ctr", pad_lr=0, pad_tb=0)
    slides.append(s21)

    # ---- Slide 22: Phase 3 — 17 OWASP Checks & 5-Stack Fix KB ----
    s22 = SlideBuilder(22, WHITE)
    s22.add_chrome("Phase 3: All 17 Curated OWASP Top 10 Checks & 5-Stack Fix KB", "Modular 1-file BaseCheck auto-registry, 85 framework patches, SHA-1 dedup & isolated ScanOrchestrator", "PHASE 3 • 17 CHECKS", 2)
    cols = [
        ("8 Passive Checks (Quick+)", NAVY, PASSIVE_CHECKS),
        ("6 Safe Active Checks (Std / Deep)", TEAL, ACTIVE_CHECKS),
        ("3 Discovery Checks (Std / Deep)", SLATE, DISCOVERY_CHECKS),
    ]
    for ci, (hdr, bg, items) in enumerate(cols):
        cx = 28 + ci * 414
        s22.add_rect(cx, 90, 396, 428, fill=BG_LIGHT, line="E2E8F0", line_pt=1.0, rounded=True)
        s22.add_rect(cx, 90, 396, 34, fill=bg)
        s22.add_text(cx + 12, 96, 370, 22, [{"text": hdr, "size": 10.8, "bold": True, "color": WHITE}], anchor="ctr", pad_lr=0, pad_tb=0)
        for ri, (cid, ow) in enumerate(items):
            ry = 134 + ri * 46
            s22.add_rect(cx + 12, ry, 372, 38, fill=WHITE, line="E2E8F0", line_pt=0.8, rounded=True)
            s22.add_text(cx + 22, ry + 7, 300, 24, [{"text": cid, "size": 10.2, "bold": True, "color": NAVY, "font": "Consolas"}], anchor="ctr", pad_lr=0, pad_tb=0)
            s22.add_text(cx + 330, ry + 8, 44, 22, [{"text": ow, "size": 9, "bold": True, "color": "0369A1", "font": "Consolas", "align": "ctr"}], fill="E0F2FE", rounded=True, anchor="ctr", pad_lr=0, pad_tb=0)
        if ci == 2:
            s22.add_rect(cx + 12, 376, 372, 128, fill=NAVY, rounded=True)
            s22.add_text(cx + 24, 388, 348, 104, [
                {"text": "PROFILE TIERS & 5 FIX STACKS", "size": 9.5, "bold": True, "color": TEAL_LIGHT, "space_after": 10},
                {"text": "Quick: 8   •   Standard: 14   •   Deep: 17", "size": 12, "bold": True, "color": "4ADE80", "align": "ctr", "space_after": 10},
                {"text": "FastAPI • Flask • Express • PHP • HTML", "size": 10.5, "color": "CBD5E1", "align": "ctr"},
            ], pad_lr=0, pad_tb=0)
    _add_bottom_4(s22, [("", t, d) for t, d in P3_ENGINE_CARDS], y=532, h=144)
    slides.append(s22)

    # ---- Slide 23: Phases 4 & 5 — 6-View Workbench & Dark+ Reports ----
    s23 = SlideBuilder(23, WHITE)
    s23.add_chrome("Phases 4 & 5: 6-View Developer Workbench & VS Code Dark+ Reports", "Zero-build Vanilla ES6 workbench with live SSE, Swap & Reset scan diff & offline auto-escaped HTML5 exports", "PHASES 4–5 • UI & REPORTS", 2)
    for idx, (num, nm, desc) in enumerate(P5_VIEWS):
        col = idx % 3
        row = idx // 3
        vx = 28 + col * 414
        vy = 92 + row * 214
        s23.add_rect(vx, vy, 396, 198, fill=BG_LIGHT, line="E2E8F0", line_pt=1.0, rounded=True)
        s23.add_rect(vx, vy, 396, 5, fill=NAVY)
        s23.add_text(vx + 14, vy + 18, 38, 28, [{"text": num, "size": 11, "bold": True, "color": WHITE, "font": "Consolas", "align": "ctr"}], fill=TEAL, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0)
        s23.add_text(vx + 62, vy + 18, 318, 28, [{"text": nm, "size": 14, "bold": True, "color": NAVY}], anchor="ctr", pad_lr=0, pad_tb=0)
        s23.add_text(vx + 14, vy + 58, 368, 128, [{"text": desc, "size": 11, "color": SLATE}], pad_lr=0, pad_tb=0)
    for i, (t, d) in enumerate(P5_PILLS):
        ix = 28 + i * 414
        s23.add_rect(ix, 530, 396, 146, fill=NAVY, rounded=True)
        s23.add_rect(ix, 530, 6, 146, fill=EMERALD)
        s23.add_text(ix + 18, 544, 366, 118, [{"text": t, "size": 11.5, "bold": True, "color": TEAL_LIGHT, "space_after": 6}, {"text": d, "size": 10, "color": "CBD5E1"}], pad_lr=0, pad_tb=0)
    slides.append(s23)

    # ---- Slide 24: Phase 6 — VulnBench & Live NFR-08 Accuracy ----
    s24 = SlideBuilder(24, WHITE)
    s24.add_chrome("Phase 6: Deterministic VulnBench & Live NFR-08 Accuracy Results", "Reproducible empirical evaluation via scripts/evaluate.py across Quick, Standard & Deep profiles", "PHASE 6 • NFR-08 PASS", 2)
    for i, (val, lbl, sub, pct) in enumerate(NFR08_GATES):
        gx = 28 + i * 310
        s24.add_rect(gx, 92, 296, 132, fill=GREEN_SOFT, line=GREEN_LIGHT, line_pt=1.5, rounded=True)
        s24.add_text(gx + 14, 102, 180, 36, [{"text": val, "size": 22, "bold": True, "color": GREEN_DARK}], pad_lr=0, pad_tb=0)
        s24.add_text(gx + 226, 108, 56, 22, [{"text": "PASS", "size": 8.5, "bold": True, "color": WHITE, "align": "ctr"}], fill=GREEN, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0)
        s24.add_text(gx + 14, 142, 268, 22, [{"text": lbl, "size": 11.5, "bold": True, "color": NAVY}], pad_lr=0, pad_tb=0)
        s24.add_rect(gx + 14, 170, 268, 7, fill="DCFCE7", rounded=True)
        s24.add_rect(gx + 14, 170, int(round(268 * pct / 100.0)), 7, fill=GREEN, rounded=True)
        s24.add_text(gx + 14, 184, 268, 28, [{"text": sub, "size": 9.5, "color": SLATE}], pad_lr=0, pad_tb=0)
    s24.add_table_flex(
        28, 244, 1224, 240,
        ["Profile", "Checks", "TP / FP / FN", "Precision", "Recall (All)", "F1 (All)", "Clean FPs", "Route Cov.", "Duration (SLA)"],
        VULNBENCH_ROWS,
        [0.14, 0.08, 0.11, 0.10, 0.11, 0.10, 0.09, 0.13, 0.14],
        font_size=10.2, mono_cols={1, 2, 3, 4, 5, 6, 7, 8}, bold_cols={0}, highlight_row=2, name="VulnBenchTable",
    )
    notes = [
        ("4 Clean /safe/* Negative Controls — 0 False Positives", "/safe/form (CSRF token) • /safe/item (parameterized SQLite) • /safe/redirect (allowlist) • /safe/search (HTML-escaped + strict headers).", BG_LIGHT, BORDER, NAVY),
        ("All 6 OWASP 2021 Categories Beat SAD Ch. 6.4.1 Targets", "100% observed across A01 (4/4), A02 (1/1), A03 (3/3), A05 (9/9), A06 (1/1), A07 (1/1) • 215 Deep requests, Risk 78/100, 0 errors.", TEAL_SOFT, "99F6E4", TEAL),
    ]
    for i, (t, d, bg, ln, bar) in enumerate(notes):
        nx = 28 + i * 620
        s24.add_rect(nx, 504, 604, 170, fill=bg, line=ln, line_pt=1.0, rounded=True)
        s24.add_rect(nx, 504, 6, 170, fill=bar)
        s24.add_text(nx + 20, 522, 568, 136, [{"text": t, "size": 12.5, "bold": True, "color": NAVY, "space_after": 8}, {"text": d, "size": 11, "color": SLATE}], pad_lr=0, pad_tb=0)
    slides.append(s24)

    # ---- Slide 25: Fig 17 Accuracy Benchmark Chart ----
    s25 = SlideBuilder(25, WHITE)
    s25.add_chrome("Accuracy Benchmark Visualization (Figure 17)", "SAD Ch. 6 targets vs. live observed Deep 100.0% Precision / 100.0% Recall / 100.0% F1 (19/19 TP, 0 FP, 0 FN)", "PHASE 6 • FIGURE 17", 2)
    _add_fig(s25, "fig17", img_info, 28, 90, 1224, 430)
    _add_bottom_3(s25, FIG17_CARDS, y=534, h=142)
    slides.append(s25)

    # ---- Slide 26: Fig 18 Coverage & Latency Chart ----
    s26 = SlideBuilder(26, WHITE)
    s26.add_chrome("Coverage & Profile Latency Visualization (Figure 18)", "Live observed durations (1.92s / 20.22s / 21.42s) vs. NFR-02 SLAs & 93.3% (14/15) VulnBench coverage", "PHASE 6 • FIGURE 18", 2)
    _add_fig(s26, "fig18", img_info, 28, 90, 1224, 430)
    _add_bottom_3(s26, FIG18_CARDS, y=534, h=142)
    slides.append(s26)

    # ---- Slide 27: DX Benchmark vs ZAP & Honest Boundaries ----
    s27 = SlideBuilder(27, WHITE)
    s27.add_chrome("Developer-Experience (DX) Benchmark vs. OWASP ZAP & Honest Boundaries", "Structured 5-dimension ergonomics comparison plus transparent academic disclosure of technical limits", "EVALUATION • DX & LIMITS", 2)
    s27.add_table_flex(
        28, 92, 1224, 344,
        ["DX Dimension", "OWASP ZAP Baseline", "OWASP-Lite Scanner (This Project)"],
        [[d, z, o] for d, z, o in DX_ROWS],
        [0.19, 0.39, 0.42],
        font_size=10.5, bold_cols={0, 2}, name="DXTable",
    )
    s27.add_rect(28, 454, 1224, 222, fill=AMBER_SOFT, line="FCD34D", line_pt=1.5, rounded=True)
    s27.add_text(44, 464, 1180, 22, [{"text": "HONEST TECHNICAL BOUNDARIES & THREATS TO VALIDITY (ACADEMIC DISCLOSURE)", "size": 9.8, "bold": True, "color": AMBER_DARK}], pad_lr=0, pad_tb=0)
    for i, (t, d) in enumerate(BOUNDARY_CARDS):
        bx = 44 + i * 402
        s27.add_rect(bx, 494, 388, 166, fill=WHITE, line="FDE68A", line_pt=1.0, rounded=True)
        s27.add_text(bx + 14, 506, 360, 144, [{"text": t, "size": 11.5, "bold": True, "color": NAVY, "space_after": 6}, {"text": d, "size": 10.2, "color": SLATE}], pad_lr=0, pad_tb=0)
    slides.append(s27)

    # ---- Slide 28: Phase 7 Self-Scan Audit & Security Hardening ----
    s28 = SlideBuilder(28, WHITE)
    s28.add_chrome("Phase 7: Live Self-Scan Audit & Security Hardening", "Dogfooding our own Deep 17-check scan on http://127.0.0.1:8000 — Risk halved (6 → 3/100) with CI guard", "PHASE 7 • SELF-SCAN", 2)
    s28.add_text(
        28, 92, 1224, 42,
        [{"text": "Target: http://127.0.0.1:8000   •   Profile: Deep (17/17 checks)   •   83 HTTP Requests   •   0 Errors   •   0 CRITICAL • 0 HIGH", "size": 11.2, "bold": True, "color": TEAL_LIGHT, "align": "ctr"}],
        fill=NAVY, rounded=True, anchor="ctr",
    )
    # Before card
    s28.add_rect(28, 150, 576, 250, fill=AMBER_SOFT, line=AMBER, line_pt=2.0, rounded=True)
    s28.add_text(46, 164, 240, 26, [{"text": "BEFORE HARDENING (BASELINE)", "size": 9, "bold": True, "color": WHITE, "align": "ctr"}], fill=AMBER, rounded=True, anchor="ctr")
    s28.add_text(418, 160, 170, 34, [{"text": "Risk 6 / 100", "size": 18, "bold": True, "color": AMBER_DARK, "align": "r"}], pad_lr=0, pad_tb=0)
    s28.add_text(46, 206, 540, 180, [
        {"bullet": True, "space_after": 10, "text": "0 Critical • 0 High • 2 Medium (missing_security_headers + weak_csp)", "size": 11, "bold": True, "color": NAVY},
        {"bullet": True, "space_after": 10, "text": "Permissions-Policy header absent; object-src 'none' not explicitly set.", "size": 11, "color": SLATE},
        {"bullet": True, "space_after": 6, "text": "Default Uvicorn Server banner and static asset caching active.", "size": 11, "color": SLATE},
    ], pad_lr=0, pad_tb=0)
    s28.add_text(608, 250, 64, 50, [{"text": "→", "size": 28, "bold": True, "color": TEAL, "align": "ctr"}], anchor="ctr", pad_lr=0, pad_tb=0)
    # After card
    s28.add_rect(676, 150, 576, 250, fill=GREEN_SOFT, line=GREEN, line_pt=2.0, rounded=True)
    s28.add_text(694, 164, 260, 26, [{"text": "AFTER PHASE 7 HARDENING (-50%)", "size": 9, "bold": True, "color": WHITE, "align": "ctr"}], fill=GREEN, rounded=True, anchor="ctr")
    s28.add_text(1066, 160, 170, 34, [{"text": "Risk 3 / 100", "size": 18, "bold": True, "color": GREEN_DARK, "align": "r"}], pad_lr=0, pad_tb=0)
    s28.add_text(694, 206, 540, 180, [
        {"bullet": True, "space_after": 10, "text": "0 Critical • 0 High • 0 missing_security_headers • 0 server_banner_leak", "size": 11, "bold": True, "color": NAVY},
        {"bullet": True, "space_after": 10, "text": "16/17 checks pass clean; scoped /docs CSP preserves Swagger while locking app script-src.", "size": 11, "color": SLATE},
        {"bullet": True, "space_after": 6, "text": "Single Medium (style-src 'unsafe-inline') transparently documented for zero-build Tailwind UI.", "size": 11, "color": SLATE},
    ], pad_lr=0, pad_tb=0)
    # 5 hardening actions
    for i, (t, d) in enumerate(HARDENING_ACTIONS):
        hx = 28 + i * 247
        s28.add_rect(hx, 420, 236, 254, fill=BG_LIGHT, line=BORDER, line_pt=1.0, rounded=True)
        s28.add_rect(hx, 420, 236, 5, fill=TEAL)
        s28.add_text(hx + 12, 438, 212, 224, [{"text": t, "size": 11, "bold": True, "color": NAVY, "space_after": 8}, {"text": d, "size": 10, "color": SLATE}], pad_lr=0, pad_tb=0)
    slides.append(s28)

    # ---- Slide 29: Fig 9 Docker + 88-Test Pyramid + 3-Job CI ----
    s29 = SlideBuilder(29, WHITE)
    s29.add_chrome("Multi-Container Docker Deployment, 88-Test Pyramid & 3-Job CI", "Containerized local stack (Figure 9), 5-tier verification pyramid & automated GitHub Actions pipeline", "PHASE 7 • FIG. 9 • 88 TESTS", 2)
    _add_fig(s29, "fig09", img_info, 28, 90, 740, 452)
    s29.add_rect(28, 554, 740, 122, fill=BG_LIGHT, line="E2E8F0", line_pt=1.0, rounded=True)
    s29.add_rect(28, 554, 740, 30, fill=NAVY)
    s29.add_text(40, 558, 540, 22, [{"text": "3-Job GitHub Actions CI (.github/workflows/ci.yml)", "size": 10, "bold": True, "color": WHITE}], anchor="ctr", pad_lr=0, pad_tb=0)
    s29.add_text(682, 559, 76, 20, [{"text": "3/3 GREEN", "size": 8, "bold": True, "color": WHITE, "align": "ctr"}], fill=GREEN, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0)
    for i, (job, desc) in enumerate(CI_JOBS):
        jx = 40 + i * 242
        s29.add_rect(jx, 594, 232, 72, fill=WHITE, line=BORDER, line_pt=0.8, rounded=True)
        s29.add_rect(jx, 594, 4, 72, fill=GREEN)
        s29.add_text(jx + 12, 602, 212, 56, [{"text": job, "size": 9.8, "bold": True, "color": NAVY, "font": "Consolas", "space_after": 4}, {"text": desc, "size": 9.2, "color": SLATE}], pad_lr=0, pad_tb=0)
    # Right side: Pass banner + 5-tier pyramid
    s29.add_rect(784, 90, 468, 76, fill=GREEN_SOFT, line=GREEN, line_pt=2.0, rounded=True)
    s29.add_text(798, 108, 40, 40, [{"text": "✓", "size": 18, "bold": True, "color": WHITE, "align": "ctr"}], fill=GREEN, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0)
    s29.add_text(850, 100, 390, 58, [{"text": "88 Passed + 29 Subtests", "size": 15.5, "bold": True, "color": GREEN_DARK, "space_after": 3}, {"text": "24.71s • 0 failures • 0 errors", "size": 10, "bold": True, "color": SLATE, "font": "Consolas"}], pad_lr=0, pad_tb=0)
    s29.add_rect(784, 180, 468, 496, fill=BG_LIGHT, line="E2E8F0", line_pt=1.0, rounded=True)
    s29.add_rect(784, 180, 468, 34, fill=TEAL)
    s29.add_text(798, 186, 360, 22, [{"text": "5-Tier Automated Test Pyramid", "size": 11, "bold": True, "color": WHITE}], anchor="ctr", pad_lr=0, pad_tb=0)
    bar_clrs = {"teal": TEAL, "navy": NAVY, "green": GREEN}
    for i, (nm, src, cnt, pct, tone) in enumerate(TEST_TIERS):
        ty = 228 + i * 78
        s29.add_text(800, ty, 360, 20, [{"text": nm, "size": 10.5, "bold": True, "color": NAVY}], pad_lr=0, pad_tb=0)
        s29.add_text(1176, ty, 60, 20, [{"text": cnt, "size": 10.5, "bold": True, "color": TEAL, "font": "Consolas", "align": "r"}], pad_lr=0, pad_tb=0)
        s29.add_rect(800, ty + 24, 436, 10, fill="E2E8F0", rounded=True)
        s29.add_rect(800, ty + 24, max(24, int(round(436 * pct / 100.0))), 10, fill=bar_clrs[tone], rounded=True)
        s29.add_text(800, ty + 38, 436, 18, [{"text": src, "size": 9, "color": MUTED, "font": "Consolas"}], pad_lr=0, pad_tb=0)
    s29.add_rect(784, 634, 468, 42, fill="F1F5F9")
    s29.add_text(800, 642, 436, 26, [{"text": "Total: 2 + 70 + 10 + 4 + 2 = 88 + 29 subtests", "size": 10.5, "bold": True, "color": GREEN_DARK, "font": "Consolas", "align": "ctr"}], anchor="ctr", pad_lr=0, pad_tb=0)
    slides.append(s29)

    # ---- Slide 30: Dark Navy Closing ----
    s30 = SlideBuilder(30, NAVY)
    s30.add_rect(0, 0, 12, 720, fill=TEAL_BRIGHT)
    s30.add_text(56, 22, 540, 24, [{"text": "FINAL GRADUATION DEFENSE • RELEASE v1.0.0 • ALL 8 PHASES & 19 DIAGRAMS", "size": 8.8, "bold": True, "color": TEAL_LIGHT, "align": "ctr"}], fill="134E4A", line=TEAL_BRIGHT, line_pt=1.0, rounded=True, anchor="ctr")
    s30.add_text(56, 52, 680, 42, [{"text": "3-Min Live Demo, Team Contributions & Q&A", "size": 24, "bold": True, "color": WHITE}], pad_lr=0, pad_tb=0)
    s30.add_rect(756, 30, 478, 56, fill=NAVY_MID, line=TEAL_BRIGHT, line_pt=1.0, rounded=True)
    s30.add_text(768, 36, 454, 44, [{"text": "GITHUB REPOSITORY", "size": 8, "bold": True, "color": TEAL_LIGHT, "align": "r", "space_after": 2}, {"text": "https://github.com/mohammewaleed/Graduation-Project-2027", "size": 9.2, "color": WHITE, "font": "Consolas", "align": "r"}], pad_lr=0, pad_tb=0)
    # Compact 5-step live demo bar
    for i, (num, tm, t, d) in enumerate(DEMO_STEPS):
        dx = 56 + i * 238
        s30.add_rect(dx, 106, 228, 108, fill=NAVY_MID, line="334155", line_pt=1.0, rounded=True)
        s30.add_rect(dx, 106, 228, 4, fill=TEAL_BRIGHT)
        s30.add_text(dx + 10, 116, 32, 18, [{"text": num, "size": 8.5, "bold": True, "color": WHITE, "font": "Consolas", "align": "ctr"}], fill=TEAL, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0)
        s30.add_text(dx + 148, 116, 70, 18, [{"text": tm, "size": 8.5, "bold": True, "color": TEAL_LIGHT, "font": "Consolas", "align": "r"}], anchor="ctr", pad_lr=0, pad_tb=0)
        s30.add_text(dx + 10, 140, 208, 68, [{"text": t, "size": 10, "bold": True, "color": WHITE, "space_after": 3}, {"text": d, "size": 8.8, "color": "CBD5E1"}], pad_lr=0, pad_tb=0)
    # 7-member team table
    s30.add_table_flex(
        56, 228, 1178, 362,
        ["Team Member", "Student ID", "Role & Delivered Module Ownership"],
        [[m[0], m[1], m[2]] for m in TEAM_ROSTER],
        [0.28, 0.12, 0.60],
        dark=True, font_size=10.2, mono_cols={1}, bold_cols={0, 1}, name="TeamRoster",
    )
    # Closing banner + Q&A
    s30.add_rect(56, 608, 1178, 86, fill="134E4A", line=TEAL_BRIGHT, line_pt=1.5, rounded=True)
    s30.add_text(78, 622, 970, 60, [
        {"text": "OWASP-Lite Scanner v1.0.0 — Architected, Verified, Hardened & Ready for Live Defense", "size": 15, "bold": True, "color": WHITE, "space_after": 4},
        {"text": "Department of Cyber Security • Academic Year 2026–2027 • Prepared for Dr. Samar • 30 Slides • 19/19 Original Diagrams", "size": 10, "color": "CBD5E1"},
    ], pad_lr=0, pad_tb=0)
    s30.add_text(1090, 624, 122, 54, [{"text": "Q & A", "size": 18, "bold": True, "color": NAVY, "align": "ctr"}], fill=TEAL_BRIGHT, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0)
    slides.append(s30)

    return slides


def write_pptx(out_path: Path) -> None:
    img_info: dict[str, tuple[str, int, int]] = {}
    media_files: list[tuple[str, bytes]] = []
    for idx, (key, (stem, _, _)) in enumerate(FIGURES.items(), start=1):
        png_path = PNG_DIR / f"{stem}.png"
        if not png_path.exists():
            raise FileNotFoundError(f"Original PNG missing: {png_path}")
        with Image.open(png_path) as im:
            w, h = im.size
        mname = f"image{idx:02d}.png"
        img_info[key] = (mname, w, h)
        media_files.append((mname, png_path.read_bytes()))

    slides = build_pptx_slides(img_info)
    n_slides = len(slides)
    assert n_slides == TOTAL_SLIDES, f"Expected {TOTAL_SLIDES} PPTX slides, built {n_slides}"

    slide_overrides = "".join(
        f'<Override PartName="/ppt/slides/slide{i}.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>'
        for i in range(1, n_slides + 1)
    )
    content_types = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="png" ContentType="image/png"/>
  <Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>
  <Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>
  <Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>
  <Override PartName="/ppt/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>
  <Override PartName="/ppt/presProps.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presProps+xml"/>
  <Override PartName="/ppt/viewProps.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.viewProps+xml"/>
  <Override PartName="/ppt/tableStyles.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.tableStyles+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
  {slide_overrides}
</Types>"""

    root_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>"""

    core_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                   xmlns:dc="http://purl.org/dc/elements/1.1/"
                   xmlns:dcterms="http://purl.org/dc/terms/"
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:title>Full Graduation Defense — Lightweight OWASP Top 10 Vulnerability Scanner (SAD + v1.0.0)</dc:title>
  <dc:creator>Graduation Project Team (2026–2027)</dc:creator>
  <dc:subject>Prepared for Dr. Samar — Department of Cyber Security</dc:subject>
</cp:coreProperties>"""

    app_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
  <Application>Microsoft Office PowerPoint</Application>
  <PresentationFormat>Widescreen</PresentationFormat>
  <Slides>{n_slides}</Slides>
</Properties>"""

    sld_id_list = "".join(
        f'<p:sldId id="{256 + i}" r:id="rId{i + 1}"/>' for i in range(1, n_slides + 1)
    )
    presentation_xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
                xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
                xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"
                saveSubsetFonts="1">
  <p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId1"/></p:sldMasterIdLst>
  <p:sldIdLst>{sld_id_list}</p:sldIdLst>
  <p:sldSz cx="{SLIDE_W}" cy="{SLIDE_H}" type="screen16x9"/>
  <p:notesSz cx="6858000" cy="9144000"/>
</p:presentation>"""

    pres_rels_items = [
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="slideMasters/slideMaster1.xml"/>'
    ]
    for i in range(1, n_slides + 1):
        pres_rels_items.append(
            f'<Relationship Id="rId{i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide{i}.xml"/>'
        )
    base_rid = n_slides + 2
    pres_rels_items.extend([
        f'<Relationship Id="rId{base_rid}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/presProps" Target="presProps.xml"/>',
        f'<Relationship Id="rId{base_rid + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/viewProps" Target="viewProps.xml"/>',
        f'<Relationship Id="rId{base_rid + 2}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="theme/theme1.xml"/>',
        f'<Relationship Id="rId{base_rid + 3}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/tableStyles" Target="tableStyles.xml"/>',
    ])
    pres_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + "".join(pres_rels_items)
        + "</Relationships>"
    )

    slide_master_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldMaster xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
             xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
             xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld>
    <p:bg><p:bgRef idx="1001"><a:schemeClr val="bg1"/></p:bgRef></p:bg>
    <p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
      <p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>
    </p:spTree>
  </p:cSld>
  <p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>
  <p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst>
</p:sldMaster>"""

    slide_master_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="../theme/theme1.xml"/>
</Relationships>"""

    slide_layout_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldLayout xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
             xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
             xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"
             type="blank" preserve="1">
  <p:cSld name="Blank">
    <p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
      <p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>
    </p:spTree>
  </p:cSld>
  <p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr>
</p:sldLayout>"""

    slide_layout_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="../slideMasters/slideMaster1.xml"/>
</Relationships>"""

    theme_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="CyberAcademic">
  <a:themeElements>
    <a:clrScheme name="CyberAcademic">
      <a:dk1><a:srgbClr val="0F172A"/></a:dk1>
      <a:lt1><a:srgbClr val="FFFFFF"/></a:lt1>
      <a:dk2><a:srgbClr val="1E293B"/></a:dk2>
      <a:lt2><a:srgbClr val="F8FAFC"/></a:lt2>
      <a:accent1><a:srgbClr val="0D9488"/></a:accent1>
      <a:accent2><a:srgbClr val="14B8A6"/></a:accent2>
      <a:accent3><a:srgbClr val="0284C7"/></a:accent3>
      <a:accent4><a:srgbClr val="16A34A"/></a:accent4>
      <a:accent5><a:srgbClr val="D97706"/></a:accent5>
      <a:accent6><a:srgbClr val="64748B"/></a:accent6>
      <a:hlink><a:srgbClr val="0D9488"/></a:hlink>
      <a:folHlink><a:srgbClr val="0F766E"/></a:folHlink>
    </a:clrScheme>
    <a:fontScheme name="CyberAcademic">
      <a:majorFont><a:latin typeface="Segoe UI"/><a:ea typeface=""/><a:cs typeface=""/></a:majorFont>
      <a:minorFont><a:latin typeface="Segoe UI"/><a:ea typeface=""/><a:cs typeface=""/></a:minorFont>
    </a:fontScheme>
    <a:fmtScheme name="CyberAcademic">
      <a:fillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:fillStyleLst>
      <a:lnStyleLst><a:ln w="9525"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln><a:ln w="19050"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln><a:ln w="28575"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln></a:lnStyleLst>
      <a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst>
      <a:bgFillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:bgFillStyleLst>
    </a:fmtScheme>
  </a:themeElements>
</a:theme>"""

    pres_props = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:presentationPr xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"/>'
    view_props = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><p:viewPr xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"/>'
    table_styles = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><a:tblStyleLst xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" def="{5C22544A-7EE6-4342-B048-85BDC9FD1C3A}"/>'

    with zipfile.ZipFile(out_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", root_rels)
        zf.writestr("docProps/core.xml", core_xml)
        zf.writestr("docProps/app.xml", app_xml)
        zf.writestr("ppt/presentation.xml", presentation_xml)
        zf.writestr("ppt/_rels/presentation.xml.rels", pres_rels)
        zf.writestr("ppt/presProps.xml", pres_props)
        zf.writestr("ppt/viewProps.xml", view_props)
        zf.writestr("ppt/tableStyles.xml", table_styles)
        zf.writestr("ppt/theme/theme1.xml", theme_xml)
        zf.writestr("ppt/slideMasters/slideMaster1.xml", slide_master_xml)
        zf.writestr("ppt/slideMasters/_rels/slideMaster1.xml.rels", slide_master_rels)
        zf.writestr("ppt/slideLayouts/slideLayout1.xml", slide_layout_xml)
        zf.writestr("ppt/slideLayouts/_rels/slideLayout1.xml.rels", slide_layout_rels)
        for mname, mbytes in media_files:
            zf.writestr(f"ppt/media/{mname}", mbytes)
        for idx, sb in enumerate(slides, start=1):
            zf.writestr(f"ppt/slides/slide{idx}.xml", sb.to_slide_xml())
            zf.writestr(f"ppt/slides/_rels/slide{idx}.xml.rels", sb.to_rels_xml())


# =============================================================================
# 5. COMPREHENSIVE VALIDATION (HTML + PPTX + PDF)
# =============================================================================


def validate_outputs() -> None:
    # 1. Validate PPTX (OOXML structure, 30 slides, 19 original PNGs)
    with zipfile.ZipFile(OUT_PPTX, "r") as zf:
        names = set(zf.namelist())
        for name in names:
            if name.endswith(".xml") or name.endswith(".rels"):
                ET.fromstring(zf.read(name))
        for i in range(1, TOTAL_SLIDES + 1):
            assert f"ppt/slides/slide{i}.xml" in names, f"Missing slide{i}.xml"
            assert f"ppt/slides/_rels/slide{i}.xml.rels" in names, f"Missing slide{i}.xml.rels"
        assert f"ppt/slides/slide{TOTAL_SLIDES + 1}.xml" not in names, "Extra slide detected"
        media = sorted(n for n in names if n.startswith("ppt/media/"))
        assert len(media) == 19, f"Expected 19 embedded PNGs, got {len(media)}"
        for m in media:
            raw = zf.read(m)
            assert raw[:8] == b"\x89PNG\r\n\x1a\n", f"Invalid PNG signature in {m}"

    # 2. Validate HTML (30 slides, 19 inline SVGs, 0 duplicate IDs, 0 external CDN refs)
    html_text = OUT_HTML.read_text(encoding="utf-8")
    slide_count = len(re.findall(r'<section class="slide\b', html_text))
    assert slide_count == TOTAL_SLIDES, f"HTML slide count mismatch: {slide_count} != {TOTAL_SLIDES}"
    svg_count = html_text.count('class="zv-svg"')
    assert svg_count == 19, f"Expected 19 inline SVGs, got {svg_count}"
    for key in FIGURES:
        assert f'data-fig="{key}"' in html_text, f"Missing figure viewer {key}"

    # Check zero duplicate DOM id="..." across entire HTML (excluding JS string literals)
    body_only = html_text.split("<script>")[0]
    all_ids = re.findall(r'\bid="([^"]+)"', body_only)
    dups = {i for i in all_ids if all_ids.count(i) > 1}
    assert not dups, f"Duplicate DOM IDs detected in HTML: {sorted(dups)[:10]}"

    lower_html = html_text.lower()
    assert "cdn." not in lower_html and "fonts.googleapis" not in lower_html, "External CDN reference detected!"
    assert "Part 1: SAD" in html_text and "Part 2: Technical" in html_text, "Part jump tabs missing!"

    # 3. Validate PDF (%PDF- header + exact 30 pages)
    pdf_bytes = OUT_PDF.read_bytes()
    assert pdf_bytes.startswith(b"%PDF-"), "PDF missing %PDF- header"
    pdf_pages = len(re.findall(rb"/Type\s*/Page\b(?!s)", pdf_bytes))
    assert pdf_pages == TOTAL_SLIDES, f"PDF page count mismatch: {pdf_pages} != {TOTAL_SLIDES}"


def main() -> int:
    PRES_DIR.mkdir(parents=True, exist_ok=True)
    svgs = load_all_svgs()
    print(f"[OK] Loaded & namespaced {len(svgs)}/19 original SVGs from {SVG_DIR}")

    OUT_HTML.write_text(build_html(svgs), encoding="utf-8")
    print(f"[OK] Wrote {OUT_HTML} ({OUT_HTML.stat().st_size:,} bytes)")

    build_pdf(OUT_HTML, OUT_PDF)
    print(f"[OK] Wrote {OUT_PDF} ({OUT_PDF.stat().st_size:,} bytes)")

    write_pptx(OUT_PPTX)
    print(f"[OK] Wrote {OUT_PPTX} ({OUT_PPTX.stat().st_size:,} bytes)")

    validate_outputs()
    print(f"[OK] Validated all 3 artifacts: {TOTAL_SLIDES} slides, 19/19 original SVGs (HTML) & 19/19 PNGs (PPTX), 30 PDF pages, 0 duplicate IDs, 0 external CDNs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
