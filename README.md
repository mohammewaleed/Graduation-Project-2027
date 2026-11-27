# Lightweight OWASP Top 10 Vulnerability Scanner (Developer-Experience Focus)

> **Graduation Project** — *Developing a Lightweight OWASP Top 10 Vulnerability Scanner Tailored for Web Developers and Student Projects*  
> **Department of Cyber Security** · **Academic Year 2026–2027** · **Project Supervisor:** Dr. Samar

| # | Team Member | Student ID |
| :-: | :--- | :---: |
| 1 | Ahmed Ashraf Ammar | `235204` |
| 2 | Islam Mohammed | `235164` |
| 3 | Abdelrhman Mohamed AbdEl-latif | `235216` |
| 4 | Ahmed Waleed Mokthar | `235052` |
| 5 | Mohamed Waleed Mokthar | `235051` |
| 6 | Mohamed Ibrahim Elsayed | `235401` |
| 7 | Ali Ibrahim Elsayed | `235332` |

---

## Overview

Enterprise DAST platforms like OWASP ZAP and Burp Suite are powerful, yet their JVM setup overhead, proxy CA certificates, complex policy tuning, and analyst-oriented alert dumps create high friction for web developers and students testing local web applications.

**OWASP-Lite Scanner** is a **lightweight, zero-config, ethical-by-design OWASP Top 10 (2021) vulnerability scanner** built around **Developer Experience (DX)** and aligned with the **NIST Secure Software Development Framework (SSDF, SP 800-218)**:

- **17 Curated OWASP Top 10 (2021) Checks**: 8 Passive, 6 Active Safe, and 3 Discovery checks across `A01`, `A02`, `A03`, `A05`, `A06`, and `A07`, organized into `Quick`, `Standard`, and `Deep` scan profiles.
- **6-View Dark/Light Developer Dashboard**: Zero-build HTML5 + Tailwind CSS + Modular Vanilla JS ES Modules workbench (`Overview & Projects`, `Scan Launcher`, `Live Scan Progress`, `Findings Explorer`, `Compare Scans`, and `OWASP Check Catalog`) with **zero `innerHTML`** and **zero inline JS handlers**.
- **VS Code Dark+ Multi-Stack Before/After Code Fixes**: Interactive remediation modal providing copy-ready **Before / After** patches tailored for **FastAPI, Flask, Express, PHP, and HTML** backed by `backend/scanner/remediation/kb.json`.
- **Real-Time SSE Progress & Cancellation**: Live scan telemetry over Server-Sent Events (`GET /api/scans/{id}/stream`) with deterministic cooperative mid-scan cancellation (`POST /api/scans/{id}/cancel`) and zero external message-broker overhead.
- **Deterministic SHA-1 Cross-Scan Diff**: Compare any two scans of a project to track **`Fixed`**, **`New`**, and **`Unchanged`** findings with one-click **Reset & Swap** controls and Risk Score delta tracking.
- **Offline Autoescaped HTML5 & JSON Reports**: Export self-contained, print-ready HTML5 (`GET /api/scans/{id}/report.html`, Jinja2 autoescaped with zero `|safe` bypasses) and structured JSON (`report.json`) reports.
- **Strict Loopback & Private-Network Safety Guardrails**: Hardcoded local/RFC1918 allow-list (`localhost`, `127.0.0.1`, `host.docker.internal`, local Docker targets), pre-request DNS-rebinding defense, same-origin redirect validation, destructive-path exclusion (`/logout`, `/delete`), token-bucket rate limiting, Soft-404 calibration, and mandatory ownership confirmation.

---

## Architecture Summary

| Layer | Technology | Responsibilities |
| :--- | :--- | :--- |
| **Backend API** | Python 3.12, FastAPI, Uvicorn, Pydantic v2, `pydantic-settings` | Typed `/api` REST routers (`health`, `projects`, `scans`, `findings`, `reports`, `checks`), SSE streaming, security headers middleware, error envelopes, static UI serving |
| **Worker & Telemetry** | Bounded `ThreadPoolExecutor`, `threading.Event` registry, SSE | Non-blocking background scan execution, cooperative cancellation, live progress broadcast (`backend/app/worker.py`) |
| **Scanning Engine** | Pure Python (`requests`, `BeautifulSoup4`, `lxml`, `packaging`) | `ScopeGuardrail`, rate-limited HTTP client + Soft-404 calibration + DVWA auto-login, BFS crawler, `BaseCheck` auto-registry, deterministic SHA-1 fingerprinting & risk scoring, JSON remediation KB |
| **Persistence** | SQLAlchemy 2.0 ORM (SQLite WAL default + optional PostgreSQL 16) | Zero-config single-file `data/scanner.db` out of the box, or drop-in PostgreSQL via `DATABASE_URL` and `--profile postgres` |
| **Frontend UI** | HTML5, Tailwind CSS, Modular Vanilla JS (ES Modules) | Zero-build 6-view Dark/Light dashboard, SVG severity/OWASP charts, VS Code Dark+ fix modal, live SSE monitor, and diff view |
| **Reports** | Jinja2 (`autoescape=True`) & JSON serializer | Offline HTML5 printable reports (`backend/app/reports/templates/report.html.j2`) and machine-readable JSON exports |
| **Containerization & Testbench** | Multi-stage `Dockerfile` (non-root `scanner`, `--no-server-header`), Docker Compose | Reproducible local deployment plus isolated loopback testbench (`VulnBench`, DVWA, OWASP Juice Shop) |

---

## Repository Map

```text
.
├── .env.example                            # Default environment, DB, and scope guardrail settings
├── .gitignore                              # Python, venv, SQLite DB, and cache ignores
├── Dockerfile                              # Multi-stage Python 3.12 slim image (non-root, --no-server-header)
├── docker-compose.yml                      # Scanner service (SQLite WAL) + optional PostgreSQL 16 profile
├── docker-compose.testbench.yml            # Isolated local testbench (DVWA, OWASP Juice Shop, VulnBench)
├── README.md                               # Project overview, Quick Start, catalog, and deliverables index
├── backend/
│   ├── requirements.txt                    # Pinned Python 3.12 dependencies
│   ├── app/
│   │   ├── config.py                       # pydantic-settings configuration & allow-list defaults
│   │   ├── database.py                     # SQLAlchemy 2.0 engine (SQLite WAL + PostgreSQL)
│   │   ├── db_models.py                    # 3NF ORM tables (projects, scans, findings, endpoints)
│   │   ├── main.py                         # FastAPI factory, hardened SECURITY_HEADERS, CORS, static UI
│   │   ├── schemas.py                      # Pydantic v2 request/response DTOs & error envelopes
│   │   ├── worker.py                       # Bounded ThreadPoolExecutor + SSE broadcaster + cancel registry
│   │   ├── reports/
│   │   │   ├── generator.py                # Autoescaped HTML5 & JSON report generator
│   │   │   └── templates/report.html.j2    # Self-contained offline printable HTML5 report template
│   │   └── routers/                        # health.py, projects.py, scans.py, findings.py, reports.py, checks.py
│   ├── scanner/
│   │   ├── policy.py                       # ScopeGuardrail (allow-list, DNS-rebinding & redirect checks)
│   │   ├── http_client.py                  # Token-bucket HTTP client, Soft-404 calibration, DVWA auto-login
│   │   ├── crawler.py                      # Same-origin BFS crawler, DOM/form extractor, ResponseCache
│   │   ├── models.py                       # Pure Python dataclasses & enums (ScanProfile, Severity, RawFinding)
│   │   ├── scoring.py                      # Canonical SHA-1 fingerprint, deduplication & 0–100 risk score
│   │   ├── orchestrator.py                 # End-to-end scan pipeline with per-check error isolation
│   │   ├── remediation/
│   │   │   ├── kb.json                     # 17-check multi-stack (FastAPI/Flask/Express/PHP/HTML) fix KB
│   │   │   └── loader.py                   # Remediation enrichment loader
│   │   └── checks/
│   │       ├── base.py                     # BaseCheck ABC, CheckContext & __init_subclass__ auto-registry
│   │       ├── passive/                    # banners.py, components.py, cookies.py, csrf.py, errors.py, headers.py, transport.py
│   │       ├── active/                     # cors.py, idor.py, redirect.py, sqli.py, xss.py
│   │       └── discovery/                  # dir_listing.py, forced_browsing.py, sensitive_files.py
│   └── tests/
│       ├── test_health.py                  # API health, static UI & baseline security header tests
│       ├── unit/                           # Unit tests for policy, HTTP client, crawler, all 17 checks, orchestrator
│       └── integration/
│           ├── test_api_e2e.py             # End-to-end FastAPI CRUD, SSE, diff & report export tests
│           ├── test_vulnbench_accuracy.py  # Automated precision/recall/F1 regression gate against VulnBench
│           └── test_self_scan_hardening.py # Phase 7 self-scan security header & posture regression tests
├── frontend/
│   ├── index.html                          # 6-view Dark/Light workbench shell (zero inline JS)
│   ├── css/styles.css                      # Theme tokens, layout & VS Code Dark+ code block styling
│   └── js/
│       ├── api.js                          # Typed Fetch & EventSource API client
│       ├── app.js                          # 6-view SPA controller, theme persistence & project/scan workflows
│       ├── utils.js                        # Safe DOM builder (el/clear), badges & toast notifications
│       └── components/                     # charts.js, compare_view.js, findings_explorer.js, fix_modal.js, scan_live.js
├── testbench/
│   ├── ground_truth.json                   # Machine-verifiable manifest (19 seeded flaws + 4 /safe/* controls)
│   └── vulnbench/
│       ├── app.py                          # Deterministic Python stdlib + SQLite vulnerable benchmark app
│       └── Dockerfile                      # Standalone VulnBench container (127.0.0.1:5050)
├── scripts/
│   ├── evaluate.py                         # Automated VulnBench Precision/Recall/F1 evaluator & report writer
│   ├── render_diagrams.py                  # Offline Mermaid → SVG/PNG diagram renderer
│   ├── build_sad_html.py                   # Printable offline HTML5 SAD book builder
│   ├── build_sad_docx.py                   # Native Word (.docx) SAD book builder
│   ├── build_sad_pdf.py                    # Formal A4 PDF SAD book builder
│   ├── build_semester_editions.py          # Semester 1 & Semester 2 split package builder
│   └── build_presentation.py               # Semester 1 Progress & Architecture Defense PPTX/PDF/HTML builder
└── docs/
    ├── SAD.md                              # Master Software Architecture Document index & metadata
    ├── SAD_Book.pdf                        # Formal A4 PDF Graduation Project Book (also .docx, .md, Printable .html)
    ├── TESTBENCH_RESULTS.md                # Phase 6 empirical VulnBench evaluation & OWASP ZAP DX comparison
    ├── SELF_SCAN_REPORT.md                 # Phase 7 self-scan audit & hardening verification report
    ├── sad_chapters/                       # Chapters 1–6 standalone Markdown sources
    ├── diagrams/                           # 19 Mermaid sources (.mmd) + rendered PNG/SVG images
    ├── semester_1/                         # Semester 1 split deliverables (Chapters 1–3 + 15 figures)
    ├── semester_2/                         # Semester 2 split deliverables (Chapters 4–6 + 4 figures)
    └── presentations/                      # Semester1_Progress_Defense.{pptx,pdf,html}
```

---

## 3-Minute Quick Start

### Option A: Docker Compose (Recommended)

```bash
# 1. (Optional) Copy environment defaults — works out of the box without editing
cp .env.example .env

# 2. Build and start the scanner (SQLite WAL persistence on ./data)
docker compose up --build
```

Open **http://localhost:8000** for the Developer Dashboard, **http://localhost:8000/docs** for interactive OpenAPI/Swagger docs, and **http://localhost:8000/api/health** for live readiness status.

#### Optional: Run with PostgreSQL 16

```bash
DATABASE_URL=postgresql+psycopg://scanner:scanner@postgres:5432/scanner \
  docker compose --profile postgres up --build
```

#### Optional: Launch the Isolated Local Vulnerable Testbench

```bash
docker compose -f docker-compose.testbench.yml up -d
```

All three testbench services bind strictly to `127.0.0.1` on an isolated `testbench_net` bridge network:

- **VulnBench** (Deterministic benchmark): `http://127.0.0.1:5050`
- **DVWA** (Authenticated server-rendered benchmark): `http://127.0.0.1:8080`
- **OWASP Juice Shop** (Modern SPA benchmark): `http://127.0.0.1:3000`

---

### Option B: Native Python 3.12 Virtual Environment

Requires **Python 3.12** (`py -3.12` on Windows or `python3.12` on Linux/macOS).

```powershell
# 1. Create and activate a Python 3.12 virtual environment (Windows PowerShell)
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1

# Linux / macOS:
# python3.12 -m venv .venv && source .venv/bin/activate

# 2. Install pinned backend dependencies
pip install -r backend/requirements.txt

# 3. Start the hardened FastAPI server (suppresses Uvicorn Server banner)
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --no-server-header
```

#### Run Standalone `VulnBench`, Automated Evaluation & Full Test Suite

```powershell
# Start standalone deterministic VulnBench locally (in a separate terminal)
py -3.12 -m testbench.vulnbench.app --host 127.0.0.1 --port 5050

# Run the automated VulnBench Quick / Standard / Deep benchmark (auto-starts ephemeral VulnBench)
py -3.12 scripts/evaluate.py --auto-start-vulnbench --benchmark-all-profiles --write-report docs/TESTBENCH_RESULTS.md

# Execute the complete unit + integration + hardening test suite
pytest backend/tests -v
```

---

## Complete 17 OWASP Top 10 (2021) Checks Catalog

All 17 checks live under `backend/scanner/checks/` and auto-register into `BaseCheck.registry` at startup. Each check maps 1-to-1 to a multi-stack remediation entry in `backend/scanner/remediation/kb.json`.

| # | Check ID | Kind | OWASP Top 10 (2021) Category | CWE | Default Severity | Scan Profiles |
| :-: | :--- | :---: | :--- | :---: | :---: | :--- |
| 1 | `csrf_missing_token` | `passive` | `A01:2021` — Broken Access Control | `CWE-352` | Medium | `quick`, `standard`, `deep` |
| 2 | `insecure_cookies` | `passive` | `A07:2021` — Identification & Auth Failures | `CWE-614` | Medium | `quick`, `standard`, `deep` |
| 3 | `insecure_transport` | `passive` | `A02:2021` — Cryptographic Failures | `CWE-319` | Medium | `quick`, `standard`, `deep` |
| 4 | `missing_security_headers` | `passive` | `A05:2021` — Security Misconfiguration | `CWE-693` | Medium | `quick`, `standard`, `deep` |
| 5 | `outdated_js_components` | `passive` | `A06:2021` — Vulnerable & Outdated Components | `CWE-1104` | Medium | `quick`, `standard`, `deep` |
| 6 | `server_banner_leak` | `passive` | `A05:2021` — Security Misconfiguration | `CWE-200` | Low | `quick`, `standard`, `deep` |
| 7 | `verbose_error_pages` | `passive` | `A05:2021` — Security Misconfiguration | `CWE-209` | Medium | `quick`, `standard`, `deep` |
| 8 | `weak_csp` | `passive` | `A05:2021` — Security Misconfiguration | `CWE-693` | Medium | `quick`, `standard`, `deep` |
| 9 | `cors_misconfig` | `active` | `A05:2021` — Security Misconfiguration | `CWE-942` | High | `standard`, `deep` |
| 10 | `idor_heuristic` | `active` | `A01:2021` — Broken Access Control | `CWE-639` | Medium | `deep` |
| 11 | `open_redirect` | `active` | `A01:2021` — Broken Access Control | `CWE-601` | Medium | `standard`, `deep` |
| 12 | `sqli_boolean_diff` | `active` | `A03:2021` — Injection | `CWE-89` | High | `standard`, `deep` |
| 13 | `sqli_error_based` | `active` | `A03:2021` — Injection | `CWE-89` | Critical | `standard`, `deep` |
| 14 | `xss_reflected` | `active` | `A03:2021` — Injection | `CWE-79` | High | `standard`, `deep` |
| 15 | `directory_listing` | `discovery` | `A05:2021` — Security Misconfiguration | `CWE-548` | Medium | `deep` |
| 16 | `forced_browsing_admin` | `discovery` | `A01:2021` — Broken Access Control | `CWE-425` | High | `deep` |
| 17 | `sensitive_files` | `discovery` | `A05:2021` — Security Misconfiguration | `CWE-538` | High | `standard`, `deep` |

---

## Empirical Evaluation & Self-Scan Hardening Summary

### `VulnBench` Benchmark Across Scan Profiles (`NFR-08`: **PASS**)

Verified reproducibly by `scripts/evaluate.py` against `testbench/vulnbench/app.py` and `testbench/ground_truth.json` (`19` seeded vulnerabilities across all 17 checks + `4` hardened `/safe/*` negative-control routes). Full breakdown and OWASP ZAP DX comparison in [docs/TESTBENCH_RESULTS.md](docs/TESTBENCH_RESULTS.md).

| Profile | Checks Run | TP / Expected | FP | FN (All) | Precision | Recall (All) | F1 (All) | Clean FPs (`/safe/*`) | Route Coverage | Duration | SLA | Verdict |
| :--- | :---: | :---: | :-: | :-: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Quick** | `8 / 17` | `9 / 9` | `0` | `10` | `100.0%` | `47.4%` | `64.3%` | `0` | `93.3%` (`14/15`) | `1.92 s` | `<= 15 s` | **PASS** |
| **Standard** | `14 / 17` | `16 / 16` | `0` | `3` | `100.0%` | `84.2%` | `91.4%` | `0` | `93.3%` (`14/15`) | `20.22 s` | `<= 45 s` | **PASS** |
| **Deep** | **`17 / 17`** | **`19 / 19`** | **`0`** | **`0`** | **`100.0%`** | **`100.0%`** | **`100.0%`** | **`0`** | **`93.3%` (`14/15`)** | **`21.42 s`** | `<= 90 s` | **NFR-08 PASS** |

### Phase 7 Self-Scan & Hardening Audit (`http://127.0.0.1:8000`)

Dogfooding the scanner against itself with the `Deep` (17-check) profile drove concrete Phase 7 hardening across `backend/app/main.py` (`Permissions-Policy`, `object-src 'none'`, static `Cache-Control: no-cache`), `Dockerfile` (`--no-server-header`), and `backend/tests/integration/test_self_scan_hardening.py`:

- **Baseline Live Deep Self-Scan:** `2` pages crawled · `83` requests · `0` errors · `Risk Score: 6/100` (`0` Critical, `0` High, `2` Medium: `missing_security_headers` + `weak_csp`).
- **Post-Hardening Target Posture:** **`Risk Score: 3/100`** (`0` Critical, `0` High, **`0` `missing_security_headers`**, **`0` `server_banner_leak`**, `0` errors) — with an honest architectural rationale for the single accepted `style-src 'self' 'unsafe-inline'` zero-build trade-off while `script-src` remains strictly free of `'unsafe-inline'` and `'unsafe-eval'`.
- Full audit report: [docs/SELF_SCAN_REPORT.md](docs/SELF_SCAN_REPORT.md).

---

## Developer Extensibility Guide: Add a New OWASP Check in 1 File

Because `BaseCheck.__init_subclass__` automatically registers any concrete subclass declaring a non-empty `id`, and `backend/scanner/checks/__init__.py` auto-imports every module under `passive/`, `active/`, or `discovery/` via `pkgutil.walk_packages`, adding a new security check requires **zero edits to the orchestrator, API routers, or UI**.

### Step 1: Drop a New Plugin Module in `backend/scanner/checks/passive/` (or `active/` / `discovery/`)

```python
# backend/scanner/checks/passive/cache_headers.py
from __future__ import annotations

from typing import ClassVar

from backend.scanner.checks.base import BaseCheck, CheckContext
from backend.scanner.checks.passive._helpers import ALL_PROFILES, get_header
from backend.scanner.models import (
    CheckKind,
    Confidence,
    OWASPCategory,
    RawFinding,
    ScanProfile,
    Severity,
)


class SensitiveCacheHeaderCheck(BaseCheck):
    """Flags authenticated HTML responses missing Cache-Control: no-store."""

    id: ClassVar[str] = "sensitive_cache_control"
    name: ClassVar[str] = "Missing No-Store Cache-Control on Sensitive Page"
    owasp_category: ClassVar[str] = OWASPCategory.A05
    cwe_id: ClassVar[str] = "CWE-525"
    kind: ClassVar[CheckKind] = CheckKind.PASSIVE
    default_severity: ClassVar[Severity] = Severity.LOW
    profiles: ClassVar[frozenset[ScanProfile]] = ALL_PROFILES
    description: ClassVar[str] = (
        "Detects account or profile responses cached without Cache-Control: no-store."
    )

    def run(self, ctx: CheckContext) -> list[RawFinding]:
        if ctx.is_cancelled():
            return []

        findings: list[RawFinding] = []
        for resp in ctx.responses.by_origin(ctx.target_url):
            if "/account" not in resp.url:
                continue
            cache_ctrl = (get_header(resp.headers, "Cache-Control") or "").lower()
            if "no-store" not in cache_ctrl:
                findings.append(
                    RawFinding(
                        check_id=self.id,
                        title="Sensitive Route Missing Cache-Control: no-store",
                        owasp_category=self.owasp_category,
                        cwe_id=self.cwe_id,
                        severity=self.default_severity,
                        url=resp.url,
                        method="GET",
                        parameter="Cache-Control",
                        evidence={"header": "Cache-Control", "value": cache_ctrl or "<missing>"},
                        confidence=Confidence.MEDIUM,
                    )
                )
        return findings
```

### Step 2: Add Multi-Stack Remediation Entry to `backend/scanner/remediation/kb.json`

```json
"sensitive_cache_control": {
  "check_id": "sensitive_cache_control",
  "title": "Missing No-Store Cache-Control on Sensitive Page",
  "owasp_category": "A05:2021 - Security Misconfiguration",
  "cwe_id": "CWE-525",
  "summary": "Set Cache-Control: no-store on responses carrying user profile or session-sensitive data.",
  "root_cause_template": "The response from {method} {path} ({parameter}) permits browser or proxy caching of sensitive content.",
  "snippets": [
    {
      "stack": "fastapi",
      "language": "python",
      "before": "@app.get(\"/account\")\ndef account():\n    return {\"email\": \"dev@local\"}",
      "after": "from fastapi import Response\n\n@app.get(\"/account\")\ndef account(response: Response):\n    response.headers[\"Cache-Control\"] = \"no-store\"\n    return {\"email\": \"dev@local\"}"
    }
  ],
  "references": [
    "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
  ]
}
```

Restart the server (or run `pytest`): your new check immediately appears in `GET /api/checks`, the **OWASP Check Catalog** UI view, scan execution, SHA-1 diffing, and HTML5/JSON reports.

---

## Academic Deliverables & Documentation Index

| Deliverable | Path | Description |
| :--- | :--- | :--- |
| **Master SAD Index** | [docs/SAD.md](docs/SAD.md) | Complete System Analysis & Design index, 19-figure catalog, team metadata & build commands |
| **Formal Graduation Book (PDF)** | [docs/SAD_Book.pdf](docs/SAD_Book.pdf) | Print-ready A4 PDF book (Chapters 1–6 + 19 embedded offline figures) |
| **Graduation Book (Word / HTML / MD)** | [SAD_Book.docx](docs/SAD_Book.docx) · [SAD_Printable.html](docs/SAD_Printable.html) · [SAD_Book.md](docs/SAD_Book.md) | Editable OOXML Word edition, self-contained printable HTML5 edition, and unified Markdown source |
| **Semester 1 Split Package** | [docs/semester_1/](docs/semester_1/) | Chapters 1–3 & 15 figures (`SAD_Semester1_Book.{pdf,docx,md}`) |
| **Semester 2 Split Package** | [docs/semester_2/](docs/semester_2/) | Chapters 4–6 & 4 figures (`SAD_Semester2_Book.{pdf,docx,md}`) |
| **Semester 1 Defense Deck** | [Semester1_Progress_Defense.pptx](docs/presentations/Semester1_Progress_Defense.pptx) · [PDF](docs/presentations/Semester1_Progress_Defense.pdf) · [HTML](docs/presentations/Semester1_Progress_Defense.html) | 12-slide 16:9 widescreen Semester 1 Progress & Architecture Defense presentation |
| **Empirical Testbench Report** | [docs/TESTBENCH_RESULTS.md](docs/TESTBENCH_RESULTS.md) | Automated `VulnBench` Quick/Standard/Deep Precision/Recall/F1 metrics & OWASP ZAP DX rubric |
| **Phase 7 Self-Scan & Hardening Audit** | [docs/SELF_SCAN_REPORT.md](docs/SELF_SCAN_REPORT.md) | Live `Deep` self-scan baseline, 5 hardening actions, post-hardening posture (`3/100`), and CSP rationale |

---

## Development Phase Checklist

- [x] **Phase 0** — Clean Greenfield Workspace Reset & Project Bootstrap
- [x] **Phase 1** — Software Architecture Document (SAD), 19 Formal Diagrams & Multi-Format Publication Pipeline
- [x] **Phase 2** — Core Engine: Scope Guardrail, Token-Bucket HTTP Client, BFS Crawler & Soft-404 Fingerprinting
- [x] **Phase 3** — OWASP Top 10 (2021) Auto-Registry & 17 Curated Security Checks + Multi-Stack Remediation KB
- [x] **Phase 4** — Scan Orchestration, SQLAlchemy 2.0 Persistence, SSE Live Progress, SHA-1 Diff & Offline HTML5/JSON Reports
- [x] **Phase 5** — 6-View Dark/Light Developer-Experience Dashboard (Zero-Build HTML5 + Tailwind CSS + Vanilla ES Modules)
- [x] **Phase 6** — Deterministic `VulnBench`, Automated Precision/Recall Evaluation (`100%` Deep F1, `NFR-08 PASS`) & ZAP DX Comparison
- [x] **Phase 7** — Final Hardening (`Permissions-Policy`, `object-src 'none'`, `--no-server-header`), Self-Scan Verification & Capstone Delivery Package

---

## Ethical & Authorized Use Notice

This tool is developed strictly for **authorized local development, university coursework, and controlled lab testbenches** (`localhost`, `127.0.0.1`, `host.docker.internal`, RFC1918 private ranges, and local Docker testbench targets). Public internet scanning is intentionally blocked by `ScopeGuardrail`. Never scan any system you do not own or lack explicit written authorization to test.
