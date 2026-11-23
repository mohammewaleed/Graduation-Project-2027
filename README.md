# Lightweight OWASP Top 10 Vulnerability Scanner (Developer-Experience Focus)

> **Academic Graduation Project** — Department of Cyber Security (October 2026)  
> *Developing a Lightweight OWASP Top 10 Vulnerability Scanner Tailored for Web Developers and Student Projects*

## Overview

Enterprise DAST tools like OWASP ZAP are powerful, yet their setup overhead, cryptic alerts, and noisy output create friction for web developers and students building local web apps. This project delivers a **lightweight, zero-config, ethical-by-design OWASP Top 10 (2021) vulnerability scanner** focused on **Developer Experience (DX)**:

- **3-Minute Setup**: Single-command `docker compose up` or native Python `venv` startup.
- **Plain-English Findings & Actionable Fixes**: Structured severity, evidence snippets, and copy-ready remediation guidance.
- **Safety & Scope Guardrails**: Built strictly for authorized local development and educational testbenches (`localhost`, `127.0.0.1`, `host.docker.internal`, RFC1918 networks, and local Docker testbench targets).
- **Decoupled Plugin Architecture**: Pure Python scanning engine with modular `BaseCheck` checks, FastAPI + SSE live progress streaming, and zero-build HTML5 + Tailwind CSS + Vanilla JS ES Modules UI.

---

## Architecture Summary

| Layer | Technology | Purpose |
| :--- | :--- | :--- |
| **Backend API** | Python 3.12, FastAPI, Uvicorn, Pydantic v2, `pydantic-settings` | REST API, SSE live progress streaming, security headers middleware, static UI serving |
| **Scanning Engine** | Requests, BeautifulSoup4, `lxml`, `packaging` | Scope guardrail, crawler, soft-404 detector, and 17 curated OWASP Top 10 (2021) checks |
| **Persistence** | SQLAlchemy 2.0 (SQLite WAL default + optional PostgreSQL 16) | Scan history, findings, and reports (`sqlite:///./data/scanner.db` or `--profile postgres`) |
| **Frontend UI** | HTML5, Tailwind CSS, Modular Vanilla JS (ES Modules) | Zero-build developer dashboard served directly by FastAPI |
| **Containerization** | Multi-stage `Dockerfile` (non-root `scanner` user) & Docker Compose | Reproducible local deployment and isolated testbench orchestration |
| **Testbench** | DVWA, OWASP Juice Shop, and local deterministic `VulnBench` | Quantitative precision/recall evaluation and developer-experience benchmarking |

---

## 3-Minute Quick Start

### Option A: Docker Compose (Recommended)

```bash
# 1. Copy the example environment file (optional — sensible defaults work out of the box)
cp .env.example .env

# 2. Build and start the scanner (SQLite WAL persistence on ./data)
docker compose up --build
```

Open **http://localhost:8000** in your browser and verify **http://localhost:8000/api/health**.

#### Optional: Run with PostgreSQL 16

```bash
DATABASE_URL=postgresql+psycopg://scanner:scanner@postgres:5432/scanner \
  docker compose --profile postgres up --build
```

#### Optional: Start the Local Vulnerable Testbench

```bash
docker compose -f docker-compose.testbench.yml up -d
```

- **DVWA**: `http://127.0.0.1:8080`
- **OWASP Juice Shop**: `http://127.0.0.1:3000`
- **VulnBench**: `http://127.0.0.1:5050` *(added in the testbench phase)*

---

### Option B: Native Python Virtual Environment (`venv`)

Requires **Python 3.11+ / 3.12**.

```bash
# 1. Create and activate a virtual environment
python -m venv .venv

# Windows (PowerShell)
.\.venv\Scripts\Activate.ps1
# Linux / macOS
# source .venv/bin/activate

# 2. Install dependencies
pip install -r backend/requirements.txt

# 3. Run the FastAPI server
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Run the test suite:

```bash
pytest backend/tests
```

---

## Repository Map

```text
.
├── .env.example                 # Default environment & scope guardrail configuration
├── .gitignore                   # Python, venv, SQLite DB, and cache ignores
├── Dockerfile                   # Multi-stage Python 3.12 slim image (non-root user)
├── docker-compose.yml           # Scanner service + optional PostgreSQL 16 profile
├── docker-compose.testbench.yml # DVWA, OWASP Juice Shop, and VulnBench testbench
├── README.md                    # Project documentation & quick start
├── backend/
│   ├── requirements.txt         # Pinned Python dependencies
│   ├── app/
│   │   ├── config.py            # pydantic-settings configuration
│   │   ├── database.py          # SQLAlchemy 2.0 engine (SQLite WAL + PostgreSQL)
│   │   ├── main.py              # FastAPI app factory, security headers, CORS, static UI
│   │   └── routers/
│   │       └── health.py        # GET /api/health readiness & DB check endpoint
│   ├── scanner/                 # Pure Python OWASP scanning engine package (Phases 2–4)
│   └── tests/
│       └── test_health.py       # Phase 0 smoke tests (API health, UI, security headers)
├── frontend/
│   ├── index.html               # HTML5 + Tailwind CSS dashboard shell
│   └── js/
│       └── bootstrap.js         # Live /api/health status module
├── docs/                        # Software Architecture Document (SAD) & Mermaid diagrams
├── scripts/                     # Build & evaluation tooling
└── testbench/                   # VulnBench & ground-truth evaluation artifacts
```

---

## Development Phase Checklist

- [x] **Phase 0** — Clean Greenfield Workspace Reset & Project Bootstrap *(Ready)*
- [x] **Phase 1** — Software Architecture Document (SAD), Formal Diagrams & Architecture Decisions *(Ready)*
- [ ] **Phase 2** — Core Engine: Scope Guardrail, HTTP Client, Crawler & Soft-404 Fingerprinting
- [ ] **Phase 3** — OWASP Top 10 (2021) Plugin Registry & 17 Curated Security Checks
- [ ] **Phase 4** — Scan Orchestration, SQLAlchemy Persistence, SSE Progress & Report Export (HTML/JSON/SARIF)
- [ ] **Phase 5** — Developer-Experience Web Dashboard (Tailwind CSS + Modular Vanilla JS)
- [ ] **Phase 6** — Deterministic `VulnBench`, Automated Precision/Recall Evaluation & ZAP Comparison
- [ ] **Phase 7** — Final Hardening, End-to-End Verification & Capstone Presentation Package

---

## Ethical & Authorized Use Notice

This tool is developed strictly for **authorized local development, educational coursework, and controlled lab testbenches**. Never scan targets you do not own or lack explicit written permission to test.
