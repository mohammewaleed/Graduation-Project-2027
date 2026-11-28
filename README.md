<div align="center">

# 🛡️ OWASP-Lite Scanner (`v1.0.0`)

### Lightweight OWASP Top 10 (2021) Vulnerability Scanner — Developer-Experience Focus

*Academic Graduation Project · Department of Cyber Security (2026–2027) · Supervised by **Dr. Samar***

[![CI](https://github.com/mohammewaleed/Graduation-Project-2027/actions/workflows/ci.yml/badge.svg)](https://github.com/mohammewaleed/Graduation-Project-2027/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688?logo=fastapi&logoColor=white)
![OWASP](https://img.shields.io/badge/OWASP%20Top%2010-2021%20(17%20Checks)-0F172A)
![Tests](https://img.shields.io/badge/Tests-88%20Passing-16A34A)
![VulnBench F1](https://img.shields.io/badge/VulnBench%20Deep%20F1-100.0%25-0D9488)

**A fast, zero-config local web vulnerability scanner built for developers and students.**  
Scan authorized local or lab apps with **17 curated OWASP Top 10 checks**, stream findings in real time over **SSE**, compare regression diffs by **SHA-1 fingerprint**, and patch vulnerabilities immediately with **VS Code Dark+ Before/After code fixes** across **FastAPI, Flask, Express, PHP, and HTML**.

[🎬 Live Demo](#-live-walkthrough) ·
[✨ Features](#-key-capabilities) ·
[🏗️ Architecture](#%EF%B8%8F-architecture--project-layout) ·
[🚀 Quick Start](#-quick-start) ·
[📊 Benchmarks](#-empirical-validation) ·
[📚 Documentation](#-documentation--deliverables) ·
[👥 Team](#-project-team)

</div>

---

## 🎬 Live Walkthrough

<div align="center">
  <img src="docs/media/gif/demo_walkthrough.gif" alt="OWASP-Lite Scanner Live Interactive Walkthrough" width="900" />
  <br />
  <sub><em>Recorded directly against the live FastAPI workbench and local <code>VulnBench</code> target — zero mockups.</em></sub>
</div>

<br />

| Step | Workbench View | What It Demonstrates |
| :---: | :--- | :--- |
| **01** | **Dashboard Overview** | Live risk score (`0–100`), project portfolio, severity badges, and recent scans |
| **02** | **Scan Launcher** | `Quick` (8) · `Standard` (14) · `Deep` (17/17) profiles + crawl limits & optional auth |
| **03** | **Live SSE Scan Stream** | Real-time progress bar, active check telemetry, and live streaming findings feed |
| **04** | **Findings Explorer** | Risk gauge, severity donut, OWASP Top 10 category breakdown, and one-click exports |
| **05** | **VS Code Dark+ Code Fix** | Root cause, fix strategy, *"Where to Patch"* locator, and red `-` / green `+` code diff |
| **06** | **5-Stack Remediation KB** | Instant tab switching across **FastAPI · Flask · Express · PHP · HTML** with Copy Fix |
| **07** | **Compare Scans Diff** | SHA-1 fingerprint comparison highlighting **New**, **Fixed**, and **Unchanged** findings |
| **08** | **Offline HTML5 Report** | Autoescaped, zero-JS standalone security report ready for developer or academic review |

---

## ✨ Key Capabilities

| Pillar | Highlights |
| :--- | :--- |
| **🔍 17 Curated OWASP Checks** | **8 Passive** (Headers, CSP, Cookies, Transport, CSRF, Banners, Error Leaks, Outdated JS) · **6 Safe Active** (Error/Boolean SQLi, Reflected XSS, CORS, Open Redirect, IDOR) · **3 Discovery** (Directory Listing, Sensitive Files, Forced Browsing) |
| **💡 Actionable Developer UX** | Every finding ships with a **VS Code Dark+ Before/After diff**, line-level diff markers, **5 framework tabs**, CWE/OWASP references, and interactive triage (`Open` / `Fixed` / `False Positive`) |
| **⚡ Real-Time & Offline-First** | Streaming **Server-Sent Events (SSE)** progress, SQLite WAL zero-config storage (optional PostgreSQL 16), and standalone **HTML5 / JSON** audit reports with zero external JS |
| **🔁 Fix Verification Diff** | Deterministic **SHA-1 finding fingerprinting** lets you re-scan after patching and verify exactly which issues moved to **`Fixed`** without regressions |
| **🛡️ Ethical Scope Guardrail** | Strict pre-connect **Local-Only allowlist** (`127.0.0.1`, `localhost`, RFC 1918, Docker lab) + DNS anti-rebinding & cloud metadata (`169.254.169.254`) SSRF block + destructive path denylist |

<details>
<summary><strong>📋 View Full 17-Check OWASP Top 10 (2021) Matrix</strong></summary>

| Profile | Checks Included | Execution Style | Typical Time (`VulnBench`) |
| :--- | :--- | :--- | :---: |
| **Quick** (`8/17`) | Security Headers, Weak CSP, Insecure Cookies, Cleartext Transport, Missing CSRF Token, Server Banners, Stack Trace Leaks, Vulnerable JS Components | Passive only · Depth `2` | `1.92 s` |
| **Standard** (`14/17`) | All Quick checks + Error-Based SQLi, Reflected XSS, Permissive CORS, Open Redirect, Sensitive File Exposure, Directory Listing | Safe Active + Passive · Depth `3` | `20.22 s` |
| **Deep** (`17/17`) | All Standard checks + Boolean-Blind SQLi, Tentative IDOR Heuristics, Forced Browsing (`admin` / backup paths) | Full Audit · Depth `5` | `21.42 s` |

</details>

---

## 🏗️ Architecture & Project Layout

The pure-Python scanner core (`backend/scanner/`) is **100% AST-isolated** from FastAPI and SQLAlchemy, communicating through typed dataclasses and a bounded background `ScanJobManager`.

<details>
<summary><strong>🗺️ View Master End-to-End Scanner Pipeline (Figure 2)</strong></summary>
<br />
<div align="center">
  <img src="docs/diagrams/png/02_master_scanner_pipeline.png" alt="Master End-to-End Vulnerability Scanner Execution Pipeline" width="880" />
</div>
</details>

| Layer | Technology Stack | Directory |
| :--- | :--- | :--- |
| **Backend API & Persistence** | FastAPI · Uvicorn · Pydantic v2 · SQLAlchemy 2.0 (SQLite WAL / PostgreSQL 16) · Jinja2 | [`backend/app/`](backend/app/) |
| **Pure-Python Scanner Engine** | Requests · BeautifulSoup4 · `ScopeGuardrail` · BFS Crawler · 17 `BaseCheck` Plugins · `kb.json` | [`backend/scanner/`](backend/scanner/) |
| **Automated Test Suite** | `pytest` · Unit, Integration, E2E API, VulnBench Accuracy & Self-Scan Hardening (**88 tests**) | [`backend/tests/`](backend/tests/) |
| **Web Workbench (6 Views)** | HTML5 · Tailwind CSS · Modular Vanilla JS (ES Modules, **0** `innerHTML`/`eval` sinks) | [`frontend/`](frontend/) |
| **Evaluation Testbench** | Custom pure-stdlib `VulnBench` (17 flaws + 4 clean controls) · DVWA · OWASP Juice Shop | [`testbench/`](testbench/) |
| **Docs, Diagrams & Decks** | Extension-organized SAD Books (`pdf/docx/md/html`), 19 Diagrams (`png/svg/mmd`), Defense Decks | [`docs/`](docs/) |

---

## 🚀 Quick Start

### Option 1 · Native Python *(Fastest — Zero Docker Required)*

> **Prerequisites:** Git · Python `3.12+` · `pip`

```powershell
# 1. Clone & activate virtual environment
git clone https://github.com/mohammewaleed/Graduation-Project-2027.git
cd Graduation-Project-2027
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1        # macOS/Linux: source .venv/bin/activate

# 2. Install backend dependencies
pip install -r backend/requirements.txt

# 3. Launch the OWASP-Lite Scanner Workbench (http://127.0.0.1:8000)
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --no-server-header
```

*(Optional)* Start the bundled local vulnerable test target (`http://127.0.0.1:5050`) in a second terminal:

```powershell
python testbench/vulnbench/app.py --host 127.0.0.1 --port 5050
```


### 🐳 Option 2 · Docker Compose (Scanner + Optional Testbench + Optional PostgreSQL 16)</strong></summary>

> **Prerequisites:** [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Compose v2; **WSL 2** enabled on Windows) · Free port `8000`

```bash
# 1. Clone and start the scanner (http://localhost:8000)
git clone https://github.com/mohammewaleed/Graduation-Project-2027.git
cd Graduation-Project-2027
docker compose up --build

# 2. (Optional) Start scanner + all 3 vulnerable testbenches (VulnBench :5050, DVWA :8080, Juice Shop :3000)
docker compose -f docker-compose.yml -f docker-compose.testbench.yml up --build -d

# 3. (Optional) Use PostgreSQL 16 instead of SQLite
DATABASE_URL=postgresql+psycopg://scanner:scanner@postgres:5432/scanner docker compose --profile postgres up --build

# 4. Stop all containers when done
docker compose -f docker-compose.yml -f docker-compose.testbench.yml down
```



### ⚡ First Scan in 60 Seconds

1. Open **`http://127.0.0.1:8000`** and click **`+ New Project`**.
2. Enter your authorized local URL (`http://127.0.0.1:5050`, or `http://vulnbench:5050` in Docker), choose your stack, and tick the authorization checkbox.
3. Navigate to **Scan Launcher** → pick **`Quick`**, **`Standard`**, or **`Deep`** → click **`Start Security Scan`**.
4. Open **Findings Explorer** → click **`View Fix`** on any finding for **Before/After code diffs**, update triage status, or export **HTML / JSON** reports.
5. Re-scan after applying fixes and open **Compare Scans** to verify **`Fixed`** vs **`New`** findings.

---

## 📊 Empirical Validation

Reproduce the full test suite and multi-profile accuracy benchmark locally:

```bash
pytest backend/tests -v
python scripts/evaluate.py --auto-start-vulnbench --benchmark-all-profiles --write-report docs/reports/TESTBENCH_RESULTS.md
```

### VulnBench Ground-Truth Accuracy (`NFR-08` Verified)

| Scan Profile | Active Checks | Precision | Recall | F1-Score | Clean-Route FPs | Duration |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Quick** | `8 / 17` | `100.0%` | `47.4%` | `64.3%` | `0` | `1.92 s` |
| **Standard** | `14 / 17` | `100.0%` | `84.2%` | `91.4%` | `0` | `20.22 s` |
| **Deep** | **`17 / 17`** | **`100.0%`** | **`100.0%`** | **`100.0%`** | **`0`** | **`21.42 s`** |

> **Security & Reliability Highlights:** **88 / 88** automated pytest cases passing · **93.3%** crawler coverage · Live Deep self-scan hardened (`Risk 6 → 3 / 100`, `0` Critical/High findings) · Verified in GitHub Actions across **3 CI jobs** (`backend-tests`, `frontend-and-security`, `docker-verify`).

---

## 📚 Documentation & Deliverables

All academic deliverables are cleanly organized by file extension under [`docs/`](docs/):

| Deliverable | Interactive / Readable | Printable / Office | Source / Assets |
| :--- | :--- | :--- | :--- |
| **Full Defense Presentation** *(30 Slides · 19 Original SVGs)* | [Interactive HTML5 (Zoom/Pan)](docs/presentations/html/Full_Graduation_Defense.html) | [PowerPoint (PPTX)](docs/presentations/pptx/Full_Graduation_Defense.pptx) · [PDF](docs/presentations/pdf/Full_Graduation_Defense.pdf) | [`build_full_defense.py`](scripts/build_full_defense.py) |
| **Software Architecture Document (SAD)** | [Master SAD Index](docs/SAD.md) · [Offline HTML](docs/books/html/SAD_Printable.html) | [Full Book PDF](docs/books/pdf/SAD_Book.pdf) · [DOCX](docs/books/docx/SAD_Book.docx) | [Chapters (1–6)](docs/sad_chapters/) |
| **Semester Split Editions** | [Sem 1 MD](docs/books/md/SAD_Semester1_Book.md) · [Sem 2 MD](docs/books/md/SAD_Semester2_Book.md) | [Sem 1 PDF](docs/books/pdf/SAD_Semester1_Book.pdf) · [Sem 2 PDF](docs/books/pdf/SAD_Semester2_Book.pdf) | [Sem 1 & 2 DOCX](docs/books/docx/) |
| **19 Original Architecture Diagrams** | [High-DPI PNGs (`01..19`)](docs/diagrams/png/) | [Vector SVGs (`01..19`)](docs/diagrams/svg/) | [Mermaid Sources (`01..19`)](docs/diagrams/mmd/) |
| **Validation & Audit Reports** | [VulnBench Accuracy Results](docs/reports/TESTBENCH_RESULTS.md) | [Self-Scan Hardening Audit](docs/reports/SELF_SCAN_REPORT.md) | [`evaluate.py`](scripts/evaluate.py) |

---

## 👥 Project Team

**Academic Supervisor:** **Dr. Samar** — Department of Cyber Security (`2026–2027`)

| Student Name | Academic ID |
| :--- | :---: |
| Ahmed Ashraf Ammar | `235204` |
| Islam Mohammed | `235164` |
| Abdelrhman Mohamed AbdEl-latif | `235216` |
| Ahmed Waleed Mokthar | `235052` |
| Mohamed Waleed Mokthar | `235051` |
| Mohamed Ibrahim Elsayed | `235401` |
| Ali Ibrahim Elsayed | `235332` |

---

> [!CAUTION]
> **Authorized Local & Educational Use Only.**  
> OWASP-Lite Scanner is strictly built for local development environments and authorized cybersecurity lab testbenches (`127.0.0.1`, RFC 1918 private subnets, Docker lab networks). Never scan external or third-party systems without explicit written authorization.
