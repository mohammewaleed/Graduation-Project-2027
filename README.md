# OWASP-Lite Scanner (`v1.0.0`)

> **Lightweight OWASP Top 10 (2021) Vulnerability Scanner — Developer-Experience Focus**  
> Academic Graduation Project · Department of Cyber Security (2026–2027) · Supervised by **Dr. Samar**

A fast, zero-config local web vulnerability scanner built for developers and students. Scans authorized local/lab apps with **17 OWASP Top 10 checks**, streams live progress, and delivers **VS Code Dark+ Before/After code fixes** across **FastAPI, Flask, Express, PHP, and HTML**.

---

## Key Features

- **17 OWASP Top 10 (2021) Checks:** 8 Passive · 6 Safe Active · 3 Discovery (`Quick` / `Standard` / `Deep`)
- **VS Code Dark+ Code Fixes:** Copy-ready Before/After diffs across 5 stacks with line-level diff highlighting
- **6-View Interactive Dashboard:** Dashboard, Scan Launcher, Live Scan, Findings Explorer, Compare Scans, Check Catalog
- **Offline Reports & Regression Diff:** Standalone autoescaped HTML5 & JSON reports + SHA-1 scan comparison
- **Ethical Local-Only Guardrail:** Blocks public internet targets (loopback, RFC1918 & local testbenches only)

---

## Quick Start

### Option 1: Native Python

**Prerequisites:** Git · Python `3.12+` · `pip`

1. Clone the repository and create a virtual environment:
   ```powershell
   git clone https://github.com/mohammewaleed/Graduation-Project-2027.git
   cd Graduation-Project-2027
   py -3.12 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
   *(macOS/Linux activate: `source .venv/bin/activate`)*

2. Install dependencies:
   ```powershell
   pip install -r backend/requirements.txt
   ```

3. Start the scanner (`http://127.0.0.1:8000`):
   ```powershell
   uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --no-server-header
   ```

4. *(Optional)* Start the local vulnerable target (`http://127.0.0.1:5050`) in a second terminal:
   ```powershell
   python testbench/vulnbench/app.py --host 127.0.0.1 --port 5050
   ```

---

### Option 2: Docker Compose

**Prerequisites:** [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Compose v2; **WSL 2** enabled on Windows) · Free port `8000`

1. Clone the repository:
   ```bash
   git clone https://github.com/mohammewaleed/Graduation-Project-2027.git
   cd Graduation-Project-2027
   ```

2. Build and start the scanner (`http://localhost:8000`):
   ```bash
   docker compose up --build
   ```

3. *(Optional)* Start the scanner together with all 3 vulnerable testbench apps (`VulnBench :5050`, `DVWA :8080`, `Juice Shop :3000`):
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.testbench.yml up --build -d
   ```

4. *(Optional)* Run with **PostgreSQL 16** instead of SQLite:
   ```bash
   DATABASE_URL=postgresql+psycopg://scanner:scanner@postgres:5432/scanner docker compose --profile postgres up --build
   ```

5. Stop all containers when finished:
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.testbench.yml down
   ```

---

## How to Use

1. Open **`http://127.0.0.1:8000`** → click **`+ New Project`**.
2. Enter your local target (e.g., `http://127.0.0.1:5050` or `http://vulnbench:5050` in Docker), select your stack, and confirm authorization.
3. Open **Scan Launcher** → choose **Quick**, **Standard**, or **Deep** → click **Start Security Scan**.
4. Open **Findings Explorer** → click any finding for **Before/After code fixes**, update triage status, or export **HTML / JSON** reports.
5. Re-scan after applying fixes and use **Compare Scans** to verify **`Fixed`** vs **`New`** findings.

---

## Testing & Benchmark

```bash
pytest backend/tests -v
python scripts/evaluate.py --auto-start-vulnbench --benchmark-all-profiles --write-report docs/TESTBENCH_RESULTS.md
```

| Profile | Checks | Precision | Recall | F1-Score | Clean FPs | Duration |
|---|---:|---:|---:|---:|---:|---:|
| **Quick** | 8/17 | 100.0% | 47.4% | 64.3% | `0` | `1.92 s` |
| **Standard** | 14/17 | 100.0% | 84.2% | 91.4% | `0` | `20.22 s` |
| **Deep** | **17/17** | **100.0%** | **100.0%** | **100.0%** | **`0`** | **`21.42 s`** |

---

## Tech Stack & Structure

| Layer | Stack | Path |
|---|---|---|
| **Backend API** | FastAPI · Uvicorn · Pydantic v2 · SQLAlchemy 2.0 (SQLite / PostgreSQL) | [`backend/app/`](backend/app/) |
| **Scanner Engine** | Pure Python · Requests · BeautifulSoup4 · 17 `BaseCheck` Plugins | [`backend/scanner/`](backend/scanner/) |
| **Web Dashboard** | HTML5 · Tailwind CSS · Modular Vanilla JS (ES Modules) | [`frontend/`](frontend/) |
| **Testbench** | `VulnBench` · DVWA · OWASP Juice Shop | [`testbench/`](testbench/) |

---

## Documentation

- **Architecture Book:** [SAD.md](docs/SAD.md) · [Full PDF](docs/SAD_Book.pdf) · [Semester 1 PDF](docs/semester_1/SAD_Semester1_Book.pdf) · [Semester 2 PDF](docs/semester_2/SAD_Semester2_Book.pdf)
- **Defense Presentation:** [Semester 1 Slides (PPTX)](docs/presentations/Semester1_Progress_Defense.pptx) · [PDF](docs/presentations/Semester1_Progress_Defense.pdf)
- **Validation Reports:** [VulnBench Accuracy Results](docs/TESTBENCH_RESULTS.md) · [Self-Scan Hardening Audit](docs/SELF_SCAN_REPORT.md)

---

## Project Team

**Supervisor:** Dr. Samar

| Student | ID |
|---|---|
| Ahmed Ashraf Ammar | `235204` |
| Islam Mohammed | `235164` |
| Abdelrhman Mohamed AbdEl-latif | `235216` |
| Ahmed Waleed Mokthar | `235052` |
| Mohamed Waleed Mokthar | `235051` |
| Mohamed Ibrahim Elsayed | `235401` |
| Ali Ibrahim Elsayed | `235332` |

---

> **Authorized Use Only:** Built strictly for local development and educational lab testbenches. Never scan systems without explicit permission.
