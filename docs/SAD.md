# GRADUATION PROJECT BOOK – SYSTEM ANALYSIS AND DESIGN

**Developing a Lightweight OWASP Top 10 Vulnerability Scanner**  
*Tailored for Web Developers and Student Projects (Developer-Experience Focus)*

---

## Executive Abstract

Modern web application development in academic and early-stage engineering environments frequently defers security verification until the final stages prior to submission or deployment. Enterprise Dynamic Application Security Testing (DAST) platforms such as OWASP ZAP and Burp Suite impose considerable operational friction on novice developers, requiring manual proxy certificate configuration, intricate scan policy tuning, and specialized security expertise to translate raw HTTP transcripts and abstract CWE identifiers into source-code remediation.

This Software Architecture Document (SAD) establishes the complete, formal System Analysis and Design baseline for a **lightweight, self-contained, developer-first OWASP Top 10 (2021) vulnerability scanner**. Grounded in the OWASP Top 10 (2021) taxonomy and the NIST Secure Software Development Framework (SSDF, SP 800-218), the proposed architecture launches through a single Docker Compose command (`docker compose up`) or native Python virtual environment. It systematically crawls authorized local web targets, executes **17 curated, non-destructive security checks**, and presents actionable findings mapped to exact endpoints and input parameters alongside plain-language root-cause explanations and copy-ready **Before/After** remediation snippets across FastAPI, Flask, Express, PHP, and HTML.

The system employs a clean layered architecture built on Python 3.12, FastAPI, Requests, BeautifulSoup4, SQLAlchemy 2.0 (defaulting to SQLite in WAL mode with an optional PostgreSQL 16 Docker Compose profile), and a zero-build HTML5/Tailwind CSS/Vanilla JS dashboard. Mandatory ethical safeguards—including a hardcoded local/private-network allow-list, pre-request DNS-rebinding defense, same-origin redirect enforcement, and non-destructive proof-of-detection policies—guarantee safe operation during active coding and empirical validation against DVWA, OWASP Juice Shop, and a deterministic local VulnBench suite.

---

## Project Metadata

| Attribute | Specification |
| :--- | :--- |
| **Project Title** | Developing a Lightweight OWASP Top 10 Vulnerability Scanner (Tailored for Web Developers and Student Projects) |
| **Document Type** | Graduation Project Book – System Analysis and Design (SAD) |
| **Methodological Reference** | OWASP Top 10 (2021) & NIST SSDF (SP 800-218) |
| **Target Audience** | Junior Web Developers, University Students, and Small Development Teams |
| **Department** | Department of Cyber Security |
| **Project Supervisor** | Dr. Samar |
| **Project Team** | Seven Members: Ahmed Ashraf Ammar (235204), Islam Mohammed (235164), Abdelrhman Mohamed AbdEl-latif (235216), Ahmed Waleed Mokthar (235052), Mohamed Waleed Mokthar (235051), Mohamed Ibrahim Elsayed (235401), Ali Ibrahim Elsayed (235332) |
| **Academic Year** | 2026–2027 |
| **Document Status** | Proposed System Analysis and Design (Formal Edition v1.1) |
| **Current Project Phase** | First Semester – Requirements Analysis and System Architecture Design |
| **Next Project Phase** | Second Semester – Technical Implementation, Integration, and Testbench Validation |

---

## Quick Architecture Snapshot

| Architectural Layer | Confirmed Technology Stack | Primary Responsibilities |
| :--- | :--- | :--- |
| **Backend API & Engine** | Python 3.11+/3.12, FastAPI, Uvicorn, Pydantic v2, `pydantic-settings` | Typed REST API under `/api`, schema validation, security headers middleware, OpenAPI specification, and static dashboard serving. |
| **Worker & Live Telemetry** | In-process bounded `ThreadPoolExecutor`, `threading.Event` registry, Server-Sent Events (SSE) | Non-blocking background scan execution, deterministic mid-scan cancellation, and live progress streaming (`GET /api/scans/{id}/stream`) with zero external broker overhead. |
| **HTTP Client & HTML Parser** | `requests` (`requests.Session`), `BeautifulSoup4` (`bs4` + `lxml`) | Scope-enforced HTTP client, token-bucket rate limiting, request caps, manual redirect checks, Soft-404 calibration, BFS crawling, and DOM/form/script extraction. |
| **Security Engine & Knowledge Base** | Modular `BaseCheck` plugin auto-registry (17 curated checks) + JSON Remediation KB | 8 Passive, 5 Active Safe, 3 Discovery, and 1 Deep Auth checks across OWASP A01, A02, A03, A05, A06, and A07; multi-stack Before/After fix snippets (FastAPI, Flask, Express, PHP, HTML). |
| **Data Persistence** | SQLAlchemy 2.0 ORM — SQLite default (`sqlite:///./data/scanner.db`, WAL mode) + optional PostgreSQL 16 | Zero-configuration single-file persistence out of the box with drop-in PostgreSQL support via `DATABASE_URL` and Docker Compose `--profile postgres`. |
| **Developer Dashboard UI** | HTML5, Tailwind CSS, Modular Vanilla JS (ES Modules), Chart.js | Zero-build frontend served directly by FastAPI providing Projects/Dashboard, Scan Launcher, Live SSE Progress, Findings & Endpoints Explorer, Actionable Code Fix Modal, and Scan Comparison/Export. |
| **Containerization & Testbench** | Docker, Docker Compose (`docker-compose.yml`, `docker-compose.testbench.yml`) | Single-command local deployment with `host.docker.internal` bridging and isolated testbench containers (DVWA, OWASP Juice Shop, and local deterministic VulnBench). |

---

## Table of Contents

Each chapter is maintained as a standalone, version-controlled Markdown document in `docs/sad_chapters/` and compiled into the formal book editions.

| Chapter | Title | Source Document | Embedded Figures |
| :---: | :--- | :--- | :---: |
| **Chapter 1** | Introduction and Scope | [01_introduction_and_scope.md](sad_chapters/01_introduction_and_scope.md) | Figures 1–2, 19 |
| **Chapter 2** | System Requirements Specification | [02_requirements_srs.md](sad_chapters/02_requirements_srs.md) | Figure 3 |
| **Chapter 3** | Software Architecture and Multi-View Design | [03_architecture_views.md](sad_chapters/03_architecture_views.md) | Figures 4–14 |
| **Chapter 4** | Data Model, REST/SSE API, and Remediation Knowledge Base Design | [04_data_and_api_design.md](sad_chapters/04_data_and_api_design.md) | Figure 15 |
| **Chapter 5** | Security, Ethics, Risk Management, and Architecture Decision Records | [05_security_ethics_and_adrs.md](sad_chapters/05_security_ethics_and_adrs.md) | Figure 16 |
| **Chapter 6** | Validation Strategy, Benchmarking, and Developer-Experience Evaluation | [06_validation_and_benchmarking.md](sad_chapters/06_validation_and_benchmarking.md) | Figures 17–18 |

---

## List of Figures

All 19 architectural, behavioral, flowchart, data, security, and benchmarking figures are maintained as both high-resolution rendered PNG/SVG images in `docs/diagrams/png/` and `docs/diagrams/svg/` and standalone Mermaid source files in `docs/diagrams/mmd/`.

| Figure | Title | Host Chapter | Rendered Image (PNG) | Diagram Source (Mermaid) |
| :---: | :--- | :---: | :--- | :--- |
| **Figure 1** | As-Is Enterprise DAST vs. Proposed Lightweight Local Developer Workflow | [Chapter 1](sad_chapters/01_introduction_and_scope.md) | [01_as_is_vs_to_be.png](diagrams/png/01_as_is_vs_to_be.png) | [01_as_is_vs_to_be.mmd](diagrams/mmd/01_as_is_vs_to_be.mmd) |
| **Figure 2** | Master End-to-End Vulnerability Scanner Execution Pipeline | [Chapter 1](sad_chapters/01_introduction_and_scope.md) | [02_master_scanner_pipeline.png](diagrams/png/02_master_scanner_pipeline.png) | [02_master_scanner_pipeline.mmd](diagrams/mmd/02_master_scanner_pipeline.mmd) |
| **Figure 3** | System Use Case Diagram | [Chapter 2](sad_chapters/02_requirements_srs.md) | [03_use_case_diagram.png](diagrams/png/03_use_case_diagram.png) | [03_use_case_diagram.mmd](diagrams/mmd/03_use_case_diagram.mmd) |
| **Figure 4** | C4 Level 1 — System Context Diagram | [Chapter 3](sad_chapters/03_architecture_views.md) | [04_c4_l1_context.png](diagrams/png/04_c4_l1_context.png) | [04_c4_l1_context.mmd](diagrams/mmd/04_c4_l1_context.mmd) |
| **Figure 5** | C4 Level 2 — Container Architecture Diagram | [Chapter 3](sad_chapters/03_architecture_views.md) | [05_c4_l2_containers.png](diagrams/png/05_c4_l2_containers.png) | [05_c4_l2_containers.mmd](diagrams/mmd/05_c4_l2_containers.mmd) |
| **Figure 6** | C4 Level 3 — Scanner Engine Component Architecture | [Chapter 3](sad_chapters/03_architecture_views.md) | [06_c4_l3_scanner_components.png](diagrams/png/06_c4_l3_scanner_components.png) | [06_c4_l3_scanner_components.mmd](diagrams/mmd/06_c4_l3_scanner_components.mmd) |
| **Figure 7** | Data Flow Diagram Level 0 — System Context | [Chapter 3](sad_chapters/03_architecture_views.md) | [07_dfd_l0_context.png](diagrams/png/07_dfd_l0_context.png) | [07_dfd_l0_context.mmd](diagrams/mmd/07_dfd_l0_context.mmd) |
| **Figure 8** | Data Flow Diagram Level 1 — Internal Processes and Trust Boundaries | [Chapter 3](sad_chapters/03_architecture_views.md) | [08_dfd_l1_trust_boundaries.png](diagrams/png/08_dfd_l1_trust_boundaries.png) | [08_dfd_l1_trust_boundaries.mmd](diagrams/mmd/08_dfd_l1_trust_boundaries.mmd) |
| **Figure 9** | Docker Compose Deployment and Network Topology | [Chapter 3](sad_chapters/03_architecture_views.md) | [09_docker_deployment.png](diagrams/png/09_docker_deployment.png) | [09_docker_deployment.mmd](diagrams/mmd/09_docker_deployment.mmd) |
| **Figure 10** | End-to-End Scan Lifecycle Sequence Diagram | [Chapter 3](sad_chapters/03_architecture_views.md) | [10_scan_lifecycle_sequence.png](diagrams/png/10_scan_lifecycle_sequence.png) | [10_scan_lifecycle_sequence.mmd](diagrams/mmd/10_scan_lifecycle_sequence.mmd) |
| **Figure 11** | Scan Cancellation and Per-Check Error Isolation Sequence | [Chapter 3](sad_chapters/03_architecture_views.md) | [11_cancel_error_isolation_sequence.png](diagrams/png/11_cancel_error_isolation_sequence.png) | [11_cancel_error_isolation_sequence.mmd](diagrams/mmd/11_cancel_error_isolation_sequence.mmd) |
| **Figure 12** | Scan Execution Lifecycle State Machine | [Chapter 3](sad_chapters/03_architecture_views.md) | [12_scan_state_machine.png](diagrams/png/12_scan_state_machine.png) | [12_scan_state_machine.mmd](diagrams/mmd/12_scan_state_machine.mmd) |
| **Figure 13** | Cross-Component Swimlane Activity Diagram | [Chapter 3](sad_chapters/03_architecture_views.md) | [13_swimlane_activity.png](diagrams/png/13_swimlane_activity.png) | [13_swimlane_activity.mmd](diagrams/mmd/13_swimlane_activity.mmd) |
| **Figure 14** | Scanner Plugin Architecture Class Diagram | [Chapter 3](sad_chapters/03_architecture_views.md) | [14_scanner_plugin_class_diagram.png](diagrams/png/14_scanner_plugin_class_diagram.png) | [14_scanner_plugin_class_diagram.mmd](diagrams/mmd/14_scanner_plugin_class_diagram.mmd) |
| **Figure 15** | Third Normal Form (3NF) Entity-Relationship Diagram | [Chapter 4](sad_chapters/04_data_and_api_design.md) | [15_erd_3nf.png](diagrams/png/15_erd_3nf.png) | [15_erd_3nf.mmd](diagrams/mmd/15_erd_3nf.mmd) |
| **Figure 16** | Pre-Request Scope Guardrail and Safety Decision Flow | [Chapter 5](sad_chapters/05_security_ethics_and_adrs.md) | [16_scope_guardrail_flow.png](diagrams/png/16_scope_guardrail_flow.png) | [16_scope_guardrail_flow.mmd](diagrams/mmd/16_scope_guardrail_flow.mmd) |
| **Figure 17** | Target Detection Accuracy Benchmark Profile Across OWASP Categories | [Chapter 6](sad_chapters/06_validation_and_benchmarking.md) | [17_accuracy_benchmark_chart.png](diagrams/png/17_accuracy_benchmark_chart.png) | [17_accuracy_benchmark_chart.mmd](diagrams/mmd/17_accuracy_benchmark_chart.mmd) |
| **Figure 18** | Target Crawler Coverage and Latency Profile Across Scan Modes | [Chapter 6](sad_chapters/06_validation_and_benchmarking.md) | [18_coverage_latency_chart.png](diagrams/png/18_coverage_latency_chart.png) | [18_coverage_latency_chart.mmd](diagrams/mmd/18_coverage_latency_chart.mmd) |
| **Figure 19** | Classic Top-Down Master System Flowchart | [Chapter 1](sad_chapters/01_introduction_and_scope.md) | [19_master_system_flowchart.png](diagrams/png/19_master_system_flowchart.png) | [19_master_system_flowchart.mmd](diagrams/mmd/19_master_system_flowchart.mmd) |

---

## Output Artifacts and Publication Pipeline

All publication editions are generated reproducibly from the modular Markdown chapters (`docs/sad_chapters/`) and standalone diagram definitions (`docs/diagrams/`) without requiring external network access or cloud services.

| Artifact | Path | Format & Intended Use | Build Command |
| :--- | :--- | :--- | :--- |
| **Diagram Image Assets** | `docs/diagrams/{svg,png}/01..19.{svg,png}` | High-resolution vector SVGs and 2x DPI PNG figures for offline embedding | `python scripts/render_diagrams.py` |
| **Unified Markdown Book** | [SAD_Book.md](books/md/SAD_Book.md) | Combined single-file formal Markdown graduation book with image references | `python scripts/build_sad_docx.py` |
| **Microsoft Word Book** | [SAD_Book.docx](books/docx/SAD_Book.docx) | Native OOXML `.docx` with Cover Page, TOC, List of Figures, 19 embedded PNGs, headers/footers, and academic styles | `python scripts/build_sad_docx.py` |
| **Formal PDF Book** | [SAD_Book.pdf](books/pdf/SAD_Book.pdf) | Print-ready A4 PDF book with embedded offline figures for supervisor and committee submission | `python scripts/build_sad_pdf.py` |
| **Offline Printable HTML** | [SAD_Printable.html](books/html/SAD_Printable.html) | Self-contained offline HTML5 edition with inline base64 PNG figures, clickable TOC/List of Figures, and A4 `@media print` CSS | `python scripts/build_sad_html.py` |
| **Semester 1 Defense Presentation** | [PPTX](presentations/pptx/Semester1_Progress_Defense.pptx) · [PDF](presentations/pdf/Semester1_Progress_Defense.pdf) · [HTML](presentations/html/Semester1_Progress_Defense.html) | 12-slide 16:9 widescreen Semester 1 Progress & Architecture Defense deck (Chapters 1–3, 7 embedded figures, 100% offline) | `py -3.12 scripts/build_presentation.py` |

### Semester Split Editions

Alongside the full combined graduation book (`SAD_Book.*`), two standalone semester packages partition the chapters and diagram assets cleanly for semester-by-semester academic submission. Both packages are regenerated reproducibly via `py -3.12 scripts/build_semester_editions.py`:

| Semester Package | Included Scope | Printable PDF | Word Document (`.docx`) | Markdown Source | Standalone Figures (`PNG` & `SVG`) | Build Command |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Semester 1** | Chapters 1–3, 15 Figures (Figures 1–14, 19) | [SAD_Semester1_Book.pdf](books/pdf/SAD_Semester1_Book.pdf) | [SAD_Semester1_Book.docx](books/docx/SAD_Semester1_Book.docx) | [SAD_Semester1_Book.md](books/md/SAD_Semester1_Book.md) | [diagrams/png/](diagrams/png/) · [svg/](diagrams/svg/) | `py -3.12 scripts/build_semester_editions.py` |
| **Semester 2** | Chapters 4–6, 4 Figures (Figures 15–18) | [SAD_Semester2_Book.pdf](books/pdf/SAD_Semester2_Book.pdf) | [SAD_Semester2_Book.docx](books/docx/SAD_Semester2_Book.docx) | [SAD_Semester2_Book.md](books/md/SAD_Semester2_Book.md) | [diagrams/png/](diagrams/png/) · [svg/](diagrams/svg/) | `py -3.12 scripts/build_semester_editions.py` |

### Full Regeneration Sequence

Execute the following commands from the repository root using Python 3.12:

```bash
python scripts/render_diagrams.py
python scripts/build_sad_html.py
python scripts/build_sad_docx.py
python scripts/build_sad_pdf.py
py -3.12 scripts/build_semester_editions.py
py -3.12 scripts/build_presentation.py
```

---

## Document Sign-Off Summary

| Sign-Off Field | Details |
| :--- | :--- |
| **Prepared For** | Dr. Samar, Project Supervisor — Department of Cyber Security |
| **Prepared By** | Ahmed Ashraf Ammar (235204), Islam Mohammed (235164), Abdelrhman Mohamed AbdEl-latif (235216), Ahmed Waleed Mokthar (235052), Mohamed Waleed Mokthar (235051), Mohamed Ibrahim Elsayed (235401), Ali Ibrahim Elsayed (235332) |
| **Academic Year** | 2026–2027 |
| **Document Version** | Formal Edition v1.1 (First Semester – System Analysis and Design Baseline) |
| **Scope Covered** | 6 Formal Chapters, 19 Rendered Architectural Figures (SVG/PNG + Mermaid), 17 Curated OWASP Top 10 Checks, NIST SSDF Alignment, 15-Scenario Verification Matrix, and Multi-Format Publication Exports (`MD`, `DOCX`, `PDF`, `HTML`) |
| **Supervisor Approval Status** | Pending Review and Sign-Off for Transition to Second Semester Implementation |
