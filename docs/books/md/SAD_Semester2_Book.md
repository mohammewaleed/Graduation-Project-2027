# GRADUATION PROJECT BOOK – SEMESTER 2

## Developing a Lightweight OWASP Top 10 Vulnerability Scanner

*Tailored for Web Developers and Student Projects (Developer-Experience Focus)*

---

## Executive Abstract

This Semester 2 Graduation Project Book presents the detailed relational data model, REST and Server-Sent Events (SSE) API contracts, curated 17-check OWASP Top 10 (2021) catalog and multi-stack remediation knowledge base, ethical security governance, Architecture Decision Records (ADR-01–ADR-05), and empirical benchmarking protocol for the lightweight OWASP Top 10 vulnerability scanner. Covering Chapters 4 through 6 and Figures 15 through 18, this volume specifies the 3NF SQLAlchemy 2.0 schema (SQLite default with optional PostgreSQL profile), deterministic risk scoring and SHA-1 finding deduplication, pre-request local-scope allow-list and DNS-rebinding guardrails, NIST SSDF (SP 800-218) alignment, the 15-scenario System Verification Matrix (TC-01–TC-15), and automated evaluation across VulnBench, DVWA, and OWASP Juice Shop.

## Project Metadata

| Attribute | Specification |
| :--- | :--- |
| **Project Title** | Developing a Lightweight OWASP Top 10 Vulnerability Scanner (Tailored for Web Developers and Student Projects) |
| **Volume Scope** | Semester 2 Edition — Chapters 4–6 & Figures 15–18 |
| **Methodological Reference** | OWASP Top 10 (2021) & NIST SSDF (SP 800-218) |
| **Target Audience** | Junior Web Developers, University Students, and Small Development Teams |
| **Project Supervisor** | Dr. Samar |
| **Project Team** | Seven Members: Ahmed Ashraf Ammar (235204), Islam Mohammed (235164), Abdelrhman Mohamed AbdEl-latif (235216), Ahmed Waleed Mokthar (235052), Mohamed Waleed Mokthar (235051), Mohamed Ibrahim Elsayed (235401), Ali Ibrahim Elsayed (235332) |
| **Academic Year** | 2026–2027 |
| **Document Status** | Detailed Design, Security Governance & Validation – Semester 2 Edition (v1.1) |
| **Current Phase** | Second Semester – Data/API Design, Security ADRs, and Validation Strategy |
| **Next Phase** | Full-System Integration, Empirical Testbench Execution, and Graduation Defense |

---

## Table of Contents

- **[Chapter 4: Data Model, REST/SSE API, and Remediation Knowledge Base Design](#chapter-4-data-model-restsse-api-and-remediation-knowledge-base-design)**
  - [4.1 Third Normal Form (3NF) Entity-Relationship Diagram](#41-third-normal-form-3nf-entity-relationship-diagram)
  - [4.2 Complete Relational Data Dictionary](#42-complete-relational-data-dictionary)
  - [4.3 REST and SSE API Specification](#43-rest-and-sse-api-specification)
  - [4.4 Curated 17-Check Catalog and Developer Remediation JSON Schema](#44-curated-17-check-catalog-and-developer-remediation-json-schema)
  - [4.5 Chapter Summary](#45-chapter-summary)
- **[Chapter 5: Security, Ethics, Risk Management, and Architecture Decision Records](#chapter-5-security-ethics-risk-management-and-architecture-decision-records)**
  - [5.1 Ethical and Legal Operating Principles](#51-ethical-and-legal-operating-principles)
  - [5.2 Mandatory Scope Guardrail and Anti-Abuse Controls](#52-mandatory-scope-guardrail-and-anti-abuse-controls)
  - [5.3 Scanner Self-Security Controls](#53-scanner-self-security-controls)
  - [5.4 NIST Secure Software Development Framework (SSDF SP 800-218) Alignment](#54-nist-secure-software-development-framework-ssdf-sp-800-218-alignment)
  - [5.5 Risk Register](#55-risk-register)
  - [5.6 Formal Architecture Decision Records (ADRs)](#56-formal-architecture-decision-records-adrs)
  - [5.7 Chapter Summary](#57-chapter-summary)
- **[Chapter 6: Validation Strategy, Benchmarking, and Developer-Experience Evaluation](#chapter-6-validation-strategy-benchmarking-and-developer-experience-evaluation)**
  - [6.1 Validation Objectives and Testbench Architecture](#61-validation-objectives-and-testbench-architecture)
  - [6.2 Quantitative Evaluation Metrics and Acceptance Gates](#62-quantitative-evaluation-metrics-and-acceptance-gates)
  - [6.3 Automated Evaluation Pipeline (scripts/evaluate.py)](#63-automated-evaluation-pipeline-scriptsevaluatepy)
  - [6.4 Target Benchmark Visualization and Reporting Templates](#64-target-benchmark-visualization-and-reporting-templates)
  - [6.5 System Verification Matrix (TC-01 to TC-15)](#65-system-verification-matrix-tc-01-to-tc-15)
  - [6.6 Qualitative Developer-Experience Comparison Rubric Against OWASP ZAP Baseline](#66-qualitative-developer-experience-comparison-rubric-against-owasp-zap-baseline)
  - [6.7 Known Limitations and Honest Threats-to-Validity Disclosure](#67-known-limitations-and-honest-threats-to-validity-disclosure)
  - [6.8 Chapter Summary](#68-chapter-summary)
- **[References](#references)**
- **[Semester 2 Final Sign-Off Summary](#semester-2-final-sign-off-summary)**

---

## List of Figures

| Figure | Title | Chapter | Image Asset | Mermaid Source |
| :---: | :--- | :---: | :--- | :--- |
| **Figure 15** | Third Normal Form (3NF) Entity-Relationship Diagram | Chapter 4 | [15_erd_3nf.png](../../diagrams/png/15_erd_3nf.png) | [15_erd_3nf.mmd](../../diagrams/mmd/15_erd_3nf.mmd) |
| **Figure 16** | Pre-Request Scope Guardrail and Safety Decision Flow | Chapter 5 | [16_scope_guardrail_flow.png](../../diagrams/png/16_scope_guardrail_flow.png) | [16_scope_guardrail_flow.mmd](../../diagrams/mmd/16_scope_guardrail_flow.mmd) |
| **Figure 17** | Target Detection Accuracy Benchmark Profile Across OWASP Categories | Chapter 6 | [17_accuracy_benchmark_chart.png](../../diagrams/png/17_accuracy_benchmark_chart.png) | [17_accuracy_benchmark_chart.mmd](../../diagrams/mmd/17_accuracy_benchmark_chart.mmd) |
| **Figure 18** | Target Crawler Coverage and Latency Profile Across Scan Modes | Chapter 6 | [18_coverage_latency_chart.png](../../diagrams/png/18_coverage_latency_chart.png) | [18_coverage_latency_chart.mmd](../../diagrams/mmd/18_coverage_latency_chart.mmd) |

---

# Chapter 4: Data Model, REST/SSE API, and Remediation Knowledge Base Design

This chapter specifies the relational data persistence model, Third Normal Form (3NF) integrity rules, deterministic risk scoring and deduplication algorithms, REST and Server-Sent Events (SSE) API contracts, the curated 17-check OWASP Top 10 (2021) catalogue, and the developer-centric multi-stack Remediation Knowledge Base (`kb.json`). All persistence and interface definitions are engineered to maintain minimal local operational overhead—defaulting to SQLite in Write-Ahead Logging (WAL) mode with drop-in PostgreSQL 16 compatibility via SQLAlchemy 2.0—while delivering exact endpoint/parameter mappings and copy-ready code fixes to web developers and student teams.

---

## 4.1 Third Normal Form (3NF) Entity-Relationship Diagram

The relational database schema comprises four core entities—`PROJECTS`, `SCANS`, `ENDPOINTS`, and `FINDINGS`—normalized to **Third Normal Form (3NF)**:

- **First Normal Form (1NF):** Every table defines an immutable UUID v4 primary key (`id`) and atomic relational columns with zero repeating groups. Semi-structured auxiliary payloads that are not queried as relational child tables (`query_params`, `form_fields`, `config_snapshot`, `remediation_json`) are stored in typed JSON columns natively supported by both SQLite (`JSON1`) and PostgreSQL 16 (`JSONB`/`JSON`).
- **Second Normal Form (2NF):** Because every primary key is a single-column surrogate UUID, partial key dependencies are structurally impossible.
- **Third Normal Form (3NF):** Non-key attributes depend exclusively on their owning entity's primary key with zero transitive dependencies across entities: project metadata resides solely on `PROJECTS`, scan execution telemetry on `SCANS`, crawled attack surface metadata on `ENDPOINTS`, and vulnerability detections plus triage states on `FINDINGS`.
- **Controlled Materialized Rollups on `SCANS`:** The summary metrics `risk_score`, `endpoints_found`, and `critical_count` through `info_count` on `SCANS` are explicitly documented derived rollups recalculated atomically inside the same database transaction upon scan completion, cancellation, or finding triage updates. This design preserves strict consistency while enabling O(1) dashboard loading and historical trend rendering.

![Figure 15: Third Normal Form (3NF) Entity-Relationship Diagram](../../diagrams/png/15_erd_3nf.png)

*Figure 15: Third Normal Form (3NF) Entity-Relationship Diagram (Source: [15_erd_3nf.mmd](../../diagrams/mmd/15_erd_3nf.mmd)).*

### Table 4.1: Entity Relationships and Referential Integrity Rules

| Relationship | Cardinality | Foreign Key and Cascade Policy | Architectural Rationale |
| :--- | :--- | :--- | :--- |
| `PROJECTS` -> `SCANS` | `1 : 0..*` | `scans.project_id -> projects.id ON DELETE CASCADE` | Removing a project cleanly purges all associated historical scans, endpoints, and findings without leaving orphaned rows. |
| `SCANS` -> `ENDPOINTS` | `1 : 0..*` | `endpoints.scan_id -> scans.id ON DELETE CASCADE` | Each scan preserves an immutable point-in-time snapshot of the target application's discovered attack surface. |
| `SCANS` -> `FINDINGS` | `1 : 0..*` | `findings.scan_id -> scans.id ON DELETE CASCADE` | Findings are scoped strictly to the originating scan run to guarantee deterministic historical diff comparisons. |
| `ENDPOINTS` -> `FINDINGS` | `0..1 : 0..*` | `findings.endpoint_id -> endpoints.id ON DELETE SET NULL` | Nullable foreign key accommodates target-wide or wordlist-discovered checks (e.g., `sensitive_files`, `insecure_transport`) that may not map to a crawled link while parameter and form checks reference their exact `ENDPOINTS` row. |

---

## 4.2 Complete Relational Data Dictionary

All ORM entities are implemented using **SQLAlchemy 2.0** `DeclarativeBase` and typed `Mapped[...]` declarations so an identical codebase executes seamlessly against both **SQLite** (default `sqlite:///./data/scanner.db` initialized with `PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000`) and **PostgreSQL 16** (enabled via `--profile postgres` and `DATABASE_URL`). Tables 4.2 through 4.5 provide the complete column-level data dictionary.

### Table 4.2: Data Dictionary — `projects`

| Column | SQLAlchemy 2.0 Type | SQLite Type | PostgreSQL 16 Type | Constraints | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `id` | `String(36)` | `VARCHAR(36)` | `VARCHAR(36)` | `PRIMARY KEY` | UUID v4 unique project identifier. |
| `name` | `String(120)` | `VARCHAR(120)` | `VARCHAR(120)` | `NOT NULL` | Human-readable project display name (e.g., `"Capstone E-Shop API"`). |
| `target_url` | `String(512)` | `VARCHAR(512)` | `VARCHAR(512)` | `NOT NULL` | Normalized base URL validated against `ScopeGuardrail` allow-list. |
| `framework_hint` | `String(32)` | `VARCHAR(32)` | `VARCHAR(32)` | `NOT NULL, DEFAULT 'auto'` | Preferred stack tab in Fix Modal (`fastapi`, `flask`, `express`, `php`, `html`, `auto`). |
| `ownership_confirmed` | `Boolean` | `BOOLEAN` | `BOOLEAN` | `NOT NULL, CHECK (ownership_confirmed = 1)` | Mandatory explicit developer authorization confirmation flag. |
| `description` | `Text` | `TEXT` | `TEXT` | `NULLABLE` | Optional course, sprint, or architecture notes. |
| `created_at` | `DateTime(timezone=True)` | `DATETIME` | `TIMESTAMPTZ` | `NOT NULL, DEFAULT utcnow` | Project creation timestamp (UTC). |
| `updated_at` | `DateTime(timezone=True)` | `DATETIME` | `TIMESTAMPTZ` | `NOT NULL, DEFAULT utcnow` | Last modification timestamp (UTC). |

### Table 4.3: Data Dictionary — `scans`

| Column | SQLAlchemy 2.0 Type | SQLite Type | PostgreSQL 16 Type | Constraints | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `id` | `String(36)` | `VARCHAR(36)` | `VARCHAR(36)` | `PRIMARY KEY` | UUID v4 unique scan identifier. |
| `project_id` | `String(36)` | `VARCHAR(36)` | `VARCHAR(36)` | `FK -> projects.id (CASCADE), NOT NULL, INDEX` | Owning project foreign key. |
| `profile` | `String(16)` | `VARCHAR(16)` | `VARCHAR(16)` | `NOT NULL, CHECK IN ('quick','standard','deep')` | Selected crawl depth and active-check execution profile. |
| `status` | `String(16)` | `VARCHAR(16)` | `VARCHAR(16)` | `NOT NULL, INDEX, CHECK IN ('queued','crawling','scanning','completed','failed','cancelled')` | Current lifecycle state machine value. |
| `progress_pct` | `Integer` | `INTEGER` | `INTEGER` | `NOT NULL, DEFAULT 0, CHECK (0..100)` | Completion percentage broadcast over SSE. |
| `current_phase` | `String(64)` | `VARCHAR(64)` | `VARCHAR(64)` | `NOT NULL, DEFAULT 'queued'` | Active execution phase or running check identifier. |
| `endpoints_found` | `Integer` | `INTEGER` | `INTEGER` | `NOT NULL, DEFAULT 0` | Count of unique normalized endpoints discovered by `BFSCrawler`. |
| `requests_sent` | `Integer` | `INTEGER` | `INTEGER` | `NOT NULL, DEFAULT 0` | Cumulative HTTP requests dispatched within the 2,000-request cap. |
| `risk_score` | `Integer` | `INTEGER` | `INTEGER` | `NOT NULL, DEFAULT 0, CHECK (0..100)` | Bounded weighted risk score excluding `false_positive` findings. |
| `critical_count` | `Integer` | `INTEGER` | `INTEGER` | `NOT NULL, DEFAULT 0` | Count of active (non-`false_positive`) Critical findings. |
| `high_count` | `Integer` | `INTEGER` | `INTEGER` | `NOT NULL, DEFAULT 0` | Count of active High findings. |
| `medium_count` | `Integer` | `INTEGER` | `INTEGER` | `NOT NULL, DEFAULT 0` | Count of active Medium findings. |
| `low_count` | `Integer` | `INTEGER` | `INTEGER` | `NOT NULL, DEFAULT 0` | Count of active Low findings. |
| `info_count` | `Integer` | `INTEGER` | `INTEGER` | `NOT NULL, DEFAULT 0` | Count of active Info findings. |
| `config_snapshot` | `JSON` | `JSON` | `JSONB / JSON` | `NOT NULL, DEFAULT '{}'` | Redacted execution settings (`rate_limit_rps`, `max_requests`, `auth_mode`, `max_depth`); raw secrets are never persisted. |
| `error_message` | `Text` | `TEXT` | `TEXT` | `NULLABLE` | Sanitized fatal error description populated exclusively when `status='failed'`. |
| `started_at` | `DateTime(timezone=True)` | `DATETIME` | `TIMESTAMPTZ` | `NULLABLE` | Worker execution start timestamp (UTC). |
| `finished_at` | `DateTime(timezone=True)` | `DATETIME` | `TIMESTAMPTZ` | `NULLABLE` | Completion, cancellation, or failure timestamp (UTC). |
| `created_at` | `DateTime(timezone=True)` | `DATETIME` | `TIMESTAMPTZ` | `NOT NULL, INDEX, DEFAULT utcnow` | Scan enqueue timestamp (UTC). |

### Table 4.4: Data Dictionary — `endpoints`

| Column | SQLAlchemy 2.0 Type | SQLite Type | PostgreSQL 16 Type | Constraints | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `id` | `String(36)` | `VARCHAR(36)` | `VARCHAR(36)` | `PRIMARY KEY` | UUID v4 unique endpoint identifier. |
| `scan_id` | `String(36)` | `VARCHAR(36)` | `VARCHAR(36)` | `FK -> scans.id (CASCADE), NOT NULL, INDEX` | Owning scan foreign key. |
| `method` | `String(10)` | `VARCHAR(10)` | `VARCHAR(10)` | `NOT NULL` | Uppercase HTTP verb (`GET`, `POST`, `PUT`, `DELETE`). |
| `url` | `Text` | `TEXT` | `TEXT` | `NOT NULL` | Full normalized endpoint URL. |
| `normalized_path` | `String(512)` | `VARCHAR(512)` | `VARCHAR(512)` | `NOT NULL, INDEX` | Canonical path with collapsed duplicate slashes and standardized trailing slash. |
| `status_code` | `Integer` | `INTEGER` | `INTEGER` | `NULLABLE` | HTTP status code returned during crawl discovery. |
| `content_type` | `String(128)` | `VARCHAR(128)` | `VARCHAR(128)` | `NULLABLE` | Normalized MIME media type (e.g., `text/html`, `application/json`). |
| `depth` | `Integer` | `INTEGER` | `INTEGER` | `NOT NULL, DEFAULT 0` | Breadth-first crawl hop count from base URL. |
| `query_params` | `JSON` | `JSON` | `JSONB / JSON` | `NOT NULL, DEFAULT '[]'` | Extracted URL query parameter names. |
| `form_fields` | `JSON` | `JSON` | `JSONB / JSON` | `NOT NULL, DEFAULT '[]'` | Extracted HTML form input descriptors (`[{"name": "user", "type": "text"}]`). |
| `discovered_at` | `DateTime(timezone=True)` | `DATETIME` | `TIMESTAMPTZ` | `NOT NULL, DEFAULT utcnow` | Endpoint discovery timestamp (UTC). |

### Table 4.5: Data Dictionary — `findings`

| Column | SQLAlchemy 2.0 Type | SQLite Type | PostgreSQL 16 Type | Constraints | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `id` | `String(36)` | `VARCHAR(36)` | `VARCHAR(36)` | `PRIMARY KEY` | UUID v4 unique finding identifier. |
| `scan_id` | `String(36)` | `VARCHAR(36)` | `VARCHAR(36)` | `FK -> scans.id (CASCADE), NOT NULL, INDEX` | Owning scan foreign key. |
| `endpoint_id` | `String(36)` | `VARCHAR(36)` | `VARCHAR(36)` | `FK -> endpoints.id (SET NULL), NULLABLE, INDEX` | Optional reference to the discovered `endpoints` row. |
| `check_id` | `String(64)` | `VARCHAR(64)` | `VARCHAR(64)` | `NOT NULL, INDEX` | Canonical identifier of one of the 17 curated plugins. |
| `owasp_category` | `String(16)` | `VARCHAR(16)` | `VARCHAR(16)` | `NOT NULL, INDEX` | OWASP Top 10 (2021) category code (e.g., `A03:2021`). |
| `cwe_id` | `String(16)` | `VARCHAR(16)` | `VARCHAR(16)` | `NOT NULL` | Common Weakness Enumeration identifier (e.g., `CWE-89`, `CWE-79`). |
| `title` | `String(200)` | `VARCHAR(200)` | `VARCHAR(200)` | `NOT NULL` | Concise developer-oriented finding title. |
| `severity` | `String(16)` | `VARCHAR(16)` | `VARCHAR(16)` | `NOT NULL, INDEX, CHECK IN ('critical','high','medium','low','info')` | Severity classification. |
| `confidence` | `String(16)` | `VARCHAR(16)` | `VARCHAR(16)` | `NOT NULL, CHECK IN ('high','medium','low','tentative')` | Detection certainty (`tentative` designated for `idor_heuristic`). |
| `status` | `String(16)` | `VARCHAR(16)` | `VARCHAR(16)` | `NOT NULL, DEFAULT 'open', INDEX, CHECK IN ('open','fixed','false_positive','accepted')` | Developer triage lifecycle state. |
| `fingerprint` | `String(40)` | `VARCHAR(40)` | `VARCHAR(40)` | `NOT NULL, INDEX` | 40-character lowercase SHA-1 hex digest for deduplication and diffing. |
| `http_method` | `String(10)` | `VARCHAR(10)` | `VARCHAR(10)` | `NOT NULL` | Exact HTTP verb where the vulnerability manifested. |
| `affected_url` | `Text` | `TEXT` | `TEXT` | `NOT NULL` | Exact vulnerable endpoint URL. |
| `parameter_name` | `String(128)` | `VARCHAR(128)` | `VARCHAR(128)` | `NULLABLE` | Exact vulnerable query parameter, form field, cookie, or HTTP header name. |
| `evidence_snippet` | `Text` | `TEXT` | `TEXT` | `NOT NULL` | Sanitized, truncated (<= 500 characters) proof-of-detection excerpt. |
| `plain_explanation` | `Text` | `TEXT` | `TEXT` | `NOT NULL` | Plain-language root cause and impact explanation tailored for developers. |
| `remediation_json` | `JSON` | `JSON` | `JSONB / JSON` | `NOT NULL` | Embedded multi-stack Before/After code fixes and verification steps loaded from `kb.json`. |
| `triage_note` | `Text` | `TEXT` | `TEXT` | `NULLABLE` | Optional developer justification recorded during triage. |
| `created_at` | `DateTime(timezone=True)` | `DATETIME` | `TIMESTAMPTZ` | `NOT NULL, DEFAULT utcnow` | Finding creation timestamp (UTC). |
| `updated_at` | `DateTime(timezone=True)` | `DATETIME` | `TIMESTAMPTZ` | `NOT NULL, DEFAULT utcnow` | Most recent triage modification timestamp (UTC). |

### Table 4.6: Composite Indexes and Uniqueness Constraints

| Index Name | Table and Columns | Performance and Integrity Role |
| :--- | :--- | :--- |
| `uq_findings_scan_fingerprint` | `findings (scan_id, fingerprint)` — `UNIQUE` | Enforces intra-scan deduplication at the persistence tier. |
| `ix_findings_scan_severity_status` | `findings (scan_id, severity, status)` | Accelerates Findings Explorer filtering and atomic risk-score recalculation. |
| `ix_scans_project_created` | `scans (project_id, created_at DESC)` | Optimizes project scan history listings and latest-scan overview queries. |
| `uq_endpoints_scan_method_path` | `endpoints (scan_id, method, normalized_path)` — `UNIQUE` | Guarantees a strictly deduplicated attack-surface inventory per scan. |

### Deterministic Risk Score and Deduplication Formulas

#### 1. Scan Risk Score Formula (0–100 Bounded)

To provide an intuitive, bounded security posture metric that updates immediately as vulnerabilities are remediated or dismissed as false positives, the scan risk score is defined as:

```text
risk_score = min(100, 10 * N_critical + 6 * N_high + 3 * N_medium + 1 * N_low)
```

where `N_critical`, `N_high`, `N_medium`, and `N_low` denote the number of findings in the scan whose triage `status != 'false_positive'`. Findings classified as `info` carry weight `0` so purely informational hardening notes do not distort the risk indicator. Whenever a triage update executes via `PATCH /api/findings/{finding_id}`, the application service atomically recomputes `risk_score` and the severity rollup counts on the parent `SCANS` record.

#### 2. Finding Fingerprint Formula (SHA-1)

To guarantee deterministic intra-scan deduplication and accurate cross-scan regression comparisons (`New`, `Fixed`, `Unchanged`) across successive coding iterations, every finding is assigned a canonical 40-character SHA-1 digest:

```text
fingerprint = SHA1(
    lower(check_id) + "|" +
    upper(http_method) + "|" +
    normalized_path + "|" +
    lower(parameter_name or "")
)
```

Hashing the canonical structural tuple `(check_id, http_method, normalized_path, parameter_name)` rather than volatile query values or timestamps ensures that an identical vulnerability observed across two separate scans yields the exact same fingerprint, supporting precise set-theoretic diffing:

- **New Findings:** `Fingerprints(target_scan) - Fingerprints(baseline_scan)`
- **Fixed Findings:** `Fingerprints(baseline_scan) - Fingerprints(target_scan)`
- **Unchanged Findings:** `Fingerprints(baseline_scan) ∩ Fingerprints(target_scan)`

---

## 4.3 REST and SSE API Specification

All API routes are version-scoped under the `/api` prefix, serialize payloads using Pydantic v2 schemas (`application/json` by default, with `text/event-stream` for SSE and `text/html` for standalone reports), and publish an interactive OpenAPI 3.1 specification at `/api/docs`. Table 4.7 enumerates the complete REST and SSE interface contract.

### Table 4.7: Complete REST and SSE Endpoint Catalogue

| Domain | Method and Path | Success Status | Request Parameters / Body | Response Summary |
| :--- | :--- | :--- | :--- | :--- |
| **Health** | `GET /api/health` | `200 OK` | None | Returns `{"status": "ok", "version": "0.1.0", "database": {"dialect": "sqlite\|postgresql", "status": "up"}}`. |
| **Projects** | `POST /api/projects` | `201 Created` | JSON: `name`, `target_url`, `framework_hint`, `ownership_confirmed: true`, `description?` | Validates target against `ScopeGuardrail` and creates project; returns `403` for out-of-scope targets or `422` if `ownership_confirmed` is false. |
| **Projects** | `GET /api/projects` | `200 OK` | Query: `limit?`, `offset?` | Returns paginated project list enriched with latest scan status and `risk_score`. |
| **Projects** | `GET /api/projects/{project_id}` | `200 OK` | Path: `project_id` | Returns full project record, scan summary history, and risk-score trend series. |
| **Projects** | `PATCH /api/projects/{project_id}` | `200 OK` | JSON: partial `name`, `framework_hint`, `description` | Updates mutable project metadata (`target_url` edits re-run allow-list validation). |
| **Projects** | `DELETE /api/projects/{project_id}` | `204 No Content` | Path: `project_id` | Deletes the project and cascades removal of associated scans, endpoints, and findings. |
| **Scans** | `POST /api/projects/{project_id}/scans` | `202 Accepted` | JSON: `profile` (`quick\|standard\|deep`), `auth?` (`none\|cookie\|bearer\|dvwa_login` + transient credentials), `rate_limit_rps?`, `max_requests?` | Enqueues job on `ThreadPoolExecutor`, returning `{scan_id, status: "queued", stream_url}`. |
| **Scans** | `GET /api/projects/{project_id}/scans` | `200 OK` | Path: `project_id`; Query: `status?` | Lists project scans ordered newest-first with severity rollups and execution duration. |
| **Scans** | `GET /api/scans/{scan_id}` | `200 OK` | Path: `scan_id` | Returns complete scan detail, progress metrics, severity counts, OWASP distribution, and `risk_score`. |
| **Scans** | `POST /api/scans/{scan_id}/cancel` | `202 Accepted` | Path: `scan_id` | Triggers `cancel_event.set()` in the cancellation registry; returns `409 Conflict` if scan is already terminal. |
| **SSE Live** | `GET /api/scans/{scan_id}/stream` | `200 OK` (`text/event-stream`) | Path: `scan_id` | Streams real-time SSE phase changes, progress metrics, warnings, finding summaries, and terminal status events. |
| **Endpoints** | `GET /api/scans/{scan_id}/endpoints` | `200 OK` | Query: `method?`, `path_contains?`, `status_code?` | Lists discovered attack-surface endpoints with extracted query parameters and HTML form fields. |
| **Findings** | `GET /api/scans/{scan_id}/findings` | `200 OK` | Query: `severity?`, `owasp_category?`, `status?`, `check_id?`, `q?` | Returns filtered findings ordered by severity (`critical` through `info`) with location mapping badges. |
| **Findings** | `GET /api/findings/{finding_id}` | `200 OK` | Path: `finding_id` | Returns complete finding detail including sanitized evidence, plain explanation, and multi-stack `remediation_json`. |
| **Triage** | `PATCH /api/findings/{finding_id}` | `200 OK` | JSON: `status` (`open\|fixed\|false_positive\|accepted`), `triage_note?` | Persists triage transition and atomically recalculates parent scan `risk_score` and severity counts. |
| **Compare** | `GET /api/projects/{project_id}/compare` | `200 OK` | Query: `baseline_scan_id`, `target_scan_id` | Executes fingerprint set diff returning `summary` (`risk_delta`, counts) plus `new_findings`, `fixed_findings`, and `unchanged_findings`. |
| **Reports** | `GET /api/scans/{scan_id}/report.json` | `200 OK` (`application/json`) | Path: `scan_id` | Exports complete structured JSON audit bundle (project metadata, scan metrics, endpoints, findings, code fixes). |
| **Reports** | `GET /api/scans/{scan_id}/report.html` | `200 OK` (`text/html`) | Path: `scan_id` | Exports standalone, self-contained HTML developer report rendered via Jinja2 with strict autoescaping. |
| **Catalog** | `GET /api/checks` | `200 OK` | Query: `category?`, `profile?` | Returns live metadata for all 17 registered `BaseCheck` plugins from `CheckRegistry`. |

### Standard Error Envelope

All `4xx` and `5xx` error responses conform to a uniform structured JSON envelope so frontend modules can render actionable inline error notifications deterministically:

```json
{
  "error": {
    "code": "TARGET_OUT_OF_SCOPE",
    "message": "Target host 'example.com' is blocked by the local-only Scope Guardrail.",
    "details": {
      "target_url": "https://example.com",
      "allowed_hosts": ["localhost", "127.0.0.1", "host.docker.internal", "dvwa", "juice-shop", "vulnbench"],
      "hint": "Use a local development server or an isolated testbench container."
    }
  }
}
```

### Table 4.8: Standard HTTP Error Status Code Mapping

| HTTP Status | Canonical Error Code | Triggering Condition |
| :--- | :--- | :--- |
| `400 Bad Request` | `INVALID_SCAN_COMPARISON` | Comparing scans belonging to distinct projects or scans not in a comparable state. |
| `403 Forbidden` | `TARGET_OUT_OF_SCOPE` / `OWNERSHIP_NOT_CONFIRMED` | Target violates `ScopeGuardrail` allow-list/DNS check, or `ownership_confirmed` is `false`. |
| `404 Not Found` | `RESOURCE_NOT_FOUND` | Referenced `project_id`, `scan_id`, or `finding_id` does not exist. |
| `409 Conflict` | `SCAN_ALREADY_TERMINAL` | Cancellation requested for a scan already in `completed`, `cancelled`, or `failed` state. |
| `422 Unprocessable Entity` | `VALIDATION_ERROR` | Pydantic v2 validation error (invalid enum value, malformed URL, or missing required field). |
| `429 Too Many Requests` | `WORKER_POOL_SATURATED` | Active concurrent scan requests exceed the configured local worker pool queue capacity. |
| `500 Internal Server Error` | `INTERNAL_SERVER_ERROR` | Unexpected runtime exception (full stack trace logged server-side; sanitized response returned to client). |

### Server-Sent Events (SSE) Stream Specification (`GET /api/scans/{scan_id}/stream`)

The SSE route emits `Content-Type: text/event-stream`, `Cache-Control: no-cache`, and `X-Accel-Buffering: no`. If a client attaches to an already-terminal scan, the endpoint immediately sends the terminal state event and closes the stream cleanly. Table 4.9 documents the exact SSE event catalogue.

### Table 4.9: SSE Stream Event Catalogue and Wire Payloads

| SSE Event Name | Emission Trigger | Example JSON `data` Payload |
| :--- | :--- | :--- |
| `phase_change` | Scan state advances (`queued` -> `crawling` -> `scanning`) | `{"scan_id": "a1b2...", "status": "crawling", "phase": "crawling", "progress_pct": 5, "timestamp": "2026-10-15T10:00:02Z"}` |
| `progress` | Crawl batch or check execution updates progress | `{"scan_id": "a1b2...", "progress_pct": 48, "current_check": "sqli_error_based", "endpoints_found": 24, "requests_sent": 182}` |
| `finding_discovered` | Deduplicated, enriched finding persisted to database | `{"scan_id": "a1b2...", "finding_id": "f9e8...", "check_id": "sqli_error_based", "severity": "critical", "title": "Error-Based SQL Injection", "location": "POST /api/login · field: user"}` |
| `check_warning` | Isolated plugin encounters timeout or non-fatal exception | `{"scan_id": "a1b2...", "check_id": "xss_reflected", "warning": "ReadTimeout on /slow-endpoint (skipped endpoint, scan continuing)"}` |
| `heartbeat` | Periodic keep-alive emitted every 15 seconds while idle | `{"scan_id": "a1b2...", "ts": "2026-10-15T10:00:15Z"}` |
| `scan_completed` | Terminal success (stream flushes and closes) | `{"scan_id": "a1b2...", "status": "completed", "risk_score": 42, "counts": {"critical": 1, "high": 3, "medium": 4, "low": 2, "info": 1}}` |
| `scan_cancelled` | Terminal cooperative cancellation (stream closes) | `{"scan_id": "a1b2...", "status": "cancelled", "partial_findings_preserved": true, "risk_score": 16}` |
| `scan_failed` | Terminal unrecoverable error (stream closes) | `{"scan_id": "a1b2...", "status": "failed", "error": "Target unreachable during pre-flight check"}` |

---

## 4.4 Curated 17-Check Catalog and Developer Remediation JSON Schema

To maximize signal-to-noise ratio for student and web-developer projects, the scanner implements **17 high-impact, curated OWASP Top 10 (2021) checks** partitioned across four execution categories: **8 Passive**, **5 Active Safe**, **3 Discovery**, and **1 Deep Auth (Tentative)**. Table 4.10 specifies every check's taxonomy, default severity, profile inclusion, and non-destructive detection method.

### Table 4.10: Curated 17-Check OWASP Top 10 (2021) Detection Catalogue

| # | `check_id` | Category | OWASP Top 10 (2021) | CWE | Default Severity | Profiles | Non-Destructive Detection Mechanism |
| :-: | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `missing_security_headers` | Passive | A05:2021 Security Misconfiguration | CWE-693 | Medium | Quick, Standard, Deep | Inspects crawled HTML responses for absent `X-Content-Type-Options`, `X-Frame-Options` (or `frame-ancestors`), `Referrer-Policy`, and `Strict-Transport-Security` (when HTTPS). |
| 2 | `weak_csp` | Passive | A05:2021 Security Misconfiguration | CWE-693 | Medium | Quick, Standard, Deep | Parses `Content-Security-Policy` headers for absent `default-src`/`script-src` directives or permissive tokens (`'unsafe-inline'`, `'unsafe-eval'`, wildcard `*`). |
| 3 | `server_banner_leak` | Passive | A05:2021 Security Misconfiguration | CWE-200 | Low | Quick, Standard, Deep | Flags version-disclosing `Server`, `X-Powered-By`, or `X-AspNet-Version` response headers (e.g., `Werkzeug/3.0.1 Python/3.12`). |
| 4 | `verbose_error_pages` | Passive | A05:2021 Security Misconfiguration | CWE-209 | Medium | Quick, Standard, Deep | Scans response bodies for unhandled framework stack traces (Python Traceback, Node/Express stack, PHP Fatal/Notice, raw SQL errors, or Werkzeug debuggers). |
| 5 | `insecure_cookies` | Passive | A02:2021 Cryptographic Failures | CWE-614 | Medium | Quick, Standard, Deep | Inspects `Set-Cookie` headers on session-oriented cookies for missing `HttpOnly`, `SameSite`, or `Secure` (over HTTPS) flags. |
| 6 | `insecure_transport` | Passive | A02:2021 Cryptographic Failures | CWE-319 | Low / Medium | Quick, Standard, Deep | Detects unencrypted HTTP login/password forms or mixed-content active script loads while noting local development exceptions for `localhost`. |
| 7 | `csrf_missing_token` | Passive | A01:2021 Broken Access Control | CWE-352 | Medium | Quick, Standard, Deep | Analyzes state-changing HTML `POST` forms (excluding search forms) for missing hidden CSRF tokens (`csrf_token`, `_csrf`, `authenticity_token`) combined with non-`Strict` session cookies. |
| 8 | `outdated_js_components` | Passive | A06:2021 Vulnerable and Outdated Components | CWE-1104 | Medium / High | Quick, Standard, Deep | Extracts versioned client-side JavaScript library references from `<script src>` paths and headers (e.g., jQuery, Bootstrap, AngularJS, Lodash), evaluating versions via `packaging.version` against a curated vulnerability manifest. |
| 9 | `cors_misconfig` | Active Safe | A05:2021 Security Misconfiguration | CWE-942 | High | Standard, Deep | Dispatches a benign synthetic `Origin: https://evil.example.test` header and checks whether `Access-Control-Allow-Origin` echoes the untrusted origin, particularly alongside `Access-Control-Allow-Credentials: true`. |
| 10 | `sqli_error_based` | Active Safe | A03:2021 Injection | CWE-89 | Critical | Standard, Deep | Submits harmless syntax-breaking characters (`'`, `"`, `' OR '1'='1`) into query parameters and form fields, matching DBMS-specific error signatures (SQLite, MySQL, PostgreSQL, MSSQL, Oracle) absent from the baseline response. |
| 11 | `sqli_boolean_diff` | Active Safe | A03:2021 Injection | CWE-89 | High | Standard, Deep | Evaluates response length and structural similarity differentials across benign true (`' AND 1=1--`) versus false (`' AND 1=2--`) boolean probes relative to a stable baseline, avoiding destructive writes or `SLEEP()` delays. |
| 12 | `xss_reflected` | Active Safe | A03:2021 Injection | CWE-79 | High | Standard, Deep | Injects a unique inert canary token delimited by harmless HTML characters (e.g., `devscan<x7f>"'probe`) and checks whether it reflects unescaped in an executable HTML or attribute context without executing browser scripts. |
| 13 | `open_redirect` | Active Safe | A01:2021 Broken Access Control | CWE-601 | Medium | Standard, Deep | Probes redirect-oriented parameters (`next`, `redirect`, `return_to`, `url`) with an inert external canary URL (`https://redirect-check.example.test`) and inspects raw `3xx Location` headers under `allow_redirects=False`. |
| 14 | `sensitive_files` | Discovery | A05:2021 Security Misconfiguration | CWE-538 | High | Standard, Deep | Probes a compact, high-signal set of inadvertently exposed developer artifacts (`/.env`, `/.git/HEAD`, `/config.php.bak`, `/backup.sql`, `/swagger.json`) filtered through `Soft404Calibrator` and strict content validators (e.g., `ref: refs/heads/`). |
| 15 | `directory_listing` | Discovery | A05:2021 Security Misconfiguration | CWE-548 | Low / Medium | Standard, Deep | Evaluates crawled parent directory paths for enabled web-server auto-index pages (`Index of /`, `Parent Directory`). |
| 16 | `forced_browsing_admin` | Discovery | A01:2021 Broken Access Control | CWE-425 | High | Standard, Deep | Probes common administrative and diagnostic endpoints (`/admin`, `/admin/users`, `/debug`, `/phpinfo.php`) filtered through `Soft404Calibrator` to detect unauthenticated `200 OK` exposure without a login redirect. |
| 17 | `idor_heuristic` | Deep Auth | A01:2021 Broken Access Control | CWE-639 | High (Confidence: `tentative`) | Deep | Active only when authentication is enabled: identifies sequential numeric object identifiers in routes or query parameters (e.g., `/api/orders/101`), probes an adjacent ID (`102`), and flags non-403/404 distinct-body responses as **tentative** for manual developer confirmation. |

### Developer Remediation Knowledge Base (`backend/scanner/remediation/kb.json`) Schema

Every enriched finding returned by `GET /api/findings/{finding_id}` and displayed in the Dashboard Actionable Code Fix Modal combines exact location telemetry (`POST /api/login · field: user`), a sanitized proof-of-detection snippet, a plain-language root-cause summary, verification steps, and copy-ready Before/After code fixes across all five supported developer stacks (**FastAPI**, **Flask**, **Express**, **PHP**, and **HTML**). Listing 4.1 presents a complete concrete JSON payload conforming to this schema.

#### Listing 4.1: Concrete Enriched Finding and Multi-Stack Remediation JSON Payload

```json
{
  "id": "f9e8d7c6-5432-41ab-9cde-1234567890ab",
  "scan_id": "a1b2c3d4-1111-4222-8333-abcdef012345",
  "endpoint_id": "e4f5a6b7-9999-4888-8777-fedcba987654",
  "check_id": "sqli_error_based",
  "owasp_category": "A03:2021",
  "cwe_id": "CWE-89",
  "title": "Error-Based SQL Injection in Login Form",
  "severity": "critical",
  "confidence": "high",
  "status": "open",
  "fingerprint": "9f2c7b1e4a8d3c5f0b6e1a2d4c8e7f901234abcd",
  "location_badge": "POST /api/login · field: user",
  "http_method": "POST",
  "affected_url": "http://host.docker.internal:5050/api/login",
  "parameter_name": "user",
  "evidence_snippet": "HTTP 500 Internal Server Error matched SQLite syntax signature: 'sqlite3.OperationalError: unrecognized token' after submitting single-quote probe in form field 'user'.",
  "plain_explanation": "The backend inserts the 'user' form input directly into a SQL query string using string concatenation or f-strings. When an attacker submits a quote character, the database interprets the input as SQL syntax rather than literal data, enabling authentication bypass or unauthorized data extraction.",
  "remediation": {
    "summary": "Replace string-concatenated SQL with parameterized queries (bound parameters) or ORM query builders so user input is always treated strictly as data.",
    "root_cause": "Untrusted user input from POST /api/login (field: user) is interpolated directly into an executable SQL statement without parameterization.",
    "verification_steps": [
      "Replace raw string formatting in the /api/login database query with parameterized placeholders.",
      "Submit a single quote (') in the 'user' field manually and confirm the endpoint returns 401 Unauthorized rather than a 500 SQL error.",
      "Re-run a Standard scan and verify 'sqli_error_based' moves to the Fixed column in Compare Scans."
    ],
    "stacks": {
      "fastapi": {
        "label": "Python (FastAPI + SQLAlchemy 2.0)",
        "before": "query = text(f\"SELECT * FROM users WHERE username = '{payload.user}'\")\nrow = db.execute(query).fetchone()",
        "after": "stmt = select(User).where(User.username == payload.user)\nrow = db.execute(stmt).scalar_one_or_none()"
      },
      "flask": {
        "label": "Python (Flask + sqlite3)",
        "before": "cursor.execute(f\"SELECT id, password_hash FROM users WHERE username = '{request.form['user']}'\")",
        "after": "cursor.execute(\"SELECT id, password_hash FROM users WHERE username = ?\", (request.form[\"user\"],))"
      },
      "express": {
        "label": "Node.js (Express + pg / mysql2)",
        "before": "const sql = `SELECT id, password_hash FROM users WHERE username = '${req.body.user}'`;\nconst result = await db.query(sql);",
        "after": "const sql = 'SELECT id, password_hash FROM users WHERE username = $1';\nconst result = await db.query(sql, [req.body.user]);"
      },
      "php": {
        "label": "PHP (PDO Prepared Statements)",
        "before": "$stmt = $pdo->query(\"SELECT id, password_hash FROM users WHERE username = '\" . $_POST['user'] . \"'\");",
        "after": "$stmt = $pdo->prepare('SELECT id, password_hash FROM users WHERE username = :user');\n$stmt->execute(['user' => $_POST['user']]);"
      },
      "html": {
        "label": "HTML / Frontend Input Hardening (Defense-in-Depth)",
        "before": "<input type=\"text\" name=\"user\">",
        "after": "<!-- Always enforce parameterized queries on the backend; add client validation only as UX defense-in-depth -->\n<input type=\"text\" name=\"user\" maxlength=\"64\" pattern=\"[A-Za-z0-9_.@-]+\" required>"
      }
    }
  },
  "triage_note": null,
  "created_at": "2026-10-15T10:01:14Z",
  "updated_at": "2026-10-15T10:01:14Z"
}
```

---

## 4.5 Chapter Summary

This chapter defined the complete data, interface, and remediation specifications governing the scanner's backend and frontend subsystems. The 3NF relational schema (`PROJECTS`, `SCANS`, `ENDPOINTS`, `FINDINGS`) provides dialect-portable persistence across SQLite WAL and PostgreSQL 16 while supporting O(1) risk-score rollups and deterministic SHA-1 fingerprint diffing (`New`, `Fixed`, `Unchanged`). The REST and SSE API contract establishes uniform Pydantic v2 error envelopes, real-time progress telemetry, finding triage, and self-contained HTML/JSON reporting. Finally, the curated 17-check OWASP Top 10 (2021) catalogue and multi-stack `kb.json` remediation schema translate raw vulnerability detections into precise endpoint/parameter locations and copy-ready Before/After fixes across FastAPI, Flask, Express, PHP, and HTML. Chapter 5 builds upon these interfaces to detail mandatory scope guardrails, scanner self-security controls, risk management, and formal Architecture Decision Records (ADRs).

---

# Chapter 5: Security, Ethics, Risk Management, and Architecture Decision Records

## 5.1 Ethical and Legal Operating Principles

Dynamic Application Security Testing (DAST) systems issue automated HTTP probes designed to expose software weaknesses. Because unauthorized probing of third-party infrastructure violates institutional computing policies and cybercrime statutes—such as the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent national legislation—ethical safety is engineered as a **first-class architectural invariant** (`NFR-03`) rather than an advisory disclaimer.

The proposed scanner enforces three non-negotiable ethical and legal operating principles:

1. **Authorized Local Development and Educational Testing Only:** The system is strictly restricted to applications owned, developed, or explicitly provisioned by the operator within local development environments (`localhost`, `127.0.0.1`, RFC1918 private lab networks) and containerized academic testbenches (`dvwa`, `juice-shop`, `vulnbench`). Probing public internet hosts is blocked by default at the network client layer.
2. **Non-Destructive Proof-of-Detection:** Active vulnerability checks issue minimal, read-oriented diagnostic probes sufficient to confirm the *presence* of a security flaw without mutating target application state, altering database rows, or disrupting active development sessions.
3. **Zero Exploitation and Zero Weaponization:** The engine excludes automated data exfiltration, credential brute-forcing, privilege escalation, persistent payload implantation, reverse-shell generation, and Web Application Firewall (WAF) evasion techniques. Stored evidence is strictly truncated to minimal proof-of-detection artifacts (for example, matched HTTP headers, an inert reflected canary token, or a database parser error signature).

| Vulnerability Class | Prohibited Offensive Behavior (Explicitly Out of Scope) | Permitted Non-Destructive Proof-of-Detection Technique |
|---|---|---|
| **SQL Injection (`A03`)** | `UNION SELECT` table dumping, `DROP`/`DELETE`/`UPDATE` queries, stacked statements, prolonged `SLEEP(30)` denial-of-service loops | Single syntax-breaking probe (`'` or `"`) analyzed for DBMS error signatures (`sqli_error_based`), combined with paired benign boolean tautology/contradiction differential analysis (`1=1` versus `1=2` in `sqli_boolean_diff`) |
| **Reflected XSS (`A03`)** | Executing weaponized JavaScript (`document.cookie` exfiltration, DOM defacement, persistent stored XSS payloads) | Submitting an inert alphanumeric canary containing benign HTML metacharacters (for example, `devscan_xss_<id>"><`) and confirming unencoded reflection inside an HTML response context (`xss_reflected`) |
| **Broken Access Control (`A01`)** | Automated account takeover, bulk enumeration of user records, unauthorized state-mutating `PUT`/`DELETE` calls | Single-origin `Origin: https://evil.example` CORS header verification (`cors_misconfig`), non-followed `3xx` redirect inspection (`open_redirect`), bounded admin path probing with Soft-404 suppression (`forced_browsing_admin`), and read-only adjacent-ID comparison (`idor_heuristic`, Deep profile only) |
| **Misconfiguration and Exposure (`A05`)** | Downloading database backups or invoking exposed debug consoles to execute arbitrary server-side code | Bounded `GET`/`HEAD` requests against a small curated path list (`.env`, `.git/HEAD`, `robots.txt`, backup markers) paired with Soft-404 calibration and truncated metadata checks (`sensitive_files`, `directory_listing`) |
| **Authentication and Sessions (`A02`, `A07`)** | Password spraying, credential stuffing, active session hijacking | Passive inspection of `Set-Cookie` directives (`Secure`, `HttpOnly`, `SameSite`), transport scheme verification (`http://`), and HTML `<form method="POST">` anti-CSRF token presence (`insecure_cookies`, `insecure_transport`, `csrf_missing_token`) |

> [!IMPORTANT]
> Every active plugin registered under `backend/scanner/checks/` must satisfy a formal safety review prior to inclusion: probes must remain idempotent, read-oriented, rate-limited, and incapable of modifying database records or triggering administrative state transitions on a compliant web application.

---

## 5.2 Mandatory Scope Guardrail and Anti-Abuse Controls

To satisfy `FR-01`, `FR-02`, and `NFR-03`, all scope validation and anti-abuse rules are centralized within `ScopeGuardrail` and `GuardedHttpClient` (`backend/scanner/core/`). Crawlers and check plugins are prohibited from invoking `requests.get()` or `requests.post()` directly; every outbound HTTP operation must traverse the guarded client. Enforcement occurs at two independent boundaries: **API ingress** (upon project registration and scan launch) and **HTTP egress** (prior to dispatching every network request and every redirect hop).

### 5.2.1 Defense-in-Depth Control Gates

1. **Explicit UI Ownership Confirmation (`Gate 1`):** Project registration (`POST /api/projects`) mandates an explicit ownership attestation checkbox in the dashboard (`ownership_confirmed: true`). The backend rejects any project creation or scan launch request lacking this confirmation and persists both the boolean attestation and its UTC timestamp in the `projects` table.
2. **Strict URL Syntax and Scheme Validation (`Gate 2`):** Target URLs are parsed via `urllib.parse.urlparse`. Only `http` and `https` schemes are permitted; unsafe schemes (`file://`, `ftp://`, `gopher://`, `data://`, `javascript:`) and embedded credential authority strings (`http://user:pass@host`) are rejected immediately with `400 InvalidTargetURLError`.
3. **Destructive and Logout Route Denylist (`Gate 3`):** Prior to crawling or active probing, each normalized URL path is evaluated against a case-insensitive denylist of session-terminating and state-destroying segments: `/logout`, `/signout`, `/sign-out`, `/logoff`, `/delete`, `/remove`, `/destroy`, `/drop`, `/reset`, `/shutdown`, and `/purge`. Matching routes are bypassed safely and logged as `GuardrailSkip` telemetry events to preserve authenticated scan sessions and protect local development data.
4. **Hardcoded Local and Private Allow-List (`Gate 4`):** Target hostnames are validated against a hardcoded local allow-list configurable only within local and private bounds via `SCAN_ALLOWLIST` (default: `localhost`, `127.0.0.1`, `::1`, `host.docker.internal`, `dvwa`, `juice-shop`, `vulnbench`, plus RFC1918 CIDR blocks `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`). Public domains and externally routable IP addresses are rejected unconditionally with `403 OutOfScopeHostError`.
5. **Pre-Request DNS Resolution and Anti-Rebinding Verification (`Gate 5`):** Hostname string checks alone remain susceptible to DNS rebinding and Server-Side Request Forgery (SSRF) targeting cloud instance metadata services. Immediately before initiating a socket connection, `ScopeGuardrail` resolves the host via `socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)` and evaluates **every** returned IP address using Python's `ipaddress.ip_address()`:
   - IPv4-mapped IPv6 addresses (such as `::ffff:93.184.216.34`) are unwrapped via `.ipv4_mapped` before policy checks.
   - Every resolved address must satisfy `(ip.is_loopback or ip.is_private)` **and** must not be link-local (`ip.is_link_local`, blocking `169.254.169.254` and `fe80::/10`), multicast, unspecified (`0.0.0.0`), or globally routable (`ip.is_global`).
   - Any non-compliant address aborts the request with `403 DNSRebindingBlockedError`.
6. **Per-Scan Request Budget and Cooperative Cancellation (`Gate 6`):** Each scan maintains an atomic request counter capped by `SCAN_MAX_REQUESTS` (default `2000`) and polls a per-scan `threading.Event` cancellation flag (`FR-07`). Reaching the request ceiling or receiving `POST /api/scans/{id}/cancel` halts subsequent outbound traffic cleanly without leaving orphaned background threads.
7. **Token-Bucket Rate Limiting and Strict Timeouts (`Gate 7`):** A per-scan token-bucket rate limiter enforces `SCAN_RATE_LIMIT_RPS` (default `10` requests per second), preventing accidental overload of single-threaded student development servers (such as Flask's Werkzeug server or PHP's built-in server). Outbound requests enforce a strict `10`-second socket timeout and a `2 MB` response body cap.
8. **Manual Same-Origin Redirect Validation (`Gate 8`):** `requests.Session` executes with `allow_redirects=False`. Upon receiving an HTTP `301`, `302`, `303`, `307`, or `308` response, `GuardedHttpClient` extracts the `Location` header, resolves relative paths via `urllib.parse.urljoin`, and verifies both (a) strict same-origin matching `(scheme, host, port)` with the scan target and (b) a maximum redirect depth of `5` hops. Cross-origin redirects are never followed; instead, the raw `3xx` response is returned to the caller so the `open_redirect` plugin can capture proof-of-detection safely without contacting external hosts. Same-origin hops loop back through Gates 2 through 5 to verify that the redirected path is neither destructive nor DNS-rebound.

### 5.2.2 Scope Guardrail Decision Flow

Figure 16 illustrates the end-to-end decision pipeline executed inside `GuardedHttpClient` and `ScopeGuardrail` for every outbound HTTP request candidate.

![Figure 16: Pre-Request Scope Guardrail and Safety Decision Flow](../../diagrams/png/16_scope_guardrail_flow.png)

*Figure 16: Pre-Request Scope Guardrail and Safety Decision Flow (Mermaid source: [16_scope_guardrail_flow.mmd](../../diagrams/mmd/16_scope_guardrail_flow.mmd)).*

### 5.2.3 Summary of Guardrail Enforcement Gates

| Gate | Mechanism and Implementation Anchor | Default Configuration | Failure / Enforcement Outcome | Primary Threat Mitigated |
|---|---|---|---|---|
| **Gate 1** | `Project.ownership_confirmed` check at API and worker entry | Required boolean `true` | `403 OwnershipNotConfirmedError` | Unintentional scanning without operator consent |
| **Gate 2** | `urllib.parse` scheme and credential-stripping check | `http`, `https` only | `400 InvalidTargetURLError` | Protocol smuggling (`file://`, `gopher://`) |
| **Gate 3** | Case-insensitive path denylist in `ScopeGuardrail` | `/logout`, `/signout`, `/delete`, `/remove`, `/reset`, etc. | Safe skip and telemetry event | Session invalidation and local database loss |
| **Gate 4** | Hardcoded hostname and RFC1918 CIDR verification | `SCAN_ALLOWLIST` + RFC1918 | `403 OutOfScopeHostError` | Unauthorized scanning of public hosts |
| **Gate 5** | `socket.getaddrinfo` + `ipaddress` loopback/private check | Rejects public and `169.254.0.0/16` | `403 DNSRebindingBlockedError` | DNS rebinding, SSRF, cloud metadata exposure |
| **Gate 6** | Atomic request counter and `threading.Event` cancel flag | `SCAN_MAX_REQUESTS=2000` | Graceful scan halt | Crawler loops and runaway execution |
| **Gate 7** | Token-bucket throttle and fixed socket timeout | `SCAN_RATE_LIMIT_RPS=10`, `10s` timeout | Controlled pacing or timeout | Accidental denial-of-service against local dev servers |
| **Gate 8** | Manual redirect inspection (`allow_redirects=False`) | Same-origin only, max `5` hops | Return raw `3xx`, do not follow | Redirect-based scope escape to external domains |

---

## 5.3 Scanner Self-Security Controls

To satisfy `NFR-04`, the scanner application itself adheres to secure-by-design engineering practices. Because a DAST dashboard ingests untrusted HTTP headers, HTML fragments, and error payloads emitted by scanned target applications, rigorous output encoding and container hardening are mandatory to prevent the scanner from becoming an attack vector.

| Security Domain | Self-Security Control Implemented | Architectural Layer | Verification Method |
|---|---|---|---|
| **Strict Input Validation** | All REST request bodies, query parameters, and path identifiers are validated through Pydantic v2 schemas enforcing strict types, enumerated `scan_profile` and `triage_status` values, bounded string lengths, and custom URL validators. | FastAPI Routers (`backend/app/routers/`) | Automated `pytest` suite confirming HTTP `422` on malformed payloads |
| **Scanner HTTP Security Headers** | Custom FastAPI middleware injects `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy: geolocation=(), microphone=(), camera=()`, and a restrictive `Content-Security-Policy` on all scanner responses. | FastAPI Middleware (`backend/app/main.py`) | Automated header assertions in `backend/tests/test_health.py` and self-scan verification |
| **Non-Root Container Hardening** | The multi-stage `python:3.12-slim` `Dockerfile` provisions an unprivileged `scanner` system account (`USER scanner`), restricts writable paths to `/app/data`, and omits build compilers from the runtime stage. | Container Image (`Dockerfile`) | Runtime `id` verification confirming non-zero UID |
| **Parameterized Database Queries** | All persistence operations use SQLAlchemy 2.0 ORM statements (`select()`, `where()`) with bound parameters, eliminating raw SQL string interpolation across both SQLite and PostgreSQL dialects. | Persistence Layer (`backend/app/database.py`, ORM models) | Static code review and API injection probe tests |
| **XSS-Safe Dashboard and Reports** | Exported HTML reports configure Jinja2 with `autoescape=select_autoescape(["html", "xml"])`. The Vanilla JS dashboard renders untrusted URLs, headers, and evidence snippets via `textContent` (never unescaped `innerHTML`), and evidence strings are truncated to 512 bytes. | Frontend ES Modules (`frontend/`) and Report Generator | Unit tests injecting `<script>alert(1)</script>` into mock target responses and verifying escaped output |
| **Secrets and Credential Hygiene** | Zero hardcoded credentials exist in source control; `.env` is excluded via `.gitignore` while `.env.example` contains non-sensitive defaults. Optional scan credentials (`FR-14`) remain in memory within `requests.Session` and are redacted (`[REDACTED]`) in logs and JSON/HTML exports. | Configuration (`pydantic-settings`) and HTTP Client | Repository secret check and export redaction unit test |
| **Loopback-Only Testbench Binding** | In `docker-compose.testbench.yml`, intentionally vulnerable test targets (`dvwa`, `juice-shop`, `vulnbench`) bind exclusively to `127.0.0.1:<port>`, ensuring vulnerable services are unreachable from external LAN interfaces. | Testbench Compose (`docker-compose.testbench.yml`) | Compose manifest audit and `docker ps` binding verification |

---

## 5.4 NIST Secure Software Development Framework (SSDF SP 800-218) Alignment

In alignment with the Shift-Left security model introduced in Chapter 1, the design, implementation, and verification lifecycle of the proposed scanner maps directly onto the four practice groups of the **NIST Secure Software Development Framework (SSDF, SP 800-218)** [4]. Table 5.4 documents how each SDLC security phase is operationalized within the project architecture.

| NIST SSDF Phase / Practice Group | Representative SSDF Tasks | Project Engineering Practices and Controls | Architectural Artifacts and Requirements |
|---|---|---|---|
| **PO — Prepare the Organization** | `PO.1` Define security requirements; `PO.3` Implement supporting toolchains; `PO.5` Maintain secure environments | Established explicit ethical/legal scope boundaries, formal `FR-01`–`FR-15` and `NFR-01`–`NFR-09` baselines, deterministic containerized development/testbench environments, and loopback-only Docker bindings. | Chapters 1–2 (`FR`/`NFR`), `docker-compose.yml`, `docker-compose.testbench.yml`, `NFR-03`, `NFR-05` |
| **PW.1 — Design Software to Meet Security Requirements and Mitigate Security Risks** | `PW.1.1` Perform threat modeling and architectural risk analysis; `PW.1.2` Document design decisions | Authored C4 Level 1–3 architecture views, DFD Level 1 with explicit trust boundaries, 8-gate `ScopeGuardrail` flow, formal Risk Register (`RSK-01`–`RSK-08`), and five Architectural Decision Records (`ADR-01`–`ADR-05`). | Chapter 3 (Figures 4–8), Chapter 5 (Figure 16, Risk Register, `ADR-01`–`ADR-05`) |
| **PS / PW.5 — Protect Software and Produce Well-Secured Code** | `PS.1` Protect all forms of code from unauthorized access; `PW.5` Follow secure coding practices | Enforced Pydantic v2 strict input validation, SQLAlchemy 2.0 parameterized ORM queries, Jinja2 autoescaping and DOM `textContent` output encoding, FastAPI security-header middleware, non-root `scanner` Docker user, `.gitignore` secrets hygiene, and decoupled pure-Python `BaseCheck` plugin boundaries. | `backend/app/main.py`, `backend/app/database.py`, `backend/scanner/core/`, `Dockerfile`, `NFR-04`, `NFR-06` |
| **PW.8 / RV — Test Executable Code and Respond to Vulnerabilities** | `PW.8` Test executable code to identify vulnerabilities and verify compliance; `RV.1`–`RV.3` Identify, remediate, and prevent recurrence | Implemented automated `pytest` unit/integration suites with HTTP mocks (`responses`), a 15-scenario Verification Matrix (`TC-01`–`TC-15`), automated benchmarking (`scripts/evaluate.py` against `VulnBench`, `DVWA`, and `OWASP Juice Shop`), and multi-stack copy-ready remediation fixes (`kb.json`) enabling developers to patch and re-verify findings via SHA-1 fingerprint diffs. | Chapter 6 (`TC-01`–`TC-15`, `scripts/evaluate.py`), `backend/tests/`, `backend/scanner/remediation/kb.json`, `NFR-08`, `NFR-09` |

---

## 5.5 Risk Register

Table 5.5 documents the primary technical, operational, security, and academic risks identified during architectural design, alongside their likelihood, impact, concrete architectural mitigations, and residual risk levels.

| Risk ID | Risk Description | Category | Likelihood | Impact | Concrete Architectural Mitigation | Residual Risk |
|---|---|---|---|---|---|---|
| **RSK-01** | **High False Positive Rate Eroding Developer Trust:** Naive pattern matching (such as interpreting custom `200 OK` error templates as exposed `.env` files) produces alert fatigue. | Accuracy / DX | Medium | High | Apply pre-scan **Soft-404 baseline fingerprinting** against two random nonexistent UUID paths, require multi-signal confirmation for active checks, mark heuristic plugins (`idor_heuristic`) as `tentative`, and support one-click `false_positive` triage (`FR-13`) excluding dismissed items from the risk score. | Low |
| **RSK-02** | **Client-Side SPA Crawling Limitations (OWASP Juice Shop):** Lightweight `requests` + `BeautifulSoup4` crawling without a headless browser cannot execute runtime Angular/React routing logic. | Technical / Coverage | High | Medium | Augment HTML `<a href>` and `<form>` extraction with static JavaScript bundle inspection for quoted `/api/...` and `/rest/...` route literals, permit user-supplied seed paths, and disclose SPA coverage limits transparently in the UI and Section 6.7. | Medium (Accepted and Documented) |
| **RSK-03** | **Misuse Against Unauthorized External Targets:** An operator attempts to scan a public website or institutional server outside local development. | Ethical / Legal | Medium | High | Enforce the 8-gate `ScopeGuardrail` (`Section 5.2`): UI ownership attestation, hardcoded local/RFC1918 allow-list, pre-request `socket.getaddrinfo` + `ipaddress` anti-rebinding check, and manual same-origin redirect blocking. | Low |
| **RSK-04** | **Target Overload or Crash of Local Dev Servers:** Aggressive active probing overwhelms single-threaded student frameworks (Flask dev server, SQLite write locks, PHP built-in server). | Operational / Reliability | Medium | Medium | Enforce `SCAN_RATE_LIMIT_RPS=10` token-bucket throttling, `SCAN_MAX_REQUESTS=2000` ceiling, bounded `ThreadPoolExecutor` concurrency, `10s` per-request timeouts, and cooperative cancellation (`FR-07`). | Low |
| **RSK-05** | **Cross-Platform Docker Host Networking Friction (Windows vs. Linux):** Inside Linux Docker Engine, `host.docker.internal` does not resolve automatically unless explicitly mapped, breaking scans of host-resident apps. | Portability / UX | Medium | Medium | Declare `extra_hosts: ["host.docker.internal:host-gateway"]` in `docker-compose.yml`, validate on both Windows Docker Desktop and Linux Docker Engine, and provide native Python `venv` execution (`NFR-05`). | Low |
| **RSK-06** | **Stored XSS in Scanner Dashboard or Exported HTML Report:** A scanned target reflects malicious JavaScript inside HTTP response evidence rendered by the scanner UI or report. | Self-Security | Low | High | Enforce Jinja2 `autoescape=True`, render untrusted fields via DOM `textContent` in Vanilla JS, truncate evidence strings to 512 bytes, and enforce a strict scanner `Content-Security-Policy` (`Section 5.3`). | Low |
| **RSK-07** | **Scope Creep Jeopardizing Graduation Schedule:** Attempting to replicate enterprise DAST suites (headless browsers, 100+ plugins, multi-tenant SaaS) compromises core quality and evaluation depth. | Schedule / Scope | Medium | High | Lock scope to the 17 curated OWASP Top 10 checks, explicit in-scope/out-of-scope boundaries (`Chapter 1`), and the `NFR-08` empirical accuracy gate. | Low |
| **RSK-08** | **Authenticated Session Expiry During Deep Scans:** Triggering a logout link or exceeding a short session TTL invalidates cookies mid-scan, causing silent False Negatives on authenticated routes. | Accuracy / Reliability | Medium | Medium | Enforce the logout/destructive route denylist (`Gate 3`), log unexpected `401` or `302 -> /login` drops in scan telemetry, and isolate per-check exceptions (`NFR-07`) so completed findings remain persisted. | Low |

---

## 5.6 Formal Architecture Decision Records (ADRs)

Five foundational Architecture Decision Records formalize the major structural trade-offs made in designing the scanner.

---

### ADR-01: FastAPI over Flask for Backend Engine and Live SSE Streaming

- **Status:** Accepted
- **Date:** October 2026
- **Related Requirements:** `FR-01`–`FR-15`, `NFR-01`, `NFR-02`, `NFR-04`, `NFR-09`

#### Context
The backend must serve a strongly validated REST API for projects, scans, endpoints, findings, triage, and reports while streaming real-time scan lifecycle progress (`crawling`, `scanning`, `finding_discovered`, `completed`) to the browser dashboard (`FR-06`). It must also maintain minimal operational overhead suitable for single-container local deployment.

#### Decision
Adopt **FastAPI** served by **Uvicorn** with **Pydantic v2** request/response schemas and **Server-Sent Events (`StreamingResponse` with `text/event-stream`)**, paired with an in-process bounded `ThreadPoolExecutor` for executing synchronous `requests`-based crawl and probe workloads without blocking the ASGI event loop.

#### Consequences
- **Positive:**
  - Native ASGI `async`/`await` enables lightweight SSE progress streaming (`GET /api/scans/{id}/stream`) without external message brokers or distributed worker infrastructure.
  - Pydantic v2 enforces strict payload validation (`NFR-04`) and automatically generates interactive OpenAPI (`/docs`) documentation for developers and examiners.
  - Built-in `fastapi.testclient.TestClient` streamlines automated API integration testing in `pytest`.
- **Trade-offs:**
  - Combining synchronous `requests.Session` worker threads with an async FastAPI event loop requires disciplined thread-safety, including dedicated SQLAlchemy sessions per worker thread and thread-safe event signaling.

#### Alternatives Rejected
- **Flask with WSGI (Gunicorn/Waitress):** Lacks built-in request schema validation, native async SSE streaming, and automatic OpenAPI generation; sustaining concurrent SSE connections under synchronous WSGI ties up worker threads and necessitates supplementary libraries (`marshmallow`, `gevent`).
- **Django with Django REST Framework:** Introduces substantial boilerplate, heavyweight ORM/admin overhead, and slower startup for a compact local developer utility.

---

### ADR-02: SQLAlchemy 2.0 with SQLite Default and Drop-in PostgreSQL Docker Profile

- **Status:** Accepted
- **Date:** October 2026
- **Related Requirements:** `FR-11`, `FR-13`, `NFR-01`, `NFR-05`

#### Context
Achieving the `< 3 minute` zero-configuration setup requirement (`NFR-01`) demands that student developers launch the scanner with a single command (`docker compose up` or `uvicorn` inside a local Python `venv`) without provisioning an external database server. Concurrently, larger capstone teams or lab deployments may wish to attach a client-server PostgreSQL instance without modifying source code.

#### Decision
Standardize persistence on **SQLAlchemy 2.0 ORM**, defaulting to embedded **SQLite** (`sqlite:///./data/scanner.db`) configured with Write-Ahead Logging (`PRAGMA journal_mode=WAL`) and foreign-key enforcement (`PRAGMA foreign_keys=ON`). Supply an optional **PostgreSQL 16** service under Docker Compose `profiles: ["postgres"]` activated cleanly via `DATABASE_URL` and `psycopg[binary]`.

#### Consequences
- **Positive:**
  - Enables single-container zero-config launch (`docker compose up`) backed by a persistent named volume (`scanner_data:/app/data`), as well as frictionless native Python `venv` execution.
  - SQLite WAL mode permits concurrent dashboard reads while the scan worker commits discovered endpoints and findings without lock contention.
  - Preserves a strict Third Normal Form (3NF) relational schema (`projects`, `scans`, `endpoints`, `findings`) supporting cross-scan SHA-1 fingerprint diffs (`FR-11`) and transparent migration to PostgreSQL.
- **Trade-offs:**
  - SQLite serializes concurrent write transactions; worker persistence must batch writes cleanly at crawl-batch and check-completion boundaries.

#### Alternatives Rejected
- **Mandatory PostgreSQL Default:** Requires multi-container orchestration on every startup, increases memory footprint on student laptops, and prevents zero-dependency native Python `venv` runs.
- **NoSQL Document Stores or Flat JSON Files:** Adds external service complexity (document databases) or weak concurrency and relational query semantics (flat files) for cross-scan comparison and triage aggregation.

---

### ADR-03: Pure Decoupled Scanner Package and 1-File `BaseCheck` Plugin Auto-Registry

- **Status:** Accepted
- **Date:** October 2026
- **Related Requirements:** `FR-05`, `FR-15`, `NFR-06`, `NFR-07`, `NFR-09`

#### Context
Maintainability and extensibility (`NFR-06`) require that contributing an additional OWASP check involves creating a single self-contained Python module without modifying FastAPI routers, database models, orchestrator loops, or frontend views. Additionally, the scanning engine must be unit-testable independently of HTTP server and database state.

#### Decision
Isolate `backend/scanner/` as a **pure Python package** containing zero imports from `backend/app/`. Define an abstract `BaseCheck` interface (`check_id`, `owasp_category`, `mode`, `severity`, `run(ctx: CheckContext) -> list[RawFinding]`), backed by a declarative plugin auto-registry (`@register_check`) and a centralized multi-stack remediation knowledge base (`backend/scanner/remediation/kb.json`). Wrap every plugin invocation inside an isolated `try/except` boundary in `ScanOrchestrator` (`NFR-07`).

#### Consequences
- **Positive:**
  - Adding an 18th check requires a single Python file under `backend/scanner/checks/` and a corresponding entry in `kb.json`; the check is automatically exposed via `GET /api/checks` (`FR-15`) and scheduled according to scan profile.
  - Per-check exception isolation ensures an unexpected parsing anomaly in one plugin never aborts an entire scan.
  - Enables rapid, deterministic `pytest` runs with `responses` HTTP mocks and direct invocation from the automated benchmarking harness (`scripts/evaluate.py`).
- **Trade-offs:**
  - Introduces a lightweight mapping layer in the FastAPI service module to translate pure dataclasses (`EnrichedFinding`) into SQLAlchemy ORM entities.

#### Alternatives Rejected
- **Monolithic Procedural Scanner Module:** Tightly couples network probing, ORM transactions, and API routes, impeding parallel team development and isolated testing.
- **Subprocess Wrapping of External Scanners:** Undermines the pedagogical and architectural objective of building a transparent, lightweight Python engine and introduces brittle stdout parsing.

---

### ADR-04: HTML5, Tailwind CSS, and Modular Vanilla JS over SPA Build Toolchain

- **Status:** Accepted
- **Date:** October 2026
- **Related Requirements:** `FR-06`, `FR-08`–`FR-13`, `NFR-01`, `NFR-05`

#### Context
The project proposal explicitly aligns the scanner with **zero-config local Docker startup** and a streamlined developer-experience architecture (Proposal Slide 6: HTML5, Tailwind CSS, and Vanilla JS served directly alongside FastAPI). The dashboard comprises six focused operational views (Projects Overview, Scan Launcher, Live SSE Progress, Findings and Endpoints Explorer, Actionable Code Fix Modal with multi-stack tabs, and Scan Comparison/Export) alongside Chart.js visualizations.

#### Decision
Implement the web dashboard using semantic **HTML5**, **Tailwind CSS**, **Modular Vanilla JavaScript (native ES Modules)**, and **Chart.js**, served directly as static assets by FastAPI at `/`. Exclude Node.js, npm, Vite, and SPA bundler stages from the build and runtime architecture.

#### Consequences
- **Positive:**
  - Eliminates large `node_modules` trees, multi-runtime Docker builds, and cross-origin dev-server configuration—directly supporting the `< 3 minute` startup SLA (`NFR-01`) and compact single-container footprint.
  - Browser-native `EventSource` consumes FastAPI SSE streams directly, while ES Modules (`frontend/js/*.js`) maintain clean separation between API clients, state handling, safe DOM rendering, and chart widgets.
  - Zero frontend compilation latency simplifies iterative capstone development and live academic demonstrations.
- **Trade-offs:**
  - Manual DOM updates require disciplined helper abstractions using `textContent` to guarantee consistent XSS-safe rendering across all views.

#### Alternatives Rejected
- **SPA Build Toolchains (React / Vue / Next.js):** Introduce Node.js build stages, heavier container images, and dependency churn disproportionate to a six-view local utility dashboard.
- **Static Server-Rendered Templates Without Client JS:** Cannot deliver smooth real-time SSE progress updates, instant client-side finding filtering, or interactive multi-stack Before/After code-fix tabs without full page reloads.

---

### ADR-05: Hardcoded Scope Guardrail, Soft-404 Fingerprinting, and Non-Destructive Proof-of-Detection Policy

- **Status:** Accepted
- **Date:** October 2026
- **Related Requirements:** `FR-02`, `FR-05`, `NFR-03`, `NFR-08`

#### Context
Lightweight DAST tools typically suffer from two structural failure modes: (1) missing technical guardrails that expose operators to legal/ethical risk if an external URL is scanned accidentally; and (2) high false-positive rates caused by modern frameworks returning custom `200 OK` HTML error templates for nonexistent paths ("Soft-404s"), undermining developer trust and failing `NFR-08` (`Precision >= 85%`, `0` false positives on clean controls).

#### Decision
Enforce three coupled engine invariants within `backend/scanner/core/`:
1. **Hardcoded 8-Gate Scope Guardrail** (`Section 5.2`) mandating ownership attestation, local/RFC1918 allow-listing, pre-request DNS-to-IP anti-rebinding validation, manual same-origin redirect enforcement, destructive-route exclusion, and `10 req/s` / `2,000 req` ceilings.
2. **Pre-Scan Soft-404 Baseline Calibration:** Prior to running discovery plugins (`sensitive_files`, `directory_listing`, `forced_browsing_admin`), the engine requests two guaranteed-nonexistent random UUID paths (`/__devscan_404_<uuid>`) and records their HTTP status code, content type, length band, and normalized body digest. Discovery responses matching this baseline are suppressed automatically.
3. **Non-Destructive Proof-of-Detection Only:** All 17 checks rely exclusively on passive inspection or minimal read-only probes paired with explicit confidence tiers (`high`, `medium`, `tentative`).

#### Consequences
- **Positive:**
  - Provides auditable, unit-testable ethical safety guarantees appropriate for academic cybersecurity review.
  - Eliminates false-positive floods on SPA catch-all routers (such as OWASP Juice Shop returning `index.html` with HTTP `200`) and custom framework error handlers.
  - Preserves local application state so developers can run scans continuously during active coding.
- **Trade-offs:**
  - Scanning remote staging environments on public domains is intentionally unsupported unless the scanner runs inside the same private RFC1918 network.
  - Excluding persistent state-mutating payloads places stored/second-order vulnerabilities outside detection scope (`Section 6.7`).

#### Alternatives Rejected
- **Advisory Disclaimer Banner Without Technical Enforcement:** Fails to prevent accidental typos, SSRF, DNS rebinding, or cross-origin redirect scope escapes.
- **Naive `HTTP 200` Status-Code Discovery Matching:** Triggers widespread false positives on SPAs and custom error-handling routes, violating `NFR-08`.

---

## 5.7 Chapter Summary

Chapter 5 established the ethical, security, risk-management, and architectural-decision foundations of the proposed lightweight OWASP Top 10 vulnerability scanner. Section 5.1 codified the non-destructive proof-of-detection and zero-exploitation principles governing all 17 curated checks. Section 5.2 detailed the eight-gate `ScopeGuardrail` and `GuardedHttpClient` decision pipeline (Figure 16), defending against unauthorized external probing, DNS rebinding, cloud-metadata SSRF, cross-origin redirect escapes, destructive route execution, and local server overload. Section 5.3 documented the scanner's own self-security controls (`NFR-04`), while Section 5.4 aligned engineering practices with the four lifecycle phases of NIST SSDF (SP 800-218). Finally, Section 5.5 cataloged eight prioritized project risks (`RSK-01`–`RSK-08`) with architectural mitigations, and Section 5.6 recorded five formal Architecture Decision Records (`ADR-01`–`ADR-05`) justifying the confirmed FastAPI, SQLAlchemy 2.0, decoupled plugin, Vanilla JS, and guardrail/Soft-404 design choices. Chapter 6 builds on these guarantees to define the quantitative validation strategy, verification matrix, and developer-experience benchmarking protocol.

---

# Chapter 6: Validation Strategy, Benchmarking, and Developer-Experience Evaluation

## 6.1 Validation Objectives and Testbench Architecture

To confirm empirically that the proposed scanner satisfies its detection accuracy (`NFR-08`), performance (`NFR-02`), ethical safety (`NFR-03`), reliability (`NFR-07`), and developer-experience (`NFR-01`) targets, Phase 6 executes a reproducible evaluation suite against a **three-tier containerized testbench** defined in `docker-compose.testbench.yml`.

All testbench services operate on an isolated Docker bridge network (`testbench_net`) and bind host-exposed ports strictly to loopback (`127.0.0.1`), guaranteeing that intentionally vulnerable targets remain inaccessible from external network interfaces.

| Tier | Target Application | Container Image / Stack | Local Binding | Authentication Mode Tested | Primary Validation Objective |
|---|---|---|---|---|---|
| **Tier 1 (Deterministic Ground Truth)** | **`VulnBench`** (Custom Local Micro-Application) | `./testbench/vulnbench` (Python Flask + SQLite) | `127.0.0.1:5050` | Anonymous + Session Cookie (`FR-14`) | Deterministic TP/FP/FN measurement across all **17 curated OWASP checks** (1 seeded vulnerability per check) plus **hardened clean control routes** verifying `0` false positives (`NFR-08`). |
| **Tier 2 (Classic Server-Rendered Target)** | **DVWA** (Damn Vulnerable Web Application) [10] | `vulnerables/web-dvwa:latest` (PHP + Apache + MySQL) | `127.0.0.1:8080` | DVWA Form Login + `security=low` / `medium` cookie | Independent external validation on a standard academic server-rendered application; verifies authenticated BFS HTML form crawling, SQLi/XSS/CSRF/header detection, and logout-route denylist stability. |
| **Tier 3 (Modern SPA Target)** | **OWASP Juice Shop** [11] | `bkimminich/juice-shop:latest` (Node.js + Express + Angular) | `127.0.0.1:3000` | Anonymous + Optional Bearer JWT | Validates Soft-404 baseline calibration against SPA catch-all `index.html` routing, tests CORS/header/outdated-JS checks, and quantifies non-headless SPA crawler coverage boundaries. |

### 6.1.1 Design of `VulnBench` Clean Control Routes

Measuring recall without negative test controls can conceal noisy heuristics that flag secure endpoints indiscriminately. Consequently, `VulnBench` pairs its 17 seeded vulnerable routes with a hardened `/clean/*` control suite implementing OWASP secure coding guidance [5]:

- `/clean/search` — Parameterized SQLite query (`?` placeholders) and Jinja2 auto-escaped rendering (must trigger `0` SQLi and `0` XSS findings).
- `/clean/profile` — Emits strict security headers (`Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`), `HttpOnly`/`SameSite=Lax` cookies, and validated anti-CSRF tokens on state-changing `POST` forms.
- `/clean/redirect` — Enforces an internal redirect allow-list rejecting arbitrary external destinations (must trigger `0` `open_redirect` findings).
- `/clean/soft404/<path>` — Returns a styled HTTP `200 OK` "Page Not Found" HTML page for unknown paths, verifying that Soft-404 baseline fingerprinting suppresses false hits in `sensitive_files`, `directory_listing`, and `forced_browsing_admin`.

---

## 6.2 Quantitative Evaluation Metrics and Acceptance Gates

All quantitative experiments evaluate six standardized metrics. Let `TP` denote True Positives (seeded vulnerabilities correctly identified), `FP` denote False Positives (reported findings not corresponding to any ground-truth vulnerability), and `FN` denote False Negatives (seeded vulnerabilities missed by the engine).

### 6.2.1 Mathematical Metric Definitions

```text
Precision            = TP / (TP + FP)

Recall (TPR)         = TP / (TP + FN)

F1-Score             = 2 * (Precision * Recall) / (Precision + Recall)

Clean-Control FPR    = FP_clean / N_clean_checks

Route Coverage (%)   = (|Routes_Discovered ∩ Routes_Expected| / |Routes_Expected|) * 100

Scan Duration (s)    = t_completed - t_started
```

### 6.2.2 Formal Quantitative Acceptance Gates (`NFR-02`, `NFR-07`, `NFR-08`)

| Metric | Target Environment | Mandatory Pass Gate | Stretch Goal | Governing Requirement |
|---|---|---|---|---|
| **Overall Recall** | `VulnBench` (`Deep` profile) | `>= 80.0%` (`>= 14 / 17` checks) | `>= 90.0%` (`>= 16 / 17` checks) | `NFR-08` |
| **Overall Precision** | `VulnBench` (`Deep` profile) | `>= 85.0%` | `>= 92.0%` | `NFR-08` |
| **Overall F1-Score** | `VulnBench` (`Deep` profile) | `>= 82.0%` | `>= 91.0%` | `NFR-08` |
| **Clean-Control False Positives** | `VulnBench` `/clean/*` routes | `0` FPs (`0.0%` FPR) | `0` FPs (`0.0%` FPR) | `NFR-08` |
| **Quick Scan Duration** | `VulnBench` (`Quick` profile) | `<= 15 s` | `<= 10 s` | `NFR-02` |
| **Standard Scan Duration** | `VulnBench` (`Standard` profile) | `<= 45 s` | `<= 30 s` | `NFR-02` |
| **Deep Scan Duration** | `VulnBench` (`Deep` profile) | `<= 90 s` | `<= 65 s` | `NFR-02` |
| **Per-Check Unhandled Crash Rate** | All 3 testbench targets | `0%` (isolated via `try/except`) | `0%` | `NFR-07` |

---

## 6.3 Automated Evaluation Pipeline (`scripts/evaluate.py`)

Empirical benchmarking is automated via `scripts/evaluate.py` and driven by a version-controlled ground-truth specification at `testbench/ground_truth.json`, ensuring repeatable regression checks during development and transparent auditing during graduation defense.

### 6.3.1 Canonical Finding Matching Tuple

Both expected ground-truth items and scanner output findings are normalized into a canonical 4-tuple prior to set comparison:

```text
MatchKey = (check_id, method, normalized_path, parameter)
```

- `check_id`: Exact plugin identifier from the 17-check catalog (for example, `sqli_error_based`, `xss_reflected`, `missing_security_headers`).
- `method`: Uppercase HTTP verb (`GET`, `POST`, etc.).
- `normalized_path`: URL path component with query strings stripped and trailing slashes normalized (preserving `/` for the application root).
- `parameter`: Specific query parameter, form field, cookie, or header name (normalized to lowercase; empty string `""` for endpoint-level passive or discovery findings).

Matching on all four attributes prevents inflated accuracy scores where a check detects the correct vulnerability class on an incorrect endpoint or parameter.

### 6.3.2 Ground-Truth Manifest Schema (`testbench/ground_truth.json`)

```json
{
  "target": "vulnbench",
  "base_url": "http://127.0.0.1:5050",
  "expected_routes": [
    "/",
    "/vuln/sqli-error",
    "/vuln/sqli-boolean",
    "/vuln/xss-reflected",
    "/vuln/open-redirect",
    "/vuln/cors",
    "/vuln/csrf-form",
    "/vuln/cookies",
    "/vuln/error-trace",
    "/vuln/outdated-js",
    "/vuln/admin",
    "/vuln/orders/101",
    "/clean/search",
    "/clean/profile",
    "/clean/redirect"
  ],
  "expected_findings": [
    {
      "check_id": "sqli_error_based",
      "owasp_category": "A03",
      "method": "GET",
      "normalized_path": "/vuln/sqli-error",
      "parameter": "id"
    },
    {
      "check_id": "xss_reflected",
      "owasp_category": "A03",
      "method": "GET",
      "normalized_path": "/vuln/xss-reflected",
      "parameter": "q"
    },
    {
      "check_id": "open_redirect",
      "owasp_category": "A01",
      "method": "GET",
      "normalized_path": "/vuln/open-redirect",
      "parameter": "next"
    }
  ],
  "clean_control_paths": [
    "/clean/search",
    "/clean/profile",
    "/clean/redirect"
  ]
}
```

### 6.3.3 Automated Pipeline Execution Steps

1. **Provision Testbench:** Launch `VulnBench` (and optionally `DVWA` and `OWASP Juice Shop`) via `docker compose -f docker-compose.testbench.yml up -d` and poll `/health` until HTTP `200` is returned.
2. **Execute Benchmark Scan:** Invoke `python scripts/evaluate.py --target http://127.0.0.1:5050 --profile deep --ground-truth testbench/ground_truth.json`. The harness runs a scan through either the FastAPI REST API or the decoupled `ScanOrchestrator`, records elapsed wall-clock time and total HTTP requests issued, and loads the resulting JSON finding records.
3. **Compute Exact Set Metrics:**
   - `TP_set = Predicted_Keys ∩ Expected_Keys`
   - `FP_set = Predicted_Keys - Expected_Keys`
   - `FN_set = Expected_Keys - Predicted_Keys`
   - `FP_clean = {f in FP_set | f.normalized_path in clean_control_paths}`
4. **Emit Machine-Readable Artifacts and Enforce Gate Exit Code:** Persist per-category Precision, Recall, F1-Score, Route Coverage, and Duration to `data/eval_results.json` and print a Markdown summary table. The process exits with status `0` if and only if Recall `>= 80%`, Precision `>= 85%`, and `|FP_clean| == 0`; any gate violation returns a non-zero exit code.

---

## 6.4 Target Benchmark Visualization and Reporting Templates

> [!NOTE]
> **Pre-Execution Baseline Notice:** Figures 17 and 18 and the associated SLA tables establish the **Phase 1 target accuracy baselines and latency SLAs** prior to Phase 6 empirical execution. During Phase 6, `scripts/evaluate.py` will record observed empirical outputs directly against these baseline thresholds for variance analysis in the final evaluation chapter.

### 6.4.1 Target Detection Accuracy Benchmark Profile

Figure 17 presents the pre-Phase 6 target Recall (bars) and target Precision (line) baselines across the six covered OWASP Top 10 (2021) categories [1] on `VulnBench`.

![Figure 17: Target Detection Accuracy Benchmark Profile Across OWASP Categories](../../diagrams/png/17_accuracy_benchmark_chart.png)

*Figure 17: Target Detection Accuracy Benchmark Profile Across OWASP Categories — Pre-Phase 6 Target Baseline (Mermaid source: [17_accuracy_benchmark_chart.mmd](../../diagrams/mmd/17_accuracy_benchmark_chart.mmd)).*

#### Target Accuracy Breakdown by OWASP Category (17 Curated Checks)

| OWASP Top 10 (2021) Category | Assigned Check IDs (Count) | Target Recall (%) | Target Precision (%) | Target F1 (%) | Primary Accuracy Risk / Tuning Focus |
|---|---|---:|---:|---:|---|
| **A01: Broken Access Control** | `cors_misconfig`, `open_redirect`, `forced_browsing_admin`, `idor_heuristic` (4) | 85% | 88% | 86.5% | `idor_heuristic` uses `tentative` confidence to avoid false alarms on public numeric identifiers |
| **A02: Cryptographic Failures** | `insecure_transport`, `insecure_cookies` (2) | 95% | 98% | 96.5% | Deterministic URL scheme and `Set-Cookie` attribute inspection yields high precision |
| **A03: Injection** | `sqli_error_based`, `sqli_boolean_diff`, `xss_reflected` (3) | 85% | 90% | 87.4% | Boolean differential stability filtering and strict HTML-context reflection checks |
| **A05: Security Misconfiguration** | `missing_security_headers`, `weak_csp`, `server_banner_leak`, `verbose_error_pages`, `sensitive_files`, `directory_listing` (6) | 92% | 95% | 93.5% | Soft-404 baseline fingerprinting suppresses catch-all `200 OK` false positives |
| **A06: Vulnerable and Outdated Components** | `outdated_js_components` (1) | 90% | 95% | 92.4% | Semantic version parsing (`packaging.version`) against curated vulnerable library ranges |
| **A07: Identification and Auth Failures** | `csrf_missing_token` (1) | 88% | 90% | 89.0% | Filtering non-state-changing search/filter forms from `POST` anti-CSRF verification |
| **Macro-Target Baseline** | **All 17 Curated Checks** | **89.2%** | **92.7%** | **90.9%** | **Exceeds `NFR-08` mandatory pass gates (Recall `>= 80%`, Precision `>= 85%`)** |

---

### 6.4.2 Target Crawler Coverage and Latency Profile Across Scan Modes

Figure 18 defines the target SLA profile for crawler route coverage (bars, %) and scan duration ceiling (line, seconds) across the `Quick`, `Standard`, and `Deep` profiles on `VulnBench`, alongside expected `Standard` profile behavior on `DVWA` and `OWASP Juice Shop`.

![Figure 18: Target Crawler Coverage and Latency Profile Across Scan Modes](../../diagrams/png/18_coverage_latency_chart.png)

*Figure 18: Target Crawler Coverage and Latency Profile Across Scan Modes — Pre-Phase 6 Target SLA Profile (Mermaid source: [18_coverage_latency_chart.mmd](../../diagrams/mmd/18_coverage_latency_chart.mmd)).*

#### Scan Profile Configuration and Target SLA Matrix

| Benchmark Profile | Crawl Depth | Max URLs | Active Check Scope | Target Coverage (%) | Target Duration SLA (s) | Expected Engineering Behavior |
|---|---:|---:|---|---:|---:|---|
| **Quick (`VulnBench`)** | 1 | 30 | Passive checks only (8 checks) | 55% | `<= 8 s` | Rapid developer feedback during active coding with zero active injection payloads |
| **Standard (`VulnBench`)** | 3 | 150 | Passive (8) + Active Safe (5) + Discovery (3) | 95% | `<= 28 s` | Balanced default scan covering 16/17 checks with Soft-404 baseline calibration |
| **Deep (`VulnBench`)** | 5 | 300 | All 17 checks including `idor_heuristic` (Auth) | 100% | `<= 65 s` | Comprehensive pre-submission audit within the 2,000-request budget |
| **Standard (`DVWA`)** | 3 | 150 | Authenticated Passive + Active + Discovery | 88% | `<= 42 s` | High server-rendered HTML form discovery while safely skipping `/logout.php` |
| **Standard (`Juice Shop`)** | 3 | 150 | Passive + Active + Discovery + JS Route Hints | 35% | `<= 55 s` | Expected non-headless SPA coverage ceiling; Soft-404 prevents catch-all FP floods |

### 6.4.3 Phase 6 Empirical Results Reporting Template

During Phase 6 execution, observed runs emitted by `scripts/evaluate.py` will populate Table 6.4.3 for final thesis reporting and variance analysis:

| Target and Profile | Seeded / Known Vulns | TP | FP | FN | Precision (%) | Recall (%) | F1 (%) | Clean-Control FPs | Route Coverage (%) | Duration (s) | Gate Status |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `VulnBench` (Quick) | *TBD Phase 6* | — | — | — | — | — | — | — | — | — | Pending |
| `VulnBench` (Standard) | *TBD Phase 6* | — | — | — | — | — | — | — | — | — | Pending |
| `VulnBench` (Deep) | 17 | — | — | — | — | — | — | — | — | — | Pending |
| `DVWA` (Low, Auth) | *TBD Phase 6* | — | — | — | — | — | — | N/A | — | — | Pending |
| `DVWA` (Medium, Auth) | *TBD Phase 6* | — | — | — | — | — | — | N/A | — | — | Pending |
| `OWASP Juice Shop` (Standard) | *TBD Phase 6* | — | — | — | — | — | — | N/A | — | — | Pending |

---

## 6.5 System Verification Matrix (`TC-01` to `TC-15`)

To ensure comprehensive end-to-end traceability from functional and non-functional requirements (`Chapter 2`) to concrete executable test procedures, Table 6.5 specifies fifteen formal verification scenarios (`TC-01`–`TC-15`) covering deployment, ethical guardrails, live scanning, accuracy, remediation usability, self-security, and extensibility.

| Test ID | Verification Scenario | Requirement(s) | Preconditions & Input | Expected Pass Criterion | Verification Level |
|---|---|---|---|---|---|
| **TC-01** | Single-Command Startup and Health Check | `NFR-01`, `NFR-05` | Clean host with Docker Compose; run `docker compose up -d` | Container reaches healthy state in `< 3 min`; `GET /api/health` returns HTTP `200` with `database.status == "up"` and `GET /` serves dashboard HTML with security headers | Integration / System |
| **TC-02** | Project Creation with Ownership Attestation | `FR-01`, `NFR-03` | `POST /api/projects` with `ownership_confirmed: false`, then `true` | Request with `false` rejected with HTTP `403`/`422`; request with `true` returns HTTP `201` and persists timestamped attestation in `projects` | API Integration (`pytest`) |
| **TC-03** | Scope Guardrail External Host Blocking | `FR-02`, `NFR-03` | Submit public target `https://example.com` via API and `GuardedHttpClient` | Blocked immediately with `403 OutOfScopeHostError`; zero outbound network packets sent to external host | Unit & API (`pytest`) |
| **TC-04** | DNS Rebinding and Cloud Metadata IP Rejection | `FR-02`, `NFR-03` | Mock `socket.getaddrinfo` returning `93.184.216.34` and `169.254.169.254` for an allow-listed hostname | Gate 5 rejects both resolutions with `403 DNSRebindingBlockedError`; zero HTTP requests dispatched | Unit (`pytest`) |
| **TC-05** | Manual Redirect Policy and `open_redirect` Capture | `FR-02`, `FR-05` | Target `/vuln/open-redirect?next=https://evil.example` returning `302 Location: https://evil.example` | Guardrail refuses to follow cross-origin redirect; returns raw `302` so `open_redirect` check records a `high`-confidence finding safely | Unit & Integration |
| **TC-06** | Destructive and Logout Route Denylist Bypass | `FR-04`, `NFR-03` | Crawled HTML contains `<a href="/logout">` and `<form action="/delete/1">` | Gate 3 skips both routes, logs `GuardrailSkip` telemetry, and preserves authenticated session cookie across remainder of scan | Unit & Integration |
| **TC-07** | Rate Limiting and Per-Scan Request Cap Enforcement | `NFR-02`, `NFR-03` | Configure `SCAN_RATE_LIMIT_RPS=10`, `SCAN_MAX_REQUESTS=25` against mock target with 100 links | Request rate stays `<= 10 req/s`; scan halts cleanly upon reaching 25 requests without unhandled exceptions | Unit (`pytest`) |
| **TC-08** | Live SSE Streaming and Cooperative Cancellation | `FR-06`, `FR-07` | Start `Deep` scan; attach `EventSource` to `/api/scans/{id}/stream`; call `POST /api/scans/{id}/cancel` mid-crawl | Client receives ordered SSE progress events; cancellation transitions scan state to `cancelled` within `<= 2 s` and stops worker thread cleanly | API Integration |
| **TC-09** | Soft-404 Baseline Calibration Suppression | `FR-05`, `NFR-08` | Scan `/clean/soft404/*` returning custom `200 OK` HTML for nonexistent paths | Pre-scan UUID calibration matches baseline signature; `sensitive_files`, `directory_listing`, and `forced_browsing_admin` emit `0` false positives | Unit & System |
| **TC-10** | Full `VulnBench` 17-Check Empirical Accuracy Gate | `FR-05`, `NFR-08` | Run `scripts/evaluate.py --profile deep` against `VulnBench` (`127.0.0.1:5050`) | Achieves Recall `>= 80%`, Precision `>= 85%`, F1 `>= 82%`, and `0` FPs on `/clean/*` control routes; script exits with code `0` | System Benchmark |
| **TC-11** | Authenticated DVWA Crawl and Detection | `FR-04`, `FR-14` | Configure DVWA login + `security=low` against `127.0.0.1:8080`; run `Standard` scan | Authenticated session maintained; crawler discovers core DVWA lab forms and detects SQLi, Reflected XSS, CSRF, and missing security headers | System Benchmark |
| **TC-12** | Exact Endpoint Mapping and Multi-Stack Code Fix | `FR-08`, `FR-09` | Inspect SQLi and XSS findings via `GET /api/findings/{id}` and Dashboard Fix Modal | Response contains exact `method`, `path`, `parameter`, plain-language root cause, and copy-ready Before/After snippets for FastAPI, Flask, Express, PHP, and HTML | API & UI Test |
| **TC-13** | Finding Triage and Cross-Scan SHA-1 Comparison | `FR-11`, `FR-13` | Mark finding `false_positive`; patch 1 bug on `VulnBench`; execute Scan 2 and call compare endpoint | `false_positive` item excluded from risk score; diff endpoint classifies patched finding as `Fixed`, unchanged as `Unchanged`, and introduced as `New` | API Integration |
| **TC-14** | XSS-Safe Report Export and Credential Redaction | `FR-12`, `NFR-04` | Scan mock target echoing `<script>alert(1)</script>` using a Bearer token; export JSON and HTML reports | HTML report escapes `<script>` via Jinja2 autoescaping; neither JSON nor HTML report leaks the Authorization Bearer secret | Unit & Security Test |
| **TC-15** | Per-Check Error Isolation and 1-File Plugin Registry | `FR-15`, `NFR-06`, `NFR-07` | Register a dummy plugin raising `RuntimeError` and a new sample `BaseCheck` module under `checks/` | Faulty check error is caught and logged while remaining 16 checks complete; new 1-file plugin auto-registers and appears in `GET /api/checks` | Unit (`pytest`) |

---

## 6.6 Qualitative Developer-Experience Comparison Rubric Against OWASP ZAP Baseline

Because the primary engineering contribution of this graduation project is **Developer Experience (DX)** for web developers and student teams rather than enterprise check breadth, Phase 6 supplements quantitative detection metrics with a structured comparative evaluation against **OWASP ZAP** [6] (standard local baseline) across the five positioning dimensions defined in Chapter 1.

### 6.6.1 Five-Dimension Developer-Experience Rubric

| Evaluation Dimension | Measurement Protocol | OWASP ZAP Baseline Expectation | Proposed Lightweight Scanner Target | Scoring Scale (1–5 Anchors) |
|---|---|---|---|---|
| **1. Setup Time** | Stopwatch timing from a clean workstation to first completed scan of `http://127.0.0.1:5050` | `10–20 min` (Desktop/JVM setup or Docker flags, optional proxy CA certificate trust, scan context configuration) | **`< 3 min`** (`NFR-01`: single `docker compose up` or local Python `venv` launch) | `5`: `< 3 min` · `4`: `3–5 min` · `3`: `5–10 min` · `2`: `10–20 min` · `1`: `> 20 min` |
| **2. Configuration Steps** | Count of discrete manual user actions required prior to starting a scan | `6–10+` steps (launch mode, proxy/browser configuration, spider policy, active scan policy, alert threshold tuning) | **`<= 3` steps** (create project + confirm ownership, select `Quick`/`Standard`/`Deep`, start scan) | `5`: `<= 3` steps · `4`: `4–5` · `3`: `6–8` · `2`: `9–12` · `1`: `> 12` |
| **3. Finding Clarity** | Structured review of finding views across five seeded vulnerabilities by student evaluators | Raw HTTP request/response dumps, CWE/WASC taxonomy identifiers, and security-analyst phrasing | Exact location mapping (`POST /api/login · field: user`), plain-language root-cause explanation, and severity/confidence badge (`FR-08`, `FR-09`) | `5`: Immediately actionable by a junior developer · `3`: Requires external documentation lookup · `1`: Requires security specialist interpretation |
| **4. Actionability / Copy-Ready Fix** | Inspection of remediation guidance supplied per finding | High-level remediation paragraphs and external OWASP/CWE reference hyperlinks without stack-specific code | Copy-ready **Before / After** code remediation tabs tailored to **FastAPI, Flask, Express, PHP, and HTML** (`FR-09`) | `5`: Copy-ready multi-stack Before/After fix · `3`: Generic pseudocode · `1`: Conceptual guidance or links only |
| **5. Time-to-First-Fix (TTFF)** | Timed remediation task: locate, patch, and re-verify three seeded `VulnBench` flaws (SQLi, Reflected XSS, Missing Security Headers) | Extended documentation lookup and manual cross-scan alert comparison | Rapid remediation loop using copy-ready snippets and one-click re-scan comparison displaying **`Fixed`** badge (`FR-11`) | Elapsed minutes (`Target: >= 40% reduction in TTFF relative to OWASP ZAP baseline`) |

### 6.6.2 Controlled Phase 6 Comparison Protocol

To ensure fair and reproducible benchmarking:
- Both scanners evaluate the **identical `VulnBench` deployment** on `127.0.0.1:5050`.
- Timing runs follow a documented task script (cold start -> initial scan -> inspect three target findings -> apply remediation -> re-scan verification) with timestamped logs.
- Trade-offs are reported transparently: OWASP ZAP [6] and Burp Suite [7] offer superior enterprise check depth, AJAX spidering, and intercepting proxy workflows, whereas the proposed scanner optimizes specifically for **minimal local setup friction, plain-language developer clarity, and accelerated Time-to-First-Fix**.

---

## 6.7 Known Limitations and Honest Threats-to-Validity Disclosure

Academic integrity requires explicit disclosure of architectural boundaries and potential threats to empirical validity.

### 6.7.1 Architectural and Technical Limitations

1. **Client-Side SPA Crawling Ceiling (No Headless Browser):** Consistent with the lightweight single-container design (`ADR-04`), the crawler uses `requests` and `BeautifulSoup4` augmented by static JavaScript route-literal extraction rather than headless Chromium/Playwright. Consequently, Single-Page Applications whose navigation links, DOM forms, or API calls are assembled solely at runtime (such as **OWASP Juice Shop** [11]) exhibit lower automated route coverage (`~35%` target versus `~88–100%` on server-rendered targets like `DVWA` and `VulnBench`). Operators testing SPAs can partially mitigate this by supplying API seed endpoints.
2. **Multi-Step Business Logic and Workflow Vulnerabilities:** Stateless automated probes cannot reason about application-specific domain invariants (such as negative cart totals, coupon stacking, race conditions, or complex multi-role authorization matrices beyond `idor_heuristic`).
3. **Non-Destructive Proof-of-Detection Boundary:** Because the engine strictly prohibits persistent state mutation (`Section 5.1`), vulnerability classes requiring persistent storage or out-of-band network callbacks—including Stored XSS across distinct user sessions, Second-Order SQL Injection, and Blind Out-of-Band SSRF—are intentionally excluded from scope.
4. **Authenticated Session Expiry and Complex Authentication Flows:** Although `FR-14` supports custom session cookies, Bearer tokens, and DVWA form login, targets employing short-lived rotating JWTs, CAPTCHAs, OAuth2/OIDC redirects, or Multi-Factor Authentication (MFA) cannot be re-authenticated automatically if tokens expire mid-scan.
5. **Local and Private Network Scope Restriction:** The hardcoded `ScopeGuardrail` (`Section 5.2`) deliberately prohibits scanning public internet hosts directly unless the scanner is deployed inside the same authorized RFC1918 private network.

### 6.7.2 Threats to Empirical Validity

| Validity Dimension | Identified Threat | Mitigation Strategy Applied in Phase 6 |
|---|---|---|
| **Construct Validity** | **Overfitting to `VulnBench`:** Because `VulnBench` is authored by the same team developing the 17 plugins, strong scores on `VulnBench` alone could reflect over-specialized signatures rather than generalizable detection. | Cross-validate against two independent community targets (**DVWA** [10] and **OWASP Juice Shop** [11]), enforce hardened `/clean/*` negative control routes, and prohibit target-specific URLs or signatures inside check plugins. |
| **Internal Validity** | **Non-Determinism and Host Timing Variance:** Background CPU contention, container cold starts, or rate-limiter jitter can skew measured scan durations. | Warm up containers prior to timed runs, execute three repeated trials per scan profile, report median and standard deviation for latency metrics, and exclude sleep-based blind SQLi from the core 17 checks. |
| **External Validity** | **Generalizability Beyond Capstone Web Stacks:** Remediation snippets target five common student/web stacks (FastAPI, Flask, Express, PHP, HTML) and 17 high-impact OWASP checks, which do not encompass every enterprise stack (for example, Spring Boot, ASP.NET, or GraphQL gateways). | Explicitly bound thesis claims to **web developer and student capstone projects**, and highlight the 1-file `BaseCheck` plugin registry (`ADR-03`) and JSON `kb.json` schema as the clean extension mechanism for additional stacks and rules. |

---

## 6.8 Chapter Summary

Chapter 6 established the empirical validation methodology, automated benchmarking pipeline, verification matrix, and developer-experience evaluation framework for the proposed scanner. Section 6.1 defined the three-tier containerized testbench combining deterministic ground-truth evaluation (`VulnBench` with 17 seeded flaws and hardened `/clean/*` control routes) with external community benchmarks (`DVWA` and `OWASP Juice Shop`). Section 6.2 and Section 6.3 formalized six quantitative metrics, `NFR-08` pass gates (`Recall >= 80%`, `Precision >= 85%`, `0` clean-control false positives), and the automated 4-tuple evaluation pipeline (`scripts/evaluate.py` and `testbench/ground_truth.json`). Section 6.4 presented the pre-Phase 6 target accuracy and coverage/latency SLA baselines (Figures 17 and 18) alongside standardized reporting templates, while Section 6.5 defined the 15-scenario System Verification Matrix (`TC-01`–`TC-15`). Finally, Section 6.6 outlined the five-dimension qualitative comparison rubric against OWASP ZAP, and Section 6.7 provided a transparent disclosure of technical limitations and threats to validity.

---

## References

[1] OWASP Foundation, *OWASP Top 10:2021 — The Ten Most Critical Web Application Security Risks*, 2021. [Online]. Available: https://owasp.org/Top10/

[2] OWASP Foundation, *OWASP Web Security Testing Guide (WSTG)*, Version 4.2, 2023. [Online]. Available: https://owasp.org/www-project-web-security-testing-guide/

[3] OWASP Foundation, *OWASP Application Security Verification Standard (ASVS)*, Version 4.0.3, 2021. [Online]. Available: https://owasp.org/www-project-application-security-verification-standard/

[4] M. Souppaya, K. Scarfone, and D. Dodson, *Secure Software Development Framework (SSDF) Version 1.1: Recommendations for Mitigating the Risk of Software Vulnerabilities*, National Institute of Standards and Technology (NIST), Special Publication 800-218, Feb. 2022. [Online]. Available: https://csrc.nist.gov/publications/detail/sp/800-218/final

[5] OWASP Foundation, *OWASP Cheat Sheet Series*, 2025. [Online]. Available: https://cheatsheetseries.owasp.org/

[6] Checkmarx / ZAP Community, *Zed Attack Proxy (ZAP) User Guide and Documentation*, 2025. [Online]. Available: https://www.zaproxy.org/docs/

[7] PortSwigger Ltd., *Burp Suite Documentation — Web Application Security Testing*, 2025. [Online]. Available: https://portswigger.net/burp/documentation

[8] N. Surribas, *Wapiti — Web-Application Vulnerability Scanner Documentation*, 2025. [Online]. Available: https://wapiti-scanner.github.io/

[9] ProjectDiscovery Inc., *Nuclei — Fast and Customizable Template-Based Vulnerability Scanner Documentation*, 2025. [Online]. Available: https://docs.projectdiscovery.io/tools/nuclei/overview

[10] R. Dewhurst and DVWA Contributors, *Damn Vulnerable Web Application (DVWA)*, 2025. [Online]. Available: https://github.com/digininja/DVWA

[11] B. Kimminich and OWASP Contributors, *OWASP Juice Shop — Probably the Most Modern and Sophisticated Insecure Web Application*, 2025. [Online]. Available: https://owasp.org/www-project-juice-shop/

[12] S. Ramírez, *FastAPI Framework Documentation*, and M. Bayer, *SQLAlchemy 2.0 Documentation*, 2025. [Online]. Available: https://fastapi.tiangolo.com/ and https://docs.sqlalchemy.org/en/20/

---

## Semester 2 Final Sign-Off Summary

This Semester 2 Graduation Project Book (Chapters 4–6, Figures 15–18) serves as the formal second-semester academic submission covering Detailed Data/API Design, Security Governance & ADRs, and Empirical Validation Strategy.

| Document Attribute | Details |
| :--- | :--- |
| **Document Edition** | GRADUATION PROJECT BOOK – SEMESTER 2 (SAD_Semester2_Book) |
| **Project Title** | Developing a Lightweight OWASP Top 10 Vulnerability Scanner — Tailored for Web Developers and Student Projects (Developer-Experience Focus) |
| **Department** | Department of Cyber Security |
| **Academic Year** | 2026–2027 |
| **Prepared For (Project Supervisor)** | **Dr. Samar**, Project Supervisor |
| **Review Milestone** | Second Semester Milestone — Detailed Design, Security & Validation Final Approval |

### Project Team Sign-Off

| # | Student Name | Student ID | Primary Architectural Ownership | Sign-Off Status |
| :---: | :--- | :---: | :--- | :--- |
| 1 | Ahmed Ashraf Ammar | `235204` | System Architecture, Orchestrator & FastAPI Core | Approved — Semester 2 Final v1.1 |
| 2 | Islam Mohammed | `235164` | Scope Guardrail, HTTP Client & BFS Crawler | Approved — Semester 2 Final v1.1 |
| 3 | Abdelrhman Mohamed AbdEl-latif | `235216` | Passive OWASP Checks & Soft-404 Calibration | Approved — Semester 2 Final v1.1 |
| 4 | Ahmed Waleed Mokthar | `235052` | Active Safe Injection & Access Control Checks | Approved — Semester 2 Final v1.1 |
| 5 | Mohamed Waleed Mokthar | `235051` | SQLAlchemy Persistence, Diffing & Report Export | Approved — Semester 2 Final v1.1 |
| 6 | Mohamed Ibrahim Elsayed | `235401` | Developer Dashboard UI (HTML5/Tailwind/Vanilla JS & SSE) | Approved — Semester 2 Final v1.1 |
| 7 | Ali Ibrahim Elsayed | `235332` | Remediation KB, `VulnBench` Testbench & Evaluation Suite | Approved — Semester 2 Final v1.1 |

### Academic Supervisor Review

| Reviewer Role | Name | Review Decision | Signature / Date |
| :--- | :--- | :--- | :--- |
| **Project Supervisor** | **Dr. Samar** | `[ ] Approved` / `[ ] Approved with Revisions` | `_______________________` / `____-__-__` |
