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

![Figure 16: Pre-Request Scope Guardrail and Safety Decision Flow](../diagrams/png/16_scope_guardrail_flow.png)

*Figure 16: Pre-Request Scope Guardrail and Safety Decision Flow (Mermaid source: [16_scope_guardrail_flow.mmd](../diagrams/mmd/16_scope_guardrail_flow.mmd)).*

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
