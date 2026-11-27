# Phase 6 Empirical Validation & Testbench Benchmark Report

> **Automated Reproducibility Statement:** All quantitative VulnBench metrics in this report were generated directly by `scripts/evaluate.py` executing `backend.scanner.ScanOrchestrator` against the deterministic local `VulnBench` server (`testbench/vulnbench/app.py`) and verified against `testbench/ground_truth.json`.

| Metadata Field | Value |
|---|---|
| **Generated (UTC)** | `2026-11-27T14:25:54Z` |
| **Primary Benchmark Target** | `VulnBench` (Python 3.12 stdlib `ThreadingHTTPServer` + in-memory `sqlite3`) |
| **Ground-Truth Manifest** | `testbench/ground_truth.json` (`19` expected findings across all 17 OWASP checks; `4` clean `/safe/*` control routes) |
| **Primary Evaluation Profile** | `Deep` (`17 / 17` checks executed, `0` runtime errors) |
| **Rate Limit Configuration** | `10.0 req/s` (default non-destructive throttle, `max_requests=2000`) |
| **Overall NFR-08 Gate Verdict** | **PASS** |

## 1. Quantitative Acceptance Gate Scorecard (`NFR-08`, `NFR-02`, `NFR-07`)

| Acceptance Gate | Governing Req. | Mandatory Threshold | Observed (`Deep`) | Status |
|---|---|---:|---:|---|
| **Overall Recall (TPR)** | `NFR-08` | `>= 80.0%` | **100.0%** (`19/19`) | PASS |
| **Overall Precision** | `NFR-08` | `>= 85.0%` | **100.0%** (`19/19`) | PASS |
| **Overall F1-Score** | `NFR-08` | `>= 82.0%` | **100.0%** | PASS |
| **Clean-Control False Positives (`/safe/*`)** | `NFR-08` | `0` FPs (`0.0%` FPR) | **`0`** | PASS |
| **Crawler Route Coverage** | `FR-04` / Ch. 6 | `>= 80.0%` | **93.3%** (`14/15` routes) | PASS |
| **Deep Profile Scan Duration** | `NFR-02` | `<= 90 s` | **`21.42 s`** | PASS |
| **Per-Check Error Isolation (Unhandled Crashes)** | `NFR-07` | `0` errors | **`0`** | PASS |
| **All 17 OWASP Checks Executed** | `FR-05` | `17 / 17` | **`17 / 17`** | PASS |

## 2. Empirical `VulnBench` Results Across Scan Profiles (`Quick`, `Standard`, `Deep`)

Table 2 compares all three scan profiles against the identical `VulnBench` instance. Note that `Quick` executes only the 8 passive checks (zero active injection probes), `Standard` adds 5 active checks plus `sensitive_files` (14 checks total), and `Deep` executes all 17 checks including `idor_heuristic`, `directory_listing`, and `forced_browsing_admin`.

| Profile | Checks Run | Seeded Total | Profile Expected | TP | FP | FN (All) | Precision | Recall (All) | Recall (Profile) | F1 (All) | Clean FPs | Route Coverage | Pages Crawled | Requests | Duration (s) | SLA (s) | Risk Score |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Quick** | 8/17 | 19 | 9 | 9 | 0 | 10 | 100.0% | 47.4% | 100.0% | 64.3% | 0 | 93.3% (14/15) | 14 | 20 | 1.92 | <= 15 | 23/100 |
| **Standard** | 14/17 | 19 | 16 | 16 | 0 | 3 | 100.0% | 84.2% | 100.0% | 91.4% | 0 | 93.3% (14/15) | 14 | 203 | 20.22 | <= 45 | 66/100 |
| **Deep** | 17/17 | 19 | 19 | 19 | 0 | 0 | 100.0% | 100.0% | 100.0% | 100.0% | 0 | 93.3% (14/15) | 14 | 215 | 21.42 | <= 90 | 78/100 |

## 3. Per-Check Empirical Breakdown (Deep Profile — All 17 Checks)

| Check ID | Kind | OWASP 2021 | Expected | Detected | TP | FP | FN | Precision | Recall | F1-Score | Status |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `csrf_missing_token` | passive | `A01` | 1 | 1 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% | **PASS** |
| `insecure_cookies` | passive | `A07` | 1 | 1 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% | **PASS** |
| `insecure_transport` | passive | `A02` | 1 | 1 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% | **PASS** |
| `missing_security_headers` | passive | `A05` | 1 | 1 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% | **PASS** |
| `outdated_js_components` | passive | `A06` | 1 | 1 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% | **PASS** |
| `server_banner_leak` | passive | `A05` | 2 | 2 | 2 | 0 | 0 | 100.0% | 100.0% | 100.0% | **PASS** |
| `verbose_error_pages` | passive | `A05` | 1 | 1 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% | **PASS** |
| `weak_csp` | passive | `A05` | 1 | 1 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% | **PASS** |
| `cors_misconfig` | active | `A05` | 1 | 1 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% | **PASS** |
| `idor_heuristic` | active | `A01` | 1 | 1 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% | **PASS** |
| `open_redirect` | active | `A01` | 1 | 1 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% | **PASS** |
| `sqli_boolean_diff` | active | `A03` | 1 | 1 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% | **PASS** |
| `sqli_error_based` | active | `A03` | 1 | 1 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% | **PASS** |
| `xss_reflected` | active | `A03` | 1 | 1 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% | **PASS** |
| `directory_listing` | discovery | `A05` | 1 | 1 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% | **PASS** |
| `forced_browsing_admin` | discovery | `A01` | 1 | 1 | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% | **PASS** |
| `sensitive_files` | discovery | `A05` | 2 | 2 | 2 | 0 | 0 | 100.0% | 100.0% | 100.0% | **PASS** |

## 4. Per-OWASP Category Accuracy vs. SAD Chapter 6.4.1 Target Baselines

| OWASP Category | Assigned Checks | Seeded | TP | FP | FN | Observed Recall | SAD Target Recall | Observed Precision | SAD Target Precision | Observed F1 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **A01:2021 - Broken Access Control** | `csrf_missing_token`, `idor_heuristic`, `open_redirect`, `forced_browsing_admin` | 4 | 4 | 0 | 0 | 100.0% | 85.0% | 100.0% | 88.0% | 100.0% |
| **A02:2021 - Cryptographic Failures** | `insecure_transport` | 1 | 1 | 0 | 0 | 100.0% | 95.0% | 100.0% | 98.0% | 100.0% |
| **A03:2021 - Injection** | `sqli_boolean_diff`, `sqli_error_based`, `xss_reflected` | 3 | 3 | 0 | 0 | 100.0% | 85.0% | 100.0% | 90.0% | 100.0% |
| **A05:2021 - Security Misconfiguration** | `missing_security_headers`, `server_banner_leak`, `verbose_error_pages`, `weak_csp`, `cors_misconfig`, `directory_listing`, `sensitive_files` | 9 | 9 | 0 | 0 | 100.0% | 92.0% | 100.0% | 95.0% | 100.0% |
| **A06:2021 - Vulnerable and Outdated Components** | `outdated_js_components` | 1 | 1 | 0 | 0 | 100.0% | 90.0% | 100.0% | 95.0% | 100.0% |
| **A07:2021 - Identification and Authentication Failures** | `insecure_cookies` | 1 | 1 | 0 | 0 | 100.0% | 88.0% | 100.0% | 90.0% | 100.0% |

## 5. Clean Control Route False-Positive Verification (`/safe/*`)

To confirm that active injection, redirect, CSRF, and header heuristics do not trigger false alarms on properly hardened endpoints, `VulnBench` exposes four clean control routes implementing strict security headers, HTML output encoding, parameterized SQLite queries, allow-listed redirects, and anti-CSRF tokens:

| Clean Control Route | Hardening Controls Tested | Discovered by Crawler | False Positives Observed | Verdict |
|---|---|---|---:|---|
| `/safe/form` | Hidden `csrf_token` field + non-password POST form (`csrf_missing_token` & `insecure_transport` negative control) | Yes | `0` | **PASS** |
| `/safe/item` | Parameterized SQLite query (`?`) + non-enumerable ID check (`sqli_*` & `idor_heuristic` negative control) | Yes | `0` | **PASS** |
| `/safe/redirect` | Strict relative-path allowlist (`{/home, /about}`) (`open_redirect` negative control) | Yes | `0` | **PASS** |
| `/safe/search` | HTML-escaped output (`html.escape(..., quote=True)`) + strict headers (`xss_reflected` negative control) | Yes | `0` | **PASS** |

## 6. Crawler Route Coverage Analysis

- **Known Linked Routes in Manifest:** `15`
- **Discovered Known Routes (`Deep`):** `14` (**93.3%**)
- **Total Attack Surface Recorded (`Deep`):** `14` endpoints, `2` forms, `14` pages crawled
- **Undiscovered Known Routes:** `/home`

## 7. External Community Target Benchmarking Procedure (Docker Testbench)

To mitigate construct-validity bias from evaluating solely against our own `VulnBench` target (SAD Section 6.7.2), `docker-compose.testbench.yml` provisions two independent community targets strictly bound to `127.0.0.1` on an isolated `testbench_net` bridge network.

### 7.1 Provisioning All Three Testbench Containers

```bash
# 1. Start VulnBench (127.0.0.1:5050), DVWA (127.0.0.1:8080), and OWASP Juice Shop (127.0.0.1:3000)
docker compose -f docker-compose.testbench.yml up -d

# 2. Verify all local testbench services respond on loopback only
curl -fsS http://127.0.0.1:5050/ > /dev/null && echo 'VulnBench ready'
curl -fsS http://127.0.0.1:8080/login.php > /dev/null && echo 'DVWA ready'
curl -fsS http://127.0.0.1:3000/ > /dev/null && echo 'Juice Shop ready'
```

### 7.2 Tier 2: DVWA (`http://127.0.0.1:8080`, Authenticated Server-Rendered Benchmark)

1. Initialize the DVWA database once at `http://127.0.0.1:8080/setup.php` (**Create / Reset Database**).
2. In the OWASP Lite Scanner dashboard (`http://127.0.0.1:8000`), create a project for `http://127.0.0.1:8080` with ownership confirmed, select the **Standard** or **Deep** profile, and enable **DVWA Auto-Login** (`admin` / `password`, `security=low` or `security=medium`).
3. Verify that:
   - The crawler authenticates cleanly via `ScannerHttpClient.auto_login_dvwa()` and skips `/logout.php` via `ScopeGuardrail.is_destructive_path()`.
   - `sqli_error_based` / `sqli_boolean_diff`, `xss_reflected`, `csrf_missing_token`, `missing_security_headers`, `insecure_cookies`, and `server_banner_leak` fire on the expected DVWA modules.
   - Switching DVWA to `security=medium` demonstrates reduced findings and cross-scan diff classification (`Fixed` vs `Unchanged`).

### 7.3 Tier 3: OWASP Juice Shop (`http://127.0.0.1:3000`, Modern SPA Benchmark)

1. Create a project for `http://127.0.0.1:3000` (anonymous or with an optional Bearer JWT obtained from `/rest/user/login`) and run the **Standard** or **Deep** profile.
2. Verify that:
   - Pre-scan Soft-404 calibration (`calibrate_soft_404`) accurately fingerprints Angular's catch-all `index.html` HTTP `200 OK` fallback and prevents false-positive floods in `sensitive_files`, `directory_listing`, and `forced_browsing_admin`.
   - Passive/active checks detect permissive CORS (`cors_misconfig`), missing/weak CSP headers, and outdated client-side libraries where exposed.
   - Non-headless crawler route coverage aligns with the documented ~35% SPA ceiling (SAD Section 6.4.2 & 6.7.1).

### 7.4 Re-Running the Automated `VulnBench` Benchmark Anytime

```bash
# Zero-external-server reproducible run across Quick, Standard, and Deep profiles:
python scripts/evaluate.py --auto-start-vulnbench --benchmark-all-profiles --write-report docs/TESTBENCH_RESULTS.md --json-out data/eval_results.json

# Or against a running Docker VulnBench container:
python scripts/evaluate.py --target http://127.0.0.1:5050 --benchmark-all-profiles --ground-truth testbench/ground_truth.json
```

## 8. Developer-Experience (DX) Comparison Rubric vs. OWASP ZAP Baseline

Aligned with SAD Section 6.6, the scanner's primary differentiation is **developer ergonomics and rapid remediation for student and local web projects** rather than enterprise scan breadth. Table 8 summarizes the structured 5-dimension comparison rubric against **OWASP ZAP** on the identical `VulnBench` target.

| DX Dimension | Measurement Protocol | OWASP ZAP Baseline | OWASP Lite Scanner (This Project) | Key Engineering Advantage |
|---|---|---|---|---|
| **1. Setup Time** | Clean host to first completed `VulnBench` scan | `10–20 min` (JVM/Desktop or CLI Docker flags, proxy CA cert, context config) | **`< 3 min`** (`docker compose up` or `uvicorn` + single-command `evaluate.py`) | Zero JVM overhead, SQLite default, zero proxy CA configuration |
| **2. Configuration Steps** | Manual steps before scan starts | `6–10+` steps (mode, spider policy, active scan policy, alert thresholds) | **`<= 3` steps** (create project + confirm ownership, choose profile, launch) | Opinionated `Quick` / `Standard` / `Deep` profiles + built-in loopback safety guardrail |
| **3. Finding Clarity** | Junior developer review of 5 seeded flaws | Raw HTTP traces, WASC/CWE jargon, analyst-oriented descriptions | Exact `METHOD /path · param`, severity/confidence badge, plain-language root cause | Eliminates security-analyst translation overhead (`FR-08`) |
| **4. Copy-Ready Fix Guidance** | Remediation inspection per finding | Conceptual paragraphs + external OWASP/CWE links | Multi-stack **Before / After** code tabs (**FastAPI, Flask, Express, PHP, HTML**) | Directly copy-pasteable remediation tailored to student web stacks (`FR-09`) |
| **5. Time-to-First-Fix (TTFF)** | Locate, patch, and re-verify 3 `VulnBench` flaws | Manual re-scan and alert diffing | One-click re-scan + deterministic SHA-1 cross-scan diff showing **`Fixed`** badges | Closed feedback loop accelerates developer remediation (`FR-11`) |

> **Fair Trade-Off Disclosure:** OWASP ZAP and Burp Suite remain superior for enterprise penetration testing requiring an intercepting HTTPS proxy, headless AJAX spidering, custom active fuzzer scripts, and broad non-OWASP CVE coverage. OWASP Lite Scanner intentionally trades enterprise breadth for safe local defaults, sub-minute feedback, and actionable code fixes.

## 9. Honest Limitations, Observed Misses / False Positives & Threats to Validity

### 9.1 Observed False Negatives & False Positives on `VulnBench` (`Deep` Profile)

- **False Negatives (`FN = 0`):** All `19` seeded ground-truth findings across all 17 OWASP checks were detected cleanly.
- **False Positives (`FP = 0`):** Zero unexpected findings were emitted across both vulnerable routes and all four `/safe/*` clean control routes.

### 9.2 Architectural Boundaries & Threats to Validity

1. **Construct Validity (`VulnBench` Authorship):** Because `VulnBench` was authored alongside the 17 checks, 100% or near-100% deterministic metrics on `VulnBench` validate check contract correctness and regression safety rather than universal real-world recall. Cross-validation against **DVWA** and **OWASP Juice Shop** (Section 7) is essential for external generalization.
2. **Non-Headless SPA Crawling Ceiling:** The lightweight `requests` + `BeautifulSoup4` crawler does not execute client-side JavaScript frameworks (React/Angular/Vue). SPAs that build routes dynamically at runtime exhibit lower automated discovery coverage than server-rendered apps.
3. **Non-Destructive Scope Boundary:** Persistent state-mutating attacks (Stored XSS across sessions, Second-Order SQLi, Blind OOB SSRF, and destructive `DELETE`/`/logout` mutations) are deliberately excluded to uphold ethical non-destructive scanning guarantees (`NFR-03`).
4. **Heuristic Tentative Confidence (`idor_heuristic`):** Numeric ID adjacency probing cannot prove broken authorization without multi-user session comparison; findings are intentionally labeled `confidence=low` so developers manually confirm object-level ownership checks.
5. **Loopback & Private-Network Scope Guardrail:** Public internet scanning is hard-blocked by `ScopeGuardrail` (`127.0.0.1`, `localhost`, and RFC1918 allow-listed targets only).
