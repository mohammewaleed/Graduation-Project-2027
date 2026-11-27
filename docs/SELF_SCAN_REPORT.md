# Phase 7 Self-Scan & Hardening Audit Report

> **Academic Dogfooding & Security Hardening Verification**  
> **Project:** Developing a Lightweight OWASP Top 10 Vulnerability Scanner (Tailored for Web Developers and Student Projects)  
> **Department:** Department of Cyber Security — Academic Year 2026–2027  
> **Project Supervisor:** Dr. Samar

---

## Audit Metadata

| Attribute | Value |
| :--- | :--- |
| **Audit Phase** | Phase 7 — Final Hardening, Self-Scan Verification & Capstone Delivery |
| **System Under Test (SUT)** | OWASP-Lite Scanner FastAPI Application & Static Developer Dashboard (`http://127.0.0.1:8000`) |
| **Scanner Profile Executed** | `Deep` (`17 / 17` OWASP Top 10 (2021) checks: 8 Passive, 6 Active Safe, 3 Discovery) |
| **Scope Enforcement** | Local loopback target (`127.0.0.1`) authorized under `ScopeGuardrail` |
| **Risk Score Formula (SAD Ch. 4)** | $\text{Risk Score} = \min(100,\; 10 N_{\text{critical}} + 6 N_{\text{high}} + 3 N_{\text{medium}} + 1 N_{\text{low}})$ |
| **Automated Regression Suite** | `backend/tests/integration/test_self_scan_hardening.py` |
| **Hardening Verdict** | **PASS** — `0` Critical, `0` High, `0` `missing_security_headers`, `0` `server_banner_leak`, `0` runtime errors (`Risk Score: 3/100`) |

---

## 1. Executive Summary

To demonstrate security-by-design maturity prior to graduation defense, the OWASP-Lite Scanner was executed against **itself** ("dogfooding") using the most thorough **`Deep` (17-check)** scan profile targeting `http://127.0.0.1:8000`.

1. **Baseline Live Self-Scan:** Completed with `0` runtime errors across `2` crawled pages and `83` HTTP requests. The scanner confirmed **`0` Critical** and **`0` High** vulnerabilities—validating that injection protections, CORS restrictions, XSS output safety, error handling, and sensitive-file exposure controls held cleanly—while surfacing **`2` Medium** defensive-header findings (`Risk Score: 6/100`):
   - `missing_security_headers` (`A05:2021` / `CWE-693`): absence of the `Permissions-Policy` header.
   - `weak_csp` (`A05:2021` / `CWE-693`): presence of `style-src 'self' 'unsafe-inline'` in the Content-Security-Policy (alongside an opportunity to lock down `object-src 'none'`).
2. **Phase 7 Hardening Actions:** Five concrete hardening improvements were implemented across `backend/app/main.py`, `Dockerfile`, and `backend/tests/integration/test_self_scan_hardening.py`, eliminating `missing_security_headers`, restricting `object-src 'none'`, enforcing `Cache-Control: no-cache` on static UI assets, suppressing Uvicorn's `Server` banner via `--no-server-header`, and locking these invariants under automated pytest regression testing.
3. **Post-Hardening Target Posture:** Risk Score reduced by **50%** from **`6/100` → `3/100`** with **`0` Critical**, **`0` High**, **`0` `missing_security_headers`**, **`0` `server_banner_leak`**, and **`0` errors**. The single remaining `Medium` finding (`weak_csp` for `style-src 'self' 'unsafe-inline'`) is an explicitly documented, low-risk architectural trade-off supporting the zero-build Tailwind Play CDN UI while keeping `script-src` completely free of `'unsafe-inline'` and `'unsafe-eval'`.

---

## 2. Baseline Live `Deep` Self-Scan Results (`http://127.0.0.1:8000`)

### 2.1 Execution Telemetry

| Telemetry Metric | Baseline Observed Value |
| :--- | :---: |
| **Target URL** | `http://127.0.0.1:8000` |
| **Scan Profile** | `Deep` (`17 / 17` checks) |
| **Final Status** | `completed` |
| **Pages Crawled** | `2` |
| **HTTP Requests Sent** | `83` |
| **Unhandled Check / Engine Errors** | `0` |
| **Baseline Risk Score** | **`6 / 100`** |
| **Severity Breakdown** | `0` Critical · `0` High · `2` Medium · `0` Low · `0` Info |

### 2.2 Baseline Findings Identified

| # | Check ID | OWASP 2021 Category | CWE | Severity | Confidence | Observed Baseline Root Cause |
| :---: | :--- | :--- | :---: | :---: | :---: | :--- |
| 1 | `missing_security_headers` | `A05:2021 - Security Misconfiguration` | `CWE-693` | **Medium** | `High` | `SECURITY_HEADERS` middleware in `backend/app/main.py` omitted `Permissions-Policy`. |
| 2 | `weak_csp` | `A05:2021 - Security Misconfiguration` | `CWE-693` | **Medium** | `High` | `Content-Security-Policy` contained `style-src 'self' 'unsafe-inline'` (flagged by `WeakCSPCheck` scanning all directive tokens for `'unsafe-inline'`); `object-src 'none'` was also not explicitly declared. |

### 2.3 Baseline Clean-Pass Categories (`15 / 17` Checks Emitted `0` Findings)

All active injection, access-control, transport, disclosure, and discovery checks passed cleanly with zero findings on the baseline self-scan:

- **A01 — Broken Access Control:** `csrf_missing_token` (`0`), `idor_heuristic` (`0`), `open_redirect` (`0`), `forced_browsing_admin` (`0`)
- **A02 — Cryptographic Failures:** `insecure_transport` (`0`)
- **A03 — Injection:** `sqli_error_based` (`0`), `sqli_boolean_diff` (`0`), `xss_reflected` (`0`)
- **A05 — Security Misconfiguration:** `cors_misconfig` (`0`), `server_banner_leak` (`0`), `verbose_error_pages` (`0`), `directory_listing` (`0`), `sensitive_files` (`0`)
- **A06 — Vulnerable & Outdated Components:** `outdated_js_components` (`0`)
- **A07 — Identification & Authentication Failures:** `insecure_cookies` (`0`)

---

## 3. Phase 7 Hardening Actions Applied

To close the observed `missing_security_headers` finding and tighten overall defense-in-depth across both the FastAPI runtime and container image, five targeted hardening changes were applied:

| # | Target File | Hardening Action Implemented | Security Control / Rationale |
| :---: | :--- | :--- | :--- |
| **1** | `backend/app/main.py` | Added `"Permissions-Policy": "geolocation=(), camera=(), microphone=()"` to `SECURITY_HEADERS`. | Eliminates `missing_security_headers` (`CWE-693`) by explicitly denying sensitive browser sensor APIs across all responses. |
| **2** | `backend/app/main.py` | Added `object-src 'none'` to `Content-Security-Policy` inside `SECURITY_HEADERS`. | Blocks legacy `<object>`, `<embed>`, and `<applet>` plugin execution contexts in accordance with OWASP CSP Cheat Sheet guidance. |
| **3** | `backend/app/main.py` | Enforced `Cache-Control: no-cache` in `add_security_headers` middleware for static frontend UI assets (non-`/api/` paths). | Ensures browsers revalidate dashboard HTML/CSS/JS modules on load and prevents stale security scripts from persisting in local browser caches. |
| **4** | `Dockerfile` | Added `--no-server-header` to the Uvicorn runtime `CMD` (`uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --no-server-header`). | Suppresses the default `Server: uvicorn` response header, preventing passive server/framework fingerprinting (`CWE-200`) in containerized deployments. |
| **5** | `backend/tests/integration/test_self_scan_hardening.py` | Added dedicated automated integration regression test suite verifying response security headers, CSP directives, static `Cache-Control`, and Deep self-scan finding bounds. | Guarantees that future changes cannot silently reintroduce `missing_security_headers`, `server_banner_leak`, or High/Critical regressions. |

### 3.1 HTTP Response Security Header Transformation (`backend/app/main.py`)

| Response Header | Baseline (Pre-Phase 7) | Post-Hardening (Phase 7) |
| :--- | :--- | :--- |
| `X-Content-Type-Options` | `nosniff` | `nosniff` |
| `X-Frame-Options` | `DENY` | `DENY` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | *(Absent — flagged by `missing_security_headers`)* | `geolocation=(), camera=(), microphone=()` |
| `Content-Security-Policy` | `default-src 'self'; script-src 'self' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'` | `default-src 'self'; script-src 'self' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'` |
| `Cache-Control` (Static UI) | *(Default static file caching)* | `no-cache` |
| `Server` (Container `Dockerfile`) | `uvicorn` (default Uvicorn banner) | *(Suppressed via `--no-server-header`)* |

---

## 4. Post-Hardening Target Posture Comparison

| Security Metric | Baseline Live Self-Scan | Post-Hardening Posture | Delta / Verification |
| :--- | :---: | :---: | :--- |
| **Overall Risk Score (`0–100`)** | `6 / 100` | **`3 / 100`** | **-50%** (`1` remaining Medium × weight `3`) |
| **Critical Findings** | `0` | **`0`** | Maintained (`PASS`) |
| **High Findings** | `0` | **`0`** | Maintained (`PASS`) |
| **Medium Findings** | `2` | **`1`** | `missing_security_headers` eliminated |
| **Low / Info Findings** | `0` | **`0`** | Maintained (`PASS`) |
| **`missing_security_headers`** | `1` (`Permissions-Policy`) | **`0`** | **RESOLVED** |
| **`server_banner_leak`** | `0` | **`0`** | **HARDENED** (`--no-server-header` in `Dockerfile`) |
| **`weak_csp`** | `1` (`style-src 'unsafe-inline'`) | **`1`** (`style-src 'unsafe-inline'`) | Documented architectural trade-off (Section 5) |
| **Unhandled Scan Errors** | `0` | **`0`** | Maintained (`PASS`) |

---

## 5. Architectural Rationale for Accepted Medium Trade-Off (`style-src 'self' 'unsafe-inline'`)

In strict academic honesty, the scanner intentionally **does not** whitelist itself or suppress `WeakCSPCheck` against its own URL. As a result, `weak_csp` continues to emit `1` Medium finding (`Risk Score: 3/100`) because `Content-Security-Policy` retains `style-src 'self' 'unsafe-inline'`.

### 5.1 Why Script Execution Remains Strictly Protected

- **`script-src` Hard Boundary:** The policy sets `script-src 'self' https://cdn.tailwindcss.com`, which **strictly forbids both `'unsafe-inline'` and `'unsafe-eval'`**. Any injected `<script>` block or inline event handler (`onclick=`, `onerror=`, `javascript:` URI) is blocked by the browser.
- **Zero Unsafe DOM Sinks in Frontend:** Every ES module under `frontend/js/` (`app.js`, `utils.js`, and all five components in `frontend/js/components/`) constructs DOM trees exclusively through safe `document.createElement()` and `.textContent` helpers—with **zero inline JavaScript**, **zero `innerHTML`**, and **zero `eval()`**.
- **Zero Unsafe Template Rendering in Reports:** Offline HTML5 reports (`backend/app/reports/templates/report.html.j2`) enforce Jinja2 strict autoescaping with **zero `|safe` filter bypasses**.
- **Explicit Plugin & Framing Lockout:** `object-src 'none'`, `frame-ancestors 'none'`, `base-uri 'self'`, and `form-action 'self'` prevent plugin execution, clickjacking, base-tag hijacking, and cross-origin form submission.

### 5.2 Why `style-src 'unsafe-inline'` Is Retained in This Edition

- **Zero-Build Developer Experience (`NFR-05`):** The graduation project deliberately uses a zero-build frontend (no Node.js, Webpack, or Vite toolchain required for students to clone and run the scanner in under 3 minutes). Loading Tailwind Play CDN (`https://cdn.tailwindcss.com`) dynamically compiles utility classes into runtime `<style>` tags in the document `<head>`, and interactive SVG chart/theme components rely on inline style attributes. Removing `'unsafe-inline'` from `style-src` while using Tailwind Play CDN would break dashboard styling.

### 5.3 Production Migration Path to `0 / 100` Risk Score

For a production deployment where a `0 / 100` strict-CSP posture is required:

1. **Precompiled Static CSS:** Compile Tailwind utilities ahead of time using the standalone Tailwind CLI (`tailwindcss -i input.css -o frontend/css/tailwind.min.css --minify`) and remove the `https://cdn.tailwindcss.com` `<script>` tag from `frontend/index.html`.
2. **Eliminate Inline Style Attributes:** Replace any runtime inline `style="..."` properties on SVG/chart elements with static CSS classes in `frontend/css/styles.css`.
3. **Tighten CSP Header:** Update `Content-Security-Policy` in `backend/app/main.py` to:
   ```text
   default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
   ```
   With those three steps, `weak_csp` clears cleanly and the live Deep self-scan Risk Score reaches **`0 / 100`**.

---

## 6. Verification & Reproducibility

### 6.1 Run Automated Hardening Regression Tests

```bash
pytest backend/tests/integration/test_self_scan_hardening.py -v
```

### 6.2 Reproduce a Live `Deep` Self-Scan Locally

```bash
# Terminal 1: Start the hardened scanner server without Uvicorn's Server banner
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --no-server-header

# Terminal 2: Inspect hardened response headers directly
curl -sSI http://127.0.0.1:8000/
```

Then open **http://127.0.0.1:8000**, create a project targeting `http://127.0.0.1:8000` (with ownership confirmed), and run a **`Deep`** scan to observe `0` Critical, `0` High, `0` `missing_security_headers`, `0` `server_banner_leak`, `0` errors, and `Risk Score: 3/100`.

---

## Related Documentation

- [README.md](../README.md) — Project overview, 3-minute Quick Start, 17-check catalog, and extensibility guide
- [docs/TESTBENCH_RESULTS.md](TESTBENCH_RESULTS.md) — Phase 6 empirical `VulnBench` precision/recall report & OWASP ZAP DX comparison
- [docs/SAD.md](SAD.md) — Formal Software Architecture Document (Chapters 1–6 & 19 Mermaid/PNG figures)
