#!/usr/bin/env python3
"""
Build the 11-slide Supervisor Progress Briefing for Dr. Samar in three formats:
  1. docs/presentations/html/Semester1_Progress_Defense.html  (100% offline 16:9 interactive slideshow + print styles)
  2. docs/presentations/pdf/Semester1_Progress_Defense.pdf    (11-page 16:9 widescreen PDF via headless Chrome)
  3. docs/presentations/pptx/Semester1_Progress_Defense.pptx  (100% valid 16:9 OOXML PowerPoint via stdlib zipfile + XML)

Usage:
    py -3.12 scripts/build_presentation.py
"""

from __future__ import annotations

import base64
import html
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
IMG_DIR = DOCS_DIR / "diagrams" / "png"
PRES_DIR = DOCS_DIR / "presentations"

OUT_HTML = PRES_DIR / "html" / "Semester1_Progress_Defense.html"
OUT_PDF = PRES_DIR / "pdf" / "Semester1_Progress_Defense.pdf"
OUT_PPTX = PRES_DIR / "pptx" / "Semester1_Progress_Defense.pptx"

CHROME_PATH = Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")

TOTAL_SLIDES = 11

DIAGRAMS = {
    "flowchart": IMG_DIR / "19_master_system_flowchart.png",
    "c4_l2": IMG_DIR / "05_c4_l2_containers.png",
    "guardrail": IMG_DIR / "16_scope_guardrail_flow.png",
}

ROADMAP_PHASES = [
    ("P0", "DONE", "done", "Repo & Docker", "Clean repo layout, Docker, testbenches & API health"),
    ("P1", "DONE", "done", "SAD & Diagrams", "6 formal SAD chapters, 19 diagrams & 3 print books"),
    ("P2", "DONE", "done", "Core Scanner", "Scope guardrail, HTTP client, BFS crawler & 20 tests"),
    ("P3", "NEXT UP", "next", "17 OWASP Checks", "BaseCheck plugins, 5-stack Fix KB & orchestrator"),
    ("P4", "UPCOMING", "upcoming", "API & Reports", "FastAPI REST/SSE, 3NF DB, triage & JSON/HTML"),
    ("P5", "UPCOMING", "upcoming", "Web Dashboard", "6-view interactive Tailwind UI & Copy Fix Modal"),
    ("P6", "UPCOMING", "upcoming", "Testbench Eval", "VulnBench, DVWA & Juice Shop Precision/Recall/F1"),
    ("P7", "UPCOMING", "upcoming", "Audit & Defense", "Self-security hardening & final thesis defense"),
]

PROBLEM_ITEMS = [
    (
        "Heavy Proxy & Cert Setup",
        "Tools like OWASP ZAP and Burp Suite require browser proxy routing and custom TLS root certificates just to scan a local app.",
    ),
    (
        "Complex Policy Tuning",
        "Beginners face dozens of scan policies and noisy alerts, leading to misconfigured scans or abandoned security checks.",
    ),
    (
        "Raw HTTP & CWE Jargon",
        "Traditional scanners output cryptic CWE IDs and raw HTTP dumps without explaining how to fix the actual source code.",
    ),
    (
        "Late Pre-Release Audits",
        "Because setup is slow, teams postpone testing until right before submission—when code fixes are hardest and riskiest.",
    ),
]

SOLUTION_ITEMS = [
    (
        "One-Command Local Launch",
        "Starts in seconds via docker compose up (or native Python venv) with zero proxy configuration and zero cloud dependencies.",
    ),
    (
        "Curated 17 OWASP Checks",
        "Pre-tuned Quick, Standard, and Deep profiles test high-signal OWASP Top 10 (2021) flaws safely without destructive payloads.",
    ),
    (
        "Exact Endpoint & Parameter Pinpointing",
        "Reports the exact URL, HTTP method, vulnerable form field, and reproducible evidence so developers locate bugs immediately.",
    ),
    (
        "Plain-Language Root Cause & Copy-Ready Fixes",
        "Explains why the flaw is dangerous and provides copy-ready Before/After code patches for FastAPI, Flask, Express, PHP, and HTML.",
    ),
]

PHASE0_CARDS = [
    (
        "A",
        "Clean Repository Layout",
        "Separates backend/scanner/ (pure Python engine with zero web/DB imports) from backend/app/ (FastAPI), frontend/, docs/, testbench/, and scripts/ for clean modularity and isolated unit testing.",
    ),
    (
        "B",
        "Hardened Multi-Stage Docker Setup",
        "Non-root multi-stage Dockerfile and docker-compose.yml run SQLite by default, support optional --profile postgres, and bridge host.docker.internal so containerized scans reach local dev servers.",
    ),
    (
        "C",
        "Reproducible Testbench Stack",
        "Dedicated docker-compose.testbench.yml launches DVWA, OWASP Juice Shop, and our deterministic VulnBench app on isolated localhost ports for repeatable benchmark validation.",
    ),
    (
        "D",
        "FastAPI Bootstrap & Native Python venv",
        "Working /api/health endpoint with security headers middleware (CSP, X-Content-Type-Options, X-Frame-Options) plus full native Python venv execution for machines without Docker.",
    ),
]

SAD_CHAPTERS = [
    ("Ch. 1", "Introduction & Scope", "Problem statement, project objectives, ethical scope boundaries & 7-member team ownership."),
    ("Ch. 2", "Formal SRS", "15 Functional (FR-01..15), 9 Non-Functional (NFR-01..09) & 6 Use Cases (UC-01..06)."),
    ("Ch. 3", "Architecture Views", "C4 L1–L3, DFD L0–L1, UML Use Case, Class, Sequence, State & Master Flowchart."),
    ("Ch. 4", "Data & API Design", "3NF relational schema (scans, findings, endpoints) & REST/SSE endpoint contracts."),
    ("Ch. 5", "Security & ADRs", "STRIDE threat model, NIST SSDF (SP 800-218) alignment & 5 Architecture Decision Records."),
    ("Ch. 6", "Validation Plan", "15 verification test cases (TC-01..15), VulnBench ground truth & Precision/Recall/F1."),
]

SAD_DELIVERABLES = [
    ("SAD_Book.pdf", "84 pp. — Unified Full Graduation Book"),
    ("SAD_Semester1_Book.pdf", "44 pp. / 15 figs — Chapters 1–3"),
    ("SAD_Semester2_Book.pdf", "44 pp. / 4 figs — Chapters 4–6"),
    ("Word (.docx) & HTML", "Editable thesis source + offline web reader"),
    ("19 Crisp Diagrams", "2x DPI PNG, SVG & Mermaid (.mmd) sources"),
]

WORKFLOW_STEPS = [
    ("01", "Target Authorization", "ScopeGuardrail validates localhost/RFC1918/Docker targets and requires explicit ownership consent."),
    ("02", "Reachability & Auth Check", "Verifies target connectivity, establishes Cookie/Bearer/DVWA CSRF sessions, and captures baseline headers."),
    ("03", "Soft-404 & Bounded BFS Crawl", "Fingerprints custom 404 pages and crawls same-origin links, forms, inputs, and inline JS API routes."),
    ("04", "Profile-Driven OWASP Checks", "Runs non-destructive passive, discovery, and safe active probes based on Quick, Standard, or Deep profile."),
    ("05", "SHA-1 Dedup, Scoring & Fixes", "Deduplicates findings by SHA-1 hash, computes weighted 0–100 risk score, and attaches multi-stack code patches."),
    ("06", "Dashboard & Report Export", "Streams live SSE scan progress to the UI and exports offline JSON and styled HTML security reports."),
]

ARCH_LAYERS = [
    ("FastAPI", "Native OpenAPI schema, Pydantic validation, and built-in SSE streaming for live scan progress."),
    ("Requests + BeautifulSoup4", "Predictable HTTP session control and resilient HTML/form parsing without heavy browser overhead."),
    ("SQLAlchemy 2.0", "Zero-config SQLite default with seamless 1-switch portability to PostgreSQL (--profile postgres)."),
    ("HTML5 + Tailwind + Vanilla JS", "Zero-build, fast 6-view web dashboard without Node.js bundler or dependency bloat."),
    ("Docker Compose", "One-command local setup bundling the scanner, optional Postgres, and vulnerable testbenches."),
    ("Pure backend/scanner/ Core", "AST-verified zero web/DB imports keep scanning logic 100% decoupled, portable, and unit-testable."),
]

GUARDRAIL_POINTS = [
    ("Localhost / RFC1918 / Docker Allow-List:", "Permits only local developer hosts and private testbench subnets; blocks all public internet targets."),
    ("Pre-Request DNS Resolution:", "Resolves hostnames before socket connect to block DNS rebinding and cloud metadata IP 169.254.169.254."),
    ("Destructive Path Denylist:", "Automatically skips /logout, /delete, /reset, and state-destroying routes to keep local apps intact."),
]

HTTP_CLIENT_POINTS = [
    ("Flexible Auth & DVWA CSRF Auto-Login:", "Supports Cookie, Bearer token, custom headers, and automatic DVWA CSRF token extraction."),
    ("Rate Limiter, Budget & Cancel:", "Token-bucket throttle (10 req/s), hard 2,000-request cap, and thread-safe cancel_event."),
    ("Manual Redirects & Soft-404 Baseline:", "Enforces allow_redirects=False with per-hop same-origin checks and calibrates Soft-404 fingerprints."),
]

CRAWLER_POINTS = [
    ("normalize_url & Deduplication:", "Canonicalizes paths, strips fragments, and deduplicates query parameter shapes to prevent infinite loops."),
    ("robots.txt, sitemap.xml & BS4 Parsing:", "Extracts links, HTML forms, input fields, and script references cleanly across same-origin pages."),
    ("Inline JS /api/... Route Hints:", "Scans inline script blocks for REST API paths so modern single-page endpoints enter the attack surface."),
    ("Bounded Caps & 200KB ResponseCache:", "Enforces max_depth/max_pages limits, skips binary & destructive paths, and caches pages up to 200KB."),
]

NEXT_PHASES = [
    (
        "Phase 3",
        "IMMEDIATE NEXT",
        True,
        "17 Curated OWASP Checks + Multi-Stack Fix KB + ScanOrchestrator",
        "Implement 8 passive, 5 active safe, 3 discovery, and 1 IDOR check via 1-file BaseCheck registry + 100%-coverage Remediation KB (FastAPI, Flask, Express, PHP, HTML) + SHA-1 scoring & cancellable orchestrator.",
    ),
    (
        "Phase 4",
        "UPCOMING",
        False,
        "FastAPI REST/SSE API, 3NF Persistence & Report Export",
        "Build REST/SSE scan endpoints, SQLAlchemy 3NF storage, finding triage (open/fixed/false_positive/accepted), scan comparison (New/Fixed/Unchanged) & offline JSON/HTML reports.",
    ),
    (
        "Phase 5",
        "UPCOMING",
        False,
        "6-View Interactive Tailwind CSS + JS Developer Dashboard",
        "Deliver zero-build UI with live SSE progress bar, risk score gauges, finding filters, scan diff view, and Copy-Ready Code Fix Modal.",
    ),
    (
        "Phase 6",
        "UPCOMING",
        False,
        "Deterministic VulnBench + DVWA & Juice Shop Evaluation",
        "Build ground-truth VulnBench target and run scripts/evaluate.py across DVWA and OWASP Juice Shop to measure empirical Precision, Recall, and F1.",
    ),
    (
        "Phase 7",
        "UPCOMING",
        False,
        "Self-Security Audit, Hardening & Final Graduation Defense",
        "Audit scanner CSP, safe DOM rendering, non-root Docker security, and rehearse final end-to-end graduation defense demonstration.",
    ),
]

TEAM_ROSTER = [
    ("Ahmed Ashraf Ammar", "235204", "Team Lead — FastAPI Backend & SSE Scan Orchestration"),
    ("Islam Mohammed", "235164", "Core Engine — Scope Guardrail, HTTP Client & BFS Crawler"),
    ("Abdelrhman Mohamed AbdEl-latif", "235216", "Security Checks — Active & Injection OWASP Checks"),
    ("Ahmed Waleed Mokthar", "235052", "Security Checks — Passive & Discovery OWASP Checks"),
    ("Mohamed Waleed Mokthar", "235051", "Data & Reporting — 3NF Database, Scan Diff & JSON/HTML Reports"),
    ("Mohamed Ibrahim Elsayed", "235401", "Frontend UI — 6-View Tailwind Dashboard & Copy-Ready Fix Modal"),
    ("Ali Ibrahim Elsayed", "235332", "DevOps & QA — Docker Stack, VulnBench & Testbench Evaluation"),
]


# =============================================================================
# 1. HTML BUILDER (100% OFFLINE, 16:9 INTERACTIVE + EXACT PRINT-TO-PDF)
# =============================================================================


def load_b64_images() -> dict[str, str]:
    out: dict[str, str] = {}
    for key, path in DIAGRAMS.items():
        if not path.exists():
            raise FileNotFoundError(f"Required diagram missing: {path}")
        out[key] = "data:image/png;base64," + base64.b64encode(path.read_bytes()).decode("ascii")
    return out


def slide_header(title: str, subtitle: str, badge: str) -> str:
    return f"""
    <div class="slide-header">
      <div class="header-accent"></div>
      <div class="header-titles">
        <div class="header-title">{html.escape(title)}</div>
        <div class="header-subtitle">{html.escape(subtitle)}</div>
      </div>
      <div class="header-badge">{html.escape(badge)}</div>
    </div>
    """


def slide_footer(num: int) -> str:
    return f"""
    <div class="slide-footer">
      <span>Lightweight OWASP Top 10 Vulnerability Scanner &mdash; Progress Briefing &amp; Technical Walkthrough (Prepared for Dr. Samar)</span>
      <span class="footer-page">Slide {num:02d} / {TOTAL_SLIDES:02d}</span>
    </div>
    """


def build_html(b64: dict[str, str]) -> str:
    # ---- Slide 1: Title Slide (Dark Navy) ----
    s1 = """
    <section class="slide slide-dark" data-slide="1">
      <div class="cover-bg-grid"></div>
      <div class="cover-accent-bar"></div>
      <div class="cover-content">
        <div>
          <div class="cover-pill">SUPERVISOR PROGRESS BRIEFING &bull; ACADEMIC YEAR 2026&ndash;2027</div>
          <h1 class="cover-title">Developing a Lightweight OWASP<br/>Top 10 Vulnerability Scanner</h1>
          <p class="cover-subtitle">Progress Briefing &amp; Technical Walkthrough &mdash; What We Built, How It Works &amp; Where We Are</p>
        </div>

        <div class="cover-meta-row">
          <div class="cover-meta-card">
            <div class="cm-label">PREPARED FOR</div>
            <div class="cm-val">Dr. Samar</div>
            <div class="cm-sub">Department of Cyber Security</div>
          </div>
          <div class="cover-meta-card">
            <div class="cm-label">ACADEMIC YEAR</div>
            <div class="cm-val">2026&ndash;2027</div>
            <div class="cm-sub">Graduation Project Progress</div>
          </div>
          <div class="cover-meta-card">
            <div class="cm-label">PROJECT TEAM</div>
            <div class="cm-val">7-Member Team</div>
            <div class="cm-sub">Department of Cyber Security</div>
          </div>
        </div>

        <div class="cover-status-bar">
          <span class="cs-pill cs-green">&#10003; Phases 0&ndash;2 Complete</span>
          <span class="cs-pill cs-amber">&#9654; Immediate Next: Phase 3</span>
          <span class="cs-pill cs-teal">20 / 20 Core Unit Tests Passing</span>
        </div>
      </div>
    </section>
    """

    # ---- Slide 2: Where We Are in the Plan (Done vs. Next) ----
    roadmap_cols = []
    for code, badge_txt, state, title, desc in ROADMAP_PHASES:
        pointer = (
            '<div class="rm-pointer">YOU ARE HERE &rarr; P3</div>'
            if state == "next"
            else '<div class="rm-pointer-spacer"></div>'
        )
        icon = "&#10003; " if state == "done" else ("&#9654; " if state == "next" else "")
        roadmap_cols.append(
            f"""
            <div class="rm-col rm-{state}">
              {pointer}
              <div class="rm-node">
                <div class="rm-code">{html.escape(code)}</div>
                <div class="rm-badge rm-badge-{state}">{icon}{html.escape(badge_txt)}</div>
              </div>
              <div class="rm-card">
                <div class="rm-title">{html.escape(title)}</div>
                <div class="rm-desc">{html.escape(desc)}</div>
              </div>
            </div>
            """
        )

    s2 = f"""
    <section class="slide slide-light" data-slide="2">
      {slide_header("Where We Are in the Plan (Done vs. Next)", "Full 8-phase build roadmap — completed Semester 1 foundation and immediate next milestone", "ROADMAP • P2 → P3")}
      <div class="slide-body roadmap-body">
        <div class="milestone-strip">
          <div class="ms-card ms-green">
            <div class="ms-val">100% Complete</div>
            <div class="ms-lbl">Semester 1 Documentation &amp; Core Foundation</div>
          </div>
          <div class="ms-card ms-navy">
            <div class="ms-val">3 of 8 Phases</div>
            <div class="ms-lbl">Full Project Build Complete (P0, P1 &amp; P2)</div>
          </div>
          <div class="ms-card ms-amber">
            <div class="ms-val">Phase 3 NEXT UP</div>
            <div class="ms-lbl">17 OWASP Checks, 5-Stack Fix KB &amp; Orchestrator</div>
          </div>
        </div>

        <div class="rm-track-wrap">
          <div class="rm-line-bg"></div>
          <div class="rm-line-done"></div>
          <div class="rm-grid">
            {''.join(roadmap_cols)}
          </div>
        </div>

        <div class="rm-legend">
          <span><i class="lg-dot lg-green"></i><strong>Phases 0&ndash;2 Done:</strong> Repo, Docker, 6-Ch. SAD, 19 Figs &amp; Core Scanner</span>
          <span><i class="lg-dot lg-amber"></i><strong>Phase 3 Next Up:</strong> 17 OWASP Checks &amp; Multi-Stack Fix KB</span>
          <span><i class="lg-dot lg-slate"></i><strong>Phases 4&ndash;7 Upcoming:</strong> API, Dashboard, Eval &amp; Defense</span>
        </div>
      </div>
      {slide_footer(2)}
    </section>
    """

    # ---- Slide 3: Problem Statement & How Our Solution Solves It ----
    prob_html = "".join(
        f'<li><div class="ps-title">{html.escape(t)}</div><div class="ps-desc">{html.escape(d)}</div></li>'
        for t, d in PROBLEM_ITEMS
    )
    sol_html = "".join(
        f'<li><div class="ps-title">{html.escape(t)}</div><div class="ps-desc">{html.escape(d)}</div></li>'
        for t, d in SOLUTION_ITEMS
    )
    s3 = f"""
    <section class="slide slide-light" data-slide="3">
      {slide_header("Problem Statement & How Our Solution Solves It", "Why student and junior developers skip early security testing — and how our lightweight scanner closes the gap", "MOTIVATION • SCOPE")}
      <div class="slide-body two-col-equal">
        <div class="exec-card card-problem">
          <div class="ec-hdr ec-hdr-navy">
            <span>The Problem: Why Developers Skip Early Testing</span>
            <span class="badge-pill badge-warn">PAIN POINTS</span>
          </div>
          <ul class="ps-list ps-list-prob">
            {prob_html}
          </ul>
        </div>

        <div class="exec-card card-solution">
          <div class="ec-hdr ec-hdr-teal">
            <span>Our Solution: Developer-First Local Scanner</span>
            <span class="badge-pill badge-done">OUR APPROACH</span>
          </div>
          <ul class="ps-list ps-list-sol">
            {sol_html}
          </ul>
        </div>
      </div>
      {slide_footer(3)}
    </section>
    """

    # ---- Slide 4: Phase 0 Explained: Clean Greenfield Foundation & Docker Setup ----
    p0_cards = "".join(
        f"""
        <div class="p0-card">
          <div class="p0-top">
            <span class="p0-letter">{html.escape(letter)}</span>
            <span class="p0-title">{html.escape(title)}</span>
            <span class="badge-pill badge-done">DONE</span>
          </div>
          <p class="p0-desc">{html.escape(desc)}</p>
        </div>
        """
        for letter, title, desc in PHASE0_CARDS
    )
    s4 = f"""
    <section class="slide slide-light" data-slide="4">
      {slide_header("Phase 0 Explained: Clean Greenfield Foundation & Docker Setup", "Modular repository layout, hardened containerization, local testbench stack & FastAPI bootstrap", "PHASE 0 • DONE")}
      <div class="slide-body p0-body">
        <div class="p0-grid">
          {p0_cards}
        </div>
        <div class="p0-strip">
          <span><strong>Key Engineering Outcome:</strong> Zero-friction local onboarding &mdash; runs identically via <code>docker compose up</code> or native Python <code>venv</code> with strict engine isolation.</span>
        </div>
      </div>
      {slide_footer(4)}
    </section>
    """

    # ---- Slide 5: Phase 1 Explained: Formal 6-Chapter SAD & 19 Architecture Diagrams ----
    sad_rows = "".join(
        f"""
        <tr>
          <td class="st-ch">{html.escape(ch)}</td>
          <td class="st-title">{html.escape(title)}</td>
          <td class="st-desc">{html.escape(desc)}</td>
        </tr>
        """
        for ch, title, desc in SAD_CHAPTERS
    )
    deliv_items = "".join(
        f'<li><strong><code>{html.escape(k)}</code></strong><div class="dv-sub">{html.escape(v)}</div></li>'
        for k, v in SAD_DELIVERABLES
    )
    s5 = f"""
    <section class="slide slide-light" data-slide="5">
      {slide_header("Phase 1 Explained: Formal 6-Chapter SAD & 19 Diagrams", "Complete IEEE-aligned Software Architecture Document and print-ready graduation books", "PHASE 1 • DONE")}
      <div class="slide-body sad-split">
        <div class="sad-table-wrap">
          <div class="ec-hdr ec-hdr-navy">
            <span>6 Formal SAD Chapters Breakdown</span>
            <span class="badge-pill badge-done">COMPLETE</span>
          </div>
          <table class="sad-table">
            <thead>
              <tr>
                <th style="width:12%">Ch.</th>
                <th style="width:27%">Chapter Focus</th>
                <th style="width:61%">Key Specifications &amp; Engineering Artifacts</th>
              </tr>
            </thead>
            <tbody>
              {sad_rows}
            </tbody>
          </table>
        </div>

        <div class="exec-card sad-deliv">
          <div class="ec-hdr ec-hdr-teal">
            <span>Ready-to-Submit Deliverables</span>
            <span class="badge-pill badge-done">VERIFIED</span>
          </div>
          <ul class="dv-list">
            {deliv_items}
          </ul>
        </div>
      </div>
      {slide_footer(5)}
    </section>
    """

    # ---- Slide 6: How the Whole System Works (Figure 19 Master Flowchart) ----
    step_cards = "".join(
        f"""
        <div class="step-card6">
          <div class="step-num6">{num}</div>
          <div>
            <div class="step-title6">{html.escape(title)}</div>
            <div class="step-desc6">{html.escape(desc)}</div>
          </div>
        </div>
        """
        for num, title, desc in WORKFLOW_STEPS
    )
    s6 = f"""
    <section class="slide slide-light" data-slide="6">
      {slide_header("How the Whole System Works (Figure 19 Master Flowchart)", "End-to-end safe local scanning pipeline from target authorization to copy-ready code fixes", "WORKFLOW • FIGURE 19")}
      <div class="slide-body split-flow">
        <div class="diagram-frame flow-diagram">
          <img src="{b64['flowchart']}" alt="Figure 19 Master System Flowchart" />
          <div class="diagram-caption">Figure 19: Master System Flowchart</div>
        </div>
        <div class="steps-col6">
          {step_cards}
        </div>
      </div>
      {slide_footer(6)}
    </section>
    """

    # ---- Slide 7: System Architecture & Why We Chose Each Technology (Figure 5) ----
    arch_cards = "".join(
        f"""
        <div class="arch-card">
          <div class="ac-name">{html.escape(name)}</div>
          <div class="ac-why">{html.escape(why)}</div>
        </div>
        """
        for name, why in ARCH_LAYERS
    )
    s7 = f"""
    <section class="slide slide-light" data-slide="7">
      {slide_header("System Architecture & Why We Chose Each Technology", "Modular monolith engineered for zero-config local execution — Figure 5 C4 Level 2 Containers", "ARCHITECTURE • FIGURE 5")}
      <div class="slide-body arch-split">
        <div class="diagram-frame arch-diagram-left">
          <img src="{b64['c4_l2']}" alt="Figure 5 C4 Level 2 Container Diagram" />
          <div class="diagram-caption">Figure 5: C4 Level 2 &mdash; Container Architecture</div>
        </div>
        <div class="arch-why-col">
          <div class="arch-why-hdr">Architectural Justification by Layer</div>
          {arch_cards}
        </div>
      </div>
      {slide_footer(7)}
    </section>
    """

    # ---- Slide 8: Phase 2 Explained (Part 1): Safety Guardrail & Smart HTTP Client ----
    gr_items = "".join(
        f'<li><strong>{html.escape(h)}</strong> {html.escape(b)}</li>'
        for h, b in GUARDRAIL_POINTS
    )
    hc_items = "".join(
        f'<li><strong>{html.escape(h)}</strong> {html.escape(b)}</li>'
        for h, b in HTTP_CLIENT_POINTS
    )
    s8 = f"""
    <section class="slide slide-light" data-slide="8">
      {slide_header("Phase 2 Explained (Part 1): Safety Guardrail & Smart HTTP Client", "Defense-in-depth scope enforcement and resilient local HTTP transport — Figure 16", "PHASE 2 • DONE")}
      <div class="slide-body p2-split">
        <div class="diagram-frame guard-diagram">
          <img src="{b64['guardrail']}" alt="Figure 16 Scope Guardrail Authorization Flow" />
          <div class="diagram-caption">Figure 16: Scope Guardrail Flow</div>
        </div>
        <div class="p2-cards-col">
          <div class="exec-card p2-card">
            <div class="ec-hdr ec-hdr-navy">
              <span><code>policy.py</code> &mdash; ScopeGuardrail</span>
              <span class="badge-pill badge-done">8/8 TESTS</span>
            </div>
            <ul class="compact-bullets">
              {gr_items}
            </ul>
          </div>
          <div class="exec-card p2-card">
            <div class="ec-hdr ec-hdr-teal">
              <span><code>http_client.py</code> &mdash; ScannerHttpClient</span>
              <span class="badge-pill badge-done">7/7 TESTS</span>
            </div>
            <ul class="compact-bullets">
              {hc_items}
            </ul>
          </div>
        </div>
      </div>
      {slide_footer(8)}
    </section>
    """

    # ---- Slide 9: Phase 2 Explained (Part 2): Bounded BFS Crawler & Live Verification Proof ----
    cr_items = "".join(
        f'<li><strong>{html.escape(h)}</strong> {html.escape(b)}</li>'
        for h, b in CRAWLER_POINTS
    )
    s9 = f"""
    <section class="slide slide-light" data-slide="9">
      {slide_header("Phase 2 Explained (Part 2): Bounded BFS Crawler & Live Proof", "Same-origin attack surface discovery verified with automated unit tests", "PHASE 2 • VERIFIED")}
      <div class="slide-body code-split">
        <div class="exec-card">
          <div class="ec-hdr ec-hdr-navy">
            <span><code>crawler.py</code> &mdash; Bounded BFS WebCrawler</span>
            <span class="badge-pill badge-done">5/5 TESTS</span>
          </div>
          <ul class="big-bullets code-bullets">
            {cr_items}
          </ul>
        </div>

        <div class="proof-col">
          <div class="pass-banner">
            <div class="pb-icon">&#10003;</div>
            <div>
              <div class="pb-title">20 / 20 Unit Tests PASSED in 1.186s</div>
              <div class="pb-sub">test_policy.py (8/8) &bull; test_http_client.py (7/7) &bull; test_crawler.py (5/5)</div>
            </div>
          </div>

          <div class="terminal-box">
            <div class="term-bar">
              <span class="dot d-red"></span><span class="dot d-yel"></span><span class="dot d-grn"></span>
              <span class="term-title">powershell &mdash; live verification proof</span>
            </div>
            <pre class="term-pre"><span class="t-cmd">$ py -3.12 -m unittest discover -s tests -v</span>

<span class="t-info">[ScopeGuardrail]</span>  Allowed: <span class="t-ok">127.0.0.1</span>  |  Blocked: <span class="t-err">google.com</span>
<span class="t-info">[ScopeGuardrail]</span>  Blocked: <span class="t-err">169.254.169.254</span> (DNS rebinding guard)
<span class="t-info">[HttpClient]</span>      Soft-404 Baseline: <span class="t-ok">Calibrated</span> | Rate-Limit: 10 req/s
<span class="t-info">[AttackSurface]</span>   Endpoints, HTML Forms &amp; JS /api/ routes discovered

--------------------------------------------------------------
<span class="t-ok">Ran 20 tests in 1.186s  &mdash;  OK (0 failures, 0 errors)</span></pre>
          </div>
        </div>
      </div>
      {slide_footer(9)}
    </section>
    """

    # ---- Slide 10: What Is Next: Detailed Phases 3–7 Implementation Plan ----
    p3 = NEXT_PHASES[0]
    up_cards = "".join(
        f"""
        <div class="next-card">
          <div class="nc-top">
            <span class="nc-phase">{html.escape(ph)}</span>
            <span class="badge-pill badge-up">{html.escape(tag)}</span>
          </div>
          <div class="nc-title">{html.escape(title)}</div>
          <div class="nc-desc">{html.escape(desc)}</div>
        </div>
        """
        for ph, tag, _, title, desc in NEXT_PHASES[1:]
    )
    s10 = f"""
    <section class="slide slide-light" data-slide="10">
      {slide_header("What Is Next: Detailed Phases 3–7 Implementation Plan", "Clear execution roadmap from OWASP vulnerability checks to final graduation defense", "NEXT • PHASE 3 → 7")}
      <div class="slide-body next-body">
        <div class="next-hero">
          <div class="nh-left">
            <div class="nh-top">
              <span class="nh-phase">{html.escape(p3[0])}</span>
              <span class="badge-pill badge-next">&#9654; {html.escape(p3[1])}</span>
            </div>
            <div class="nh-title">{html.escape(p3[3])}</div>
            <div class="nh-desc">{html.escape(p3[4])}</div>
          </div>
          <div class="nh-callout">
            <div class="nhc-big">17 Checks</div>
            <div class="nhc-sub">OWASP Top 10 + 5-Stack Fix KB</div>
          </div>
        </div>

        <div class="next-grid-4">
          {up_cards}
        </div>
      </div>
      {slide_footer(10)}
    </section>
    """

    # ---- Slide 11: 7-Member Team Ownership & Approval for Phase 3 (Closing — Dark Navy) ----
    roster_rows = "".join(
        f"""
        <tr>
          <td class="rt-name">{html.escape(name)}</td>
          <td class="rt-id">{html.escape(sid)}</td>
          <td class="rt-mod">{html.escape(mod)}</td>
        </tr>
        """
        for name, sid, mod in TEAM_ROSTER
    )
    s11 = f"""
    <section class="slide slide-dark" data-slide="11">
      <div class="cover-bg-grid"></div>
      <div class="cover-accent-bar"></div>
      <div class="closing-content">
        <div class="closing-header">
          <div>
            <div class="cover-pill">7-MEMBER TEAM &amp; PHASE 3 APPROVAL</div>
            <h1 class="closing-title">Team Ownership &amp; Approval for Phase 3</h1>
          </div>
          <div class="repo-chip">
            <div class="rc-lbl">GITHUB REPOSITORY</div>
            <div class="rc-url">https://github.com/mohammewaleed/Graduation-Project-2027</div>
          </div>
        </div>

        <table class="roster-table">
          <thead>
            <tr>
              <th style="width:30%">Team Member</th>
              <th style="width:13%">Student ID</th>
              <th style="width:57%">Role &amp; Module Owned</th>
            </tr>
          </thead>
          <tbody>
            {roster_rows}
          </tbody>
        </table>

        <div class="approval-banner">
          <div>
            <div class="ab-title">Phases 0&ndash;2 Verified Complete &mdash; Ready for Dr. Samar&rsquo;s Approval to Launch Phase 3</div>
            <div class="ab-sub">Department of Cyber Security &bull; Academic Year 2026&ndash;2027 &bull; 3 of 8 Phases Complete &rarr; Next: Phase 3</div>
          </div>
          <div class="qa-badge">Q &amp; A</div>
        </div>
      </div>
    </section>
    """

    slides_html = "\n".join([s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Supervisor Progress Briefing — Lightweight OWASP Top 10 Vulnerability Scanner</title>
<style>
  :root {{
    --navy: #0F172A;
    --navy-mid: #1E293B;
    --teal: #0D9488;
    --teal-bright: #14B8A6;
    --teal-light: #5EEAD4;
    --green: #16A34A;
    --green-dark: #15803D;
    --green-soft: #F0FDF4;
    --amber: #D97706;
    --amber-bright: #F59E0B;
    --amber-soft: #FFFBEB;
    --red: #DC2626;
    --slate: #334155;
    --slate-muted: #64748B;
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

  body.overview {{
    overflow-y: auto;
    padding: 36px 24px 80px;
  }}
  body.overview .deck-stage {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
    gap: 24px;
    width: 100%;
    height: auto;
    max-width: 1400px;
    margin: 0 auto;
  }}
  body.overview .slide {{
    display: flex !important;
    transform: none !important;
    width: 100% !important;
    height: auto !important;
    aspect-ratio: 16 / 9;
    cursor: pointer;
    border: 2px solid rgba(255, 255, 255, 0.14);
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

  /* Cover & Closing shared dark background */
  .cover-bg-grid {{
    position: absolute;
    inset: 0;
    background-image:
      linear-gradient(rgba(20, 184, 166, 0.06) 1px, transparent 1px),
      linear-gradient(90deg, rgba(20, 184, 166, 0.06) 1px, transparent 1px);
    background-size: 48px 48px;
    pointer-events: none;
  }}
  .cover-accent-bar {{
    position: absolute;
    left: 0;
    top: 0;
    bottom: 0;
    width: 12px;
    background: linear-gradient(180deg, #14B8A6 0%, #0D9488 100%);
  }}

  /* Slide 1: Title Slide */
  .cover-content {{
    position: relative;
    z-index: 2;
    padding: 54px 72px 48px 84px;
    height: 100%;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
  }}
  .cover-pill {{
    display: inline-block;
    background: rgba(20, 184, 166, 0.16);
    border: 1px solid rgba(20, 184, 166, 0.5);
    color: #5EEAD4;
    font-size: 13px;
    font-weight: 800;
    letter-spacing: 1.5px;
    padding: 7px 16px;
    border-radius: 999px;
  }}
  .cover-title {{
    font-size: 52px;
    font-weight: 800;
    line-height: 1.12;
    letter-spacing: -1px;
    margin-top: 20px;
    color: #FFFFFF;
  }}
  .cover-subtitle {{
    font-size: 21px;
    color: #5EEAD4;
    font-weight: 600;
    margin-top: 14px;
  }}
  .cover-meta-row {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 22px;
  }}
  .cover-meta-card {{
    background: rgba(30, 41, 59, 0.85);
    border: 1px solid rgba(148, 163, 184, 0.25);
    border-top: 4px solid #14B8A6;
    border-radius: 10px;
    padding: 20px 24px;
  }}
  .cm-label {{ font-size: 12px; font-weight: 800; letter-spacing: 1.2px; color: #5EEAD4; }}
  .cm-val {{ font-size: 26px; font-weight: 800; color: #FFFFFF; margin-top: 6px; }}
  .cm-sub {{ font-size: 14px; color: #CBD5E1; margin-top: 4px; }}
  .cover-status-bar {{
    display: flex;
    gap: 16px;
    align-items: center;
  }}
  .cs-pill {{
    padding: 10px 20px;
    border-radius: 999px;
    font-size: 14.5px;
    font-weight: 700;
  }}
  .cs-green {{ background: rgba(22, 163, 74, 0.22); border: 1px solid #22C55E; color: #86EFAC; }}
  .cs-amber {{ background: rgba(217, 119, 6, 0.25); border: 1px solid #F59E0B; color: #FCD34D; }}
  .cs-teal {{ background: rgba(20, 184, 166, 0.2); border: 1px solid #14B8A6; color: #5EEAD4; }}

  /* Content Slide Header & Footer */
  .slide-header {{
    height: 80px;
    background: var(--navy);
    display: flex;
    align-items: center;
    padding: 0 34px 0 0;
    flex-shrink: 0;
  }}
  .header-accent {{ width: 10px; height: 100%; background: var(--teal-bright); flex-shrink: 0; }}
  .header-titles {{ padding-left: 24px; flex: 1; }}
  .header-title {{ font-size: 24px; font-weight: 800; color: #FFFFFF; letter-spacing: -0.3px; }}
  .header-subtitle {{ font-size: 13.5px; color: #94A3B8; margin-top: 3px; }}
  .header-badge {{
    background: var(--navy-mid);
    border: 1.5px solid var(--teal-bright);
    color: var(--teal-light);
    font-size: 12px;
    font-weight: 800;
    letter-spacing: 0.9px;
    padding: 7px 15px;
    border-radius: 999px;
    white-space: nowrap;
  }}

  .slide-body {{
    flex: 1;
    padding: 22px 34px 18px;
    display: flex;
    flex-direction: column;
    gap: 18px;
    min-height: 0;
  }}

  .slide-footer {{
    height: 32px;
    background: var(--bg-light);
    border-top: 1px solid #E2E8F0;
    padding: 0 34px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: 11.5px;
    color: var(--slate-muted);
    flex-shrink: 0;
  }}
  .footer-page {{ font-weight: 800; color: var(--navy); }}

  /* Shared Status Badges */
  .badge-pill {{
    display: inline-block;
    padding: 4px 11px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 800;
    letter-spacing: 0.6px;
    white-space: nowrap;
  }}
  .badge-done {{ background: var(--green); color: #FFFFFF; }}
  .badge-next {{ background: var(--amber); color: #FFFFFF; }}
  .badge-up {{ background: var(--slate-muted); color: #FFFFFF; }}
  .badge-warn {{ background: var(--red); color: #FFFFFF; }}

  /* Slide 2: Big Visual Roadmap */
  .roadmap-body {{ justify-content: space-between; gap: 18px; }}
  .milestone-strip {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 18px;
  }}
  .ms-card {{
    border-radius: 10px;
    padding: 16px 20px;
    border: 1.5px solid var(--border);
    border-left-width: 6px;
  }}
  .ms-green {{ background: var(--green-soft); border-color: #BBF7D0; border-left-color: var(--green); }}
  .ms-navy {{ background: #F0FDFA; border-color: #99F6E4; border-left-color: var(--teal); }}
  .ms-amber {{ background: var(--amber-soft); border-color: #FDE68A; border-left-color: var(--amber); }}
  .ms-val {{ font-size: 26px; font-weight: 900; color: var(--navy); line-height: 1.1; }}
  .ms-green .ms-val {{ color: var(--green-dark); }}
  .ms-amber .ms-val {{ color: #B45309; }}
  .ms-lbl {{ font-size: 14px; font-weight: 700; color: var(--slate); margin-top: 5px; }}

  .rm-track-wrap {{
    position: relative;
    display: flex;
    flex-direction: column;
  }}
  .rm-line-bg {{
    position: absolute;
    top: 88px;
    left: 48px;
    right: 48px;
    height: 8px;
    background: #E2E8F0;
    border-radius: 999px;
    z-index: 1;
  }}
  .rm-line-done {{
    position: absolute;
    top: 88px;
    left: 48px;
    width: 40%;
    height: 8px;
    background: linear-gradient(90deg, #16A34A 0%, #16A34A 78%, #D97706 100%);
    border-radius: 999px;
    z-index: 2;
  }}
  .rm-grid {{
    display: grid;
    grid-template-columns: repeat(8, 1fr);
    gap: 10px;
    position: relative;
    z-index: 3;
  }}
  .rm-col {{
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 11px;
  }}
  .rm-pointer-spacer {{ height: 32px; }}
  .rm-pointer {{
    height: 32px;
    background: var(--amber);
    color: #FFFFFF;
    font-size: 10px;
    font-weight: 900;
    padding: 0 8px;
    border-radius: 6px;
    display: flex;
    align-items: center;
    justify-content: center;
    text-align: center;
    white-space: nowrap;
    box-shadow: 0 4px 12px rgba(217, 119, 6, 0.35);
  }}
  .rm-node {{
    width: 100%;
    border-radius: 10px;
    padding: 11px 6px;
    text-align: center;
    border: 2px solid var(--border);
    background: #FFFFFF;
  }}
  .rm-done .rm-node {{ background: var(--green-soft); border-color: var(--green); }}
  .rm-next .rm-node {{ background: var(--amber-soft); border-color: var(--amber); border-width: 3px; box-shadow: 0 6px 18px rgba(217, 119, 6, 0.22); }}
  .rm-upcoming .rm-node {{ background: #F8FAFC; border-color: #CBD5E1; }}
  .rm-code {{ font-size: 22px; font-weight: 900; color: var(--navy); line-height: 1; }}
  .rm-done .rm-code {{ color: var(--green-dark); }}
  .rm-next .rm-code {{ color: #B45309; }}
  .rm-upcoming .rm-code {{ color: var(--slate-muted); }}
  .rm-badge {{
    display: inline-block;
    margin-top: 6px;
    padding: 3px 7px;
    border-radius: 999px;
    font-size: 9.5px;
    font-weight: 800;
    letter-spacing: 0.4px;
    white-space: nowrap;
  }}
  .rm-badge-done {{ background: var(--green); color: #FFFFFF; }}
  .rm-badge-next {{ background: var(--amber); color: #FFFFFF; }}
  .rm-badge-upcoming {{ background: #94A3B8; color: #FFFFFF; }}

  .rm-card {{
    width: 100%;
    min-height: 162px;
    border-radius: 10px;
    padding: 15px 9px;
    text-align: center;
    border: 1.5px solid #E2E8F0;
    background: #F8FAFC;
    display: flex;
    flex-direction: column;
    justify-content: center;
    gap: 8px;
  }}
  .rm-done .rm-card {{ background: #FFFFFF; border-color: #BBF7D0; border-top: 4px solid var(--green); }}
  .rm-next .rm-card {{ background: var(--amber-soft); border-color: var(--amber); border-top: 5px solid var(--amber); }}
  .rm-title {{ font-size: 13.5px; font-weight: 800; color: var(--navy); line-height: 1.2; }}
  .rm-desc {{ font-size: 12px; color: var(--slate); line-height: 1.38; }}
  .rm-legend {{
    background: #F8FAFC;
    border: 1.5px solid #E2E8F0;
    border-radius: 10px;
    padding: 12px 20px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-size: 13px;
    color: var(--slate);
  }}
  .lg-dot {{
    display: inline-block;
    width: 11px;
    height: 11px;
    border-radius: 50%;
    margin-right: 7px;
    vertical-align: -1px;
  }}
  .lg-green {{ background: var(--green); }}
  .lg-amber {{ background: var(--amber); }}
  .lg-slate {{ background: #94A3B8; }}

  /* Shared Cards */
  .exec-card {{
    background: #F8FAFC;
    border: 1.5px solid #E2E8F0;
    border-radius: 10px;
    overflow: hidden;
    display: flex;
    flex-direction: column;
  }}
  .ec-hdr {{
    padding: 12px 18px;
    color: #FFFFFF;
    font-size: 16px;
    font-weight: 800;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
  }}
  .ec-hdr code {{
    background: rgba(255, 255, 255, 0.16);
    color: #5EEAD4;
    padding: 2px 7px;
    border-radius: 4px;
    font-family: 'Consolas', monospace;
    font-size: 14.5px;
  }}
  .ec-hdr-navy {{ background: var(--navy); }}
  .ec-hdr-teal {{ background: var(--teal); }}

  /* Slide 3: Problem vs Solution */
  .two-col-equal {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 24px;
  }}
  .ps-list {{
    list-style: none;
    padding: 18px 22px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    flex: 1;
    gap: 14px;
  }}
  .ps-list li {{
    background: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-left: 5px solid var(--teal);
    border-radius: 8px;
    padding: 13px 16px;
  }}
  .ps-list-prob li {{ border-left-color: var(--red); }}
  .ps-list-sol li {{ border-left-color: var(--teal); }}
  .ps-title {{ font-size: 15.5px; font-weight: 800; color: var(--navy); }}
  .ps-desc {{ font-size: 13.5px; color: var(--slate); margin-top: 4px; line-height: 1.42; }}

  /* Slide 4: Phase 0 Grid */
  .p0-body {{ justify-content: space-between; gap: 16px; }}
  .p0-grid {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    grid-template-rows: 1fr 1fr;
    gap: 18px;
    flex: 1;
  }}
  .p0-card {{
    background: #F8FAFC;
    border: 1.5px solid #E2E8F0;
    border-top: 5px solid var(--teal);
    border-radius: 10px;
    padding: 20px 22px;
    display: flex;
    flex-direction: column;
    gap: 12px;
    justify-content: center;
  }}
  .p0-top {{
    display: flex;
    align-items: center;
    gap: 12px;
  }}
  .p0-letter {{
    width: 34px;
    height: 34px;
    border-radius: 8px;
    background: var(--navy);
    color: #5EEAD4;
    font-weight: 900;
    font-size: 16px;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }}
  .p0-title {{ font-size: 17.5px; font-weight: 800; color: var(--navy); flex: 1; }}
  .p0-desc {{ font-size: 14.5px; color: var(--slate); line-height: 1.5; }}
  .p0-strip {{
    background: #F0FDFA;
    border: 1.5px solid #99F6E4;
    border-left: 6px solid var(--teal);
    border-radius: 8px;
    padding: 13px 20px;
    font-size: 14px;
    color: var(--navy);
  }}
  .p0-strip code {{
    background: #CCFBF1;
    color: var(--navy);
    padding: 2px 6px;
    border-radius: 4px;
    font-family: 'Consolas', monospace;
    font-size: 13px;
  }}

  /* Slide 5: Phase 1 SAD Table + Deliverables */
  .sad-split {{
    display: grid;
    grid-template-columns: 1.82fr 1fr;
    gap: 20px;
  }}
  .sad-table-wrap {{
    background: #FFFFFF;
    border: 1.5px solid #E2E8F0;
    border-radius: 10px;
    overflow: hidden;
    display: flex;
    flex-direction: column;
  }}
  .sad-table {{
    width: 100%;
    border-collapse: collapse;
    flex: 1;
  }}
  .sad-table th {{
    background: #F1F5F9;
    color: var(--navy);
    text-align: left;
    padding: 10px 14px;
    font-size: 12.5px;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 1.5px solid #CBD5E1;
  }}
  .sad-table td {{
    padding: 10px 14px;
    font-size: 13.5px;
    line-height: 1.38;
    border-bottom: 1px solid #E2E8F0;
    color: var(--slate);
    vertical-align: middle;
  }}
  .sad-table tr:nth-child(even) td {{ background: #F8FAFC; }}
  .sad-table tr:last-child td {{ border-bottom: none; }}
  .st-ch {{ font-weight: 900; color: var(--teal); font-family: 'Consolas', monospace; }}
  .st-title {{ font-weight: 800; color: var(--navy); }}
  .dv-list {{
    list-style: none;
    padding: 16px 18px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    flex: 1;
    gap: 10px;
  }}
  .dv-list li {{
    background: #FFFFFF;
    border: 1px solid #E2E8F0;
    border-left: 4px solid var(--teal);
    border-radius: 8px;
    padding: 10px 13px;
  }}
  .dv-list code {{
    color: var(--navy);
    font-family: 'Consolas', monospace;
    font-size: 13.5px;
  }}
  .dv-sub {{ font-size: 12.5px; color: var(--slate); margin-top: 3px; }}

  /* Shared Diagram Frame */
  .diagram-frame {{
    background: #FFFFFF;
    border: 1.5px solid var(--border);
    border-radius: 10px;
    padding: 10px;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    overflow: hidden;
  }}
  .diagram-frame img {{
    max-width: 100%;
    max-height: calc(100% - 24px);
    object-fit: contain;
    display: block;
  }}
  .diagram-caption {{
    font-size: 12.5px;
    font-weight: 700;
    color: var(--slate-muted);
    margin-top: 5px;
  }}

  /* Slide 6: Master Flowchart + 6 Steps */
  .split-flow {{
    flex-direction: row !important;
    gap: 24px;
  }}
  .flow-diagram {{
    width: 445px;
    height: 100%;
    flex-shrink: 0;
  }}
  .steps-col6 {{
    flex: 1;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    gap: 10px;
  }}
  .step-card6 {{
    background: #F8FAFC;
    border: 1.5px solid #E2E8F0;
    border-left: 5px solid var(--teal);
    border-radius: 9px;
    padding: 11px 16px;
    display: flex;
    align-items: center;
    gap: 14px;
    flex: 1;
  }}
  .step-num6 {{
    width: 40px;
    height: 40px;
    border-radius: 8px;
    background: var(--navy);
    color: #5EEAD4;
    font-family: 'Consolas', monospace;
    font-size: 16px;
    font-weight: 900;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }}
  .step-title6 {{ font-size: 15.5px; font-weight: 800; color: var(--navy); }}
  .step-desc6 {{ font-size: 13px; color: var(--slate); margin-top: 2px; line-height: 1.35; }}

  /* Slide 7: Architecture (Figure 5) + 6 Layer Justifications */
  .arch-split {{
    display: grid;
    grid-template-columns: 1.48fr 1fr;
    gap: 20px;
    min-height: 0;
  }}
  .arch-diagram-left {{
    height: 100%;
    min-height: 0;
  }}
  .arch-why-col {{
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    gap: 8px;
  }}
  .arch-why-hdr {{
    background: var(--navy);
    color: #FFFFFF;
    font-size: 14.5px;
    font-weight: 800;
    padding: 9px 14px;
    border-radius: 8px;
    border-left: 5px solid var(--teal-bright);
  }}
  .arch-card {{
    background: #F8FAFC;
    border: 1px solid #E2E8F0;
    border-left: 4px solid var(--teal);
    border-radius: 8px;
    padding: 8px 13px;
    flex: 1;
    display: flex;
    flex-direction: column;
    justify-content: center;
  }}
  .ac-name {{ font-size: 13.5px; font-weight: 800; color: var(--navy); }}
  .ac-why {{ font-size: 12px; color: var(--slate); margin-top: 2px; line-height: 1.34; }}

  /* Slide 8: Phase 2 Part 1 (Figure 16 + Guardrail & HTTP Client) */
  .p2-split {{
    display: grid;
    grid-template-columns: 0.92fr 1.28fr;
    gap: 22px;
    min-height: 0;
  }}
  .guard-diagram {{
    height: 100%;
    min-height: 0;
  }}
  .p2-cards-col {{
    display: flex;
    flex-direction: column;
    gap: 16px;
    min-height: 0;
  }}
  .p2-card {{ flex: 1; }}
  .compact-bullets {{
    list-style: none;
    padding: 14px 18px;
    display: flex;
    flex-direction: column;
    justify-content: space-around;
    flex: 1;
    gap: 10px;
  }}
  .compact-bullets li {{
    font-size: 13.8px;
    line-height: 1.42;
    color: var(--slate);
    padding-left: 18px;
    position: relative;
  }}
  .compact-bullets li::before {{
    content: "•";
    position: absolute;
    left: 0;
    color: var(--teal);
    font-size: 18px;
    line-height: 1.05;
    font-weight: 900;
  }}

  /* Slide 9: Crawler + Live Terminal Proof */
  .code-split {{
    display: grid;
    grid-template-columns: 1.02fr 0.98fr;
    gap: 22px;
  }}
  .big-bullets {{
    list-style: none;
    padding: 18px 22px;
    display: flex;
    flex-direction: column;
    justify-content: space-around;
    flex: 1;
    gap: 12px;
  }}
  .big-bullets li {{
    font-size: 14.5px;
    line-height: 1.44;
    color: var(--slate);
    padding-left: 18px;
    position: relative;
  }}
  .big-bullets li::before {{
    content: "•";
    position: absolute;
    left: 0;
    color: var(--teal);
    font-size: 19px;
    line-height: 1.05;
    font-weight: 900;
  }}
  .proof-col {{
    display: flex;
    flex-direction: column;
    gap: 16px;
  }}
  .pass-banner {{
    background: var(--green-soft);
    border: 2px solid var(--green);
    border-radius: 10px;
    padding: 16px 20px;
    display: flex;
    align-items: center;
    gap: 15px;
  }}
  .pb-icon {{
    width: 46px;
    height: 46px;
    border-radius: 50%;
    background: var(--green);
    color: #FFFFFF;
    font-size: 24px;
    font-weight: 900;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }}
  .pb-title {{ font-size: 20px; font-weight: 900; color: var(--green-dark); }}
  .pb-sub {{ font-size: 12.8px; color: var(--slate); font-weight: 700; margin-top: 3px; font-family: 'Consolas', monospace; }}

  .terminal-box {{
    background: var(--navy);
    border-radius: 10px;
    border: 1.5px solid #334155;
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }}
  .term-bar {{
    background: var(--navy-mid);
    padding: 9px 15px;
    display: flex;
    align-items: center;
    gap: 8px;
    border-bottom: 1px solid #334155;
  }}
  .dot {{ width: 11px; height: 11px; border-radius: 50%; display: inline-block; }}
  .d-red {{ background: #EF4444; }}
  .d-yel {{ background: #F59E0B; }}
  .d-grn {{ background: #22C55E; }}
  .term-title {{ margin-left: 8px; font-family: 'Consolas', monospace; font-size: 12.5px; color: #94A3B8; }}
  .term-pre {{
    padding: 18px 20px;
    font-family: 'Consolas', 'Cascadia Code', monospace;
    font-size: 13.2px;
    line-height: 1.72;
    color: #E2E8F0;
    white-space: pre-wrap;
    flex: 1;
  }}
  .t-cmd {{ color: #38BDF8; font-weight: 700; }}
  .t-ok {{ color: #4ADE80; font-weight: 700; }}
  .t-err {{ color: #FCA5A5; font-weight: 700; }}
  .t-info {{ color: #5EEAD4; font-weight: 700; }}

  /* Slide 10: What Is Next (Phase 3 Hero + 4 Cards) */
  .next-body {{ gap: 18px; }}
  .next-hero {{
    background: var(--amber-soft);
    border: 2.5px solid var(--amber);
    border-left: 8px solid var(--amber);
    border-radius: 12px;
    padding: 18px 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 22px;
  }}
  .nh-left {{ flex: 1; }}
  .nh-top {{ display: flex; align-items: center; gap: 12px; }}
  .nh-phase {{ font-size: 15px; font-weight: 900; color: #B45309; letter-spacing: 0.6px; text-transform: uppercase; }}
  .nh-title {{ font-size: 21px; font-weight: 900; color: var(--navy); margin-top: 6px; }}
  .nh-desc {{ font-size: 14px; color: var(--slate); margin-top: 5px; line-height: 1.42; }}
  .nh-callout {{
    background: var(--amber);
    color: #FFFFFF;
    border-radius: 10px;
    padding: 16px 22px;
    text-align: center;
    min-width: 210px;
    flex-shrink: 0;
  }}
  .nhc-big {{ font-size: 27px; font-weight: 900; }}
  .nhc-sub {{ font-size: 12.5px; font-weight: 700; margin-top: 4px; opacity: 0.95; }}

  .next-grid-4 {{
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
    flex: 1;
  }}
  .next-card {{
    background: #F8FAFC;
    border: 1.5px solid #E2E8F0;
    border-top: 4px solid var(--slate-muted);
    border-radius: 10px;
    padding: 16px 20px;
    display: flex;
    flex-direction: column;
    justify-content: center;
  }}
  .nc-top {{ display: flex; align-items: center; justify-content: space-between; }}
  .nc-phase {{ font-size: 13.5px; font-weight: 900; color: var(--teal); letter-spacing: 0.6px; text-transform: uppercase; }}
  .nc-title {{ font-size: 16.5px; font-weight: 800; color: var(--navy); margin-top: 6px; line-height: 1.25; }}
  .nc-desc {{ font-size: 13.5px; color: var(--slate); margin-top: 5px; line-height: 1.4; }}

  /* Slide 11: Closing Team & Approval */
  .closing-content {{
    position: relative;
    z-index: 2;
    padding: 34px 54px 32px 64px;
    height: 100%;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    gap: 15px;
  }}
  .closing-header {{
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    gap: 20px;
  }}
  .closing-title {{ font-size: 34px; font-weight: 800; color: #FFFFFF; margin-top: 9px; letter-spacing: -0.5px; }}
  .repo-chip {{
    background: rgba(30, 41, 59, 0.9);
    border: 1px solid rgba(20, 184, 166, 0.45);
    border-radius: 8px;
    padding: 10px 15px;
    text-align: right;
  }}
  .rc-lbl {{ font-size: 10.5px; font-weight: 800; letter-spacing: 1px; color: #5EEAD4; }}
  .rc-url {{ font-family: 'Consolas', monospace; font-size: 12.5px; color: #FFFFFF; margin-top: 3px; }}

  .roster-table {{
    width: 100%;
    border-collapse: collapse;
    background: rgba(30, 41, 59, 0.85);
    border: 1px solid rgba(148, 163, 184, 0.25);
    border-radius: 10px;
    overflow: hidden;
  }}
  .roster-table th {{
    background: rgba(20, 184, 166, 0.2);
    color: #5EEAD4;
    text-align: left;
    padding: 10px 16px;
    font-size: 13px;
    font-weight: 800;
    letter-spacing: 0.6px;
    text-transform: uppercase;
    border-bottom: 1px solid rgba(20, 184, 166, 0.35);
  }}
  .roster-table td {{
    padding: 9.5px 16px;
    font-size: 14px;
    border-bottom: 1px solid rgba(148, 163, 184, 0.16);
    color: #E2E8F0;
  }}
  .roster-table tr:last-child td {{ border-bottom: none; }}
  .rt-name {{ font-weight: 700; color: #FFFFFF; }}
  .rt-id {{ font-family: 'Consolas', monospace; color: #5EEAD4; font-weight: 700; }}
  .rt-mod {{ color: #CBD5E1; }}

  .approval-banner {{
    background: rgba(20, 184, 166, 0.16);
    border: 1.5px solid #14B8A6;
    border-radius: 10px;
    padding: 15px 22px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 18px;
  }}
  .ab-title {{ font-size: 20px; font-weight: 800; color: #FFFFFF; }}
  .ab-sub {{ font-size: 13px; color: #CBD5E1; margin-top: 4px; }}
  .qa-badge {{
    background: #14B8A6;
    color: #0F172A;
    font-size: 19px;
    font-weight: 900;
    padding: 10px 22px;
    border-radius: 8px;
    letter-spacing: 1px;
    white-space: nowrap;
  }}

  /* Floating Interactive HUD */
  .hud {{
    position: fixed;
    bottom: 16px;
    left: 50%;
    transform: translateX(-50%);
    background: rgba(15, 23, 42, 0.92);
    border: 1px solid rgba(148, 163, 184, 0.3);
    border-radius: 999px;
    padding: 6px 14px;
    display: flex;
    align-items: center;
    gap: 10px;
    z-index: 100;
    color: #F8FAFC;
    font-size: 12.5px;
    backdrop-filter: blur(8px);
  }}
  .hud button {{
    background: rgba(255, 255, 255, 0.1);
    border: none;
    color: #F8FAFC;
    padding: 5px 11px;
    border-radius: 999px;
    cursor: pointer;
    font-size: 12px;
    font-weight: 600;
  }}
  .hud button:hover {{ background: #0D9488; }}
  .hud-counter {{ font-family: 'Consolas', monospace; font-weight: 700; color: #5EEAD4; min-width: 58px; text-align: center; }}

  /* Print / Headless Chrome PDF rules (exact 16:9 widescreen, 11 pages = 960 x 540 pt) */
  @page {{
    size: 13.333in 7.5in;
    margin: 0;
  }}
  @media print {{
    html, body {{
      width: 13.333in;
      background: #FFFFFF !important;
      margin: 0;
      padding: 0;
    }}
    .hud {{ display: none !important; }}
    .deck-stage {{
      display: block !important;
      width: 13.333in !important;
      height: auto !important;
      overflow: visible !important;
    }}
    .slide {{
      display: flex !important;
      width: 1280px !important;
      height: 720px !important;
      transform: none !important;
      box-shadow: none !important;
      page-break-after: always;
      break-after: page;
    }}
    .slide:last-child {{
      page-break-after: auto;
      break-after: auto;
    }}
  }}
</style>
</head>
<body>
  <main class="deck-stage" id="stage">
    {slides_html}
  </main>

  <nav class="hud" aria-label="Slide controls">
    <button id="btnPrev" title="Previous (Left Arrow)">&larr; Prev</button>
    <span class="hud-counter" id="counter">01 / {TOTAL_SLIDES:02d}</span>
    <button id="btnNext" title="Next (Right Arrow)">Next &rarr;</button>
    <button id="btnGrid" title="Overview (G)">Grid</button>
    <button id="btnFs" title="Fullscreen (F)">Fullscreen</button>
  </nav>

  <script>
    (function() {{
      const slides = Array.from(document.querySelectorAll('.slide'));
      const counter = document.getElementById('counter');
      let idx = 0;

      function fitSlide() {{
        if (document.body.classList.contains('overview')) return;
        const scale = Math.min(window.innerWidth / 1280, window.innerHeight / 720) * 0.96;
        slides.forEach(s => {{ s.style.transform = 'scale(' + scale.toFixed(4) + ')'; }});
      }}

      function show(n) {{
        idx = Math.max(0, Math.min(slides.length - 1, n));
        slides.forEach((s, i) => s.classList.toggle('active', i === idx));
        counter.textContent = String(idx + 1).padStart(2, '0') + ' / ' + String(slides.length).padStart(2, '0');
        fitSlide();
      }}

      document.getElementById('btnPrev').onclick = () => show(idx - 1);
      document.getElementById('btnNext').onclick = () => show(idx + 1);
      document.getElementById('btnGrid').onclick = () => {{
        document.body.classList.toggle('overview');
        if (!document.body.classList.contains('overview')) fitSlide();
      }};
      document.getElementById('btnFs').onclick = () => {{
        if (!document.fullscreenElement) document.documentElement.requestFullscreen();
        else document.exitFullscreen();
      }};
      slides.forEach((s, i) => s.addEventListener('click', () => {{
        if (document.body.classList.contains('overview')) {{
          document.body.classList.remove('overview');
          show(i);
        }}
      }}));

      window.addEventListener('keydown', (e) => {{
        if (e.key === 'ArrowRight' || e.key === ' ' || e.key === 'PageDown') {{ e.preventDefault(); show(idx + 1); }}
        else if (e.key === 'ArrowLeft' || e.key === 'PageUp') {{ e.preventDefault(); show(idx - 1); }}
        else if (e.key === 'Home') show(0);
        else if (e.key === 'End') show(slides.length - 1);
        else if (e.key.toLowerCase() === 'g') document.getElementById('btnGrid').click();
        else if (e.key.toLowerCase() === 'f') document.getElementById('btnFs').click();
      }});
      window.addEventListener('resize', fitSlide);
      show(0);
    }})();
  </script>
</body>
</html>
"""


# =============================================================================
# 2. PDF BUILDER (HEADLESS CHROME, 100% OFFLINE)
# =============================================================================


def build_pdf(html_path: Path, pdf_path: Path) -> None:
    if not CHROME_PATH.exists():
        raise FileNotFoundError(f"Headless Chrome not found at {CHROME_PATH}")
    uri = html_path.resolve().as_uri()
    tmp_dir = Path(tempfile.mkdtemp(prefix="pres_pdf_"))
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
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
        if res.returncode != 0 or not pdf_path.exists():
            raise RuntimeError(f"Chrome PDF export failed (rc={res.returncode}): {res.stderr[:500]}")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# =============================================================================
# 3. OOXML PPTX BUILDER (PURE PYTHON STDLIB zipfile + XML + PIL)
# =============================================================================

SLIDE_W = 12192000  # 13.3333 in
SLIDE_H = 6858000  # 7.5 in

NAVY = "0F172A"
NAVY_MID = "1E293B"
TEAL = "0D9488"
TEAL_BRIGHT = "14B8A6"
TEAL_LIGHT = "5EEAD4"
TEAL_SOFT = "F0FDFA"
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
AMBER_LIGHT = "FCD34D"
RED = "DC2626"


def px(val: float) -> int:
    """Convert 1280x720 design pixels to OOXML EMUs (96 dpi -> 1 px = 9525 EMU)."""
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
  <p:nvSpPr>
    <p:cNvPr id="{sid}" name="{esc(name)}"/>
    <p:cNvSpPr/>
    <p:nvPr/>
  </p:nvSpPr>
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
        pad_lr: int = 91440,
        pad_tb: int = 45720,
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
            spc_after = int(round(p.get("space_after", 4) * 100))
            bullet = p.get("bullet", False)
            if bullet:
                ppr = f'<a:pPr algn="{algn}" marL="200000" indent="-150000"><a:spcAft><a:spcPts val="{spc_after}"/></a:spcAft><a:buChar char="&#x2022;"/></a:pPr>'
            else:
                ppr = f'<a:pPr algn="{algn}"><a:spcAft><a:spcPts val="{spc_after}"/></a:spcAft><a:buNone/></a:pPr>'

            runs = p.get("runs")
            if runs is None:
                runs = [
                    {
                        "text": p.get("text", ""),
                        "size": p.get("size", 13),
                        "bold": p.get("bold", False),
                        "color": p.get("color", SLATE),
                        "font": p.get("font", "Segoe UI"),
                    }
                ]
            r_parts = []
            for r in runs:
                sz = int(round(r.get("size", 13) * 100))
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
  <p:nvSpPr>
    <p:cNvPr id="{sid}" name="{esc(name)}"/>
    <p:cNvSpPr txBox="1"/>
    <p:nvPr/>
  </p:nvSpPr>
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
        pad = 10.0
        cap_h = 24.0 if caption else 0.0
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
                x + 6,
                y + box_h - cap_h - 3,
                box_w - 12,
                cap_h,
                [{"text": caption, "size": 10.5, "bold": True, "color": MUTED, "align": "ctr"}],
                anchor="ctr",
                pad_lr=0,
                pad_tb=0,
                name=f"{name}_Caption",
            )

    def add_table(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        headers: list[str],
        rows: list[list[str]],
        col_ratios: list[float],
        dark: bool = True,
        font_size: float = 11.0,
        name: str = "Table",
    ) -> None:
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
                f'<a:txBody><a:bodyPr wrap="square" lIns="85000" tIns="40000" rIns="85000" bIns="40000" anchor="ctr"/>'
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
        hdr_bg = "134E4A" if dark else "F1F5F9"
        hdr_fg = TEAL_LIGHT if dark else NAVY
        hdr_cells = "".join(make_cell(h_txt, hdr_bg, hdr_fg, True, font_size) for h_txt in headers)
        tr_parts.append(f'<a:tr h="{row_h}">{hdr_cells}</a:tr>')
        for idx, r in enumerate(rows):
            if dark:
                bg = NAVY_MID if idx % 2 == 0 else "162032"
                cells = [
                    make_cell(r[0], bg, WHITE, True, font_size),
                    make_cell(r[1], bg, TEAL_LIGHT, True, font_size, "Consolas"),
                    make_cell(r[2], bg, "CBD5E1", False, font_size),
                ]
            else:
                bg = WHITE if idx % 2 == 0 else BG_LIGHT
                cells = [
                    make_cell(r[0], bg, TEAL, True, font_size, "Consolas"),
                    make_cell(r[1], bg, NAVY, True, font_size),
                    make_cell(r[2], bg, SLATE, False, font_size),
                ]
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

    def add_chrome(self, title: str, subtitle: str, badge: str) -> None:
        self.add_rect(0, 0, 1280, 80, fill=NAVY, name="HeaderBG")
        self.add_rect(0, 0, 10, 80, fill=TEAL_BRIGHT, name="HeaderAccent")
        self.add_text(
            26, 11, 960, 34,
            [{"text": title, "size": 19, "bold": True, "color": WHITE}],
            pad_lr=40000, pad_tb=0, name="HeaderTitle",
        )
        self.add_text(
            26, 46, 960, 24,
            [{"text": subtitle, "size": 10.5, "color": "94A3B8"}],
            pad_lr=40000, pad_tb=0, name="HeaderSubtitle",
        )
        self.add_text(
            1026, 23, 220, 34,
            [{"text": badge, "size": 9.5, "bold": True, "color": TEAL_LIGHT, "align": "ctr"}],
            fill=NAVY_MID, line=TEAL_BRIGHT, line_pt=1.25, rounded=True, anchor="ctr", pad_lr=20000, pad_tb=0, name="HeaderBadge",
        )
        self.add_rect(0, 688, 1280, 32, fill=BG_LIGHT, name="FooterBG")
        self.add_rect(0, 688, 1280, 1, fill="E2E8F0", name="FooterRule")
        self.add_text(
            34, 692, 980, 24,
            [{"text": "Lightweight OWASP Top 10 Vulnerability Scanner — Progress Briefing & Technical Walkthrough (Prepared for Dr. Samar)", "size": 9, "color": MUTED}],
            anchor="ctr", pad_lr=0, pad_tb=0, name="FooterLeft",
        )
        self.add_text(
            1100, 692, 146, 24,
            [{"text": f"Slide {self.slide_num:02d} / {TOTAL_SLIDES:02d}", "size": 9, "bold": True, "color": NAVY, "align": "r"}],
            anchor="ctr", pad_lr=0, pad_tb=0, name="FooterRight",
        )

    def to_slide_xml(self) -> str:
        return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
       xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
       xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld>
    <p:bg>
      <p:bgPr>
        <a:solidFill><a:srgbClr val="{self.bg_hex}"/></a:solidFill>
        <a:effectLst/>
      </p:bgPr>
    </p:bg>
    <p:spTree>
      <p:nvGrpSpPr>
        <p:cNvPr id="1" name=""/>
        <p:cNvGrpSpPr/>
        <p:nvPr/>
      </p:nvGrpSpPr>
      <p:grpSpPr>
        <a:xfrm>
          <a:off x="0" y="0"/><a:ext cx="0" cy="0"/>
          <a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/>
        </a:xfrm>
      </p:grpSpPr>
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


def build_pptx_slides(img_info: dict[str, tuple[str, int, int]]) -> list[SlideBuilder]:
    slides: list[SlideBuilder] = []

    # ---- Slide 1: Title Slide ----
    s1 = SlideBuilder(1, NAVY)
    s1.add_rect(0, 0, 12, 720, fill=TEAL_BRIGHT, name="CoverAccent")
    s1.add_text(
        80, 58, 570, 34,
        [{"text": "SUPERVISOR PROGRESS BRIEFING • ACADEMIC YEAR 2026–2027", "size": 10.5, "bold": True, "color": TEAL_LIGHT, "align": "ctr"}],
        fill="134E4A", line=TEAL_BRIGHT, line_pt=1.0, rounded=True, anchor="ctr",
    )
    s1.add_text(
        80, 114, 1120, 145,
        [
            {"text": "Developing a Lightweight OWASP", "size": 40, "bold": True, "color": WHITE, "space_after": 2},
            {"text": "Top 10 Vulnerability Scanner", "size": 40, "bold": True, "color": WHITE, "space_after": 8},
        ],
        pad_lr=0, pad_tb=0,
    )
    s1.add_text(
        80, 264, 1120, 42,
        [{"text": "Progress Briefing & Technical Walkthrough — What We Built, How It Works & Where We Are", "size": 16.5, "bold": True, "color": TEAL_LIGHT}],
        pad_lr=0, pad_tb=0,
    )
    meta_cards = [
        ("PREPARED FOR", "Dr. Samar", "Department of Cyber Security"),
        ("ACADEMIC YEAR", "2026–2027", "Graduation Project Progress"),
        ("PROJECT TEAM", "7-Member Team", "Department of Cyber Security"),
    ]
    for i, (lbl, val, sub) in enumerate(meta_cards):
        mx = 80 + i * 380
        s1.add_rect(mx, 362, 356, 138, fill=NAVY_MID, line="334155", line_pt=1.0, rounded=True)
        s1.add_rect(mx, 362, 356, 5, fill=TEAL_BRIGHT)
        s1.add_text(
            mx + 18, 378, 320, 110,
            [
                {"text": lbl, "size": 10, "bold": True, "color": TEAL_LIGHT, "space_after": 6},
                {"text": val, "size": 21, "bold": True, "color": WHITE, "space_after": 4},
                {"text": sub, "size": 11.5, "color": "CBD5E1"},
            ],
            pad_lr=0, pad_tb=0,
        )
    pills = [
        (80, 260, "✓  Phases 0–2 Complete", "14532D", GREEN, GREEN_LIGHT),
        (360, 290, "▶  Immediate Next: Phase 3", "78350F", AMBER, AMBER_LIGHT),
        (670, 310, "20 / 20 Core Unit Tests Passing", "134E4A", TEAL_BRIGHT, TEAL_LIGHT),
    ]
    for px_x, pw, txt, bg, ln, fg in pills:
        s1.add_text(
            px_x, 574, pw, 42,
            [{"text": txt, "size": 11.5, "bold": True, "color": fg, "align": "ctr"}],
            fill=bg, line=ln, line_pt=1.25, rounded=True, anchor="ctr",
        )
    slides.append(s1)

    # ---- Slide 2: Where We Are in the Plan (Done vs. Next) ----
    s2 = SlideBuilder(2, WHITE)
    s2.add_chrome("Where We Are in the Plan (Done vs. Next)", "Full 8-phase build roadmap — completed Semester 1 foundation and immediate next milestone", "ROADMAP • P2 → P3")
    milestones = [
        ("100% Complete", "Semester 1 Documentation & Core Foundation", GREEN_SOFT, GREEN, GREEN_DARK),
        ("3 of 8 Phases", "Full Project Build Complete (P0, P1 & P2)", TEAL_SOFT, TEAL, NAVY),
        ("Phase 3 NEXT UP", "17 OWASP Checks, 5-Stack Fix KB & Orchestrator", AMBER_SOFT, AMBER, AMBER_DARK),
    ]
    for i, (val, lbl, bg, accent, val_clr) in enumerate(milestones):
        mx = 34 + i * 410
        s2.add_rect(mx, 102, 394, 88, fill=bg, line=BORDER, line_pt=1.0, rounded=True)
        s2.add_rect(mx, 102, 7, 88, fill=accent)
        s2.add_text(
            mx + 20, 112, 360, 68,
            [
                {"text": val, "size": 20, "bold": True, "color": val_clr, "space_after": 4},
                {"text": lbl, "size": 11, "bold": True, "color": SLATE},
            ],
            pad_lr=0, pad_tb=0,
        )
    s2.add_rect(60, 310, 1160, 8, fill="E2E8F0")
    s2.add_rect(60, 310, 480, 8, fill=GREEN)

    for i, (code, badge_txt, state, title, desc) in enumerate(ROADMAP_PHASES):
        rx = 34 + i * 152
        rw = 142
        if state == "next":
            s2.add_text(
                rx - 12, 228, rw + 24, 30,
                [{"text": "YOU ARE HERE → P3", "size": 8.5, "bold": True, "color": WHITE, "align": "ctr"}],
                fill=AMBER, rounded=True, anchor="ctr", pad_lr=10000, pad_tb=0,
            )
        node_bg = GREEN_SOFT if state == "done" else (AMBER_SOFT if state == "next" else BG_LIGHT)
        node_ln = GREEN if state == "done" else (AMBER if state == "next" else BORDER)
        code_clr = GREEN_DARK if state == "done" else (AMBER_DARK if state == "next" else MUTED)
        badge_bg = GREEN if state == "done" else (AMBER if state == "next" else "94A3B8")
        s2.add_rect(rx, 270, rw, 84, fill=node_bg, line=node_ln, line_pt=2.5 if state == "next" else 1.5, rounded=True)
        s2.add_text(rx + 6, 276, rw - 12, 34, [{"text": code, "size": 17, "bold": True, "color": code_clr, "align": "ctr"}], pad_lr=0, pad_tb=0)
        s2.add_text(
            rx + 18, 318, rw - 36, 24,
            [{"text": badge_txt, "size": 8, "bold": True, "color": WHITE, "align": "ctr"}],
            fill=badge_bg, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0,
        )
        card_bg = AMBER_SOFT if state == "next" else (WHITE if state == "done" else BG_LIGHT)
        card_top = GREEN if state == "done" else (AMBER if state == "next" else BORDER)
        s2.add_rect(rx, 374, rw, 184, fill=card_bg, line=node_ln if state != "upcoming" else "E2E8F0", line_pt=1.5, rounded=True)
        s2.add_rect(rx, 374, rw, 5, fill=card_top)
        s2.add_text(
            rx + 8, 390, rw - 16, 156,
            [
                {"text": title, "size": 11, "bold": True, "color": NAVY, "align": "ctr", "space_after": 8},
                {"text": desc, "size": 9.8, "color": SLATE, "align": "ctr"},
            ],
            anchor="ctr", pad_lr=0, pad_tb=0,
        )
    s2.add_rect(34, 594, 1212, 52, fill=BG_LIGHT, line="E2E8F0", line_pt=1.25, rounded=True)
    s2.add_text(
        50, 604, 1180, 32,
        [{
            "align": "ctr",
            "runs": [
                {"text": "● Phases 0–2 Done: ", "size": 10.5, "bold": True, "color": GREEN_DARK},
                {"text": "Repo, Docker, 6-Ch. SAD & Core Scanner      ", "size": 10.5, "color": SLATE},
                {"text": "● Phase 3 Next Up: ", "size": 10.5, "bold": True, "color": AMBER_DARK},
                {"text": "17 OWASP Checks & Fix KB      ", "size": 10.5, "color": SLATE},
                {"text": "● Phases 4–7 Upcoming: ", "size": 10.5, "bold": True, "color": MUTED},
                {"text": "API, Dashboard, Eval & Defense", "size": 10.5, "color": SLATE},
            ],
        }],
        anchor="ctr", pad_lr=0, pad_tb=0,
    )
    slides.append(s2)

    # ---- Slide 3: Problem Statement & How Our Solution Solves It ----
    s3 = SlideBuilder(3, WHITE)
    s3.add_chrome("Problem Statement & How Our Solution Solves It", "Why student and junior developers skip early security testing — and how our lightweight scanner closes the gap", "MOTIVATION • SCOPE")
    for idx, (hdr, hdr_bg, tag, tag_bg, accent, items) in enumerate([
        ("The Problem: Why Developers Skip Early Testing", NAVY, "PAIN POINTS", RED, RED, PROBLEM_ITEMS),
        ("Our Solution: Developer-First Local Scanner", TEAL, "OUR APPROACH", GREEN, TEAL, SOLUTION_ITEMS),
    ]):
        cx = 34 + idx * 618
        s3.add_rect(cx, 102, 594, 564, fill=BG_LIGHT, line="E2E8F0", line_pt=1.25, rounded=True)
        s3.add_rect(cx, 102, 594, 46, fill=hdr_bg)
        s3.add_text(cx + 16, 111, 430, 28, [{"text": hdr, "size": 12.5, "bold": True, "color": WHITE}], pad_lr=0, pad_tb=0)
        s3.add_text(cx + 462, 113, 114, 24, [{"text": tag, "size": 8.5, "bold": True, "color": WHITE, "align": "ctr"}], fill=tag_bg, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0)
        for j, (t, d) in enumerate(items):
            iy = 166 + j * 122
            s3.add_rect(cx + 18, iy, 558, 108, fill=WHITE, line="E2E8F0", line_pt=1.0, rounded=True)
            s3.add_rect(cx + 18, iy, 6, 108, fill=accent)
            s3.add_text(
                cx + 36, iy + 12, 526, 86,
                [
                    {"text": t, "size": 12.5, "bold": True, "color": NAVY, "space_after": 4},
                    {"text": d, "size": 10.8, "color": SLATE},
                ],
                pad_lr=0, pad_tb=0,
            )
    slides.append(s3)

    # ---- Slide 4: Phase 0 Explained: Clean Greenfield Foundation & Docker Setup ----
    s4 = SlideBuilder(4, WHITE)
    s4.add_chrome("Phase 0 Explained: Clean Greenfield Foundation & Docker Setup", "Modular repository layout, hardened containerization, local testbench stack & FastAPI bootstrap", "PHASE 0 • DONE")
    for idx, (letter, title, desc) in enumerate(PHASE0_CARDS):
        col = idx % 2
        row = idx // 2
        cx = 34 + col * 616
        cy = 104 + row * 246
        s4.add_rect(cx, cy, 596, 228, fill=BG_LIGHT, line="E2E8F0", line_pt=1.25, rounded=True)
        s4.add_rect(cx, cy, 596, 6, fill=TEAL)
        s4.add_text(cx + 20, cy + 22, 34, 34, [{"text": letter, "size": 13, "bold": True, "color": TEAL_LIGHT, "align": "ctr"}], fill=NAVY, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0)
        s4.add_text(cx + 66, cy + 24, 420, 30, [{"text": title, "size": 14, "bold": True, "color": NAVY}], anchor="ctr", pad_lr=0, pad_tb=0)
        s4.add_text(cx + 506, cy + 27, 70, 24, [{"text": "DONE", "size": 8.5, "bold": True, "color": WHITE, "align": "ctr"}], fill=GREEN, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0)
        s4.add_text(cx + 20, cy + 72, 556, 138, [{"text": desc, "size": 12, "color": SLATE}], pad_lr=0, pad_tb=0)
    s4.add_rect(34, 604, 1212, 56, fill=TEAL_SOFT, line="99F6E4", line_pt=1.25, rounded=True)
    s4.add_rect(34, 604, 7, 56, fill=TEAL)
    s4.add_text(
        54, 616, 1176, 34,
        [{
            "runs": [
                {"text": "Key Engineering Outcome: ", "size": 11.5, "bold": True, "color": NAVY},
                {"text": "Zero-friction local onboarding — runs identically via docker compose up or native Python venv with strict engine isolation.", "size": 11.5, "color": SLATE},
            ]
        }],
        anchor="ctr", pad_lr=0, pad_tb=0,
    )
    slides.append(s4)

    # ---- Slide 5: Phase 1 Explained: Formal 6-Chapter SAD & 19 Diagrams ----
    s5 = SlideBuilder(5, WHITE)
    s5.add_chrome("Phase 1 Explained: Formal 6-Chapter SAD & 19 Diagrams", "Complete IEEE-aligned Software Architecture Document and print-ready graduation books", "PHASE 1 • DONE")
    s5.add_rect(34, 102, 774, 46, fill=NAVY)
    s5.add_text(50, 112, 540, 26, [{"text": "6 Formal SAD Chapters Breakdown", "size": 13, "bold": True, "color": WHITE}], pad_lr=0, pad_tb=0)
    s5.add_text(694, 113, 98, 24, [{"text": "COMPLETE", "size": 8.5, "bold": True, "color": WHITE, "align": "ctr"}], fill=GREEN, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0)
    s5.add_table(
        34, 148, 774, 516,
        ["Ch.", "Chapter Focus", "Key Specifications & Engineering Artifacts"],
        [[c[0], c[1], c[2]] for c in SAD_CHAPTERS],
        [0.12, 0.27, 0.61],
        dark=False,
        font_size=10.8,
        name="SADChapters",
    )
    s5.add_rect(828, 102, 418, 562, fill=BG_LIGHT, line="E2E8F0", line_pt=1.25, rounded=True)
    s5.add_rect(828, 102, 418, 46, fill=TEAL)
    s5.add_text(844, 112, 280, 26, [{"text": "Ready-to-Submit Deliverables", "size": 12.5, "bold": True, "color": WHITE}], pad_lr=0, pad_tb=0)
    s5.add_text(1140, 113, 90, 24, [{"text": "VERIFIED", "size": 8.5, "bold": True, "color": WHITE, "align": "ctr"}], fill=GREEN, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0)
    for j, (k, v) in enumerate(SAD_DELIVERABLES):
        dy = 164 + j * 96
        s5.add_rect(844, dy, 386, 84, fill=WHITE, line="E2E8F0", line_pt=1.0, rounded=True)
        s5.add_rect(844, dy, 5, 84, fill=TEAL)
        s5.add_text(
            860, dy + 12, 358, 62,
            [
                {"text": k, "size": 11.5, "bold": True, "color": NAVY, "font": "Consolas", "space_after": 4},
                {"text": v, "size": 10.5, "color": SLATE},
            ],
            pad_lr=0, pad_tb=0,
        )
    slides.append(s5)

    # ---- Slide 6: How the Whole System Works (Figure 19) ----
    s6 = SlideBuilder(6, WHITE)
    s6.add_chrome("How the Whole System Works (Figure 19 Master Flowchart)", "End-to-end safe local scanning pipeline from target authorization to copy-ready code fixes", "WORKFLOW • FIGURE 19")
    fm, fw, fh = img_info["flowchart"]
    s6.add_image_fit(34, 102, 445, 564, fm, fw, fh, "Figure 19: Master System Flowchart", "Flowchart")
    for i, (num, title, desc) in enumerate(WORKFLOW_STEPS):
        sy = 102 + i * 95
        s6.add_rect(502, sy, 744, 84, fill=BG_LIGHT, line="E2E8F0", line_pt=1.25, rounded=True)
        s6.add_rect(502, sy, 6, 84, fill=TEAL)
        s6.add_text(
            520, sy + 20, 44, 44,
            [{"text": num, "size": 14, "bold": True, "color": TEAL_LIGHT, "font": "Consolas", "align": "ctr"}],
            fill=NAVY, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0,
        )
        s6.add_text(
            580, sy + 10, 652, 66,
            [
                {"text": title, "size": 13, "bold": True, "color": NAVY, "space_after": 3},
                {"text": desc, "size": 10.5, "color": SLATE},
            ],
            pad_lr=0, pad_tb=0,
        )
    slides.append(s6)

    # ---- Slide 7: System Architecture & Why We Chose Each Technology (Figure 5) ----
    s7 = SlideBuilder(7, WHITE)
    s7.add_chrome("System Architecture & Why We Chose Each Technology", "Modular monolith engineered for zero-config local execution — Figure 5 C4 Level 2 Containers", "ARCHITECTURE • FIGURE 5")
    cm, cw, ch = img_info["c4_l2"]
    s7.add_image_fit(34, 102, 718, 564, cm, cw, ch, "Figure 5: C4 Level 2 — Container Architecture", "C4_L2")
    s7.add_rect(772, 102, 474, 38, fill=NAVY, rounded=True)
    s7.add_rect(772, 102, 6, 38, fill=TEAL_BRIGHT)
    s7.add_text(788, 108, 448, 26, [{"text": "Architectural Justification by Layer", "size": 12, "bold": True, "color": WHITE}], anchor="ctr", pad_lr=0, pad_tb=0)
    for i, (name, why) in enumerate(ARCH_LAYERS):
        ay = 150 + i * 87
        s7.add_rect(772, ay, 474, 78, fill=BG_LIGHT, line="E2E8F0", line_pt=1.0, rounded=True)
        s7.add_rect(772, ay, 5, 78, fill=TEAL)
        s7.add_text(
            788, ay + 8, 446, 62,
            [
                {"text": name, "size": 11.5, "bold": True, "color": NAVY, "space_after": 2},
                {"text": why, "size": 9.8, "color": SLATE},
            ],
            pad_lr=0, pad_tb=0,
        )
    slides.append(s7)

    # ---- Slide 8: Phase 2 Explained (Part 1): Safety Guardrail & Smart HTTP Client ----
    s8 = SlideBuilder(8, WHITE)
    s8.add_chrome("Phase 2 Explained (Part 1): Safety Guardrail & Smart HTTP Client", "Defense-in-depth scope enforcement and resilient local HTTP transport — Figure 16", "PHASE 2 • DONE")
    gm, gw, gh = img_info["guardrail"]
    s8.add_image_fit(34, 102, 502, 564, gm, gw, gh, "Figure 16: Scope Guardrail Flow", "GuardrailFlow")

    for idx, (hdr, hdr_bg, tag, pts) in enumerate([
        ("policy.py — ScopeGuardrail", NAVY, "8/8 TESTS", GUARDRAIL_POINTS),
        ("http_client.py — ScannerHttpClient", TEAL, "7/7 TESTS", HTTP_CLIENT_POINTS),
    ]):
        cy = 102 + idx * 290
        s8.add_rect(558, cy, 688, 274, fill=BG_LIGHT, line="E2E8F0", line_pt=1.25, rounded=True)
        s8.add_rect(558, cy, 688, 44, fill=hdr_bg)
        s8.add_text(576, cy + 10, 520, 26, [{"text": hdr, "size": 13, "bold": True, "color": WHITE}], pad_lr=0, pad_tb=0)
        s8.add_text(1136, cy + 10, 94, 24, [{"text": tag, "size": 8.5, "bold": True, "color": WHITE, "align": "ctr"}], fill=GREEN, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0)
        paras = [
            {
                "bullet": True,
                "space_after": 12,
                "runs": [
                    {"text": h + " ", "size": 11.2, "bold": True, "color": NAVY},
                    {"text": b, "size": 11.2, "color": SLATE},
                ],
            }
            for h, b in pts
        ]
        s8.add_text(576, cy + 56, 654, 206, paras, pad_lr=0, pad_tb=0)
    slides.append(s8)

    # ---- Slide 9: Phase 2 Explained (Part 2): Bounded BFS Crawler & Live Verification Proof ----
    s9 = SlideBuilder(9, WHITE)
    s9.add_chrome("Phase 2 Explained (Part 2): Bounded BFS Crawler & Live Proof", "Same-origin attack surface discovery verified with automated unit tests", "PHASE 2 • VERIFIED")
    s9.add_rect(34, 102, 608, 564, fill=BG_LIGHT, line="E2E8F0", line_pt=1.25, rounded=True)
    s9.add_rect(34, 102, 608, 46, fill=NAVY)
    s9.add_text(52, 112, 460, 26, [{"text": "crawler.py — Bounded BFS WebCrawler", "size": 13.5, "bold": True, "color": WHITE}], pad_lr=0, pad_tb=0)
    s9.add_text(534, 113, 92, 24, [{"text": "5/5 TESTS", "size": 8.5, "bold": True, "color": WHITE, "align": "ctr"}], fill=GREEN, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0)
    cr_paras = [
        {
            "bullet": True,
            "space_after": 18,
            "runs": [
                {"text": h + " ", "size": 12, "bold": True, "color": NAVY},
                {"text": b, "size": 12, "color": SLATE},
            ],
        }
        for h, b in CRAWLER_POINTS
    ]
    s9.add_text(54, 170, 568, 474, cr_paras, pad_lr=0, pad_tb=0)

    s9.add_rect(664, 102, 582, 92, fill=GREEN_SOFT, line=GREEN, line_pt=2.0, rounded=True)
    s9.add_text(682, 124, 48, 48, [{"text": "✓", "size": 21, "bold": True, "color": WHITE, "align": "ctr"}], fill=GREEN, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0)
    s9.add_text(
        746, 116, 484, 68,
        [
            {"text": "20 / 20 Unit Tests PASSED in 1.186s", "size": 16, "bold": True, "color": GREEN_DARK, "space_after": 4},
            {"text": "test_policy.py (8/8) • test_http_client.py (7/7) • test_crawler.py (5/5)", "size": 9.8, "bold": True, "color": SLATE, "font": "Consolas"},
        ],
        pad_lr=0, pad_tb=0,
    )
    s9.add_rect(664, 212, 582, 454, fill=NAVY, line="334155", line_pt=1.5, rounded=True)
    s9.add_rect(664, 212, 582, 36, fill=NAVY_MID)
    s9.add_text(682, 218, 420, 24, [{"text": "powershell — live verification proof", "size": 10, "color": "94A3B8", "font": "Consolas"}], anchor="ctr", pad_lr=0, pad_tb=0)
    term_lines = [
        ("$ py -3.12 -m unittest discover -s tests -v", "38BDF8", True),
        ("", "E2E8F0", False),
        ("[ScopeGuardrail]  Allowed: 127.0.0.1 | Blocked: google.com", "5EEAD4", True),
        ("[ScopeGuardrail]  Blocked: 169.254.169.254 (DNS rebinding)", "FCA5A5", False),
        ("[HttpClient]      Soft-404: Calibrated | Rate-Limit: 10/s", "E2E8F0", False),
        ("[AttackSurface]   Endpoints, Forms & JS /api/ routes found", "E2E8F0", False),
        ("", "E2E8F0", False),
        ("----------------------------------------------------------", "64748B", False),
        ("Ran 20 tests in 1.186s — OK (0 failures, 0 errors)", "4ADE80", True),
    ]
    s9.add_text(
        684, 270, 542, 374,
        [{"text": txt, "size": 11, "bold": bld, "color": clr, "font": "Consolas", "space_after": 9} for txt, clr, bld in term_lines],
        pad_lr=0, pad_tb=0,
    )
    slides.append(s9)

    # ---- Slide 10: What Is Next: Detailed Phases 3–7 Implementation Plan ----
    s10 = SlideBuilder(10, WHITE)
    s10.add_chrome("What Is Next: Detailed Phases 3–7 Implementation Plan", "Clear execution roadmap from OWASP vulnerability checks to final graduation defense", "NEXT • PHASE 3 → 7")
    p3 = NEXT_PHASES[0]
    s10.add_rect(34, 102, 1212, 158, fill=AMBER_SOFT, line=AMBER, line_pt=2.5, rounded=True)
    s10.add_rect(34, 102, 9, 158, fill=AMBER)
    s10.add_text(60, 114, 110, 26, [{"text": "PHASE 3", "size": 12, "bold": True, "color": AMBER_DARK}], pad_lr=0, pad_tb=0)
    s10.add_text(164, 114, 168, 24, [{"text": "▶ IMMEDIATE NEXT", "size": 9, "bold": True, "color": WHITE, "align": "ctr"}], fill=AMBER, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0)
    s10.add_text(
        60, 146, 930, 102,
        [
            {"text": p3[3], "size": 16.5, "bold": True, "color": NAVY, "space_after": 5},
            {"text": p3[4], "size": 11.2, "color": SLATE},
        ],
        pad_lr=0, pad_tb=0,
    )
    s10.add_text(
        1014, 128, 212, 106,
        [
            {"text": "17 Checks", "size": 21, "bold": True, "color": WHITE, "align": "ctr", "space_after": 4},
            {"text": "OWASP Top 10 + 5-Stack Fix KB", "size": 10, "bold": True, "color": WHITE, "align": "ctr"},
        ],
        fill=AMBER, rounded=True, anchor="ctr",
    )
    for idx, (ph, tag, _, title, desc) in enumerate(NEXT_PHASES[1:]):
        col = idx % 2
        row = idx // 2
        nx = 34 + col * 616
        ny = 280 + row * 198
        s10.add_rect(nx, ny, 596, 182, fill=BG_LIGHT, line="E2E8F0", line_pt=1.25, rounded=True)
        s10.add_rect(nx, ny, 596, 5, fill=MUTED)
        s10.add_text(nx + 20, ny + 16, 140, 24, [{"text": ph.upper(), "size": 11, "bold": True, "color": TEAL}], pad_lr=0, pad_tb=0)
        s10.add_text(nx + 466, ny + 16, 110, 24, [{"text": tag, "size": 8.5, "bold": True, "color": WHITE, "align": "ctr"}], fill=MUTED, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0)
        s10.add_text(
            nx + 20, ny + 48, 556, 120,
            [
                {"text": title, "size": 13.5, "bold": True, "color": NAVY, "space_after": 6},
                {"text": desc, "size": 11, "color": SLATE},
            ],
            pad_lr=0, pad_tb=0,
        )
    slides.append(s10)

    # ---- Slide 11: 7-Member Team Ownership & Approval for Phase 3 (Closing) ----
    s11 = SlideBuilder(11, NAVY)
    s11.add_rect(0, 0, 12, 720, fill=TEAL_BRIGHT, name="ClosingAccent")
    s11.add_text(
        64, 32, 330, 30,
        [{"text": "7-MEMBER TEAM & PHASE 3 APPROVAL", "size": 9.5, "bold": True, "color": TEAL_LIGHT, "align": "ctr"}],
        fill="134E4A", line=TEAL_BRIGHT, line_pt=1.0, rounded=True, anchor="ctr",
    )
    s11.add_text(
        64, 68, 660, 48,
        [{"text": "Team Ownership & Approval for Phase 3", "size": 26, "bold": True, "color": WHITE}],
        pad_lr=0, pad_tb=0,
    )
    s11.add_rect(726, 48, 498, 62, fill=NAVY_MID, line=TEAL_BRIGHT, line_pt=1.0, rounded=True)
    s11.add_text(
        740, 54, 470, 50,
        [
            {"text": "GITHUB REPOSITORY", "size": 8.5, "bold": True, "color": TEAL_LIGHT, "align": "r", "space_after": 2},
            {"text": "https://github.com/mohammewaleed/Graduation-Project-2027", "size": 9.8, "color": WHITE, "font": "Consolas", "align": "r"},
        ],
        pad_lr=0, pad_tb=0,
    )
    s11.add_table(
        64, 134, 1160, 430,
        ["Team Member", "Student ID", "Role & Module Owned"],
        [[m[0], m[1], m[2]] for m in TEAM_ROSTER],
        [0.30, 0.13, 0.57],
        dark=True,
        font_size=11.2,
        name="TeamRoster",
    )
    s11.add_rect(64, 588, 1160, 94, fill="134E4A", line=TEAL_BRIGHT, line_pt=1.5, rounded=True)
    s11.add_text(
        88, 602, 960, 66,
        [
            {"text": "Phases 0–2 Verified Complete — Ready for Dr. Samar's Approval to Launch Phase 3", "size": 16.5, "bold": True, "color": WHITE, "space_after": 4},
            {"text": "Department of Cyber Security • Academic Year 2026–2027 • 3 of 8 Phases Complete → Next: Phase 3", "size": 10.5, "color": "CBD5E1"},
        ],
        pad_lr=0, pad_tb=0,
    )
    s11.add_text(
        1076, 606, 120, 56,
        [{"text": "Q & A", "size": 18, "bold": True, "color": NAVY, "align": "ctr"}],
        fill=TEAL_BRIGHT, rounded=True, anchor="ctr", pad_lr=0, pad_tb=0,
    )
    slides.append(s11)

    return slides


def write_pptx(out_path: Path) -> None:
    img_info: dict[str, tuple[str, int, int]] = {}
    media_files: list[tuple[str, bytes]] = []
    for idx, (key, path) in enumerate(DIAGRAMS.items(), start=1):
        with Image.open(path) as im:
            w, h = im.size
        mname = f"image{idx}.png"
        img_info[key] = (mname, w, h)
        media_files.append((mname, path.read_bytes()))

    slides = build_pptx_slides(img_info)
    n_slides = len(slides)

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
  <dc:title>Supervisor Progress Briefing — Lightweight OWASP Top 10 Vulnerability Scanner</dc:title>
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
  <p:sldMasterIdLst>
    <p:sldMasterId id="2147483648" r:id="rId1"/>
  </p:sldMasterIdLst>
  <p:sldIdLst>
    {sld_id_list}
  </p:sldIdLst>
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
    pres_rels_items.extend(
        [
            f'<Relationship Id="rId{base_rid}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/presProps" Target="presProps.xml"/>',
            f'<Relationship Id="rId{base_rid + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/viewProps" Target="viewProps.xml"/>',
            f'<Relationship Id="rId{base_rid + 2}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="theme/theme1.xml"/>',
            f'<Relationship Id="rId{base_rid + 3}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/tableStyles" Target="tableStyles.xml"/>',
        ]
    )
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
    <p:bg>
      <p:bgRef idx="1001"><a:schemeClr val="bg1"/></p:bgRef>
    </p:bg>
    <p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
      <p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>
    </p:spTree>
  </p:cSld>
  <p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>
  <p:sldLayoutIdLst>
    <p:sldLayoutId id="2147483649" r:id="rId1"/>
  </p:sldLayoutIdLst>
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


def validate_outputs() -> None:
    with zipfile.ZipFile(OUT_PPTX, "r") as zf:
        names = set(zf.namelist())
        for name in names:
            if name.endswith(".xml") or name.endswith(".rels"):
                ET.fromstring(zf.read(name))
        for i in range(1, TOTAL_SLIDES + 1):
            assert f"ppt/slides/slide{i}.xml" in names, f"Missing slide{i}.xml"
            assert f"ppt/slides/_rels/slide{i}.xml.rels" in names, f"Missing slide{i}.xml.rels"
        assert f"ppt/slides/slide{TOTAL_SLIDES + 1}.xml" not in names, "Extra slide detected"
        media = [n for n in names if n.startswith("ppt/media/")]
        assert len(media) == len(DIAGRAMS), f"Expected {len(DIAGRAMS)} embedded PNGs, got {len(media)}"
        for m in media:
            raw = zf.read(m)
            assert raw[:8] == b"\x89PNG\r\n\x1a\n", f"Invalid PNG signature in {m}"

    html_text = OUT_HTML.read_text(encoding="utf-8")
    assert html_text.count('class="slide ') == TOTAL_SLIDES, "HTML slide count mismatch"
    assert "cdn." not in html_text.lower() and "fonts.googleapis" not in html_text.lower(), "External CDN ref detected!"

    pdf_bytes = OUT_PDF.read_bytes()
    assert pdf_bytes.startswith(b"%PDF-"), "PDF missing %PDF- header"


def main() -> int:
    PRES_DIR.mkdir(parents=True, exist_ok=True)
    b64 = load_b64_images()
    OUT_HTML.write_text(build_html(b64), encoding="utf-8")
    print(f"[OK] Wrote {OUT_HTML} ({OUT_HTML.stat().st_size:,} bytes)")

    build_pdf(OUT_HTML, OUT_PDF)
    print(f"[OK] Wrote {OUT_PDF} ({OUT_PDF.stat().st_size:,} bytes)")

    write_pptx(OUT_PPTX)
    print(f"[OK] Wrote {OUT_PPTX} ({OUT_PPTX.stat().st_size:,} bytes)")

    validate_outputs()
    print(f"[OK] All 3 presentation artifacts ({TOTAL_SLIDES} slides) validated successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
