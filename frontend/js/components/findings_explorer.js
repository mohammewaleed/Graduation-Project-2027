/**
 * View 4 — Findings Explorer, Analytics Strip & Discovered Endpoints (#view-findings).
 * Supports live triage refresh, multi-criteria filtering, report exports, and FixModal handoff.
 */

import { getReportUrl, getScan, getScanEndpoints, getScanFindings } from "../api.js";
import {
  clear,
  el,
  formatDate,
  riskColorClass,
  severityBadge,
  shortId,
  showToast,
  statusBadge,
  triageBadge,
} from "../utils.js";
import { renderOwaspBarChart, renderRiskGauge, renderSeverityDonut } from "./charts.js";

const OWASP_FILTER_OPTIONS = [
  { value: "", label: "All OWASP Categories" },
  { value: "A01", label: "A01 — Broken Access Control" },
  { value: "A02", label: "A02 — Cryptographic Failures" },
  { value: "A03", label: "A03 — Injection" },
  { value: "A04", label: "A04 — Insecure Design" },
  { value: "A05", label: "A05 — Security Misconfiguration" },
  { value: "A06", label: "A06 — Vulnerable Components" },
  { value: "A07", label: "A07 — Auth Failures" },
  { value: "A08", label: "A08 — Data Integrity Failures" },
  { value: "A09", label: "A09 — Logging & Monitoring" },
  { value: "A10", label: "A10 — SSRF" },
];

const SEVERITY_FILTER_OPTIONS = [
  { value: "", label: "All Severities" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
  { value: "info", label: "Info" },
];

const TRIAGE_FILTER_OPTIONS = [
  { value: "", label: "All Triage States" },
  { value: "open", label: "Open" },
  { value: "fixed", label: "Fixed" },
  { value: "false_positive", label: "False Positive" },
  { value: "accepted", label: "Accepted Risk" },
];

function renderTriageBadgeSafe(status) {
  const normalized = String(status || "open").trim().toLowerCase();
  if (normalized === "accepted") {
    const badge = triageBadge("accepted_risk");
    badge.classList.add("badge-triage-accepted");
    return badge;
  }
  return triageBadge(normalized);
}

function methodBadgeClass(method) {
  const m = String(method || "GET").trim().toLowerCase();
  if (["get", "post", "put", "patch", "delete"].includes(m)) {
    return `method-badge method-${m}`;
  }
  return "method-badge";
}

function formatEndpointPath(rawUrl) {
  const str = String(rawUrl || "").trim();
  if (!str) return "/";
  try {
    const parsed = new URL(str);
    return `${parsed.pathname || "/"}${parsed.search || ""}`;
  } catch (_err) {
    return str;
  }
}

function httpStatusBadge(code) {
  const num = Number(code || 0);
  let cls = "badge badge-neutral mono";
  if (num >= 200 && num < 300) cls = "badge badge-status-completed mono";
  else if (num >= 300 && num < 400) cls = "badge badge-status-scanning mono";
  else if (num >= 400 && num < 500) cls = "badge badge-sev-medium mono";
  else if (num >= 500) cls = "badge badge-sev-critical mono";
  return el("span", { class: cls, text: num > 0 ? String(num) : "—" });
}

function confidenceBadge(conf) {
  const val = String(conf || "medium").trim().toLowerCase();
  const label = val.charAt(0).toUpperCase() + val.slice(1);
  return el("span", { class: "badge badge-neutral", text: label });
}

function formatScanOptionLabel(scan) {
  const proj = scan.project_name || `Project ${shortId(scan.project_id)}`;
  const profile = String(scan.profile || "standard").toUpperCase();
  const status = String(scan.status || "queued");
  const risk = scan.risk_score !== null && scan.risk_score !== undefined ? `Risk ${scan.risk_score}` : "Risk —";
  const date = formatDate(scan.created_at || scan.started_at);
  return `${proj} · #${shortId(scan.id)} (${profile} · ${status} · ${risk} · ${date})`;
}

export class FindingsExplorerView {
  /**
   * @param {HTMLElement | null} container
   * @param {{
   *   onOpenFinding?: (findingId: string, context?: any) => void,
   *   onScanSelected?: (scanId: string) => void,
   *   onLaunchNew?: () => void,
   * }} [callbacks]
   */
  constructor(container, callbacks = {}) {
    this._container = container || document.getElementById("view-findings");
    this._callbacks = callbacks || {};
    this._scans = [];
    this._scanId = null;
    this._scan = null;
    this._findings = [];
    this._endpoints = [];
    this._activeTab = "findings";
    this._filters = {
      q: "",
      severity: "",
      owasp: "",
      triage_status: "",
    };
    this._endpointQuery = "";
    this._loadToken = 0;
    this._refs = null;
  }

  /** @returns {string | null} */
  getCurrentScanId() {
    return this._scanId;
  }

  /**
   * Update available scans list for the top selector bar.
   * @param {Array<Record<string, any>>} scans
   */
  setScans(scans) {
    this._scans = Array.isArray(scans) ? [...scans] : [];
    if (this._refs?.scanSelect) {
      this._populateScanSelect();
    }
  }

  /**
   * Load full scan metadata, findings, and discovered endpoints for a scan.
   * @param {string | null} scanId
   * @param {Array<Record<string, any>> | null} [scansList]
   */
  async load(scanId, scansList = null) {
    if (Array.isArray(scansList)) {
      this._scans = [...scansList];
    }

    const targetId = scanId || this._scanId || (this._scans[0]?.id ?? null);
    if (!targetId) {
      this._scanId = null;
      this._scan = null;
      this._findings = [];
      this._endpoints = [];
      this._renderEmpty();
      return;
    }

    this._scanId = targetId;
    await this.refresh();
  }

  /**
   * Re-fetch scan metadata, findings, and endpoints for the active scan and re-render
   * analytics (Risk Gauge, Donut, OWASP Bars) + active table cleanly.
   */
  async refresh() {
    if (!this._scanId) {
      this._renderEmpty();
      return;
    }

    const scanId = this._scanId;
    const token = ++this._loadToken;

    if (!this._refs && this._container) {
      clear(this._container);
      this._container.appendChild(
        el("div", { class: "card" }, [
          el("div", { class: "empty-state" }, [
            el("p", { class: "empty-state-desc", text: "Loading scan findings and analytics..." }),
          ]),
        ]),
      );
    }

    try {
      const [scan, findings, endpoints] = await Promise.all([
        getScan(scanId),
        getScanFindings(scanId),
        getScanEndpoints(scanId),
      ]);

      if (token !== this._loadToken) return;
      this._scan = scan;
      this._findings = Array.isArray(findings) ? findings : [];
      this._endpoints = Array.isArray(endpoints) ? endpoints : [];

      // Keep local scan cache fresh with updated risk_score/summary
      const idx = this._scans.findIndex((s) => s.id === scan.id);
      if (idx >= 0) {
        this._scans[idx] = { ...this._scans[idx], ...scan };
      } else {
        this._scans.unshift(scan);
      }

      this._renderFull();
    } catch (err) {
      if (token !== this._loadToken) return;
      showToast(err?.message || "Failed to load scan findings.", "error");
      this._renderEmpty("Unable to load scan results. Select another scan or try again.");
    }
  }

  _renderEmpty(customMessage = null) {
    this._refs = null;
    if (!this._container) return;
    clear(this._container);

    const actions = [];
    if (typeof this._callbacks.onLaunchNew === "function") {
      actions.push(
        el("button", {
          type: "button",
          class: "btn btn-primary",
          text: "Launch First Scan",
          on: { click: () => this._callbacks.onLaunchNew() },
        }),
      );
    }

    this._container.appendChild(
      el("div", { class: "card" }, [
        el("div", { class: "empty-state" }, [
          el("h3", { class: "empty-state-title", text: "No Scan Results Available" }),
          el("p", {
            class: "empty-state-desc",
            text:
              customMessage ||
              "Run a scan against an authorized local target to explore risk scores, OWASP analytics, discovered endpoints, and code fixes.",
          }),
          ...actions,
        ]),
      ]),
    );
  }

  _renderFull() {
    if (!this._container || !this._scan) return;
    clear(this._container);

    const scan = this._scan;

    // 1. Scan Selector & Report Export Bar
    const scanSelect = el("select", {
      id: "findings-scan-select",
      class: "form-select",
      "aria-label": "Select scan to inspect",
      style: { width: "100%", minWidth: "250px", maxWidth: "400px" },
      on: {
        change: (e) => {
          const nextId = e.target.value;
          if (nextId && nextId !== this._scanId) {
            this._scanId = nextId;
            if (typeof this._callbacks.onScanSelected === "function") {
              this._callbacks.onScanSelected(nextId);
            }
            this.refresh();
          }
        },
      },
    });

    const previewHtmlLink = el("a", {
      class: "btn btn-secondary btn-sm",
      href: getReportUrl(scan.id, "html", false),
      target: "_blank",
      rel: "noopener noreferrer",
      text: "Preview Report ↗",
    });

    const downloadHtmlLink = el("a", {
      class: "btn btn-primary btn-sm",
      href: getReportUrl(scan.id, "html", true),
      download: `scan-${shortId(scan.id)}-report.html`,
      text: "Download HTML",
    });

    const downloadJsonLink = el("a", {
      class: "btn btn-secondary btn-sm",
      href: getReportUrl(scan.id, "json", true),
      download: `scan-${shortId(scan.id)}-report.json`,
      text: "Download JSON",
    });

    const telemetryStrip = el("div", { class: "scan-telemetry-strip" }, [
      el("div", { class: "scan-telemetry-badges" }, [
        statusBadge(scan.status),
        el("span", {
          class: `risk-pill ${riskColorClass(scan.risk_score)}`,
          text: `Risk ${scan.risk_score ?? 0}/100`,
        }),
        el("span", {
          class: "badge badge-stack",
          text: String(scan.profile || "standard").toUpperCase(),
        }),
      ]),
      el("div", { class: "scan-telemetry-stats" }, [
        el("div", { class: "scan-stat-item" }, [
          el("span", { class: "scan-stat-label", text: "Pages" }),
          el("strong", { class: "scan-stat-val", text: String(scan.pages_crawled ?? 0) }),
        ]),
        el("div", { class: "scan-stat-item" }, [
          el("span", { class: "scan-stat-label", text: "Requests" }),
          el("strong", { class: "scan-stat-val", text: String(scan.requests_sent ?? 0) }),
        ]),
        el("div", { class: "scan-stat-item" }, [
          el("span", { class: "scan-stat-label", text: "Scanned" }),
          el("strong", {
            class: "scan-stat-val",
            text: formatDate(scan.finished_at || scan.started_at),
          }),
        ]),
      ]),
    ]);

    const toolbarCard = el("div", { class: "card scan-hero-card" }, [
      el("div", { class: "scan-hero-bar" }, [
        el("div", { class: "scan-hero-selector" }, [
          el("label", {
            for: "findings-scan-select",
            class: "scan-hero-eyebrow",
            text: "Active Scan",
          }),
          scanSelect,
        ]),
        el("div", { class: "scan-hero-actions" }, [
          previewHtmlLink,
          downloadHtmlLink,
          downloadJsonLink,
        ]),
      ]),
      telemetryStrip,
    ]);

    // 2. 3-Column Analytics Strip
    const gaugeHost = el("div");
    const donutHost = el("div");
    const owaspHost = el("div");

    const analyticsStrip = el("div", { class: "analytics-grid" }, [
      el("div", { class: "card" }, [
        el("div", { class: "card-header" }, [
          el("div", null, [
            el("h3", { class: "card-title", text: "Overall Risk Score" }),
            el("p", { class: "card-subtitle", text: "Auto-recalculates on triage" }),
          ]),
        ]),
        el("div", { class: "card-body" }, [gaugeHost]),
      ]),
      el("div", { class: "card" }, [
        el("div", { class: "card-header" }, [
          el("div", null, [
            el("h3", { class: "card-title", text: "Severity Breakdown" }),
            el("p", { class: "card-subtitle", text: "Active findings by severity" }),
          ]),
        ]),
        el("div", { class: "card-body" }, [donutHost]),
      ]),
      el("div", { class: "card" }, [
        el("div", { class: "card-header" }, [
          el("div", null, [
            el("h3", { class: "card-title", text: "OWASP Top 10 Breakdown" }),
            el("p", { class: "card-subtitle", text: "Active findings by category" }),
          ]),
        ]),
        el("div", { class: "card-body" }, [owaspHost]),
      ]),
    ]);

    // 3. Sub-Tabs & Explorer Table Card
    const findingsTabBtn = el("button", {
      type: "button",
      class: `tab-btn${this._activeTab === "findings" ? " active" : ""}`,
      text: `Security Findings (${this._findings.length})`,
      on: { click: () => this._switchTab("findings") },
    });

    const endpointsTabBtn = el("button", {
      type: "button",
      class: `tab-btn${this._activeTab === "endpoints" ? " active" : ""}`,
      text: `Discovered Endpoints (${this._endpoints.length})`,
      on: { click: () => this._switchTab("endpoints") },
    });

    const countSummary = el("span", { class: "text-xs text-muted" });

    // Findings Filter Bar
    const searchInput = el("input", {
      type: "search",
      class: "form-input filter-search",
      placeholder: "Search title, endpoint, parameter, CWE...",
      value: this._filters.q,
      "aria-label": "Search findings",
      on: {
        input: (e) => {
          this._filters.q = e.target.value;
          this._renderFindingsTable();
        },
      },
    });

    const severitySelect = el(
      "select",
      {
        class: "form-select",
        "aria-label": "Filter by severity",
        on: {
          change: (e) => {
            this._filters.severity = e.target.value;
            this._renderFindingsTable();
          },
        },
      },
      SEVERITY_FILTER_OPTIONS.map((opt) =>
        el("option", {
          value: opt.value,
          text: opt.label,
          selected: opt.value === this._filters.severity,
        }),
      ),
    );

    const owaspSelect = el(
      "select",
      {
        class: "form-select",
        "aria-label": "Filter by OWASP category",
        on: {
          change: (e) => {
            this._filters.owasp = e.target.value;
            this._renderFindingsTable();
          },
        },
      },
      OWASP_FILTER_OPTIONS.map((opt) =>
        el("option", {
          value: opt.value,
          text: opt.label,
          selected: opt.value === this._filters.owasp,
        }),
      ),
    );

    const triageSelect = el(
      "select",
      {
        class: "form-select",
        "aria-label": "Filter by triage status",
        on: {
          change: (e) => {
            this._filters.triage_status = e.target.value;
            this._renderFindingsTable();
          },
        },
      },
      TRIAGE_FILTER_OPTIONS.map((opt) =>
        el("option", {
          value: opt.value,
          text: opt.label,
          selected: opt.value === this._filters.triage_status,
        }),
      ),
    );

    const resetBtn = el("button", {
      type: "button",
      class: "btn btn-ghost btn-sm",
      text: "Reset Filters",
      on: {
        click: () => {
          this._filters = { q: "", severity: "", owasp: "", triage_status: "" };
          searchInput.value = "";
          severitySelect.value = "";
          owaspSelect.value = "";
          triageSelect.value = "";
          this._renderFindingsTable();
        },
      },
    });

    const findingsFilterBar = el("div", { class: "filter-bar" }, [
      searchInput,
      severitySelect,
      owaspSelect,
      triageSelect,
      resetBtn,
    ]);

    const findingsTableHost = el("div", { class: "table-wrap" });
    const findingsPanel = el("div", { class: this._activeTab === "findings" ? "" : "hidden", hidden: this._activeTab !== "findings" }, [
      findingsFilterBar,
      findingsTableHost,
    ]);

    // Endpoints Filter Bar & Table
    const endpointSearch = el("input", {
      type: "search",
      class: "form-input filter-search",
      placeholder: "Filter endpoints by URL, method, parameter, or source...",
      value: this._endpointQuery,
      "aria-label": "Search discovered endpoints",
      on: {
        input: (e) => {
          this._endpointQuery = e.target.value;
          this._renderEndpointsTable();
        },
      },
    });

    const endpointsTableHost = el("div", { class: "table-wrap" });
    const endpointsPanel = el(
      "div",
      { class: this._activeTab === "endpoints" ? "" : "hidden", hidden: this._activeTab !== "endpoints" },
      [el("div", { class: "filter-bar" }, [endpointSearch]), endpointsTableHost],
    );

    const explorerCard = el("div", { class: "card" }, [
      el("div", { class: "card-header" }, [
        el("div", { class: "tabs", role: "tablist" }, [findingsTabBtn, endpointsTabBtn]),
        countSummary,
      ]),
      findingsPanel,
      endpointsPanel,
    ]);

    this._refs = {
      scanSelect,
      gaugeHost,
      donutHost,
      owaspHost,
      findingsTabBtn,
      endpointsTabBtn,
      findingsPanel,
      endpointsPanel,
      findingsTableHost,
      endpointsTableHost,
      countSummary,
      resetBtn,
    };

    this._container.appendChild(toolbarCard);
    this._container.appendChild(analyticsStrip);
    this._container.appendChild(explorerCard);

    this._populateScanSelect();
    renderRiskGauge(gaugeHost, scan.risk_score);
    renderSeverityDonut(donutHost, scan.summary);
    renderOwaspBarChart(owaspHost, this._findings);
    this._renderFindingsTable();
    this._renderEndpointsTable();
  }

  _populateScanSelect() {
    if (!this._refs?.scanSelect) return;
    const select = this._refs.scanSelect;
    clear(select);

    for (const scan of this._scans) {
      const proj = scan.project_name || `Project ${shortId(scan.project_id)}`;
      const profile = String(scan.profile || "standard").toUpperCase();
      const status = String(scan.status || "queued");
      const statusDisplay = status.charAt(0).toUpperCase() + status.slice(1);
      const risk =
        scan.risk_score !== null && scan.risk_score !== undefined
          ? `Risk ${scan.risk_score}/100`
          : "Risk —";
      select.appendChild(
        el("option", {
          value: scan.id,
          text: `${proj} · #${shortId(scan.id)}`,
          "data-badge": profile,
          "data-sub": `${risk} · ${statusDisplay} · ${formatDate(scan.created_at || scan.started_at)}`,
          selected: scan.id === this._scanId,
        }),
      );
    }
  }

  _switchTab(tab) {
    this._activeTab = tab;
    if (!this._refs) return;

    const showFindings = tab === "findings";
    this._refs.findingsTabBtn.classList.toggle("active", showFindings);
    this._refs.endpointsTabBtn.classList.toggle("active", !showFindings);

    this._refs.findingsPanel.classList.toggle("hidden", !showFindings);
    this._refs.findingsPanel.hidden = !showFindings;
    this._refs.endpointsPanel.classList.toggle("hidden", showFindings);
    this._refs.endpointsPanel.hidden = showFindings;

    if (showFindings) {
      this._renderFindingsTable();
    } else {
      this._renderEndpointsTable();
    }
  }

  _getFilteredFindings() {
    const q = this._filters.q.trim().toLowerCase();
    const sev = this._filters.severity.trim().toLowerCase();
    const owasp = this._filters.owasp.trim().toLowerCase();
    const triage = this._filters.triage_status.trim().toLowerCase();

    return this._findings.filter((f) => {
      if (sev && String(f.severity || "").toLowerCase() !== sev) return false;
      if (owasp && !String(f.owasp_category || "").toLowerCase().includes(owasp)) return false;
      if (triage && String(f.triage_status || "open").toLowerCase() !== triage) return false;
      if (q) {
        const haystack = [
          f.title,
          f.endpoint_url,
          f.parameter,
          f.check_id,
          f.cwe_id,
          f.owasp_category,
          f.method,
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });
  }

  _renderFindingsTable() {
    if (!this._refs?.findingsTableHost) return;
    const host = this._refs.findingsTableHost;
    clear(host);

    const filtered = this._getFilteredFindings();
    if (this._activeTab === "findings") {
      this._refs.countSummary.textContent = `Showing ${filtered.length} of ${this._findings.length} findings`;
    }

    const hasActiveFilters = Boolean(
      this._filters.q || this._filters.severity || this._filters.owasp || this._filters.triage_status,
    );
    this._refs.resetBtn.disabled = !hasActiveFilters;

    if (filtered.length === 0) {
      host.appendChild(
        el("div", { class: "empty-state" }, [
          el("h4", {
            class: "empty-state-title",
            text: this._findings.length === 0 ? "No Vulnerabilities Detected" : "No Matching Findings",
          }),
          el("p", {
            class: "empty-state-desc",
            text:
              this._findings.length === 0
                ? "This scan finished cleanly with zero reported OWASP Top 10 findings."
                : "Try clearing or broadening your search, severity, OWASP, or triage filters.",
          }),
        ]),
      );
      return;
    }

    const tbody = el(
      "tbody",
      null,
      filtered.map((finding) => {
        const openModal = () => {
          if (typeof this._callbacks.onOpenFinding === "function") {
            this._callbacks.onOpenFinding(finding.id, { scan: this._scan, finding });
          }
        };

        const owaspShort = String(finding.owasp_category || "").split(" - ")[0] || "OWASP";
        const pathDisplay = formatEndpointPath(finding.endpoint_url);

        return el("tr", null, [
          el("td", null, [severityBadge(finding.severity)]),
          el("td", null, [
            el("div", { class: "stack", style: { gap: "3px" } }, [
              el("span", {
                class: "mono text-xs",
                style: { fontWeight: "700", color: "var(--text-primary)" },
                text: owaspShort,
                title: finding.owasp_category || "",
              }),
              el("span", {
                class: "mono text-xs text-muted",
                text: finding.cwe_id || "—",
              }),
            ]),
          ]),
          el("td", null, [
            el("button", {
              type: "button",
              class: "btn btn-ghost btn-sm",
              text: finding.title || "Untitled Finding",
              style: {
                padding: "0",
                textAlign: "left",
                whiteSpace: "normal",
                color: "var(--text-primary)",
                fontWeight: "600",
              },
              on: { click: openModal },
            }),
          ]),
          el("td", null, [
            el(
              "div",
              {
                class: "row",
                style: { gap: "6px", flexWrap: "wrap" },
              },
              [
                el("span", {
                  class: methodBadgeClass(finding.method),
                  text: String(finding.method || "GET").toUpperCase(),
                }),
                el("span", {
                  class: "mono text-xs truncate",
                  text: pathDisplay,
                  title: finding.endpoint_url || "",
                  style: { maxWidth: "240px", color: "var(--text-secondary)" },
                }),
                finding.parameter
                  ? el("span", {
                      class: "badge badge-neutral mono",
                      text: `param: ${finding.parameter}`,
                    })
                  : null,
              ],
            ),
          ]),
          el("td", null, [confidenceBadge(finding.confidence)]),
          el("td", null, [renderTriageBadgeSafe(finding.triage_status)]),
          el("td", null, [
            el("button", {
              type: "button",
              class: "btn btn-primary btn-sm",
              text: "View Fix",
              on: { click: openModal },
            }),
          ]),
        ]);
      }),
    );

    const table = el("table", { class: "data-table" }, [
      el("thead", null, [
        el("tr", null, [
          el("th", { text: "Severity" }),
          el("th", { text: "OWASP / CWE" }),
          el("th", { text: "Title" }),
          el("th", { text: "Exact Endpoint" }),
          el("th", { text: "Confidence" }),
          el("th", { text: "Triage" }),
          el("th", { text: "Remediation" }),
        ]),
      ]),
      tbody,
    ]);

    host.appendChild(table);
  }

  _renderEndpointsTable() {
    if (!this._refs?.endpointsTableHost) return;
    const host = this._refs.endpointsTableHost;
    clear(host);

    const needle = this._endpointQuery.trim().toLowerCase();
    const filtered = needle
      ? this._endpoints.filter((ep) => {
          const hay = [
            ep.method,
            ep.url,
            ep.source,
            String(ep.status_code || ""),
            ...(Array.isArray(ep.params) ? ep.params : []),
          ]
            .join(" ")
            .toLowerCase();
          return hay.includes(needle);
        })
      : this._endpoints;

    if (this._activeTab === "endpoints") {
      this._refs.countSummary.textContent = `Showing ${filtered.length} of ${this._endpoints.length} endpoints`;
    }

    if (filtered.length === 0) {
      host.appendChild(
        el("div", { class: "empty-state" }, [
          el("h4", { class: "empty-state-title", text: "No Endpoints Found" }),
          el("p", {
            class: "empty-state-desc",
            text:
              this._endpoints.length === 0
                ? "No in-scope endpoints were recorded for this scan."
                : "No discovered endpoints match your current search filter.",
          }),
        ]),
      );
      return;
    }

    const tbody = el(
      "tbody",
      null,
      filtered.map((ep) => {
        const params = Array.isArray(ep.params) ? ep.params.filter(Boolean) : [];
        const paramsCell =
          params.length > 0
            ? el(
                "div",
                { class: "row", style: { gap: "4px" } },
                params.map((p) => el("span", { class: "badge badge-neutral mono", text: p })),
              )
            : el("span", { class: "text-muted", text: "—" });

        return el("tr", null, [
          el("td", null, [
            el("span", {
              class: methodBadgeClass(ep.method),
              text: String(ep.method || "GET").toUpperCase(),
            }),
          ]),
          el("td", null, [
            el("span", {
              class: "mono text-xs",
              text: ep.url || "—",
              style: { wordBreak: "break-all", color: "var(--text-primary)" },
            }),
          ]),
          el("td", null, [paramsCell]),
          el("td", null, [
            el("span", {
              class: "badge badge-neutral",
              text: ep.source || "crawl",
            }),
          ]),
          el("td", null, [httpStatusBadge(ep.status_code)]),
        ]);
      }),
    );

    const table = el("table", { class: "data-table" }, [
      el("thead", null, [
        el("tr", null, [
          el("th", { text: "Method" }),
          el("th", { text: "URL" }),
          el("th", { text: "Parameters" }),
          el("th", { text: "Source" }),
          el("th", { text: "Status Code" }),
        ]),
      ]),
      tbody,
    ]);

    host.appendChild(table);
  }
}
