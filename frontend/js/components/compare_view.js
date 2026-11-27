/**
 * View 6 — Compare Scans (Fingerprint-Based Regression Diff) component (#view-compare).
 * Compares Base vs. Head scan into New, Fixed, and Unchanged columns with FixModal integration.
 */

import { compareScans } from "../api.js";
import {
  clear,
  el,
  formatDate,
  severityBadge,
  shortId,
  showToast,
  triageBadge,
} from "../utils.js";

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

function buildScanOptionMeta(scan) {
  const proj = scan.project_name || `Project ${shortId(scan.project_id)}`;
  const profile = String(scan.profile || "standard").toUpperCase();
  const status = String(scan.status || "queued");
  const statusDisplay = status.charAt(0).toUpperCase() + status.slice(1);
  const risk =
    scan.risk_score !== null && scan.risk_score !== undefined
      ? `Risk ${scan.risk_score}/100`
      : "Risk —";
  return {
    title: `${proj} · #${shortId(scan.id)}`,
    badge: profile,
    sub: `${risk} · ${statusDisplay} · ${formatDate(scan.created_at || scan.started_at)}`,
  };
}

export class CompareScansView {
  /**
   * @param {HTMLElement | null} container
   * @param {{
   *   onOpenFinding?: (findingId: string, context?: any) => void,
   *   onLaunchNew?: () => void,
   * }} [callbacks]
   */
  constructor(container, callbacks = {}) {
    this._container = container || document.getElementById("view-compare");
    this._callbacks = callbacks || {};
    this._scans = [];
    this._baseId = "";
    this._headId = "";
    this._result = null;
    this._loading = false;
    this._error = null;
    this._requestToken = 0;
  }

  _selectDefaultPair() {
    this._headId = this._scans[0]?.id || "";
    const headScan = this._scans.find((s) => s.id === this._headId);
    const sameProjectOlder = headScan
      ? this._scans.find((s) => s.id !== headScan.id && s.project_id === headScan.project_id)
      : null;
    const anyDifferent = this._scans.find((s) => s.id !== this._headId);
    this._baseId = sameProjectOlder?.id || anyDifferent?.id || this._headId;
  }

  /**
   * Supply available scans and pre-select sensible Base (older) and Head (newer) defaults.
   * @param {Array<Record<string, any>>} scans
   */
  setScans(scans) {
    this._scans = Array.isArray(scans) ? [...scans] : [];
    const ids = new Set(this._scans.map((s) => s.id));

    if (!ids.has(this._headId) || !ids.has(this._baseId)) {
      this._selectDefaultPair();
    }

    this.render();
  }

  /** Clear active comparison results, errors, and restore default Base/Head selection. */
  reset() {
    this._requestToken += 1;
    this._result = null;
    this._error = null;
    this._loading = false;
    this._selectDefaultPair();
    this.render();
    showToast("Comparison reset.", "info");
  }

  /**
   * Execute fingerprint comparison between two scans.
   * @param {string} baseId
   * @param {string} headId
   */
  async compare(baseId, headId) {
    if (!baseId || !headId) {
      showToast("Select both a Base Scan and a Head Scan to compare.", "warning");
      return;
    }

    this._baseId = baseId;
    this._headId = headId;
    this._loading = true;
    this._error = null;
    const token = ++this._requestToken;
    this.render();

    try {
      const result = await compareScans(baseId, headId);
      if (token !== this._requestToken) return;
      this._result = result;
      this._loading = false;
      this.render();
    } catch (err) {
      if (token !== this._requestToken) return;
      this._loading = false;
      this._error = err?.message || "Failed to compare selected scans.";
      showToast(this._error, "error");
      this.render();
    }
  }

  /** Render the Compare Scans controls, summary badges, and 3 diff columns. */
  render() {
    if (!this._container) return;
    clear(this._container);

    if (this._scans.length < 2) {
      const actions = [];
      if (typeof this._callbacks.onLaunchNew === "function") {
        actions.push(
          el("button", {
            type: "button",
            class: "btn btn-primary",
            text: "Launch Another Scan",
            on: { click: () => this._callbacks.onLaunchNew() },
          }),
        );
      }

      this._container.appendChild(
        el("div", { class: "card" }, [
          el("div", { class: "empty-state" }, [
            el("h3", { class: "empty-state-title", text: "At Least Two Scans Needed to Compare" }),
            el("p", {
              class: "empty-state-desc",
              text: "Run a baseline scan, apply your remediation code fixes, and run a second scan to track New, Fixed, and Unchanged vulnerabilities.",
            }),
            ...actions,
          ]),
        ]),
      );
      return;
    }

    const baseSelect = el(
      "select",
      {
        id: "compare-base-select",
        class: "form-select",
        "aria-label": "Select baseline scan",
        on: {
          change: (e) => {
            this._baseId = e.target.value;
          },
        },
      },
      this._scans.map((scan) => {
        const meta = buildScanOptionMeta(scan);
        return el("option", {
          value: scan.id,
          text: meta.title,
          "data-badge": meta.badge,
          "data-sub": meta.sub,
          selected: scan.id === this._baseId,
        });
      }),
    );

    const headSelect = el(
      "select",
      {
        id: "compare-head-select",
        class: "form-select",
        "aria-label": "Select head scan",
        on: {
          change: (e) => {
            this._headId = e.target.value;
          },
        },
      },
      this._scans.map((scan) => {
        const meta = buildScanOptionMeta(scan);
        return el("option", {
          value: scan.id,
          text: meta.title,
          "data-badge": meta.badge,
          "data-sub": meta.sub,
          selected: scan.id === this._headId,
        });
      }),
    );

    const resetBtn = el("button", {
      id: "compare-reset-btn",
      type: "button",
      class: "btn btn-ghost",
      text: "Reset",
      title: "Clear comparison results and reset selected scans",
      on: {
        click: () => this.reset(),
      },
    });

    const swapBtn = el("button", {
      type: "button",
      class: "btn btn-secondary",
      text: "⇄ Swap",
      title: "Swap Base and Head scans",
      on: {
        click: () => {
          const prevBase = this._baseId;
          this._baseId = this._headId;
          this._headId = prevBase;
          this.render();
        },
      },
    });

    const compareBtn = el("button", {
      type: "button",
      class: "btn btn-primary",
      text: this._loading ? "Comparing..." : "Compare Scans",
      disabled: this._loading,
      on: {
        click: () => this.compare(this._baseId, this._headId),
      },
    });

    const sameScanNotice =
      this._baseId && this._baseId === this._headId
        ? el("div", {
            class: "text-xs text-muted",
            style: { marginRight: "auto" },
            text: "Tip: Base and Head currently point to the same scan — choose two different scans to view fixes or regressions.",
          })
        : null;

    const controlsCard = el("div", { class: "card" }, [
      el("div", { class: "card-header" }, [
        el("div", null, [
          el("h3", { class: "card-title", text: "Regression & Fix Verification Diff" }),
          el("p", {
            class: "card-subtitle",
            text: "Compare two scans by finding fingerprint to verify fixed issues and spot newly introduced regressions.",
          }),
        ]),
      ]),
      el("div", { class: "card-body stack" }, [
        el(
          "div",
          {
            style: {
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
              gap: "14px",
              alignItems: "end",
            },
          },
          [
            el("div", { class: "form-group" }, [
              el("label", {
                for: "compare-base-select",
                class: "form-label",
                text: "Base Scan (Before / Baseline)",
              }),
              baseSelect,
            ]),
            el("div", { class: "form-group" }, [
              el("label", {
                for: "compare-head-select",
                class: "form-label",
                text: "Head Scan (After / Target)",
              }),
              headSelect,
            ]),
          ],
        ),
        el(
          "div",
          { class: "row", style: { justifyContent: "flex-end", alignItems: "center" } },
          [sameScanNotice, resetBtn, swapBtn, compareBtn],
        ),
        this._error ? el("div", { class: "form-error", role: "alert", text: this._error }) : null,
      ]),
    ]);

    this._container.appendChild(controlsCard);

    if (this._loading) {
      this._container.appendChild(
        el("div", { class: "card" }, [
          el("div", { class: "empty-state" }, [
            el("p", { class: "empty-state-desc", text: "Computing finding fingerprint diff..." }),
          ]),
        ]),
      );
      return;
    }

    if (!this._result) {
      this._container.appendChild(
        el("div", { class: "card" }, [
          el("div", { class: "empty-state" }, [
            el("h4", { class: "empty-state-title", text: "Ready to Compare" }),
            el("p", {
              class: "empty-state-desc",
              text: "Choose a Base Scan and Head Scan above, then click Compare Scans to inspect New, Fixed, and Unchanged findings.",
            }),
          ]),
        ]),
      );
      return;
    }

    const counts = this._result.counts || {
      new: (this._result.new || []).length,
      fixed: (this._result.fixed || []).length,
      unchanged: (this._result.unchanged || []).length,
    };

    const summaryBar = el("div", { class: "card" }, [
      el("div", { class: "card-body row-between" }, [
        el("div", { class: "row" }, [
          el("span", {
            class: "badge badge-sev-critical",
            style: { padding: "5px 12px", fontSize: "12.5px" },
            text: `New: ${counts.new ?? 0}`,
          }),
          el("span", {
            class: "badge badge-status-completed",
            style: { padding: "5px 12px", fontSize: "12.5px" },
            text: `Fixed: ${counts.fixed ?? 0}`,
          }),
          el("span", {
            class: "badge badge-neutral",
            style: { padding: "5px 12px", fontSize: "12.5px" },
            text: `Unchanged: ${counts.unchanged ?? 0}`,
          }),
        ]),
        el("span", {
          class: "mono text-xs text-muted",
          text: `Base #${shortId(this._result.base_scan_id)} → Head #${shortId(this._result.head_scan_id)}`,
        }),
      ]),
    ]);

    const columnsGrid = el("div", { class: "compare-grid" }, [
      this._buildColumn(
        "New Findings",
        "Introduced in Head scan",
        "badge-sev-critical",
        this._result.new || [],
        "No new vulnerabilities introduced.",
        "compare-col--new",
      ),
      this._buildColumn(
        "Fixed Findings",
        "Resolved since Base scan",
        "badge-status-completed",
        this._result.fixed || [],
        "No baseline findings resolved yet.",
        "compare-col--fixed",
      ),
      this._buildColumn(
        "Unchanged Findings",
        "Present in both scans",
        "badge-neutral",
        this._result.unchanged || [],
        "No overlapping findings between scans.",
        "compare-col--unchanged",
      ),
    ]);

    this._container.appendChild(summaryBar);
    this._container.appendChild(columnsGrid);
  }

  _buildColumn(title, subtitle, badgeClass, findings, emptyMessage, colClass = "") {
    const items = Array.isArray(findings) ? findings : [];

    const bodyContent =
      items.length === 0
        ? [
            el("div", { class: "empty-state", style: { padding: "24px 10px" } }, [
              el("p", { class: "empty-state-desc text-sm", text: emptyMessage }),
            ]),
          ]
        : items.map((finding) => this._buildFindingCard(finding));

    return el("div", { class: `card compare-col ${colClass}`.trim() }, [
      el("div", { class: "card-header" }, [
        el("div", null, [
          el("h4", { class: "card-title", text: title }),
          el("p", { class: "card-subtitle", text: subtitle }),
        ]),
        el("span", { class: `badge ${badgeClass}`, text: String(items.length) }),
      ]),
      el("div", { class: "card-body stack", style: { gap: "10px" } }, bodyContent),
    ]);
  }

  _buildFindingCard(finding) {
    const endpointPath = formatEndpointPath(finding.endpoint_url);
    const owaspShort = String(finding.owasp_category || "").split(" - ")[0] || "";
    const sevSlug = String(finding.severity || "info").trim().toLowerCase();

    return el(
      "button",
      {
        type: "button",
        class: `live-feed-item finding-list-card sev-accent-${sevSlug}`,
        style: {
          flexDirection: "column",
          alignItems: "stretch",
          gap: "8px",
        },
        on: {
          click: () => {
            if (finding.id && typeof this._callbacks.onOpenFinding === "function") {
              this._callbacks.onOpenFinding(finding.id, { finding });
            }
          },
        },
      },
      [
        el("div", { class: "row-between", style: { gap: "6px" } }, [
          el("div", { class: "row", style: { gap: "6px" } }, [
            severityBadge(finding.severity),
            owaspShort ? el("span", { class: "badge badge-neutral mono", text: owaspShort }) : null,
            finding.cwe_id
              ? el("span", { class: "badge badge-neutral mono", text: finding.cwe_id })
              : null,
          ]),
          renderTriageBadgeSafe(finding.triage_status),
        ]),
        el("div", {
          style: {
            fontWeight: "600",
            color: "var(--text-primary)",
            fontSize: "13.5px",
            textAlign: "left",
          },
          text: finding.title || "Untitled Finding",
        }),
        el("div", { class: "row", style: { gap: "6px" } }, [
          el("span", {
            class: methodBadgeClass(finding.method),
            text: String(finding.method || "GET").toUpperCase(),
          }),
          el("span", {
            class: "mono text-xs text-muted truncate",
            text: endpointPath,
            title: finding.endpoint_url || "",
            style: { maxWidth: "100%" },
          }),
          finding.parameter
            ? el("span", {
                class: "badge badge-neutral mono",
                text: `param: ${finding.parameter}`,
              })
            : null,
        ]),
      ],
    );
  }
}
