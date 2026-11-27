/**
 * View 3 — Live Scan Progress & Real-Time Finding Feed component (#view-live).
 * Manages EventSource lifecycle via openScanStream with clean teardown and strict XSS safety.
 */

import { cancelScan, getScan, getScanFindings, openScanStream } from "../api.js";
import {
  clear,
  el,
  formatDate,
  severityBadge,
  shortId,
  showToast,
  statusBadge,
} from "../utils.js";

const TERMINAL_STATUSES = new Set(["completed", "failed", "cancelled"]);

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

function findingCompositeKey(f) {
  const check = String(f?.check_id || "").toLowerCase();
  const method = String(f?.method || "GET").toUpperCase();
  const url = String(f?.endpoint_url || f?.url || "").trim();
  const param = String(f?.parameter || "").trim();
  return `${check}|${method}|${url}|${param}`;
}

export class LiveScanView {
  /**
   * @param {HTMLElement | null} container
   * @param {{
   *   onOpenFinding?: (findingId: string, context?: any) => void,
   *   onViewReport?: (scanId: string) => void,
   *   onScanTerminal?: (scan: any) => void,
   *   onLaunchNew?: () => void,
   * }} [callbacks]
   */
  constructor(container, callbacks = {}) {
    this._container = container || document.getElementById("view-live");
    this._callbacks = callbacks || {};
    this._scanId = null;
    this._scan = null;
    this._stream = null;
    this._feedItems = [];
    this._currentCheck = "";
    this._loadToken = 0;
    this._cancelling = false;
    this._refs = null;
  }

  /** @returns {string | null} */
  getCurrentScanId() {
    return this._scanId;
  }

  /** @returns {boolean} */
  isStreaming() {
    return this._stream !== null;
  }

  /** Cleanly close any active EventSource connection. */
  disconnect() {
    if (this._stream) {
      this._stream.close();
      this._stream = null;
    }
  }

  /** Alias for clean teardown on view switch or unmount. */
  destroy() {
    this.disconnect();
    this._loadToken += 1;
  }

  /** Render an informative empty state when no scan is currently selected. */
  renderEmpty() {
    this.disconnect();
    this._scanId = null;
    this._scan = null;
    this._feedItems = [];
    this._refs = null;

    if (!this._container) return;
    clear(this._container);

    const actions = [];
    if (typeof this._callbacks.onLaunchNew === "function") {
      actions.push(
        el("button", {
          type: "button",
          class: "btn btn-primary",
          text: "Launch a New Scan",
          on: { click: () => this._callbacks.onLaunchNew() },
        }),
      );
    }

    this._container.appendChild(
      el("div", { class: "card" }, [
        el("div", { class: "empty-state" }, [
          el("h3", { class: "empty-state-title", text: "No Active Scan Selected" }),
          el("p", {
            class: "empty-state-desc",
            text: "Start a scan from the Scan Launcher or select a recent scan from Overview to stream live progress and findings.",
          }),
          ...actions,
        ]),
      ]),
    );
  }

  /**
   * Load and monitor a scan by ID, opening an SSE stream if the scan is in progress.
   * @param {string} scanId
   * @param {Record<string, any> | null} [initialScan]
   */
  async load(scanId, initialScan = null) {
    if (!scanId) {
      this.renderEmpty();
      return;
    }

    this.disconnect();
    const token = ++this._loadToken;
    this._scanId = scanId;
    this._scan = initialScan ? { ...initialScan } : null;
    this._feedItems = [];
    this._currentCheck = initialScan?.current_stage || "";
    this._cancelling = false;

    if (this._scan) {
      this._buildShell();
      this._syncDisplay();
    } else if (this._container) {
      clear(this._container);
      this._container.appendChild(
        el("div", { class: "card" }, [
          el("div", { class: "empty-state" }, [
            el("p", { class: "empty-state-desc", text: "Connecting to scan telemetry..." }),
          ]),
        ]),
      );
    }

    let scan;
    try {
      scan = await getScan(scanId);
    } catch (err) {
      if (token !== this._loadToken) return;
      showToast(err?.message || "Failed to load scan details.", "error");
      this.renderEmpty();
      return;
    }

    if (token !== this._loadToken) return;
    this._scan = scan;
    this._currentCheck =
      scan.status === "scanning" && scan.current_stage !== "scanning" ? scan.current_stage : "";
    this._buildShell();
    this._syncDisplay();

    const normalizedStatus = String(scan.status || "").toLowerCase();
    if (TERMINAL_STATUSES.has(normalizedStatus)) {
      await this._loadPersistedFindings(scanId, token);
      return;
    }

    this._connectStream(scanId, token);
  }

  /** Build the persistent DOM structure for live updates without full re-renders. */
  _buildShell() {
    if (!this._container) return;
    clear(this._container);

    const statusSlot = el("span");
    const cancelBtn = el("button", {
      type: "button",
      class: "btn btn-danger btn-sm",
      text: "Cancel Scan",
      on: { click: () => this._handleCancel() },
    });
    const reportBtn = el("button", {
      type: "button",
      class: "btn btn-primary btn-sm hidden",
      text: "View Full Report & Fixes",
      hidden: true,
      on: {
        click: () => {
          if (this._scanId && typeof this._callbacks.onViewReport === "function") {
            this._callbacks.onViewReport(this._scanId);
          }
        },
      },
    });

    const headerTitle = el("h3", { class: "card-title" });
    const headerSub = el("p", { class: "card-subtitle mono" });
    const headerMeta = el("div", { class: "row text-xs text-muted", style: { marginTop: "6px" } });

    const headerCard = el("div", { class: "card" }, [
      el("div", { class: "card-header" }, [
        el("div", { style: { minWidth: "0" } }, [headerTitle, headerSub, headerMeta]),
        el("div", { class: "row" }, [statusSlot, cancelBtn, reportBtn]),
      ]),
      el("div", { class: "card-body stack" }, [
        this._buildStepper(),
        this._buildProgressSection(),
      ]),
    ]);

    const kpiPages = el("div", { class: "kpi-value mono", text: "0" });
    const kpiRequests = el("div", { class: "kpi-value mono", text: "0" });
    const kpiCheck = el("div", {
      class: "kpi-value mono truncate",
      text: "—",
      style: { fontSize: "17px", lineHeight: "1.4" },
    });
    const kpiFindings = el("div", { class: "kpi-value mono", text: "0" });

    const kpiGrid = el("div", { class: "kpi-grid" }, [
      el("div", { class: "kpi-card" }, [
        el("span", { class: "kpi-label", text: "Pages Crawled" }),
        kpiPages,
        el("span", { class: "kpi-sub", text: "In-scope HTML & routes" }),
      ]),
      el("div", { class: "kpi-card" }, [
        el("span", { class: "kpi-label", text: "Requests Sent" }),
        kpiRequests,
        el("span", { class: "kpi-sub", text: "Rate-limited probes" }),
      ]),
      el("div", { class: "kpi-card" }, [
        el("span", { class: "kpi-label", text: "Current Check" }),
        kpiCheck,
        el("span", { class: "kpi-sub", text: "Active OWASP module" }),
      ]),
      el("div", { class: "kpi-card" }, [
        el("span", { class: "kpi-label", text: "Findings" }),
        kpiFindings,
        el("span", { class: "kpi-sub", text: "Click any item for code fix" }),
      ]),
    ]);

    const errorBanner = el("div", { class: "form-error hidden", role: "alert", hidden: true });

    const feedCountPill = el("span", { class: "badge badge-neutral", text: "0 detected" });
    const feedList = el("div", { class: "live-feed" });

    const feedCard = el("div", { class: "card" }, [
      el("div", { class: "card-header" }, [
        el("div", null, [
          el("h3", { class: "card-title", text: "Live Finding Feed" }),
          el("p", {
            class: "card-subtitle",
            text: "Vulnerabilities stream here in real time. Click any finding to open before/after code fixes.",
          }),
        ]),
        feedCountPill,
      ]),
      el("div", { class: "card-body" }, [feedList]),
    ]);

    this._refs = {
      headerTitle,
      headerSub,
      headerMeta,
      statusSlot,
      cancelBtn,
      reportBtn,
      stepQueued: this._stepNodes.queued,
      stepCrawling: this._stepNodes.crawling,
      stepScanning: this._stepNodes.scanning,
      stepTerminal: this._stepNodes.terminal,
      stepTerminalLabel: this._stepNodes.terminalLabel,
      progressLabel: this._progressNodes.label,
      progressPct: this._progressNodes.pct,
      progressFill: this._progressNodes.fill,
      kpiPages,
      kpiRequests,
      kpiCheck,
      kpiFindings,
      errorBanner,
      feedCountPill,
      feedList,
    };

    this._container.appendChild(headerCard);
    this._container.appendChild(kpiGrid);
    this._container.appendChild(errorBanner);
    this._container.appendChild(feedCard);

    this._renderFeedList();
  }

  _buildStepper() {
    const makeStep = (indexText, labelText) => {
      const labelNode = el("span", { text: labelText });
      const node = el("div", { class: "stepper-step" }, [
        el("span", {
          class: "mono text-xs",
          text: indexText,
          style: { opacity: "0.8" },
        }),
        labelNode,
      ]);
      return { node, labelNode };
    };

    const s1 = makeStep("01", "Queued");
    const s2 = makeStep("02", "Crawling");
    const s3 = makeStep("03", "Scanning");
    const s4 = makeStep("04", "Completed");

    this._stepNodes = {
      queued: s1.node,
      crawling: s2.node,
      scanning: s3.node,
      terminal: s4.node,
      terminalLabel: s4.labelNode,
    };

    return el("div", { class: "stepper", role: "list", "aria-label": "Scan stages" }, [
      s1.node,
      s2.node,
      s3.node,
      s4.node,
    ]);
  }

  _buildProgressSection() {
    const label = el("span", { class: "text-sm text-secondary", text: "Initializing scan..." });
    const pct = el("span", { class: "mono text-sm", style: { fontWeight: "700" }, text: "0%" });
    const fill = el("div", { class: "progress-fill", style: { width: "0%" } });

    this._progressNodes = { label, pct, fill };

    return el("div", { class: "stack", style: { gap: "6px" } }, [
      el("div", { class: "row-between" }, [label, pct]),
      el(
        "div",
        {
          class: "progress-track",
          role: "progressbar",
          "aria-valuemin": "0",
          "aria-valuemax": "100",
          "aria-valuenow": "0",
        },
        [fill],
      ),
    ]);
  }

  /** Synchronize header, stepper, progress bar, KPIs, and action buttons with current scan state. */
  _syncDisplay() {
    if (!this._refs || !this._scan) return;

    const scan = this._scan;
    const status = String(scan.status || "queued").toLowerCase();
    const isTerminal = TERMINAL_STATUSES.has(status);
    const pct = Math.max(0, Math.min(100, Math.round(Number(scan.progress_pct || 0))));

    const projectLabel = scan.project_name || `Scan ${shortId(scan.id)}`;
    this._refs.headerTitle.textContent = projectLabel;
    this._refs.headerSub.textContent = isTerminal
      ? "Scan session completed"
      : "Live security assessment in progress";

    clear(this._refs.headerMeta);
    this._refs.headerMeta.appendChild(
      el("span", { class: "badge badge-neutral mono", text: `#${shortId(scan.id)}` }),
    );
    this._refs.headerMeta.appendChild(
      el("span", {
        class: "badge badge-stack",
        text: `${String(scan.profile || "standard").toUpperCase()} PROFILE`,
      }),
    );
    this._refs.headerMeta.appendChild(
      el("span", { text: `Started ${formatDate(scan.started_at || scan.created_at)}` }),
    );
    if (scan.finished_at) {
      this._refs.headerMeta.appendChild(
        el("span", { text: `Finished ${formatDate(scan.finished_at)}` }),
      );
    }

    clear(this._refs.statusSlot);
    this._refs.statusSlot.appendChild(statusBadge(status));

    // Action buttons
    if (isTerminal) {
      this._refs.cancelBtn.classList.add("hidden");
      this._refs.cancelBtn.hidden = true;
      this._refs.reportBtn.classList.remove("hidden");
      this._refs.reportBtn.hidden = false;
    } else {
      this._refs.cancelBtn.classList.remove("hidden");
      this._refs.cancelBtn.hidden = false;
      this._refs.cancelBtn.disabled = this._cancelling;
      this._refs.cancelBtn.textContent = this._cancelling ? "Cancelling..." : "Cancel Scan";
      this._refs.reportBtn.classList.add("hidden");
      this._refs.reportBtn.hidden = true;
    }

    // 4-stage stepper classes
    const setStepClass = (node, state) => {
      node.className = state ? `stepper-step ${state}` : "stepper-step";
    };

    if (status === "queued") {
      setStepClass(this._refs.stepQueued, "active");
      setStepClass(this._refs.stepCrawling, "");
      setStepClass(this._refs.stepScanning, "");
      setStepClass(this._refs.stepTerminal, "");
      this._refs.stepTerminalLabel.textContent = "Completed";
    } else if (status === "crawling") {
      setStepClass(this._refs.stepQueued, "done");
      setStepClass(this._refs.stepCrawling, "active");
      setStepClass(this._refs.stepScanning, "");
      setStepClass(this._refs.stepTerminal, "");
      this._refs.stepTerminalLabel.textContent = "Completed";
    } else if (status === "scanning") {
      setStepClass(this._refs.stepQueued, "done");
      setStepClass(this._refs.stepCrawling, "done");
      setStepClass(this._refs.stepScanning, "active");
      setStepClass(this._refs.stepTerminal, "");
      this._refs.stepTerminalLabel.textContent = "Completed";
    } else if (status === "completed") {
      setStepClass(this._refs.stepQueued, "done");
      setStepClass(this._refs.stepCrawling, "done");
      setStepClass(this._refs.stepScanning, "done");
      setStepClass(this._refs.stepTerminal, "done");
      this._refs.stepTerminalLabel.textContent = "Completed";
    } else if (status === "cancelled") {
      setStepClass(this._refs.stepQueued, "done");
      setStepClass(this._refs.stepCrawling, "done");
      setStepClass(this._refs.stepScanning, "done");
      setStepClass(this._refs.stepTerminal, "error");
      this._refs.stepTerminalLabel.textContent = "Cancelled";
    } else {
      setStepClass(this._refs.stepQueued, "done");
      setStepClass(this._refs.stepCrawling, "done");
      setStepClass(this._refs.stepScanning, "done");
      setStepClass(this._refs.stepTerminal, "error");
      this._refs.stepTerminalLabel.textContent = "Failed";
    }

    // Progress bar
    const effectivePct = status === "completed" ? 100 : pct;
    this._refs.progressPct.textContent = `${effectivePct}%`;
    this._refs.progressFill.style.width = `${effectivePct}%`;
    if (this._refs.progressFill.parentElement) {
      this._refs.progressFill.parentElement.setAttribute("aria-valuenow", String(effectivePct));
    }

    let stageLabel = "Waiting in worker queue...";
    if (status === "crawling") {
      stageLabel = "Discovering in-scope pages, links, and forms...";
    } else if (status === "scanning") {
      stageLabel = this._currentCheck
        ? `Running OWASP check: ${this._currentCheck}`
        : "Executing security checks across discovered endpoints...";
    } else if (status === "completed") {
      stageLabel = `Scan completed — Risk Score ${scan.risk_score ?? 0}/100`;
    } else if (status === "cancelled") {
      stageLabel = "Scan cancelled by operator (partial results preserved).";
    } else if (status === "failed") {
      stageLabel = "Scan failed — inspect error details below.";
    }
    this._refs.progressLabel.textContent = stageLabel;

    // KPI counters
    this._refs.kpiPages.textContent = String(scan.pages_crawled ?? 0);
    this._refs.kpiRequests.textContent = String(scan.requests_sent ?? 0);
    const checkDisplay = isTerminal
      ? status.toUpperCase()
      : this._currentCheck || scan.current_stage || status;
    this._refs.kpiCheck.textContent = checkDisplay;
    this._refs.kpiCheck.title = checkDisplay;

    const summaryTotal = scan.summary
      ? Object.values(scan.summary).reduce((acc, v) => acc + Number(v || 0), 0)
      : 0;
    const findingsCount = Math.max(this._feedItems.length, summaryTotal);
    this._refs.kpiFindings.textContent = String(findingsCount);
    this._refs.feedCountPill.textContent = `${findingsCount} detected`;

    // Errors list
    const errors = Array.isArray(scan.errors) ? scan.errors.filter(Boolean) : [];
    if (errors.length > 0) {
      clear(this._refs.errorBanner);
      this._refs.errorBanner.appendChild(
        el("strong", { text: `Scan Warnings / Errors (${errors.length}): ` }),
      );
      this._refs.errorBanner.appendChild(el("span", { text: errors.join(" · ") }));
      this._refs.errorBanner.classList.remove("hidden");
      this._refs.errorBanner.hidden = false;
    } else {
      this._refs.errorBanner.classList.add("hidden");
      this._refs.errorBanner.hidden = true;
    }
  }

  /** Subscribe to SSE events for an active scan. */
  _connectStream(scanId, token) {
    this.disconnect();
    this._stream = openScanStream(scanId, {
      onProgress: (evt) => {
        if (token !== this._loadToken || !this._scan) return;
        this._scan.status = evt.status || this._scan.status;
        this._scan.current_stage = evt.stage || this._scan.current_stage;
        if (evt.percent !== undefined && evt.percent !== null) {
          this._scan.progress_pct = Number(evt.percent);
        }
        if (evt.pages_crawled !== undefined) {
          this._scan.pages_crawled = Number(evt.pages_crawled);
        }
        if (evt.requests_sent !== undefined) {
          this._scan.requests_sent = Number(evt.requests_sent);
        }
        this._currentCheck = evt.current_check || (evt.stage === "crawling" ? "crawler" : "");
        this._syncDisplay();
      },
      onFinding: (finding) => {
        if (token !== this._loadToken || !finding) return;
        const normalized = {
          id: finding.id || null,
          check_id: finding.check_id || "",
          severity: finding.severity || "info",
          title: finding.title || "Security Finding",
          endpoint_url: finding.endpoint_url || finding.url || "",
          method: (finding.method || "GET").toUpperCase(),
          parameter: finding.parameter || null,
        };
        const key = findingCompositeKey(normalized);
        const alreadyExists = this._feedItems.some(
          (item) =>
            (normalized.id && item.id === normalized.id) || findingCompositeKey(item) === key,
        );
        if (!alreadyExists) {
          this._feedItems.unshift(normalized);
          this._renderFeedList();
          this._syncDisplay();
        }
      },
      onStatus: async (evt) => {
        if (token !== this._loadToken) return;
        this._stream = null;
        if (this._scan) {
          this._scan.status = evt.status || this._scan.status;
          if (evt.risk_score !== undefined) this._scan.risk_score = Number(evt.risk_score);
          if (evt.summary) this._scan.summary = evt.summary;
          if (evt.pages_crawled !== undefined) this._scan.pages_crawled = Number(evt.pages_crawled);
          if (evt.requests_sent !== undefined) this._scan.requests_sent = Number(evt.requests_sent);
          if (Array.isArray(evt.errors)) this._scan.errors = evt.errors;
          if (String(evt.status || "").toLowerCase() === "completed") {
            this._scan.progress_pct = 100;
          }
        }
        this._currentCheck = "";
        this._syncDisplay();

        // Fetch authoritative persisted scan & findings (attaches DB IDs for FixModal)
        try {
          const freshScan = await getScan(scanId);
          if (token !== this._loadToken) return;
          this._scan = freshScan;
          this._syncDisplay();
        } catch (_err) {
          // Keep SSE snapshot if refresh fails transiently.
        }

        await this._loadPersistedFindings(scanId, token);

        if (token !== this._loadToken) return;
        const finalStatus = String(this._scan?.status || evt.status || "").toLowerCase();
        if (finalStatus === "completed") {
          showToast("Scan completed! Click any finding or open the full report.", "success");
        } else if (finalStatus === "cancelled") {
          showToast("Scan cancelled.", "warning");
        } else if (finalStatus === "failed") {
          showToast("Scan finished with errors.", "error");
        }

        if (typeof this._callbacks.onScanTerminal === "function" && this._scan) {
          this._callbacks.onScanTerminal(this._scan);
        }
      },
      onError: () => {
        if (token !== this._loadToken) return;
        // EventSource may emit transient error when closing or reconnecting; check DB state once.
        const status = String(this._scan?.status || "").toLowerCase();
        if (TERMINAL_STATUSES.has(status)) {
          this.disconnect();
        }
      },
    });
  }

  /** Fetch persisted findings so every feed item has a real DB UUID for FixModal. */
  async _loadPersistedFindings(scanId, token) {
    try {
      const persisted = await getScanFindings(scanId);
      if (token !== this._loadToken) return;
      this._feedItems = Array.isArray(persisted) ? persisted : [];
      this._renderFeedList();
      this._syncDisplay();
    } catch (_err) {
      // Non-fatal: keep any live streamed items already displayed.
    }
  }

  /** Request cooperative cancellation of the running scan. */
  async _handleCancel() {
    if (!this._scanId || this._cancelling) return;
    this._cancelling = true;
    this._syncDisplay();
    try {
      const updated = await cancelScan(this._scanId);
      this._scan = updated;
      showToast("Cancellation requested for active scan.", "warning");
      this._syncDisplay();
    } catch (err) {
      showToast(err?.message || "Failed to cancel scan.", "error");
    } finally {
      this._cancelling = false;
      this._syncDisplay();
    }
  }

  /** Open FixModal when clicking a finding item in the live feed. */
  async _handleFindingClick(item) {
    if (!item) return;
    if (item.id) {
      if (typeof this._callbacks.onOpenFinding === "function") {
        this._callbacks.onOpenFinding(item.id, { scan: this._scan, finding: item });
      }
      return;
    }

    // Attempt to resolve persisted ID if scan just finished
    if (this._scanId) {
      try {
        const persisted = await getScanFindings(this._scanId);
        const key = findingCompositeKey(item);
        const match = (persisted || []).find((f) => findingCompositeKey(f) === key);
        if (match?.id) {
          this._feedItems = persisted;
          this._renderFeedList();
          if (typeof this._callbacks.onOpenFinding === "function") {
            this._callbacks.onOpenFinding(match.id, { scan: this._scan, finding: match });
          }
          return;
        }
      } catch (_err) {
        // Fall through to toast below.
      }
    }

    showToast("Full remediation code unlocks as soon as the scan completes.", "info");
  }

  /** Render the clickable real-time finding feed list. */
  _renderFeedList() {
    if (!this._refs?.feedList) return;
    const listEl = this._refs.feedList;
    clear(listEl);

    if (this._feedItems.length === 0) {
      const status = String(this._scan?.status || "queued").toLowerCase();
      const emptyText = TERMINAL_STATUSES.has(status)
        ? "No security vulnerabilities were reported during this scan."
        : "Listening for real-time findings as OWASP checks execute...";
      listEl.appendChild(
        el("div", { class: "empty-state", style: { padding: "24px 12px" } }, [
          el("p", { class: "empty-state-desc", text: emptyText }),
        ]),
      );
      return;
    }

    for (const item of this._feedItems) {
      const endpointText = formatEndpointPath(item.endpoint_url || item.url);
      const paramChip = item.parameter
        ? el("span", {
            class: "badge badge-neutral mono",
            text: `param: ${item.parameter}`,
          })
        : null;

      const rowBtn = el(
        "button",
        {
          type: "button",
          class: "live-feed-item",
          on: { click: () => this._handleFindingClick(item) },
        },
        [
          el(
            "div",
            {
              style: {
                display: "flex",
                alignItems: "center",
                gap: "10px",
                minWidth: "0",
                flex: "1",
                flexWrap: "wrap",
              },
            },
            [
              severityBadge(item.severity),
              el("span", {
                style: {
                  fontWeight: "600",
                  color: "var(--text-primary)",
                },
                text: item.title || "Untitled Finding",
              }),
              el("span", {
                class: methodBadgeClass(item.method),
                text: String(item.method || "GET").toUpperCase(),
              }),
              el("span", {
                class: "mono text-xs text-muted truncate",
                text: endpointText,
                title: item.endpoint_url || item.url || "",
                style: { maxWidth: "360px" },
              }),
              paramChip,
            ],
          ),
          el("span", {
            class: "text-xs",
            style: {
              color: item.id ? "var(--accent-primary)" : "var(--text-muted)",
              fontWeight: "600",
              flexShrink: "0",
            },
            text: item.id ? "View Fix →" : "Live...",
          }),
        ],
      );

      listEl.appendChild(rowBtn);
    }
  }
}
