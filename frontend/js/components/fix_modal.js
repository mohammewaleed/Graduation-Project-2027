/**
 * View 5 — Actionable Code Fix & Developer Triage Modal (#fix-modal / #fix-modal-body).
 * Renders multi-stack Before vs. After remediation code, escaped HTTP evidence,
 * safe OWASP references, and live triage updates with strict XSS & CSP safety.
 */

import { getFinding, triageFinding } from "../api.js";
import {
  clear,
  copyToClipboard,
  el,
  isSafeHttpUrl,
  severityBadge,
  showToast,
  triageBadge,
} from "../utils.js";

const CANONICAL_STACKS = [
  { key: "fastapi", label: "FastAPI" },
  { key: "flask", label: "Flask" },
  { key: "express", label: "Express" },
  { key: "php", label: "PHP" },
  { key: "html", label: "HTML" },
];

const STACK_LABEL_MAP = Object.fromEntries(CANONICAL_STACKS.map((s) => [s.key, s.label]));

const STACK_FILENAME_MAP = {
  fastapi: "app.py",
  flask: "app.py",
  express: "server.js",
  php: "index.php",
  html: "index.html",
};

const CTRL_KEYWORDS = new Set([
  "import", "from", "as", "return", "if", "elif", "else", "for", "while",
  "try", "except", "finally", "raise", "with", "await", "yield", "break",
  "continue", "pass", "throw", "catch", "export", "default", "switch", "case",
  "require", "include", "use",
]);

const DECL_KEYWORDS = new Set([
  "def", "async", "class", "lambda", "del", "in", "is", "not", "and", "or",
  "None", "True", "False", "const", "let", "var", "function", "new", "typeof",
  "true", "false", "null", "undefined", "echo", "public", "private", "protected",
  "static", "On", "Off",
]);

const CODE_TOKEN_RE =
  /(#[^\n]*|\/\/[^\n]*|\/\*.*?\*\/|<!--.*?-->|^\s*;[^\n]*)|(<\?php|\?>)|(@[A-Za-z_][A-Za-z0-9_.]*)|((?:[fFrRbBuU]{0,2})(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`))|(\$[A-Za-z_][A-Za-z0-9_]*)|(\b\d+(?:\.\d+)?\b)|(\b[A-Za-z_][A-Za-z0-9_]*(?=\s*\())|(\b[A-Za-z_][A-Za-z0-9_]*\b)/g;

const HTML_TOKEN_RE =
  /(<!--.*?-->)|(<\/?[A-Za-z][A-Za-z0-9:-]*|\/?>)|("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|(\b[A-Za-z_:][A-Za-z0-9_.:-]*(?=\s*=))/g;

function snippetFilename(stackKey, language) {
  const s = String(stackKey || "").trim().toLowerCase();
  if (STACK_FILENAME_MAP[s]) return STACK_FILENAME_MAP[s];
  const lang = String(language || "").trim().toLowerCase();
  const map = {
    python: "app.py",
    javascript: "server.js",
    typescript: "server.ts",
    php: "index.php",
    html: "index.html",
  };
  return map[lang] || "snippet.txt";
}

function buildTokenizedLineNodes(line, language) {
  if (!line) {
    return [el("span", { class: "tok-plain", text: " " })];
  }
  const lang = String(language || "").trim().toLowerCase();
  const isHtml = lang === "html" || lang === "xml";
  const regex = new RegExp(isHtml ? HTML_TOKEN_RE.source : CODE_TOKEN_RE.source, "g");
  const nodes = [];
  let pos = 0;
  let match;

  while ((match = regex.exec(line)) !== null) {
    if (match.index > pos) {
      nodes.push(el("span", { class: "tok-plain", text: line.slice(pos, match.index) }));
    }
    const text = match[0];
    let cls = "tok-plain";
    if (isHtml) {
      if (match[1]) cls = "tok-comment";
      else if (match[2]) cls = "tok-tag";
      else if (match[3]) cls = "tok-str";
      else if (match[4]) cls = "tok-attr";
    } else {
      if (match[1]) cls = "tok-comment";
      else if (match[2]) cls = "tok-kw";
      else if (match[3]) cls = "tok-dec";
      else if (match[4]) cls = "tok-str";
      else if (match[5]) cls = "tok-attr";
      else if (match[6]) cls = "tok-num";
      else if (match[7]) {
        if (CTRL_KEYWORDS.has(text)) cls = "tok-ctrl";
        else if (DECL_KEYWORDS.has(text)) cls = "tok-kw";
        else cls = "tok-fn";
      } else if (match[8]) {
        if (CTRL_KEYWORDS.has(text)) cls = "tok-ctrl";
        else if (DECL_KEYWORDS.has(text)) cls = "tok-kw";
      }
    }
    nodes.push(el("span", { class: cls, text }));
    pos = match.index + text.length;
  }

  if (pos < line.length) {
    nodes.push(el("span", { class: "tok-plain", text: line.slice(pos) }));
  }
  return nodes;
}

function buildVsCodeEditor(code, language, lineDiffs = null) {
  const rawLines = String(code || "").split(/\r?\n/);
  const lines = rawLines.length > 0 ? rawLines : [""];
  const lineNodes = lines.map((line, idx) => {
    const diffKind = lineDiffs ? lineDiffs[idx] || "ctx" : "ctx";
    const marker = diffKind === "del" ? "-" : diffKind === "add" ? "+" : " ";
    return el("div", { class: `vscode-line diff-${diffKind}` }, [
      el("span", { class: "vscode-ln", text: String(idx + 1) }),
      el("span", { class: "vscode-marker", text: marker }),
      el("span", { class: "vscode-code" }, buildTokenizedLineNodes(line, language)),
    ]);
  });
  return el("div", { class: "vscode-editor" }, [
    el("div", { class: "vscode-lines" }, lineNodes),
  ]);
}

function computeLineDiffs(beforeCode, afterCode) {
  const beforeLines = String(beforeCode || "").split(/\r?\n/);
  const afterLines = String(afterCode || "").split(/\r?\n/);
  const beforeSet = new Set(beforeLines.map((l) => l.trim()).filter(Boolean));
  const afterSet = new Set(afterLines.map((l) => l.trim()).filter(Boolean));

  const beforeDiffs = beforeLines.map((line) => {
    const trimmed = line.trim();
    return trimmed && !afterSet.has(trimmed) ? "del" : "ctx";
  });
  const afterDiffs = afterLines.map((line) => {
    const trimmed = line.trim();
    return trimmed && !beforeSet.has(trimmed) ? "add" : "ctx";
  });
  return { beforeDiffs, afterDiffs };
}

function formatReferenceCardMeta(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    const host = (parsed.hostname || "").replace(/^www\./, "");
    const parts = (parsed.pathname || "").split("/").filter(Boolean);
    const rawSlug = parts[parts.length - 1] || host;
    const slug = rawSlug.replace(/\.(html?|php|md)$/i, "");
    const hash = parsed.hash ? parsed.hash.replace(/^#/, "").replace(/[-_]+/g, " ") : "";
    const pretty = slug.replace(/[-_]+/g, " ").trim();
    const fullLabel = hash ? `${pretty} — ${hash}` : pretty;

    let title = fullLabel || host;
    let category = "Security Guide";
    if (host.includes("cheatsheetseries.owasp.org")) {
      title = fullLabel.toLowerCase().startsWith("owasp") ? fullLabel : `OWASP ${fullLabel}`;
      category = "Cheat Sheet";
    } else if (host.includes("owasp.org") && parsed.pathname.toLowerCase().includes("top10")) {
      title = `OWASP Top 10 — ${fullLabel}`;
      category = "OWASP Top 10";
    } else if (host.includes("developer.mozilla.org")) {
      title = `MDN Web Docs — ${fullLabel}`;
      category = "MDN Docs";
    } else if (host.includes("cwe.mitre.org")) {
      title = `MITRE CWE — ${fullLabel}`;
      category = "CWE Reference";
    }
    return { url: rawUrl, title, domain: host, category };
  } catch (_err) {
    return { url: rawUrl, title: rawUrl, domain: "Reference", category: "Guide" };
  }
}

function buildCodeLocatorHint(finding) {
  let path = "/";
  try {
    const parsed = new URL(finding.endpoint_url || "http://localhost/");
    path = parsed.pathname || "/";
  } catch (_err) {
    path = finding.endpoint_url || "/";
  }
  if (finding.parameter) {
    return `Search your route handler for "${path}" and input "${finding.parameter}"`;
  }
  return `Search your route/middleware handler for "${path}"`;
}

const TRIAGE_OPTIONS = [
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

function formatStackLabel(stackKey) {
  const normalized = String(stackKey || "").trim().toLowerCase();
  return STACK_LABEL_MAP[normalized] || normalized.toUpperCase() || "Code";
}

function formatEvidenceKey(key) {
  return String(key || "")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (ch) => ch.toUpperCase());
}

function normalizeEvidenceValue(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch (_err) {
    return String(value);
  }
}

export class FixModal {
  /**
   * @param {{
   *   modalEl?: HTMLElement | null,
   *   bodyEl?: HTMLElement | null,
   *   onTriaged?: (updatedFinding: any) => void | Promise<void>,
   * }} [options]
   */
  constructor(options = {}) {
    this._modalEl = options.modalEl || document.getElementById("fix-modal");
    this._bodyEl = options.bodyEl || document.getElementById("fix-modal-body");
    this._onTriaged = typeof options.onTriaged === "function" ? options.onTriaged : null;

    this._isOpen = false;
    this._finding = null;
    this._preferredStack = null;
    this._selectedStack = null;
    this._openToken = 0;
    this._previousFocus = null;

    this._onBackdropClick = (event) => {
      if (event.target === this._modalEl) {
        this.close();
      }
    };

    this._onKeyDown = (event) => {
      if (this._isOpen && event.key === "Escape") {
        event.preventDefault();
        this.close();
      }
    };

    if (this._modalEl) {
      this._modalEl.addEventListener("click", this._onBackdropClick);
    }
    document.addEventListener("keydown", this._onKeyDown);
  }

  /** @returns {boolean} */
  isOpen() {
    return this._isOpen;
  }

  /** Remove global listeners cleanly. */
  destroy() {
    if (this._modalEl) {
      this._modalEl.removeEventListener("click", this._onBackdropClick);
    }
    document.removeEventListener("keydown", this._onKeyDown);
  }

  /**
   * Open the Fix Modal for a given finding ID and fetch full remediation details.
   * @param {string} findingId
   * @param {{ preferredStack?: string | null }} [context]
   */
  async open(findingId, context = {}) {
    if (!findingId || !this._modalEl || !this._bodyEl) return;

    const token = ++this._openToken;
    this._previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    this._preferredStack = context?.preferredStack
      ? String(context.preferredStack).trim().toLowerCase()
      : null;

    this._showModal();
    this._renderLoading();

    try {
      const finding = await getFinding(findingId);
      if (token !== this._openToken || !this._isOpen) return;
      this._finding = finding;
      this._renderFinding(finding);
    } catch (err) {
      if (token !== this._openToken || !this._isOpen) return;
      this._renderError(err?.message || "Failed to load finding remediation details.");
    }
  }

  /** Close the modal cleanly and restore scroll/focus. */
  close() {
    this._openToken += 1;
    this._isOpen = false;
    if (this._modalEl) {
      this._modalEl.classList.add("hidden");
      this._modalEl.hidden = true;
    }
    document.body.style.overflow = "";
    if (this._previousFocus && typeof this._previousFocus.focus === "function") {
      try {
        this._previousFocus.focus();
      } catch (_err) {
        // Ignore if trigger element was removed from DOM.
      }
    }
    this._previousFocus = null;
  }

  _showModal() {
    this._isOpen = true;
    if (this._modalEl) {
      this._modalEl.classList.remove("hidden");
      this._modalEl.hidden = false;
    }
    document.body.style.overflow = "hidden";
  }

  _renderLoading() {
    if (!this._bodyEl) return;
    clear(this._bodyEl);
    this._bodyEl.appendChild(
      el("div", { class: "modal-header" }, [
        el("h3", { id: "fix-modal-title", class: "modal-title", text: "Loading Remediation Fix..." }),
        el("button", {
          type: "button",
          class: "modal-close",
          "aria-label": "Close modal",
          text: "×",
          on: { click: () => this.close() },
        }),
      ]),
    );
    this._bodyEl.appendChild(
      el("div", { class: "modal-body" }, [
        el("div", { class: "empty-state" }, [
          el("p", { class: "empty-state-desc", text: "Fetching finding details, HTTP evidence, and framework code fixes..." }),
        ]),
      ]),
    );
  }

  _renderError(message) {
    if (!this._bodyEl) return;
    clear(this._bodyEl);
    this._bodyEl.appendChild(
      el("div", { class: "modal-header" }, [
        el("h3", { id: "fix-modal-title", class: "modal-title", text: "Unable to Load Finding" }),
        el("button", {
          type: "button",
          class: "modal-close",
          "aria-label": "Close modal",
          text: "×",
          on: { click: () => this.close() },
        }),
      ]),
    );
    this._bodyEl.appendChild(
      el("div", { class: "modal-body stack" }, [
        el("div", { class: "form-error", role: "alert", text: message }),
      ]),
    );
    this._bodyEl.appendChild(
      el("div", { class: "modal-footer" }, [
        el("button", {
          type: "button",
          class: "btn btn-secondary",
          text: "Close",
          on: { click: () => this.close() },
        }),
      ]),
    );
  }

  /**
   * Build ordered list of stack tabs (preferred stack first, then remaining 5 canonical stacks).
   * @param {any} finding
   */
  _buildStackOrder(finding) {
    const snippets = Array.isArray(finding?.fix?.snippets) ? finding.fix.snippets : [];
    const snippetByStack = new Map();
    for (const snippet of snippets) {
      const key = String(snippet?.stack || "").trim().toLowerCase();
      if (key && !snippetByStack.has(key)) {
        snippetByStack.set(key, snippet);
      }
    }

    const firstFromBackend = snippets[0]?.stack
      ? String(snippets[0].stack).trim().toLowerCase()
      : null;
    const primaryStack = this._preferredStack || firstFromBackend || "fastapi";

    const orderedKeys = [];
    const pushUnique = (key) => {
      if (key && !orderedKeys.includes(key)) orderedKeys.push(key);
    };

    pushUnique(primaryStack);
    for (const s of CANONICAL_STACKS) {
      pushUnique(s.key);
    }
    for (const key of snippetByStack.keys()) {
      pushUnique(key);
    }

    return { orderedKeys, snippetByStack, primaryStack };
  }

  _renderFinding(finding) {
    if (!this._bodyEl) return;
    clear(this._bodyEl);

    const triageBadgeHost = el("span", null, [renderTriageBadgeSafe(finding.triage_status)]);
    const confidenceLabel = String(finding.confidence || "medium");
    const confidenceDisplay = `Confidence: ${confidenceLabel.charAt(0).toUpperCase() + confidenceLabel.slice(1)}`;

    const closeBtn = el("button", {
      type: "button",
      class: "modal-close",
      "aria-label": "Close modal",
      text: "×",
      on: { click: () => this.close() },
    });

    const header = el("div", { class: "modal-header", style: { alignItems: "flex-start" } }, [
      el("div", { class: "stack", style: { gap: "8px", minWidth: "0", flex: "1" } }, [
        el("h3", {
          id: "fix-modal-title",
          class: "modal-title",
          text: finding.title || "Security Finding",
        }),
        el("div", { class: "row", style: { gap: "6px" } }, [
          severityBadge(finding.severity),
          el("span", { class: "badge badge-neutral", text: confidenceDisplay }),
          triageBadgeHost,
          finding.owasp_category
            ? el("span", { class: "badge badge-stack", text: finding.owasp_category })
            : null,
          finding.cwe_id
            ? el("span", { class: "badge badge-neutral mono", text: finding.cwe_id })
            : null,
          finding.check_id
            ? el("span", { class: "badge badge-neutral mono", text: finding.check_id })
            : null,
        ]),
      ]),
      closeBtn,
    ]);

    // 1. Prominent Exact Endpoint Banner (clean route path without host/port clutter)
    let cleanRoutePath = finding.endpoint_url || "/";
    try {
      const parsedEp = new URL(finding.endpoint_url || "http://localhost/");
      cleanRoutePath = `${parsedEp.pathname || "/"}${parsedEp.search || ""}`;
    } catch (_err) {
      cleanRoutePath = finding.endpoint_url || "/";
    }
    const endpointParts = [
      el("span", {
        class: methodBadgeClass(finding.method),
        text: String(finding.method || "GET").toUpperCase(),
      }),
      el("span", {
        text: cleanRoutePath,
        title: finding.endpoint_url || "/",
        style: { color: "var(--text-primary)", fontWeight: "600" },
      }),
    ];
    if (finding.parameter) {
      endpointParts.push(
        el("span", {
          text: `· parameter: ${finding.parameter}`,
          style: { color: "var(--accent-primary)", fontWeight: "700" },
        }),
      );
    }
    const endpointBanner = el("div", { class: "endpoint-banner" }, endpointParts);

    // 2. Modern 2-Column Insight Grid (Root Cause + Recommended Fix Strategy)
    const fixSummary = String(finding.fix?.summary || "").trim();
    const explanation = String(finding.explanation || "").trim();
    const rootCause = String(finding.fix?.root_cause || "").trim();
    const causeText =
      explanation ||
      rootCause ||
      "Review the exact endpoint, HTTP evidence, and secure code remediation below.";

    const insightCards = [
      el("div", { class: "insight-card insight-cause" }, [
        el("div", { class: "insight-heading", text: "Why This Matters & Root Cause" }),
        el("p", { class: "insight-text", text: causeText }),
      ]),
    ];
    if (fixSummary) {
      insightCards.push(
        el("div", { class: "insight-card insight-fix" }, [
          el("div", { class: "insight-heading", text: "Recommended Fix Strategy" }),
          el("p", { class: "insight-text", text: fixSummary }),
        ]),
      );
    }

    const rootCauseBox = el("div", { class: "insight-grid" }, insightCards);

    // 3. Tabbed Multi-Stack Before vs. After Code Fixes
    const { orderedKeys, snippetByStack, primaryStack } = this._buildStackOrder(finding);
    this._selectedStack = primaryStack;

    const stackTabsEl = el("div", {
      class: "stack-tabs",
      role: "tablist",
      "aria-label": "Framework remediation stacks",
    });
    const codeDiffHost = el("div");

    const renderCodeDiff = () => {
      clear(stackTabsEl);
      for (const stackKey of orderedKeys) {
        const isPreferred = stackKey === primaryStack;
        const label = isPreferred ? `${formatStackLabel(stackKey)} ★` : formatStackLabel(stackKey);
        const tabBtn = el("button", {
          type: "button",
          role: "tab",
          class: `stack-tab${stackKey === this._selectedStack ? " active" : ""}`,
          "aria-selected": stackKey === this._selectedStack ? "true" : "false",
          text: label,
          on: {
            click: () => {
              this._selectedStack = stackKey;
              renderCodeDiff();
            },
          },
        });
        stackTabsEl.appendChild(tabBtn);
      }

      clear(codeDiffHost);
      const snippet = snippetByStack.get(this._selectedStack);
      if (!snippet) {
        codeDiffHost.appendChild(
          el("div", { class: "empty-state", style: { padding: "20px 12px" } }, [
            el("p", {
              class: "empty-state-desc",
              text: `No dedicated ${formatStackLabel(this._selectedStack)} snippet is registered for this check. Switch tabs above to inspect another stack.`,
            }),
          ]),
        );
        return;
      }

      const langRaw = String(snippet.language || snippet.stack || "code");
      const langLabel = langRaw.toUpperCase();
      const fileName = snippetFilename(this._selectedStack, langRaw);
      const beforeCode = String(snippet.before || "");
      const afterCode = String(snippet.after || "");

      const copyBtn = el("button", {
        type: "button",
        class: "btn btn-secondary btn-sm",
        text: "Copy Fix",
        on: {
          click: async () => {
            const ok = await copyToClipboard(afterCode);
            if (ok) {
              showToast(`Copied ${formatStackLabel(this._selectedStack)} fix to clipboard.`, "success");
            } else {
              showToast("Clipboard copy failed in this browser context.", "warning");
            }
          },
        },
      });

      const { beforeDiffs, afterDiffs } = computeLineDiffs(beforeCode, afterCode);

      const beforePanel = el("div", { class: "code-block code-block--before" }, [
        el("div", { class: "code-block-header" }, [
          el("div", { class: "vscode-tab" }, [
            el("span", { class: "vscode-dot" }),
            el("span", { text: fileName }),
          ]),
          el("div", { class: "vscode-tab-meta" }, [
            el("span", { class: "vscode-diff-badge", text: "Before · Vulnerable" }),
            el("span", { class: "vscode-lang-pill", text: langLabel }),
          ]),
        ]),
        buildVsCodeEditor(beforeCode, langRaw, beforeDiffs),
      ]);

      const afterPanel = el("div", { class: "code-block code-block--after" }, [
        el("div", { class: "code-block-header" }, [
          el("div", { class: "vscode-tab" }, [
            el("span", { class: "vscode-dot" }),
            el("span", { text: fileName }),
          ]),
          el("div", { class: "vscode-tab-meta" }, [
            el("span", { class: "vscode-diff-badge", text: "After · Secure Fix" }),
            copyBtn,
          ]),
        ]),
        buildVsCodeEditor(afterCode, langRaw, afterDiffs),
      ]);

      codeDiffHost.appendChild(el("div", { class: "code-diff-grid" }, [beforePanel, afterPanel]));
    };

    renderCodeDiff();

    const codeLocatorBar = el("div", { class: "code-locator-bar" }, [
      el("div", { class: "code-locator-main" }, [
        el("span", { class: "code-locator-tag", text: "Where to Patch" }),
        el("span", { text: buildCodeLocatorHint(finding) }),
      ]),
      el("span", {
        class: "code-locator-note",
        text: "Red/green lines mark the exact diff",
      }),
    ]);

    const codeSection = el("div", { class: "card" }, [
      el("div", { class: "card-header" }, [
        el("div", null, [
          el("h4", { class: "card-title", text: "Actionable Code Fix (Before vs. After)" }),
          el("p", {
            class: "card-subtitle",
            text: "Project preferred stack is shown first. Switch tabs for other frameworks.",
          }),
        ]),
      ]),
      el("div", { class: "card-body" }, [codeLocatorBar, stackTabsEl, codeDiffHost]),
    ]);

    // 4. Collapsible HTTP Evidence (<details>, strictly textContent escaped)
    const evidenceEntries = Object.entries(finding.evidence || {}).filter(
      ([, v]) => v !== null && v !== undefined && String(v).trim() !== "",
    );

    const evidenceBodyChildren =
      evidenceEntries.length > 0
        ? evidenceEntries.map(([key, value]) =>
            el("div", { class: "stack", style: { gap: "4px" } }, [
              el("span", {
                class: "text-xs text-muted",
                style: { fontWeight: "700", textTransform: "uppercase", letterSpacing: "0.05em" },
                text: formatEvidenceKey(key),
              }),
              el("pre", {
                class: "code-pre",
                style: {
                  backgroundColor: "var(--bg-code)",
                  border: "1px solid var(--border-default)",
                  borderRadius: "var(--radius-sm)",
                  padding: "10px 12px",
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                },
                text: normalizeEvidenceValue(value),
              }),
            ]),
          )
        : [
            el("p", {
              class: "text-sm text-muted",
              style: { margin: "0" },
              text: "No raw HTTP evidence payload recorded for this finding.",
            }),
          ];

    const evidenceDetails = el("details", { class: "evidence-details" }, [
      el("summary", {
        class: "evidence-summary",
        text: `HTTP Evidence & Proof (${evidenceEntries.length} field${evidenceEntries.length === 1 ? "" : "s"})`,
      }),
      el("div", { class: "evidence-body" }, evidenceBodyChildren),
    ]);

    // 5. Safe OWASP References (Modern Reference Cards, http/https ONLY)
    const safeRefs = (Array.isArray(finding.fix?.references) ? finding.fix.references : []).filter(
      (url) => isSafeHttpUrl(url),
    );

    const referencesCard =
      safeRefs.length > 0
        ? el("div", { class: "card" }, [
            el("div", { class: "card-header" }, [
              el("h4", { class: "card-title", text: "OWASP & Security References" }),
            ]),
            el(
              "div",
              { class: "card-body" },
              [
                el(
                  "div",
                  { class: "ref-grid" },
                  safeRefs.map((refUrl) => {
                    const meta = formatReferenceCardMeta(refUrl);
                    return el(
                      "a",
                      {
                        href: meta.url,
                        target: "_blank",
                        rel: "noopener noreferrer",
                        class: "ref-card",
                      },
                      [
                        el("div", { class: "ref-card-body" }, [
                          el("span", { class: "ref-card-title", text: meta.title }),
                          el("span", { class: "ref-card-meta" }, [
                            el("span", { class: "ref-card-badge", text: meta.category }),
                            el("span", { text: meta.domain }),
                          ]),
                        ]),
                        el("span", { class: "ref-card-arrow", "aria-hidden": "true", text: "↗" }),
                      ],
                    );
                  }),
                ),
              ],
            ),
          ])
        : null;

    // 6. Developer Triage Form
    const triageError = el("div", { class: "form-error hidden", role: "alert", hidden: true });
    const currentStatus = String(finding.triage_status || "open").trim().toLowerCase();
    const triageSelect = el(
      "select",
      {
        id: "fix-triage-status",
        name: "triage_status",
        class: "form-select",
      },
      TRIAGE_OPTIONS.map((opt) =>
        el("option", {
          value: opt.value,
          text: opt.label,
          selected: opt.value === currentStatus,
        }),
      ),
    );

    const triageNote = el("textarea", {
      id: "fix-triage-note",
      name: "triage_note",
      class: "form-textarea",
      maxlength: "2000",
      placeholder: "Add remediation commit SHA, verification steps, or risk acceptance rationale...",
      value: finding.triage_note || "",
    });
    triageNote.value = finding.triage_note || "";

    const saveTriageBtn = el("button", {
      type: "submit",
      class: "btn btn-primary",
      text: "Save Triage Status",
    });

    const triageForm = el(
      "form",
      {
        class: "card",
        on: {
          submit: async (event) => {
            event.preventDefault();
            triageError.classList.add("hidden");
            triageError.hidden = true;
            saveTriageBtn.disabled = true;
            saveTriageBtn.textContent = "Saving...";

            try {
              const updated = await triageFinding(finding.id, {
                triage_status: triageSelect.value,
                triage_note: triageNote.value.trim() || null,
              });
              this._finding = updated;
              clear(triageBadgeHost);
              triageBadgeHost.appendChild(renderTriageBadgeSafe(updated.triage_status));
              showToast("Triage updated — scan risk score recalculated live.", "success");
              if (this._onTriaged) {
                await this._onTriaged(updated);
              }
            } catch (err) {
              triageError.textContent = err?.message || "Failed to save triage status.";
              triageError.classList.remove("hidden");
              triageError.hidden = false;
            } finally {
              saveTriageBtn.disabled = false;
              saveTriageBtn.textContent = "Save Triage Status";
            }
          },
        },
      },
      [
        el("div", { class: "card-header" }, [
          el("div", null, [
            el("h4", { class: "card-title", text: "Developer Triage" }),
            el("p", {
              class: "card-subtitle",
              text: "Marking a finding as Fixed or False Positive immediately recalculates the scan Risk Score.",
            }),
          ]),
        ]),
        el("div", { class: "card-body form-stack" }, [
          triageError,
          el("div", { class: "form-group" }, [
            el("label", { for: "fix-triage-status", class: "form-label", text: "Triage Status" }),
            triageSelect,
          ]),
          el("div", { class: "form-group" }, [
            el("label", { for: "fix-triage-note", class: "form-label", text: "Triage Note (Optional)" }),
            triageNote,
          ]),
          el("div", { class: "row", style: { justifyContent: "flex-end" } }, [saveTriageBtn]),
        ]),
      ],
    );

    const body = el("div", { class: "modal-body stack", style: { gap: "16px" } }, [
      endpointBanner,
      rootCauseBox,
      codeSection,
      evidenceDetails,
      referencesCard,
      triageForm,
    ]);

    const footer = el("div", { class: "modal-footer" }, [
      el("button", {
        type: "button",
        class: "btn btn-secondary",
        text: "Close",
        on: { click: () => this.close() },
      }),
    ]);

    this._bodyEl.appendChild(header);
    this._bodyEl.appendChild(body);
    this._bodyEl.appendChild(footer);

    closeBtn.focus();
  }
}
