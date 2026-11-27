/**
 * Strict XSS-safe DOM builders, formatting helpers, badges, URL validators,
 * clipboard helper, and toast notifications for OWASP-Lite Scanner.
 * Uses only textContent / createTextNode and addEventListener (strict CSP).
 */

const HTML_ESCAPE_MAP = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

const SEVERITY_LABELS = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

const STATUS_LABELS = {
  queued: "Queued",
  crawling: "Crawling",
  scanning: "Scanning",
  completed: "Completed",
  failed: "Failed",
  cancelled: "Cancelled",
};

const TRIAGE_LABELS = {
  open: "Open",
  fixed: "Fixed",
  false_positive: "False Positive",
  accepted: "Accepted Risk",
  accepted_risk: "Accepted Risk",
};

const BOOLEAN_ATTRS = new Set([
  "disabled",
  "checked",
  "selected",
  "hidden",
  "required",
  "readOnly",
  "readonly",
  "open",
  "multiple",
]);

const FORBIDDEN_ATTRS = new Set(["innerHTML", "outerHTML", "innerhtml", "outerhtml"]);

/**
 * Escape untrusted text into HTML entities.
 * @param {unknown} str
 * @returns {string}
 */
export function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str).replace(/[&<>"']/g, (ch) => HTML_ESCAPE_MAP[ch] || ch);
}

/**
 * Validate that a URL is an explicit http: or https: URL (blocks javascript:, data:, etc.).
 * @param {unknown} url
 * @returns {boolean}
 */
export function isSafeHttpUrl(url) {
  if (typeof url !== "string" || !url.trim()) return false;
  try {
    const parsed = new URL(url.trim());
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch (_err) {
    return false;
  }
}

/**
 * Check whether an href value is safe (relative path/hash or http/https URL).
 * @param {string} value
 * @returns {boolean}
 */
function isSafeHref(value) {
  const trimmed = String(value || "").trim();
  if (!trimmed) return false;
  if (trimmed.startsWith("/") || trimmed.startsWith("#")) return true;
  return isSafeHttpUrl(trimmed);
}

/**
 * Append heterogeneous child values safely to a parent DOM node.
 * Strings and numbers are always added as Text nodes (strict XSS protection).
 * @param {Node} parent
 * @param {unknown} child
 */
function appendChildSafe(parent, child) {
  if (child === null || child === undefined || child === false) return;
  if (Array.isArray(child)) {
    for (const item of child) {
      appendChildSafe(parent, item);
    }
    return;
  }
  if (child instanceof Node) {
    parent.appendChild(child);
    return;
  }
  parent.appendChild(document.createTextNode(String(child)));
}

/**
 * Strictly XSS-safe DOM element builder.
 * Supports:
 *  - `class` / `className`
 *  - `text` (assigns `textContent`)
 *  - `dataset` (assigns `data-*` attributes)
 *  - `style` (string or style property object)
 *  - `on` ({ click: fn, ... }) or `onClick: fn` -> wired via addEventListener (never inline HTML attrs)
 *  - Boolean attributes (`disabled`, `checked`, `hidden`, etc.)
 *  - Children array or single child (Nodes or plain text)
 *
 * @param {string} tag
 * @param {Record<string, any> | null} [attrs]
 * @param {any} [children]
 * @returns {HTMLElement}
 */
export function el(tag, attrs = null, children = []) {
  const node = document.createElement(tag);

  if (attrs && typeof attrs === "object") {
    for (const [key, value] of Object.entries(attrs)) {
      if (value === undefined || value === null || FORBIDDEN_ATTRS.has(key)) {
        continue;
      }

      if (key === "class" || key === "className") {
        node.className = String(value);
      } else if (key === "text") {
        node.textContent = String(value);
      } else if (key === "dataset" && typeof value === "object") {
        for (const [dKey, dVal] of Object.entries(value)) {
          if (dVal !== undefined && dVal !== null) {
            node.dataset[dKey] = String(dVal);
          }
        }
      } else if (key === "style") {
        if (typeof value === "string") {
          node.setAttribute("style", value);
        } else if (typeof value === "object") {
          Object.assign(node.style, value);
        }
      } else if (key === "on" && typeof value === "object") {
        for (const [eventName, handler] of Object.entries(value)) {
          if (typeof handler === "function") {
            node.addEventListener(eventName, handler);
          }
        }
      } else if (key.startsWith("on") && typeof value === "function") {
        node.addEventListener(key.slice(2).toLowerCase(), value);
      } else if (key.startsWith("on")) {
        // Reject string inline event handlers to guarantee strict CSP compliance.
        continue;
      } else if (key === "href") {
        if (isSafeHref(String(value))) {
          node.setAttribute("href", String(value));
        }
      } else if (BOOLEAN_ATTRS.has(key)) {
        const flag = Boolean(value);
        const propName = key === "readonly" ? "readOnly" : key;
        if (propName in node) {
          node[propName] = flag;
        }
        if (flag) {
          node.setAttribute(key.toLowerCase(), "");
        } else {
          node.removeAttribute(key.toLowerCase());
        }
      } else if (key === "value" && "value" in node) {
        node.value = String(value);
      } else {
        node.setAttribute(key, String(value));
      }
    }
  }

  appendChildSafe(node, children);
  return node;
}

/**
 * Safely remove all child nodes from a container.
 * @param {Element | null | undefined} node
 */
export function clear(node) {
  if (!node) return;
  while (node.firstChild) {
    node.removeChild(node.firstChild);
  }
}

/**
 * Format an ISO-8601 timestamp into a concise readable date/time string.
 * @param {string | Date | null | undefined} iso
 * @returns {string}
 */
export function formatDate(iso) {
  if (!iso) return "—";
  const date = iso instanceof Date ? iso : new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return String(iso);
  }
  try {
    return new Intl.DateTimeFormat(undefined, {
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    }).format(date);
  } catch (_err) {
    return date.toISOString().replace("T", " ").slice(0, 16);
  }
}

/**
 * Return a short 8-character identifier prefix for UUIDs.
 * @param {string | null | undefined} id
 * @returns {string}
 */
export function shortId(id) {
  if (!id) return "—";
  const str = String(id).trim();
  return str.length > 8 ? str.slice(0, 8) : str;
}

/**
 * Create a styled severity badge element.
 * @param {string} sev
 * @returns {HTMLElement}
 */
export function severityBadge(sev) {
  const key = String(sev || "info").trim().toLowerCase();
  const normalized = Object.prototype.hasOwnProperty.call(SEVERITY_LABELS, key) ? key : "info";
  return el("span", {
    class: `badge badge-sev-${normalized}`,
    text: SEVERITY_LABELS[normalized],
  });
}

/**
 * Create a styled scan status badge element.
 * @param {string} status
 * @returns {HTMLElement}
 */
export function statusBadge(status) {
  const key = String(status || "queued").trim().toLowerCase();
  const normalized = Object.prototype.hasOwnProperty.call(STATUS_LABELS, key) ? key : "queued";
  return el("span", {
    class: `badge badge-status-${normalized}`,
    text: STATUS_LABELS[normalized],
  });
}

/**
 * Create a styled finding triage badge element.
 * @param {string} status
 * @returns {HTMLElement}
 */
export function triageBadge(status) {
  const key = String(status || "open").trim().toLowerCase();
  const normalized = Object.prototype.hasOwnProperty.call(TRIAGE_LABELS, key) ? key : "open";
  return el("span", {
    class: `badge badge-triage-${normalized}`,
    text: TRIAGE_LABELS[normalized],
  });
}

/**
 * Return the semantic CSS risk color class for a 0-100 risk score.
 * Matches risk gauge thresholds: <=25 low (green), <=50 medium (amber), <=75 high (orange), >75 critical (red).
 * @param {number | null | undefined} score
 * @returns {string}
 */
export function riskColorClass(score) {
  if (score === null || score === undefined || Number.isNaN(Number(score))) {
    return "risk-none";
  }
  const num = Number(score);
  if (num <= 25) return "risk-low";
  if (num <= 50) return "risk-medium";
  if (num <= 75) return "risk-high";
  return "risk-critical";
}

/**
 * Copy plain text to the user's clipboard with graceful HTTP fallback.
 * @param {string} text
 * @returns {Promise<boolean>}
 */
export async function copyToClipboard(text) {
  const value = String(text ?? "");
  if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
    try {
      await navigator.clipboard.writeText(value);
      return true;
    } catch (_err) {
      // Fall through to legacy textarea copy fallback.
    }
  }

  try {
    const textarea = document.createElement("textarea");
    textarea.value = value;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    textarea.style.left = "-9999px";
    document.body.appendChild(textarea);
    textarea.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(textarea);
    return Boolean(ok);
  } catch (_fallbackErr) {
    return false;
  }
}

/**
 * Display a temporary XSS-safe toast notification in #toast-container.
 * @param {string} message
 * @param {"info" | "success" | "warning" | "error"} [type="info"]
 */
export function showToast(message, type = "info") {
  const allowedTypes = new Set(["info", "success", "warning", "error"]);
  const tone = allowedTypes.has(type) ? type : "info";

  let container = document.getElementById("toast-container");
  if (!container) {
    container = el("div", {
      id: "toast-container",
      class: "toast-container",
      "aria-live": "polite",
      "aria-atomic": "true",
    });
    document.body.appendChild(container);
  }

  let timerId = null;
  const dismiss = () => {
    if (timerId !== null) {
      window.clearTimeout(timerId);
      timerId = null;
    }
    if (toastEl.parentNode) {
      toastEl.parentNode.removeChild(toastEl);
    }
  };

  const closeBtn = el("button", {
    type: "button",
    class: "toast-close",
    "aria-label": "Dismiss notification",
    text: "×",
    on: { click: dismiss },
  });

  const toastEl = el(
    "div",
    {
      class: `toast toast-${tone}`,
      role: tone === "error" ? "alert" : "status",
    },
    [el("span", { text: String(message ?? "") }), closeBtn],
  );

  container.appendChild(toastEl);
  timerId = window.setTimeout(dismiss, 4500);
}
