/**
 * Pure inline SVG & DOM analytics visualizations for OWASP-Lite Scanner.
 * Zero external chart libraries, zero innerHTML, 100% strict CSP & XSS safe.
 */

import { clear, el, riskColorClass } from "../utils.js";

const SVG_NS = "http://www.w3.org/2000/svg";

const SEVERITY_ORDER = [
  { key: "critical", label: "Critical", color: "#DC2626" },
  { key: "high", label: "High", color: "#EA580C" },
  { key: "medium", label: "Medium", color: "#D97706" },
  { key: "low", label: "Low", color: "#0284C7" },
  { key: "info", label: "Info", color: "#64748B" },
];

const OWASP_SHORT_NAMES = {
  A01: "Broken Access Control",
  A02: "Cryptographic Failures",
  A03: "Injection",
  A04: "Insecure Design",
  A05: "Security Misconfiguration",
  A06: "Vulnerable Components",
  A07: "Auth Failures",
  A08: "Data Integrity Failures",
  A09: "Logging & Monitoring",
  A10: "SSRF",
};

const INACTIVE_TRIAGE_STATUSES = new Set(["fixed", "false_positive"]);

/**
 * Create an SVG namespaced element safely with attributes and optional text/children.
 * @param {string} tag
 * @param {Record<string, string | number>} [attrs]
 * @param {(Node | string)[]} [children]
 * @returns {SVGElement}
 */
function svgEl(tag, attrs = {}, children = []) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value !== undefined && value !== null) {
      node.setAttribute(key, String(value));
    }
  }
  for (const child of children) {
    if (child === null || child === undefined) continue;
    if (child instanceof Node) {
      node.appendChild(child);
    } else {
      node.appendChild(document.createTextNode(String(child)));
    }
  }
  return node;
}

/**
 * Map a 0-100 risk score to gauge stroke color and human-readable risk level.
 * Thresholds: <=25 green, <=50 amber, <=75 orange, >75 red.
 * @param {number} score
 * @returns {{ color: string, label: string }}
 */
function getRiskMeta(score) {
  if (score <= 25) return { color: "#10B981", label: "Low Risk" };
  if (score <= 50) return { color: "#F59E0B", label: "Moderate Risk" };
  if (score <= 75) return { color: "#EA580C", label: "High Risk" };
  return { color: "#DC2626", label: "Critical Risk" };
}

/**
 * Render a crisp inline SVG semi-circle risk gauge (0-100).
 * @param {HTMLElement | null} container
 * @param {number | null | undefined} riskScore
 */
export function renderRiskGauge(container, riskScore) {
  if (!container) return;
  clear(container);

  const hasScore = riskScore !== null && riskScore !== undefined && !Number.isNaN(Number(riskScore));
  const score = hasScore ? Math.max(0, Math.min(100, Math.round(Number(riskScore)))) : 0;
  const meta = hasScore ? getRiskMeta(score) : { color: "#64748B", label: "No Score" };

  // Semi-circle arc from left (20, 108) to right (180, 108) with radius 80
  const radius = 80;
  const arcLength = Math.PI * radius; // ~251.33
  const filledLength = hasScore ? (score / 100) * arcLength : 0;
  const dashOffset = Math.max(0, arcLength - filledLength);

  const svg = svgEl(
    "svg",
    {
      viewBox: "0 0 200 124",
      width: "100%",
      height: "128",
      role: "img",
      "aria-label": hasScore
        ? `Risk score ${score} out of 100, ${meta.label}`
        : "No risk score available",
      style: "max-width: 220px; display: block; margin: 0 auto; overflow: visible;",
    },
    [
      // Background semi-circle track
      svgEl("path", {
        d: "M 20 108 A 80 80 0 0 1 180 108",
        fill: "none",
        stroke: "var(--border-strong, #334155)",
        "stroke-width": 14,
        "stroke-linecap": "round",
        opacity: "0.45",
      }),
      // Colored progress arc
      svgEl("path", {
        d: "M 20 108 A 80 80 0 0 1 180 108",
        fill: "none",
        stroke: meta.color,
        "stroke-width": 14,
        "stroke-linecap": "round",
        "stroke-dasharray": arcLength.toFixed(2),
        "stroke-dashoffset": dashOffset.toFixed(2),
        style: "transition: stroke-dashoffset 0.35s ease, stroke 0.25s ease;",
      }),
      // Scale labels (0 and 100)
      svgEl(
        "text",
        {
          x: 18,
          y: 123,
          "text-anchor": "middle",
          fill: "var(--text-muted, #94a3b8)",
          "font-size": "10",
          "font-weight": "600",
        },
        ["0"],
      ),
      svgEl(
        "text",
        {
          x: 182,
          y: 123,
          "text-anchor": "middle",
          fill: "var(--text-muted, #94a3b8)",
          "font-size": "10",
          "font-weight": "600",
        },
        ["100"],
      ),
      // Main score number
      svgEl(
        "text",
        {
          x: 100,
          y: 86,
          "text-anchor": "middle",
          fill: "var(--text-primary, #f1f5f9)",
          "font-size": "34",
          "font-weight": "700",
        },
        [hasScore ? String(score) : "—"],
      ),
      // Sub-caption
      svgEl(
        "text",
        {
          x: 100,
          y: 105,
          "text-anchor": "middle",
          fill: "var(--text-muted, #94a3b8)",
          "font-size": "11",
          "font-weight": "600",
        },
        ["/ 100 RISK SCORE"],
      ),
    ],
  );

  const pill = el("span", {
    class: `risk-pill ${hasScore ? riskColorClass(score) : "risk-none"}`,
    text: meta.label,
  });

  const wrapper = el(
    "div",
    {
      style: {
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        gap: "10px",
        padding: "4px 0",
      },
    },
    [svg, pill],
  );

  container.appendChild(wrapper);
}

/**
 * Render a crisp inline SVG severity donut chart with center total and legend.
 * @param {HTMLElement | null} container
 * @param {Record<string, number> | null | undefined} summary
 */
export function renderSeverityDonut(container, summary) {
  if (!container) return;
  clear(container);

  const counts = SEVERITY_ORDER.map((item) => ({
    ...item,
    count: Math.max(0, Number(summary?.[item.key] || 0)),
  }));
  const total = counts.reduce((acc, item) => acc + item.count, 0);

  const radius = 50;
  const strokeWidth = 16;
  const circumference = 2 * Math.PI * radius;

  const segments = [
    svgEl("circle", {
      cx: 68,
      cy: 68,
      r: radius,
      fill: "none",
      stroke: "var(--border-strong, #334155)",
      "stroke-width": strokeWidth,
      opacity: "0.35",
    }),
  ];

  if (total > 0) {
    let accumulated = 0;
    for (const item of counts) {
      if (item.count <= 0) continue;
      const frac = item.count / total;
      const segLength = frac * circumference;
      const gap = counts.filter((c) => c.count > 0).length > 1 ? 1.5 : 0;
      const visibleLength = Math.max(1.5, segLength - gap);
      const offset = circumference - accumulated;

      segments.push(
        svgEl("circle", {
          cx: 68,
          cy: 68,
          r: radius,
          fill: "none",
          stroke: item.color,
          "stroke-width": strokeWidth,
          "stroke-dasharray": `${visibleLength.toFixed(2)} ${(circumference - visibleLength).toFixed(2)}`,
          "stroke-dashoffset": offset.toFixed(2),
          transform: "rotate(-90 68 68)",
        }),
      );
      accumulated += segLength;
    }
  }

  segments.push(
    svgEl(
      "text",
      {
        x: 68,
        y: 66,
        "text-anchor": "middle",
        fill: "var(--text-primary, #f1f5f9)",
        "font-size": "24",
        "font-weight": "700",
      },
      [String(total)],
    ),
    svgEl(
      "text",
      {
        x: 68,
        y: 83,
        "text-anchor": "middle",
        fill: "var(--text-muted, #94a3b8)",
        "font-size": "10.5",
        "font-weight": "600",
      },
      [total === 1 ? "ACTIVE" : "ACTIVE"],
    ),
  );

  const svg = svgEl(
    "svg",
    {
      viewBox: "0 0 136 136",
      width: "132",
      height: "132",
      role: "img",
      "aria-label": `Severity distribution: ${total} active findings`,
      style: "flex-shrink: 0;",
    },
    segments,
  );

  const legend = el(
    "div",
    {
      style: {
        display: "flex",
        flexDirection: "column",
        gap: "7px",
        flex: "1",
        minWidth: "128px",
      },
    },
    counts.map((item) =>
      el(
        "div",
        {
          style: {
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: "8px",
            fontSize: "12.5px",
          },
        },
        [
          el(
            "span",
            {
              style: {
                display: "inline-flex",
                alignItems: "center",
                gap: "7px",
                color: item.count > 0 ? "var(--text-primary)" : "var(--text-muted)",
              },
            },
            [
              el("span", {
                style: {
                  width: "9px",
                  height: "9px",
                  borderRadius: "50%",
                  backgroundColor: item.color,
                  flexShrink: "0",
                },
                "aria-hidden": "true",
              }),
              el("span", { text: item.label }),
            ],
          ),
          el("span", {
            class: "mono",
            text: String(item.count),
            style: {
              fontWeight: item.count > 0 ? "700" : "500",
              color: item.count > 0 ? "var(--text-primary)" : "var(--text-muted)",
            },
          }),
        ],
      ),
    ),
  );

  const wrapper = el(
    "div",
    {
      style: {
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        gap: "18px",
        flexWrap: "wrap",
        padding: "4px 0",
      },
    },
    [svg, legend],
  );

  container.appendChild(wrapper);
}

/**
 * Extract canonical OWASP Top 10 code (A01..A10) from a category string.
 * @param {string | null | undefined} category
 * @returns {{ code: string, label: string }}
 */
function parseOwaspCategory(category) {
  const raw = String(category || "").trim();
  const match = raw.match(/\b(A(?:0[1-9]|10))\b/i);
  if (match) {
    const code = match[1].toUpperCase();
    const shortName = OWASP_SHORT_NAMES[code] || raw;
    return { code, label: `${code} · ${shortName}` };
  }
  return { code: "OTHER", label: raw || "Uncategorized" };
}

/**
 * Render a horizontal bar chart grouping active findings by OWASP Top 10 category sorted by count desc.
 * @param {HTMLElement | null} container
 * @param {Array<Record<string, any>>} findings
 */
export function renderOwaspBarChart(container, findings) {
  if (!container) return;
  clear(container);

  const list = Array.isArray(findings) ? findings : [];
  const activeFindings = list.filter((f) => {
    const status = String(f?.triage_status || "open").trim().toLowerCase();
    return !INACTIVE_TRIAGE_STATUSES.has(status);
  });

  if (activeFindings.length === 0) {
    const note =
      list.length > 0
        ? `All ${list.length} finding(s) are marked Fixed or False Positive.`
        : "No active OWASP Top 10 findings detected.";
    container.appendChild(
      el(
        "div",
        {
          style: {
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            minHeight: "132px",
            textAlign: "center",
            gap: "6px",
            color: "var(--text-muted)",
          },
        },
        [
          el("span", {
            class: "badge badge-status-completed",
            text: "Clean",
          }),
          el("span", { class: "text-sm", text: note }),
        ],
      ),
    );
    return;
  }

  const bucketMap = new Map();
  for (const finding of activeFindings) {
    const parsed = parseOwaspCategory(finding?.owasp_category);
    const existing = bucketMap.get(parsed.code);
    if (existing) {
      existing.count += 1;
    } else {
      bucketMap.set(parsed.code, {
        code: parsed.code,
        label: parsed.label,
        count: 1,
      });
    }
  }

  const sorted = Array.from(bucketMap.values()).sort((a, b) => {
    if (b.count !== a.count) return b.count - a.count;
    return a.code.localeCompare(b.code);
  });

  const maxCount = Math.max(1, sorted[0].count);
  const topItems = sorted.slice(0, 6);

  const chartList = el(
    "div",
    {
      role: "list",
      "aria-label": "Active findings by OWASP Top 10 category",
      style: {
        display: "flex",
        flexDirection: "column",
        gap: "10px",
        padding: "2px 0",
      },
    },
    topItems.map((item) => {
      const pct = Math.max(8, Math.round((item.count / maxCount) * 100));
      return el(
        "div",
        {
          role: "listitem",
          style: {
            display: "flex",
            flexDirection: "column",
            gap: "4px",
          },
        },
        [
          el(
            "div",
            {
              style: {
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                gap: "8px",
                fontSize: "12px",
              },
            },
            [
              el("span", {
                class: "truncate",
                text: item.label,
                title: item.label,
                style: {
                  color: "var(--text-secondary)",
                  fontWeight: "600",
                },
              }),
              el("span", {
                class: "mono",
                text: String(item.count),
                style: {
                  color: "var(--text-primary)",
                  fontWeight: "700",
                  flexShrink: "0",
                },
              }),
            ],
          ),
          el(
            "div",
            {
              style: {
                width: "100%",
                height: "7px",
                borderRadius: "999px",
                backgroundColor: "var(--bg-surface-elevated)",
                border: "1px solid var(--border-subtle)",
                overflow: "hidden",
              },
            },
            [
              el("div", {
                style: {
                  width: `${pct}%`,
                  height: "100%",
                  borderRadius: "999px",
                  background: "linear-gradient(90deg, var(--accent-primary), var(--accent-secondary))",
                  transition: "width 0.3s ease",
                },
              }),
            ],
          ),
        ],
      );
    }),
  );

  if (sorted.length > topItems.length) {
    chartList.appendChild(
      el("div", {
        class: "text-xs text-muted",
        text: `+ ${sorted.length - topItems.length} additional OWASP categories`,
      }),
    );
  }

  container.appendChild(chartList);
}
