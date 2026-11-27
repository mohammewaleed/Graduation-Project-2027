/**
 * REST & SSE API Client for OWASP-Lite Scanner FastAPI backend (/api).
 * Pure ES module with uniform ApiError parsing and automatic SSE teardown.
 */

const API_BASE = "/api";

const TERMINAL_SCAN_STATUSES = new Set(["completed", "failed", "cancelled"]);

export class ApiError extends Error {
  /**
   * @param {number} status HTTP status code (0 for network failure)
   * @param {string} code Machine-readable error code (e.g. TARGET_NOT_ALLOWED)
   * @param {string} message Human-readable error message
   * @param {unknown} [details] Optional structured details from backend
   */
  constructor(status, code, message, details = null) {
    super(message || `Request failed (${status})`);
    this.name = "ApiError";
    this.status = status;
    this.code = code || `HTTP_${status}`;
    this.details = details;
  }
}

/**
 * Format Pydantic validation error details into a helpful message suffix if present.
 * @param {string} baseMessage
 * @param {unknown} details
 * @returns {string}
 */
function formatValidationMessage(baseMessage, details) {
  if (!Array.isArray(details) || details.length === 0) {
    return baseMessage;
  }
  const first = details[0];
  if (first && typeof first === "object" && typeof first.msg === "string") {
    const loc = Array.isArray(first.loc)
      ? first.loc.filter((part) => part !== "body").join(".")
      : "";
    return loc ? `${baseMessage} (${loc}: ${first.msg})` : `${baseMessage} (${first.msg})`;
  }
  return baseMessage;
}

/**
 * Execute a JSON request against the FastAPI /api namespace.
 * @param {string} path Path beginning with "/"
 * @param {RequestInit & { json?: unknown }} [options]
 * @returns {Promise<any>}
 */
async function request(path, options = {}) {
  const { json, headers = {}, ...rest } = options;
  const reqHeaders = {
    Accept: "application/json",
    ...headers,
  };

  let body = rest.body;
  if (json !== undefined) {
    reqHeaders["Content-Type"] = "application/json";
    body = JSON.stringify(json);
  }

  let response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...rest,
      headers: reqHeaders,
      body,
    });
  } catch (_err) {
    throw new ApiError(
      0,
      "NETWORK_ERROR",
      "Unable to reach the scanner API. Ensure the backend server is running.",
      null,
    );
  }

  if (response.status === 204) {
    return null;
  }

  let payload = null;
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    try {
      payload = await response.json();
    } catch (_parseErr) {
      payload = null;
    }
  } else {
    const text = await response.text().catch(() => "");
    if (text) {
      try {
        payload = JSON.parse(text);
      } catch (_ignore) {
        payload = { detail: text };
      }
    }
  }

  if (!response.ok) {
    const errEnvelope =
      payload && typeof payload === "object" && payload.error && typeof payload.error === "object"
        ? payload.error
        : null;

    const code =
      (errEnvelope && typeof errEnvelope.code === "string" && errEnvelope.code) ||
      `HTTP_${response.status}`;

    const details = errEnvelope ? (errEnvelope.details ?? null) : null;

    let message =
      (errEnvelope && typeof errEnvelope.message === "string" && errEnvelope.message) ||
      (payload && typeof payload.detail === "string" && payload.detail) ||
      (payload && typeof payload.message === "string" && payload.message) ||
      response.statusText ||
      `Request failed with HTTP ${response.status}`;

    if (code === "VALIDATION_ERROR") {
      message = formatValidationMessage(message, details);
    }

    throw new ApiError(response.status, code, message, details);
  }

  return payload;
}

/* ---------- Health & Checks Catalog ---------- */

export function getHealth() {
  return request("/health", { method: "GET" });
}

export function getChecks() {
  return request("/checks", { method: "GET" });
}

/* ---------- Projects ---------- */

export function listProjects() {
  return request("/projects", { method: "GET" });
}

export function createProject(payload) {
  return request("/projects", { method: "POST", json: payload });
}

export function getProject(id) {
  return request(`/projects/${encodeURIComponent(id)}`, { method: "GET" });
}

export function deleteProject(id) {
  return request(`/projects/${encodeURIComponent(id)}`, { method: "DELETE" });
}

/* ---------- Scans & Live SSE ---------- */

export function listScans() {
  return request("/scans", { method: "GET" });
}

export function listProjectScans(projectId) {
  return request(`/projects/${encodeURIComponent(projectId)}/scans`, { method: "GET" });
}

export function startScan(projectId, payload = {}) {
  return request(`/projects/${encodeURIComponent(projectId)}/scans`, {
    method: "POST",
    json: payload,
  });
}

export function getScan(scanId) {
  return request(`/scans/${encodeURIComponent(scanId)}`, { method: "GET" });
}

export function cancelScan(scanId) {
  return request(`/scans/${encodeURIComponent(scanId)}/cancel`, { method: "POST" });
}

/**
 * Subscribe to live SSE scan events and automatically close on terminal status.
 * @param {string} scanId
 * @param {{
 *   onProgress?: (event: any) => void,
 *   onFinding?: (finding: any, rawEvent: any) => void,
 *   onStatus?: (event: any) => void,
 *   onError?: (err: Event | Error) => void,
 * }} [handlers]
 * @returns {{ close: () => void, eventSource: EventSource }}
 */
export function openScanStream(scanId, handlers = {}) {
  const { onProgress, onFinding, onStatus, onError } = handlers;
  const url = `${API_BASE}/scans/${encodeURIComponent(scanId)}/stream`;
  const source = new EventSource(url);
  let closed = false;

  const close = () => {
    if (closed) return;
    closed = true;
    source.close();
  };

  source.addEventListener("message", (event) => {
    if (closed) return;
    let data;
    try {
      data = JSON.parse(event.data);
    } catch (_err) {
      return;
    }

    if (!data || typeof data !== "object") return;

    if (data.type === "progress") {
      if (typeof onProgress === "function") onProgress(data);
      return;
    }

    if (data.type === "finding") {
      if (typeof onFinding === "function") {
        onFinding(data.finding ?? data, data);
      }
      return;
    }

    if (data.type === "status") {
      const normalized = String(data.status || "").toLowerCase();
      if (TERMINAL_SCAN_STATUSES.has(normalized)) {
        close();
      }
      if (typeof onStatus === "function") onStatus(data);
    }
  });

  source.addEventListener("error", (err) => {
    if (closed) return;
    if (typeof onError === "function") onError(err);
  });

  return { close, eventSource: source };
}

export function getScanEndpoints(scanId) {
  return request(`/scans/${encodeURIComponent(scanId)}/endpoints`, { method: "GET" });
}

/**
 * Fetch scan findings with optional filter & sort query parameters.
 * @param {string} scanId
 * @param {{ severity?: string|string[], owasp?: string, triage_status?: string|string[], q?: string, sort?: string }} [filters]
 */
export function getScanFindings(scanId, filters = {}) {
  const params = new URLSearchParams();
  if (filters && typeof filters === "object") {
    for (const key of ["severity", "owasp", "triage_status", "q", "sort"]) {
      const raw = filters[key];
      if (raw === undefined || raw === null) continue;
      const value = Array.isArray(raw) ? raw.filter(Boolean).join(",") : String(raw).trim();
      if (value) {
        params.set(key, value);
      }
    }
  }
  const qs = params.toString();
  const suffix = qs ? `?${qs}` : "";
  return request(`/scans/${encodeURIComponent(scanId)}/findings${suffix}`, { method: "GET" });
}

/* ---------- Findings & Triage ---------- */

export function getFinding(findingId) {
  return request(`/findings/${encodeURIComponent(findingId)}`, { method: "GET" });
}

export function triageFinding(findingId, payload) {
  return request(`/findings/${encodeURIComponent(findingId)}`, {
    method: "PATCH",
    json: payload,
  });
}

/* ---------- Scan Diff & Reports ---------- */

export function compareScans(baseId, headId) {
  const params = new URLSearchParams({
    base: String(baseId),
    head: String(headId),
  });
  return request(`/scans/compare?${params.toString()}`, { method: "GET" });
}

export function getReportUrl(scanId, format = "html", download = false) {
  const params = new URLSearchParams({
    format: format === "json" ? "json" : "html",
    download: download ? "true" : "false",
  });
  return `${API_BASE}/scans/${encodeURIComponent(scanId)}/report?${params.toString()}`;
}
