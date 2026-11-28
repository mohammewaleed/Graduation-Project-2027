/**
 * Main SPA Controller for OWASP-Lite Scanner Workbench.
 * Wires all 6 dashboard views, theme persistence, live health badge,
 * New Project modal, Scan Launcher, OWASP Check Catalog, and modular view components.
 * Strict CSP & XSS safe: zero inline handlers, zero innerHTML.
 */

import {
  ApiError,
  createProject,
  deleteProject,
  deleteScan,
  getChecks,
  getHealth,
  listProjects,
  listScans,
  startScan,
  updateProject,
  updateScan,
} from "./api.js?v=11";
import { CompareScansView } from "./components/compare_view.js?v=7";
import { FindingsExplorerView } from "./components/findings_explorer.js?v=10";
import { FixModal } from "./components/fix_modal.js?v=10";
import { LiveScanView } from "./components/scan_live.js?v=10";
import { initModernSelects } from "./custom_select.js?v=7";
import {
  clear,
  el,
  formatDate,
  riskColorClass,
  severityBadge,
  shortId,
  showToast,
  statusBadge,
} from "./utils.js";

const THEME_STORAGE_KEY = "owasp_lite_theme";
const HEALTH_POLL_INTERVAL_MS = 30000;

const ACTIVE_SCAN_STATUSES = new Set(["queued", "crawling", "scanning"]);

const VIEW_TITLES = {
  overview: "Dashboard",
  launcher: "Scan Launcher",
  live: "Live Scan Progress",
  findings: "Findings Explorer",
  compare: "Compare Scans",
  checks: "OWASP Check Catalog",
};

const STACK_LABELS = {
  fastapi: "FastAPI",
  flask: "Flask",
  express: "Express",
  php: "PHP",
  html: "HTML",
};

const PROFILE_DEFINITIONS = [
  {
    id: "quick",
    name: "Quick",
    badge: "Passive Only",
    depth: 2,
    maxPages: 40,
    summary: "8 passive security checks · crawl depth 2",
    description:
      "Fast, non-intrusive audit inspecting headers, CSP, cookies, transport, CSRF tokens, error leaks, and outdated JS.",
  },
  {
    id: "standard",
    name: "Standard",
    badge: "Recommended",
    depth: 3,
    maxPages: 100,
    summary: "Passive + safe active + sensitive files · depth 3",
    description:
      "Balanced developer workflow adding safe SQLi, reflected XSS, CORS, open redirect, and sensitive file checks.",
  },
  {
    id: "deep",
    name: "Deep",
    badge: "All 17 Checks",
    depth: 5,
    maxPages: 250,
    summary: "All 17 checks incl. discovery & IDOR · depth 5",
    description:
      "Comprehensive local lab audit adding directory listing, forced browsing, boolean SQLi, and tentative IDOR heuristics.",
  },
];

const AUTH_TYPE_OPTIONS = [
  { value: "none", label: "None (Unauthenticated)" },
  { value: "cookie", label: "Cookie Header" },
  { value: "bearer", label: "Bearer Token" },
  { value: "header", label: "Custom Header (Name: Value)" },
];

const AUTH_PLACEHOLDERS = {
  cookie: "PHPSESSID=abc123; security=low",
  bearer: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  header: "X-API-Key: local-dev-token",
};

const state = {
  activeView: "overview",
  projects: [],
  scans: [],
  checks: [],
  activeScanId: null,
  selectedFindingsScanId: null,
  initialLoaded: false,
  launcher: {
    projectId: "",
    profile: "standard",
    authType: "none",
    authValue: "",
    autoLoginDvwa: false,
    dvwaUsername: "admin",
    dvwaPassword: "password",
    maxDepth: "",
    maxPages: "",
    authExpanded: false,
    checksExpanded: false,
    selectedCheckIds: new Set(),
    isCustomChecksModified: false,
    submitting: false,
    error: null,
  },
  checksFilter: {
    q: "",
    kind: "",
    profile: "",
    severity: "",
  },
};

/* ---------- DOM References ---------- */

const dom = {
  sidebar: document.getElementById("sidebar"),
  sidebarBackdrop: document.getElementById("sidebar-backdrop"),
  sidebarToggle: document.getElementById("sidebar-toggle"),
  navItems: Array.from(document.querySelectorAll(".nav-item[data-view]")),
  navLiveIndicator: document.getElementById("nav-live-indicator"),
  appVersion: document.getElementById("app-version"),
  viewTitle: document.getElementById("view-title"),
  healthBadge: document.getElementById("health-badge"),
  healthDot: document.getElementById("health-dot"),
  healthStatus: document.getElementById("health-status"),
  healthMeta: document.getElementById("health-meta"),
  themeToggle: document.getElementById("theme-toggle"),
  themeToggleIcon: document.getElementById("theme-toggle-icon"),
  themeToggleLabel: document.getElementById("theme-toggle-label"),
  openProjectModalBtn: document.getElementById("open-project-modal-btn"),

  views: {
    overview: document.getElementById("view-overview"),
    launcher: document.getElementById("view-launcher"),
    live: document.getElementById("view-live"),
    findings: document.getElementById("view-findings"),
    compare: document.getElementById("view-compare"),
    checks: document.getElementById("view-checks"),
  },

  projectModal: document.getElementById("project-modal"),
  projectModalTitle: document.getElementById("project-modal-title"),
  closeProjectModalBtn: document.getElementById("close-project-modal-btn"),
  cancelProjectModalBtn: document.getElementById("cancel-project-modal-btn"),
  projectForm: document.getElementById("project-form"),
  projectFormError: document.getElementById("project-form-error"),
  projectNameInput: document.getElementById("project-name"),
  projectBaseUrlInput: document.getElementById("project-base-url"),
  projectStackSelect: document.getElementById("project-target-stack"),
  projectAuthorizedCheckbox: document.getElementById("project-authorized"),
  submitProjectBtn: document.getElementById("submit-project-btn"),

  editScanModal: document.getElementById("edit-scan-modal"),
  editScanModalTitle: document.getElementById("edit-scan-modal-title"),
  editScanModalSubtitle: document.getElementById("edit-scan-modal-subtitle"),
  closeEditScanModalBtn: document.getElementById("close-edit-scan-modal-btn"),
  cancelEditScanModalBtn: document.getElementById("cancel-edit-scan-modal-btn"),
  editScanRerunBtn: document.getElementById("edit-scan-rerun-btn"),
  editScanForm: document.getElementById("edit-scan-form"),
  editScanFormError: document.getElementById("edit-scan-form-error"),
  editScanProfileSelect: document.getElementById("edit-scan-profile"),
  editScanMaxDepthInput: document.getElementById("edit-scan-max-depth"),
  editScanMaxPagesInput: document.getElementById("edit-scan-max-pages"),
  submitEditScanBtn: document.getElementById("submit-edit-scan-btn"),

  fixModal: document.getElementById("fix-modal"),
  fixModalBody: document.getElementById("fix-modal-body"),
};

/* ---------- Component Instances ---------- */

let fixModal = null;
let liveScanView = null;
let findingsExplorerView = null;
let compareScansView = null;
let isProjectModalOpen = false;
let editingProjectId = null;
let projectModalPreviousFocus = null;
let isEditScanModalOpen = false;
let editingScan = null;
let editScanModalPreviousFocus = null;

/* ---------- Helpers ---------- */

function formatDialectName(dialect) {
  const raw = String(dialect || "sqlite").trim().toLowerCase();
  if (raw === "sqlite") return "SQLite";
  if (raw === "postgresql" || raw === "postgres") return "PostgreSQL";
  if (raw === "mysql") return "MySQL";
  return raw ? raw.charAt(0).toUpperCase() + raw.slice(1) : "DB";
}

function formatStackLabel(stack) {
  const key = String(stack || "fastapi").trim().toLowerCase();
  return STACK_LABELS[key] || key.toUpperCase();
}

function formatApiError(err, fallback = "An unexpected error occurred.") {
  if (err instanceof ApiError) {
    return err.code ? `[${err.code}] ${err.message}` : err.message;
  }
  if (err && typeof err.message === "string" && err.message.trim()) {
    return err.message.trim();
  }
  return fallback;
}

function getProjectById(projectId) {
  if (!projectId) return null;
  return state.projects.find((p) => p.id === projectId) || null;
}

function getLatestScanForProject(projectId) {
  if (!projectId) return null;
  return state.scans.find((s) => s.project_id === projectId) || null;
}

function resolvePreferredStack(context = {}) {
  const scanFromCtx = context?.scan || null;
  let projectId = scanFromCtx?.project_id || null;

  if (!projectId && context?.finding?.scan_id) {
    const matchedScan = state.scans.find((s) => s.id === context.finding.scan_id);
    projectId = matchedScan?.project_id || null;
  }

  if (!projectId && state.activeView === "findings" && findingsExplorerView) {
    const currentScanId = findingsExplorerView.getCurrentScanId();
    const matchedScan = state.scans.find((s) => s.id === currentScanId);
    projectId = matchedScan?.project_id || null;
  }

  const project = getProjectById(projectId);
  return project?.target_stack || null;
}

function getProfileDefaultCheckIds(profile) {
  const normalized = String(profile || "standard").trim().toLowerCase();
  const ids = new Set();
  for (const check of state.checks) {
    const profiles = Array.isArray(check.profiles)
      ? check.profiles.map((p) => String(p).toLowerCase())
      : [];
    if (profiles.includes(normalized)) {
      ids.add(check.id);
    }
  }
  return ids;
}

function syncLauncherDefaultChecks() {
  if (state.launcher.isCustomChecksModified) return;
  state.launcher.selectedCheckIds = getProfileDefaultCheckIds(state.launcher.profile);
}

function updateLiveIndicator() {
  if (!dom.navLiveIndicator) return;
  const hasRunningScan =
    Boolean(liveScanView && liveScanView.isStreaming()) ||
    state.scans.some((scan) => ACTIVE_SCAN_STATUSES.has(String(scan.status || "").toLowerCase()));
  dom.navLiveIndicator.classList.toggle("hidden", !hasRunningScan);
  dom.navLiveIndicator.hidden = !hasRunningScan;
}

function openFindingModal(findingId, context = {}) {
  if (!findingId || !fixModal) return;
  const preferredStack = resolvePreferredStack(context);
  fixModal.open(findingId, { preferredStack });
}

/* ---------- Theme Persistence & Toggle ---------- */

function readSavedTheme() {
  try {
    const saved = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (saved === "light" || saved === "dark") return saved;
  } catch (_err) {
    // Storage may be unavailable in restricted contexts.
  }
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

function applyTheme(theme) {
  const normalized = theme === "light" ? "light" : "dark";
  document.documentElement.dataset.theme = normalized;
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, normalized);
  } catch (_err) {
    // Ignore storage quota or privacy-mode failures.
  }

  if (dom.themeToggleIcon) {
    dom.themeToggleIcon.textContent = normalized === "dark" ? "☀" : "☾";
  }
  if (dom.themeToggleLabel) {
    dom.themeToggleLabel.textContent = normalized === "dark" ? "Light" : "Dark";
  }
  if (dom.themeToggle) {
    dom.themeToggle.setAttribute(
      "aria-label",
      normalized === "dark" ? "Switch to light theme" : "Switch to dark theme",
    );
  }
}

/* ---------- Mobile Sidebar Drawer ---------- */

function setSidebarOpen(open) {
  if (!dom.sidebar || !dom.sidebarBackdrop) return;
  dom.sidebar.classList.toggle("open", open);
  dom.sidebarBackdrop.classList.toggle("hidden", !open);
  dom.sidebarBackdrop.hidden = !open;
  if (dom.sidebarToggle) {
    dom.sidebarToggle.setAttribute("aria-expanded", open ? "true" : "false");
  }
}

/* ---------- Health Badge Polling ---------- */

async function refreshHealth(interactive = false) {
  if (!dom.healthBadge || !dom.healthDot || !dom.healthStatus) return;
  try {
    const health = await getHealth();
    const overallOk = String(health?.status || "").toLowerCase() === "ok";
    const dbDialect = formatDialectName(health?.database?.dialect);
    const dbStatus = String(health?.database?.status || (overallOk ? "up" : "down")).toUpperCase();

    dom.healthDot.className = `health-dot ${overallOk ? "health-dot--ok" : "health-dot--degraded"}`;
    dom.healthStatus.textContent = `${dbDialect} · ${dbStatus}`;
    if (dom.healthMeta) {
      dom.healthMeta.textContent = overallOk ? "API OK" : "Degraded";
    }
    if (dom.appVersion && health?.version) {
      dom.appVersion.textContent = `v${health.version}`;
    }
    if (interactive) {
      showToast(`Scanner API healthy (${dbDialect} · ${dbStatus}).`, "success");
    }
  } catch (err) {
    dom.healthDot.className = "health-dot health-dot--error";
    dom.healthStatus.textContent = "API Offline";
    if (dom.healthMeta) {
      dom.healthMeta.textContent = "";
    }
    if (interactive) {
      showToast(formatApiError(err, "Unable to reach scanner API."), "error");
    }
  }
}

/* ---------- New Project Modal ---------- */

function showProjectFormError(message) {
  if (!dom.projectFormError) return;
  if (!message) {
    dom.projectFormError.textContent = "";
    dom.projectFormError.classList.add("hidden");
    dom.projectFormError.hidden = true;
    return;
  }
  dom.projectFormError.textContent = message;
  dom.projectFormError.classList.remove("hidden");
  dom.projectFormError.hidden = false;
}

function openProjectModal(project = null) {
  if (!dom.projectModal || !dom.projectForm) return;
  projectModalPreviousFocus =
    document.activeElement instanceof HTMLElement ? document.activeElement : null;

  dom.projectForm.reset();
  showProjectFormError(null);
  editingProjectId = project ? project.id : null;

  if (dom.projectModalTitle) {
    dom.projectModalTitle.textContent = project
      ? "Edit Authorized Local Project"
      : "New Authorized Local Project";
  }

  if (project) {
    if (dom.projectNameInput) dom.projectNameInput.value = project.name || "";
    if (dom.projectBaseUrlInput) dom.projectBaseUrlInput.value = project.base_url || "";
    if (dom.projectStackSelect) {
      dom.projectStackSelect.value = project.target_stack || "fastapi";
      dom.projectStackSelect.dispatchEvent(new Event("change", { bubbles: true }));
    }
    if (dom.projectAuthorizedCheckbox) dom.projectAuthorizedCheckbox.checked = true;
  }

  if (dom.submitProjectBtn) {
    dom.submitProjectBtn.disabled = false;
    dom.submitProjectBtn.textContent = project ? "Save Changes" : "Create Project";
  }

  isProjectModalOpen = true;
  dom.projectModal.classList.remove("hidden");
  dom.projectModal.hidden = false;
  document.body.style.overflow = "hidden";

  if (dom.projectNameInput) {
    dom.projectNameInput.focus();
  }
}

function closeProjectModal() {
  if (!dom.projectModal) return;
  isProjectModalOpen = false;
  editingProjectId = null;
  dom.projectModal.classList.add("hidden");
  dom.projectModal.hidden = true;
  if ((!fixModal || !fixModal.isOpen()) && !isEditScanModalOpen) {
    document.body.style.overflow = "";
  }
  if (projectModalPreviousFocus && typeof projectModalPreviousFocus.focus === "function") {
    try {
      projectModalPreviousFocus.focus();
    } catch (_err) {
      // Ignore if previous focus target was detached.
    }
  }
  projectModalPreviousFocus = null;
}

async function handleProjectFormSubmit(event) {
  event.preventDefault();
  showProjectFormError(null);

  const isEditing = Boolean(editingProjectId);
  const name = String(dom.projectNameInput?.value || "").trim();
  const baseUrl = String(dom.projectBaseUrlInput?.value || "").trim();
  const targetStack = String(dom.projectStackSelect?.value || "fastapi").trim().toLowerCase();
  const authorizedConfirmed = Boolean(dom.projectAuthorizedCheckbox?.checked);

  if (!name) {
    showProjectFormError("Project Name is required.");
    dom.projectNameInput?.focus();
    return;
  }

  if (!baseUrl) {
    showProjectFormError("Target Base URL is required (e.g., http://127.0.0.1:5050).");
    dom.projectBaseUrlInput?.focus();
    return;
  }

  if (!authorizedConfirmed) {
    showProjectFormError(
      "Authorization confirmation is required. Confirm that you own or are authorized to test this local/private target.",
    );
    dom.projectAuthorizedCheckbox?.focus();
    return;
  }

  if (dom.submitProjectBtn) {
    dom.submitProjectBtn.disabled = true;
    dom.submitProjectBtn.textContent = isEditing ? "Saving..." : "Creating...";
  }

  try {
    let saved;
    if (isEditing) {
      saved = await updateProject(editingProjectId, {
        name,
        base_url: baseUrl,
        target_stack: targetStack,
      });
      closeProjectModal();
      showToast(`Project "${saved.name}" updated.`, "success");
    } else {
      saved = await createProject({
        name,
        base_url: baseUrl,
        target_stack: targetStack,
        authorized_confirmed: true,
      });
      closeProjectModal();
      showToast(`Project "${saved.name}" created successfully.`, "success");
      if (!state.launcher.projectId || state.activeView === "launcher") {
        state.launcher.projectId = saved.id;
      }
    }

    await refreshCoreData({ skipChecks: true });
    if (state.activeView === "overview") {
      renderOverview();
    } else if (state.activeView === "launcher") {
      renderLauncher();
    }
  } catch (err) {
    showProjectFormError(
      formatApiError(err, isEditing ? "Failed to update project." : "Failed to create project."),
    );
  } finally {
    if (dom.submitProjectBtn) {
      dom.submitProjectBtn.disabled = false;
      dom.submitProjectBtn.textContent = editingProjectId ? "Save Changes" : "Create Project";
    }
  }
}

/* ---------- Edit Scan Modal & Scan Deletion ---------- */

function showEditScanFormError(message) {
  if (!dom.editScanFormError) return;
  if (!message) {
    dom.editScanFormError.textContent = "";
    dom.editScanFormError.classList.add("hidden");
    dom.editScanFormError.hidden = true;
    return;
  }
  dom.editScanFormError.textContent = message;
  dom.editScanFormError.classList.remove("hidden");
  dom.editScanFormError.hidden = false;
}

function openEditScanModal(scan) {
  if (!scan || !dom.editScanModal || !dom.editScanForm) return;
  editScanModalPreviousFocus =
    document.activeElement instanceof HTMLElement ? document.activeElement : null;

  editingScan = scan;
  dom.editScanForm.reset();
  showEditScanFormError(null);

  const cfg = scan.config && typeof scan.config === "object" ? scan.config : {};
  const projectObj = getProjectById(scan.project_id);
  const projectName = scan.project_name || projectObj?.name || `Project ${shortId(scan.project_id)}`;

  if (dom.editScanModalTitle) {
    dom.editScanModalTitle.textContent = `Edit Scan #${shortId(scan.id)}`;
  }
  if (dom.editScanModalSubtitle) {
    dom.editScanModalSubtitle.textContent = `${projectName} · Save changes or open in Scan Launcher to re-run.`;
  }
  if (dom.editScanProfileSelect) {
    dom.editScanProfileSelect.value = String(scan.profile || "standard").toLowerCase();
    dom.editScanProfileSelect.dispatchEvent(new Event("change", { bubbles: true }));
  }
  if (dom.editScanMaxDepthInput) {
    dom.editScanMaxDepthInput.value =
      cfg.max_depth !== undefined && cfg.max_depth !== null ? String(cfg.max_depth) : "";
  }
  if (dom.editScanMaxPagesInput) {
    dom.editScanMaxPagesInput.value =
      cfg.max_pages !== undefined && cfg.max_pages !== null ? String(cfg.max_pages) : "";
  }

  const isRunning =
    String(scan.status || "").toLowerCase() === "crawling" ||
    String(scan.status || "").toLowerCase() === "scanning";
  if (dom.submitEditScanBtn) {
    dom.submitEditScanBtn.disabled = isRunning;
    dom.submitEditScanBtn.textContent = "Save Changes";
  }
  if (isRunning) {
    showEditScanFormError("This scan is currently running. Cancel it first to edit saved fields, or click 'Edit in Scan Launcher'.");
  }

  isEditScanModalOpen = true;
  dom.editScanModal.classList.remove("hidden");
  dom.editScanModal.hidden = false;
  document.body.style.overflow = "hidden";
  dom.editScanProfileSelect?.focus();
}

function closeEditScanModal() {
  if (!dom.editScanModal) return;
  isEditScanModalOpen = false;
  editingScan = null;
  dom.editScanModal.classList.add("hidden");
  dom.editScanModal.hidden = true;
  if ((!fixModal || !fixModal.isOpen()) && !isProjectModalOpen) {
    document.body.style.overflow = "";
  }
  if (editScanModalPreviousFocus && typeof editScanModalPreviousFocus.focus === "function") {
    try {
      editScanModalPreviousFocus.focus();
    } catch (_err) {
      // Ignore if previous focus target was detached.
    }
  }
  editScanModalPreviousFocus = null;
}

function prefillLauncherFromScan(scan) {
  if (!scan) return;
  const cfg = scan.config && typeof scan.config === "object" ? scan.config : {};
  state.launcher.projectId = scan.project_id || state.launcher.projectId;
  state.launcher.profile = String(dom.editScanProfileSelect?.value || scan.profile || "standard").toLowerCase();
  const depthVal = String(dom.editScanMaxDepthInput?.value ?? (cfg.max_depth ?? "")).trim();
  const pagesVal = String(dom.editScanMaxPagesInput?.value ?? (cfg.max_pages ?? "")).trim();
  state.launcher.maxDepth = depthVal;
  state.launcher.maxPages = pagesVal;
  if (Array.isArray(cfg.enabled_checks) && cfg.enabled_checks.length > 0) {
    state.launcher.selectedCheckIds = new Set(cfg.enabled_checks);
    state.launcher.isCustomChecksModified = true;
  } else {
    state.launcher.isCustomChecksModified = false;
  }
  state.launcher.error = null;
}

async function handleEditScanFormSubmit(event) {
  event.preventDefault();
  if (!editingScan) return;
  showEditScanFormError(null);

  const profile = String(dom.editScanProfileSelect?.value || "standard").trim().toLowerCase();
  const maxDepthRaw = String(dom.editScanMaxDepthInput?.value || "").trim();
  const maxPagesRaw = String(dom.editScanMaxPagesInput?.value || "").trim();

  const payload = { profile };
  if (maxDepthRaw !== "") {
    const parsed = Number.parseInt(maxDepthRaw, 10);
    if (Number.isNaN(parsed) || parsed < 0 || parsed > 10) {
      showEditScanFormError("Max crawl depth must be an integer between 0 and 10.");
      dom.editScanMaxDepthInput?.focus();
      return;
    }
    payload.max_depth = parsed;
  }
  if (maxPagesRaw !== "") {
    const parsed = Number.parseInt(maxPagesRaw, 10);
    if (Number.isNaN(parsed) || parsed < 1 || parsed > 2000) {
      showEditScanFormError("Max pages must be an integer between 1 and 2000.");
      dom.editScanMaxPagesInput?.focus();
      return;
    }
    payload.max_pages = parsed;
  }

  if (dom.submitEditScanBtn) {
    dom.submitEditScanBtn.disabled = true;
    dom.submitEditScanBtn.textContent = "Saving...";
  }

  try {
    const updated = await updateScan(editingScan.id, payload);
    closeEditScanModal();
    showToast(`Scan #${shortId(updated.id)} updated.`, "success");
    await refreshCoreData({ skipChecks: true });
    if (state.activeView === "overview") {
      renderOverview();
    }
  } catch (err) {
    showEditScanFormError(formatApiError(err, "Failed to update scan."));
  } finally {
    if (dom.submitEditScanBtn) {
      dom.submitEditScanBtn.disabled = false;
      dom.submitEditScanBtn.textContent = "Save Changes";
    }
  }
}

async function handleDeleteScan(scan) {
  if (!scan) return;
  const statusLower = String(scan.status || "").toLowerCase();
  if (statusLower === "crawling" || statusLower === "scanning") {
    showToast("Cancel the running scan before deleting it.", "error");
    return;
  }
  const projectObj = getProjectById(scan.project_id);
  const projectName = scan.project_name || projectObj?.name || `Project ${shortId(scan.project_id)}`;
  const confirmed = window.confirm(
    `Delete scan #${shortId(scan.id)} (${projectName} · ${String(scan.profile || "standard").toUpperCase()}) and all of its findings?`,
  );
  if (!confirmed) return;

  try {
    await deleteScan(scan.id);
    showToast(`Deleted scan #${shortId(scan.id)}.`, "info");
    if (state.activeScanId === scan.id) {
      state.activeScanId = null;
    }
    if (state.selectedFindingsScanId === scan.id) {
      state.selectedFindingsScanId = null;
    }
    await refreshCoreData({ skipChecks: true });
    if (state.activeView === "overview") {
      renderOverview();
    } else if (state.activeView === "findings") {
      await findingsExplorerView.load(state.selectedFindingsScanId, state.scans);
    }
  } catch (err) {
    showToast(formatApiError(err, "Failed to delete scan."), "error");
  }
}

/* ---------- Core Data Synchronization ---------- */

async function refreshCoreData(options = {}) {
  const { skipChecks = false } = options;

  try {
    const tasks = [listProjects(), listScans()];
    if (!skipChecks || state.checks.length === 0) {
      tasks.push(getChecks());
    }

    const results = await Promise.all(tasks);
    state.projects = Array.isArray(results[0]) ? results[0] : [];
    state.scans = Array.isArray(results[1]) ? results[1] : [];
    if (results.length > 2) {
      state.checks = Array.isArray(results[2]) ? results[2] : [];
    }
    state.initialLoaded = true;

    // Ensure launcher project selection stays valid
    const projectIds = new Set(state.projects.map((p) => p.id));
    if (!projectIds.has(state.launcher.projectId)) {
      state.launcher.projectId = state.projects[0]?.id || "";
    }

    // Ensure default check selection is populated once catalog loads
    syncLauncherDefaultChecks();

    // Ensure activeScanId points to a valid scan if one exists
    const scanIds = new Set(state.scans.map((s) => s.id));
    if (state.activeScanId && !scanIds.has(state.activeScanId)) {
      state.activeScanId = null;
    }
    if (!state.activeScanId && state.scans.length > 0) {
      const running = state.scans.find((s) =>
        ACTIVE_SCAN_STATUSES.has(String(s.status || "").toLowerCase()),
      );
      state.activeScanId = running ? running.id : state.scans[0].id;
    }

    if (state.selectedFindingsScanId && !scanIds.has(state.selectedFindingsScanId)) {
      state.selectedFindingsScanId = state.scans[0]?.id || null;
    }

    if (findingsExplorerView) {
      findingsExplorerView.setScans(state.scans);
    }
    if (compareScansView) {
      compareScansView.setScans(state.scans);
    }

    updateLiveIndicator();
  } catch (err) {
    showToast(formatApiError(err, "Failed to refresh dashboard data."), "error");
  }
}

/* ---------- Navigation Controller ---------- */

async function navigate(viewName, options = {}) {
  const targetView = Object.prototype.hasOwnProperty.call(VIEW_TITLES, viewName)
    ? viewName
    : "overview";
  const previousView = state.activeView;

  // Tear down SSE connection cleanly when navigating away from Live view
  if (previousView === "live" && targetView !== "live" && liveScanView) {
    liveScanView.disconnect();
  }

  state.activeView = targetView;

  // Update sidebar active states & topbar title
  for (const item of dom.navItems) {
    const isActive = item.dataset.view === targetView;
    item.classList.toggle("active", isActive);
    if (isActive) {
      item.setAttribute("aria-current", "page");
    } else {
      item.removeAttribute("aria-current");
    }
  }

  if (dom.viewTitle) {
    dom.viewTitle.textContent = VIEW_TITLES[targetView];
  }

  for (const [key, panel] of Object.entries(dom.views)) {
    if (!panel) continue;
    const visible = key === targetView;
    panel.classList.toggle("hidden", !visible);
    panel.hidden = !visible;
  }

  setSidebarOpen(false);

  if (targetView === "overview") {
    renderOverview();
    if (options.refresh) {
      await refreshCoreData({ skipChecks: true });
      if (state.activeView === "overview") {
        renderOverview();
      }
    }
    return;
  }

  if (targetView === "launcher") {
    if (options.projectId) {
      state.launcher.projectId = options.projectId;
    }
    state.launcher.error = null;
    syncLauncherDefaultChecks();
    renderLauncher();
    return;
  }

  if (targetView === "live") {
    const scanId = options.scanId || state.activeScanId;
    if (scanId) {
      state.activeScanId = scanId;
      await liveScanView.load(scanId, options.initialScan || null);
      updateLiveIndicator();
    } else {
      liveScanView.renderEmpty();
    }
    return;
  }

  if (targetView === "findings") {
    const scanId =
      options.scanId ||
      state.selectedFindingsScanId ||
      findingsExplorerView.getCurrentScanId() ||
      state.scans[0]?.id ||
      null;
    state.selectedFindingsScanId = scanId;
    await findingsExplorerView.load(scanId, state.scans);
    return;
  }

  if (targetView === "compare") {
    compareScansView.setScans(state.scans);
    return;
  }

  if (targetView === "checks") {
    renderChecksCatalog();
  }
}

/* ---------- View 1: Overview & Projects Home ---------- */

function buildFindingsSummaryBadges(summary) {
  const counts = summary && typeof summary === "object" ? summary : {};
  const keys = ["critical", "high", "medium", "low", "info"];
  const pills = [];

  for (const sev of keys) {
    const count = Number(counts[sev] || 0);
    if (count > 0) {
      pills.push(
        el("span", {
          class: `badge badge-sev-${sev} mono`,
          text: `${sev.charAt(0).toUpperCase()}:${count}`,
          title: `${count} ${sev} finding${count === 1 ? "" : "s"}`,
        }),
      );
    }
  }

  if (pills.length === 0) {
    return el("span", { class: "text-xs text-muted", text: "0 findings" });
  }
  return el("div", { class: "row", style: { gap: "4px" } }, pills);
}

async function handleDeleteProject(project) {
  if (!project) return;
  const confirmed = window.confirm(
    `Delete project "${project.name}" (${project.base_url}) and all of its scan history?`,
  );
  if (!confirmed) return;

  try {
    await deleteProject(project.id);
    showToast(`Deleted project "${project.name}".`, "info");

    if (state.launcher.projectId === project.id) {
      state.launcher.projectId = "";
    }
    await refreshCoreData({ skipChecks: true });
    if (state.activeView === "overview") {
      renderOverview();
    }
  } catch (err) {
    showToast(formatApiError(err, "Failed to delete project."), "error");
  }
}

function renderOverview() {
  const container = dom.views.overview;
  if (!container) return;
  clear(container);

  // Compute KPI metrics
  const totalProjects = state.projects.length;
  const totalScans = state.scans.length;
  const runningCount = state.scans.filter((s) =>
    ACTIVE_SCAN_STATUSES.has(String(s.status || "").toLowerCase()),
  ).length;
  const completedCount = state.scans.filter(
    (s) => String(s.status || "").toLowerCase() === "completed",
  ).length;

  const projectScores = state.projects
    .map((p) => p.latest_risk_score)
    .filter((v) => v !== null && v !== undefined && !Number.isNaN(Number(v)))
    .map(Number);

  const fallbackScores =
    projectScores.length > 0
      ? projectScores
      : state.scans
          .filter((s) => String(s.status || "").toLowerCase() === "completed")
          .map((s) => Number(s.risk_score || 0));

  const hasScores = fallbackScores.length > 0;
  const maxRisk = hasScores ? Math.max(...fallbackScores) : null;
  const avgRisk = hasScores
    ? Math.round(fallbackScores.reduce((sum, val) => sum + val, 0) / fallbackScores.length)
    : null;

  const checksCount = state.checks.length || 17;

  // 1. KPI Summary Strip
  const riskKpiValue = hasScores
    ? el("div", { class: "row", style: { gap: "8px" } }, [
        el("span", { class: "kpi-value mono", text: `${maxRisk}` }),
        el("span", {
          class: `risk-pill ${riskColorClass(maxRisk)}`,
          text: `Max / 100`,
        }),
      ])
    : el("div", { class: "kpi-value mono text-muted", text: "—" });

  const kpiGrid = el("div", { class: "kpi-grid" }, [
    el("div", { class: "kpi-card" }, [
      el("span", { class: "kpi-label", text: "Total Projects" }),
      el("div", { class: "kpi-value mono", text: String(totalProjects) }),
      el("span", { class: "kpi-sub", text: "Authorized local/private targets" }),
    ]),
    el(
      "div",
      {
        class: "kpi-card clickable",
        title: "Open Scan Launcher",
        on: { click: () => navigate("launcher") },
      },
      [
        el("span", { class: "kpi-label", text: "Total Scans" }),
        el("div", { class: "row-between" }, [
          el("span", { class: "kpi-value mono", text: String(totalScans) }),
          el("button", {
            type: "button",
            class: "btn btn-ghost btn-sm",
            text: "Scan →",
            on: {
              click: (e) => {
                e.stopPropagation();
                navigate("launcher");
              },
            },
          }),
        ]),
        el("span", {
          class: "kpi-sub",
          text: `${runningCount} active · ${completedCount} completed`,
        }),
      ],
    ),
    el("div", { class: "kpi-card" }, [
      el("span", { class: "kpi-label", text: "Latest Risk (Max / Avg)" }),
      riskKpiValue,
      el("span", {
        class: "kpi-sub",
        text: hasScores
          ? `Avg ${avgRisk}/100 across ${fallbackScores.length} scored target${fallbackScores.length === 1 ? "" : "s"}`
          : "Run a scan to calculate risk posture",
      }),
    ]),
    el("div", { class: "kpi-card" }, [
      el("span", { class: "kpi-label", text: "Registered OWASP Checks" }),
      el("div", { class: "row-between" }, [
        el("span", { class: "kpi-value mono", text: String(checksCount) }),
        el("button", {
          type: "button",
          class: "btn btn-ghost btn-sm",
          text: "Browse →",
          on: { click: () => navigate("checks") },
        }),
      ]),
      el("span", { class: "kpi-sub", text: "OWASP Top 10:2021 ruleset" }),
    ]),
  ]);

  // 2. Projects Grid Section
  let projectsContent;
  if (state.projects.length === 0) {
    projectsContent = el("div", { class: "empty-state" }, [
      el("h4", { class: "empty-state-title", text: "No Projects Registered Yet" }),
      el("p", {
        class: "empty-state-desc",
        text: "Register an authorized local or Docker lab target (such as http://127.0.0.1:5050) to launch OWASP Top 10 scans and view actionable code fixes.",
      }),
      el("button", {
        type: "button",
        class: "btn btn-primary",
        text: "+ Register First Project",
        on: { click: () => openProjectModal() },
      }),
    ]);
  } else {
    projectsContent = el(
      "div",
      { class: "projects-grid" },
      state.projects.map((project) => {
        const latestScan = getLatestScanForProject(project.id);
        const hasRisk =
          project.latest_risk_score !== null && project.latest_risk_score !== undefined;
        const riskText = hasRisk ? `Risk ${project.latest_risk_score}/100` : "Not Scanned";
        const riskCls = riskColorClass(project.latest_risk_score);

        return el(
          "article",
          {
            class: "project-card clickable",
            title: `Click to open Scan Launcher for ${project.name}`,
            on: {
              click: (e) => {
                if (e.target.closest("button")) return;
                navigate("launcher", { projectId: project.id });
              },
            },
          },
          [
            el("div", { class: "row-between", style: { alignItems: "center" } }, [
              el("div", { style: { minWidth: "0", flex: "1" } }, [
                el("h4", {
                  class: "card-title truncate",
                  text: project.name,
                  title: project.name,
                }),
              ]),
              el("span", { class: `risk-pill ${riskCls}`, text: riskText }),
            ]),

            el("div", { class: "row text-xs text-muted" }, [
              el("span", {
                class: "badge badge-stack",
                text: formatStackLabel(project.target_stack),
              }),
              el("span", {
                class: "badge badge-neutral mono",
                text: `${project.scan_count ?? 0} scan${project.scan_count === 1 ? "" : "s"}`,
              }),
              el("span", { text: `Added ${formatDate(project.created_at)}` }),
            ]),

            el(
              "div",
              {
                class: "row",
                style: { marginTop: "auto", paddingTop: "6px", justifyContent: "space-between", gap: "8px" },
              },
              [
                el("div", { class: "row", style: { gap: "6px" } }, [
                  el("button", {
                    type: "button",
                    class: "btn btn-primary btn-sm",
                    text: "Launch Scan",
                    on: {
                      click: (e) => {
                        e.stopPropagation();
                        navigate("launcher", { projectId: project.id });
                      },
                    },
                  }),
                  el("button", {
                    type: "button",
                    class: "btn btn-secondary btn-sm",
                    text: "Latest Results",
                    disabled: !latestScan,
                    title: latestScan
                      ? `Open Findings Explorer for scan #${shortId(latestScan.id)}`
                      : "Run a scan first to view results",
                    on: {
                      click: (e) => {
                        e.stopPropagation();
                        if (latestScan) {
                          navigate("findings", { scanId: latestScan.id });
                        }
                      },
                    },
                  }),
                ]),
                el("div", { class: "row", style: { gap: "6px" } }, [
                  el("button", {
                    type: "button",
                    class: "btn btn-ghost btn-sm",
                    text: "Edit",
                    "aria-label": `Edit project ${project.name}`,
                    on: {
                      click: (e) => {
                        e.stopPropagation();
                        openProjectModal(project);
                      },
                    },
                  }),
                  el("button", {
                    type: "button",
                    class: "btn btn-danger btn-sm",
                    text: "Delete",
                    "aria-label": `Delete project ${project.name}`,
                    on: {
                      click: (e) => {
                        e.stopPropagation();
                        handleDeleteProject(project);
                      },
                    },
                  }),
                ]),
              ],
            ),
          ],
        );
      }),
    );
  }

  const projectsCard = el("div", { class: "card" }, [
    el("div", { class: "card-header" }, [
      el("div", null, [
        el("h3", { class: "card-title", text: "Authorized Target Projects" }),
        el("p", {
          class: "card-subtitle",
          text: "Localhost and private lab applications scoped for developer security testing.",
        }),
      ]),
      el("button", {
        type: "button",
        class: "btn btn-primary btn-sm",
        text: "+ New Project",
        on: { click: () => openProjectModal() },
      }),
    ]),
    el("div", { class: "card-body" }, [projectsContent]),
  ]);

  // 3. Recent Scans Table
  let scansContent;
  if (state.scans.length === 0) {
    scansContent = el("div", { class: "empty-state" }, [
      el("h4", { class: "empty-state-title", text: "No Scans Executed Yet" }),
      el("p", {
        class: "empty-state-desc",
        text: "Launch a Quick, Standard, or Deep scan to stream live progress and inspect OWASP Top 10 findings.",
      }),
      el("button", {
        type: "button",
        class: "btn btn-secondary",
        text: "Open Scan Launcher",
        on: { click: () => navigate("launcher") },
      }),
    ]);
  } else {
    const tbody = el(
      "tbody",
      null,
      state.scans.slice(0, 20).map((scan) => {
        const statusLower = String(scan.status || "queued").toLowerCase();
        const isActive = ACTIVE_SCAN_STATUSES.has(statusLower);
        const projectObj = getProjectById(scan.project_id);
        const projectName = scan.project_name || projectObj?.name || `Project ${shortId(scan.project_id)}`;
        const riskVal = scan.risk_score ?? 0;

        const openScanDirect = () => {
          if (isActive) {
            navigate("live", { scanId: scan.id, initialScan: scan });
          } else {
            navigate("findings", { scanId: scan.id });
          }
        };

        return el(
          "tr",
          {
            class: "clickable-row",
            title: isActive
              ? `Click to open Live Scan #${shortId(scan.id)}`
              : `Click to open Findings for Scan #${shortId(scan.id)}`,
            on: {
              click: (e) => {
                if (e.target.closest("button")) return;
                openScanDirect();
              },
            },
          },
          [
            el("td", null, [
              el("span", {
                class: "mono text-xs",
                style: { fontWeight: "700", color: "var(--text-primary)" },
                text: `#${shortId(scan.id)}`,
                title: scan.id,
              }),
            ]),
            el("td", null, [
              el("span", {
                style: { fontWeight: "600", color: "var(--text-primary)" },
                text: projectName,
              }),
            ]),
            el("td", null, [
              el("span", {
                class: "badge badge-stack",
                text: String(scan.profile || "standard").toUpperCase(),
              }),
            ]),
            el("td", null, [statusBadge(statusLower)]),
            el("td", null, [
              el("span", {
                class: `risk-pill ${riskColorClass(isActive ? null : riskVal)}`,
                text: isActive ? `${scan.progress_pct ?? 0}%` : `${riskVal}/100`,
              }),
            ]),
            el("td", null, [buildFindingsSummaryBadges(scan.summary)]),
            el("td", null, [
              el("span", {
                class: "text-xs text-muted",
                text: formatDate(scan.created_at || scan.started_at),
              }),
            ]),
            el("td", null, [
              el("div", { class: "row", style: { gap: "6px", flexWrap: "nowrap" } }, [
                isActive
                  ? el("button", {
                      type: "button",
                      class: "btn btn-primary btn-sm",
                      text: "Live",
                      on: {
                        click: (e) => {
                          e.stopPropagation();
                          navigate("live", { scanId: scan.id, initialScan: scan });
                        },
                      },
                    })
                  : el("button", {
                      type: "button",
                      class: "btn btn-secondary btn-sm",
                      text: "Results",
                      on: {
                        click: (e) => {
                          e.stopPropagation();
                          navigate("findings", { scanId: scan.id });
                        },
                      },
                    }),
                el("button", {
                  type: "button",
                  class: "btn btn-ghost btn-sm",
                  text: "Edit",
                  "aria-label": `Edit scan ${shortId(scan.id)}`,
                  on: {
                    click: (e) => {
                      e.stopPropagation();
                      openEditScanModal(scan);
                    },
                  },
                }),
                el("button", {
                  type: "button",
                  class: "btn btn-danger btn-sm",
                  text: "Delete",
                  disabled: statusLower === "crawling" || statusLower === "scanning",
                  title:
                    statusLower === "crawling" || statusLower === "scanning"
                      ? "Cancel the running scan before deleting"
                      : `Delete scan #${shortId(scan.id)}`,
                  "aria-label": `Delete scan ${shortId(scan.id)}`,
                  on: {
                    click: (e) => {
                      e.stopPropagation();
                      handleDeleteScan(scan);
                    },
                  },
                }),
              ]),
            ]),
          ],
        );
      }),
    );

    scansContent = el("div", { class: "table-wrap" }, [
      el("table", { class: "data-table" }, [
        el("thead", null, [
          el("tr", null, [
            el("th", { text: "Scan ID" }),
            el("th", { text: "Project" }),
            el("th", { text: "Profile" }),
            el("th", { text: "Status" }),
            el("th", { text: "Risk Score" }),
            el("th", { text: "Findings" }),
            el("th", { text: "Started" }),
            el("th", { text: "Action" }),
          ]),
        ]),
        tbody,
      ]),
    ]);
  }

  const scansCard = el("div", { class: "card" }, [
    el("div", { class: "card-header" }, [
      el("div", null, [
        el("h3", { class: "card-title", text: "Recent Scans" }),
        el("p", {
          class: "card-subtitle",
          text: "Latest scan jobs across all registered targets. Jump straight into live telemetry or full findings.",
        }),
      ]),
      el("button", {
        type: "button",
        class: "btn btn-ghost btn-sm",
        text: "Refresh",
        on: {
          click: async () => {
            await refreshCoreData({ skipChecks: true });
            renderOverview();
            showToast("Dashboard refreshed.", "info");
          },
        },
      }),
    ]),
    scansContent,
  ]);

  container.appendChild(kpiGrid);
  container.appendChild(projectsCard);
  container.appendChild(scansCard);
}

/* ---------- View 2: Scan Launcher ---------- */

async function handleLaunchScanSubmit(event) {
  event.preventDefault();
  state.launcher.error = null;

  if (!state.launcher.projectId) {
    state.launcher.error = "Select a target project before launching a scan.";
    renderLauncher();
    return;
  }

  if (state.launcher.isCustomChecksModified && state.launcher.selectedCheckIds.size === 0) {
    state.launcher.error = "Select at least one security check or click 'Reset to Profile'.";
    renderLauncher();
    return;
  }

  const maxDepthRaw = String(state.launcher.maxDepth || "").trim();
  const maxPagesRaw = String(state.launcher.maxPages || "").trim();

  let maxDepth = null;
  if (maxDepthRaw !== "") {
    const parsed = Number.parseInt(maxDepthRaw, 10);
    if (Number.isNaN(parsed) || parsed < 0 || parsed > 10) {
      state.launcher.error = "Max crawl depth must be an integer between 0 and 10.";
      renderLauncher();
      return;
    }
    maxDepth = parsed;
  }

  let maxPages = null;
  if (maxPagesRaw !== "") {
    const parsed = Number.parseInt(maxPagesRaw, 10);
    if (Number.isNaN(parsed) || parsed < 1 || parsed > 2000) {
      state.launcher.error = "Max crawl pages must be an integer between 1 and 2000.";
      renderLauncher();
      return;
    }
    maxPages = parsed;
  }

  const payload = {
    profile: state.launcher.profile,
    auth_type: state.launcher.authType,
    auth_value: state.launcher.authType === "none" ? "" : state.launcher.authValue.trim(),
    auto_login_dvwa: Boolean(state.launcher.autoLoginDvwa),
    dvwa_username: state.launcher.dvwaUsername.trim() || "admin",
    dvwa_password: state.launcher.dvwaPassword || "password",
    max_depth: maxDepth,
    max_pages: maxPages,
    enabled_checks: state.launcher.isCustomChecksModified
      ? Array.from(state.launcher.selectedCheckIds)
      : null,
  };

  state.launcher.submitting = true;
  renderLauncher();

  try {
    const scan = await startScan(state.launcher.projectId, payload);
    state.launcher.submitting = false;
    state.launcher.error = null;

    // Prepend new scan immediately for instant UI responsiveness
    state.scans = [scan, ...state.scans.filter((s) => s.id !== scan.id)];
    state.activeScanId = scan.id;
    findingsExplorerView.setScans(state.scans);
    compareScansView.setScans(state.scans);
    updateLiveIndicator();

    showToast(`Scan #${shortId(scan.id)} launched — streaming live progress.`, "success");
    await navigate("live", { scanId: scan.id, initialScan: scan });
  } catch (err) {
    state.launcher.submitting = false;
    state.launcher.error = formatApiError(err, "Failed to launch scan.");
    showToast(state.launcher.error, "error");
    renderLauncher();
  }
}

function renderLauncher() {
  const container = dom.views.launcher;
  if (!container) return;
  clear(container);

  syncLauncherDefaultChecks();

  const selectedProfileDef =
    PROFILE_DEFINITIONS.find((p) => p.id === state.launcher.profile) || PROFILE_DEFINITIONS[1];

  // Error Banner
  const errorBanner = state.launcher.error
    ? el("div", { class: "form-error", role: "alert", text: state.launcher.error })
    : null;

  // Section 1: Target Project Selector
  const projectSelect = el(
    "select",
    {
      id: "launcher-project-select",
      class: "form-select",
      disabled: state.projects.length === 0,
      on: {
        change: (e) => {
          state.launcher.projectId = e.target.value;
          state.launcher.error = null;
          renderLauncher();
        },
      },
    },
    state.projects.length === 0
      ? [el("option", { value: "", text: "No projects available — create one first" })]
      : state.projects.map((p) =>
          el("option", {
            value: p.id,
            text: p.name,
            "data-badge": formatStackLabel(p.target_stack),
            selected: p.id === state.launcher.projectId,
          }),
        ),
  );

  const projectRow = el("div", { class: "row", style: { alignItems: "stretch" } }, [
    el("div", { style: { flex: "1", minWidth: "240px" } }, [projectSelect]),
    el("button", {
      type: "button",
      class: "btn btn-secondary",
      text: "+ New Project",
      on: { click: () => openProjectModal() },
    }),
  ]);

  const emptyProjectHint =
    state.projects.length === 0
      ? el("p", {
          class: "form-hint",
          style: { color: "var(--sev-medium-text)" },
          text: "Create an authorized local project first (e.g., http://127.0.0.1:5050) to enable scan launching.",
        })
      : null;

  const projectCard = el("div", { class: "card" }, [
    el("div", { class: "card-header" }, [
      el("div", null, [
        el("h3", { class: "card-title", text: "1. Target Project" }),
        el("p", {
          class: "card-subtitle",
          text: "Choose which authorized local application to scan.",
        }),
      ]),
    ]),
    el("div", { class: "card-body form-stack" }, [
      el("div", { class: "form-group" }, [
        el("label", {
          for: "launcher-project-select",
          class: "form-label",
          text: "Registered Project",
        }),
        projectRow,
        emptyProjectHint,
      ]),
    ]),
  ]);

  // Section 2: Visual Profile Cards & Optional Depth/Pages Overrides
  const profileCards = el(
    "div",
    { class: "profile-grid", role: "radiogroup", "aria-label": "Scan Profile" },
    PROFILE_DEFINITIONS.map((prof) => {
      const isSelected = state.launcher.profile === prof.id;
      const defaultCount = getProfileDefaultCheckIds(prof.id).size;
      return el(
        "button",
        {
          type: "button",
          class: `profile-card${isSelected ? " selected" : ""}`,
          role: "radio",
          "aria-checked": isSelected ? "true" : "false",
          on: {
            click: () => {
              state.launcher.profile = prof.id;
              state.launcher.isCustomChecksModified = false;
              state.launcher.selectedCheckIds = getProfileDefaultCheckIds(prof.id);
              renderLauncher();
            },
          },
        },
        [
          el("div", { class: "row-between", style: { width: "100%" } }, [
            el("span", {
              style: { fontSize: "15px", fontWeight: "700", color: "var(--text-primary)" },
              text: prof.name,
            }),
            el("span", {
              class: isSelected ? "badge badge-status-completed" : "badge badge-neutral",
              text: prof.badge,
            }),
          ]),
          el("div", {
            class: "mono text-xs",
            style: { color: "var(--accent-secondary)", fontWeight: "600" },
            text:
              defaultCount > 0
                ? `${defaultCount} checks · depth ${prof.depth}`
                : prof.summary,
          }),
          el("p", {
            class: "text-xs text-muted",
            style: { margin: "2px 0 0", lineHeight: "1.45" },
            text: prof.description,
          }),
        ],
      );
    }),
  );

  const depthInput = el("input", {
    id: "launcher-max-depth",
    type: "number",
    min: "0",
    max: "10",
    class: "form-input mono",
    placeholder: `Default (${selectedProfileDef.depth})`,
    value: state.launcher.maxDepth,
    on: {
      input: (e) => {
        state.launcher.maxDepth = e.target.value;
      },
    },
  });

  const pagesInput = el("input", {
    id: "launcher-max-pages",
    type: "number",
    min: "1",
    max: "2000",
    class: "form-input mono",
    placeholder: `Default (${selectedProfileDef.maxPages})`,
    value: state.launcher.maxPages,
    on: {
      input: (e) => {
        state.launcher.maxPages = e.target.value;
      },
    },
  });

  const profileCard = el("div", { class: "card" }, [
    el("div", { class: "card-header" }, [
      el("div", null, [
        el("h3", { class: "card-title", text: "2. Scan Profile & Scope Limits" }),
        el("p", {
          class: "card-subtitle",
          text: "Select a preset profile; optionally tune crawl depth or page cap.",
        }),
      ]),
    ]),
    el("div", { class: "card-body form-stack" }, [
      profileCards,
      el(
        "div",
        {
          style: {
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
            gap: "12px",
          },
        },
        [
          el("div", { class: "form-group" }, [
            el("label", {
              for: "launcher-max-depth",
              class: "form-label",
              text: "Max Crawl Depth (Optional)",
            }),
            depthInput,
          ]),
          el("div", { class: "form-group" }, [
            el("label", {
              for: "launcher-max-pages",
              class: "form-label",
              text: "Max Pages (Optional)",
            }),
            pagesInput,
          ]),
        ],
      ),
    ]),
  ]);

  // Section 3: Optional Authentication Collapsible Section
  const authTypeSelect = el(
    "select",
    {
      id: "launcher-auth-type",
      class: "form-select",
      on: {
        change: (e) => {
          state.launcher.authType = e.target.value;
          state.launcher.authExpanded = true;
          renderLauncher();
        },
      },
    },
    AUTH_TYPE_OPTIONS.map((opt) =>
      el("option", {
        value: opt.value,
        text: opt.label,
        selected: opt.value === state.launcher.authType,
      }),
    ),
  );

  const authValueGroup =
    state.launcher.authType !== "none"
      ? el("div", { class: "form-group" }, [
          el("label", {
            for: "launcher-auth-value",
            class: "form-label",
            text:
              state.launcher.authType === "cookie"
                ? "Cookie Header Value"
                : state.launcher.authType === "bearer"
                  ? "Bearer Token"
                  : "Custom Header (Name: Value)",
          }),
          el("input", {
            id: "launcher-auth-value",
            type: "text",
            class: "form-input mono",
            placeholder: AUTH_PLACEHOLDERS[state.launcher.authType] || "",
            value: state.launcher.authValue,
            on: {
              input: (e) => {
                state.launcher.authValue = e.target.value;
              },
            },
          }),
          el("p", {
            class: "form-hint",
            text: "Credentials are injected only into in-scope scan requests and are never persisted to SQLite.",
          }),
        ])
      : null;

  const dvwaCheckbox = el("input", {
    id: "launcher-auto-dvwa",
    type: "checkbox",
    checked: state.launcher.autoLoginDvwa,
    on: {
      change: (e) => {
        state.launcher.autoLoginDvwa = Boolean(e.target.checked);
        state.launcher.authExpanded = true;
        renderLauncher();
      },
    },
  });

  const dvwaCredentialsRow = state.launcher.autoLoginDvwa
    ? el(
        "div",
        {
          style: {
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
            gap: "12px",
          },
        },
        [
          el("div", { class: "form-group" }, [
            el("label", {
              for: "launcher-dvwa-user",
              class: "form-label",
              text: "DVWA Username",
            }),
            el("input", {
              id: "launcher-dvwa-user",
              type: "text",
              class: "form-input mono",
              value: state.launcher.dvwaUsername,
              on: {
                input: (e) => {
                  state.launcher.dvwaUsername = e.target.value;
                },
              },
            }),
          ]),
          el("div", { class: "form-group" }, [
            el("label", {
              for: "launcher-dvwa-pass",
              class: "form-label",
              text: "DVWA Password",
            }),
            el("input", {
              id: "launcher-dvwa-pass",
              type: "password",
              class: "form-input mono",
              value: state.launcher.dvwaPassword,
              on: {
                input: (e) => {
                  state.launcher.dvwaPassword = e.target.value;
                },
              },
            }),
          ]),
        ],
      )
    : null;

  const authSummarySuffix =
    state.launcher.autoLoginDvwa
      ? "DVWA Auto-Login Enabled"
      : state.launcher.authType !== "none"
        ? `Mode: ${state.launcher.authType.toUpperCase()}`
        : "Unauthenticated";

  const authDetails = el(
    "details",
    {
      class: "evidence-details",
      open: state.launcher.authExpanded,
      on: {
        toggle: (e) => {
          state.launcher.authExpanded = Boolean(e.currentTarget.open);
        },
      },
    },
    [
      el("summary", {
        class: "evidence-summary",
        text: `3. Optional Authentication & DVWA Auto-Login (${authSummarySuffix})`,
      }),
      el("div", { class: "evidence-body form-stack" }, [
        el("div", { class: "form-group" }, [
          el("label", {
            for: "launcher-auth-type",
            class: "form-label",
            text: "Authentication Mode",
          }),
          authTypeSelect,
        ]),
        authValueGroup,
        el("label", { class: "form-checkbox-row", for: "launcher-auto-dvwa" }, [
          dvwaCheckbox,
          el("span", { class: "text-sm" }, [
            el("strong", { text: "Auto-Login to DVWA Lab: " }),
            "Automatically authenticate against DVWA /login.php and set security cookie to low before crawling.",
          ]),
        ]),
        dvwaCredentialsRow,
      ]),
    ],
  );

  // Section 4: Optional Custom Check Picker Collapsible Section
  const selectedCount = state.launcher.selectedCheckIds.size;
  const totalCheckCount = state.checks.length;

  const checkPickerGrid = el(
    "div",
    {
      style: {
        display: "grid",
        gridTemplateColumns: "repeat(auto-fill, minmax(290px, 1fr))",
        gap: "10px",
      },
    },
    state.checks.map((check) => {
      const checked = state.launcher.selectedCheckIds.has(check.id);
      const inputId = `launcher-check-${check.id}`;
      const owaspShort = String(check.owasp_category || "").split(" - ")[0] || "OWASP";

      return el("label", { class: "form-checkbox-row", for: inputId }, [
        el("input", {
          id: inputId,
          type: "checkbox",
          checked,
          on: {
            change: (e) => {
              if (e.target.checked) {
                state.launcher.selectedCheckIds.add(check.id);
              } else {
                state.launcher.selectedCheckIds.delete(check.id);
              }
              state.launcher.isCustomChecksModified = true;
              state.launcher.checksExpanded = true;
              renderLauncher();
            },
          },
        }),
        el("div", { class: "stack", style: { gap: "4px", minWidth: "0", flex: "1" } }, [
          el("div", { class: "row-between", style: { gap: "6px" } }, [
            el("span", {
              class: "text-sm",
              style: { fontWeight: "600", color: "var(--text-primary)" },
              text: check.name,
            }),
            severityBadge(check.default_severity),
          ]),
          el("div", { class: "row text-xs text-muted", style: { gap: "6px" } }, [
            el("span", { class: "mono", text: check.id }),
            el("span", { class: "badge badge-neutral mono", text: owaspShort }),
            el("span", { class: "badge badge-neutral", text: check.kind }),
          ]),
        ]),
      ]);
    }),
  );

  const checkPickerDetails = el(
    "details",
    {
      class: "evidence-details",
      open: state.launcher.checksExpanded,
      on: {
        toggle: (e) => {
          state.launcher.checksExpanded = Boolean(e.currentTarget.open);
        },
      },
    },
    [
      el("summary", {
        class: "evidence-summary",
        text: `4. Optional Custom Check Picker (${selectedCount} / ${totalCheckCount} selected${state.launcher.isCustomChecksModified ? " · Custom" : " · Profile Default"})`,
      }),
      el("div", { class: "evidence-body stack" }, [
        el("div", { class: "row-between" }, [
          el("span", {
            class: "text-xs text-muted",
            text: "Defaults auto-toggle when you switch Scan Profile above. Customize individual checks if needed.",
          }),
          el("div", { class: "row", style: { gap: "6px" } }, [
            el("button", {
              type: "button",
              class: "btn btn-secondary btn-sm",
              text: "Select All",
              on: {
                click: () => {
                  state.launcher.selectedCheckIds = new Set(state.checks.map((c) => c.id));
                  state.launcher.isCustomChecksModified = true;
                  state.launcher.checksExpanded = true;
                  renderLauncher();
                },
              },
            }),
            el("button", {
              type: "button",
              class: "btn btn-ghost btn-sm",
              text: "Reset Profile",
              on: {
                click: () => {
                  state.launcher.isCustomChecksModified = false;
                  state.launcher.selectedCheckIds = getProfileDefaultCheckIds(
                    state.launcher.profile,
                  );
                  state.launcher.checksExpanded = true;
                  renderLauncher();
                },
              },
            }),
          ]),
        ]),
        state.checks.length > 0
          ? checkPickerGrid
          : el("p", {
              class: "text-sm text-muted",
              text: "Loading registered OWASP checks from /api/checks...",
            }),
      ]),
    ],
  );

  // Submit Footer Card
  const submitBtn = el("button", {
    type: "submit",
    class: "btn btn-primary",
    disabled: state.launcher.submitting || state.projects.length === 0,
    text: state.launcher.submitting
      ? "Launching Scan..."
      : `Launch ${selectedProfileDef.name} Scan`,
  });

  const actionCard = el("div", { class: "card" }, [
    el("div", { class: "card-body row-between" }, [
      el("div", { class: "stack", style: { gap: "2px" } }, [
        el("span", {
          style: { fontWeight: "600", color: "var(--text-primary)" },
          text: "Ready to execute authorized local scan",
        }),
        el("span", {
          class: "text-xs text-muted",
          text: `Profile: ${selectedProfileDef.name} · ${selectedCount} checks selected · Streams live SSE progress immediately.`,
        }),
      ]),
      el("div", { class: "row" }, [
        el("button", {
          type: "button",
          class: "btn btn-ghost",
          text: "Cancel",
          on: { click: () => navigate("overview") },
        }),
        submitBtn,
      ]),
    ]),
  ]);

  const form = el(
    "form",
    {
      class: "stack",
      style: { gap: "18px" },
      on: { submit: (e) => handleLaunchScanSubmit(e) },
    },
    [errorBanner, projectCard, profileCard, authDetails, checkPickerDetails, actionCard],
  );

  container.appendChild(form);
}

/* ---------- View 6: OWASP Check Catalog ---------- */

function kindBadge(kind) {
  const normalized = String(kind || "passive").trim().toLowerCase();
  let cls = "badge badge-neutral";
  if (normalized === "passive") cls = "badge badge-status-completed";
  else if (normalized === "active") cls = "badge badge-sev-high";
  else if (normalized === "discovery") cls = "badge badge-status-scanning";
  return el("span", {
    class: cls,
    text: normalized.charAt(0).toUpperCase() + normalized.slice(1),
  });
}

function getFilteredChecks() {
  const q = state.checksFilter.q.trim().toLowerCase();
  const kind = state.checksFilter.kind.trim().toLowerCase();
  const profile = state.checksFilter.profile.trim().toLowerCase();
  const severity = state.checksFilter.severity.trim().toLowerCase();

  return state.checks.filter((check) => {
    if (kind && String(check.kind || "").toLowerCase() !== kind) return false;
    if (severity && String(check.default_severity || "").toLowerCase() !== severity) return false;
    if (profile) {
      const profiles = Array.isArray(check.profiles)
        ? check.profiles.map((p) => String(p).toLowerCase())
        : [];
      if (!profiles.includes(profile)) return false;
    }
    if (q) {
      const haystack = [
        check.id,
        check.name,
        check.owasp_category,
        check.cwe_id,
        check.kind,
        check.description,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      if (!haystack.includes(q)) return false;
    }
    return true;
  });
}

function renderChecksCatalog() {
  const container = dom.views.checks;
  if (!container) return;
  clear(container);

  const total = state.checks.length;
  const passiveCount = state.checks.filter(
    (c) => String(c.kind || "").toLowerCase() === "passive",
  ).length;
  const activeCount = state.checks.filter(
    (c) => String(c.kind || "").toLowerCase() === "active",
  ).length;
  const discoveryCount = state.checks.filter(
    (c) => String(c.kind || "").toLowerCase() === "discovery",
  ).length;

  const kpiStrip = el("div", { class: "kpi-grid" }, [
    el("div", { class: "kpi-card" }, [
      el("span", { class: "kpi-label", text: "Registered Checks" }),
      el("div", { class: "kpi-value mono", text: String(total) }),
      el("span", { class: "kpi-sub", text: "Loaded live from /api/checks" }),
    ]),
    el("div", { class: "kpi-card" }, [
      el("span", { class: "kpi-label", text: "Passive Checks" }),
      el("div", { class: "kpi-value mono", text: String(passiveCount) }),
      el("span", { class: "kpi-sub", text: "Included in Quick, Standard & Deep" }),
    ]),
    el("div", { class: "kpi-card" }, [
      el("span", { class: "kpi-label", text: "Safe Active Checks" }),
      el("div", { class: "kpi-value mono", text: String(activeCount) }),
      el("span", { class: "kpi-sub", text: "Non-destructive probes (SQLi, XSS, CORS, IDOR)" }),
    ]),
    el("div", { class: "kpi-card" }, [
      el("span", { class: "kpi-label", text: "Discovery Checks" }),
      el("div", { class: "kpi-value mono", text: String(discoveryCount) }),
      el("span", { class: "kpi-sub", text: "Sensitive files, dir listing & admin routes" }),
    ]),
  ]);

  const countBadge = el("span", { class: "text-xs text-muted" });
  const tableHost = el("div", { class: "table-wrap" });

  const renderTable = () => {
    clear(tableHost);
    const filtered = getFilteredChecks();
    countBadge.textContent = `Showing ${filtered.length} of ${state.checks.length} checks`;

    if (filtered.length === 0) {
      tableHost.appendChild(
        el("div", { class: "empty-state" }, [
          el("h4", {
            class: "empty-state-title",
            text: state.checks.length === 0 ? "No Checks Loaded" : "No Matching Checks",
          }),
          el("p", {
            class: "empty-state-desc",
            text:
              state.checks.length === 0
                ? "Ensure the backend API is running so /api/checks can populate the catalog."
                : "Try adjusting or clearing your search, kind, profile, or severity filters.",
          }),
        ]),
      );
      return;
    }

    const tbody = el(
      "tbody",
      null,
      filtered.map((check) => {
        const profiles = Array.isArray(check.profiles) ? check.profiles : [];
        return el("tr", null, [
          el("td", null, [
            el("div", { class: "stack", style: { gap: "3px" } }, [
              el("span", {
                style: { fontWeight: "600", color: "var(--text-primary)" },
                text: check.name,
              }),
              el("span", { class: "mono text-xs text-muted", text: check.id }),
            ]),
          ]),
          el("td", null, [
            el("span", {
              class: "text-xs",
              style: { fontWeight: "600", color: "var(--text-secondary)" },
              text: check.owasp_category || "—",
            }),
          ]),
          el("td", null, [
            el("span", { class: "badge badge-neutral mono", text: check.cwe_id || "—" }),
          ]),
          el("td", null, [kindBadge(check.kind)]),
          el("td", null, [severityBadge(check.default_severity)]),
          el("td", null, [
            el(
              "div",
              { class: "row", style: { gap: "4px" } },
              profiles.map((prof) =>
                el("span", {
                  class: "badge badge-stack",
                  text: String(prof).toUpperCase(),
                }),
              ),
            ),
          ]),
          el("td", null, [
            el("p", {
              class: "text-xs text-secondary",
              style: { margin: "0", minWidth: "220px", maxWidth: "360px", lineHeight: "1.45" },
              text: check.description || "—",
            }),
          ]),
        ]);
      }),
    );

    tableHost.appendChild(
      el("table", { class: "data-table" }, [
        el("thead", null, [
          el("tr", null, [
            el("th", { text: "Check Name / ID" }),
            el("th", { text: "OWASP Category" }),
            el("th", { text: "CWE" }),
            el("th", { text: "Kind" }),
            el("th", { text: "Default Severity" }),
            el("th", { text: "Profiles" }),
            el("th", { text: "Description" }),
          ]),
        ]),
        tbody,
      ]),
    );
  };

  const searchInput = el("input", {
    type: "search",
    class: "form-input filter-search",
    placeholder: "Search by check ID, name, OWASP category, CWE, or description...",
    value: state.checksFilter.q,
    "aria-label": "Search OWASP checks",
    on: {
      input: (e) => {
        state.checksFilter.q = e.target.value;
        renderTable();
      },
    },
  });

  const kindSelect = el(
    "select",
    {
      class: "form-select",
      "aria-label": "Filter checks by kind",
      on: {
        change: (e) => {
          state.checksFilter.kind = e.target.value;
          renderTable();
        },
      },
    },
    [
      { value: "", label: "All Kinds" },
      { value: "passive", label: "Passive" },
      { value: "active", label: "Active" },
      { value: "discovery", label: "Discovery" },
    ].map((opt) =>
      el("option", {
        value: opt.value,
        text: opt.label,
        selected: opt.value === state.checksFilter.kind,
      }),
    ),
  );

  const profileSelect = el(
    "select",
    {
      class: "form-select",
      "aria-label": "Filter checks by profile",
      on: {
        change: (e) => {
          state.checksFilter.profile = e.target.value;
          renderTable();
        },
      },
    },
    [
      { value: "", label: "All Profiles" },
      { value: "quick", label: "Quick" },
      { value: "standard", label: "Standard" },
      { value: "deep", label: "Deep" },
    ].map((opt) =>
      el("option", {
        value: opt.value,
        text: opt.label,
        selected: opt.value === state.checksFilter.profile,
      }),
    ),
  );

  const severitySelect = el(
    "select",
    {
      class: "form-select",
      "aria-label": "Filter checks by default severity",
      on: {
        change: (e) => {
          state.checksFilter.severity = e.target.value;
          renderTable();
        },
      },
    },
    [
      { value: "", label: "All Severities" },
      { value: "critical", label: "Critical" },
      { value: "high", label: "High" },
      { value: "medium", label: "Medium" },
      { value: "low", label: "Low" },
      { value: "info", label: "Info" },
    ].map((opt) =>
      el("option", {
        value: opt.value,
        text: opt.label,
        selected: opt.value === state.checksFilter.severity,
      }),
    ),
  );

  const resetBtn = el("button", {
    type: "button",
    class: "btn btn-ghost btn-sm",
    text: "Reset",
    on: {
      click: () => {
        state.checksFilter = { q: "", kind: "", profile: "", severity: "" };
        searchInput.value = "";
        kindSelect.value = "";
        profileSelect.value = "";
        severitySelect.value = "";
        renderTable();
      },
    },
  });

  const catalogCard = el("div", { class: "card" }, [
    el("div", { class: "card-header" }, [
      el("div", null, [
        el("h3", { class: "card-title", text: "OWASP Top 10 Security Check Plugins" }),
        el("p", {
          class: "card-subtitle",
          text: "Every registered check ships with plain-language root cause explanations and 5-stack Before/After code fixes.",
        }),
      ]),
      countBadge,
    ]),
    el("div", { class: "filter-bar" }, [
      searchInput,
      kindSelect,
      profileSelect,
      severitySelect,
      resetBtn,
    ]),
    tableHost,
  ]);

  container.appendChild(kpiStrip);
  container.appendChild(catalogCard);
  renderTable();
}

/* ---------- Component & Shell Event Wiring ---------- */

function initComponents() {
  fixModal = new FixModal({
    modalEl: dom.fixModal,
    bodyEl: dom.fixModalBody,
    onTriaged: async (_updatedFinding) => {
      // Refresh both Overview KPIs/scans and Findings Explorer live risk charts
      await refreshCoreData({ skipChecks: true });
      if (findingsExplorerView && findingsExplorerView.getCurrentScanId()) {
        await findingsExplorerView.refresh();
      }
      if (state.activeView === "overview") {
        renderOverview();
      }
    },
  });

  liveScanView = new LiveScanView(dom.views.live, {
    onOpenFinding: (findingId, ctx) => openFindingModal(findingId, ctx),
    onViewReport: (scanId) => navigate("findings", { scanId }),
    onScanTerminal: async (_scan) => {
      await refreshCoreData({ skipChecks: true });
      updateLiveIndicator();
    },
    onLaunchNew: () => navigate("launcher"),
  });

  findingsExplorerView = new FindingsExplorerView(dom.views.findings, {
    onOpenFinding: (findingId, ctx) => openFindingModal(findingId, ctx),
    onScanSelected: (scanId) => {
      state.selectedFindingsScanId = scanId;
    },
    onLaunchNew: () => navigate("launcher"),
  });

  compareScansView = new CompareScansView(dom.views.compare, {
    onOpenFinding: (findingId, ctx) => openFindingModal(findingId, ctx),
    onLaunchNew: () => navigate("launcher"),
  });
}

function bindGlobalEvents() {
  // Sidebar navigation
  for (const item of dom.navItems) {
    item.addEventListener("click", () => {
      const targetView = item.dataset.view;
      if (targetView) {
        navigate(targetView, { refresh: targetView === "overview" });
      }
    });
  }

  // Mobile sidebar drawer
  if (dom.sidebarToggle) {
    dom.sidebarToggle.addEventListener("click", () => {
      const isOpen = dom.sidebar?.classList.contains("open");
      setSidebarOpen(!isOpen);
    });
  }
  if (dom.sidebarBackdrop) {
    dom.sidebarBackdrop.addEventListener("click", () => setSidebarOpen(false));
  }

  // Theme toggle
  if (dom.themeToggle) {
    dom.themeToggle.addEventListener("click", () => {
      const current = document.documentElement.dataset.theme === "light" ? "light" : "dark";
      applyTheme(current === "dark" ? "light" : "dark");
    });
  }

  // Health badge manual refresh
  if (dom.healthBadge) {
    dom.healthBadge.addEventListener("click", () => {
      refreshHealth(true);
    });
  }

  // New Project Modal controls
  if (dom.openProjectModalBtn) {
    dom.openProjectModalBtn.addEventListener("click", () => openProjectModal());
  }
  if (dom.closeProjectModalBtn) {
    dom.closeProjectModalBtn.addEventListener("click", () => closeProjectModal());
  }
  if (dom.cancelProjectModalBtn) {
    dom.cancelProjectModalBtn.addEventListener("click", () => closeProjectModal());
  }
  if (dom.projectModal) {
    dom.projectModal.addEventListener("click", (event) => {
      if (event.target === dom.projectModal) {
        closeProjectModal();
      }
    });
  }
  if (dom.projectForm) {
    dom.projectForm.addEventListener("submit", (event) => {
      handleProjectFormSubmit(event);
    });
  }

  // Edit Scan Modal controls
  if (dom.closeEditScanModalBtn) {
    dom.closeEditScanModalBtn.addEventListener("click", () => closeEditScanModal());
  }
  if (dom.cancelEditScanModalBtn) {
    dom.cancelEditScanModalBtn.addEventListener("click", () => closeEditScanModal());
  }
  if (dom.editScanRerunBtn) {
    dom.editScanRerunBtn.addEventListener("click", () => {
      if (!editingScan) return;
      const targetScan = editingScan;
      prefillLauncherFromScan(targetScan);
      closeEditScanModal();
      navigate("launcher", { projectId: targetScan.project_id });
    });
  }
  if (dom.editScanModal) {
    dom.editScanModal.addEventListener("click", (event) => {
      if (event.target === dom.editScanModal) {
        closeEditScanModal();
      }
    });
  }
  if (dom.editScanForm) {
    dom.editScanForm.addEventListener("submit", (event) => {
      handleEditScanFormSubmit(event);
    });
  }

  // Escape key closes active modals or mobile sidebar
  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    if (isEditScanModalOpen) {
      event.preventDefault();
      closeEditScanModal();
    } else if (isProjectModalOpen) {
      event.preventDefault();
      closeProjectModal();
    } else if (dom.sidebar?.classList.contains("open")) {
      setSidebarOpen(false);
    }
  });
}

/* ---------- Boot Sequence ---------- */

async function bootstrap() {
  applyTheme(readSavedTheme());
  initModernSelects();
  initComponents();
  bindGlobalEvents();

  // Render immediate overview shell, then hydrate live data + health concurrently
  renderOverview();

  await Promise.all([refreshHealth(false), refreshCoreData({ skipChecks: false })]);

  // Render active view with hydrated state
  if (state.activeView === "overview") {
    renderOverview();
  } else if (state.activeView === "launcher") {
    renderLauncher();
  } else if (state.activeView === "checks") {
    renderChecksCatalog();
  }

  window.setInterval(() => {
    refreshHealth(false);
  }, HEALTH_POLL_INTERVAL_MS);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => {
    bootstrap();
  });
} else {
  bootstrap();
}
