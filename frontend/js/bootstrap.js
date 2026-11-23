const statusEl = document.getElementById("health-status");
const metaEl = document.getElementById("health-meta");
const dotEl = document.getElementById("health-dot");
const versionEl = document.getElementById("app-version");
const refreshBtn = document.getElementById("refresh-health");

async function fetchHealth() {
  if (!statusEl || !metaEl || !dotEl) return;

  statusEl.textContent = "Checking /api/health...";
  dotEl.className = "h-3 w-3 rounded-full bg-amber-400";

  try {
    const response = await fetch("/api/health", {
      headers: { Accept: "application/json" },
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    const isHealthy = data.status === "ok" && data.database?.status === "up";

    dotEl.className = isHealthy
      ? "h-3 w-3 rounded-full bg-emerald-400"
      : "h-3 w-3 rounded-full bg-rose-500";
    statusEl.textContent = isHealthy ? "Online (Healthy)" : "Degraded";
    metaEl.textContent = `v${data.version ?? "0.1.0"} · DB: ${data.database?.dialect ?? "unknown"} (${data.database?.status ?? "unknown"})`;

    if (versionEl && data.version) {
      versionEl.textContent = data.version;
    }
  } catch (error) {
    dotEl.className = "h-3 w-3 rounded-full bg-rose-500";
    statusEl.textContent = "Unreachable";
    metaEl.textContent = error instanceof Error ? error.message : "Network error";
  }
}

if (refreshBtn) {
  refreshBtn.addEventListener("click", () => {
    void fetchHealth();
  });
}

void fetchHealth();
