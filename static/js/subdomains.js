/**
 * SENTINEL-X | Subdomain Reconnaissance Controller
 * Handles passive CT querying, filter toggles, live search, CSV export,
 * and quick-link pivot actions into Scanner, Domain Dossier, or URL Forensics.
 */

let currentSubdomainData = null;
let currentSubdomainFilter = "all";
let currentSubdomainSearchQuery = "";

document.addEventListener("DOMContentLoaded", () => {
  const urlParams = new URLSearchParams(window.location.search);
  const targetParam = urlParams.get("target") || urlParams.get("domain");
  if (targetParam) {
    setSubdomainPreset(targetParam, true);
  }
});

function setSubdomainPreset(domain, autoRun = false) {
  const input = document.getElementById("targetSubdomainField");
  if (input) {
    input.value = domain;
    if (autoRun) {
      runSubdomainEnumeration();
    }
  }
}

function clearSubdomainForm() {
  const input = document.getElementById("targetSubdomainField");
  if (input) input.value = "";
  const results = document.getElementById("subdomainResultsSection");
  if (results) results.style.display = "none";
}

async function runSubdomainEnumeration() {
  const input = document.getElementById("targetSubdomainField");
  const target = input?.value.trim() || "";

  if (!target) {
    showHorrorToast("Please enter a valid apex domain to enumerate.", "warning");
    input?.focus();
    return;
  }

  const loader = document.getElementById("subdomainLoadingOverlay");
  const results = document.getElementById("subdomainResultsSection");
  const submitBtn = document.getElementById("enumSubdomainBtn");

  if (loader) loader.style.display = "block";
  if (results) results.style.display = "none";
  if (submitBtn) submitBtn.disabled = true;

  try {
    const response = await fetch("/api/subdomains/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain: target })
    });

    const json = await response.json();

    if (json.success && json.data) {
      currentSubdomainData = json.data;
      renderSubdomainResults(json.data);
      if (loader) loader.style.display = "none";
      if (results) results.style.display = "block";

      showHorrorToast(`Recon complete: ${json.data.total_discovered} subdomains mapped (${json.data.live_count} live).`, "success");
    } else {
      if (loader) loader.style.display = "none";
      showHorrorToast(json.error || "Subdomain reconnaissance failed.", "danger");
    }
  } catch (err) {
    if (loader) loader.style.display = "none";
    showHorrorToast(`Network error: ${err.message}`, "danger");
  } finally {
    if (submitBtn) submitBtn.disabled = false;
  }
}

function renderSubdomainResults(data) {
  // Metric Counts
  const totalElem = document.getElementById("resTotalSubdomains");
  if (totalElem) totalElem.innerText = data.total_discovered || 0;

  const liveElem = document.getElementById("resLiveSubdomains");
  if (liveElem) liveElem.innerText = data.live_count || 0;

  const dormantElem = document.getElementById("resDormantSubdomains");
  if (dormantElem) dormantElem.innerText = data.dormant_count || 0;

  const subdomains = data.subdomains || [];
  const stagingCount = subdomains.filter(s => (s.risk_tag || "").includes("STAGING")).length;
  const stagingElem = document.getElementById("resStagingSubdomains");
  if (stagingElem) stagingElem.innerText = stagingCount;

  renderSubdomainsTable();
}

function renderSubdomainsTable() {
  if (!currentSubdomainData) return;
  const tbody = document.getElementById("subdomainsTableBody");
  if (!tbody) return;

  const list = currentSubdomainData.subdomains || [];
  const search = currentSubdomainSearchQuery.toLowerCase();

  const filtered = list.filter(item => {
    // Filter type
    if (currentSubdomainFilter === "live" && !item.is_live) return false;
    if (currentSubdomainFilter === "dormant" && item.is_live) return false;
    if (currentSubdomainFilter === "staging" && !item.risk_tag.includes("STAGING")) return false;

    // Search query
    if (search) {
      const matchSub = item.subdomain.toLowerCase().includes(search);
      const matchIp = (item.ip || "").toLowerCase().includes(search);
      const matchTag = (item.risk_tag || "").toLowerCase().includes(search);
      if (!matchSub && !matchIp && !matchTag) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" class="text-center py-4 text-ash font-mono">
          <i class="bi bi-filter fs-2 d-block mb-2 text-dim"></i>
          No subdomains match the active filter criteria.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = filtered.map(item => {
    const isLive = item.is_live;
    const statusBadge = isLive
      ? `<span class="threat-status-tag low font-mono py-0.5 px-2"><i class="bi bi-activity me-1"></i> LIVE</span>`
      : `<span class="threat-status-tag font-mono py-0.5 px-2 text-dim" style="background: var(--bg-hover); border: 1px solid var(--border-hairline);">DORMANT</span>`;

    const isStaging = (item.risk_tag || "").includes("STAGING");
    const isInternal = item.is_internal;
    const tagBadge = isInternal
      ? `<span class="threat-status-tag critical font-mono py-0.5 px-2"><i class="bi bi-shield-lock me-1"></i> RFC-1918</span>`
      : isStaging
      ? `<span class="threat-status-tag medium font-mono py-0.5 px-2"><i class="bi bi-exclamation-diamond me-1"></i> EXPOSED STAGING</span>`
      : `<span class="threat-status-tag font-mono py-0.5 px-2 text-ash" style="background: var(--bg-hover); border: 1px solid var(--border-hairline);">PUBLIC ASSET</span>`;

    const ipDisplay = isLive
      ? `<span class="text-success fw-bold font-mono">${escapeHtml(item.ip || "")}</span>`
      : `<span class="text-dim font-mono">${escapeHtml(item.ip || "Unresolved")}</span>`;

    return `
      <tr>
        <td class="fw-bold text-bone user-select-all">
          <i class="bi bi-hdd-network text-blood me-1.5"></i> ${escapeHtml(item.subdomain)}
        </td>
        <td class="user-select-all">
          ${ipDisplay}
        </td>
        <td>${statusBadge}</td>
        <td>${tagBadge}</td>
        <td class="text-dim small">${escapeHtml(item.source || "Target Probe")}</td>
        <td class="text-end">
          <div class="d-inline-flex gap-1">
            <a href="/scanner?target=https://${encodeURIComponent(item.subdomain)}" class="editorial-btn-outline btn-sm py-1 px-2" title="Scan in Multi-Engine VirusTotal Grid">
              <i class="bi bi-shield-shaded me-1"></i> Scan
            </a>
            <a href="/analyzer?target=https://${encodeURIComponent(item.subdomain)}" class="editorial-btn-outline btn-sm py-1 px-2" title="Inspect URL Forensics">
              <i class="bi bi-search"></i>
            </a>
            <a href="/domain?target=${encodeURIComponent(item.subdomain)}" class="editorial-btn-outline btn-sm py-1 px-2" title="Domain Surveillance">
              <i class="bi bi-globe"></i>
            </a>
          </div>
        </td>
      </tr>
    `;
  }).join("");
}

function filterSubdomains(filter) {
  currentSubdomainFilter = filter;
  ["All", "Live", "Dormant", "Staging"].forEach(f => {
    const btn = document.getElementById(`subFilter${f}`);
    if (btn) {
      if (f.toLowerCase() === filter) {
        btn.classList.add("active");
      } else {
        btn.classList.remove("active");
      }
    }
  });
  renderSubdomainsTable();
}

function searchSubdomains(query) {
  currentSubdomainSearchQuery = query.trim();
  renderSubdomainsTable();
}

function copyAllSubdomains() {
  if (!currentSubdomainData || !currentSubdomainData.subdomains) {
    showHorrorToast("No subdomains available to copy.", "warning");
    return;
  }
  const subs = currentSubdomainData.subdomains.map(s => s.subdomain).join("\n");
  copyTextToClipboard(subs, `${currentSubdomainData.subdomains.length} subdomains copied to clipboard.`);
}

function exportSubdomainsCsv() {
  if (!currentSubdomainData || !currentSubdomainData.subdomains) {
    showHorrorToast("No subdomains available to export.", "warning");
    return;
  }
  const rows = [
    "subdomain,resolved_ip,status,classification,source",
    ...currentSubdomainData.subdomains.map(s => `"${s.subdomain}","${s.ip}","${s.status}","${s.risk_tag}","${s.source}"`)
  ];
  const blob = new Blob([rows.join("\n")], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `subdomains_${currentSubdomainData.domain || 'recon'}.csv`;
  a.click();
  URL.revokeObjectURL(url);
  showHorrorToast("Subdomain CSV exported.", "success");
}

function copyTextToClipboard(text, successMsg = "Copied to clipboard") {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(() => {
      showHorrorToast(successMsg, "success");
    }).catch(() => fallbackCopy(text, successMsg));
  } else {
    fallbackCopy(text, successMsg);
  }
}

function fallbackCopy(text, successMsg) {
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.position = "fixed";
  ta.style.left = "-999999px";
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  try {
    document.execCommand("copy");
    showHorrorToast(successMsg, "success");
  } catch (e) {
    showHorrorToast("Failed to copy text.", "warning");
  }
  document.body.removeChild(ta);
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
