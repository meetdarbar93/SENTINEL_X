/**
* SENTINEL-X | Dark Horror Investigation Dashboard Controller
* Manages live SQLite statistics, animated counters, Chart.js telemetry,
* rapid launchpad routing, and investigation history operations.
*/

let riskChartInstance = null;
let activityChartInstance = null;

document.addEventListener("DOMContentLoaded", () => {
  fetchDashboardMetrics();
  loadDashboardHistory();
  loadRecentInvestigationsFeed();
  initQuickLaunchpad();
  initHistoryFilters();

  window.addEventListener("themeChanged", () => {
    if (lastCachedStats) {
      const dist = lastCachedStats.risk_distribution || { low: 0, medium: 0, high: 0 };
      renderRiskChart(dist);
      renderActivityChart(lastCachedStats.timeline);
    }
  });
});

// -------------------------------------------------------------
// METRICS & CHARTS LOADER
// -------------------------------------------------------------
async function fetchDashboardMetrics() {
  try {
    const resp = await fetch("/api/dashboard/stats");
    const json = await resp.json();

    if (json.success && json.stats) {
      const stats = json.stats;

      // Animate top counters
      animateValue("statTotalUrls", stats.total_urls);
      animateValue("statTotalDomains", stats.total_domains);
      animateValue("statTotalQueries", stats.total_queries);
      animateValue("statSuspiciousUrls", stats.suspicious_count);

      // Update risk distribution counters
      const dist = stats.risk_distribution || { low: 0, medium: 0, high: 0 };
      const lowEl = document.getElementById("labelLowRisk");
      const medEl = document.getElementById("labelMedRisk");
      const highEl = document.getElementById("labelHighRisk");
      if (lowEl) lowEl.innerText = dist.low;
      if (medEl) medEl.innerText = dist.medium;
      if (highEl) highEl.innerText = dist.high;

      lastCachedStats = stats;

      // Render Charts
      renderRiskChart(dist);
      renderActivityChart(stats.timeline);
    }
  } catch (err) {
    console.error("Failed to load dashboard metrics:", err);
  }
}

function animateValue(elemId, targetVal, duration = 800) {
  const elem = document.getElementById(elemId);
  if (!elem) return;

  targetVal = Number(targetVal) || 0;
  const startVal = parseInt(elem.innerText.replace(/,/g, ""), 10) || 0;
  if (startVal === targetVal) {
    elem.innerText = targetVal.toLocaleString();
    return;
  }
  const startTime = performance.now();

  function updateCounter(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const currentVal = Math.floor(progress * (targetVal - startVal) + startVal);
    elem.innerText = currentVal.toLocaleString();

    if (progress < 1) {
      requestAnimationFrame(updateCounter);
    } else {
      elem.innerText = targetVal.toLocaleString();
    }
  }

  requestAnimationFrame(updateCounter);
}

// -------------------------------------------------------------
// CHART.JS TELEMETRY VISUALIZATIONS
// -------------------------------------------------------------
let lastCachedStats = null;

function renderRiskChart(dist) {
  if (typeof Chart === "undefined") {
    console.warn("Chart.js is not loaded yet.");
    return;
  }
  const canvas = document.getElementById("riskDistributionChart");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");

  const total = dist.low + dist.medium + dist.high;
  const dataValues = total === 0 ? [1, 0, 0] : [dist.low, dist.medium, dist.high];
  const theme = document.documentElement.getAttribute("data-theme") || "dark";
  const isMono = theme === "monochrome";
  const isCyber = theme === "cyberpunk";
  const isNeo = theme === "neomorphism";
  const isHacker = theme === "hacker";
  const is3D = theme === "3d";
  const isPrimary = theme === "primary" || theme === "normal";

  let colors;
  if (total === 0) {
    colors = [isPrimary ? "rgba(37, 99, 235, 0.2)" : (is3D ? "rgba(0, 210, 255, 0.2)" : (isHacker ? "rgba(0, 255, 65, 0.2)" : (isCyber ? "rgba(0, 245, 255, 0.2)" : (isNeo ? "rgba(230, 0, 35, 0.15)" : (isMono ? "rgba(255, 255, 255, 0.15)" : "rgba(181, 18, 27, 0.15)"))))), "transparent", "transparent"];
  } else if (isPrimary) {
    colors = ["#10B981", "#F59E0B", "#EF4444"]; // Clean Emerald, Amber, Red
  } else if (is3D) {
    colors = ["#00F0A0", "#FFB300", "#FF0055"]; // Glowing Emerald, Amber Prism, Ruby Laser
  } else if (isHacker) {
    colors = ["#00FF41", "#FFFF00", "#FF0033"]; // Phosphor Green, Warning Amber, Breach Red
  } else if (isCyber) {
    colors = ["#00F5FF", "#FFD166", "#FF0055"]; // Electric Cyan, Neon Yellow, Hot Neon Pink
  } else if (isNeo) {
    colors = ["#00875A", "#D97706", "#E60023"]; // Mint, Amber, Pinterest Red
  } else if (isMono) {
    colors = ["#777777", "#CCCCCC", "#FFFFFF"];
  } else {
    colors = ["#659B78", "#C69B42", "#E32636"];
  }

  if (riskChartInstance) {
    riskChartInstance.destroy();
  }

  riskChartInstance = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["Low Anomaly", "Medium Threat", "Critical Breach"],
      datasets: [{
        data: dataValues,
        backgroundColor: colors,
        borderColor: isPrimary ? "#161F30" : (is3D ? "#060913" : (isHacker ? "#020B05" : (isNeo ? "#ECECF1" : (isCyber ? "#060713" : (isMono ? "#000000" : "#111111"))))),
        borderWidth: is3D ? 4 : (isPrimary ? 2 : 3),
        hoverOffset: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: "74%",
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: isPrimary ? "rgba(11, 15, 25, 0.96)" : (is3D ? "rgba(17, 26, 48, 0.96)" : (isHacker ? "#020B05" : (isNeo ? "#FFFFFF" : (isCyber ? "rgba(6, 7, 19, 0.95)" : (isMono ? "rgba(0, 0, 0, 0.95)" : "rgba(17, 17, 17, 0.95)"))))),
          titleColor: isPrimary ? "#3B82F6" : (is3D ? "#00D2FF" : (isHacker ? "#00FF41" : (isNeo ? "#E60023" : (isCyber ? "#00F5FF" : (isMono ? "#FFFFFF" : "#E32636"))))),
          bodyColor: isPrimary ? "#F8FAFC" : (is3D ? "#F0F5FF" : (isHacker ? "#D4FCD7" : (isNeo ? "#111111" : "#F1EAEA"))),
          borderColor: isPrimary ? "#3B82F6" : (is3D ? "#00D2FF" : (isHacker ? "#00FF41" : (isNeo ? "#D1D1DB" : (isCyber ? "#00F5FF" : (isMono ? "#444444" : "#351316"))))),
          borderWidth: 1,
          padding: 12,
          callbacks: {
            label: function (context) {
              if (total === 0) return "No investigations recorded yet";
              return ` ${context.label}: ${context.raw} (${Math.round((context.raw / total) * 100)}%)`;
            }
          }
        }
      }
    }
  });
}

function renderActivityChart(timeline) {
  if (typeof Chart === "undefined") {
    console.warn("Chart.js is not loaded yet.");
    return;
  }
  const canvas = document.getElementById("activityTimelineChart");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");

  const labels = timeline ? timeline.labels : ["Day 1", "Day 2", "Day 3", "Day 4", "Day 5", "Day 6", "Day 7"];
  const urlsData = timeline ? timeline.urls : [0, 0, 0, 0, 0, 0, 0];
  const domainsData = timeline ? timeline.domains : [0, 0, 0, 0, 0, 0, 0];
  const osintData = timeline ? timeline.osint : [0, 0, 0, 0, 0, 0, 0];

  const theme = document.documentElement.getAttribute("data-theme") || "dark";
  const isMono = theme === "monochrome";
  const isCyber = theme === "cyberpunk";
  const isNeo = theme === "neomorphism";
  const isHacker = theme === "hacker";
  const is3D = theme === "3d";
  const isPrimary = theme === "primary" || theme === "normal";

  let barColors;
  if (isPrimary) {
    barColors = {
      urlsBg: "rgba(37, 99, 235, 0.85)",
      urlsBorder: "#3B82F6",
      domainsBg: "rgba(14, 165, 233, 0.8)",
      domainsBorder: "#38BDF8",
      osintBg: "rgba(99, 102, 241, 0.8)",
      osintBorder: "#818CF8"
    };
  } else if (is3D) {
    barColors = {
      urlsBg: "rgba(0, 210, 255, 0.85)",
      urlsBorder: "#38EFFF",
      domainsBg: "rgba(121, 40, 202, 0.85)",
      domainsBorder: "#9D4EDD",
      osintBg: "rgba(255, 0, 128, 0.85)",
      osintBorder: "#FF0080"
    };
  } else if (isHacker) {
    barColors = {
      urlsBg: "rgba(0, 255, 65, 0.85)",
      urlsBorder: "#00FF41",
      domainsBg: "rgba(57, 255, 20, 0.85)",
      domainsBorder: "#39FF14",
      osintBg: "rgba(0, 153, 51, 0.85)",
      osintBorder: "#009933"
    };
  } else if (isCyber) {
    barColors = {
      urlsBg: "rgba(0, 245, 255, 0.8)",
      urlsBorder: "#00F5FF",
      domainsBg: "rgba(157, 78, 221, 0.8)",
      domainsBorder: "#9D4EDD",
      osintBg: "rgba(255, 0, 127, 0.8)",
      osintBorder: "#FF007F"
    };
  } else if (isNeo) {
    barColors = {
      urlsBg: "rgba(230, 0, 35, 0.85)",
      urlsBorder: "#E60023",
      domainsBg: "rgba(50, 50, 50, 0.75)",
      domainsBorder: "#333333",
      osintBg: "rgba(255, 82, 99, 0.85)",
      osintBorder: "#FF5263"
    };
  } else if (isMono) {
    barColors = {
      urlsBg: "rgba(255, 255, 255, 0.85)",
      urlsBorder: "#FFFFFF",
      domainsBg: "rgba(180, 180, 180, 0.75)",
      domainsBorder: "#B4B4B4",
      osintBg: "rgba(110, 110, 110, 0.75)",
      osintBorder: "#777777"
    };
  } else {
    barColors = {
      urlsBg: "rgba(181, 18, 27, 0.75)",
      urlsBorder: "#B5121B",
      domainsBg: "rgba(101, 11, 18, 0.75)",
      domainsBorder: "#650B12",
      osintBg: "rgba(227, 38, 54, 0.75)",
      osintBorder: "#E32636"
    };
  }

  if (activityChartInstance) {
    activityChartInstance.destroy();
  }

  activityChartInstance = new Chart(ctx, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [
        {
          label: "URLs Examined",
          data: urlsData,
          backgroundColor: barColors.urlsBg,
          borderColor: barColors.urlsBorder,
          borderWidth: 1,
          borderRadius: 3
        },
        {
          label: "Domain Probes",
          data: domainsData,
          backgroundColor: barColors.domainsBg,
          borderColor: barColors.domainsBorder,
          borderWidth: 1,
          borderRadius: 3
        },
        {
          label: "OSINT Sweeps",
          data: osintData,
          backgroundColor: barColors.osintBg,
          borderColor: barColors.osintBorder,
          borderWidth: 1,
          borderRadius: 3
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          grid: { color: isPrimary ? "rgba(51, 65, 85, 0.45)" : (is3D ? "rgba(255, 255, 255, 0.08)" : (isHacker ? "rgba(0, 255, 65, 0.15)" : (isNeo ? "rgba(200, 200, 210, 0.4)" : (isCyber ? "rgba(0, 245, 255, 0.15)" : (isMono ? "rgba(255, 255, 255, 0.1)" : "rgba(53, 19, 22, 0.3)"))))) },
          ticks: { color: isPrimary ? "#94A3B8" : (is3D ? "#94A3B8" : (isHacker ? "#639E6D" : (isNeo ? "#555555" : (isCyber ? "#9AA6C0" : (isMono ? "#AAAAAA" : "#928888"))))), font: { family: "JetBrains Mono", size: 11 } }
        },
        y: {
          beginAtZero: true,
          grid: { color: isPrimary ? "rgba(51, 65, 85, 0.45)" : (is3D ? "rgba(255, 255, 255, 0.08)" : (isHacker ? "rgba(0, 255, 65, 0.15)" : (isNeo ? "rgba(200, 200, 210, 0.4)" : (isCyber ? "rgba(0, 245, 255, 0.15)" : (isMono ? "rgba(255, 255, 255, 0.1)" : "rgba(53, 19, 22, 0.3)"))))) },
          ticks: {
            color: isPrimary ? "#94A3B8" : (is3D ? "#94A3B8" : (isHacker ? "#639E6D" : (isNeo ? "#555555" : (isCyber ? "#9AA6C0" : (isMono ? "#AAAAAA" : "#928888"))))),
            stepSize: 1,
            font: { family: "JetBrains Mono", size: 11 }
          }
        }
      },
      plugins: {
        legend: {
          position: "top",
          labels: { color: isPrimary ? "#F8FAFC" : (is3D ? "#F0F5FF" : (isHacker ? "#D4FCD7" : (isNeo ? "#111111" : (isCyber ? "#F4F7FF" : (isMono ? "#FFFFFF" : "#F1EAEA"))))), boxWidth: 12, font: { family: "JetBrains Mono", size: 12, weight: 600 } }
        },
        tooltip: {
          backgroundColor: isPrimary ? "rgba(11, 15, 25, 0.96)" : (is3D ? "rgba(17, 26, 48, 0.96)" : (isHacker ? "#020B05" : (isNeo ? "#FFFFFF" : (isCyber ? "rgba(6, 7, 19, 0.95)" : (isMono ? "rgba(0, 0, 0, 0.95)" : "rgba(17, 17, 17, 0.95)"))))),
          titleColor: isPrimary ? "#3B82F6" : (is3D ? "#00D2FF" : (isHacker ? "#00FF41" : (isNeo ? "#E60023" : (isCyber ? "#00F5FF" : (isMono ? "#FFFFFF" : "#E32636"))))),
          bodyColor: isPrimary ? "#F8FAFC" : (is3D ? "#F0F5FF" : (isHacker ? "#D4FCD7" : (isNeo ? "#111111" : (isCyber ? "#F4F7FF" : (isMono ? "#FFFFFF" : "#F1EAEA"))))),
          borderColor: isPrimary ? "#3B82F6" : (is3D ? "#00D2FF" : (isHacker ? "#00FF41" : (isNeo ? "#D1D1DB" : (isCyber ? "#00F5FF" : (isMono ? "#444444" : "#351316"))))),
          borderWidth: 1,
          padding: 10
        }
      }
    }
  });
}

// -------------------------------------------------------------
// INVESTIGATION HISTORY TABLE
// -------------------------------------------------------------
async function loadDashboardHistory() {
  const tbody = document.getElementById("dashboardHistoryTableBody");
  if (!tbody) return;

  const typeFilter = document.getElementById("historyFilterType")?.value || "all";
  const riskFilter = document.getElementById("historyFilterRisk")?.value || "all";

  tbody.innerHTML = `
    <tr>
      <td colspan="6" class="text-center py-4 text-ash">
        <i class="bi bi-arrow-repeat spin fs-5 d-block mb-1 text-blood"></i>
        Scanning classified intelligence archives...
      </td>
    </tr>
  `;

  try {
    const url = `/api/history?limit=10&type=${typeFilter}&risk=${riskFilter}`;
    const resp = await fetch(url);
    const json = await resp.json();

    if (json.success && json.records && json.records.length > 0) {
      tbody.innerHTML = json.records.map(r => {
        let typeBadge = `<span class="badge font-monospace text-blood" style="background:#171313; border:1px solid #351316;">URL</span>`;
        if (r.investigation_type === "threat_scan") {
          typeBadge = `<span class="badge font-monospace" style="background:rgba(227,38,54,0.18); color:#E32636; border: 1px solid var(--blood-crimson);">SCANNER</span>`;
        } else if (r.investigation_type === "domain_intelligence") {
          typeBadge = `<span class="badge font-monospace" style="background:#171313; color:#C69B42; border: 1px solid #351316;">DOMAIN</span>`;
        } else if (r.investigation_type === "osint_query") {
          typeBadge = `<span class="badge font-monospace text-blood" style="background:#171313; border: 1px solid #650B12;">OSINT</span>`;
        } else if (r.investigation_type === "redirect_inspection") {
          typeBadge = `<span class="badge font-monospace" style="background:#171313; color:#E26B35; border: 1px solid #351316;">REDIRECT</span>`;
        }

        let riskClass = "low";
        if (r.risk_level === "High" || r.risk_level === "Critical") riskClass = "critical";
        else if (r.risk_level === "Medium") riskClass = "medium";
        else if (r.risk_level === "Info") riskClass = "low";

        return `
          <tr>
            <td>
              <div class="fw-semibold text-truncate text-bone font-monospace" style="max-width: 260px;" title="${r.target}">
                ${r.target}
              </div>
            </td>
            <td>${typeBadge}</td>
            <td>
              <span class="risk-badge ${riskClass}">
                ${r.risk_level} (${r.risk_score}/100)
              </span>
            </td>
            <td>
              <div class="text-ash small text-truncate" style="max-width: 320px;" title="${r.summary}">
                ${r.summary || "Investigation completed."}
              </div>
            </td>
            <td class="font-monospace small text-dim" style="white-space:nowrap;">${r.created_at}</td>
            <td class="text-end" style="white-space:nowrap;">
              <button class="horror-btn horror-btn-outline btn-sm py-1 px-2 me-1" onclick="viewInvestigationDossier(${r.id})" title="View Dossier">
                <i class="bi bi-eye"></i>
              </button>
              <a href="/api/reports/pdf/${r.id}" class="horror-btn horror-btn-outline btn-sm py-1 px-2 me-1" title="Download Official PDF">
                <i class="bi bi-file-earmark-pdf"></i>
              </a>
              <button class="btn btn-outline-danger btn-sm py-1 px-2" onclick="deleteHistoryRecord(${r.id})" title="Purge Record">
                <i class="bi bi-trash"></i>
              </button>
            </td>
          </tr>
        `;
      }).join("");
    } else {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" class="text-center py-5 text-ash">
            <i class="bi bi-inbox fs-2 d-block mb-2 text-dim"></i>
            No previous investigations match current parameters.
          </td>
        </tr>
      `;
    }
  } catch (err) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" class="text-center py-4 text-danger">
          Failed to load investigation history: ${err.message}
        </td>
      </tr>
    `;
  }
}

function initHistoryFilters() {
  document.getElementById("historyFilterType")?.addEventListener("change", loadDashboardHistory);
  document.getElementById("historyFilterRisk")?.addEventListener("change", loadDashboardHistory);
}

// -------------------------------------------------------------
// LIVE SOC RECENT INVESTIGATIONS ACTIVITY STREAM
// -------------------------------------------------------------
async function loadRecentInvestigationsFeed() {
  const container = document.getElementById("recentInvestigationsFeed");
  if (!container) return;

  try {
    const resp = await fetch("/api/activity/recent?limit=8");
    const json = await resp.json();

    if (json.success && json.activities && json.activities.length > 0) {
      container.innerHTML = json.activities.map(act => {
        let icon = "bi-shield-check text-success";
        if (act.event_type.includes("THREAT") || act.event_type.includes("DELETED") || act.event_type.includes("BLOCK")) {
          icon = "bi-shield-slash text-danger";
        } else if (act.event_type.includes("OSINT") || act.event_type.includes("QUERY")) {
          icon = "bi-radar text-warning";
        } else if (act.event_type.includes("DOMAIN")) {
          icon = "bi-globe2 text-info";
        }

        return `
          <div class="activity-feed-item p-2 mb-2 rounded" style="background: var(--bg-panel); border-left: 2px solid var(--blood-crimson);">
            <div class="d-flex justify-content-between align-items-center mb-1">
              <span class="font-mono text-blood fw-bold" style="font-size: 0.7rem;">// ${act.event_type}</span>
              <span class="text-dim font-mono" style="font-size: 0.65rem;">${act.created_at ? act.created_at.split(" ")[1] : ""}</span>
            </div>
            <div class="text-bone font-mono small text-truncate" title="${act.target || ''}">
              <i class="bi ${icon} me-1"></i> ${act.target || 'System'}
            </div>
            <div class="text-ash" style="font-size: 0.7rem; line-height: 1.2;">
              ${act.description || ''}
            </div>
          </div>
        `;
      }).join("");
    } else {
      container.innerHTML = `
        <div class="text-ash small text-center py-4 font-mono">
          <i class="bi bi-clock-history fs-5 d-block mb-1 text-dim"></i>
          Awaiting live sensory telemetry...
        </div>
      `;
    }
  } catch (err) {
    container.innerHTML = `
      <div class="text-ash small text-center py-3 font-mono">
        Telemetry stream offline.
      </div>
    `;
  }
}

// -------------------------------------------------------------
// DOSSIER PREVIEW & MODAL
// -------------------------------------------------------------
async function viewInvestigationDossier(id) {
  const modalBody = document.getElementById("dossierModalBody");
  const modalTitle = document.getElementById("dossierModalTitle");
  const pdfBtn = document.getElementById("dossierDownloadPdfBtn");

  if (pdfBtn) pdfBtn.href = `/api/reports/pdf/${id}`;

  const dossierModal = new bootstrap.Modal(document.getElementById("viewDossierModal"));
  dossierModal.show();

  modalBody.innerHTML = `<div class="text-center py-4 text-ash"><i class="bi bi-arrow-repeat spin fs-4 d-block mb-2 text-blood"></i>Loading dossier #${id}...</div>`;

  try {
    const resp = await fetch(`/api/history/${id}`);
    const json = await resp.json();

    if (json.success && json.record) {
      const rec = json.record;
      modalTitle.innerHTML = `<i class="bi bi-shield-exclamation text-blood"></i> Dossier #${rec.id} &bull; ${rec.target}`;

      const details = rec.details || {};
      const risk = details.risk_assessment || { score: rec.risk_score, level: rec.risk_level, indicators: [] };

      modalBody.innerHTML = `
        <div class="row g-3 mb-3">
          <div class="col-md-4">
            <div class="horror-inset-box p-3 rounded">
              <span class="text-ash small text-uppercase font-monospace">Target Host</span>
              <div class="fw-bold font-monospace text-truncate text-blood mt-1">${rec.target}</div>
            </div>
          </div>
          <div class="col-md-4">
            <div class="horror-inset-box p-3 rounded">
              <span class="text-ash small text-uppercase font-monospace">Assessed Risk Score</span>
              <div class="fw-bold fs-4 mt-1 font-decorative ${rec.risk_score >= 60 ? 'text-blood' : rec.risk_score >= 30 ? 'text-warning' : 'text-success'}">
                ${rec.risk_score} / 100 (${rec.risk_level})
              </div>
            </div>
          </div>
          <div class="col-md-4">
            <div class="horror-inset-box p-3 rounded">
              <span class="text-ash small text-uppercase font-monospace">Investigation Date</span>
              <div class="fw-bold font-monospace text-ash mt-1">${rec.created_at}</div>
            </div>
          </div>
        </div>

        <div class="horror-inset-box p-3 rounded mb-3">
          <h6 class="text-blood mb-2"><i class="bi bi-card-text text-blood"></i> Forensic Findings Summary</h6>
          <p class="text-ash small mb-0">${rec.summary}</p>
        </div>

        ${details.detection_ratio ? `
          <div class="horror-inset-box p-3 rounded mb-3 d-flex justify-content-between align-items-center">
            <div>
              <span class="text-ash small font-monospace text-uppercase">VirusTotal Consensus Grid</span>
              <div class="fw-bold font-headline fs-5 text-bone">${details.detection_ratio.display} Security Vendors Flagged Target</div>
            </div>
            <span class="badge ${rec.risk_score >= 60 ? 'bg-danger' : rec.risk_score >= 25 ? 'bg-warning text-dark' : 'bg-success'} font-monospace px-3 py-2">
              VERDICT: ${details.overall_verdict || rec.risk_level.toUpperCase()}
            </span>
          </div>
        ` : ''}

        ${(details.attack_findings && details.attack_findings.length > 0) ? `
          <h6 class="text-blood mb-2 font-monospace fw-bold"><i class="bi bi-shield-x text-blood"></i> Attack Vector Forensics (${details.attack_findings.length})</h6>
          <div class="d-flex flex-column gap-2 mb-3">
            ${details.attack_findings.map(af => `
              <div class="horror-inset-box p-2.5 rounded d-flex justify-content-between align-items-start gap-2">
                <div>
                  <div class="d-flex align-items-center gap-2 mb-1">
                    <span class="badge ${af.severity === 'Critical' || af.severity === 'High' ? 'bg-danger' : 'bg-warning text-dark'}">${af.severity}</span>
                    <strong class="text-bone small">${af.finding || af.vector}</strong>
                    <span class="badge bg-dark text-muted font-monospace">${af.category || 'Vector'}</span>
                  </div>
                  <div class="text-ash small">${af.description || af.detail}</div>
                </div>
                <span class="badge bg-secondary font-monospace text-blood" style="border:1px solid #351316;">+${af.points || 25} pts</span>
              </div>
            `).join("")}
          </div>
        ` : (risk.indicators && risk.indicators.length > 0) ? `
          <h6 class="text-blood mb-2"><i class="bi bi-radioactive text-blood"></i> Triggered Threat Indicators (${risk.indicators.length})</h6>
          <div class="d-flex flex-column gap-2 mb-3">
            ${risk.indicators.map(ind => `
              <div class="horror-inset-box p-2.5 rounded d-flex justify-content-between align-items-start gap-2">
                <div>
                  <div class="d-flex align-items-center gap-2 mb-1">
                    <span class="badge ${ind.severity === 'Critical' || ind.severity === 'High' ? 'bg-danger' : ind.severity === 'Medium' ? 'bg-warning text-dark' : 'bg-secondary text-bone'}">${ind.severity}</span>
                    <strong class="text-bone small">${ind.title}</strong>
                  </div>
                  <div class="text-ash small">${ind.description}</div>
                </div>
                <span class="badge bg-secondary font-monospace text-blood" style="border:1px solid #351316;">+${ind.points} pts</span>
              </div>
            `).join("")}
          </div>
        ` : `
          <div class="horror-inset-box p-3 rounded text-ash small text-center mb-3">
            No anomalous threat indicators triggered during automated evaluation.
          </div>
        `}
      `;
    }
  } catch (err) {
    modalBody.innerHTML = `<div class="text-danger p-3">Failed to load dossier details: ${err.message}</div>`;
  }
}

// -------------------------------------------------------------
// DELETE & CLEAR HISTORY
// -------------------------------------------------------------
async function deleteHistoryRecord(id) {
  if (!confirm(`Are you sure you want to delete investigation record #${id}?`)) return;

  try {
    const resp = await fetch(`/api/history/${id}`, { method: "DELETE" });
    const json = await resp.json();
    if (json.success) {
      showHorrorToast(`Investigation #${id} deleted from database.`, "success");
      loadDashboardHistory();
      fetchDashboardMetrics();
    } else {
      showHorrorToast(json.error || "Failed to delete record.", "danger");
    }
  } catch (err) {
    showHorrorToast(`Delete failed: ${err.message}`, "danger");
  }
}

async function confirmClearHistory() {
  const modalEl = document.getElementById("clearHistoryModal");
  const modalInstance = bootstrap.Modal.getInstance(modalEl);
  if (modalInstance) modalInstance.hide();

  try {
    const resp = await fetch("/api/history/clear", { method: "POST" });
    const json = await resp.json();
    if (json.success) {
      showHorrorToast("Investigation database purged successfully.", "success");
      loadDashboardHistory();
      fetchDashboardMetrics();
    }
  } catch (err) {
    showHorrorToast(`Purge failed: ${err.message}`, "danger");
  }
}

// -------------------------------------------------------------
// QUICK RECONNAISSANCE LAUNCHPAD
// -------------------------------------------------------------
function initQuickLaunchpad() {
  const input = document.getElementById("quickTargetInput");
  const typeSelect = document.getElementById("quickTargetType");
  const btn = document.getElementById("quickLaunchBtn");

  if (!btn || !input) return;

  btn.addEventListener("click", () => {
    const target = input.value.trim();
    if (!target) {
      showHorrorToast("Please provide a target domain or URL.", "warning");
      input.focus();
      return;
    }

    const type = typeSelect ? typeSelect.value : "url";
    if (type === "url") {
      window.location.href = `/analyzer?target=${encodeURIComponent(target)}`;
    } else if (type === "domain") {
      window.location.href = `/domain?target=${encodeURIComponent(target)}`;
    } else if (type === "osint") {
      window.location.href = `/osint?target=${encodeURIComponent(target)}`;
    } else if (type === "redirect") {
      window.location.href = `/redirects?target=${encodeURIComponent(target)}`;
    } else if (type === "scanner") {
      window.location.href = `/scanner?target=${encodeURIComponent(target)}`;
    }
  });

  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") btn.click();
  });
}

function fillQuickScan(target, type) {
  const input = document.getElementById("quickTargetInput");
  const typeSelect = document.getElementById("quickTargetType");
  if (input) input.value = target;
  if (typeSelect) typeSelect.value = type;
}