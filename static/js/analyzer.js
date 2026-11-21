/**
 * SENTINEL-X | Dark Horror URL Threat Analyzer Controller
 * Orchestrates deep URL structural parsing, heuristic anomaly detection,
 * safe redirect inspection, and animated blood-red HUD risk evaluation.
 */

let currentUrlAnalysisData = null;

document.addEventListener("DOMContentLoaded", () => {
  const urlParams = new URLSearchParams(window.location.search);
  const targetParam = urlParams.get("target");
  if (targetParam) {
    setUrlTarget(targetParam, true);
  }
});

function setUrlTarget(url, autoRun = false) {
  const input = document.getElementById("targetUrlInput");
  if (input) {
    input.value = url;
    if (autoRun) {
      runUrlAnalysis();
    }
  }
}

function clearUrlAnalyzerForm() {
  const input = document.getElementById("targetUrlInput");
  if (input) input.value = "";
  const results = document.getElementById("urlResultsSection");
  if (results) results.style.display = "none";
}

function navigateToRedirectInspector() {
  if (!currentUrlAnalysisData) return;
  const target = currentUrlAnalysisData.target_url;
  window.location.href = `/redirects?target=${encodeURIComponent(target)}`;
}

async function runUrlAnalysis() {
  const input = document.getElementById("targetUrlInput");
  const rawUrl = input?.value.trim() || "";

  if (!rawUrl) {
    showHorrorToast("Please provide a target URL to examine.", "warning");
    input?.focus();
    return;
  }

  const loader = document.getElementById("urlLoadingOverlay");
  const results = document.getElementById("urlResultsSection");
  const btn = document.getElementById("analyzeUrlBtn");
  const statusElem = document.getElementById("urlScannerStatus");

  if (loader) loader.style.display = "block";
  if (results) results.style.display = "none";
  if (btn) btn.disabled = true;

  // Staged Paranormal Investigation Scanning Messages
  if (statusElem) statusElem.innerText = "COMMENCING FORENSIC DECOMPOSITION & DE-OBFUSCATION...";
  const stageTimeout1 = setTimeout(() => {
    if (statusElem) statusElem.innerText = "PROBING REMOTE HOST, DNS RECORDS & RECONSTITUTING SANs...";
  }, 400);
  const stageTimeout2 = setTimeout(() => {
    if (statusElem) statusElem.innerText = "EXECUTING HEURISTIC ENGINE & EXAMINING HIDDEN ENTITIES...";
  }, 900);

  try {
    const resp = await fetch("/api/url/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: rawUrl })
    });

    const json = await resp.json();

    if (json.success && json.data) {
      currentUrlAnalysisData = json.data;
      renderUrlAnalysisResults(json.data);

      const riskLevel = json.data.risk_assessment?.level || "Low";
      if (riskLevel === "High" || riskLevel === "Critical") {
        triggerCyberAlertSound("danger");
        showHorrorToast("CRITICAL RISK PROFILE DETECTED: Exercise extreme caution.", "danger");
      } else if (riskLevel === "Medium") {
        triggerCyberAlertSound("warning");
        showHorrorToast("SUSPICIOUS ANOMALY: Heuristic risk indicators flagged.", "warning");
      } else {
        showHorrorToast("Examination complete: Target assessed as Benign.", "success");
      }
    } else {
      showHorrorToast(json.error || "URL examination failed.", "danger");
    }
  } catch (err) {
    showHorrorToast(`Network connection error: ${err.message}`, "danger");
  } finally {
    clearTimeout(stageTimeout1);
    clearTimeout(stageTimeout2);
    if (loader) loader.style.display = "none";
    if (btn) btn.disabled = false;
  }
}

function renderUrlAnalysisResults(data) {
  const struct = data.url_structure || {};
  const risk = data.risk_assessment || { score: 0, level: "Low", indicators: [], precautions: [] };
  const dom = data.domain_details || {};
  const redir = data.redirect_analysis || {};

  // 1. Executive Threat Banner
  const schemeElem = document.getElementById("resTargetScheme");
  if (schemeElem) schemeElem.innerText = (struct.scheme || "HTTPS").toUpperCase();

  const fullUrlElem = document.getElementById("resFullUrlLabel");
  if (fullUrlElem) fullUrlElem.innerText = data.target_url || "-";

  const summaryElem = document.getElementById("resSummaryText");
  if (summaryElem) summaryElem.innerText = data.summary || "Heuristic risk evaluation complete.";

  // Risk Score & Badge
  const scoreElem = document.getElementById("resRiskScore");
  const scoreVal = risk.score !== undefined ? risk.score : 0;
  if (scoreElem) scoreElem.innerText = scoreVal;

  const badgeElem = document.getElementById("resRiskBadge");
  if (badgeElem) {
    const levelStr = (risk.level || "Low").toUpperCase();
    badgeElem.innerText = `${levelStr} RISK`;
    let badgeClass = "low";
    if (risk.level === "Critical" || risk.level === "High") badgeClass = "critical";
    else if (risk.level === "Medium") badgeClass = "medium";
    badgeElem.className = `risk-badge ${badgeClass} mt-1`;
  }

  // Animated Blood Gauge Stroke & Color Logic
  const gaugeProgress = document.getElementById("neonGaugeProgress");
  const progressBar = document.getElementById("riskProgressBar");
  const verdictStatus = document.getElementById("resVerdictStatus");

  const maxCircumference = 351.8;
  const clampedScore = Math.max(0, Math.min(100, scoreVal));
  const offset = maxCircumference * (1 - clampedScore / 100);

  let gaugeColor = "#659B78"; // Ghostly Sage
  let verdictText = "BENIGN / LOW ANOMALY";

  if (clampedScore >= 80 || risk.level === "Critical") {
    gaugeColor = "#E32636"; // Blood Red
    verdictText = "CRITICAL THREAT / BREACH";
  } else if (clampedScore >= 60 || risk.level === "High") {
    gaugeColor = "#E26B35"; // Burnt Ember
    verdictText = "HIGH MALICIOUS PROFILE";
  } else if (clampedScore >= 30 || risk.level === "Medium") {
    gaugeColor = "#C69B42"; // Tarnished Brass
    verdictText = "SUSPICIOUS ANOMALY FLAGGED";
  }

  if (gaugeProgress) {
    gaugeProgress.style.strokeDashoffset = offset;
    gaugeProgress.style.stroke = gaugeColor;
  }
  if (progressBar) {
    progressBar.style.width = `${clampedScore}%`;
    progressBar.style.backgroundColor = gaugeColor;
  }
  if (verdictStatus) {
    verdictStatus.innerText = verdictText;
    verdictStatus.style.color = gaugeColor;
  }

  // Header Badges
  const indBadge = document.getElementById("resIndicatorsCountBadge");
  if (indBadge) indBadge.innerText = `${(risk.indicators || []).length} Threat Indicators`;

  // Export Buttons
  if (data.investigation_id) {
    const pdfBtn = document.getElementById("downloadPdfDossierBtn");
    if (pdfBtn) pdfBtn.href = `/api/reports/pdf/${data.investigation_id}`;

    const jsonBtn = document.getElementById("exportJsonDossierBtn");
    if (jsonBtn) jsonBtn.href = `/api/reports/json/${data.investigation_id}`;
  }

  // 2. Structural Decomposition
  const lenBadge = document.getElementById("urlLengthBadge");
  if (lenBadge) lenBadge.innerText = `${struct.total_length || 0} Chars`;

  const sScheme = document.getElementById("structScheme");
  if (sScheme) sScheme.innerText = struct.scheme || "-";

  const sHost = document.getElementById("structHostname");
  if (sHost) sHost.innerText = struct.hostname || "-";

  const sPort = document.getElementById("structPort");
  if (sPort) sPort.innerText = struct.port || (struct.scheme === "https" ? 443 : 80);

  const portBadge = document.getElementById("structPortBadge");
  if (portBadge) {
    if (struct.is_default_port) {
      portBadge.className = "badge bg-secondary ms-1 text-bone";
      portBadge.innerText = "Standard";
    } else {
      portBadge.className = "badge bg-warning text-dark ms-1";
      portBadge.innerText = "Non-Standard Port";
    }
  }

  const sSub = document.getElementById("structSubdomains");
  if (sSub) {
    sSub.innerText = `${struct.subdomain_depth || 0} levels (${(struct.domain_labels || []).join(" • ")})`;
  }

  const sPath = document.getElementById("structPath");
  if (sPath) {
    sPath.innerText = struct.path || "/";
    sPath.title = struct.path || "/";
  }

  const sFrag = document.getElementById("structFragment");
  if (sFrag) sFrag.innerText = struct.fragment || "None";

  // Query Parameters
  const paramsCountElem = document.getElementById("structParamsCount");
  if (paramsCountElem) paramsCountElem.innerText = `${struct.query_params_count || 0} detected`;

  const paramsListElem = document.getElementById("queryParamsList");
  if (paramsListElem) {
    if (struct.query_params && struct.query_params.length > 0) {
      paramsListElem.innerHTML = struct.query_params.map(p => `
        <div class="d-flex align-items-center gap-1 font-mono small">
          <span class="text-blood">${p.key}</span> = <span class="text-bone fw-semibold">${p.values.join(", ")}</span>
        </div>
      `).join("");
    } else {
      paramsListElem.innerHTML = `<span class="text-ash small">No query parameters attached</span>`;
    }
  }

  // 3. Domain Intelligence & SSL
  const hostPrimaryIpElem = document.getElementById("hostPrimaryIp");
  if (dom.is_blocked) {
    if (hostPrimaryIpElem) hostPrimaryIpElem.innerHTML = `<span class="text-danger">BLOCKED (${dom.block_reason || "SSRF Boundary"})</span>`;
  } else {
    if (hostPrimaryIpElem) hostPrimaryIpElem.innerText = dom.resolved_ip || "Unavailable";
  }

  const ssl = dom.ssl_info || {};
  const sslValBadge = document.getElementById("hostSslValidityBadge");
  const sslIssuerElem = document.getElementById("hostSslIssuer");

  if (ssl.available && !ssl.is_expired) {
    if (sslValBadge) {
      sslValBadge.className = "badge bg-success font-monospace";
      sslValBadge.innerText = "Valid TLS";
    }
    if (sslIssuerElem) {
      sslIssuerElem.innerText = `Issuer: ${ssl.issuer?.organizationName || ssl.issuer?.commonName || "Active CA"}`;
    }
  } else if (ssl.is_expired) {
    if (sslValBadge) {
      sslValBadge.className = "badge bg-danger font-monospace";
      sslValBadge.innerText = "EXPIRED";
    }
    if (sslIssuerElem) sslIssuerElem.innerText = "Certificate Expired";
  } else {
    if (sslValBadge) {
      sslValBadge.className = "badge bg-secondary font-monospace text-ash";
      sslValBadge.innerText = "Inactive";
    }
    if (sslIssuerElem) sslIssuerElem.innerText = "No SSL Certificate Detected";
  }

  // 4. Triggered Threat Indicators
  const indContainer = document.getElementById("indicatorsContainer");
  if (indContainer) {
    if (risk.indicators && risk.indicators.length > 0) {
      indContainer.innerHTML = risk.indicators.map(ind => {
        let badgeClass = "bg-secondary text-bone";
        if (ind.severity === "Critical" || ind.severity === "High") badgeClass = "bg-danger text-white";
        else if (ind.severity === "Medium") badgeClass = "bg-warning text-dark";

        return `
          <div class="horror-inset-box p-3 rounded mb-2">
            <div class="d-flex flex-wrap align-items-start justify-content-between gap-2 mb-2">
              <div class="d-flex align-items-center gap-2">
                <span class="badge ${badgeClass} font-mono">${(ind.severity || "INFO").toUpperCase()}</span>
                <strong class="text-bone fs-6">${ind.title || "Indicator"}</strong>
              </div>
              <span class="badge bg-secondary font-mono text-blood" style="border:1px solid #351316;">+${ind.points || 0} pts</span>
            </div>

            <div class="text-ash small mb-2">
              ${ind.description || "-"}
            </div>

            <div class="p-2 rounded horror-inset-box small text-blood">
              <i class="bi bi-shield-exclamation me-1"></i> <strong>Precaution:</strong> ${ind.recommendation || "Verify destination identity."}
            </div>
          </div>
        `;
      }).join("");
    } else {
      indContainer.innerHTML = `
        <div class="horror-inset-box p-4 rounded text-center text-ash">
          <i class="bi bi-check2-circle text-success fs-3 d-block mb-2"></i>
          <strong class="text-bone fs-6">No Hostile Threat Indicators Detected</strong>
          <p class="small mb-0 mt-1">The examined target exhibits no known malicious footprints, credential harvesting patterns, or deceptive executable payloads.</p>
        </div>
      `;
    }
  }

  // 5. Redirect Trajectory
  const redirFlag = document.getElementById("redirectStatusFlag");
  const redirContainer = document.getElementById("redirectChainContainer");

  if (redirContainer) {
    if (redir.chain && redir.chain.length > 0) {
      if (redirFlag) {
        redirFlag.innerText = redir.is_redirected ? `${redir.total_hops} Hops Detected` : "Direct (No Redirects)";
        redirFlag.className = redir.has_downgrade ? "badge bg-danger font-mono" : "badge bg-secondary font-mono text-bone";
      }

      redirContainer.innerHTML = redir.chain.map(h => `
        <div class="horror-inset-box p-2.5 rounded d-flex flex-wrap align-items-center justify-content-between gap-2 mb-2">
          <div class="d-flex align-items-center gap-2">
            <span class="badge bg-secondary text-blood font-mono" style="border:1px solid #351316;">HOP #${h.hop}</span>
            <span class="code-snippet text-blood py-1 px-2">${h.status_code || "-"}</span>
            <span class="text-bone text-truncate font-mono" style="max-width: 450px;" title="${h.url}">${h.url}</span>
          </div>
          <div class="text-dim font-mono small">
            <span>IP: <strong class="text-blood">${h.ip || "Unknown"}</strong></span>
            ${h.response_time_ms ? `<span class="ms-2">(${h.response_time_ms}ms)</span>` : ""}
          </div>
        </div>
      `).join("");

      if (redir.has_downgrade) {
        redirContainer.innerHTML += `
          <div class="alert alert-danger mb-0 mt-2 py-2 small" style="background:#240C0E; border:1px solid #B5121B; color:#F1EAEA;">
            <i class="bi bi-exclamation-octagon-fill me-1 text-blood"></i> <strong>Critical Protocol Downgrade:</strong> The redirect sequence transitioned from HTTPS to cleartext HTTP, exposing sessions to MITM interception.
          </div>
        `;
      }
    } else {
      if (redirFlag) {
        redirFlag.innerText = "Direct (No Redirects)";
        redirFlag.className = "badge bg-secondary font-mono text-ash";
      }
      redirContainer.innerHTML = `<div class="horror-inset-box p-3 rounded text-ash small text-center">Direct destination. No intermediate redirect hops encountered.</div>`;
    }
  }

  // 6. Actionable Precautions List
  const precContainer = document.getElementById("precautionsList");
  if (precContainer) {
    if (risk.precautions && risk.precautions.length > 0) {
      precContainer.innerHTML = risk.precautions.map(p => `
        <div class="horror-inset-box p-2.5 rounded d-flex align-items-center gap-2 text-ash small mb-2">
          <i class="bi bi-shield-check text-blood fs-5 flex-shrink-0"></i>
          <span class="text-bone">${p}</span>
        </div>
      `).join("");
    } else {
      precContainer.innerHTML = `
        <div class="horror-inset-box p-2.5 rounded text-ash small">
          <i class="bi bi-check2 text-success me-1"></i> Standard baseline defensive precautions apply.
        </div>
      `;
    }
  }

  const resultsSec = document.getElementById("urlResultsSection");
  if (resultsSec) resultsSec.style.display = "block";
}