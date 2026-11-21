/**
 * SENTINEL-X | VirusTotal-Grade Cyber Threat Scanner Controller
 * Powers 68-Vendor Consensus Grid, Attack Vector Forensics,
 * SVG Circular Detection Gauge, and SOC Mitigation Playbooks.
 */

let currentThreatScanData = null;
let currentVendorFilter = "all";
let currentVendorSearchQuery = "";
let threatGraphInstance = null;
let currentPreviewData = null;

document.addEventListener("DOMContentLoaded", () => {
  const urlParams = new URLSearchParams(window.location.search);
  const targetParam = urlParams.get("target");
  if (targetParam) {
    setScannerPreset(targetParam, true);
  }

  // Handle Tab Switch for Threat Graph Canvas Resize
  const graphTabBtn = document.getElementById("tab-graph-btn");
  if (graphTabBtn) {
    graphTabBtn.addEventListener("shown.bs.tab", () => {
      if (threatGraphInstance) {
        threatGraphInstance.initCanvasSize();
        threatGraphInstance.recenter();
      }
    });
  }
});

function setScannerPreset(target, autoRun = false) {
  const input = document.getElementById("scannerTargetInput");
  if (input) {
    input.value = target;
    if (autoRun) {
      runThreatScan();
    }
  }
}

function clearThreatScanner() {
  const input = document.getElementById("scannerTargetInput");
  if (input) input.value = "";
  const results = document.getElementById("scannerResultsSection");
  if (results) results.style.display = "none";
}

async function runThreatScan() {
  const input = document.getElementById("scannerTargetInput");
  const target = input?.value.trim() || "";

  if (!target) {
    showHorrorToast("Please specify a target hostname, URL, or IP to scan.", "warning");
    input?.focus();
    return;
  }

  const loader = document.getElementById("scannerLoadingOverlay");
  const results = document.getElementById("scannerResultsSection");
  const submitBtn = document.getElementById("scannerSubmitBtn");
  const titleElem = document.getElementById("scannerStatusTitle");
  const subElem = document.getElementById("scannerStatusSubtitle");

  if (loader) loader.style.display = "block";
  if (results) results.style.display = "none";
  if (submitBtn) submitBtn.disabled = true;

  // Staged loading telemetry simulation
  if (titleElem) titleElem.innerText = "ENFORCING RFC-1918 SSRF PERIMETER & DNS RESOLUTION...";
  if (subElem) subElem.innerText = "Checking IP ranges, resolving authoritative NS, validating boundaries...";

  const t1 = setTimeout(() => {
    if (titleElem) titleElem.innerText = "PROBING 68 SECURITY ENGINES (VIRUSTOTAL GRID)...";
    if (subElem) subElem.innerText = "Querying Google SafeBrowsing, Kaspersky, CrowdStrike, Sophos, Fortinet...";
  }, 450);

  const t2 = setTimeout(() => {
    if (titleElem) titleElem.innerText = "EVALUATING 7 CYBER ATTACK SURFACES & COMPILING PLAYBOOK...";
    if (subElem) subElem.innerText = "Phishing, Droppers, C2 gates, SQLi/XSS, Cryptojacking, Port exposure...";
  }, 950);

  try {
    const response = await fetch("/api/scanner/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: target })
    });

    const json = await response.json();

    clearTimeout(t1);
    clearTimeout(t2);

    if (json.success && json.data) {
      currentThreatScanData = json.data;
      renderThreatScanResults(json.data);
      if (loader) loader.style.display = "none";
      if (results) results.style.display = "block";

      showHorrorToast(`Scan completed: ${json.data.detection_ratio.display} security vendors flagged target.`,
        json.data.risk_score >= 60 ? "danger" : json.data.risk_score >= 25 ? "warning" : "success"
      );
    } else {
      if (loader) loader.style.display = "none";
      showHorrorToast(json.error || "Threat scanner analysis failed.", "danger");
    }
  } catch (err) {
    clearTimeout(t1);
    clearTimeout(t2);
    if (loader) loader.style.display = "none";
    showHorrorToast(`Network or server error: ${err.message}`, "danger");
  } finally {
    if (submitBtn) submitBtn.disabled = false;
  }
}

function renderThreatScanResults(data) {
  // 1. Target Banner
  const resTargetDisplay = document.getElementById("resTargetDisplay");
  if (resTargetDisplay) resTargetDisplay.innerText = data.full_url || data.target;

  const resTargetScheme = document.getElementById("resTargetScheme");
  if (resTargetScheme) resTargetScheme.innerText = (data.scheme || "HTTP").toUpperCase();

  const resTargetPort = document.getElementById("resTargetPort");
  if (resTargetPort) resTargetPort.innerText = `PORT ${data.port || 80}`;

  const resSummaryText = document.getElementById("resSummaryText");
  if (resSummaryText) resSummaryText.innerText = data.summary;

  // Export Buttons
  const pdfBtn = document.getElementById("scannerDownloadPdfBtn");
  if (pdfBtn && data.investigation_id) {
    pdfBtn.href = `/api/reports/pdf/${data.investigation_id}`;
  }
  const jsonBtn = document.getElementById("scannerExportJsonBtn");
  if (jsonBtn && data.investigation_id) {
    jsonBtn.href = `/api/reports/json/${data.investigation_id}`;
  }

  // 2. Detection Ratio & Overall Verdict
  const ratio = data.detection_ratio || { malicious: 0, suspicious: 0, clean: 68, total: 68 };
  const resRatioMain = document.getElementById("resRatioMain");
  if (resRatioMain) resRatioMain.innerText = `${ratio.malicious} / ${ratio.total}`;

  const resMaliciousCount = document.getElementById("resMaliciousCount");
  if (resMaliciousCount) resMaliciousCount.innerText = ratio.malicious;

  const resSuspiciousCount = document.getElementById("resSuspiciousCount");
  if (resSuspiciousCount) resSuspiciousCount.innerText = ratio.suspicious;

  const resCleanCount = document.getElementById("resCleanCount");
  if (resCleanCount) resCleanCount.innerText = ratio.clean;

  // Circular SVG Gauge Animation
  const gauge = document.getElementById("vtGaugeCircle");
  if (gauge) {
    const totalVendors = ratio.total || 68;
    const flaggedFraction = (ratio.malicious + ratio.suspicious * 0.5) / totalVendors;
    const maxCircumference = 314.159; // 2 * PI * 50
    const offset = maxCircumference * (1 - Math.min(flaggedFraction, 1));
    gauge.style.strokeDashoffset = offset;

    if (ratio.malicious >= 5) {
      gauge.style.stroke = "var(--blood-bright)";
    } else if (ratio.malicious > 0 || ratio.suspicious > 0) {
      gauge.style.stroke = "var(--threat-med)";
    } else {
      gauge.style.stroke = "var(--threat-low)";
    }
  }

  // Overall Verdict Badge
  const verdictBadge = document.getElementById("resOverallVerdictBadge");
  if (verdictBadge) {
    verdictBadge.innerText = data.overall_verdict || "CLEAN";
    if (data.overall_verdict === "MALICIOUS") {
      verdictBadge.style.background = "var(--blood-crimson)";
      verdictBadge.style.color = "#FFFFFF";
    } else if (data.overall_verdict === "SUSPICIOUS") {
      verdictBadge.style.background = "var(--threat-med)";
      verdictBadge.style.color = "#000000";
    } else {
      verdictBadge.style.background = "var(--threat-low)";
      verdictBadge.style.color = "#000000";
    }
  }

  // 3. Heuristic Risk Score
  const score = data.risk_score || 0;
  const resRiskScoreBig = document.getElementById("resRiskScoreBig");
  if (resRiskScoreBig) resRiskScoreBig.innerText = score;

  const riskRatingBadge = document.getElementById("resRiskRatingBadge");
  const riskBar = document.getElementById("resRiskBar");

  let ratingColor = "var(--threat-low)";
  let ratingLabel = "LOW RISK";

  if (score >= 70) {
    ratingColor = "var(--threat-critical)";
    ratingLabel = "CRITICAL RISK";
  } else if (score >= 45) {
    ratingColor = "var(--threat-high)";
    ratingLabel = "HIGH RISK";
  } else if (score >= 20) {
    ratingColor = "var(--threat-med)";
    ratingLabel = "MEDIUM RISK";
  }

  if (riskRatingBadge) {
    riskRatingBadge.innerText = ratingLabel;
    riskRatingBadge.style.borderColor = ratingColor;
    riskRatingBadge.style.color = ratingColor;
    riskRatingBadge.style.background = `${ratingColor}22`;
  }
  if (riskBar) {
    riskBar.style.width = `${Math.min(score, 100)}%`;
    riskBar.style.background = ratingColor;
  }

  // 4. IP & Entropy Highlights
  const resTargetIp = document.getElementById("resTargetIp");
  if (resTargetIp) resTargetIp.innerText = data.primary_ip || "Unavailable";

  const resTargetEntropy = document.getElementById("resTargetEntropy");
  if (resTargetEntropy) resTargetEntropy.innerText = `${data.entropy_score || 0} bits`;

  const resEntropyBadge = document.getElementById("resEntropyBadge");
  if (resEntropyBadge) {
    if (data.entropy_score >= 3.6) {
      resEntropyBadge.innerText = "DGA SUSPECTED";
      resEntropyBadge.style.background = "rgba(227, 38, 54, 0.25)";
      resEntropyBadge.style.color = "var(--blood-bright)";
    } else {
      resEntropyBadge.innerText = "NORMAL";
      resEntropyBadge.style.background = "rgba(255, 255, 255, 0.08)";
      resEntropyBadge.style.color = "var(--text-ash)";
    }
  }

  // Triggered signatures
  const sigsContainer = document.getElementById("resTriggeredSignaturesList");
  if (sigsContainer) {
    sigsContainer.innerHTML = "";
    if (data.triggered_signatures && data.triggered_signatures.length > 0) {
      data.triggered_signatures.forEach(sig => {
        const span = document.createElement("span");
        span.className = "badge bg-danger text-light font-mono";
        span.innerText = sig;
        sigsContainer.appendChild(span);
      });
    } else {
      sigsContainer.innerHTML = `<span class="badge bg-dark text-muted font-mono">None (Clean Profile)</span>`;
    }
  }

  const resScanTimestamp = document.getElementById("resScanTimestamp");
  if (resScanTimestamp) resScanTimestamp.innerText = data.scan_timestamp || "";

  // 5. Update Tab Badges & Counts
  const attackBadgeCount = document.getElementById("resAttackBadgeCount");
  const attackCount = Array.isArray(data.attack_findings)
    ? data.attack_findings.length
    : (data.attack_findings ? Object.values(data.attack_findings).reduce((acc, arr) => acc + (Array.isArray(arr) ? arr.length : 0), 0) : 0);
  if (attackBadgeCount) attackBadgeCount.innerText = attackCount;

  // Filter Counts
  const filterCountAll = document.getElementById("filterCountAll");
  if (filterCountAll) filterCountAll.innerText = ratio.total;

  const filterCountMal = document.getElementById("filterCountMalicious");
  if (filterCountMal) filterCountMal.innerText = ratio.malicious;

  const filterCountSusp = document.getElementById("filterCountSuspicious");
  if (filterCountSusp) filterCountSusp.innerText = ratio.suspicious;

  const filterCountCln = document.getElementById("filterCountClean");
  if (filterCountCln) filterCountCln.innerText = ratio.clean;

  // 6. Render Vendor Grid
  renderVendorGrid();

  // 7. Render Attack Vectors
  renderAttackVectors(data.attack_findings || []);

  // 8. Render SOC Playbook
  renderMitigationPlaybook(data.mitigation_playbook || []);

  // 9. Target Anatomy
  renderTargetAnatomy(data);

  // 10. Threat Topology Graph
  if (data.threat_graph) {
    initThreatGraph(data.threat_graph);
  }

  // 11. Safe Headless Visual Preview
  fetchSafePreview(data.target || data.full_url);

  // 12. Render AI Executive Copilot
  renderAiExecutiveCopilot(data.executive_brief);

  // 13. Render MITRE & OWASP Matrix
  renderMitreMatrix(data.mitre_matrix);
}

function renderVendorGrid() {
  if (!currentThreatScanData) return;
  const grid = document.getElementById("vendorDetectionsGrid");
  if (!grid) return;

  const vendors = currentThreatScanData.vendor_detections || [];
  const search = currentVendorSearchQuery.toLowerCase();

  const filtered = vendors.filter(v => {
    // Status filter
    if (currentVendorFilter === "malicious" && v.verdict !== "malicious" && v.verdict !== "phishing") return false;
    if (currentVendorFilter === "suspicious" && v.verdict !== "suspicious") return false;
    if (currentVendorFilter === "clean" && v.verdict !== "clean") return false;

    // Search query filter
    if (search) {
      const matchName = v.vendor.toLowerCase().includes(search);
      const matchTier = v.tier.toLowerCase().includes(search);
      const matchCat = v.category.toLowerCase().includes(search);
      const matchLabel = (v.threat_label || "").toLowerCase().includes(search);
      if (!matchName && !matchTier && !matchCat && !matchLabel) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    grid.innerHTML = `
      <div class="col-12 text-center p-4 text-ash font-mono">
        <i class="bi bi-filter fs-2 d-block mb-2 text-dim"></i>
        No security vendors match the active filter criteria.
      </div>
    `;
    return;
  }

  grid.innerHTML = filtered.map(v => {
    const isMal = v.verdict === "malicious" || v.verdict === "phishing";
    const isSusp = v.verdict === "suspicious";

    const cardBorder = isMal ? "border-danger" : isSusp ? "border-warning" : "border-hairline";
    const statusColor = isMal ? "text-danger" : isSusp ? "text-warning" : "text-success";
    const statusBg = isMal ? "rgba(227, 38, 54, 0.08)" : isSusp ? "rgba(198, 155, 66, 0.08)" : "transparent";

    return `
      <div class="col-xl-3 col-lg-4 col-md-6">
        <div class="p-3 rounded h-100 d-flex flex-column justify-content-between transition-normal"
             style="background: ${statusBg}; border: 1px solid ${isMal ? 'var(--blood-crimson)' : isSusp ? 'var(--threat-med)' : 'var(--border-hairline)'};">
          <div>
            <div class="d-flex justify-content-between align-items-start mb-2">
              <span class="font-headline text-bone fw-bold" style="font-size: 0.95rem;">${escapeHtml(v.vendor)}</span>
              <i class="bi ${v.icon} fs-5"></i>
            </div>
            <div class="d-flex gap-1 mb-2">
              <span class="badge font-mono" style="background: rgba(255,255,255,0.06); color: var(--text-ash); font-size: 0.65rem;">${escapeHtml(v.tier)}</span>
              <span class="badge font-mono" style="background: rgba(255,255,255,0.03); color: var(--text-dim); font-size: 0.65rem;">${escapeHtml(v.category)}</span>
            </div>
          </div>
          <div class="border-top border-hairline pt-2 mt-2 d-flex justify-content-between align-items-center font-mono" style="font-size: 0.75rem;">
            <span class="fw-bold ${statusColor}">${v.verdict.toUpperCase()}</span>
            <span class="text-truncate text-bone user-select-all" style="max-width: 140px;" title="${escapeHtml(v.threat_label || '')}">
              ${escapeHtml(v.threat_label || 'Clean')}
            </span>
          </div>
        </div>
      </div>
    `;
  }).join("");
}

function filterVendors(filter) {
  currentVendorFilter = filter;
  ["All", "Malicious", "Suspicious", "Clean"].forEach(f => {
    const btn = document.getElementById(`filterBtn${f}`);
    if (btn) {
      if (f.toLowerCase() === filter) {
        btn.classList.add("active");
        btn.style.borderColor = "var(--blood-bright)";
      } else {
        btn.classList.remove("active");
        btn.style.borderColor = "";
      }
    }
  });
  renderVendorGrid();
}

function searchVendors(query) {
  currentVendorSearchQuery = query.trim();
  renderVendorGrid();
}

function renderAttackVectors(findings) {
  const container = document.getElementById("attackVectorsContainer");
  if (!container) return;

  let list = Array.isArray(findings) ? findings : [];
  if (!Array.isArray(findings) && findings && typeof findings === "object") {
    list = [];
    Object.keys(findings).forEach(cat => {
      if (Array.isArray(findings[cat])) {
        findings[cat].forEach(item => {
          list.push({
            category: cat.replace(/_/g, " ").toUpperCase(),
            severity: item.severity || "Medium",
            finding: item.vector || "Security Anomaly",
            description: item.detail || item.description || "-",
            points: 20
          });
        });
      }
    });
  }

  if (list.length === 0) {
    container.innerHTML = `
      <div class="col-12">
        <div class="p-5 text-center rounded font-mono" style="background: rgba(101, 155, 120, 0.08); border: 1px dashed var(--threat-low);">
          <i class="bi bi-shield-check fs-1 text-success d-block mb-3"></i>
          <h4 class="text-bone mb-2">NO EXPLOIT SIGNATURES DETECTED</h4>
          <p class="text-ash mb-0">The target does not exhibit signatures of Phishing, Executable Droppers, Ransomware C2, Web Injections, or Cryptojacking.</p>
        </div>
      </div>
    `;
    return;
  }

  container.innerHTML = list.map(f => {
    const isCritical = f.severity === "Critical" || f.severity === "High";
    const badgeColor = isCritical ? "var(--blood-bright)" : "var(--threat-med)";
    const bgGlow = isCritical ? "rgba(227, 38, 54, 0.06)" : "rgba(198, 155, 66, 0.04)";

    return `
      <div class="col-lg-6">
        <div class="p-4 rounded h-100 d-flex flex-column justify-content-between"
             style="background: ${bgGlow}; border: 1px solid ${isCritical ? 'var(--blood-crimson)' : 'var(--threat-med)'};">
          <div>
            <div class="d-flex justify-content-between align-items-center mb-2">
              <span class="badge font-mono" style="background: rgba(255,255,255,0.08); color: var(--text-ash);">
                ${escapeHtml(f.category)}
              </span>
              <span class="badge font-mono" style="background: ${badgeColor}; color: #fff;">
                ${f.severity.toUpperCase()} (+${f.points} PTS)
              </span>
            </div>
            <h5 class="font-headline text-bone mb-2">${escapeHtml(f.finding)}</h5>
            <p class="text-ash small mb-3">${escapeHtml(f.description)}</p>
          </div>
          <div class="font-mono small p-2 rounded text-truncate user-select-all" style="background: var(--bg-void); border: 1px solid var(--border-hairline); color: var(--blood-bright);">
            <code>SIGNATURE: ${escapeHtml(f.finding)}</code>
          </div>
        </div>
      </div>
    `;
  }).join("");
}

function renderMitigationPlaybook(rules) {
  const container = document.getElementById("mitigationRulesContainer");
  if (!container) return;

  if (rules.length === 0) {
    container.innerHTML = `
      <div class="col-12 text-center p-4 text-ash font-mono">
        No active mitigation rules required for this target profile.
      </div>
    `;
    return;
  }

  container.innerHTML = rules.map((r, idx) => {
    const ruleId = `mitigationRuleCode_${idx}`;
    return `
      <div class="col-lg-6">
        <div class="p-4 rounded h-100 d-flex flex-column justify-content-between" style="background: var(--bg-panel); border: 1px solid var(--border-hairline);">
          <div>
            <div class="d-flex justify-content-between align-items-center mb-2">
              <span class="font-mono text-blood small text-uppercase">// ${escapeHtml(r.type)}</span>
              <span class="badge bg-secondary font-mono small">${escapeHtml(r.action)}</span>
            </div>
            <pre class="p-3 rounded font-mono small user-select-all mb-3 text-bone" id="${ruleId}"
                 style="background: var(--bg-void); border: 1px solid var(--border-hairline); white-space: pre-wrap; word-break: break-all; max-height: 180px; overflow-y: auto;">${escapeHtml(r.command)}</pre>
          </div>
          <button class="editorial-btn editorial-btn-outline btn-sm align-self-start"
                  onclick="copyRuleFromElement('${ruleId}', '${escapeHtml(r.type)}')">
            <i class="bi bi-clipboard me-1"></i> COPY DIRECTIVE
          </button>
        </div>
      </div>
    `;
  }).join("");
}

function renderTargetAnatomy(data) {
  const setElem = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.innerText = val || "-";
  };

  setElem("resAnatomyHostname", data.hostname);
  setElem("resAnatomyIp", data.primary_ip);
  setElem("resAnatomyPort", `${data.port} (${(data.scheme || 'http').toUpperCase()})`);
  setElem("resAnatomyEntropy", `${data.entropy_score || 0} bits`);
  setElem("resAnatomyInvId", `#${data.investigation_id || 'PENDING'}`);
}

function copyRuleFromElement(elementId, ruleType) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const text = el.innerText;
  copyTextToClipboard(text, `${ruleType} copied to clipboard`);
}

function copyTextToClipboard(text, successMsg = "Copied to clipboard") {
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(() => {
      showHorrorToast(successMsg, "success");
    }).catch(() => {
      fallbackCopyText(text, successMsg);
    });
  } else {
    fallbackCopyText(text, successMsg);
  }
}

function fallbackCopyText(text, successMsg) {
  const textArea = document.createElement("textarea");
  textArea.value = text;
  textArea.style.position = "fixed";
  textArea.style.left = "-999999px";
  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();
  try {
    document.execCommand("copy");
    showHorrorToast(successMsg, "success");
  } catch (err) {
    showHorrorToast("Copy failed. Please manually select the text.", "warning");
  }
  document.body.removeChild(textArea);
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

/* =========================================================================
   THREAT TOPOLOGY GRAPH CONTROLLERS
   ========================================================================= */

function initThreatGraph(graphData) {
  const canvas = document.getElementById("threatTopologyCanvas");
  if (!canvas) return;

  if (!threatGraphInstance) {
    threatGraphInstance = new ThreatTopologyGraph("threatTopologyCanvas");
  }
  threatGraphInstance.loadGraph(graphData);
}

function setThreatGraphFilter(type) {
  if (threatGraphInstance) {
    threatGraphInstance.setFilter(type);
  }
  ["All", "Target", "Infra", "Threat"].forEach(f => {
    const btn = document.getElementById(`graphFilter${f}`);
    if (btn) {
      if ((f === "All" && type === "all") ||
          (f === "Target" && type === "target") ||
          (f === "Infra" && (type === "ip" || type === "ns")) ||
          (f === "Threat" && type === "threat")) {
        btn.classList.add("active");
        btn.style.borderColor = "var(--blood-bright)";
      } else {
        btn.classList.remove("active");
        btn.style.borderColor = "";
      }
    }
  });
}

function zoomThreatGraphIn() {
  if (threatGraphInstance) threatGraphInstance.zoomIn();
}

function zoomThreatGraphOut() {
  if (threatGraphInstance) threatGraphInstance.zoomOut();
}

function recenterThreatGraph() {
  if (threatGraphInstance) {
    threatGraphInstance.initCanvasSize();
    threatGraphInstance.recenter();
  }
}

/* =========================================================================
   SAFE HEADLESS VISUAL PREVIEW & DOM DISSECTOR
   ========================================================================= */

async function fetchSafePreview(target) {
  if (!target) return;
  const loader = document.getElementById("previewLoadingState");
  const container = document.getElementById("previewDataContainer");

  if (loader) loader.style.display = "block";
  if (container) container.style.opacity = "0.3";

  try {
    const resp = await fetch("/api/preview/capture", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target: target })
    });
    const json = await resp.json();

    if (json.success && json.data) {
      currentPreviewData = json.data;
      renderSafePreview(json.data);
    } else {
      renderSafePreviewError(json.error || "Unable to capture visual preview.");
    }
  } catch (err) {
    renderSafePreviewError(`Preview capture failed: ${err.message}`);
  } finally {
    if (loader) loader.style.display = "none";
    if (container) {
      container.style.opacity = "1";
      container.style.display = "block";
    }
  }
}

function refreshSafePreview() {
  if (currentThreatScanData) {
    fetchSafePreview(currentThreatScanData.target || currentThreatScanData.full_url);
  }
}

function renderSafePreview(preview) {
  const statusBadge = document.getElementById("previewHttpStatusBadge");
  if (statusBadge) {
    const code = preview.status_code || 200;
    statusBadge.innerText = `${code} ${code >= 400 ? 'ERROR' : code >= 300 ? 'REDIRECT' : 'OK'}`;
    statusBadge.className = `badge ${code >= 400 ? 'bg-danger' : code >= 300 ? 'bg-warning text-dark' : 'bg-success'}`;
  }

  const protoElem = document.getElementById("previewProtocol");
  if (protoElem) protoElem.innerText = (preview.scheme || "HTTPS").toUpperCase();

  const titleElem = document.getElementById("previewPageTitle");
  if (titleElem) {
    titleElem.innerText = preview.title || "No Title Tag Found";
    titleElem.title = preview.title || "";
  }

  const serverElem = document.getElementById("previewServerBanner");
  if (serverElem) {
    serverElem.innerText = preview.server || "Undisclosed Server";
  }

  // Phishing & Form Telemetry
  const phishingBadge = document.getElementById("previewPhishingBadge");
  const formAlert = document.getElementById("previewFormAlert");
  const formsContainer = document.getElementById("previewFormsContainer");
  const formCountBadge = document.getElementById("previewFormCountBadge");

  const forms = preview.forms || [];
  if (formCountBadge) formCountBadge.innerText = forms.length;

  const hasPasswordInput = forms.some(f => (f.inputs || []).some(inp => inp.type === "password"));
  const hasPhishingRisk = preview.phishing_risk || hasPasswordInput;

  if (phishingBadge) {
    if (hasPhishingRisk) {
      phishingBadge.innerHTML = `<span class="badge bg-danger text-light"><i class="bi bi-shield-exclamation me-1"></i> HIGH RISK (CREDENTIAL HARVESTING)</span>`;
    } else {
      phishingBadge.innerHTML = `<span class="badge bg-success"><i class="bi bi-shield-check me-1"></i> NOMINAL (NO PASSWORD PROMPT)</span>`;
    }
  }

  if (formAlert) {
    if (hasPhishingRisk) {
      formAlert.style.display = "block";
      formAlert.innerHTML = `
        <div class="p-3 rounded font-mono" style="background: rgba(227, 38, 54, 0.12); border: 1px solid var(--blood-crimson);">
          <div class="d-flex align-items-center gap-2 text-danger fw-bold mb-1">
            <i class="bi bi-exclamation-triangle-fill fs-5"></i>
            <span>CREDENTIAL HARVESTING TELEMETRY ALERT</span>
          </div>
          <div class="text-ash small">
            This target serves one or more HTML authentication forms containing sensitive <code>&lt;input type="password"&gt;</code> fields.
            Verify domain authenticity and TLS certificate ownership before submitting credentials.
          </div>
        </div>
      `;
    } else {
      formAlert.style.display = "none";
    }
  }

  // Render Forms in Tab
  if (formsContainer) {
    if (forms.length === 0) {
      formsContainer.innerHTML = `
        <div class="p-4 text-center rounded text-ash font-mono" style="background: var(--bg-void); border: 1px solid var(--border-hairline);">
          <i class="bi bi-ui-checks text-dim fs-2 d-block mb-2"></i>
          No interactive HTML <code>&lt;form&gt;</code> elements detected in sanitized DOM.
        </div>
      `;
    } else {
      formsContainer.innerHTML = forms.map((f, i) => {
        const inputBadges = (f.inputs || []).map(inp => {
          const isPass = inp.type === "password";
          const isEmail = inp.type === "email";
          const bg = isPass ? "bg-danger" : isEmail ? "bg-warning text-dark" : "bg-secondary";
          return `<span class="badge ${bg} me-1 mb-1 font-mono">${escapeHtml(inp.type)}: ${escapeHtml(inp.name || 'unnamed')}</span>`;
        }).join("");

        return `
          <div class="p-3 rounded" style="background: var(--bg-panel); border: 1px solid var(--border-hairline);">
            <div class="d-flex justify-content-between align-items-center mb-2">
              <span class="text-bone fw-bold">// FORM #${i + 1}</span>
              <span class="badge bg-dark border border-hairline font-mono text-blood">${escapeHtml(f.method || 'GET')}</span>
            </div>
            <div class="text-dim small mb-2 text-truncate">ACTION: <code class="text-bone">${escapeHtml(f.action || 'self')}</code></div>
            <div class="d-flex flex-wrap align-items-center gap-1 mt-2">
              <span class="text-ash small me-1">INPUTS:</span>
              ${inputBadges || '<span class="text-dim">No input fields</span>'}
            </div>
          </div>
        `;
      }).join("");
    }
  }

  // Inject sanitized HTML into iframe
  const iframe = document.getElementById("previewSandboxIframe");
  if (iframe) {
    iframe.srcdoc = preview.sanitized_html || "<!DOCTYPE html><html><body><h3 style='color:#666;font-family:sans-serif;'>Empty DOM received</h3></body></html>";
  }

  // Byte size & Raw HTML
  const sizeElem = document.getElementById("previewByteSize");
  if (sizeElem) {
    sizeElem.innerText = `Content Payload: ${(preview.html_bytes || 0).toLocaleString()} bytes`;
  }

  const rawPre = document.getElementById("previewRawHtmlCode");
  if (rawPre) {
    rawPre.innerText = preview.sanitized_html || "";
  }
}

function renderSafePreviewError(msg) {
  const iframe = document.getElementById("previewSandboxIframe");
  if (iframe) {
    iframe.srcdoc = `
      <!DOCTYPE html>
      <html>
      <head><style>body { font-family: monospace; background: #0f0a0d; color: #ff6b6b; padding: 2rem; }</style></head>
      <body>
        <h3>🛡️ SENTINEL-X SANDBOX ISOLATION ENFORCED</h3>
        <p>Could not render live DOM snapshot:</p>
        <p style="background: #2a1118; padding: 10px; border-radius: 4px; color: #fca5a5;">${escapeHtml(msg)}</p>
        <small style="color: #999;">If this target is a local RFC-1918 address or unreachable host, access is blocked by design.</small>
      </body>
      </html>
    `;
  }

  const rawPre = document.getElementById("previewRawHtmlCode");
  if (rawPre) rawPre.innerText = `<!-- Preview Error: ${msg} -->`;
}

function copyPreviewHtml() {
  if (!currentPreviewData || !currentPreviewData.sanitized_html) {
    showHorrorToast("No preview HTML available to copy.", "warning");
    return;
  }
  copyTextToClipboard(currentPreviewData.sanitized_html, "Sanitized DOM HTML copied to clipboard.");
}

/* =========================================================================
   AI SOC THREAT COPILOT & EXECUTIVE BRIEF
   ========================================================================= */

function renderAiExecutiveCopilot(brief) {
  const card = document.getElementById("aiCopilotCard");
  if (!card) return;

  if (!brief) {
    card.style.display = "none";
    return;
  }

  card.style.display = "block";

  const sevBadge = document.getElementById("aiSeverityBadge");
  if (sevBadge) {
    sevBadge.innerText = brief.severity || "SEV-4 NOMINAL";
    const isSev1 = (brief.severity || "").includes("SEV-1");
    const isSev2 = (brief.severity || "").includes("SEV-2");
    sevBadge.style.background = isSev1 ? "var(--blood-crimson)" : isSev2 ? "var(--threat-med)" : "var(--threat-low)";
    sevBadge.style.color = isSev1 ? "#FFFFFF" : "#000000";
  }

  const urgBadge = document.getElementById("aiUrgencyBadge");
  if (urgBadge) urgBadge.innerText = brief.urgency || "BASELINE";

  const archLabel = document.getElementById("aiArchetypeLabel");
  if (archLabel) archLabel.innerText = brief.archetype || "Heuristic Assessment";

  const actorElem = document.getElementById("aiActorProfile");
  if (actorElem) actorElem.innerText = brief.actor_profile || "";

  const narrativeElem = document.getElementById("aiNarrativeText");
  if (narrativeElem) narrativeElem.innerText = brief.executive_summary || "Telemetry evaluated.";

  const dirList = document.getElementById("aiDirectivesList");
  if (dirList) {
    const list = brief.actionable_directives || [];
    if (list.length === 0) {
      dirList.innerHTML = `<li class="text-dim">No critical actions required.</li>`;
    } else {
      dirList.innerHTML = list.map((d, i) => `
        <li class="d-flex align-items-start gap-2">
          <span class="text-blood fw-bold">0${i + 1}.</span>
          <span class="user-select-all text-bone">${escapeHtml(d)}</span>
        </li>
      `).join("");
    }
  }
}

/* =========================================================================
   MITRE ATT&CK & OWASP MATRIX ALIGNMENT
   ========================================================================= */

function renderMitreMatrix(matrix) {
  const postureBadge = document.getElementById("mitrePostureBadge");
  const tacticsContainer = document.getElementById("mitreTacticsContainer");
  const owaspContainer = document.getElementById("owaspBadgesContainer");
  const frameworkText = document.getElementById("mitreMitigationFrameworkText");

  if (!matrix) {
    if (tacticsContainer) tacticsContainer.innerHTML = `<div class="col-12 text-ash font-mono">No MITRE ATT&CK telemetry available.</div>`;
    return;
  }

  if (postureBadge) {
    postureBadge.innerHTML = matrix.overall_mitre_posture || "BENIGN / BASELINE";
  }

  if (frameworkText) {
    frameworkText.innerText = matrix.mitigation_framework || "Enforce zero-trust architecture.";
  }

  // Render Tactics
  if (tacticsContainer) {
    const tactics = matrix.tactics || [];
    if (tactics.length === 0) {
      tacticsContainer.innerHTML = `
        <div class="col-12">
          <div class="p-4 text-center rounded font-mono" style="background: rgba(101, 155, 120, 0.08); border: 1px dashed var(--threat-low);">
            <i class="bi bi-shield-check fs-2 text-success d-block mb-2"></i>
            <h5 class="text-bone mb-1">NO ADVERSARIAL MITRE TACTICS TRIGGERED</h5>
            <div class="text-ash small">The target did not match signatures of Initial Access, Execution, Persistence, or Command & Control.</div>
          </div>
        </div>
      `;
    } else {
      tacticsContainer.innerHTML = tactics.map(t => {
        const techPills = (t.techniques || []).map(tech => `
          <a href="${tech.url}" target="_blank" rel="noopener noreferrer"
             class="badge p-2 text-decoration-none transition-normal"
             style="background: var(--bg-void); border: 1px solid var(--border-hairline); color: var(--text-bone);"
             title="Open official MITRE ATT&CK technique reference">
            <span class="text-blood fw-bold">${escapeHtml(tech.id)}</span> &bull; ${escapeHtml(tech.name)}
            <i class="bi bi-box-arrow-up-right ms-1 small text-dim"></i>
          </a>
        `).join("");

        return `
          <div class="col-lg-6">
            <div class="p-3 rounded h-100" style="background: var(--bg-panel); border: 1px solid var(--border-hairline);">
              <div class="d-flex justify-content-between align-items-center mb-2 pb-2 border-bottom border-hairline">
                <span class="font-headline text-bone fs-6">// ${escapeHtml(t.tactic.toUpperCase())}</span>
                <span class="badge bg-secondary font-mono">${escapeHtml(t.tactic_id)}</span>
              </div>
              <div class="d-flex flex-wrap gap-2 mt-2">
                ${techPills}
              </div>
            </div>
          </div>
        `;
      }).join("");
    }
  }

  // Render OWASP Top 10 Badges
  if (owaspContainer) {
    const owasp = matrix.owasp_top10 || [];
    if (owasp.length === 0) {
      owaspContainer.innerHTML = `<span class="badge bg-dark text-muted font-mono p-2">None (No correlated OWASP vulnerabilities)</span>`;
    } else {
      owaspContainer.innerHTML = owasp.map(o => `
        <span class="badge p-2 font-mono" style="background: rgba(227, 38, 54, 0.15); border: 1px solid var(--blood-crimson); color: var(--blood-bright);">
          <i class="bi bi-shield-x me-1"></i> ${escapeHtml(o)}
        </span>
      `).join("");
    }
  }
}

/* =========================================================================
   SOC IOC EXPORT HANDLER
   ========================================================================= */

function downloadInvestigationIoc(format) {
  if (!currentThreatScanData || !currentThreatScanData.investigation_id) {
    showHorrorToast("Please run a threat scan before exporting IOCs.", "warning");
    return;
  }
  const id = currentThreatScanData.investigation_id;
  const url = `/api/reports/ioc/${id}?format=${format}`;

  if (format === "stix") {
    window.open(url, "_blank");
  } else {
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinelx_ioc_${id}.${format === 'snort' ? 'rules' : format === 'splunk' ? 'spl' : 'csv'}`;
    a.click();
  }
  showHorrorToast(`Exported ${format.toUpperCase()} IOCs successfully.`, "success");
}

/* =========================================================================
   MULTI-TARGET BATCH THREAT SCANNER
   ========================================================================= */

function populateBatchSample() {
  const ta = document.getElementById("batchTargetsInput");
  if (ta) {
    ta.value = "https://wikipedia.org\nhttp://paypal.com@verify-auth.top/login\nhttp://malware-drop-test.xyz/invoice.exe\nhttps://github.com\nhttp://127.0.0.1:8080/admin";
  }
}

async function runBatchScan() {
  const ta = document.getElementById("batchTargetsInput");
  const text = ta?.value.trim() || "";
  if (!text) {
    showHorrorToast("Please enter at least one target for batch scanning.", "warning");
    ta?.focus();
    return;
  }

  const btn = document.getElementById("btnRunBatchScan");
  const prog = document.getElementById("batchProgressLabel");
  const tableContainer = document.getElementById("batchResultsTableContainer");
  const tbody = document.getElementById("batchMatrixTbody");

  if (btn) btn.disabled = true;
  if (prog) prog.innerText = "Running concurrent thread-pool matrix scan...";

  try {
    const resp = await fetch("/api/scanner/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ targets: text })
    });
    const json = await resp.json();

    if (json.success && json.data) {
      if (prog) prog.innerText = `Completed scan of ${json.data.total_targets} targets at ${json.data.scanned_at}`;
      if (tableContainer) tableContainer.style.display = "block";

      const malElem = document.getElementById("batchMalCount");
      if (malElem) malElem.innerText = `${json.data.malicious_count} Malicious`;

      const suspElem = document.getElementById("batchSuspCount");
      if (suspElem) suspElem.innerText = `${json.data.suspicious_count} Suspicious`;

      const clnElem = document.getElementById("batchCleanCount");
      if (clnElem) clnElem.innerText = `${json.data.clean_count} Clean`;

      if (tbody) {
        tbody.innerHTML = (json.data.results || []).map(r => {
          const isMal = r.overall_verdict === "MALICIOUS";
          const isSusp = r.overall_verdict === "SUSPICIOUS";
          const verdictClass = isMal
            ? "threat-status-tag critical font-mono py-0.5 px-2"
            : isSusp
            ? "threat-status-tag medium font-mono py-0.5 px-2"
            : "threat-status-tag low font-mono py-0.5 px-2";

          return `
            <tr>
              <td class="fw-bold text-bone user-select-all">${escapeHtml(r.target)}</td>
              <td><span class="${verdictClass}">${escapeHtml(r.overall_verdict)}</span></td>
              <td class="fw-bold ${isMal ? 'text-danger' : isSusp ? 'text-warning' : 'text-success'}">${r.risk_score}</td>
              <td class="font-mono text-ash">${r.malicious_engines} / 68</td>
              <td class="text-truncate text-ash" style="max-width: 220px;" title="${escapeHtml(r.top_finding)}">${escapeHtml(r.top_finding)}</td>
              <td class="text-end">
                <button class="editorial-btn-outline btn-sm py-0.5 px-2" onclick="loadBatchTargetIntoScanner('${escapeHtml(r.target)}')">
                  Inspect
                </button>
              </td>
            </tr>
          `;
        }).join("");
      }
      showHorrorToast(`Batch scan finished: ${json.data.total_targets} targets scanned.`, "success");
    } else {
      if (prog) prog.innerText = "Batch scan failed.";
      showHorrorToast(json.error || "Batch scan failed.", "danger");
    }
  } catch (err) {
    if (prog) prog.innerText = "Batch execution error.";
    showHorrorToast(`Batch error: ${err.message}`, "danger");
  } finally {
    if (btn) btn.disabled = false;
  }
}

function loadBatchTargetIntoScanner(target) {
  const modalEl = document.getElementById("batchScannerModal");
  if (modalEl && window.bootstrap && bootstrap.Modal) {
    const inst = bootstrap.Modal.getInstance(modalEl);
    if (inst) inst.hide();
  }
  setScannerPreset(target, true);
}
