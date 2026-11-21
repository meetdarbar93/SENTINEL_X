/**
 * SENTINEL-X | Dark Horror & Paranormal Investigation Controller
 * Handles Atmospheric Dust/Ember Canvas, Terminal Sidebar, UTC Realtime Clock,
 * Eerie Audio Synthesizer, and Global Telemetry Search
 */

document.addEventListener("DOMContentLoaded", () => {
  initHorrorAtmosphereCanvas();
  initSidebar();
  initUtcClock();
  initThemeManager();
  initGlobalSearch();
  initModalReparenting();
});

// -------------------------------------------------------------
// DARK HORROR ATMOSPHERIC ASH & EMBER PARTICLES CANVAS
// -------------------------------------------------------------
function initHorrorAtmosphereCanvas() {
  const canvas = document.getElementById("horrorCanvas") || document.getElementById("cyberCanvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");

  let width = (canvas.width = window.innerWidth);
  let height = (canvas.height = window.innerHeight);

  window.addEventListener("resize", () => {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
  });

  // Floating ash motes and faint crimson embers
  const particleCount = Math.floor(Math.min(width, 1920) / 38);
  const particles = [];

  for (let i = 0; i < particleCount; i++) {
    const isEmber = Math.random() > 0.65;
    particles.push({
      x: Math.random() * width,
      y: Math.random() * height,
      vx: (Math.random() - 0.5) * 0.35,
      vy: -(Math.random() * 0.45 + 0.15), // Slow upward drift like ash/embers
      radius: Math.random() * 1.6 + 0.6,
      alpha: Math.random() * 0.35 + 0.15,
      maxAlpha: Math.random() * 0.4 + 0.2,
      pulseSpeed: Math.random() * 0.02 + 0.008,
      isEmber: isEmber,
      color: isEmber ? "227, 38, 54" : "146, 136, 136"
    });
  }

  function render() {
    ctx.clearRect(0, 0, width, height);
    const theme = document.documentElement.getAttribute("data-theme") || "dark";
    const isMono = theme === "monochrome";
    const isCyber = theme === "cyberpunk";
    const isNeo = theme === "neomorphism";
    const isHacker = theme === "hacker";
    const is3D = theme === "3d";
    const isPrimary = theme === "primary" || theme === "normal";

    for (let p of particles) {
      p.x += p.vx;
      p.y += p.vy;

      // Subtle pulse
      p.alpha += p.pulseSpeed;
      if (p.alpha > p.maxAlpha || p.alpha < 0.1) {
        p.pulseSpeed = -p.pulseSpeed;
      }

      // Wrap boundaries
      if (p.y < 0) {
        p.y = height + 10;
        p.x = Math.random() * width;
      }
      if (p.x < 0) p.x = width;
      if (p.x > width) p.x = 0;

      let particleColor = p.color;
      if (isPrimary) {
        particleColor = p.isEmber ? "59, 130, 246" : "148, 163, 184";
      } else if (is3D) {
        particleColor = p.isEmber ? "0, 210, 255" : "121, 40, 202";
      } else if (isHacker) {
        particleColor = p.isEmber ? "0, 255, 65" : "57, 255, 20";
      } else if (isCyber) {
        particleColor = p.isEmber ? "0, 245, 255" : "255, 0, 127";
      } else if (isNeo) {
        particleColor = p.isEmber ? "230, 0, 35" : "180, 180, 195";
      } else if (isMono) {
        particleColor = p.isEmber ? "245, 245, 245" : "150, 150, 150";
      }

      ctx.fillStyle = `rgba(${particleColor}, ${Math.max(0.05, p.alpha)})`;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
      ctx.fill();
    }

    requestAnimationFrame(render);
  }

  render();
}

// -------------------------------------------------------------
// SIDEBAR COLLAPSE & MOBILE DRAWER
// -------------------------------------------------------------
function initSidebar() {
  const sidebar = document.getElementById("appSidebar");
  const toggleBtn = document.getElementById("sidebarToggleBtn");
  const mobileToggle = document.getElementById("mobileMenuToggle");

  const isCollapsed = localStorage.getItem("sentinelx_sidebar_collapsed") === "true";
  if (isCollapsed && sidebar) {
    sidebar.classList.add("collapsed");
  }

  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener("click", () => {
      sidebar.classList.toggle("collapsed");
      localStorage.setItem("sentinelx_sidebar_collapsed", sidebar.classList.contains("collapsed"));
    });
  }

  if (mobileToggle && sidebar) {
    mobileToggle.addEventListener("click", () => {
      sidebar.classList.toggle("mobile-open");
    });
  }
}

// -------------------------------------------------------------
// IST (INDIAN STANDARD TIME) REAL-TIME CLOCK
// -------------------------------------------------------------
function initUtcClock() {
  initIstClock();
}

function initIstClock() {
  const timeElem = document.getElementById("utcClockTime") || document.getElementById("istClockTime");
  if (!timeElem) return;

  function update() {
    const now = new Date();
    try {
      const options = {
        timeZone: "Asia/Kolkata",
        hour12: false,
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
      };
      const formatter = new Intl.DateTimeFormat("en-GB", options);
      const parts = formatter.formatToParts(now);
      const hours = parts.find(p => p.type === "hour")?.value || "00";
      const minutes = parts.find(p => p.type === "minute")?.value || "00";
      const seconds = parts.find(p => p.type === "second")?.value || "00";
      timeElem.innerHTML = `${hours}<span class="utc-colon">:</span>${minutes}<span class="utc-colon">:</span>${seconds} IST`;
    } catch (e) {
      // Fallback: UTC + 5.5 hours
      const utcMs = now.getTime() + (now.getTimezoneOffset() * 60000);
      const istDate = new Date(utcMs + (5.5 * 3600000));
      const hours = String(istDate.getHours()).padStart(2, "0");
      const minutes = String(istDate.getMinutes()).padStart(2, "0");
      const seconds = String(istDate.getSeconds()).padStart(2, "0");
      timeElem.innerHTML = `${hours}<span class="utc-colon">:</span>${minutes}<span class="utc-colon">:</span>${seconds} IST`;
    }
  }

  update();
  setInterval(update, 1000);
}

// -------------------------------------------------------------
// THEME MANAGER (Obsidian Void / Cyberpunk 2077 / Pinterest Neomorphism / Monochrome Noir / High-Contrast Lab)
// -------------------------------------------------------------
function initThemeManager() {
  const savedTheme = localStorage.getItem("sentinelx_theme") || "dark";
  document.documentElement.setAttribute("data-theme", savedTheme);

  const themeToggle = document.getElementById("themeToggleBtn");
  if (themeToggle) {
    updateThemeIcon(savedTheme);
    themeToggle.addEventListener("click", () => {
      const current = document.documentElement.getAttribute("data-theme") || "dark";
      let nextTheme = "dark";
      if (current === "dark") nextTheme = "cyberpunk";
      else if (current === "cyberpunk") nextTheme = "neomorphism";
      else if (current === "neomorphism") nextTheme = "hacker";
      else if (current === "hacker") nextTheme = "3d";
      else if (current === "3d") nextTheme = "monochrome";
      else if (current === "monochrome") nextTheme = "primary";
      else if (current === "primary" || current === "normal") nextTheme = "light";
      else nextTheme = "dark";

      document.documentElement.setAttribute("data-theme", nextTheme);
      localStorage.setItem("sentinelx_theme", nextTheme);
      updateThemeIcon(nextTheme);
      window.dispatchEvent(new CustomEvent("themeChanged", { detail: { theme: nextTheme } }));

      const labels = {
        dark: "OBSIDIAN VOID (CRIMSON)",
        cyberpunk: "CYBERPUNK 2077 (NEON CYAN & MAGENTA)",
        neomorphism: "PINTEREST NEUMORPHISM (SOFT UI & CHERRY RED)",
        hacker: "MATRIX HACKER (PHOSPHOR GREEN)",
        "3d": "SPATIAL 3D COMPUTING (HOLOGRAPHIC CYAN & PRISM)",
        monochrome: "MONOCHROME NOIR (TITANIUM / SILVER)",
        primary: "SIMPLE NORMAL PRIMARY (ROYAL BLUE & SLATE)",
        light: "HIGH-CONTRAST LAB (HUD)"
      };
      showHorrorToast(`Theme Activated: ${labels[nextTheme] || nextTheme.toUpperCase()}`, "info");
    });
  }
}

function updateThemeIcon(theme) {
  const btn = document.getElementById("themeToggleBtn");
  const label = document.getElementById("themeToggleLabel");
  const select = document.getElementById("settingThemeSelect");

  if (select) select.value = theme;

  if (btn) {
    const icon = btn.querySelector("i");
    if (icon) {
      if (theme === "cyberpunk") {
        icon.className = "bi bi-lightning-charge-fill text-info";
        icon.style.color = "#00F5FF";
      } else if (theme === "neomorphism") {
        icon.className = "bi bi-palette2";
        icon.style.color = "#E60023";
      } else if (theme === "hacker") {
        icon.className = "bi bi-terminal-fill";
        icon.style.color = "#00FF41";
      } else if (theme === "3d") {
        icon.className = "bi bi-boxes";
        icon.style.color = "#00D2FF";
      } else if (theme === "monochrome") {
        icon.className = "bi bi-circle-half text-white";
        icon.style.color = "";
      } else if (theme === "primary" || theme === "normal") {
        icon.className = "bi bi-circle-square text-primary";
        icon.style.color = "#3B82F6";
      } else if (theme === "light") {
        icon.className = "bi bi-sun-fill text-warning";
        icon.style.color = "";
      } else {
        icon.className = "bi bi-circle-fill text-blood";
        icon.style.color = "";
      }
    }
  }

  if (label) {
    if (theme === "cyberpunk") {
      label.innerText = "CYBER";
    } else if (theme === "neomorphism") {
      label.innerText = "NEO";
    } else if (theme === "hacker") {
      label.innerText = "HACK";
    } else if (theme === "3d") {
      label.innerText = "3D";
    } else if (theme === "monochrome") {
      label.innerText = "MONO";
    } else if (theme === "primary" || theme === "normal") {
      label.innerText = "PRIMARY";
    } else if (theme === "light") {
      label.innerText = "LAB";
    } else {
      label.innerText = "VOID";
    }
  }
}

// -------------------------------------------------------------
// GLOBAL SEARCH BAR
// -------------------------------------------------------------
function initGlobalSearch() {
  const searchInput = document.getElementById("topbarSearchInput");
  if (!searchInput) return;

  searchInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      const val = searchInput.value.trim();
      if (!val) return;

      if (val.startsWith("http://") || val.startsWith("https://") || val.includes("/")) {
        window.location.href = `/analyzer?target=${encodeURIComponent(val)}`;
      } else if (val.includes(".")) {
        window.location.href = `/domain?target=${encodeURIComponent(val)}`;
      } else {
        window.location.href = `/history?search=${encodeURIComponent(val)}`;
      }
    }
  });
}

// -------------------------------------------------------------
// TOAST NOTIFICATION UTILITY
// -------------------------------------------------------------
function showCyberToast(message, type = "info", duration = 4000) {
  showHorrorToast(message, type, duration);
}

function showHorrorToast(message, type = "info", duration = 4000) {
  let container = document.getElementById("cyberToastContainer");
  if (!container) {
    container = document.createElement("div");
    container.id = "cyberToastContainer";
    container.style.cssText = "position:fixed; bottom:1.5rem; right:1.5rem; z-index:9999; display:flex; flex-direction:column; gap:0.5rem;";
    document.body.appendChild(container);
  }

  const toast = document.createElement("div");
  toast.className = `horror-toast toast-${type}`;
  toast.style.cssText = "background:#111111; border:1px solid #351316; border-left:4px solid #E32636; border-radius:4px; padding:0.75rem 1.25rem; color:#F1EAEA; display:flex; align-items:center; gap:0.75rem; box-shadow:0 8px 24px rgba(0,0,0,0.9);";

  let iconClass = "bi-shield-exclamation text-blood";
  if (type === "success") iconClass = "bi-check2-circle text-success";
  if (type === "warning") iconClass = "bi-exclamation-triangle-fill text-warning";
  if (type === "danger") iconClass = "bi-radioactive text-blood";

  toast.innerHTML = `
    <i class="bi ${iconClass} fs-5"></i>
    <span class="small fw-semibold text-bone" style="font-family:var(--font-body);">${message}</span>
    <button type="button" class="btn-close btn-close-white ms-auto" style="filter:invert(1); font-size:0.7rem;" aria-label="Close"></button>
  `;

  const closeBtn = toast.querySelector(".btn-close");
  closeBtn.addEventListener("click", () => toast.remove());

  container.appendChild(toast);

  setTimeout(() => {
    if (toast.parentNode) {
      toast.style.transition = "opacity 0.35s ease, transform 0.35s ease";
      toast.style.opacity = "0";
      toast.style.transform = "translateX(40px)";
      setTimeout(() => toast.remove(), 350);
    }
  }, duration);
}

// -------------------------------------------------------------
// CLIPBOARD COPY UTILITY & MODAL HELPERS
// -------------------------------------------------------------
function copyTextToClipboard(text, btnElement = null) {
  function fallbackCopy() {
    try {
      const ta = document.createElement("textarea");
      ta.value = text || "";
      ta.style.position = "fixed";
      ta.style.top = "-9999px";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
    } catch (e) {
      console.warn("Fallback copy failed:", e);
    }
  }

  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text || "").catch(() => fallbackCopy());
  } else {
    fallbackCopy();
  }

  if (btnElement) {
    const originalHtml = btnElement.innerHTML;
    btnElement.innerHTML = `<i class="bi bi-check2"></i> EXTRACTED`;
    btnElement.classList.add("text-blood");
    setTimeout(() => {
      btnElement.innerHTML = originalHtml;
      btnElement.classList.remove("text-blood");
    }, 2000);
  }

  showHorrorToast("Classified intelligence copied to clipboard.", "success", 2000);
}

function initModalReparenting() {
  document.querySelectorAll(".modal").forEach(modal => {
    if (modal.parentElement && modal.parentElement !== document.body) {
      document.body.appendChild(modal);
    }
  });
}

function closeModalById(modalId) {
  const modalEl = document.getElementById(modalId);
  if (!modalEl) return;
  if (window.bootstrap && bootstrap.Modal) {
    const instance = bootstrap.Modal.getInstance(modalEl) || bootstrap.Modal.getOrCreateInstance(modalEl);
    if (instance) instance.hide();
  }
}

// -------------------------------------------------------------
// EERIE WEB AUDIO SYNTHESIZER
// -------------------------------------------------------------
function triggerCyberAlertSound(type = "warning") {
  const audioEnabled = localStorage.getItem("sentinelx_audio_alerts") === "true";
  if (!audioEnabled) return;

  try {
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    if (!AudioCtx) return;
    const ctx = new AudioCtx();

    const osc = ctx.createOscillator();
    const gain = ctx.createGain();

    // Eerie descending paranormal drone
    osc.type = "sawtooth";
    osc.frequency.setValueAtTime(type === "danger" ? 220 : 340, ctx.currentTime);
    osc.frequency.exponentialRampToValueAtTime(type === "danger" ? 55 : 110, ctx.currentTime + 0.6);

    gain.gain.setValueAtTime(0.14, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.6);

    osc.connect(gain);
    gain.connect(ctx.destination);

    osc.start();
    osc.stop(ctx.currentTime + 0.6);
  } catch (e) {
    // Ignore audio context restrictions
  }
}