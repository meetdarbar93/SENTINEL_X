/**
 * SENTINEL-X | Interactive Threat Graph & Visual Topology Engine
 * Pure HTML5 Canvas Force-Directed Network Simulation.
 * Visualizes Target -> Redirects -> DNS/IPs -> Nameservers -> Attack Vectors.
 * Supports physics, node dragging, pan/zoom, edge pulse particles, and theme adaptation.
 */

class ThreatTopologyGraph {
  constructor(canvasId, options = {}) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;

    this.ctx = this.canvas.getContext("2d");
    this.options = Object.assign({
      repulsion: 1800,
      springLength: 130,
      springCoeff: 0.003,
      damping: 0.88,
      nodeRadiusScale: 1.0,
      showLabels: true
    }, options);

    this.nodes = [];
    this.edges = [];
    this.particles = [];
    this.selectedNode = null;
    this.hoveredNode = null;
    this.draggedNode = null;

    // Viewport Transform (Pan & Zoom)
    this.scale = 1.0;
    this.offsetX = 0;
    this.offsetY = 0;
    this.isPanning = false;
    this.panStartX = 0;
    this.panStartY = 0;

    this.filterType = "all";
    this.animId = null;

    this.initCanvasSize();
    this.bindEvents();
  }

  initCanvasSize() {
    const rect = this.canvas.parentElement.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    this.width = rect.width || 800;
    this.height = Math.max(rect.height, 460);

    this.canvas.width = this.width * dpr;
    this.canvas.height = this.height * dpr;
    this.canvas.style.width = `${this.width}px`;
    this.canvas.style.height = `${this.height}px`;
    this.ctx.scale(dpr, dpr);

    if (this.offsetX === 0 && this.offsetY === 0) {
      this.offsetX = this.width / 2;
      this.offsetY = this.height / 2;
    }
  }

  loadGraph(graphData) {
    if (!graphData || !graphData.nodes) return;

    const rawNodes = graphData.nodes || [];
    const rawEdges = graphData.edges || [];

    // Layout initial circular spread around center
    const total = rawNodes.length;
    this.nodes = rawNodes.map((n, i) => {
      const angle = (i / Math.max(total - 1, 1)) * Math.PI * 2;
      const dist = n.type === "target" ? 0 : (n.type === "redirect" ? 90 : (n.type === "threat" ? 170 : 140));
      return {
        id: n.id,
        label: n.label,
        type: n.type,
        sublabel: n.sublabel || "",
        color: n.color || "#3B82F6",
        icon: n.icon || "bi-circle",
        size: (n.size || 22) * this.options.nodeRadiusScale,
        data: n.data || {},
        x: n.type === "target" ? 0 : Math.cos(angle) * dist + (Math.random() - 0.5) * 40,
        y: n.type === "target" ? 0 : Math.sin(angle) * dist + (Math.random() - 0.5) * 40,
        vx: 0,
        vy: 0,
        mass: n.type === "target" ? 4.0 : 1.2
      };
    });

    const nodeMap = new Map();
    this.nodes.forEach(n => nodeMap.set(n.id, n));

    this.edges = [];
    rawEdges.forEach(e => {
      const source = nodeMap.get(e.source);
      const target = nodeMap.get(e.target);
      if (source && target) {
        this.edges.push({
          source: source,
          target: target,
          label: e.label || "",
          type: e.type || "default",
          color: e.color || "#475569",
          dashed: !!e.dashed
        });
      }
    });

    // Spawn animated edge particles
    this.particles = [];
    for (let i = 0; i < this.edges.length * 2; i++) {
      const edge = this.edges[i % this.edges.length];
      this.particles.push({
        edge: edge,
        t: Math.random(),
        speed: 0.006 + Math.random() * 0.008,
        color: edge.color || "#3B82F6"
      });
    }

    this.recenter();
    if (!this.animId) {
      this.animate();
    }
  }

  recenter() {
    this.scale = 1.0;
    this.offsetX = this.width / 2;
    this.offsetY = this.height / 2;
  }

  zoomIn() {
    this.scale = Math.min(this.scale * 1.25, 3.0);
  }

  zoomOut() {
    this.scale = Math.max(this.scale * 0.8, 0.4);
  }

  setFilter(type) {
    this.filterType = type;
  }

  updatePhysics() {
    const nodes = this.nodes;
    const edges = this.edges;

    // 1. Repulsion force between all nodes
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i];
        const b = nodes[j];

        const dx = b.x - a.x;
        const dy = b.y - a.y;
        let dist = Math.hypot(dx, dy) || 1;
        if (dist > 350) continue;

        const force = (this.options.repulsion / (dist * dist)) * 0.8;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;

        if (a !== this.draggedNode && a.type !== "target") {
          a.vx -= fx / a.mass;
          a.vy -= fy / a.mass;
        }
        if (b !== this.draggedNode && b.type !== "target") {
          b.vx += fx / b.mass;
          b.vy += fy / b.mass;
        }
      }
    }

    // 2. Spring force along edges
    for (let e of edges) {
      const a = e.source;
      const b = e.target;
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const dist = Math.hypot(dx, dy) || 1;

      const displacement = dist - this.options.springLength;
      const force = displacement * this.options.springCoeff;
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;

      if (a !== this.draggedNode && a.type !== "target") {
        a.vx += fx / a.mass;
        a.vy += fy / a.mass;
      }
      if (b !== this.draggedNode && b.type !== "target") {
        b.vx -= fx / b.mass;
        b.vy -= fy / b.mass;
      }
    }

    // 3. Central gravity pulling toward origin (0, 0)
    for (let n of nodes) {
      if (n === this.draggedNode) continue;
      if (n.type === "target") {
        n.x *= 0.9;
        n.y *= 0.9;
        continue;
      }

      const dist = Math.hypot(n.x, n.y) || 1;
      const grav = 0.0006 * dist;
      n.vx -= (n.x / dist) * grav;
      n.vy -= (n.y / dist) * grav;

      n.vx *= this.options.damping;
      n.vy *= this.options.damping;

      n.x += n.vx;
      n.y += n.vy;
    }

    // 4. Update edge particle flows
    for (let p of this.particles) {
      p.t += p.speed;
      if (p.t > 1) p.t = 0;
    }
  }

  render() {
    const ctx = this.ctx;
    ctx.clearRect(0, 0, this.width, this.height);

    ctx.save();
    ctx.translate(this.offsetX, this.offsetY);
    ctx.scale(this.scale, this.scale);

    // Current theme
    const theme = document.documentElement.getAttribute("data-theme") || "dark";
    const isCyber = theme === "cyberpunk";
    const isHacker = theme === "hacker";
    const is3D = theme === "3d";
    const isPrimary = theme === "primary" || theme === "normal";
    const isNeo = theme === "neomorphism";

    // 1. Draw Edges
    for (let e of this.edges) {
      if (!this.isNodeVisible(e.source) || !this.isNodeVisible(e.target)) continue;

      ctx.beginPath();
      ctx.moveTo(e.source.x, e.source.y);
      ctx.lineTo(e.target.x, e.target.y);

      if (e.dashed) {
        ctx.setLineDash([4, 4]);
      } else {
        ctx.setLineDash([]);
      }

      ctx.strokeStyle = e.color || (isCyber ? "rgba(0, 245, 255, 0.35)" : isHacker ? "rgba(0, 255, 65, 0.35)" : isPrimary ? "rgba(59, 130, 246, 0.35)" : "rgba(181, 18, 27, 0.3)");
      ctx.lineWidth = e.type === "threat" ? 2.2 : 1.5;
      ctx.stroke();

      // Edge labels
      if (e.label && this.scale > 0.75) {
        const midX = (e.source.x + e.target.x) / 2;
        const midY = (e.source.y + e.target.y) / 2;
        ctx.font = "9px 'JetBrains Mono', monospace";
        ctx.fillStyle = isNeo ? "#555" : (isPrimary ? "#94A3B8" : "#888");
        ctx.textAlign = "center";
        ctx.fillText(e.label, midX, midY - 3);
      }
    }
    ctx.setLineDash([]);

    // 2. Draw Moving Edge Particles
    for (let p of this.particles) {
      if (!this.isNodeVisible(p.edge.source) || !this.isNodeVisible(p.edge.target)) continue;
      const px = p.edge.source.x + (p.edge.target.x - p.edge.source.x) * p.t;
      const py = p.edge.source.y + (p.edge.target.y - p.edge.source.y) * p.t;

      ctx.beginPath();
      ctx.arc(px, py, 2.5, 0, Math.PI * 2);
      ctx.fillStyle = p.color;
      ctx.shadowColor = p.color;
      ctx.shadowBlur = 6;
      ctx.fill();
      ctx.shadowBlur = 0;
    }

    // 3. Draw Nodes
    for (let n of this.nodes) {
      if (!this.isNodeVisible(n)) continue;

      const isHovered = n === this.hoveredNode;
      const isSelected = n === this.selectedNode;
      const r = isHovered ? n.size * 1.15 : n.size;

      // Glow Halo
      if (isHovered || isSelected || n.type === "threat" || n.type === "target") {
        ctx.beginPath();
        ctx.arc(n.x, n.y, r + (n.type === "threat" ? 8 : 5), 0, Math.PI * 2);
        ctx.fillStyle = n.color + (n.type === "threat" ? "33" : "22");
        ctx.fill();
      }

      // Outer Ring
      ctx.beginPath();
      ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
      ctx.fillStyle = isNeo ? "#ECECF1" : (isPrimary ? "#161F30" : isHacker ? "#071C0E" : is3D ? "#111A30" : "#140E0F");
      ctx.fill();

      ctx.lineWidth = isSelected ? 3.5 : (isHovered ? 2.5 : 1.8);
      ctx.strokeStyle = n.color;
      ctx.stroke();

      // Node Icon / Inner Symbol
      ctx.beginPath();
      ctx.arc(n.x, n.y, r * 0.45, 0, Math.PI * 2);
      ctx.fillStyle = n.color;
      ctx.fill();

      // Node Labels
      if (this.options.showLabels) {
        ctx.font = `${n.type === 'target' ? 'bold 12px' : '10.5px'} 'JetBrains Mono', monospace`;
        ctx.fillStyle = isNeo ? "#111" : "#F8FAFC";
        ctx.textAlign = "center";
        ctx.fillText(this.truncate(n.label, 20), n.x, n.y + r + 13);

        if (n.sublabel) {
          ctx.font = "8.5px 'JetBrains Mono', monospace";
          ctx.fillStyle = n.color;
          ctx.fillText(n.sublabel, n.x, n.y + r + 24);
        }
      }
    }

    ctx.restore();
  }

  isNodeVisible(n) {
    if (this.filterType === "all") return true;
    if (this.filterType === "target" && n.type === "target") return true;
    if (this.filterType === "threat" && (n.type === "threat" || n.type === "vendor")) return true;
    if (this.filterType === "infrastructure" && (n.type === "ip" || n.type === "nameserver" || n.type === "mail" || n.type === "redirect")) return true;
    return false;
  }

  truncate(str, max) {
    if (!str) return "";
    return str.length > max ? str.slice(0, max - 2) + ".." : str;
  }

  animate() {
    this.updatePhysics();
    this.render();
    this.animId = requestAnimationFrame(() => this.animate());
  }

  bindEvents() {
    window.addEventListener("resize", () => this.initCanvasSize());

    // Mouse / Touch Dragging & Panning
    this.canvas.addEventListener("mousedown", (e) => this.handleMouseDown(e));
    window.addEventListener("mousemove", (e) => this.handleMouseMove(e));
    window.addEventListener("mouseup", (e) => this.handleMouseUp(e));

    // Mouse Wheel Zoom
    this.canvas.addEventListener("wheel", (e) => {
      e.preventDefault();
      const zoomFactor = e.deltaY < 0 ? 1.1 : 0.9;
      this.scale = Math.min(Math.max(this.scale * zoomFactor, 0.4), 3.0);
    }, { passive: false });

    // Node click
    this.canvas.addEventListener("click", (e) => {
      const node = this.getNodeAtScreen(e.clientX, e.clientY);
      if (node) {
        this.selectedNode = node;
        this.onNodeClick(node);
      }
    });
  }

  handleMouseDown(e) {
    const node = this.getNodeAtScreen(e.clientX, e.clientY);
    if (node) {
      this.draggedNode = node;
    } else {
      this.isPanning = true;
      this.panStartX = e.clientX - this.offsetX;
      this.panStartY = e.clientY - this.offsetY;
      this.canvas.style.cursor = "grabbing";
    }
  }

  handleMouseMove(e) {
    if (this.draggedNode) {
      const worldPos = this.screenToWorld(e.clientX, e.clientY);
      this.draggedNode.x = worldPos.x;
      this.draggedNode.y = worldPos.y;
      this.draggedNode.vx = 0;
      this.draggedNode.vy = 0;
      return;
    }

    if (this.isPanning) {
      this.offsetX = e.clientX - this.panStartX;
      this.offsetY = e.clientY - this.panStartY;
      return;
    }

    // Hover detection
    const hovered = this.getNodeAtScreen(e.clientX, e.clientY);
    if (hovered !== this.hoveredNode) {
      this.hoveredNode = hovered;
      this.canvas.style.cursor = hovered ? "pointer" : "default";
      this.onNodeHover(hovered);
    }
  }

  handleMouseUp(e) {
    this.draggedNode = null;
    this.isPanning = false;
    this.canvas.style.cursor = "default";
  }

  screenToWorld(screenX, screenY) {
    const rect = this.canvas.getBoundingClientRect();
    const cx = screenX - rect.left;
    const cy = screenY - rect.top;
    return {
      x: (cx - this.offsetX) / this.scale,
      y: (cy - this.offsetY) / this.scale
    };
  }

  getNodeAtScreen(screenX, screenY) {
    const world = this.screenToWorld(screenX, screenY);
    for (let i = this.nodes.length - 1; i >= 0; i--) {
      const n = this.nodes[i];
      if (!this.isNodeVisible(n)) continue;
      const dist = Math.hypot(n.x - world.x, n.y - world.y);
      if (dist <= n.size + 4) {
        return n;
      }
    }
    return null;
  }

  onNodeHover(node) {
    const tooltip = document.getElementById("graphNodeTooltip");
    if (!tooltip) return;

    if (!node) {
      tooltip.style.display = "none";
      return;
    }

    tooltip.style.display = "block";
    tooltip.innerHTML = `
      <div class="d-flex align-items-center gap-2 mb-1">
        <span class="badge" style="background:${node.color}; color:#fff; font-size:10px;">${node.type.toUpperCase()}</span>
        <strong style="color:var(--text-bone); font-size:12px;">${node.label}</strong>
      </div>
      <div style="color:var(--text-ash); font-size:11px;">${node.sublabel || ''}</div>
    `;
  }

  onNodeClick(node) {
    const inspector = document.getElementById("graphNodeInspector");
    if (!inspector) return;

    inspector.style.display = "block";
    const extra = node.data || {};
    const extraRows = Object.keys(extra).map(k => `
      <div class="d-flex justify-content-between border-bottom border-hairline py-1">
        <span class="text-dim text-uppercase">${k}:</span>
        <span class="text-bone user-select-all">${extra[k]}</span>
      </div>
    `).join("");

    inspector.innerHTML = `
      <div class="d-flex justify-content-between align-items-center mb-2">
        <span class="badge" style="background:${node.color}; color:#fff;">// ${node.type.toUpperCase()} NODE</span>
        <button class="btn btn-sm btn-link text-dim p-0" onclick="document.getElementById('graphNodeInspector').style.display='none'">✕</button>
      </div>
      <h6 class="text-bone mb-1 font-mono">${node.label}</h6>
      <div class="text-ash small mb-3">${node.sublabel || 'Entity Details'}</div>
      <div class="font-mono small">${extraRows || '<span class="text-dim">No further metadata</span>'}</div>
    `;
  }
}
