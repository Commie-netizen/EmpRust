// Graph view on a canvas, in the spirit of Obsidian's graph: grey round nodes sized by
// links, thin grey edges with small arrows, labels that fade in with zoom, hover
// highlighting, pan, zoom around the cursor, node dragging. Labels are drawn with
// fillText on the canvas, so archive text never reaches the DOM from here.
import { Simulation } from "./sim.js";

export const DEFAULT_SETTINGS = {
  search: "", tags: false, attachments: true, orphans: true, existingOnly: false,
  groups: [],
  arrows: true, textFade: 0, nodeSize: 1, linkThickness: 1, legend: true,
  center: 0.5, repel: 10, link: 1, distance: 250,
};

const COLORS = {
  bg: "#1e1e1e",
  node: "#b9b9b9",
  tag: "#6fcf8f",
  file: "#d8b45a",
  edge: "rgba(150,150,150,0.38)",
  edgeHi: "#a882ff",
  nodeHi: "#c2a8ff",
  label: "#a8a8a8",
  select: "#a882ff",
};

// Restrained tints for the default colouring by group, readable on #1e1e1e.
export const GROUP_PALETTE = ["#8fb4d9", "#c9a26b", "#93c08f", "#c48fb4", "#8fc4c0", "#c7c27a", "#a99ad6",
  "#d1957f", "#7fb0a0", "#b8b8b8"];
const LABEL_MAX = 30; // characters shown under a node; the full title is in the tooltip

/** Tag nodes are told apart by node_type, never by the shape of their id. */
export const isVirtual = (node) => node.node_type === "tag";

function truncate(label, max) {
  return label.length > max ? `${label.slice(0, max - 1).trimEnd()}\u2026` : label;
}

/** A predicate for a query such as `path:Journal tag:#idée -brouillon mot`. */
export function makeMatcher(query) {
  const tokens = String(query || "").trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (!tokens.length) return null;
  const tests = tokens.map((tok) => {
    let neg = false;
    if (tok.startsWith("-") && tok.length > 1) { neg = true; tok = tok.slice(1); }
    let fn;
    if (tok.startsWith("path:")) { const v = tok.slice(5); fn = (n) => (n.path || "").toLowerCase().includes(v); }
    else if (tok.startsWith("tag:")) {
      const v = tok.slice(4).replace(/^#/, "");
      fn = (n) => (n.tags || []).some((t) => { const l = t.toLowerCase(); return l === v || l.startsWith(`${v}/`); });
    } else if (tok.startsWith("file:")) { const v = tok.slice(5); fn = (n) => (n.label || "").toLowerCase().includes(v); }
    else fn = (n) => (n.label || "").toLowerCase().includes(tok) || (n.path || "").toLowerCase().includes(tok);
    return neg ? (n) => !fn(n) : fn;
  });
  return (n) => tests.every((t) => t(n));
}

export function nodeTime(n) { return Date.parse(n.authored_at || n.created_at); }

export class GraphView {
  constructor(canvas, { onOpen, onSelection, onStatus, onLegend, insets } = {}) {
    this.canvas = canvas;
    this.onLegend = onLegend || (() => {});
    this.insets = insets || (() => ({ right: 0 }));
    this.ctx = canvas.getContext("2d");
    this.onOpen = onOpen || (() => {});
    this.onSelection = onSelection || (() => {});
    this.onStatus = onStatus || (() => {});
    this.sim = new Simulation();
    this.settings = structuredClone(DEFAULT_SETTINGS);
    this.data = { nodes: [], edges: [], unresolved: 0 };
    this.byId = new Map(); // id -> live node object (positions survive refetches)
    this.visible = [];
    this.links = [];
    this.neighbors = new Map();
    this.selection = new Set();
    this.hover = null;
    this.t = { x: 0, y: 0, k: 1 };
    this.autoFit = true;
    this.anim = null;
    this.raf = null;
    this.dpr = window.devicePixelRatio || 1;
    this.width = 1; this.height = 1;
    this.pointer = null;
    this.frame = this.frame.bind(this);
    this.bind();
  }

  // --------------------------------------------------------------- data
  setGraph(graph) {
    this.data = graph;
    const seen = new Set();
    for (const raw of graph.nodes) {
      seen.add(raw.id);
      let n = this.byId.get(raw.id);
      if (!n) {
        n = { x: NaN, y: NaN, vx: 0, vy: 0 };
        this.byId.set(raw.id, n);
      }
      Object.assign(n, { id: raw.id, label: raw.label, path: raw.path, group: raw.group, kind: raw.kind,
        tags: raw.tags || [], degree: raw.degree, created_at: raw.created_at, authored_at: raw.authored_at,
        node_type: raw.node_type || "entry", virtual: isVirtual(raw) });
    }
    for (const id of [...this.byId.keys()]) if (!seen.has(id)) this.byId.delete(id);
    for (const id of [...this.selection]) if (!seen.has(id)) this.selection.delete(id);
    if (this.hover && !seen.has(this.hover.id)) this.hover = null;
    this.rebuild(0.5);
  }

  clear() {
    this.data = { nodes: [], edges: [], unresolved: 0 };
    this.byId.clear();
    this.neighbors.clear();
    this.pointer = null;
    this.canvas.classList.remove("dragging");
    this.selection.clear();
    this.visible = []; this.links = []; this.hover = null; this.anim = null;
    this.sim.setData([], []);
    this.autoFit = true;
    this.draw();
  }

  /** Recompute the visible subgraph from the data and the filters. */
  rebuild(heat = 0.3, subset = null) {
    const S = this.settings;
    const match = makeMatcher(S.search);
    let nodes = [];
    for (const raw of this.data.nodes) {
      const n = this.byId.get(raw.id);
      if (!n) continue;
      if (!S.attachments && n.kind === "file") continue;
      if (n.virtual && (S.existingOnly || !S.tags)) continue;
      if (match && !n.virtual && !match(n)) continue;
      if (subset && !subset.has(n.id)) continue;
      nodes.push(n);
    }
    let keep = new Set(nodes.map((n) => n.id));
    let edges = this.data.edges.filter((e) => keep.has(e.source) && keep.has(e.target));
    const deg = new Map();
    for (const e of edges) {
      deg.set(e.source, (deg.get(e.source) || 0) + 1);
      deg.set(e.target, (deg.get(e.target) || 0) + 1);
    }
    // Orphans are nodes without any visible link; tag nodes left without a note always go.
    nodes = nodes.filter((n) => (deg.get(n.id) || 0) > 0 || (!n.virtual && S.orphans));
    nodes.forEach((n, i) => {
      n.index = i;
      n.vdeg = deg.get(n.id) || 0;
      n.r = this.radius(n.vdeg);
      n.gravity = n.vdeg === 0 ? 1.6 : 1; // orphans stay gathered in a ring near the main graph
    });
    // Place newcomers next to a neighbour that already has a position.
    const byId = new Map(nodes.map((n) => [n.id, n]));
    this.links = edges.map((e) => ({ source: byId.get(e.source), target: byId.get(e.target), kind: e.kind }));
    for (const l of this.links) {
      for (const [a, b] of [[l.source, l.target], [l.target, l.source]]) {
        if (!Number.isFinite(a.x) && Number.isFinite(b.x)) {
          a.x = b.x + (Math.random() - 0.5) * 30; a.y = b.y + (Math.random() - 0.5) * 30;
        }
      }
    }
    this.neighbors = new Map(nodes.map((n) => [n, new Set()]));
    for (const l of this.links) {
      this.neighbors.get(l.source).add(l.target);
      this.neighbors.get(l.target).add(l.source);
    }
    this.visible = nodes;
    this.applyForces();
    this.sim.setData(nodes, this.links);
    this.sim.reheat(heat);
    this.colorize();
    this.status();
    this.schedule();
  }

  radius(deg) { return (2.4 + Math.sqrt(deg) * 0.95) * this.settings.nodeSize; }

  colorize() {
    const groups = (this.settings.groups || []).map((g) => ({ match: makeMatcher(g.query), color: g.color, query: g.query }))
      .filter((g) => g.match);
    // Without user groups, tint entries by GraphNode.group (the folder below the root),
    // largest groups first in the palette; the rest stay grey.
    const byGroup = new Map();
    if (!groups.length) {
      const counts = new Map();
      for (const n of this.visible) if (!n.virtual && n.group) counts.set(n.group, (counts.get(n.group) || 0) + 1);
      [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, GROUP_PALETTE.length - 1)
        .forEach(([g], i) => byGroup.set(g, GROUP_PALETTE[i]));
    }
    for (const n of this.visible) {
      let color = n.virtual ? COLORS.tag : COLORS.node;
      if (!n.virtual) {
        if (groups.length) { for (const g of groups) if (g.match(n)) { color = g.color; break; } }
        else if (byGroup.has(n.group)) color = byGroup.get(n.group);
      }
      n.color = color;
    }
    const legend = groups.length
      ? groups.map((g) => ({ label: g.query, color: g.color }))
      : [...byGroup.entries()].map(([label, color]) => ({ label, color }));
    if (this.visible.some((n) => n.virtual)) legend.push({ label: "#étiquettes", color: COLORS.tag });
    this.onLegend(this.settings.legend ? legend : []);
  }

  applyForces() {
    const S = this.settings;
    Object.assign(this.sim.params, { center: S.center, repel: S.repel, link: S.link, distance: S.distance });
  }

  /** Change settings; returns true when the data must be fetched again (tags as nodes). */
  update(partial) {
    const before = this.settings;
    this.settings = { ...before, ...partial };
    const keys = Object.keys(partial);
    const refetch = keys.includes("tags") && partial.tags !== before.tags;
    if (keys.some((k) => ["search", "attachments", "orphans", "existingOnly", "tags"].includes(k))) {
      this.rebuild(0.3);
    } else if (keys.includes("nodeSize")) {
      for (const n of this.visible) n.r = this.radius(n.vdeg);
      this.sim.reheat(0.1);
    } else if (keys.some((k) => ["center", "repel", "link", "distance"].includes(k))) {
      this.applyForces();
      this.sim.reheat(0.35);
    }
    if (keys.includes("groups") || keys.includes("legend")) this.colorize();
    this.schedule();
    return refetch;
  }

  status() {
    const n = this.visible.length, e = this.links.length;
    this.onStatus(`${n} nœud${n > 1 ? "s" : ""}, ${e} lien${e > 1 ? "s" : ""}` +
      (this.data.unresolved ? `, ${this.data.unresolved} lien${this.data.unresolved > 1 ? "s" : ""} sans cible` : "") +
      (this.selection.size ? `, ${this.selection.size} sélectionné${this.selection.size > 1 ? "s" : ""} (Maj+clic)` : ""));
  }

  // ------------------------------------------------------------- animate
  /** Replay the growth of the archive: nodes appear in date order. */
  animate() {
    if (this.anim) { this.stopAnimation(); return; }
    const order = [...this.visible].sort((a, b) => nodeTime(a) - nodeTime(b));
    if (!order.length) return;
    for (const n of order) { n.x = NaN; n.y = NaN; n.vx = 0; n.vy = 0; }
    this.anim = { order, start: performance.now(), duration: Math.min(16000, 4000 + order.length * 12) };
    this.autoFit = true;
    this.schedule();
  }

  stopAnimation() {
    if (!this.anim) return;
    this.anim = null;
    this.rebuild(0.3);
    this.onStatus("");
    this.status();
  }

  stepAnimation() {
    const a = this.anim;
    const progress = Math.min(1, (performance.now() - a.start) / a.duration);
    const count = Math.max(1, Math.round(a.order.length * progress));
    if (count === a.count && progress < 1) return;
    a.count = count;
    const subset = new Set(a.order.slice(0, count).map((n) => n.id));
    this.rebuild(0.25, subset);
    const last = a.order[Math.max(0, count - 1)];
    const when = new Date(nodeTime(last));
    this.onStatus(`Animation : ${when.toLocaleDateString("fr-FR", { year: "numeric", month: "long" })}, ${count} notes`);
    if (count >= a.order.length) { this.anim = null; this.status(); }
  }

  // ----------------------------------------------------------- viewport
  resize() {
    if (this.autoFit) this.sim.reheat(0.02);
    const rect = this.canvas.getBoundingClientRect();
    this.dpr = window.devicePixelRatio || 1;
    this.width = Math.max(1, rect.width); this.height = Math.max(1, rect.height);
    this.canvas.width = Math.round(this.width * this.dpr);
    this.canvas.height = Math.round(this.height * this.dpr);
    this.schedule();
  }

  toWorld(sx, sy) { return { x: (sx - this.width / 2 - this.t.x) / this.t.k, y: (sy - this.height / 2 - this.t.y) / this.t.k }; }

  zoomAt(sx, sy, factor) {
    const before = this.toWorld(sx, sy);
    this.t.k = Math.min(10, Math.max(0.04, this.t.k * factor));
    this.t.x = sx - this.width / 2 - before.x * this.t.k;
    this.t.y = sy - this.height / 2 - before.y * this.t.k;
    this.autoFit = false;
    this.schedule();
  }

  /** Frame the bulk of the graph: linked nodes within the 92nd percentile of distance
   * from their centroid (far outliers and the orphan ring ignored), centred in the area
   * the floating panel leaves. */
  fitStep(immediate = false) {
    const all = this.visible.filter((n) => Number.isFinite(n.x));
    if (!all.length) return;
    // Frame the linked nodes: the orphan ring around them may run past the edges.
    const linked = all.filter((n) => n.vdeg > 0);
    const placed = linked.length >= all.length * 0.5 ? linked : all;
    let cx = 0, cy = 0;
    for (const n of placed) { cx += n.x; cy += n.y; }
    cx /= placed.length; cy /= placed.length;
    const dist = placed.map((n) => Math.hypot(n.x - cx, n.y - cy)).sort((a, b) => a - b);
    const limit = dist[Math.min(dist.length - 1, Math.floor(dist.length * 0.92))] * 1.05 + 1;
    let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    for (const n of placed) {
      if (Math.hypot(n.x - cx, n.y - cy) > limit) continue;
      x0 = Math.min(x0, n.x - n.r); x1 = Math.max(x1, n.x + n.r);
      y0 = Math.min(y0, n.y - n.r); y1 = Math.max(y1, n.y + n.r);
    }
    const right = Math.max(0, Math.min(this.width * 0.45, (this.insets() || {}).right || 0));
    const freeW = this.width - right, pad = 28;
    const k = Math.min(2.5, Math.max(0.04, Math.min((freeW - pad * 2) / Math.max(1, x1 - x0), (this.height - pad * 2) / Math.max(1, y1 - y0))));
    const tx = freeW / 2 - this.width / 2 - ((x0 + x1) / 2) * k, ty = -((y0 + y1) / 2) * k;
    const f = immediate ? 1 : 0.12;
    this.t.k += (k - this.t.k) * f; this.t.x += (tx - this.t.x) * f; this.t.y += (ty - this.t.y) * f;
  }

  fit() { this.autoFit = true; this.fitStep(true); this.sim.reheat(0.05); this.schedule(); }

  focusNode(id) {
    const n = this.visible.find((v) => v.id === id);
    if (!n || !Number.isFinite(n.x)) return false;
    this.autoFit = false;
    const k = Math.max(this.t.k, 1.2);
    this.t = { k, x: -n.x * k, y: -n.y * k };
    this.hover = n;
    this.schedule();
    return true;
  }

  // ---------------------------------------------------------------- loop
  schedule() {
    if (this.raf === null && !document.hidden) this.raf = requestAnimationFrame(this.frame);
  }

  frame() {
    this.raf = null;
    if (document.hidden) return;
    let busy = false;
    if (this.anim) { this.stepAnimation(); busy = true; }
    if (this.sim.running) { this.sim.tick(); busy = true; }
    if (this.autoFit && busy) this.fitStep();
    this.draw();
    if (busy) this.schedule();
  }

  // ---------------------------------------------------------------- draw
  draw() {
    const ctx = this.ctx, S = this.settings, k = this.t.k;
    ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
    ctx.fillStyle = COLORS.bg;
    ctx.fillRect(0, 0, this.width, this.height);
    if (!this.visible.length) return;
    ctx.translate(this.width / 2 + this.t.x, this.height / 2 + this.t.y);
    ctx.scale(k, k);
    const view = { x0: (-this.width / 2 - this.t.x) / k, y0: (-this.height / 2 - this.t.y) / k };
    view.x1 = view.x0 + this.width / k; view.y1 = view.y0 + this.height / k;
    const onScreen = (n, m = 0) => n.x + n.r + m > view.x0 && n.x - n.r - m < view.x1 && n.y + n.r + m > view.y0 && n.y - n.r - m < view.y1;

    const hover = this.hover;
    const near = hover ? this.neighbors.get(hover) || new Set() : null;
    const lw = Math.max(0.55 * S.linkThickness, 0.5 / k) ;

    // Edges.
    ctx.lineWidth = lw;
    ctx.strokeStyle = COLORS.edge;
    ctx.globalAlpha = hover ? 0.25 : 1;
    ctx.beginPath();
    for (const l of this.links) {
      if (hover && (l.source === hover || l.target === hover)) continue;
      ctx.moveTo(l.source.x, l.source.y); ctx.lineTo(l.target.x, l.target.y);
    }
    ctx.stroke();
    const arrowSize = Math.max(2.4, 2.6 * lw);
    if (S.arrows && arrowSize * k > 1.6) {
      ctx.fillStyle = COLORS.edge;
      ctx.beginPath();
      for (const l of this.links) {
        if (l.kind === "tag" || (hover && (l.source === hover || l.target === hover))) continue;
        this.arrowPath(ctx, l, arrowSize);
      }
      ctx.fill();
    }
    if (hover) {
      ctx.globalAlpha = 1;
      ctx.strokeStyle = COLORS.edgeHi;
      ctx.lineWidth = lw * 1.6;
      ctx.beginPath();
      for (const l of this.links) {
        if (l.source !== hover && l.target !== hover) continue;
        ctx.moveTo(l.source.x, l.source.y); ctx.lineTo(l.target.x, l.target.y);
      }
      ctx.stroke();
      if (S.arrows) {
        ctx.fillStyle = COLORS.edgeHi;
        ctx.beginPath();
        for (const l of this.links) if ((l.source === hover || l.target === hover) && l.kind !== "tag") this.arrowPath(ctx, l, arrowSize * 1.3);
        ctx.fill();
      }
    }

    // Nodes.
    for (const n of this.visible) {
      if (!onScreen(n)) continue;
      const lit = !hover || n === hover || near.has(n);
      ctx.globalAlpha = lit ? 1 : 0.18;
      ctx.fillStyle = n === hover ? COLORS.nodeHi : n.color;
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      ctx.fill();
      if (this.selection.has(n.id)) {
        ctx.strokeStyle = COLORS.select;
        ctx.lineWidth = Math.max(1.5, 2 / k);
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r + Math.max(2, 3 / k), 0, Math.PI * 2);
        ctx.stroke();
      }
    }

    // Labels: fade in with zoom; the hovered node and its neighbours always show theirs.
    // The fitted view of a few hundred notes sits well below 1.6: no labels there.
    const threshold = Math.pow(2, S.textFade) * 1.6;
    const fade = Math.max(0, Math.min(1, (k - threshold) / (threshold * 0.5)));
    const fontPx = 10 * Math.pow(k, 0.25);
    const worldFont = fontPx / k;
    ctx.font = `${worldFont}px system-ui, -apple-system, "Segoe UI", Roboto, sans-serif`;
    ctx.textAlign = "center";
    ctx.textBaseline = "top";
    for (const n of this.visible) {
      const special = hover && (n === hover || near.has(n));
      const alpha = hover ? (special ? 1 : fade * 0.12) : fade * 0.85;
      if (alpha < 0.03 || !onScreen(n, 120 / k)) continue;
      ctx.globalAlpha = alpha;
      ctx.fillStyle = n === hover ? "#ffffff" : COLORS.label;
      const text = truncate(n.label, n === hover ? 60 : LABEL_MAX);
      ctx.fillText(text, n.x, n.y + n.r + 3 / k);
    }
    ctx.globalAlpha = 1;
  }

  arrowPath(ctx, l, size) {
    const s = l.source, t = l.target;
    const dx = t.x - s.x, dy = t.y - s.y;
    const d = Math.hypot(dx, dy);
    if (d < t.r + size * 2) return;
    const ux = dx / d, uy = dy / d;
    const tipX = t.x - ux * (t.r + 0.5), tipY = t.y - uy * (t.r + 0.5);
    const bx = tipX - ux * size * 1.8, by = tipY - uy * size * 1.8;
    ctx.moveTo(tipX, tipY);
    ctx.lineTo(bx - uy * size * 0.8, by + ux * size * 0.8);
    ctx.lineTo(bx + uy * size * 0.8, by - ux * size * 0.8);
    ctx.closePath();
  }

  // ---------------------------------------------------------- interaction
  nodeAt(sx, sy) {
    const p = this.toWorld(sx, sy);
    let best = null, bestD = Infinity;
    const slack = 4 / this.t.k;
    for (const n of this.visible) {
      const d = Math.hypot(n.x - p.x, n.y - p.y);
      if (d < n.r + slack && d < bestD) { best = n; bestD = d; }
    }
    return best;
  }

  bind() {
    const c = this.canvas;
    new ResizeObserver(() => this.resize()).observe(c);
    document.addEventListener("visibilitychange", () => { if (!document.hidden) this.schedule(); });
    const pos = (e) => { const r = c.getBoundingClientRect(); return { x: e.clientX - r.left, y: e.clientY - r.top }; };

    c.addEventListener("pointerdown", (e) => {
      if (e.button !== 0) return;
      const p = pos(e);
      const node = this.nodeAt(p.x, p.y);
      c.setPointerCapture(e.pointerId);
      this.pointer = { id: e.pointerId, start: p, last: p, node, moved: false, shift: e.shiftKey || e.ctrlKey || e.metaKey };
      if (!node) c.classList.add("dragging");
    });
    c.addEventListener("pointermove", (e) => {
      const p = pos(e);
      const ptr = this.pointer;
      if (ptr && ptr.id === e.pointerId) {
        if (!ptr.moved && Math.hypot(p.x - ptr.start.x, p.y - ptr.start.y) > 3) ptr.moved = true;
        if (ptr.moved) {
          if (ptr.node) {
            const w = this.toWorld(p.x, p.y);
            ptr.node.fx = w.x; ptr.node.fy = w.y;
            this.sim.alphaTarget = 0.25;
            this.sim.reheat(0.25);
            this.hover = ptr.node;
          } else {
            this.t.x += p.x - ptr.last.x; this.t.y += p.y - ptr.last.y;
            this.autoFit = false;
          }
          this.schedule();
        }
        ptr.last = p;
        return;
      }
      const hit = this.nodeAt(p.x, p.y);
      if (hit !== this.hover) {
        this.hover = hit;
        c.classList.toggle("on-node", !!hit);
        c.title = hit ? hit.label : "";
        this.schedule();
      }
    });
    const end = (e) => {
      const ptr = this.pointer;
      if (!ptr || ptr.id !== e.pointerId) return;
      this.pointer = null;
      c.classList.remove("dragging");
      if (ptr.node) {
        if (ptr.moved) {
          ptr.node.fx = null; ptr.node.fy = null;
          this.sim.alphaTarget = 0;
        } else if (e.type === "pointerup") {
          if (ptr.shift) this.toggleSelection(ptr.node.id);
          else if (!ptr.node.virtual) this.onOpen(ptr.node.id);
        }
      }
      this.schedule();
    };
    c.addEventListener("pointerup", end);
    c.addEventListener("pointercancel", end);
    c.addEventListener("pointerleave", () => { if (!this.pointer && this.hover) { this.hover = null; this.schedule(); } });
    c.addEventListener("wheel", (e) => {
      e.preventDefault();
      const p = pos(e);
      const delta = e.deltaMode === 1 ? e.deltaY * 16 : e.deltaY;
      this.zoomAt(p.x, p.y, Math.exp(-delta * 0.0016));
    }, { passive: false });
    c.addEventListener("keydown", (e) => {
      const step = 60;
      const keys = { ArrowLeft: [step, 0], ArrowRight: [-step, 0], ArrowUp: [0, step], ArrowDown: [0, -step] };
      if (keys[e.key]) { this.t.x += keys[e.key][0]; this.t.y += keys[e.key][1]; this.autoFit = false; this.schedule(); e.preventDefault(); }
      else if (e.key === "+" || e.key === "=") { this.zoomAt(this.width / 2, this.height / 2, 1.25); e.preventDefault(); }
      else if (e.key === "-") { this.zoomAt(this.width / 2, this.height / 2, 0.8); e.preventDefault(); }
      else if (e.key === "0") { this.fit(); e.preventDefault(); }
    });
  }

  toggleSelection(id) {
    if (this.selection.has(id)) this.selection.delete(id); else this.selection.add(id);
    this.onSelection(this.selection);
    this.status();
    this.schedule();
  }

  clearSelection() { this.selection.clear(); this.onSelection(this.selection); this.status(); this.schedule(); }
}
