// Force simulation: Barnes-Hut repulsion on a quadtree, link springs, a centre force and
// collision. Same integration scheme as d3-force (alpha cooling, velocity decay), written
// from scratch so the page loads nothing from outside.

const THETA2 = 0.81; // Barnes-Hut accuracy (theta 0.9)

function buildQuadtree(nodes) {
  let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
  for (const n of nodes) {
    if (n.x < x0) x0 = n.x; if (n.x > x1) x1 = n.x;
    if (n.y < y0) y0 = n.y; if (n.y > y1) y1 = n.y;
  }
  const size = Math.max(x1 - x0, y1 - y0, 1) * 1.0001 + 1;
  const root = makeQuad(x0, y0, size);
  for (const n of nodes) insert(root, n, 0);
  accumulate(root);
  return root;
}

function makeQuad(x, y, size) {
  return { x, y, size, kids: null, pts: null, cx: 0, cy: 0, count: 0, rmax: 0 };
}

function insert(q, p, depth) {
  if (!q.kids) {
    if (!q.pts) { q.pts = [p]; return; }
    const o = q.pts[0];
    if (depth > 30 || (Math.abs(o.x - p.x) < 1e-6 && Math.abs(o.y - p.y) < 1e-6)) { q.pts.push(p); return; }
    const old = q.pts;
    q.pts = null;
    q.kids = [null, null, null, null];
    for (const o2 of old) insertChild(q, o2, depth);
  }
  insertChild(q, p, depth);
}

function insertChild(q, p, depth) {
  const half = q.size / 2;
  const right = p.x >= q.x + half ? 1 : 0;
  const bottom = p.y >= q.y + half ? 1 : 0;
  const i = right | (bottom << 1);
  if (!q.kids[i]) q.kids[i] = makeQuad(q.x + right * half, q.y + bottom * half, half);
  insert(q.kids[i], p, depth + 1);
}

function accumulate(q) {
  let cx = 0, cy = 0, count = 0, rmax = 0;
  if (q.pts) {
    for (const p of q.pts) { cx += p.x; cy += p.y; count++; if (p.r > rmax) rmax = p.r; }
  } else if (q.kids) {
    for (const k of q.kids) {
      if (!k) continue;
      accumulate(k);
      cx += k.cx * k.count; cy += k.cy * k.count; count += k.count;
      if (k.rmax > rmax) rmax = k.rmax;
    }
  }
  q.count = count;
  q.cx = count ? cx / count : 0;
  q.cy = count ? cy / count : 0;
  q.rmax = rmax;
}

function jiggle() { return (Math.random() - 0.5) * 1e-3; }

export class Simulation {
  constructor() {
    this.nodes = [];
    this.links = [];
    this.alpha = 1;
    this.alphaMin = 0.003;
    this.alphaDecay = 1 - Math.pow(this.alphaMin, 1 / 300);
    this.alphaTarget = 0;
    this.velocityDecay = 0.42;
    // Values as shown in the Forces panel.
    this.params = { center: 0.5, repel: 10, link: 1, distance: 250 };
    // How panel values map to forces (tuned on a few hundred notes).
    this.scale = { distance: 0.24, repel: 11, center: 0.09, distanceMax: 900 };
  }

  setData(nodes, links) {
    this.nodes = nodes;
    this.links = links;
    const count = new Map();
    for (const l of links) {
      count.set(l.source, (count.get(l.source) || 0) + 1);
      count.set(l.target, (count.get(l.target) || 0) + 1);
    }
    for (const l of links) {
      const a = count.get(l.source), b = count.get(l.target);
      l.bias = a / (a + b);
      l.strength = 1 / Math.min(a, b);
    }
    // New nodes without a position: phyllotaxis spiral, like d3.
    let k = 0;
    for (const n of nodes) {
      if (!Number.isFinite(n.x) || !Number.isFinite(n.y)) {
        const radius = 10 * Math.sqrt(0.5 + k), angle = k * Math.PI * (3 - Math.sqrt(5));
        n.x = radius * Math.cos(angle); n.y = radius * Math.sin(angle);
        k++;
      }
      if (!Number.isFinite(n.vx)) n.vx = 0;
      if (!Number.isFinite(n.vy)) n.vy = 0;
    }
  }

  reheat(alpha = 0.6) { this.alpha = Math.max(this.alpha, alpha); }
  get running() { return this.alpha >= this.alphaMin || this.alphaTarget > 0; }

  tick() {
    const nodes = this.nodes;
    if (!nodes.length) { this.alpha = 0; return; }
    this.alpha += (this.alphaTarget - this.alpha) * this.alphaDecay;
    const alpha = this.alpha;
    const P = this.params;
    const linkDistance = 10 + P.distance * (this.scale.distance);
    const linkStrength = P.link;
    const charge = -P.repel * this.scale.repel;
    const center = P.center * this.scale.center;

    // Links.
    for (const l of this.links) {
      const s = l.source, t = l.target;
      let dx = t.x + t.vx - s.x - s.vx || jiggle();
      let dy = t.y + t.vy - s.y - s.vy || jiggle();
      let d = Math.sqrt(dx * dx + dy * dy);
      d = (d - linkDistance) / d * alpha * linkStrength * l.strength;
      dx *= d; dy *= d;
      t.vx -= dx * l.bias; t.vy -= dy * l.bias;
      s.vx += dx * (1 - l.bias); s.vy += dy * (1 - l.bias);
    }

    // Repulsion and collision, both on the same quadtree.
    const tree = buildQuadtree(nodes);
    for (const n of nodes) {
      this._repel(tree, n, charge * alpha);
      this._collide(tree, n);
    }

    // Centre: pull towards the origin, stronger far away.
    for (const n of nodes) {
      const g = center * (n.gravity || 1) * alpha;
      n.vx -= n.x * g;
      n.vy -= n.y * g;
    }

    // Integrate.
    const keep = 1 - this.velocityDecay;
    for (const n of nodes) {
      if (n.fx != null) { n.x = n.fx; n.vx = 0; } else { n.vx *= keep; n.x += n.vx; }
      if (n.fy != null) { n.y = n.fy; n.vy = 0; } else { n.vy *= keep; n.y += n.vy; }
    }
  }

  _repel(root, n, strength) {
    const maxD = this.scale.distanceMax, max2 = maxD * maxD;
    const stack = [root];
    while (stack.length) {
      const q = stack.pop();
      if (!q.count) continue;
      let dx = q.cx - n.x, dy = q.cy - n.y;
      let d2 = dx * dx + dy * dy;
      if (d2 > max2 && (q.x > n.x + maxD || q.x + q.size < n.x - maxD || q.y > n.y + maxD || q.y + q.size < n.y - maxD)) continue;
      if (q.kids && (q.size * q.size) / THETA2 < d2) {
        if (d2 < 1) d2 = Math.sqrt(d2) || 1;
        const f = strength * q.count / d2;
        n.vx += dx * f; n.vy += dy * f;
        continue;
      }
      if (q.kids) { for (const k of q.kids) if (k) stack.push(k); continue; }
      for (const p of q.pts) {
        if (p === n) continue;
        dx = p.x - n.x || jiggle(); dy = p.y - n.y || jiggle();
        d2 = dx * dx + dy * dy;
        if (d2 > max2) continue;
        if (d2 < 1) d2 = Math.sqrt(d2) || 1;
        const f = strength / d2;
        n.vx += dx * f; n.vy += dy * f;
      }
    }
  }

  _collide(root, n) {
    const ri = n.r + 2;
    const xi = n.x + n.vx, yi = n.y + n.vy;
    const stack = [root];
    while (stack.length) {
      const q = stack.pop();
      if (!q.count) continue;
      const reach = ri + q.rmax + 2;
      if (q.x > xi + reach || q.x + q.size < xi - reach || q.y > yi + reach || q.y + q.size < yi - reach) continue;
      if (q.kids) { for (const k of q.kids) if (k) stack.push(k); continue; }
      for (const p of q.pts) {
        if (p.index <= n.index) continue;
        const rr = ri + p.r + 2;
        let dx = xi - p.x - p.vx, dy = yi - p.y - p.vy;
        let d2 = dx * dx + dy * dy;
        if (d2 < rr * rr) {
          if (dx === 0) { dx = jiggle(); d2 += dx * dx; }
          if (dy === 0) { dy = jiggle(); d2 += dy * dy; }
          const d = Math.sqrt(d2);
          const l = (rr - d) / d * 0.7;
          const share = (p.r * p.r) / (ri * ri + p.r * p.r);
          n.vx += dx * l * share; n.vy += dy * l * share;
          p.vx -= dx * l * (1 - share); p.vy -= dy * l * (1 - share);
        }
      }
    }
  }
}
