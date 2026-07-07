/**
 * scene2d.js
 * Canvas2D renderer for the "2D Graph View" — a readability-first
 * alternative to the 3D scene, NOT a flattened copy of it. Uses the
 * deterministic radial/ring layout (layout2d.js) instead of physics, so it
 * never oscillates and lays out instantly. Implements the same public API
 * as Scene3D (setGraph, setPrimaryFocus/clearPrimaryFocus, flyToNode/
 * centerOn, fitToVisible, resetCamera, zoomIn/zoomOut, setLabelsVisible,
 * setParticlesEnabled, resize) plus onSelect/onDoubleSelect/onHover
 * callbacks, so main.js can drive either renderer identically.
 */
import { colorForProtocol } from '../utils/colors.js';
import { computeRadialLayout } from './layout2d.js';
import { maxOf } from '../utils/mathSafe.js';

const DIM_ALPHA = 0.12;
const ACTIVE_ALPHA = 0.95;

export class Scene2D {
  constructor(container, { onSelect, onHover, onDoubleSelect, onError } = {}) {
    this.container = container;
    this.onSelect = onSelect || (() => {});
    this.onHover = onHover || (() => {});
    this.onDoubleSelect = onDoubleSelect || (() => {});
    this.onError = onError || (() => {});
    this._renderFailed = false;
    this.showLabels = true;
    this.particlesEnabled = true;
    this.primaryFocus = null;

    this.canvas = document.createElement('canvas');
    this.canvas.style.width = '100%';
    this.canvas.style.height = '100%';
    this.canvas.style.display = 'block';
    container.appendChild(this.canvas);
    this.ctx = this.canvas.getContext('2d');

    this.hosts = new Map();
    this.flows = new Map();
    this.positions = new Map(); // hostId -> {x,y} in world space
    this.adjacency = new Map();

    // Camera: simple 2D pan/zoom (world -> screen: screen = (world - cam) * zoom + center)
    this.cam = { x: 0, y: 0, zoom: 1 };
    this._flight = null;
    this._t = 0;
    this._particleT = 0;

    this._dragging = false;
    this._dragMoved = false;
    this._lastPointer = { x: 0, y: 0 };
    this._clickTimer = null;
    this._hoverNode = null;

    this._bindEvents();
    this.resize();
    this._animate();
    if (typeof ResizeObserver !== 'undefined') {
      this._resizeObserver = new ResizeObserver(() => this.resize());
      this._resizeObserver.observe(this.container);
    }
  }

  _bindEvents() {
    window.addEventListener('resize', () => this.resize());
    const el = this.canvas;
    el.addEventListener('pointerdown', (e) => {
      this._dragging = true;
      this._dragMoved = false;
      this._lastPointer = { x: e.clientX, y: e.clientY };
    });
    window.addEventListener('pointermove', (e) => {
      if (this._dragging) {
        const dx = e.clientX - this._lastPointer.x;
        const dy = e.clientY - this._lastPointer.y;
        if (Math.hypot(dx, dy) > 2) this._dragMoved = true;
        this.cam.x -= dx / this.cam.zoom;
        this.cam.y -= dy / this.cam.zoom;
        this._lastPointer = { x: e.clientX, y: e.clientY };
        this._flight = null;
      }
      this._onHoverMove(e);
    });
    window.addEventListener('pointerup', () => { this._dragging = false; });
    el.addEventListener('wheel', (e) => {
      e.preventDefault();
      const rect = el.getBoundingClientRect();
      const px = e.clientX - rect.left, py = e.clientY - rect.top;
      const worldBefore = this._screenToWorld(px, py);
      const factor = Math.exp(-e.deltaY * 0.001);
      this.cam.zoom = clamp(this.cam.zoom * factor, 0.08, 6);
      // Zoom toward the pointer (or, while a node is selected, this still
      // keeps the pointer-under-cursor point fixed — combined with the
      // continuous "keep selection centered" behavior below, wheel-zooming
      // always effectively focuses on whatever is currently selected).
      const worldAfter = this._screenToWorld(px, py);
      this.cam.x += worldBefore.x - worldAfter.x;
      this.cam.y += worldBefore.y - worldAfter.y;
    }, { passive: false });
    el.addEventListener('click', (e) => {
      if (this._dragMoved) return;
      if (this._clickTimer) { clearTimeout(this._clickTimer); this._clickTimer = null; }
      const hit = this._pick(e);
      this._clickTimer = setTimeout(() => { this.onSelect(hit ? hit.userData : null); this._clickTimer = null; }, 220);
    });
    el.addEventListener('dblclick', (e) => {
      if (this._clickTimer) { clearTimeout(this._clickTimer); this._clickTimer = null; }
      const hit = this._pick(e);
      if (hit) this.onDoubleSelect(hit.userData);
    });
  }

  resize() {
    const w = Math.max(1, this.container.clientWidth);
    const h = Math.max(1, this.container.clientHeight);
    const dpr = Math.min(devicePixelRatio || 1, 2);
    this.canvas.width = w * dpr;
    this.canvas.height = h * dpr;
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    this.w = w; this.h = h;
  }

  setLabelsVisible(v) { this.showLabels = v; }
  setParticlesEnabled(v) { this.particlesEnabled = v; }

  zoomBy(factor) { this.cam.zoom = clamp(this.cam.zoom * factor, 0.08, 6); }
  zoomIn() { this.zoomBy(1.28); }
  zoomOut() { this.zoomBy(0.78); }

  setGraph(hosts, flows) {
    this.hosts = hosts;
    this.flows = flows;
    this.positions = computeRadialLayout(hosts, flows);
    this.adjacency = new Map();
    for (const id of hosts.keys()) this.adjacency.set(id, new Set());
    for (const flow of flows.values()) {
      if (!hosts.has(flow.hostA) || !hosts.has(flow.hostB)) continue;
      this.adjacency.get(flow.hostA)?.add(flow.key);
      this.adjacency.get(flow.hostB)?.add(flow.key);
    }
  }

  setPrimaryFocus(kind, id) {
    this.primaryFocus = kind ? { kind, id } : null;
  }
  clearPrimaryFocus() { this.setPrimaryFocus(null, null); }

  /** Smoothly pans/zooms so the given host is centered — 2D equivalent of flyToNode. */
  flyToNode(id, duration = 0.7) {
    const p = id ? this.positions.get(id) : this._centroid();
    if (!p) return this.resetCamera(true);
    this._startFlight(p.x, p.y, Math.max(this.cam.zoom, 1.1), duration);
  }
  centerOn(id, duration = 0.7) { this.flyToNode(id, duration); }

  /** 2D equivalent of Scene3D's centerOnEdge -- pans/zooms to a flow's
   * midpoint, or returns false if that edge isn't currently rendered
   * (e.g. collapsed inside a cluster) so the caller can fall back to a
   * host-level focus instead of silently doing nothing. */
  centerOnEdge(key, duration = 0.7) {
    const f = this.flows.get(key);
    if (!f) return false;
    const a = this.positions.get(f.hostA);
    const b = this.positions.get(f.hostB);
    if (!a || !b) return false;
    const mid = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
    this._startFlight(mid.x, mid.y, Math.max(this.cam.zoom, 1.1), duration);
    return true;
  }

  fitToVisible(animated = true) {
    if (!this.positions.size) return this.resetCamera(animated);
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    for (const id of this.hosts.keys()) {
      const p = this.positions.get(id);
      if (!p) continue;
      minX = Math.min(minX, p.x); maxX = Math.max(maxX, p.x);
      minY = Math.min(minY, p.y); maxY = Math.max(maxY, p.y);
    }
    if (!Number.isFinite(minX)) return this.resetCamera(animated);
    const cx = (minX + maxX) / 2, cy = (minY + maxY) / 2;
    const spanX = Math.max(80, maxX - minX + 160), spanY = Math.max(80, maxY - minY + 160);
    const zoom = clamp(Math.min(this.w / spanX, this.h / spanY), 0.08, 3);
    this._startFlight(cx, cy, zoom, animated ? 0.7 : 0);
  }

  resetCamera(animated = false) { this.fitToVisible(animated); }

  _startFlight(x, y, zoom, duration) {
    if (duration <= 0) { this.cam.x = x; this.cam.y = y; this.cam.zoom = zoom; this._flight = null; return; }
    this._flight = { t: 0, duration, fromX: this.cam.x, fromY: this.cam.y, fromZoom: this.cam.zoom, toX: x, toY: y, toZoom: zoom };
  }

  _centroid() {
    let n = 0, x = 0, y = 0;
    for (const p of this.positions.values()) { x += p.x; y += p.y; n++; }
    return n ? { x: x / n, y: y / n } : { x: 0, y: 0 };
  }

  _screenToWorld(sx, sy) {
    return {
      x: (sx - this.w / 2) / this.cam.zoom + this.cam.x,
      y: (sy - this.h / 2) / this.cam.zoom + this.cam.y,
    };
  }
  _worldToScreen(wx, wy) {
    return {
      x: (wx - this.cam.x) * this.cam.zoom + this.w / 2,
      y: (wy - this.cam.y) * this.cam.zoom + this.h / 2,
    };
  }

  _nodeRadius(host) {
    const maxBytes = Math.max(1, maxOf([...this.hosts.values()].map((h) => h.bytes)));
    const base = 6 + 16 * Math.cbrt((host.bytes || 0) / maxBytes);
    return host.isCluster ? base * 1.3 : base;
  }

  _pick(e) {
    const rect = this.canvas.getBoundingClientRect();
    const world = this._screenToWorld(e.clientX - rect.left, e.clientY - rect.top);
    let best = null, bestDist = Infinity;
    for (const [id, host] of this.hosts) {
      const p = this.positions.get(id);
      if (!p) continue;
      const r = this._nodeRadius(host) + 4;
      const d = Math.hypot(world.x - p.x, world.y - p.y);
      if (d <= r && d < bestDist) { bestDist = d; best = { userData: { kind: host.isCluster ? 'cluster' : 'host', id, host } }; }
    }
    if (best) return best;
    const pxThresh = 6 / this.cam.zoom;
    for (const flow of this.flows.values()) {
      const pa = this.positions.get(flow.hostA), pb = this.positions.get(flow.hostB);
      if (!pa || !pb) continue;
      const d = pointToSegmentDist(world.x, world.y, pa.x, pa.y, pb.x, pb.y);
      if (d <= pxThresh && d < bestDist) { bestDist = d; best = { userData: { kind: 'flow', key: flow.key, flow } }; }
    }
    return best;
  }

  _onHoverMove(e) {
    const hit = this._pick(e);
    this.canvas.style.cursor = hit ? 'pointer' : this._dragging ? 'grabbing' : 'grab';
    this.onHover(hit ? hit.userData : null, e);
  }

  _animate() {
    requestAnimationFrame(() => this._animate());
    if (this._renderFailed) return;
    try {
      this._tick();
    } catch (err) {
      this._renderFailed = true;
      console.error('[PacketVerse] 2D render loop failed:', err);
      this.onError(err, '2d');
    }
  }

  _tick() {
    const dt = 0.016;
    this._particleT = (this._particleT + dt * 0.35) % 1;

    if (this._flight) {
      const f = this._flight;
      f.t = Math.min(1, f.t + dt / f.duration);
      const e = easeInOutCubic(f.t);
      this.cam.x = lerp(f.fromX, f.toX, e);
      this.cam.y = lerp(f.fromY, f.toY, e);
      this.cam.zoom = lerp(f.fromZoom, f.toZoom, e);
      if (f.t >= 1) this._flight = null;
    } else if (this.primaryFocus?.kind === 'host' && !this._dragging) {
      // "Zooming always focuses on the selected object": while a node is
      // selected and the user isn't actively dragging, gently keep the
      // camera's pan target locked onto it (e.g. if it were ever repositioned).
      const p = this.positions.get(this.primaryFocus.id);
      if (p) { this.cam.x = lerp(this.cam.x, p.x, 0.08); this.cam.y = lerp(this.cam.y, p.y, 0.08); }
    }

    this._render();
  }

  _render() {
    const ctx = this.ctx;
    ctx.clearRect(0, 0, this.w, this.h);
    ctx.fillStyle = '#090d13';
    ctx.fillRect(0, 0, this.w, this.h);

    let focusHostIds = null, focusFlowKeys = null;
    if (this.primaryFocus?.kind === 'host') {
      focusFlowKeys = this.adjacency.get(this.primaryFocus.id) || new Set();
      focusHostIds = new Set([this.primaryFocus.id]);
    } else if (this.primaryFocus?.kind === 'flow') {
      const f = this.flows.get(this.primaryFocus.id);
      focusFlowKeys = new Set(f ? [this.primaryFocus.id] : []);
      focusHostIds = new Set(f ? [f.hostA, f.hostB] : []);
    }

    const maxFlowBytes = Math.max(1, maxOf([...this.flows.values()].map((f) => f.bytes)));
    for (const flow of this.flows.values()) {
      const pa = this.positions.get(flow.hostA), pb = this.positions.get(flow.hostB);
      if (!pa || !pb) continue;
      const a = this._worldToScreen(pa.x, pa.y), b = this._worldToScreen(pb.x, pb.y);
      const isPrimary = !focusFlowKeys || focusFlowKeys.has(flow.key);
      const color = colorForProtocol(flow.appProtocol || flow.protocol);
      const width = Math.max(1, (1.2 + 4 * Math.cbrt(flow.bytes / maxFlowBytes)) * Math.min(1.4, this.cam.zoom));
      ctx.globalAlpha = isPrimary ? ACTIVE_ALPHA : DIM_ALPHA;
      ctx.strokeStyle = hexToCss(color);
      ctx.lineWidth = width;
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      ctx.stroke();

      if (this.particlesEnabled && isPrimary) {
        const t = this._particleT;
        ctx.globalAlpha = 0.95;
        ctx.fillStyle = hexToCss(color);
        ctx.beginPath();
        ctx.arc(lerp(a.x, b.x, t), lerp(a.y, b.y, t), Math.max(2, width * 0.9), 0, Math.PI * 2);
        ctx.fill();
      }
    }
    ctx.globalAlpha = 1;

    for (const [id, host] of this.hosts) {
      const p = this.positions.get(id);
      if (!p) continue;
      const s = this._worldToScreen(p.x, p.y);
      const r = this._nodeRadius(host) * Math.min(1.6, Math.max(0.5, this.cam.zoom));
      const isPrimary = !focusHostIds || focusHostIds.has(id);
      const color = nodeColorFor(host);
      ctx.globalAlpha = isPrimary ? 1 : 0.25;

      if (isPrimary) {
        const grd = ctx.createRadialGradient(s.x, s.y, 0, s.x, s.y, r * 2.6);
        grd.addColorStop(0, hexToCss(color, 0.35));
        grd.addColorStop(1, hexToCss(color, 0));
        ctx.fillStyle = grd;
        ctx.beginPath(); ctx.arc(s.x, s.y, r * 2.6, 0, Math.PI * 2); ctx.fill();
      }

      ctx.beginPath();
      ctx.fillStyle = hexToCss(color);
      if (host.isCluster) {
        drawPolygon(ctx, s.x, s.y, r, 6);
        ctx.globalAlpha = isPrimary ? 0.85 : 0.2;
        ctx.strokeStyle = hexToCss(color);
        ctx.lineWidth = 2;
        ctx.stroke();
        ctx.globalAlpha = isPrimary ? 0.25 : 0.08;
        ctx.fill();
      } else {
        ctx.arc(s.x, s.y, r, 0, Math.PI * 2);
        ctx.fill();
      }
      ctx.globalAlpha = 1;

      if (this.showLabels && this.cam.zoom > 0.22) {
        const label = host.isCluster ? `\u25C8 ${shorten(id.replace('cluster:', ''))}` : shorten(id);
        ctx.font = '12px monospace';
        const tw = ctx.measureText(label).width;
        ctx.fillStyle = 'rgba(10,14,20,0.6)';
        ctx.fillRect(s.x - tw / 2 - 4, s.y + r + 4, tw + 8, 16);
        ctx.fillStyle = isPrimary ? '#e6ebf2' : 'rgba(230,235,242,0.4)';
        ctx.textAlign = 'center';
        ctx.fillText(label, s.x, s.y + r + 16);
        ctx.textAlign = 'left';
      }
    }
  }
}

function nodeColorFor(host) {
  if (host.isCluster) return 0xe9b44c;
  if (host.protocols?.has('Broadcast')) return 0x9e9e9e;
  if (host.protocols?.has('Multicast')) return 0xb0bec5;
  if (host.protocols?.has('DNS')) return 0x4caf50;
  if (host.protocols?.has('TLS')) return 0x9b59b6;
  if (host.protocols?.has('ARP') && host.protocols.size === 1) return 0x9e9e9e;
  return 0x4d9de0;
}
function shorten(id) { return id && id.length > 20 ? id.slice(0, 18) + '\u2026' : id; }
function hexToCss(hex, alpha = 1) {
  const r = (hex >> 16) & 255, g = (hex >> 8) & 255, b = hex & 255;
  return `rgba(${r},${g},${b},${alpha})`;
}
function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }
function lerp(a, b, t) { return a + (b - a) * t; }
function easeInOutCubic(t) { return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2; }
function pointToSegmentDist(px, py, ax, ay, bx, by) {
  const dx = bx - ax, dy = by - ay;
  const lenSq = dx * dx + dy * dy;
  let t = lenSq > 0 ? ((px - ax) * dx + (py - ay) * dy) / lenSq : 0;
  t = clamp(t, 0, 1);
  const cx = ax + t * dx, cy = ay + t * dy;
  return Math.hypot(px - cx, py - cy);
}
function drawPolygon(ctx, cx, cy, r, sides) {
  ctx.beginPath();
  for (let i = 0; i < sides; i++) {
    const a = (i / sides) * Math.PI * 2 - Math.PI / 2;
    const x = cx + Math.cos(a) * r, y = cy + Math.sin(a) * r;
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  }
  ctx.closePath();
}
