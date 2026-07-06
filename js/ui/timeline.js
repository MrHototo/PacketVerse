/**
 * timeline.js
 * Canvas-based traffic timeline with click-drag range selection.
 * Dispatches a 'timeline:range' CustomEvent on the container element
 * whenever the selection changes so main.js can filter the 3D scene.
 */
export class Timeline {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d');
    this.buckets = [];
    this.range = null; // { start, end } in seconds (absolute epoch)
    this.fullRange = { start: 0, end: 1 };
    this.dragStartX = null;

    canvas.addEventListener('mousedown', (e) => this._onDown(e));
    window.addEventListener('mousemove', (e) => this._onMove(e));
    window.addEventListener('mouseup', () => this._onUp());
    window.addEventListener('resize', () => this.draw());
  }

  setData(packets, timeRange, bucketCount = 120) {
    this.fullRange = timeRange;
    this.range = { ...timeRange };
    const span = Math.max(1e-6, timeRange.end - timeRange.start);
    const buckets = new Array(bucketCount).fill(0).map(() => ({ count: 0, byProtocol: {} }));
    for (const p of packets) {
      const idx = Math.min(
        bucketCount - 1,
        Math.floor(((p.ts - timeRange.start) / span) * bucketCount)
      );
      buckets[idx].count += 1;
      const proto = p.frame.layers.l7?.type || p.frame.layers.l4?.type || 'OTHER';
      buckets[idx].byProtocol[proto] = (buckets[idx].byProtocol[proto] || 0) + 1;
    }
    this.buckets = buckets;
    this.draw();
  }

  _xToTime(x) {
    const rect = this.canvas.getBoundingClientRect();
    const frac = Math.min(1, Math.max(0, (x - rect.left) / rect.width));
    return this.fullRange.start + frac * (this.fullRange.end - this.fullRange.start);
  }

  _onDown(e) {
    this.dragStartX = e.clientX;
    this._dragging = true;
  }

  _onMove(e) {
    if (!this._dragging) return;
    const t1 = this._xToTime(this.dragStartX);
    const t2 = this._xToTime(e.clientX);
    this.range = { start: Math.min(t1, t2), end: Math.max(t1, t2) };
    this.draw();
  }

  _onUp() {
    if (!this._dragging) return;
    this._dragging = false;
    if (Math.abs(this.range.end - this.range.start) < 0.001) {
      this.range = { ...this.fullRange };
    }
    this.canvas.dispatchEvent(new CustomEvent('timeline:range', { detail: this.range }));
  }

  resetRange() {
    this.range = { ...this.fullRange };
    this.draw();
    this.canvas.dispatchEvent(new CustomEvent('timeline:range', { detail: this.range }));
  }

  draw() {
    const canvas = this.canvas;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * devicePixelRatio;
    canvas.height = rect.height * devicePixelRatio;
    const ctx = this.ctx;
    ctx.setTransform(devicePixelRatio, 0, 0, devicePixelRatio, 0, 0);
    ctx.clearRect(0, 0, rect.width, rect.height);

    if (!this.buckets.length) return;
    const max = Math.max(1, ...this.buckets.map((b) => b.count));
    const barWidth = rect.width / this.buckets.length;

    this.buckets.forEach((b, i) => {
      const h = (b.count / max) * (rect.height - 6);
      ctx.fillStyle = '#4d9de0';
      ctx.fillRect(i * barWidth, rect.height - h, Math.max(1, barWidth - 1), h);
    });

    if (this.range && this.fullRange.end > this.fullRange.start) {
      const span = this.fullRange.end - this.fullRange.start;
      const x1 = ((this.range.start - this.fullRange.start) / span) * rect.width;
      const x2 = ((this.range.end - this.fullRange.start) / span) * rect.width;
      ctx.fillStyle = 'rgba(155, 89, 182, 0.18)';
      ctx.fillRect(x1, 0, x2 - x1, rect.height);
      ctx.strokeStyle = '#9b59b6';
      ctx.strokeRect(x1, 0, x2 - x1, rect.height);
    }
  }
}
