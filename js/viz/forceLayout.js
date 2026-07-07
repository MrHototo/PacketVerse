/**
 * forceLayout.js
 * Minimal, dependency-free 3D force-directed layout (repulsion + spring
 * attraction + light centering force). O(n^2) per tick, which is
 * intentionally fine for the "lightweight" scope of this project — hosts
 * are aggregated (not individual packets), so even busy captures typically
 * resolve to a few dozen–hundred nodes. See README for scaling notes.
 *
 * Convergence: the simulation carries a decaying "alpha" (energy) term,
 * the same mechanism d3-force uses. Alpha starts at 1 on every reheat and
 * multiplies by `alphaDecay` every tick; once it drops below `alphaMin` the
 * layout is considered *settled* and `tick()` becomes a no-op (positions,
 * therefore, stop changing entirely) until something explicitly calls
 * `reheat()` again (a graph rebuild, an expand/collapse, etc.) — orbiting,
 * panning, or zooming the camera never reheats it, so the graph stays
 * perfectly still until the *data* actually changes, not just the view.
 */
export class ForceLayout3D {
  constructor(nodeIds) {
    this.positions = new Map();
    this.velocities = new Map();
    this.alpha = 1;
    this.alphaMin = 0.0015;
    this.alphaDecay = 1 - Math.pow(this.alphaMin, 1 / 260); // settle in ~260 ticks
    nodeIds.forEach((id) => {
      this.positions.set(id, randomSpherePoint(120));
      this.velocities.set(id, { x: 0, y: 0, z: 0 });
    });
  }

  ensureNode(id) {
    if (!this.positions.has(id)) {
      this.positions.set(id, randomSpherePoint(120));
      this.velocities.set(id, { x: 0, y: 0, z: 0 });
      this.reheat(0.6);
    }
  }

  /** Re-energizes the simulation (e.g. after a rebuild/expand/collapse).
   * `amount` lets callers do a gentle reheat (mostly-unchanged graph) vs.
   * a full one (brand new graph) rather than always jumping back to 1. */
  reheat(amount = 1) {
    this.alpha = Math.max(this.alpha, Math.min(1, amount));
  }

  get isSettled() {
    return this.alpha <= this.alphaMin;
  }

  tick(edges, { repulsion = 900, spring = 0.02, damping = 0.85, center = 0.002, maxSpeed = 22 } = {}) {
    if (this.isSettled) return false; // frozen: nothing moves, nothing to render-update

    this.alpha *= 1 - this.alphaDecay;
    const heat = Math.max(this.alpha, 0.02); // never fully zero forces while still "live" this tick

    const ids = [...this.positions.keys()];
    const forces = new Map(ids.map((id) => [id, { x: 0, y: 0, z: 0 }]));

    for (let i = 0; i < ids.length; i++) {
      for (let j = i + 1; j < ids.length; j++) {
        const a = ids[i], b = ids[j];
        const pa = this.positions.get(a), pb = this.positions.get(b);
        const dx = pa.x - pb.x, dy = pa.y - pb.y, dz = pa.z - pb.z;
        let distSq = dx * dx + dy * dy + dz * dz;
        if (!Number.isFinite(distSq) || distSq < 1) distSq = 1;
        const force = (repulsion * heat) / distSq;
        const dist = Math.sqrt(distSq);
        const fx = (dx / dist) * force, fy = (dy / dist) * force, fz = (dz / dist) * force;
        forces.get(a).x += fx; forces.get(a).y += fy; forces.get(a).z += fz;
        forces.get(b).x -= fx; forces.get(b).y -= fy; forces.get(b).z -= fz;
      }
    }

    // Aggregate all edges by *unordered host pair* before applying spring
    // attraction. Real (and synthetic) captures routinely contain dozens of
    // short-lived flows between the same two hosts (many ephemeral ports,
    // a port scan, repeated DNS/TLS sessions, etc.). Applying spring pull
    // once per *edge* rather than once per *pair* previously let a handful
    // of hosts accumulate 10-80x the intended attraction force, which the
    // simulation would visibly and violently overshoot/oscillate trying to
    // correct for — this is what produced the "spins nonstop" symptom.
    // Summing weight per pair first and applying a single log-scaled spring
    // force keeps attraction bounded regardless of how many flows connect
    // the same two hosts.
    const pairWeights = new Map(); // "a|b" (sorted) -> { a, b, weight }
    for (const edge of edges) {
      if (!this.positions.has(edge.a) || !this.positions.has(edge.b) || edge.a === edge.b) continue;
      const key = edge.a < edge.b ? `${edge.a}|${edge.b}` : `${edge.b}|${edge.a}`;
      const entry = pairWeights.get(key);
      const w = Number.isFinite(edge.weight) ? edge.weight : 1;
      if (entry) entry.weight += w;
      else pairWeights.set(key, { a: edge.a, b: edge.b, weight: w });
    }

    for (const { a, b, weight } of pairWeights.values()) {
      const pa = this.positions.get(a), pb = this.positions.get(b);
      const dx = pb.x - pa.x, dy = pb.y - pa.y, dz = pb.z - pa.z;
      const dist = Math.max(1, Math.sqrt(dx * dx + dy * dy + dz * dz));
      const strength = spring * Math.log10(2 + weight) * heat;
      const fx = dx * strength, fy = dy * strength, fz = dz * strength;
      forces.get(a).x += fx; forces.get(a).y += fy; forces.get(a).z += fz;
      forces.get(b).x -= fx; forces.get(b).y -= fy; forces.get(b).z -= fz;
    }

    let maxDisp = 0;
    for (const id of ids) {
      const p = this.positions.get(id);
      const v = this.velocities.get(id);
      const f = forces.get(id);
      f.x += -p.x * center; f.y += -p.y * center; f.z += -p.z * center;
      let vx = (v.x + f.x) * damping;
      let vy = (v.y + f.y) * damping;
      let vz = (v.z + f.z) * damping;
      // Hard speed clamp: defends against any future source of transient
      // force spikes (huge byte-count outliers, many-parallel-edge pairs,
      // etc.) ever re-introducing a runaway/oscillating layout.
      const speed = Math.hypot(vx, vy, vz);
      if (speed > maxSpeed) {
        const s = maxSpeed / speed;
        vx *= s; vy *= s; vz *= s;
      }
      v.x = vx; v.y = vy; v.z = vz;
      p.x += v.x; p.y += v.y; p.z += v.z;
      // Safety net: if anything ever produced a non-finite position (shouldn't
      // happen given the guards above, but NaN never self-recovers via damping
      // since 0.85 * NaN = NaN forever), snap back to a fresh random point
      // rather than permanently poisoning the whole layout.
      if (!Number.isFinite(p.x) || !Number.isFinite(p.y) || !Number.isFinite(p.z)) {
        const fresh = randomSpherePoint(120);
        p.x = fresh.x; p.y = fresh.y; p.z = fresh.z;
        v.x = 0; v.y = 0; v.z = 0;
      }
      maxDisp = Math.max(maxDisp, Math.hypot(v.x, v.y, v.z));
    }

    // If velocities have already died out well before alpha's schedule
    // says to stop (a small, already-well-arranged graph), snap straight
    // to settled rather than idling at near-zero motion for ~250 more ticks.
    if (maxDisp < 0.02) this.alpha = 0;

    return true;
  }

  get(id) {
    return this.positions.get(id) || { x: 0, y: 0, z: 0 };
  }
}

function randomSpherePoint(radius) {
  const u = Math.random(), v = Math.random();
  const theta = 2 * Math.PI * u;
  const phi = Math.acos(2 * v - 1);
  const r = radius * Math.cbrt(Math.random());
  return {
    x: r * Math.sin(phi) * Math.cos(theta),
    y: r * Math.sin(phi) * Math.sin(theta),
    z: r * Math.cos(phi),
  };
}
