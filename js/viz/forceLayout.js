/**
 * forceLayout.js
 * Minimal, dependency-free 3D force-directed layout (repulsion + spring
 * attraction + light centering force). O(n^2) per tick, which is
 * intentionally fine for the "lightweight" scope of this project — hosts
 * are aggregated (not individual packets), so even busy captures typically
 * resolve to a few dozen–hundred nodes. See README for scaling notes.
 */
export class ForceLayout3D {
  constructor(nodeIds) {
    this.positions = new Map();
    this.velocities = new Map();
    nodeIds.forEach((id) => {
      this.positions.set(id, randomSpherePoint(120));
      this.velocities.set(id, { x: 0, y: 0, z: 0 });
    });
  }

  ensureNode(id) {
    if (!this.positions.has(id)) {
      this.positions.set(id, randomSpherePoint(120));
      this.velocities.set(id, { x: 0, y: 0, z: 0 });
    }
  }

  tick(edges, { repulsion = 900, spring = 0.02, damping = 0.85, center = 0.002, maxSpeed = 22 } = {}) {
    const ids = [...this.positions.keys()];
    const forces = new Map(ids.map((id) => [id, { x: 0, y: 0, z: 0 }]));

    for (let i = 0; i < ids.length; i++) {
      for (let j = i + 1; j < ids.length; j++) {
        const a = ids[i], b = ids[j];
        const pa = this.positions.get(a), pb = this.positions.get(b);
        const dx = pa.x - pb.x, dy = pa.y - pb.y, dz = pa.z - pb.z;
        let distSq = dx * dx + dy * dy + dz * dz;
        if (!Number.isFinite(distSq) || distSq < 1) distSq = 1;
        const force = repulsion / distSq;
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
      const strength = spring * Math.log10(2 + weight);
      const fx = dx * strength, fy = dy * strength, fz = dz * strength;
      forces.get(a).x += fx; forces.get(a).y += fy; forces.get(a).z += fz;
      forces.get(b).x -= fx; forces.get(b).y -= fy; forces.get(b).z -= fz;
    }

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
    }
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
