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

  tick(edges, { repulsion = 900, spring = 0.02, damping = 0.85, center = 0.002 } = {}) {
    const ids = [...this.positions.keys()];
    const forces = new Map(ids.map((id) => [id, { x: 0, y: 0, z: 0 }]));

    for (let i = 0; i < ids.length; i++) {
      for (let j = i + 1; j < ids.length; j++) {
        const a = ids[i], b = ids[j];
        const pa = this.positions.get(a), pb = this.positions.get(b);
        const dx = pa.x - pb.x, dy = pa.y - pb.y, dz = pa.z - pb.z;
        let distSq = dx * dx + dy * dy + dz * dz;
        if (distSq < 1) distSq = 1;
        const force = repulsion / distSq;
        const dist = Math.sqrt(distSq);
        const fx = (dx / dist) * force, fy = (dy / dist) * force, fz = (dz / dist) * force;
        forces.get(a).x += fx; forces.get(a).y += fy; forces.get(a).z += fz;
        forces.get(b).x -= fx; forces.get(b).y -= fy; forces.get(b).z -= fz;
      }
    }

    for (const edge of edges) {
      if (!this.positions.has(edge.a) || !this.positions.has(edge.b)) continue;
      const pa = this.positions.get(edge.a), pb = this.positions.get(edge.b);
      const dx = pb.x - pa.x, dy = pb.y - pa.y, dz = pb.z - pa.z;
      const dist = Math.max(1, Math.sqrt(dx * dx + dy * dy + dz * dz));
      const strength = spring * Math.log10(2 + (edge.weight || 1));
      const fx = dx * strength, fy = dy * strength, fz = dz * strength;
      forces.get(edge.a).x += fx; forces.get(edge.a).y += fy; forces.get(edge.a).z += fz;
      forces.get(edge.b).x -= fx; forces.get(edge.b).y -= fy; forces.get(edge.b).z -= fz;
    }

    for (const id of ids) {
      const p = this.positions.get(id);
      const v = this.velocities.get(id);
      const f = forces.get(id);
      f.x += -p.x * center; f.y += -p.y * center; f.z += -p.z * center;
      v.x = (v.x + f.x) * damping;
      v.y = (v.y + f.y) * damping;
      v.z = (v.z + f.z) * damping;
      p.x += v.x; p.y += v.y; p.z += v.z;
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
