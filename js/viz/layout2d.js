/**
 * layout2d.js
 * Deterministic, readability-optimized 2D layout — deliberately NOT a
 * flattened version of the 3D force graph. It arranges hosts in concentric
 * rings by BFS hop-distance from the highest-traffic host ("hub"), spacing
 * each ring's members evenly by angle and sorting by traffic within a ring
 * so heavy talkers cluster together. Being computed directly from the graph
 * structure (no physics/iteration), it's instant and has zero risk of
 * oscillation — exactly the "cleaner spacing, easier navigation" 2D mode
 * asked for, distinct from the 3D force-directed sphere.
 */
export function computeRadialLayout(hosts, flows, { ringGap = 130, minRadius = 90 } = {}) {
  const ids = [...hosts.keys()];
  const positions = new Map();
  if (!ids.length) return positions;

  if (ids.length === 1) {
    positions.set(ids[0], { x: 0, y: 0 });
    return positions;
  }

  const adjacency = new Map();
  for (const id of ids) adjacency.set(id, new Set());
  for (const flow of flows.values()) {
    if (!adjacency.has(flow.hostA) || !adjacency.has(flow.hostB)) continue;
    adjacency.get(flow.hostA).add(flow.hostB);
    adjacency.get(flow.hostB).add(flow.hostA);
  }

  // Hub = highest-traffic host (ties broken by highest degree) — the most
  // natural visual anchor for an investigation ("what is this device talking to").
  let hub = ids[0];
  for (const id of ids) {
    const h = hosts.get(id), best = hosts.get(hub);
    if (h.bytes > best.bytes || (h.bytes === best.bytes && adjacency.get(id).size > adjacency.get(hub).size)) hub = id;
  }

  const hop = new Map([[hub, 0]]);
  let frontier = [hub];
  while (frontier.length) {
    const next = [];
    for (const id of frontier) {
      for (const nb of adjacency.get(id)) {
        if (!hop.has(nb)) {
          hop.set(nb, hop.get(id) + 1);
          next.push(nb);
        }
      }
    }
    frontier = next;
  }
  // Any host unreachable from the hub (disconnected component) still needs a
  // ring — push it one past the current max so it renders as an outer group
  // rather than being dropped.
  const maxKnownHop = Math.max(0, ...[...hop.values()]);
  let disconnectedRing = maxKnownHop + 1;
  for (const id of ids) {
    if (!hop.has(id)) hop.set(id, disconnectedRing);
  }

  const rings = new Map(); // hop -> [ids]
  for (const id of ids) {
    const h = hop.get(id);
    if (!rings.has(h)) rings.set(h, []);
    rings.get(h).push(id);
  }
  for (const members of rings.values()) {
    members.sort((a, b) => (hosts.get(b).bytes || 0) - (hosts.get(a).bytes || 0));
  }

  positions.set(hub, { x: 0, y: 0 });
  for (const [h, members] of rings) {
    if (h === 0) continue;
    const radius = minRadius + (h - 1) * ringGap;
    const n = members.length;
    // Golden-angle offset per ring keeps neighboring rings' nodes from lining
    // up in dense radial spokes, which reads more clearly at a glance.
    const angleOffset = h * 0.6;
    members.forEach((id, i) => {
      const angle = angleOffset + (i / n) * Math.PI * 2;
      positions.set(id, { x: Math.cos(angle) * radius, y: Math.sin(angle) * radius });
    });
  }
  return positions;
}
