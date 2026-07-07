/**
 * egoNetwork.js
 * Computes the "ego network" (BFS-expanding neighborhood) around one or
 * more focus hosts within a given host/flow graph — this is what powers
 * the "click a node -> see only its directly related traffic, then
 * progressively expand outward" investigative navigation model, instead
 * of always rendering the entire capture at once.
 */

/**
 * @param {Map<string,object>} hosts full (already filtered/clustered) host set
 * @param {Map<string,object>} flows full (already filtered/clustered) flow set
 * @param {string[]} focusHostIds one or more starting host ids
 * @param {number} hops how many relationship-hops outward to reveal (0 = just the focus host(s) + edges directly between them)
 * @returns {{ hosts: Map, flows: Map }} the induced subgraph: every host within
 *   `hops` of any focus host, plus *every* flow connecting two included hosts
 *   (not just the traversal-tree edges) so all real relationships among the
 *   visible nodes are shown.
 */
export function computeEgoNetwork(hosts, flows, focusHostIds, hops = 1) {
  const adjacency = new Map(); // hostId -> Set(neighborHostId)
  for (const flow of flows.values()) {
    if (!adjacency.has(flow.hostA)) adjacency.set(flow.hostA, new Set());
    if (!adjacency.has(flow.hostB)) adjacency.set(flow.hostB, new Set());
    adjacency.get(flow.hostA).add(flow.hostB);
    adjacency.get(flow.hostB).add(flow.hostA);
  }

  const visited = new Set(focusHostIds.filter((id) => hosts.has(id)));
  let frontier = new Set(visited);
  for (let hop = 0; hop < hops; hop++) {
    const next = new Set();
    for (const id of frontier) {
      for (const neighbor of adjacency.get(id) || []) {
        if (!visited.has(neighbor)) next.add(neighbor);
      }
    }
    next.forEach((id) => visited.add(id));
    frontier = next;
    if (!frontier.size) break;
  }

  const visibleHosts = new Map();
  for (const id of visited) {
    if (hosts.has(id)) visibleHosts.set(id, hosts.get(id));
  }
  const visibleFlows = new Map();
  for (const [key, flow] of flows) {
    if (visited.has(flow.hostA) && visited.has(flow.hostB)) visibleFlows.set(key, flow);
  }
  return { hosts: visibleHosts, flows: visibleFlows };
}
