/**
 * clustering.js
 * Computes a "display graph" from the full host/flow model, optionally
 * collapsing large subnets into single cluster nodes so big captures stay
 * readable (Google-Maps-style: zoom out = see clusters, zoom in / click to
 * expand = see individual hosts). Small captures are shown at full detail
 * automatically.
 */

const DEFAULT_THRESHOLD = 22;

function subnetKeyFor(hostId, host) {
  if (host && host.isIp && /^\d+\.\d+\.\d+\.\d+$/.test(hostId)) {
    const parts = hostId.split('.');
    return `cluster:${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
  }
  return null; // MAC-only / IPv6 / non-IP hosts are never auto-clustered
}

/**
 * @param {Map<string,object>} hosts
 * @param {Map<string,object>} flows
 * @param {Set<string>} expanded - cluster keys the user has manually expanded
 * @param {number} threshold - host count above which clustering kicks in
 */
export function computeDisplayGraph(hosts, flows, expanded = new Set(), threshold = DEFAULT_THRESHOLD) {
  if (hosts.size <= threshold) {
    const identity = new Map([...flows.keys()].map((k) => [k, k]));
    return { hosts, flows, clusters: new Map(), clustered: false, rawFlowKeyToDisplayKey: identity };
  }

  const hostToCluster = new Map(); // hostId -> clusterKey (only if collapsed)
  const clusters = new Map(); // clusterKey -> { id, memberIds: [], bytes, packets, kind }

  for (const [hostId, host] of hosts) {
    const key = subnetKeyFor(hostId, host);
    if (!key || expanded.has(key)) continue;
    if (!clusters.has(key)) {
      clusters.set(key, { id: key, memberIds: [], bytes: 0, packets: 0, protocols: new Set(), kind: 'cluster' });
    }
    clusters.get(key).memberIds.push(hostId);
  }

  // Only actually cluster groups with 2+ members; singletons stay as normal hosts.
  for (const [key, cluster] of [...clusters]) {
    if (cluster.memberIds.length < 2) {
      clusters.delete(key);
      continue;
    }
    for (const hostId of cluster.memberIds) hostToCluster.set(hostId, key);
  }

  const displayHosts = new Map();
  for (const [hostId, host] of hosts) {
    if (hostToCluster.has(hostId)) continue;
    displayHosts.set(hostId, host);
  }
  for (const [key, cluster] of clusters) {
    let bytes = 0, packets = 0;
    let firstSeen = Infinity, lastSeen = -Infinity;
    const protocols = new Set();
    for (const memberId of cluster.memberIds) {
      const h = hosts.get(memberId);
      if (!h) continue;
      bytes += h.bytes || 0;
      packets += h.packets || 0;
      firstSeen = Math.min(firstSeen, h.firstSeen ?? Infinity);
      lastSeen = Math.max(lastSeen, h.lastSeen ?? -Infinity);
      (h.protocols || new Set()).forEach((p) => protocols.add(p));
    }
    displayHosts.set(key, {
      id: key,
      label: `Subnet ${key.replace('cluster:', '')}`,
      kind: 'cluster',
      isCluster: true,
      isIp: true,
      memberIds: cluster.memberIds,
      bytes, packets, protocols,
      firstSeen: Number.isFinite(firstSeen) ? firstSeen : 0,
      lastSeen: Number.isFinite(lastSeen) ? lastSeen : 0,
      mac: null, hostname: null,
    });
  }

  const displayFlows = new Map();
  const rawFlowKeyToDisplayKey = new Map();
  for (const [flowKey, flow] of flows) {
    const a = hostToCluster.get(flow.hostA) || flow.hostA;
    const b = hostToCluster.get(flow.hostB) || flow.hostB;
    if (a === b) continue; // internal-to-cluster traffic, hidden while collapsed
    const key = [a, b].sort().join('<->') + ':' + flow.protocol;
    rawFlowKeyToDisplayKey.set(flowKey, key);
    if (!displayFlows.has(key)) {
      displayFlows.set(key, {
        ...flow,
        key,
        hostA: a,
        hostB: b,
        bytes: 0,
        packets: 0,
        tags: new Set(),
        flagsSeen: new Set(),
        packetIndices: [],
        aggregated: false,
      });
    }
    const merged = displayFlows.get(key);
    merged.bytes += flow.bytes;
    merged.packets += flow.packets;
    flow.tags.forEach((t) => merged.tags.add(t));
    flow.flagsSeen.forEach((t) => merged.flagsSeen.add(t));
    if (flow.packetIndices) merged.packetIndices.push(...flow.packetIndices);
    merged.firstSeen = Math.min(merged.firstSeen, flow.firstSeen);
    merged.lastSeen = Math.max(merged.lastSeen, flow.lastSeen);
    if (a !== flow.hostA || b !== flow.hostB) merged.aggregated = true;
  }

  return { hosts: displayHosts, flows: displayFlows, clusters, clustered: true, rawFlowKeyToDisplayKey };
}

export { DEFAULT_THRESHOLD };
