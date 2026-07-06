/**
 * graphModel.js
 * Aggregates decoded frames into Hosts and Flows — the two entities the
 * 3D scene, timeline, and dashboard all read from. Keeps the raw per-packet
 * list too, but every other view should prefer these summaries so the app
 * stays responsive even on large captures.
 */

export function buildGraphModel(rawPackets, decodedFrames) {
  const hosts = new Map(); // key: ip or mac -> host record
  const flows = new Map(); // key: canonical 5-tuple -> flow record
  const packets = [];

  let firstTs = Infinity;
  let lastTs = -Infinity;

  for (let i = 0; i < decodedFrames.length; i++) {
    const frame = decodedFrames[i];
    const raw = rawPackets[i];
    const ts = raw.tsSeconds + raw.tsMicros / 1e6;
    firstTs = Math.min(firstTs, ts);
    lastTs = Math.max(lastTs, ts);

    const a = frame.endpointA;
    const b = frame.endpointB;
    touchHost(hosts, a, frame, ts, raw.originalLength);
    if (b && b !== a) touchHost(hosts, b, frame, ts, raw.originalLength);

    const flowKey = buildFlowKey(frame, a, b);
    const flow = touchFlow(flows, flowKey, frame, a, b, ts, raw.originalLength);

    packets.push({
      index: i,
      ts,
      tsSeconds: raw.tsSeconds,
      tsMicros: raw.tsMicros,
      length: raw.originalLength,
      capturedLength: raw.capturedLength,
      frame,
      flowKey,
      data: raw.data,
    });
  }

  return {
    hosts,
    flows,
    packets,
    timeRange: { start: firstTs === Infinity ? 0 : firstTs, end: lastTs === -Infinity ? 0 : lastTs },
  };
}

function touchHost(hosts, id, frame, ts, bytes) {
  if (!id) return;
  let host = hosts.get(id);
  if (!host) {
    host = {
      id,
      isIp: id.includes('.') || id.includes(':'),
      mac: frame.layers.l2?.srcMac === id ? id : null,
      packets: 0,
      bytes: 0,
      firstSeen: ts,
      lastSeen: ts,
      protocols: new Set(),
      role: 'unknown',
    };
    hosts.set(id, host);
  }
  host.packets += 1;
  host.bytes += bytes;
  host.lastSeen = ts;
  frame.tags.forEach((t) => host.protocols.add(t));
  if (frame.layers.l7?.type === 'DNS' && frame.layers.l4?.dstPort === 53) {
    // heuristic: hosts frequently answering on 53 look like resolvers
  }
}

function buildFlowKey(frame, a, b) {
  const proto = frame.layers.l4?.type || frame.layers.l3?.type || 'OTHER';
  const p1 = frame.layers.l4?.srcPort ?? '';
  const p2 = frame.layers.l4?.dstPort ?? '';
  // Canonicalize direction so A->B and B->A land in the same flow bucket.
  const forward = `${proto}|${a}:${p1}->${b}:${p2}`;
  const reverse = `${proto}|${b}:${p2}->${a}:${p1}`;
  return forward < reverse ? forward : reverse;
}

function touchFlow(flows, key, frame, a, b, ts, bytes) {
  let flow = flows.get(key);
  if (!flow) {
    flow = {
      key,
      hostA: a,
      hostB: b,
      protocol: frame.layers.l4?.type || frame.layers.l3?.type || 'OTHER',
      appProtocol: frame.layers.l7?.type || null,
      portA: frame.layers.l4?.srcPort ?? null,
      portB: frame.layers.l4?.dstPort ?? null,
      packets: 0,
      bytes: 0,
      firstSeen: ts,
      lastSeen: ts,
      tags: new Set(),
      flagsSeen: new Set(),
      retransmissions: 0,
      packetIndices: [],
    };
    flows.set(key, flow);
  }
  flow.packets += 1;
  flow.bytes += bytes;
  flow.lastSeen = ts;
  frame.tags.forEach((t) => flow.tags.add(t));
  if (frame.layers.l4?.type === 'TCP') {
    Object.entries(frame.layers.l4.flags).forEach(([f, set]) => {
      if (set) flow.flagsSeen.add(f);
    });
  }
  return flow;
}

/** Returns flows whose [firstSeen, lastSeen] window overlaps the given range. */
export function flowsInRange(flows, start, end) {
  const result = [];
  for (const flow of flows.values()) {
    if (flow.lastSeen >= start && flow.firstSeen <= end) result.push(flow);
  }
  return result;
}
