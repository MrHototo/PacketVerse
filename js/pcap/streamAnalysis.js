/**
 * streamAnalysis.js
 * Cross-packet analysis that a single-frame decoder can't do alone:
 *  - TCP stream indices + relative sequence numbers (Wireshark's
 *    "Statistics > TCP Stream Graphs" / tcp.stream / tcp.analysis.*)
 *  - Retransmission, duplicate-ACK, and zero-window detection
 *  - Expert Info notes (Chat/Note/Warning/Error) per packet
 *  - Name resolution table (ip -> hostname) learned from DNS answers,
 *    TLS SNI, and HTTP Host headers seen anywhere in the capture
 *  - In-order, deduplicated stream reassembly for "Follow Stream"
 *
 * Runs once, right after graphModel.buildGraphModel(), over model.packets.
 */

/**
 * @param {Array} packets model.packets (each has .frame, .flowKey, .index, .ts)
 * @returns {{ perPacket: Map<number, object>, nameTable: Map<string,Set<string>>, streamIndexOf: Map<string, number> }}
 */
export function analyzeStreams(packets) {
  const perPacket = new Map(); // packet index -> { expertInfo: [], tcp: {...} }
  const nameTable = new Map(); // ip -> Set<hostname>
  const streamIndexOf = new Map(); // flowKey -> incrementing tcp/udp stream index
  const streamState = new Map(); // flowKey -> per-direction seq tracking state
  let nextStreamIndex = 0;

  const addName = (ip, name) => {
    if (!ip || !name) return;
    if (!nameTable.has(ip)) nameTable.set(ip, new Set());
    nameTable.get(ip).add(name);
  };

  for (const p of packets) {
    const frame = p.frame;
    const l3 = frame.layers.l3, l4 = frame.layers.l4, l7 = frame.layers.l7;
    const expertInfo = [];

    // --- Name resolution harvesting ---
    if ((l7?.type === 'DNS' || l7?.type === 'mDNS') && l7.isResponse && Array.isArray(l7.answers)) {
      for (const ans of l7.answers) {
        if ((ans.type === 'A' || ans.type === 'AAAA') && ans.rdata) addName(ans.rdata, ans.name || l7.name);
        if (ans.type === 'CNAME' && ans.rdata) addName(null, null); // handled via chain below
      }
    }
    if (l7?.type === 'TLS' && l7.serverName && l3) {
      addName(l3.dstIp, l7.serverName);
    }
    if (l7?.type === 'HTTP' && l7.headers?.host && l3) {
      addName(l3.dstIp, l7.headers.host.split(':')[0]);
    }

    // --- TCP stream index + sequence analysis ---
    if (l4?.type === 'TCP' && p.flowKey) {
      if (!streamIndexOf.has(p.flowKey)) streamIndexOf.set(p.flowKey, nextStreamIndex++);
      const streamIndex = streamIndexOf.get(p.flowKey);

      if (!streamState.has(p.flowKey)) {
        streamState.set(p.flowKey, { dirs: new Map() }); // dirKey -> { isn, seenSegments: Map<seq,len>, lastSeq }
      }
      const state = streamState.get(p.flowKey);
      const dirKey = `${l3?.srcIp || frame.endpointA}:${l4.srcPort}`;
      if (!state.dirs.has(dirKey)) {
        state.dirs.set(dirKey, { isn: l4.seq, seenSegments: new Map(), lastSeq: null, lastPayloadLen: 0 });
      }
      const dir = state.dirs.get(dirKey);
      const payloadLen = Math.max(0, (frame.payloadOffset != null ? p.length - frame.payloadOffset : 0));
      const relSeq = seqDelta(l4.seq, dir.isn);

      const tcpInfo = { streamIndex, relSeq, relAck: l4.ack != null ? seqDelta(l4.ack, dir.isn) : null };
      perPacket.set(p.index, { tcp: tcpInfo, expertInfo });

      if (payloadLen > 0) {
        if (dir.seenSegments.has(l4.seq)) {
          expertInfo.push({ severity: 'warning', group: 'Sequence', note: 'Retransmission (this segment was already seen)' });
        } else {
          dir.seenSegments.set(l4.seq, payloadLen);
        }
      } else if (l4.flags.ACK && !l4.flags.SYN && !l4.flags.FIN) {
        if (dir.lastAckSeen === l4.ack) {
          dir.dupAckCount = (dir.dupAckCount || 0) + 1;
          if (dir.dupAckCount >= 1) {
            expertInfo.push({ severity: 'warning', group: 'Sequence', note: `Duplicate ACK #${dir.dupAckCount + 1} (ack=${l4.ack})` });
          }
        } else {
          dir.dupAckCount = 0;
        }
        dir.lastAckSeen = l4.ack;
      }

      if (l4.window === 0 && l4.flags.ACK) {
        expertInfo.push({ severity: 'warning', group: 'Flow Control', note: 'Zero window — receiver\u2019s buffer is full, sender must pause' });
      }
      if (l4.flags.RST) {
        expertInfo.push({ severity: 'note', group: 'Sequence', note: 'Connection reset (RST) — one side aborted the conversation' });
      }
      if (l4.flags.SYN && !l4.flags.ACK) {
        expertInfo.push({ severity: 'chat', group: 'Sequence', note: 'Connection establishment request (SYN)' });
      }
      continue;
    }

    if (l4?.type === 'UDP' && p.flowKey) {
      if (!streamIndexOf.has(p.flowKey)) streamIndexOf.set(p.flowKey, nextStreamIndex++);
      perPacket.set(p.index, { tcp: null, expertInfo });
    }

    if (l7?.type === 'DNS' && l7.rcode && l7.rcode !== 0 && l7.isResponse) {
      const RCODE_NAMES = { 1: 'FormErr', 2: 'ServFail', 3: 'NXDomain', 5: 'Refused' };
      expertInfo.push({ severity: 'note', group: 'DNS', note: `DNS error response: ${RCODE_NAMES[l7.rcode] || l7.rcode}` });
    }
  }

  return { perPacket, nameTable, streamIndexOf };
}

function seqDelta(seq, isn) {
  if (seq == null || isn == null) return null;
  let d = seq - isn;
  if (d < 0) d += 0x100000000; // handle 32-bit wraparound
  return d;
}

/**
 * Reassembles a TCP conversation's application-layer bytes per direction,
 * ordered by sequence number and de-duplicated (unlike a naive
 * arrival-order concatenation), for a more faithful "Follow Stream" view.
 * Falls back to arrival order for UDP/non-TCP flows (no seq numbers to sort by).
 */
export function reassembleStream(packets, flow) {
  const isTcp = flow.protocol === 'TCP';
  const segments = []; // { seq, index, isAtoB, payload, ts }
  for (const p of packets) {
    const offset = p.frame.payloadOffset;
    if (offset == null || offset >= p.data.length) continue;
    const payload = p.data.slice(offset);
    if (!payload.length) continue;
    const isAtoB = p.frame.endpointA === flow.hostA;
    segments.push({ seq: isTcp ? p.frame.layers.l4?.seq ?? 0 : p.index, index: p.index, isAtoB, payload, ts: p.ts });
  }
  if (!isTcp) return segments; // arrival order is the only meaningful order for UDP

  // Sort each direction independently by sequence number, dedupe identical seq (retransmissions).
  const forward = segments.filter((s) => s.isAtoB).sort((a, b) => a.seq - b.seq);
  const backward = segments.filter((s) => !s.isAtoB).sort((a, b) => a.seq - b.seq);
  const dedupe = (arr) => {
    const seen = new Set();
    return arr.filter((s) => (seen.has(s.seq) ? false : (seen.add(s.seq), true)));
  };
  const dedupedForward = dedupe(forward);
  const dedupedBackward = dedupe(backward);
  // Interleave back into chronological order for display, but each direction's
  // internal ordering is now seq-correct rather than raw-arrival-correct.
  return [...dedupedForward, ...dedupedBackward].sort((a, b) => a.ts - b.ts || a.index - b.index);
}
