/**
 * packetContext.js
 * "Packet Explanation / Context" engine — the replacement for the old
 * static "Security Findings" list. Instead of a flat, capture-wide list of
 * generic anomalies, this builds a rich, plain-English explanation of
 * *whatever is currently selected* (a packet, a conversation, or a host):
 *   1. What this is (packet/protocol purpose)
 *   2. Who is communicating (endpoints, roles, resolved names)
 *   3. Protocol explanation (normal behavior + what's notable here)
 *   4. Traffic context (where this sits in the surrounding conversation)
 *   5. Analyst guidance (fields to check, plus any relevant heuristic
 *      findings folded in as supporting context rather than a standalone
 *      alarm).
 * The underlying heuristic engine (securityEngine.js) still runs — its
 * output is just presented *in context* now instead of as a generic list
 * repeated next to every packet.
 */
import { formatBytes } from '../utils/bytes.js';

/** Groups security-engine findings by the host IDs they affect, so any
 * panel can ask "does anything relevant apply to this host/flow/packet?"
 * instead of dumping the whole list everywhere. */
export function buildFindingsIndex(findings) {
  const byHost = new Map();
  for (const f of findings || []) {
    for (const hostId of f.affected || []) {
      if (!byHost.has(hostId)) byHost.set(hostId, []);
      byHost.get(hostId).push(f);
    }
  }
  return { byHost, all: findings || [] };
}

function findingsForHost(findingsIndex, hostId) {
  return findingsIndex?.byHost?.get(hostId) || [];
}

function findingsForFlow(findingsIndex, flow) {
  if (!flow) return [];
  const a = findingsForHost(findingsIndex, flow.hostA);
  const b = findingsForHost(findingsIndex, flow.hostB);
  const seen = new Set();
  const out = [];
  for (const f of [...a, ...b]) {
    if (seen.has(f)) continue;
    seen.add(f);
    out.push(f);
  }
  return out;
}

function resolvedName(model, ip) {
  const names = model?.nameTable?.get(ip);
  return names && names.size ? [...names][0] : null;
}

function endpointLabel(model, ip, port) {
  const name = ip ? resolvedName(model, ip) : null;
  const addr = ip || '—';
  const portStr = port != null ? `:${port}` : '';
  return name ? `${addr}${portStr} <span class="ctx-resolved">(${escapeHtml(name)})</span>` : `${addr}${portStr}`;
}

/** Very rough, explicitly-labeled-as-a-guess client/server role heuristic
 * (well-known/registered port on one side implies "server" on that side) —
 * matches how Wireshark's own conversation heuristics work, not a hard fact. */
function inferRoles(portA, portB) {
  if (portA == null || portB == null) return null;
  if (portA < 1024 && portB >= 1024) return { server: 'A', client: 'B' };
  if (portB < 1024 && portA >= 1024) return { server: 'B', client: 'A' };
  return null;
}

const PROTO_INFO = {
  DNS: {
    normal: 'DNS translates human-readable domain names into IP addresses (and vice versa). A device typically sends a short query and receives a short answer back, usually over UDP port 53.',
  },
  mDNS: {
    normal: 'Multicast DNS lets devices on the same local network resolve each other\u2019s names (e.g. "printer.local") without a central DNS server \u2014 common on home/office networks for device discovery.',
  },
  TLS: {
    normal: 'TLS (Transport Layer Security) encrypts a connection so its contents can\u2019t be read or tampered with in transit. It starts with a handshake where both sides agree on encryption parameters and the server proves its identity with a certificate.',
  },
  HTTP: {
    normal: 'HTTP is the protocol behind most web and app traffic \u2014 a client sends a request (e.g. "GET this page") and a server sends back a response (content, or a status like an error).',
  },
  ARP: {
    normal: 'ARP maps IP addresses to hardware (MAC) addresses on a local network. Devices broadcast "who has this IP?" and the owner replies directly \u2014 this has to happen before two devices on the same LAN can exchange any actual data.',
  },
  ICMP: {
    normal: 'ICMP carries network diagnostic and control messages \u2014 for example "ping" requests/replies, or a router reporting that a destination is unreachable.',
  },
  DHCP: {
    normal: 'DHCP automatically hands a device an IP address (and other network settings) when it joins a network, so it doesn\u2019t need to be configured by hand.',
  },
  QUIC: {
    normal: 'QUIC is a modern, encrypted transport (used heavily by HTTP/3) built on UDP instead of TCP, designed to set up connections faster and handle packet loss more gracefully.',
  },
};

function protocolKey(entry) {
  return entry.frame.layers.l7?.type || entry.frame.layers.l3?.type === 'ARP' ? (entry.frame.layers.l7?.type || 'ARP') : (entry.frame.layers.l4?.type || 'Other');
}

/* ---------------------------------------------------------------- */
/* Packet-level context                                              */
/* ---------------------------------------------------------------- */

export function renderPacketContext(entry, model, findingsIndex) {
  const l = entry.frame.layers;
  const flow = entry.flowKey ? model?.flows?.get(entry.flowKey) : null;
  const title = titleFor(entry);
  const what = whatIsThis(entry);
  const who = whoIsCommunicating(entry, model, flow);
  const proto = protocolExplanation(entry);
  const context = trafficContextForPacket(entry, model, flow);
  const guidance = analystGuidanceForPacket(entry, flow, findingsIndex);

  return `
    <div class="pctx">
      <div class="pctx-title">${escapeHtml(title.icon)} ${escapeHtml(title.text)}</div>
      <div class="pctx-section">
        <h5>What this packet is</h5>
        <p>${what}</p>
      </div>
      <div class="pctx-section">
        <h5>Who is communicating</h5>
        ${who}
      </div>
      <div class="pctx-section">
        <h5>Protocol explanation</h5>
        <p>${proto}</p>
      </div>
      <div class="pctx-section">
        <h5>Traffic context</h5>
        <p>${context}</p>
      </div>
      <div class="pctx-section pctx-guidance">
        <h5>Analyst guidance</h5>
        ${guidance}
      </div>
    </div>
  `;
}

function titleFor(entry) {
  const l = entry.frame.layers;
  if (l.l7?.type === 'DNS' || l.l7?.type === 'mDNS') {
    return { icon: '\u{1F310}', text: l.l7.isResponse ? 'DNS Response' : 'DNS Query' };
  }
  if (l.l7?.type === 'TLS') {
    const map = { ClientHello: 'TLS Client Hello \u2014 Secure Connection Setup', ServerHello: 'TLS Server Hello', Certificate: 'TLS Certificate Exchange', ApplicationData: 'TLS Encrypted Application Data' };
    return { icon: '\u{1F512}', text: map[l.l7.handshakeType] || 'TLS Traffic' };
  }
  if (l.l7?.type === 'HTTP') {
    return { icon: '\u{1F4C4}', text: l.l7.isRequest ? `HTTP ${l.l7.method || ''} Request`.trim() : `HTTP Response${l.l7.statusCode ? ' (' + l.l7.statusCode + ')' : ''}` };
  }
  if (l.l3?.type === 'ARP') {
    return { icon: '\u{1F4E1}', text: l.l3.op === 'REQUEST' ? 'ARP Request' : 'ARP Reply' };
  }
  if (l.l4?.type === 'TCP') {
    const f = l.l4.flags;
    if (f.SYN && !f.ACK) return { icon: '\u{1F91D}', text: 'TCP Connection Request (SYN)' };
    if (f.SYN && f.ACK) return { icon: '\u{1F91D}', text: 'TCP Connection Accepted (SYN-ACK)' };
    if (f.FIN) return { icon: '\u{1F44B}', text: 'TCP Connection Closing (FIN)' };
    if (f.RST) return { icon: '\u26D4', text: 'TCP Connection Reset (RST)' };
    return { icon: '\u{1F4E6}', text: 'TCP Data Segment' };
  }
  if (l.l4?.type === 'UDP') return { icon: '\u{1F4E6}', text: 'UDP Datagram' };
  if (l.l4?.type === 'ICMP' || l.l4?.type === 'ICMPv6') return { icon: '\u{1F6F0}', text: `${l.l4.type} Message` };
  return { icon: '\u2753', text: 'Unrecognized / Other Traffic' };
}

function whatIsThis(entry) {
  const l = entry.frame.layers;
  if (l.l7?.type === 'DNS' || l.l7?.type === 'mDNS') {
    const d = l.l7;
    if (!d.isResponse) return `This device is asking a DNS server to resolve the name <b>${escapeHtml(d.name || 'unknown')}</b> to an IP address (a "${escapeHtml(d.queryType || 'A')}" record lookup).`;
    const answers = (d.answers || []).map((a) => `${escapeHtml(a.type)} \u2192 ${escapeHtml(String(a.rdata))}`).join(', ');
    return `This is a DNS server's answer${d.name ? ` for "${escapeHtml(d.name)}"` : ''}${d.rcodeName && d.rcodeName !== 'NOERROR' ? `, reporting an error (${escapeHtml(d.rcodeName)})` : ''}.${answers ? ` It returned: ${answers}.` : ''}`;
  }
  if (l.l7?.type === 'TLS') {
    const t = l.l7;
    if (t.handshakeType === 'ClientHello') return `This device is starting an encrypted (TLS) connection${t.serverName ? ` to <b>${escapeHtml(t.serverName)}</b>` : ''}. This is the "hello, let's talk securely, here's what encryption I support" step \u2014 no application data has been exchanged yet.`;
    if (t.handshakeType === 'ServerHello') return 'The server is responding to the encryption request, confirming which encryption method (cipher suite) and TLS version will be used for this session.';
    if (t.handshakeType === 'Certificate') return 'The server is presenting its digital certificate, which the client uses to verify the server\u2019s identity before trusting it with sensitive data.';
    return 'This is part of an already-established encrypted session \u2014 the payload itself cannot be read from the capture, by design.';
  }
  if (l.l7?.type === 'HTTP') {
    if (l.l7.isRequest) return `This device is requesting a web resource${l.l7.path ? ` (<b>${escapeHtml(l.l7.path)}</b>)` : ''} using an HTTP "${escapeHtml(l.l7.method || '')}" request \u2014 the same action as typing a URL into a browser or an app fetching data.`;
    return `A web server is responding${l.l7.statusCode ? ` with status ${l.l7.statusCode} (${escapeHtml(l.l7.statusText || '')})` : ''} \u2014 sending back a page, file, or error.`;
  }
  if (l.l3?.type === 'ARP') {
    return l.l3.op === 'REQUEST'
      ? `This device is broadcasting to the whole local network, asking "who owns IP address ${escapeHtml(l.l3.targetIp)}?" \u2014 the required first step before it can talk directly to that device.`
      : `This device is replying to an ARP request, announcing "I own that IP address, here is my hardware (MAC) address."`;
  }
  if (l.l4?.type === 'TCP') {
    const f = l.l4.flags;
    if (f.SYN && !f.ACK) return 'This device is opening a brand-new connection \u2014 the first step of the standard three-way TCP handshake, like knocking on a door before entering.';
    if (f.SYN && f.ACK) return 'The other side is accepting the connection request \u2014 the second step of the handshake.';
    if (f.FIN) return 'One side has no more data to send and is gracefully closing this connection.';
    if (f.RST) return 'This connection was abruptly terminated \u2014 typically because nothing was listening on that port, or an error occurred mid-conversation.';
    return `Data is being exchanged over an already-open connection (port ${l.l4.srcPort} \u2192 ${l.l4.dstPort}).`;
  }
  if (l.l4?.type === 'UDP') return 'A short, connectionless message is being sent \u2014 commonly used where speed matters more than guaranteed delivery (DNS, streaming, gaming, VoIP).';
  if (l.l4?.type === 'ICMP' || l.l4?.type === 'ICMPv6') return `This is a network diagnostic/control message (type ${l.l4.icmpType}, code ${l.l4.icmpCode}) \u2014 for example a ping, or a router reporting a delivery problem.`;
  return 'This packet did not match a protocol this lightweight, client-side decoder recognizes in depth \u2014 see the raw layer breakdown and hex view below for everything that was decoded.';
}

function whoIsCommunicating(entry, model, flow) {
  const l = entry.frame.layers;
  const srcIp = l.l3?.srcIp, dstIp = l.l3?.dstIp;
  const srcMac = l.l2?.srcMac, dstMac = l.l2?.dstMac;
  const srcPort = l.l4?.srcPort, dstPort = l.l4?.dstPort;
  const roles = inferRoles(srcPort, dstPort);
  const rows = [];
  if (srcIp || dstIp) {
    rows.push(['Source', endpointLabel(model, srcIp, srcPort) + (roles?.client === 'A' ? ' <span class="ctx-role">(client)</span>' : roles?.server === 'A' ? ' <span class="ctx-role">(likely server)</span>' : '')]);
    rows.push(['Destination', endpointLabel(model, dstIp, dstPort) + (roles?.client === 'B' ? ' <span class="ctx-role">(client)</span>' : roles?.server === 'B' ? ' <span class="ctx-role">(likely server)</span>' : '')]);
  }
  if (srcMac) rows.push(['Source MAC', escapeHtml(srcMac)]);
  if (dstMac) rows.push(['Destination MAC', escapeHtml(dstMac)]);
  if (l.l2?.vlanId != null) rows.push(['VLAN', String(l.l2.vlanId)]);
  if (!rows.length) return '<p class="hint">No addressable endpoints decoded for this frame.</p>';
  return `<div class="ctx-kv">${rows.map(([k, v]) => `<div class="ctx-kv-row"><span>${k}</span><b>${v}</b></div>`).join('')}</div>`;
}

function protocolExplanation(entry) {
  const l = entry.frame.layers;
  const key = l.l7?.type && PROTO_INFO[l.l7.type] ? l.l7.type : (l.l3?.type === 'ARP' ? 'ARP' : (l.l4?.type === 'ICMP' || l.l4?.type === 'ICMPv6') ? 'ICMP' : null);
  const base = key && PROTO_INFO[key] ? PROTO_INFO[key].normal : null;
  const notes = [];
  if (l.l7?.type === 'TLS') {
    if (l.l7.negotiatedVersion) notes.push(`Negotiated version: ${escapeHtml(l.l7.negotiatedVersion)}.`);
    if (l.l7.cipherSuiteCount) notes.push(`Client offered ${l.l7.cipherSuiteCount} cipher suites.`);
    if (l.l7.serverName) notes.push(`SNI (requested hostname): ${escapeHtml(l.l7.serverName)}.`);
  }
  if ((l.l7?.type === 'DNS' || l.l7?.type === 'mDNS')) {
    if (l.l7.answers?.some((a) => a.type === 'CNAME')) notes.push('This response includes a CNAME (alias) chain rather than a direct address.');
    if (l.l7.rcodeName && l.l7.rcodeName !== 'NOERROR') notes.push(`Response code "${escapeHtml(l.l7.rcodeName)}" indicates the lookup did not succeed normally.`);
    if (l.l7.authoritative) notes.push('This answer came from a server that is authoritative for the domain (not just a cache).');
  }
  if (l.l4?.type === 'TCP' && entry.tcpAnalysis?.isRetransmission) notes.push('This segment appears to be a retransmission \u2014 the original was likely lost or badly delayed.');
  if (l.l4?.type === 'TCP') {
    const flagNames = Object.entries(l.l4.flags || {}).filter(([, v]) => v).map(([k]) => k);
    if (flagNames.length) notes.push(`TCP flags set: ${flagNames.join(', ')}.`);
  }
  const combined = [base, notes.join(' ')].filter(Boolean).join(' ');
  return combined || 'This packet uses a protocol not deeply modeled by this lightweight decoder \u2014 refer to the raw layer breakdown below for what was decoded.';
}

function trafficContextForPacket(entry, model, flow) {
  if (!flow || !flow.packetIndices?.length) {
    return 'This packet is not part of a tracked conversation (e.g. a broadcast/multicast frame with no direct reply), so there is no surrounding sequence to compare it against.';
  }
  const ordered = flow.packetIndices;
  const pos = ordered.indexOf(entry.index);
  const total = ordered.length;
  const parts = [`This is packet ${pos >= 0 ? pos + 1 : '?'} of ${total} in this conversation between ${escapeHtml(flow.hostA)} and ${escapeHtml(flow.hostB)}.`];
  if (pos > 0 && model?.packets) {
    const prevEntry = model.packets[ordered[pos - 1]];
    if (prevEntry) {
      const delta = entry.ts - prevEntry.ts;
      parts.push(`It arrived ${delta >= 0 ? delta.toFixed(4) : '0.0000'}s after the previous packet in this conversation (${escapeHtml(prevEntry.frame.summary || '')}).`);
    }
  } else if (pos === 0) {
    parts.push('This is the very first packet of this conversation.');
  }
  if (pos === total - 1) parts.push('It is also the last packet seen for this conversation in the capture.');
  const sinceStart = entry.ts - flow.firstSeen;
  parts.push(`It occurred ${sinceStart.toFixed(3)}s after this conversation began.`);
  return parts.join(' ');
}

function analystGuidanceForPacket(entry, flow, findingsIndex) {
  const l = entry.frame.layers;
  const tips = [];
  if (l.l7?.type === 'TLS') tips.push('Review the negotiated TLS version and the server name (SNI) to confirm this connection is going where it should. Very old TLS versions (SSLv3/TLS 1.0/1.1) are considered weak.');
  if (l.l7?.type === 'DNS' && !l.l7.isResponse) tips.push('If this domain is unfamiliar or looks machine-generated (long/random characters), it can be worth investigating further.');
  if (l.l7?.type === 'DNS' && l.l7.isResponse) tips.push('Check whether the resolved address is what you\u2019d expect for this domain \u2014 an unexpected IP can indicate DNS spoofing or a misconfigured resolver.');
  if (l.l4?.type === 'TCP' && l.l4.flags?.RST) tips.push('A single reset is often harmless (e.g. a closed port). Resets across many different destinations from the same source are more suspicious \u2014 check the source\u2019s other conversations.');
  if (entry.tcpAnalysis?.isRetransmission) tips.push('Frequent retransmissions on this conversation can point to packet loss, congestion, or an unreliable link \u2014 worth checking if this repeats.');
  if (l.l7?.type === 'HTTP' && l.l7.isRequest) tips.push('Confirm the requested host/path is expected. Unusual paths or automated-looking User-Agents can be worth a second look.');
  if (!tips.length) tips.push('Nothing specific stands out for this packet type \u2014 use the layer breakdown and hex view below if you need field-level detail.');

  const related = findingsForFlow(findingsIndex, flow);
  const findingHtml = related.length
    ? `<div class="ctx-related-findings"><b>Related heuristic notes:</b>${related.map((f) => renderFindingNote(f)).join('')}</div>`
    : '';
  return `<ul class="ctx-tips">${tips.map((t) => `<li>${t}</li>`).join('')}</ul>${findingHtml}`;
}

function renderFindingNote(f) {
  return `<div class="finding-note finding-${f.severity}"><span class="badge badge-${f.severity}">${f.severity}</span> <b>${escapeHtml(f.type)}</b> (${Math.round(f.confidence * 100)}% confidence) \u2014 ${escapeHtml(f.explanation)}<br><span class="hint">Next step: ${escapeHtml(f.nextSteps)}</span></div>`;
}

/* ---------------------------------------------------------------- */
/* Flow-level context                                                */
/* ---------------------------------------------------------------- */

export function renderFlowContext(flow, model, findingsIndex) {
  const proto = flow.appProtocol || flow.protocol;
  const roles = inferRoles(flow.portA, flow.portB);
  const nameA = resolvedName(model, flow.hostA);
  const nameB = resolvedName(model, flow.hostB);
  const duration = Math.max(0, flow.lastSeen - flow.firstSeen);
  const captureSpan = model?.timeRange ? Math.max(1e-6, model.timeRange.end - model.timeRange.start) : null;
  const offsetIntoCapture = model?.timeRange ? flow.firstSeen - model.timeRange.start : null;

  const what = `This is a ${escapeHtml(proto)} conversation between two devices, made up of ${flow.packets} packets (${formatBytes(flow.bytes)}) over ${duration.toFixed(2)} seconds.`;
  const who = `
    <div class="ctx-kv">
      <div class="ctx-kv-row"><span>Host A</span><b>${escapeHtml(flow.hostA)}${flow.portA != null ? ':' + flow.portA : ''}${nameA ? ` <span class="ctx-resolved">(${escapeHtml(nameA)})</span>` : ''}${roles?.server === 'A' ? ' <span class="ctx-role">(likely server)</span>' : roles?.client === 'A' ? ' <span class="ctx-role">(client)</span>' : ''}</b></div>
      <div class="ctx-kv-row"><span>Host B</span><b>${escapeHtml(flow.hostB)}${flow.portB != null ? ':' + flow.portB : ''}${nameB ? ` <span class="ctx-resolved">(${escapeHtml(nameB)})</span>` : ''}${roles?.server === 'B' ? ' <span class="ctx-role">(likely server)</span>' : roles?.client === 'B' ? ' <span class="ctx-role">(client)</span>' : ''}</b></div>
    </div>`;
  const protoExplain = (PROTO_INFO[proto]?.normal) || `${escapeHtml(proto)} traffic \u2014 see individual packets for protocol-specific detail.`;
  const flagsNote = flow.flagsSeen?.size ? ` TCP flags observed across this conversation: ${[...flow.flagsSeen].join(', ')}.` : '';
  const context = offsetIntoCapture != null
    ? `This conversation started ${offsetIntoCapture.toFixed(2)}s into the capture${captureSpan ? ` (capture spans ${captureSpan.toFixed(2)}s total)` : ''} and lasted ${duration.toFixed(2)}s.`
    : `This conversation lasted ${duration.toFixed(2)}s.`;

  const tips = [];
  if (flow.flagsSeen?.has('RST')) tips.push('This conversation included a reset \u2014 confirm whether that was an expected closure or a rejected/interrupted connection.');
  if (flow.tags?.has('Broadcast')) tips.push('This traffic was broadcast to every device on the local network segment, not just one destination.');
  if (proto === 'TLS' || proto === 'HTTPS') tips.push('Use "Follow this stream" to inspect the handshake and confirm the certificate/server identity if this connection looks unfamiliar.');
  if (!tips.length) tips.push('Nothing specific stands out for this conversation \u2014 drill into individual packets for more detail.');

  const related = findingsForFlow(findingsIndex, flow);
  const findingHtml = related.length
    ? `<div class="ctx-related-findings"><b>Related heuristic notes:</b>${related.map((f) => renderFindingNote(f)).join('')}</div>`
    : '';

  return `
    <div class="pctx">
      <div class="pctx-title">\u{1F501} ${escapeHtml(proto)} Conversation</div>
      <div class="pctx-section"><h5>What this is</h5><p>${what}</p></div>
      <div class="pctx-section"><h5>Who is communicating</h5>${who}</div>
      <div class="pctx-section"><h5>Protocol explanation</h5><p>${protoExplain}${flagsNote}</p></div>
      <div class="pctx-section"><h5>Traffic context</h5><p>${context}</p></div>
      <div class="pctx-section pctx-guidance"><h5>Analyst guidance</h5><ul class="ctx-tips">${tips.map((t) => `<li>${t}</li>`).join('')}</ul>${findingHtml}</div>
    </div>`;
}

/* ---------------------------------------------------------------- */
/* Host-level context                                                */
/* ---------------------------------------------------------------- */

export function renderHostContext(host, model, findingsIndex) {
  const proto = [...(host.protocols || [])];
  const role = host.isCluster ? 'Subnet cluster' : proto.some((p) => ['DNS', 'DHCP'].includes(p)) ? 'Likely infrastructure device (DNS/DHCP)' : 'Host';
  const what = host.isCluster
    ? `This is a collapsed group of ${host.memberIds?.length ?? 0} hosts on the same subnet, shown as one node to reduce clutter. Expand it in the graph to see individual devices.`
    : `This device sent or received ${host.packets} packets (${formatBytes(host.bytes)}) in this capture.`;
  const who = `<div class="ctx-kv">
      <div class="ctx-kv-row"><span>Address</span><b>${escapeHtml(host.id)}</b></div>
      <div class="ctx-kv-row"><span>Role</span><b>${escapeHtml(role)}</b></div>
      <div class="ctx-kv-row"><span>First seen</span><b>${new Date(host.firstSeen * 1000).toLocaleTimeString()}</b></div>
      <div class="ctx-kv-row"><span>Last seen</span><b>${new Date(host.lastSeen * 1000).toLocaleTimeString()}</b></div>
    </div>`;
  const protoExplain = proto.length
    ? `This device communicates using ${proto.slice(0, 6).join(', ')}${proto.length > 6 ? ', among others' : ''}.`
    : 'No protocol was confidently decoded for this device\u2019s traffic.';
  const context = `It appears in ${host.packets} packets total in this capture, spanning ${(host.lastSeen - host.firstSeen).toFixed(2)}s.`;
  const related = findingsForHost(findingsIndex, host.id);
  const tips = [];
  if (!related.length) tips.push('Nothing specific stands out for this device \u2014 drill into its conversations for more detail.');
  const findingHtml = related.length
    ? `<div class="ctx-related-findings"><b>Related heuristic notes:</b>${related.map((f) => renderFindingNote(f)).join('')}</div>`
    : '';

  return `
    <div class="pctx">
      <div class="pctx-title">\u{1F4BB} ${escapeHtml(host.id)}</div>
      <div class="pctx-section"><h5>What this is</h5><p>${what}</p></div>
      <div class="pctx-section"><h5>Who is communicating</h5>${who}</div>
      <div class="pctx-section"><h5>Protocol explanation</h5><p>${protoExplain}</p></div>
      <div class="pctx-section"><h5>Traffic context</h5><p>${context}</p></div>
      <div class="pctx-section pctx-guidance"><h5>Analyst guidance</h5><ul class="ctx-tips">${tips.map((t) => `<li>${t}</li>`).join('')}</ul>${findingHtml}</div>
    </div>`;
}

function escapeHtml(str) { return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
