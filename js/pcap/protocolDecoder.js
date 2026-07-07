/**
 * protocolDecoder.js
 * Decodes a raw link-layer frame into a structured, layered object.
 * Deliberately dependency-free so it can run in the browser or a Web Worker.
 */
import { macToString, ipv4ToString, ipv6ToString } from '../utils/bytes.js';
import { decodeHandshakeRecord, TLS_VERSION_MAP } from './tls.js';

const ETHERTYPE_VLAN = 0x8100;
const ETHERTYPE_ARP = 0x0806;
const ETHERTYPE_IPV4 = 0x0800;
const ETHERTYPE_IPV6 = 0x86dd;

const IP_PROTO = { 1: 'ICMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6' };

const WELL_KNOWN_PORTS = {
  53: 'DNS',
  67: 'DHCP',
  68: 'DHCP',
  80: 'HTTP',
  123: 'NTP',
  443: 'TLS',
  1900: 'SSDP',
  5353: 'mDNS',
};

/**
 * @param {Uint8Array} data raw frame bytes
 * @param {number} linkType pcap LINKTYPE_* value (1 = Ethernet)
 */
export function decodeFrame(data, linkType) {
  const layers = { l2: null, l3: null, l4: null, l7: null };
  let tags = new Set();

  if (linkType !== 1 || data.length < 14) {
    layers.l2 = { type: 'Unknown link layer', linkType };
    return { layers, tags: [...tags], summary: 'Unrecognized link layer' };
  }

  const dstMac = macToString(data, 0);
  const srcMac = macToString(data, 6);
  let etherType = (data[12] << 8) | data[13];
  let ethPayloadOffset = 14;
  let vlanId = null;

  if (etherType === ETHERTYPE_VLAN && data.length >= 18) {
    vlanId = ((data[14] << 8) | data[15]) & 0x0fff;
    etherType = (data[16] << 8) | data[17];
    ethPayloadOffset = 18;
    tags.add('VLAN');
  }

  const isBroadcast = dstMac === 'ff:ff:ff:ff:ff:ff';
  const isMulticast = !isBroadcast && (data[0] & 0x01) !== 0;
  if (isBroadcast) tags.add('Broadcast');
  else if (isMulticast) tags.add('Multicast');
  else tags.add('Unicast');

  layers.l2 = { srcMac, dstMac, etherType, vlanId, isBroadcast, isMulticast };

  if (etherType === ETHERTYPE_ARP) {
    layers.l3 = decodeArp(data, ethPayloadOffset);
    tags.add('ARP');
    return finish(layers, tags, srcMac, dstMac);
  }

  if (etherType === ETHERTYPE_IPV4) {
    const ip = decodeIPv4(data, ethPayloadOffset);
    layers.l3 = ip;
    tags.add('IPv4');
    decodeTransport(data, ip, layers, tags);
    return finish(layers, tags, ip.srcIp, ip.dstIp);
  }

  if (etherType === ETHERTYPE_IPV6) {
    const ip = decodeIPv6(data, ethPayloadOffset);
    layers.l3 = ip;
    tags.add('IPv6');
    decodeTransport(data, ip, layers, tags);
    return finish(layers, tags, ip.srcIp, ip.dstIp);
  }

  layers.l3 = { type: `EtherType 0x${etherType.toString(16)}`, unknown: true };
  return finish(layers, tags, srcMac, dstMac);
}

function finish(layers, tags, endpointA, endpointB) {
  return {
    layers,
    tags: [...tags],
    endpointA,
    endpointB,
    payloadOffset: layers.payloadOffset ?? null,
    summary: buildSummary(layers, tags),
  };
}

function decodeArp(data, offset) {
  const opcode = (data[offset + 6] << 8) | data[offset + 7];
  const senderMac = macToString(data, offset + 8);
  const senderIp = ipv4ToString(data, offset + 14);
  const targetMac = macToString(data, offset + 18);
  const targetIp = ipv4ToString(data, offset + 24);
  return {
    type: 'ARP',
    op: opcode === 1 ? 'REQUEST' : opcode === 2 ? 'REPLY' : opcode,
    senderMac,
    senderIp,
    targetMac,
    targetIp,
  };
}

function decodeIPv4(data, offset) {
  const versionIhl = data[offset];
  const ihl = (versionIhl & 0x0f) * 4;
  const totalLength = (data[offset + 2] << 8) | data[offset + 3];
  const ttl = data[offset + 8];
  const protoNum = data[offset + 9];
  const srcIp = ipv4ToString(data, offset + 12);
  const dstIp = ipv4ToString(data, offset + 16);
  return {
    type: 'IPv4',
    ihl,
    totalLength,
    ttl,
    protoNum,
    protocol: IP_PROTO[protoNum] || `Proto ${protoNum}`,
    srcIp,
    dstIp,
    headerEnd: offset + ihl,
  };
}

function decodeIPv6(data, offset) {
  const payloadLength = (data[offset + 4] << 8) | data[offset + 5];
  const nextHeader = data[offset + 6];
  const hopLimit = data[offset + 7];
  const srcIp = ipv6ToString(data, offset + 8);
  const dstIp = ipv6ToString(data, offset + 24);
  return {
    type: 'IPv6',
    payloadLength,
    protoNum: nextHeader,
    protocol: IP_PROTO[nextHeader] || `Next-Header ${nextHeader}`,
    hopLimit,
    srcIp,
    dstIp,
    headerEnd: offset + 40,
  };
}

function decodeTransport(data, ip, layers, tags) {
  const offset = ip.headerEnd;
  if (ip.protoNum === 6 && data.length >= offset + 20) {
    const l4 = decodeTcp(data, offset);
    layers.l4 = l4;
    tags.add('TCP');
    if (l4.flags.SYN && !l4.flags.ACK) tags.add('Handshake');
    if (l4.flags.RST) tags.add('Errors');
    layers.payloadOffset = l4.headerEnd;
    decodeApplication(data, ip, l4, layers, tags, l4.headerEnd);
  } else if (ip.protoNum === 17 && data.length >= offset + 8) {
    const l4 = decodeUdp(data, offset);
    layers.l4 = l4;
    tags.add('UDP');
    layers.payloadOffset = offset + 8;
    decodeApplication(data, ip, l4, layers, tags, offset + 8);
  } else if (ip.protoNum === 1 || ip.protoNum === 58) {
    const type = data[offset];
    const code = data[offset + 1];
    layers.l4 = { type: ip.protoNum === 1 ? 'ICMP' : 'ICMPv6', icmpType: type, icmpCode: code };
    tags.add(ip.protoNum === 1 ? 'ICMP' : 'ICMPv6');
    layers.payloadOffset = offset + 8;
  }
}

function decodeTcp(data, offset) {
  const srcPort = (data[offset] << 8) | data[offset + 1];
  const dstPort = (data[offset + 2] << 8) | data[offset + 3];
  const seq = readU32(data, offset + 4);
  const ack = readU32(data, offset + 8);
  const dataOffsetWords = (data[offset + 12] >> 4) & 0x0f;
  const flagsByte = data[offset + 13];
  const flags = {
    FIN: !!(flagsByte & 0x01),
    SYN: !!(flagsByte & 0x02),
    RST: !!(flagsByte & 0x04),
    PSH: !!(flagsByte & 0x08),
    ACK: !!(flagsByte & 0x10),
    URG: !!(flagsByte & 0x20),
  };
  const window = (data[offset + 14] << 8) | data[offset + 15];
  return {
    type: 'TCP',
    srcPort,
    dstPort,
    seq,
    ack,
    flags,
    window,
    headerEnd: offset + dataOffsetWords * 4,
  };
}

function decodeUdp(data, offset) {
  const srcPort = (data[offset] << 8) | data[offset + 1];
  const dstPort = (data[offset + 2] << 8) | data[offset + 3];
  const length = (data[offset + 4] << 8) | data[offset + 5];
  return { type: 'UDP', srcPort, dstPort, length };
}

function decodeApplication(data, ip, l4, layers, tags, payloadOffset) {
  const srcPort = l4.srcPort;
  const dstPort = l4.dstPort;
  const proto = WELL_KNOWN_PORTS[srcPort] || WELL_KNOWN_PORTS[dstPort];
  if (payloadOffset >= data.length) return;

  if (proto === 'DNS') {
    layers.l7 = decodeDns(data, payloadOffset) || { type: 'DNS' };
    tags.add('DNS');
    return;
  }
  if (proto === 'mDNS') {
    layers.l7 = decodeDns(data, payloadOffset) || { type: 'mDNS' };
    tags.add('mDNS');
    return;
  }
  if (proto === 'DHCP') {
    layers.l7 = decodeDhcp(data, payloadOffset) || { type: 'DHCP' };
    tags.add('DHCP');
    return;
  }
  if (proto === 'NTP') {
    layers.l7 = decodeNtp(data, payloadOffset);
    tags.add('NTP');
    return;
  }
  if (proto === 'SSDP') {
    layers.l7 = decodeTextProtocol(data, payloadOffset, 'SSDP');
    tags.add('SSDP');
    return;
  }
  // Detect TLS by its actual record header byte signature — content-type
  // must be one of the four valid TLS record types (ChangeCipherSpec/Alert/
  // Handshake/ApplicationData), version 0x03xx — rather than assuming port
  // 443. Real-world TLS shows up on many ports (DoT/853, DoH/443, SMTPS/465,
  // mail/993, custom app ports, etc.), and Wireshark itself dissects TLS
  // this way rather than by port alone. Checking *all four* content types
  // (not just Handshake/0x16) matters a lot in practice: the bulk of any
  // real TLS session is ApplicationData (0x17) records, which were
  // previously invisible to this detector entirely.
  if (looksLikeTlsRecord(data, payloadOffset)) {
    layers.l7 = decodeTls(data, payloadOffset);
    tags.add('TLS');
    return;
  }
  const httpGuess = decodeHttp(data, payloadOffset);
  if (httpGuess) {
    layers.l7 = httpGuess;
    tags.add('HTTP');
  }
}

const TLS_RECORD_CONTENT_TYPES = new Set([0x14, 0x15, 0x16, 0x17]);

function looksLikeTlsRecord(data, offset) {
  return offset + 5 <= data.length && TLS_RECORD_CONTENT_TYPES.has(data[offset]) && data[offset + 1] === 0x03;
}

const TLS_CONTENT_TYPES = { 0x14: 'ChangeCipherSpec', 0x15: 'Alert', 0x16: 'Handshake', 0x17: 'ApplicationData' };

/**
 * Decodes *every* consecutive TLS record found in this segment's payload,
 * not just the first. This matters because a single TCP segment very
 * commonly carries several TLS records back-to-back — e.g. a server
 * frequently batches ServerHello + Certificate + ServerHelloDone (three
 * separate TLS records) into one TCP segment. Only decoding the first
 * record meant fields like `tls.handshake.type==11` (Certificate) or
 * `tls.cert.subject` would silently never match such packets even though
 * the bytes were right there — this fixes that by scanning forward and
 * aggregating every record's fields into one L7 object, mirroring how
 * Wireshark shows multiple protocol-tree entries for one frame.
 */
function decodeTls(data, offset) {
  const records = [];
  let cursor = offset;
  let guard = 0;
  while (guard < 16 && looksLikeTlsRecord(data, cursor)) {
    guard++;
    const contentType = data[cursor];
    const recordVersion = (data[cursor + 1] << 8) | data[cursor + 2];
    const recordLength = (data[cursor + 3] << 8) | data[cursor + 4];
    const recBase = {
      contentType,
      contentTypeName: TLS_CONTENT_TYPES[contentType] || `0x${contentType.toString(16)}`,
      version: TLS_VERSION_MAP[recordVersion] || `0x${recordVersion.toString(16)}`,
      recordLength,
    };
    if (contentType === 0x16) {
      try {
        records.push({ ...recBase, ...decodeHandshakeRecord(data, cursor) });
      } catch {
        records.push({ ...recBase, handshakeType: 'Handshake (undecodable)' });
      }
    } else {
      records.push({ ...recBase, handshakeType: null });
    }
    if (recordLength === 0) break;
    cursor += 5 + recordLength;
  }

  if (!records.length) {
    // Shouldn't normally happen (caller already checked looksLikeTlsRecord),
    // but fail gracefully rather than returning something malformed.
    return { type: 'TLS', contentTypeName: 'Unknown', handshakeType: null, records: [] };
  }

  const primary = records.find((r) => r.contentType === 0x16) || records[0];
  const handshakeTypes = records.filter((r) => r.contentType === 0x16 && r.handshakeType).map((r) => r.handshakeType);
  const handshakeMsgTypes = records.filter((r) => r.contentType === 0x16 && r.msgType != null).map((r) => r.msgType);
  const certificates = records.flatMap((r) => r.certificates || []);

  return {
    type: 'TLS',
    ...primary,
    records,
    recordCount: records.length,
    handshakeTypes,
    handshakeMsgTypes,
    certificates: certificates.length ? certificates : primary.certificates,
    contentTypes: [...new Set(records.map((r) => r.contentTypeName))],
  };
}

const DNS_RECORD_TYPES = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 64: 'SVCB', 65: 'HTTPS' };
const DNS_RCODE_NAMES = { 0: 'NoError', 1: 'FormErr', 2: 'ServFail', 3: 'NXDomain', 4: 'NotImp', 5: 'Refused' };

function decodeDns(data, offset) {
  if (offset + 12 > data.length) return null;
  const id = (data[offset] << 8) | data[offset + 1];
  const flags = (data[offset + 2] << 8) | data[offset + 3];
  const isResponse = (flags & 0x8000) !== 0;
  const opcode = (flags >> 11) & 0x0f;
  const authoritative = (flags & 0x0400) !== 0;
  const truncated = (flags & 0x0200) !== 0;
  const recursionDesired = (flags & 0x0100) !== 0;
  const recursionAvailable = (flags & 0x0080) !== 0;
  const rcode = flags & 0x000f;
  const qdCount = (data[offset + 4] << 8) | data[offset + 5];
  const anCount = (data[offset + 6] << 8) | data[offset + 7];
  const nsCount = (data[offset + 8] << 8) | data[offset + 9];
  const arCount = (data[offset + 10] << 8) | data[offset + 11];
  let cursor = offset + 12;
  let name = '';
  let queryType = null;
  let queryClass = null;

  const base = {
    type: 'DNS', id, isResponse, opcode, authoritative, truncated, recursionDesired, recursionAvailable,
    rcode, rcodeName: DNS_RCODE_NAMES[rcode] || `RCODE${rcode}`, qdCount, anCount, nsCount, arCount, answers: [],
  };

  try {
    if (qdCount > 0) {
      const { labels, next } = readDnsName(data, cursor);
      name = labels;
      cursor = next;
      if (cursor + 4 <= data.length) {
        const qtype = (data[cursor] << 8) | data[cursor + 1];
        const qclass = (data[cursor + 2] << 8) | data[cursor + 3];
        queryType = DNS_RECORD_TYPES[qtype] || `TYPE${qtype}`;
        queryClass = qclass === 1 ? 'IN' : qclass;
        cursor += 4;
      }
    }
    // Skip remaining questions (rare to have >1, but stay correct).
    for (let q = 1; q < qdCount && cursor < data.length; q++) {
      const r = readDnsName(data, cursor);
      cursor = r.next + 4;
    }
    // Parse up to a bounded number of answer records for readability + safety.
    const answers = [];
    for (let a = 0; a < anCount && a < 30 && cursor < data.length; a++) {
      const rec = readDnsRecord(data, cursor);
      if (!rec) break;
      answers.push(rec.record);
      cursor = rec.next;
    }
    return { ...base, name, queryType, queryClass, answers };
  } catch {
    return { ...base, name, queryType, queryClass };
  }
}

/** Reads one DNS resource record (used for answers/authority/additional sections). */
function readDnsRecord(data, offset) {
  const { labels: name, next: afterName } = readDnsName(data, offset);
  let cursor = afterName;
  if (cursor + 10 > data.length) return null;
  const type = (data[cursor] << 8) | data[cursor + 1];
  const cls = (data[cursor + 2] << 8) | data[cursor + 3];
  const ttl = readU32(data, cursor + 4);
  const rdLength = (data[cursor + 8] << 8) | data[cursor + 9];
  const rdataStart = cursor + 10;
  const typeName = DNS_RECORD_TYPES[type] || `TYPE${type}`;
  let rdata = null;
  try {
    if (typeName === 'A' && rdLength === 4) rdata = ipv4ToString(data, rdataStart);
    else if (typeName === 'AAAA' && rdLength === 16) rdata = ipv6ToString(data, rdataStart);
    else if (typeName === 'CNAME' || typeName === 'NS' || typeName === 'PTR') rdata = readDnsName(data, rdataStart).labels;
    else if (typeName === 'TXT') rdata = readTxtRdata(data, rdataStart, rdLength);
    else if (typeName === 'MX') rdata = `pref ${( data[rdataStart] << 8) | data[rdataStart + 1]} ${readDnsName(data, rdataStart + 2).labels}`;
    else rdata = `${rdLength} bytes`;
  } catch {
    rdata = `${rdLength} bytes (undecoded)`;
  }
  return {
    record: { name, type: typeName, class: cls === 1 ? 'IN' : cls, ttl, rdata },
    next: rdataStart + rdLength,
  };
}

function readTxtRdata(data, offset, rdLength) {
  const end = offset + rdLength;
  const parts = [];
  let cursor = offset;
  while (cursor < end && cursor < data.length) {
    const len = data[cursor];
    parts.push(String.fromCharCode(...data.slice(cursor + 1, cursor + 1 + len)));
    cursor += 1 + len;
  }
  return parts.join(' ');
}

function readDnsName(data, offset) {
  let labels = [];
  let cursor = offset;
  let guard = 0;
  while (cursor < data.length && data[cursor] !== 0 && guard < 64) {
    const len = data[cursor];
    if ((len & 0xc0) === 0xc0) {
      // Compression pointer: follow it to read the real labels, but the
      // *cursor* for continuing the outer record only advances by 2 bytes.
      const pointer = ((len & 0x3f) << 8) | data[cursor + 1];
      if (pointer < data.length) {
        const followed = readDnsName(data, pointer);
        labels.push(followed.labels);
      }
      cursor += 2;
      return { labels: labels.join('.'), next: cursor };
    }
    cursor += 1;
    labels.push(String.fromCharCode(...data.slice(cursor, cursor + len)));
    cursor += len;
    guard++;
  }
  if (data[cursor] === 0) cursor += 1;
  return { labels: labels.join('.'), next: cursor };
}

function decodeDhcp(data, offset) {
  if (offset + 240 > data.length) return { type: 'DHCP' };
  const op = data[offset];
  const yourIp = ipv4ToString(data, offset + 16);
  const clientIp = ipv4ToString(data, offset + 12);
  let cursor = offset + 240; // fixed header + magic cookie
  const OPTION_NAMES = { 53: 'DHCP Message Type', 50: 'Requested IP', 54: 'Server Identifier', 12: 'Hostname', 51: 'Lease Time' };
  const MSG_TYPES = { 1: 'DISCOVER', 2: 'OFFER', 3: 'REQUEST', 4: 'DECLINE', 5: 'ACK', 6: 'NAK', 7: 'RELEASE', 8: 'INFORM' };
  let messageType = null;
  let hostname = null;
  let guard = 0;
  while (cursor < data.length && data[cursor] !== 0xff && guard < 40) {
    const code = data[cursor];
    if (code === 0) { cursor += 1; continue; }
    const len = data[cursor + 1];
    if (code === 53) messageType = MSG_TYPES[data[cursor + 2]] || data[cursor + 2];
    if (code === 12) hostname = String.fromCharCode(...data.slice(cursor + 2, cursor + 2 + len));
    cursor += 2 + len;
    guard++;
  }
  return { type: 'DHCP', op: op === 1 ? 'BOOTREQUEST' : 'BOOTREPLY', messageType, hostname, yourIp, clientIp };
}

function decodeNtp(data, offset) {
  if (offset >= data.length) return { type: 'NTP' };
  const first = data[offset];
  const mode = first & 0x07;
  const version = (first >> 3) & 0x07;
  const MODE_NAMES = { 3: 'client', 4: 'server', 1: 'symmetric active', 2: 'symmetric passive' };
  return { type: 'NTP', version, mode: MODE_NAMES[mode] || mode };
}

function decodeTextProtocol(data, offset, label) {
  const text = safeAsciiSlice(data, offset, Math.min(offset + 400, data.length));
  const lines = text.split('\r\n').filter(Boolean);
  return { type: label, firstLine: lines[0] || null, lineCount: lines.length };
}

/** Parses a full HTTP request/response (method+path+version, or status
 * line, plus headers) from the remaining bytes of the packet payload. */
function decodeHttp(data, offset) {
  const text = safeAsciiSlice(data, offset, data.length);
  const headerEnd = text.indexOf('\r\n\r\n');
  const headerText = headerEnd >= 0 ? text.slice(0, headerEnd) : text.slice(0, 2000);
  const lines = headerText.split('\r\n');
  const firstLine = lines[0] || '';

  const reqMatch = firstLine.match(/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) (\S+) HTTP\/(\d\.\d)/);
  const respMatch = firstLine.match(/^HTTP\/(\d\.\d) (\d{3}) (.*)$/);
  if (!reqMatch && !respMatch) return null;

  const headers = {};
  for (const line of lines.slice(1)) {
    const idx = line.indexOf(':');
    if (idx > 0) headers[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
  }

  if (reqMatch) {
    return {
      type: 'HTTP', isRequest: true, method: reqMatch[1], path: reqMatch[2], httpVersion: reqMatch[3],
      headers, host: headers.host || null, userAgent: headers['user-agent'] || null,
      contentType: headers['content-type'] || null, contentLength: headers['content-length'] || null,
    };
  }
  return {
    type: 'HTTP', isRequest: false, method: 'RESPONSE', httpVersion: respMatch[1],
    statusCode: Number(respMatch[2]), statusText: respMatch[3], headers,
    contentType: headers['content-type'] || null, contentLength: headers['content-length'] || null, server: headers.server || null,
  };
}

function safeAsciiSlice(data, start, end) {
  end = Math.min(end, data.length);
  if (start >= end) return '';
  let out = '';
  for (let i = start; i < end; i++) {
    const c = data[i];
    out += c >= 32 && c < 127 ? String.fromCharCode(c) : (c === 13 || c === 10 ? String.fromCharCode(c) : '.');
  }
  return out;
}
function readU32(data, offset) {
  return (
    (data[offset] << 24) |
    (data[offset + 1] << 16) |
    (data[offset + 2] << 8) |
    data[offset + 3]
  ) >>> 0;
}

function buildSummary(layers, tags) {
  if (layers.l7?.type === 'DNS' || layers.l7?.type === 'mDNS') {
    const d = layers.l7;
    return d.isResponse
      ? `DNS response (${d.name || ''})`
      : `DNS query for ${d.name || '?'} (${d.queryType || ''})`;
  }
  if (layers.l7?.type === 'TLS') {
    const t = layers.l7;
    // Most TLS packets in a real session are ApplicationData/Alert/ChangeCipherSpec
    // records with no handshakeType at all -- fall back to the record's own content
    // type name instead of printing the literal string "null".
    const label = t.handshakeType || (t.contentTypes && t.contentTypes.length ? t.contentTypes.join('+') : 'Record');
    return `TLS ${label}${t.serverName ? ' to ' + t.serverName : ''}`;
  }
  if (layers.l7?.type === 'HTTP') {
    const h = layers.l7;
    return h.isRequest ? `HTTP ${h.method || 'request'} ${h.path || ''}`.trim() : `HTTP response${h.statusCode ? ' ' + h.statusCode : ''}`;
  }
  if (layers.l3?.type === 'ARP') {
    return `ARP ${layers.l3.op} — who has ${layers.l3.targetIp}?`;
  }
  if (layers.l4?.type === 'TCP') {
    const f = layers.l4.flags;
    const flagStr = Object.entries(f).filter(([, v]) => v).map(([k]) => k).join('/');
    return `TCP ${layers.l4.srcPort} -> ${layers.l4.dstPort} [${flagStr}]`;
  }
  if (layers.l4?.type === 'UDP') {
    return `UDP ${layers.l4.srcPort} -> ${layers.l4.dstPort}`;
  }
  if (layers.l4?.type === 'ICMP' || layers.l4?.type === 'ICMPv6') {
    return `${layers.l4.type} type ${layers.l4.icmpType}`;
  }
  return [...tags].join(', ') || 'Unrecognized frame';
}
