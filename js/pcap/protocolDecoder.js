/**
 * protocolDecoder.js
 * Decodes a raw link-layer frame into a structured, layered object.
 * Deliberately dependency-free so it can run in the browser or a Web Worker.
 */
import { macToString, ipv4ToString, ipv6ToString } from '../utils/bytes.js';

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
    decodeApplication(data, ip, l4, layers, tags, l4.headerEnd);
  } else if (ip.protoNum === 17 && data.length >= offset + 8) {
    const l4 = decodeUdp(data, offset);
    layers.l4 = l4;
    tags.add('UDP');
    decodeApplication(data, ip, l4, layers, tags, offset + 8);
  } else if (ip.protoNum === 1 || ip.protoNum === 58) {
    const type = data[offset];
    const code = data[offset + 1];
    layers.l4 = { type: ip.protoNum === 1 ? 'ICMP' : 'ICMPv6', icmpType: type, icmpCode: code };
    tags.add(ip.protoNum === 1 ? 'ICMP' : 'ICMPv6');
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
    layers.l7 = { type: 'DHCP' };
    tags.add('DHCP');
    return;
  }
  if (proto === 'NTP') {
    layers.l7 = { type: 'NTP' };
    tags.add('NTP');
    return;
  }
  if (proto === 'SSDP') {
    layers.l7 = { type: 'SSDP' };
    tags.add('SSDP');
    return;
  }
  if (dstPort === 443 || srcPort === 443) {
    const tls = decodeTlsClientHello(data, payloadOffset);
    if (tls) {
      layers.l7 = tls;
      tags.add('TLS');
      return;
    }
  }
  const httpGuess = decodeHttpGuess(data, payloadOffset);
  if (httpGuess) {
    layers.l7 = httpGuess;
    tags.add('HTTP');
  }
}

function decodeDns(data, offset) {
  if (offset + 12 > data.length) return null;
  const id = (data[offset] << 8) | data[offset + 1];
  const flags = (data[offset + 2] << 8) | data[offset + 3];
  const isResponse = (flags & 0x8000) !== 0;
  const rcode = flags & 0x000f;
  const qdCount = (data[offset + 4] << 8) | data[offset + 5];
  const anCount = (data[offset + 6] << 8) | data[offset + 7];
  let cursor = offset + 12;
  let name = '';
  const RECORD_TYPES = { 1: 'A', 28: 'AAAA', 5: 'CNAME', 15: 'MX', 16: 'TXT', 2: 'NS', 64: 'SVCB', 65: 'HTTPS' };
  if (qdCount > 0) {
    const { labels, next } = readDnsName(data, cursor);
    name = labels;
    cursor = next;
    if (cursor + 4 > data.length) return { type: 'DNS', isResponse, rcode, name, qdCount, anCount };
    const qtype = (data[cursor] << 8) | data[cursor + 1];
    return {
      type: 'DNS',
      isResponse,
      rcode,
      name,
      queryType: RECORD_TYPES[qtype] || `TYPE${qtype}`,
      qdCount,
      anCount,
    };
  }
  return { type: 'DNS', isResponse, rcode, qdCount, anCount };
}

function readDnsName(data, offset) {
  let labels = [];
  let cursor = offset;
  let guard = 0;
  while (cursor < data.length && data[cursor] !== 0 && guard < 64) {
    const len = data[cursor];
    if ((len & 0xc0) === 0xc0) { cursor += 2; guard++; break; } // compression pointer, stop
    cursor += 1;
    labels.push(
      String.fromCharCode(...data.slice(cursor, cursor + len))
    );
    cursor += len;
    guard++;
  }
  if (data[cursor] === 0) cursor += 1;
  return { labels: labels.join('.'), next: cursor };
}

function decodeTlsClientHello(data, offset) {
  if (offset + 6 > data.length) return null;
  const contentType = data[offset];
  if (contentType !== 0x16) return null; // not a TLS handshake record
  const recordVersion = (data[offset + 1] << 8) | data[offset + 2];
  const handshakeType = data[offset + 5];
  const versionMap = { 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2/1.3' };
  let sni = null;
  // Best-effort SNI extraction (ClientHello only); safe to fail silently.
  try {
    if (handshakeType === 0x01) {
      let cursor = offset + 43; // skip fixed ClientHello fields + random
      const sessionIdLen = data[cursor];
      cursor += 1 + sessionIdLen;
      const cipherSuitesLen = (data[cursor] << 8) | data[cursor + 1];
      cursor += 2 + cipherSuitesLen;
      const compressionLen = data[cursor];
      cursor += 1 + compressionLen;
      const extTotalLen = (data[cursor] << 8) | data[cursor + 1];
      cursor += 2;
      const extEnd = cursor + extTotalLen;
      while (cursor + 4 <= extEnd && cursor + 4 <= data.length) {
        const extType = (data[cursor] << 8) | data[cursor + 1];
        const extLen = (data[cursor + 2] << 8) | data[cursor + 3];
        if (extType === 0x0000) {
          const listLen = (data[cursor + 6] << 8) | data[cursor + 7];
          const nameLen = (data[cursor + 9] << 8) | data[cursor + 10];
          sni = String.fromCharCode(
            ...data.slice(cursor + 11, cursor + 11 + nameLen)
          );
          break;
        }
        cursor += 4 + extLen;
      }
    }
  } catch {
    sni = null;
  }
  return {
    type: 'TLS',
    handshakeType: handshakeType === 0x01 ? 'ClientHello' : handshakeType === 0x02 ? 'ServerHello' : handshakeType,
    version: versionMap[recordVersion] || `0x${recordVersion.toString(16)}`,
    serverName: sni,
  };
}

function decodeHttpGuess(data, offset) {
  const slice = data.slice(offset, Math.min(offset + 16, data.length));
  const text = String.fromCharCode(...slice);
  const methodMatch = text.match(/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) /);
  if (methodMatch) return { type: 'HTTP', method: methodMatch[1] };
  if (text.startsWith('HTTP/1.')) return { type: 'HTTP', method: 'RESPONSE' };
  return null;
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
    return `TLS ${layers.l7.handshakeType}${layers.l7.serverName ? ' to ' + layers.l7.serverName : ''}`;
  }
  if (layers.l7?.type === 'HTTP') {
    return `HTTP ${layers.l7.method}`;
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
