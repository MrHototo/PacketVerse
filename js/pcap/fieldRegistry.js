/**
 * fieldRegistry.js
 *
 * A declarative table of Wireshark-style dotted field names, mirroring how
 * Wireshark's own dissectors register fields. This is the single source of
 * truth for "what does field X mean and how do I read it off a decoded
 * packet" — the filter engine (filterExpression.js) never special-cases a
 * field name; it only ever asks this registry to resolve one, then applies
 * fully generic, type-driven comparison logic. That is what lets *any*
 * newly-added field automatically support every operator (==, contains,
 * matches, in{}, slices, CIDR, ranges, etc.) without touching the engine.
 *
 * Each descriptor: { type, proto, get(entry) }
 *   type:  'number' | 'string' | 'bool' | 'ip' | 'mac' | 'bytes'
 *   proto: the protocol namespace this field belongs to (used to decide
 *          whether a packet is even a candidate for this field, and to
 *          power bare protocol-name presence tests like `tls` or `arp`).
 *   get(entry): returns undefined/null (field doesn't apply to this packet),
 *          a single value, or an array of values (fields that can repeat,
 *          e.g. dns.resp.name — one per answer record).
 *   enum:  optional { name -> numeric value } map, so both
 *          `tls.handshake.type==1` and `tls.handshake.type=="client_hello"`
 *          resolve to the same comparison.
 */

const L2 = (e) => e.frame.layers.l2;
const L3 = (e) => e.frame.layers.l3;
const L4 = (e) => e.frame.layers.l4;
const L7 = (e) => e.frame.layers.l7;
const isTcp = (e) => L4(e)?.type === 'TCP';
const isUdp = (e) => L4(e)?.type === 'UDP';
const isIcmp = (e) => L4(e)?.type === 'ICMP' || L4(e)?.type === 'ICMPv6';
const isIp4 = (e) => L3(e)?.type === 'IPv4';
const isIp6 = (e) => L3(e)?.type === 'IPv6';
const isArp = (e) => L3(e)?.type === 'ARP';
const isDns = (e) => L7(e)?.type === 'DNS' || L7(e)?.type === 'mDNS';
const isTls = (e) => L7(e)?.type === 'TLS';
const isHttp = (e) => L7(e)?.type === 'HTTP';
const isDhcp = (e) => L7(e)?.type === 'DHCP';
const isNtp = (e) => L7(e)?.type === 'NTP';
const isSsdp = (e) => L7(e)?.type === 'SSDP';
const answers = (e) => (isDns(e) && Array.isArray(L7(e).answers) ? L7(e).answers : []);
const byType = (e, t) => answers(e).filter((a) => a.type === t).map((a) => a.rdata);
const expert = (e) => e.expertInfo || [];

export const TLS_HANDSHAKE_ENUM = {
  hello_request: 0, client_hello: 1, server_hello: 2, hello_verify_request: 3,
  new_session_ticket: 4, end_of_early_data: 5, encrypted_extensions: 8,
  certificate: 11, server_key_exchange: 12, certificate_request: 13,
  server_hello_done: 14, certificate_verify: 15, client_key_exchange: 16, finished: 20,
};
export const ARP_OPCODE_ENUM = { request: 1, reply: 2 };
export const DHCP_MSGTYPE_ENUM = { discover: 1, offer: 2, request: 3, decline: 4, ack: 5, nak: 6, release: 7, inform: 8 };

// --- helper accessors shared by several descriptors -----------------------
function tcpFlagList(e) {
  if (!isTcp(e)) return [];
  return Object.entries(L4(e).flags).filter(([, v]) => v).map(([k]) => k.toLowerCase());
}

/** The declarative field table. Order doesn't matter; lookup is by exact key. */
export const FIELDS = {
  // ---- frame / meta ----
  'frame.number': { type: 'number', proto: 'frame', get: (e) => (e.index != null ? e.index + 1 : null) },
  'frame.len': { type: 'number', proto: 'frame', get: (e) => e.length },
  'frame.cap_len': { type: 'number', proto: 'frame', get: (e) => e.capturedLength },
  'frame.time_relative': { type: 'number', proto: 'frame', get: (e) => e.frameTimeRelative },
  'frame.time_delta': { type: 'number', proto: 'frame', get: (e) => e.frameTimeDelta },
  'frame.time_epoch': { type: 'number', proto: 'frame', get: (e) => e.ts },
  'frame.protocols': { type: 'string', proto: 'frame', get: (e) => (e.frame.tags || []).join(':').toLowerCase() },

  // ---- ethernet / vlan ----
  'eth.src': { type: 'mac', proto: 'eth', get: (e) => L2(e)?.srcMac },
  'eth.dst': { type: 'mac', proto: 'eth', get: (e) => L2(e)?.dstMac },
  'eth.addr': { type: 'mac', proto: 'eth', get: (e) => [L2(e)?.srcMac, L2(e)?.dstMac].filter(Boolean) },
  'eth.type': { type: 'number', proto: 'eth', get: (e) => L2(e)?.etherType },
  'vlan.id': { type: 'number', proto: 'vlan', get: (e) => L2(e)?.vlanId ?? null },
  'eth.broadcast': { type: 'bool', proto: 'eth', get: (e) => !!L2(e)?.isBroadcast },
  'eth.multicast': { type: 'bool', proto: 'eth', get: (e) => !!L2(e)?.isMulticast },

  // ---- ip (v4) ----
  'ip.src': { type: 'ip', proto: 'ip', get: (e) => (isIp4(e) ? L3(e).srcIp : null) },
  'ip.dst': { type: 'ip', proto: 'ip', get: (e) => (isIp4(e) ? L3(e).dstIp : null) },
  'ip.addr': { type: 'ip', proto: 'ip', get: (e) => (isIp4(e) ? [L3(e).srcIp, L3(e).dstIp] : []) },
  'ip.ttl': { type: 'number', proto: 'ip', get: (e) => (isIp4(e) ? L3(e).ttl : null) },
  'ip.len': { type: 'number', proto: 'ip', get: (e) => (isIp4(e) ? L3(e).totalLength : null) },
  'ip.hdr_len': { type: 'number', proto: 'ip', get: (e) => (isIp4(e) ? L3(e).ihl : null) },
  'ip.proto': { type: 'number', proto: 'ip', get: (e) => (isIp4(e) ? L3(e).protoNum : null) },
  'ip.version': { type: 'number', proto: 'ip', get: (e) => (isIp4(e) ? 4 : null) },

  // ---- ipv6 ----
  'ipv6.src': { type: 'ip', proto: 'ipv6', get: (e) => (isIp6(e) ? L3(e).srcIp : null) },
  'ipv6.dst': { type: 'ip', proto: 'ipv6', get: (e) => (isIp6(e) ? L3(e).dstIp : null) },
  'ipv6.addr': { type: 'ip', proto: 'ipv6', get: (e) => (isIp6(e) ? [L3(e).srcIp, L3(e).dstIp] : []) },
  'ipv6.hlim': { type: 'number', proto: 'ipv6', get: (e) => (isIp6(e) ? L3(e).hopLimit : null) },
  'ipv6.plen': { type: 'number', proto: 'ipv6', get: (e) => (isIp6(e) ? L3(e).payloadLength : null) },
  'ipv6.nxt': { type: 'number', proto: 'ipv6', get: (e) => (isIp6(e) ? L3(e).protoNum : null) },
  'ipv6.version': { type: 'number', proto: 'ipv6', get: (e) => (isIp6(e) ? 6 : null) },

  // ---- generic cross-version convenience (not a real Wireshark field, but
  // extremely useful — documented in the help popover as an extension) ----
  'ip.host': { type: 'ip', proto: 'ip', get: (e) => [L3(e)?.srcIp, L3(e)?.dstIp, L3(e)?.senderIp, L3(e)?.targetIp].filter(Boolean) },

  // ---- arp ----
  'arp.opcode': { type: 'number', proto: 'arp', enum: ARP_OPCODE_ENUM, get: (e) => (isArp(e) ? (L3(e).op === 'REQUEST' ? 1 : L3(e).op === 'REPLY' ? 2 : L3(e).op) : null) },
  'arp.src.proto_ipv4': { type: 'ip', proto: 'arp', get: (e) => (isArp(e) ? L3(e).senderIp : null) },
  'arp.dst.proto_ipv4': { type: 'ip', proto: 'arp', get: (e) => (isArp(e) ? L3(e).targetIp : null) },
  'arp.src.hw_mac': { type: 'mac', proto: 'arp', get: (e) => (isArp(e) ? L3(e).senderMac : null) },
  'arp.dst.hw_mac': { type: 'mac', proto: 'arp', get: (e) => (isArp(e) ? L3(e).targetMac : null) },

  // ---- tcp ----
  'tcp.srcport': { type: 'number', proto: 'tcp', get: (e) => (isTcp(e) ? L4(e).srcPort : null) },
  'tcp.dstport': { type: 'number', proto: 'tcp', get: (e) => (isTcp(e) ? L4(e).dstPort : null) },
  'tcp.port': { type: 'number', proto: 'tcp', get: (e) => (isTcp(e) ? [L4(e).srcPort, L4(e).dstPort] : []) },
  'tcp.seq': { type: 'number', proto: 'tcp', get: (e) => (isTcp(e) ? L4(e).seq : null) },
  'tcp.ack': { type: 'number', proto: 'tcp', get: (e) => (isTcp(e) ? L4(e).ack : null) },
  'tcp.window_size': { type: 'number', proto: 'tcp', get: (e) => (isTcp(e) ? L4(e).window : null) },
  'tcp.len': { type: 'number', proto: 'tcp', get: (e) => (isTcp(e) && L4(e).headerEnd != null ? Math.max(0, (e.capturedLength ?? e.length ?? 0) - L4(e).headerEnd) : null) },
  'tcp.flags': { type: 'number', proto: 'tcp', get: (e) => (isTcp(e) ? tcpFlagBits(L4(e).flags) : null) },
  'tcp.flags.syn': { type: 'bool', proto: 'tcp', get: (e) => (isTcp(e) ? !!L4(e).flags.SYN : null) },
  'tcp.flags.ack': { type: 'bool', proto: 'tcp', get: (e) => (isTcp(e) ? !!L4(e).flags.ACK : null) },
  'tcp.flags.fin': { type: 'bool', proto: 'tcp', get: (e) => (isTcp(e) ? !!L4(e).flags.FIN : null) },
  'tcp.flags.reset': { type: 'bool', proto: 'tcp', get: (e) => (isTcp(e) ? !!L4(e).flags.RST : null) },
  'tcp.flags.push': { type: 'bool', proto: 'tcp', get: (e) => (isTcp(e) ? !!L4(e).flags.PSH : null) },
  'tcp.flags.urg': { type: 'bool', proto: 'tcp', get: (e) => (isTcp(e) ? !!L4(e).flags.URG : null) },
  'tcp.flags.str': { type: 'string', proto: 'tcp', get: (e) => (isTcp(e) ? tcpFlagList(e) : []) },
  'tcp.stream': { type: 'number', proto: 'tcp', get: (e) => (isTcp(e) ? e.tcpAnalysis?.streamIndex ?? null : null) },
  'tcp.analysis.retransmission': { type: 'bool', proto: 'tcp', get: (e) => expert(e).some((x) => x.note?.includes('Retransmission')) },
  'tcp.analysis.duplicate_ack': { type: 'bool', proto: 'tcp', get: (e) => expert(e).some((x) => x.note?.includes('Duplicate ACK')) },
  'tcp.analysis.zero_window': { type: 'bool', proto: 'tcp', get: (e) => expert(e).some((x) => x.note?.includes('Zero window')) },
  'tcp.analysis.flags': { type: 'bool', proto: 'tcp', get: (e) => expert(e).length > 0 },

  // ---- udp ----
  'udp.srcport': { type: 'number', proto: 'udp', get: (e) => (isUdp(e) ? L4(e).srcPort : null) },
  'udp.dstport': { type: 'number', proto: 'udp', get: (e) => (isUdp(e) ? L4(e).dstPort : null) },
  'udp.port': { type: 'number', proto: 'udp', get: (e) => (isUdp(e) ? [L4(e).srcPort, L4(e).dstPort] : []) },
  'udp.length': { type: 'number', proto: 'udp', get: (e) => (isUdp(e) ? L4(e).length : null) },
  'udp.stream': { type: 'number', proto: 'udp', get: (e) => (isUdp(e) ? e.tcpAnalysis?.streamIndex ?? null : null) },

  // ---- convenience port/addr aliases spanning tcp+udp+arp (documented extensions) ----
  'port': { type: 'number', proto: 'l4', get: (e) => [L4(e)?.srcPort, L4(e)?.dstPort].filter((v) => v != null) },
  'srcport': { type: 'number', proto: 'l4', get: (e) => L4(e)?.srcPort ?? null },
  'dstport': { type: 'number', proto: 'l4', get: (e) => L4(e)?.dstPort ?? null },
  'addr': { type: 'ip', proto: 'any', get: (e) => [L3(e)?.srcIp, L3(e)?.dstIp, L3(e)?.senderIp, L3(e)?.targetIp, L2(e)?.srcMac, L2(e)?.dstMac].filter(Boolean) },
  'host': { type: 'string', proto: 'any', get: (e) => [L3(e)?.srcIp, L3(e)?.dstIp].filter(Boolean) },
  'bytes': { type: 'number', proto: 'frame', get: (e) => e.length },
  'len': { type: 'number', proto: 'frame', get: (e) => e.length },

  // ---- icmp ----
  'icmp.type': { type: 'number', proto: 'icmp', get: (e) => (isIcmp(e) ? L4(e).icmpType : null) },
  'icmp.code': { type: 'number', proto: 'icmp', get: (e) => (isIcmp(e) ? L4(e).icmpCode : null) },

  // ---- dns ----
  'dns.qry.name': { type: 'string', proto: 'dns', get: (e) => (isDns(e) ? L7(e).name : null) },
  'dns.qry.type': { type: 'string', proto: 'dns', get: (e) => (isDns(e) ? L7(e).queryType : null) },
  'dns.qry.class': { type: 'string', proto: 'dns', get: (e) => (isDns(e) ? L7(e).queryClass : null) },
  'dns.flags.response': { type: 'bool', proto: 'dns', get: (e) => (isDns(e) ? !!L7(e).isResponse : null) },
  'dns.flags.authoritative': { type: 'bool', proto: 'dns', get: (e) => (isDns(e) ? !!L7(e).authoritative : null) },
  'dns.flags.truncated': { type: 'bool', proto: 'dns', get: (e) => (isDns(e) ? !!L7(e).truncated : null) },
  'dns.flags.recdesired': { type: 'bool', proto: 'dns', get: (e) => (isDns(e) ? !!L7(e).recursionDesired : null) },
  'dns.flags.recavail': { type: 'bool', proto: 'dns', get: (e) => (isDns(e) ? !!L7(e).recursionAvailable : null) },
  'dns.rcode': { type: 'number', proto: 'dns', get: (e) => (isDns(e) ? L7(e).rcode : null) },
  'dns.id': { type: 'number', proto: 'dns', get: (e) => (isDns(e) ? L7(e).id : null) },
  'dns.count.queries': { type: 'number', proto: 'dns', get: (e) => (isDns(e) ? L7(e).qdCount : null) },
  'dns.count.answers': { type: 'number', proto: 'dns', get: (e) => (isDns(e) ? L7(e).anCount : null) },
  'dns.resp.name': { type: 'string', proto: 'dns', get: (e) => answers(e).map((a) => a.name) },
  'dns.resp.type': { type: 'string', proto: 'dns', get: (e) => answers(e).map((a) => a.type) },
  'dns.resp.ttl': { type: 'number', proto: 'dns', get: (e) => answers(e).map((a) => a.ttl) },
  'dns.a': { type: 'ip', proto: 'dns', get: (e) => byType(e, 'A') },
  'dns.aaaa': { type: 'ip', proto: 'dns', get: (e) => byType(e, 'AAAA') },
  'dns.cname': { type: 'string', proto: 'dns', get: (e) => byType(e, 'CNAME') },
  'dns.ns': { type: 'string', proto: 'dns', get: (e) => byType(e, 'NS') },
  'dns.mx.mail_exchange': { type: 'string', proto: 'dns', get: (e) => byType(e, 'MX') },
  'dns.txt': { type: 'string', proto: 'dns', get: (e) => byType(e, 'TXT') },
  'dns.ptr.domain_name': { type: 'string', proto: 'dns', get: (e) => byType(e, 'PTR') },
  'dns.srv.target': { type: 'string', proto: 'dns', get: (e) => byType(e, 'SRV') },
  'dns.time': { type: 'number', proto: 'dns', get: () => null },

  // ---- tls / ssl ----
  // Modeled explicitly (rather than left to the generic namespace fallback,
  // which would just test "is this packet TLS at all") because Wireshark's
  // own `tls.handshake` is a real field meaning specifically "this frame
  // contains a Handshake-content-type record" -- true for ClientHello,
  // ServerHello, Certificate, Finished, etc., false for a packet that's
  // pure ApplicationData/Alert/ChangeCipherSpec.
  'tls.handshake': { type: 'bool', proto: 'tls', get: (e) => (isTls(e) ? ((L7(e).handshakeTypes && L7(e).handshakeTypes.length > 0) || L7(e).contentTypeName === 'Handshake') : null) },
  'tls.record.content_type': { type: 'string', proto: 'tls', get: (e) => (isTls(e) ? L7(e).contentTypes || L7(e).contentTypeName : null) },
  'tls.record.version': { type: 'string', proto: 'tls', get: (e) => (isTls(e) ? L7(e).version : null) },
  'tls.record.length': { type: 'number', proto: 'tls', get: (e) => (isTls(e) ? L7(e).recordLength : null) },
  // Multi-valued: a single packet can carry several concatenated TLS
  // records (e.g. ServerHello+Certificate+ServerHelloDone in one segment),
  // so this checks every handshake record found in the frame, not just the
  // first — `tls.handshake.type==11` correctly matches a packet whose
  // *second* record is a Certificate message, for instance.
  'tls.handshake.type': { type: 'number', proto: 'tls', enum: TLS_HANDSHAKE_ENUM, get: (e) => (isTls(e) ? (L7(e).handshakeMsgTypes?.length ? L7(e).handshakeMsgTypes : (L7(e).msgType != null ? [L7(e).msgType] : [])) : []) },
  'tls.handshake.version': { type: 'string', proto: 'tls', get: (e) => (isTls(e) ? L7(e).clientVersion ?? null : null) },
  'tls.handshake.extensions_server_name': { type: 'string', proto: 'tls', get: (e) => (isTls(e) ? L7(e).serverName ?? null : null) },
  'tls.handshake.ciphersuite': { type: 'string', proto: 'tls', get: (e) => (isTls(e) ? L7(e).cipherSuite?.name ?? null : null) },
  'tls.handshake.ciphersuites': { type: 'string', proto: 'tls', get: (e) => (isTls(e) ? (L7(e).cipherSuites || []).map((c) => c.name) : []) },
  'tls.handshake.extensions_alpn_str': { type: 'string', proto: 'tls', get: (e) => (isTls(e) ? L7(e).alpn || [] : []) },
  'tls.handshake.certificate': { type: 'bool', proto: 'tls', get: (e) => (isTls(e) ? (L7(e).handshakeTypes || []).includes('Certificate') : null) },
  'tls.record.count': { type: 'number', proto: 'tls', get: (e) => (isTls(e) ? L7(e).recordCount ?? 1 : null) },
  'tls.cert.subject': { type: 'string', proto: 'tls', get: (e) => (isTls(e) ? (L7(e).certificates || []).map((c) => c.subjectCN).filter(Boolean) : []) },
  'tls.cert.issuer': { type: 'string', proto: 'tls', get: (e) => (isTls(e) ? (L7(e).certificates || []).map((c) => c.issuerCN).filter(Boolean) : []) },
  'tls.alert_message': { type: 'bool', proto: 'tls', get: (e) => (isTls(e) ? L7(e).contentTypeName === 'Alert' : null) },
  'tls.app_data': { type: 'bool', proto: 'tls', get: (e) => (isTls(e) ? L7(e).contentTypeName === 'ApplicationData' : null) },

  // ---- http ----
  'http.request.method': { type: 'string', proto: 'http', get: (e) => (isHttp(e) ? L7(e).method : null) },
  'http.request.uri': { type: 'string', proto: 'http', get: (e) => (isHttp(e) ? L7(e).path : null) },
  'http.request.full_uri': { type: 'string', proto: 'http', get: (e) => (isHttp(e) ? L7(e).path : null) },
  'http.request': { type: 'bool', proto: 'http', get: (e) => (isHttp(e) ? L7(e).isRequest === true : null) },
  'http.response': { type: 'bool', proto: 'http', get: (e) => (isHttp(e) ? L7(e).isRequest === false : null) },
  'http.response.code': { type: 'number', proto: 'http', get: (e) => (isHttp(e) ? L7(e).statusCode ?? null : null) },
  'http.response.phrase': { type: 'string', proto: 'http', get: (e) => (isHttp(e) ? L7(e).statusText ?? null : null) },
  'http.host': { type: 'string', proto: 'http', get: (e) => (isHttp(e) ? L7(e).host || L7(e).headers?.host || null : null) },
  'http.user_agent': { type: 'string', proto: 'http', get: (e) => (isHttp(e) ? L7(e).userAgent : null) },
  'http.server': { type: 'string', proto: 'http', get: (e) => (isHttp(e) ? L7(e).server : null) },
  'http.content_type': { type: 'string', proto: 'http', get: (e) => (isHttp(e) ? L7(e).contentType : null) },
  'http.content_length': { type: 'number', proto: 'http', get: (e) => (isHttp(e) ? Number(L7(e).contentLength) || null : null) },
  'http.version': { type: 'string', proto: 'http', get: (e) => (isHttp(e) ? L7(e).httpVersion : null) },

  // ---- dhcp ----
  'dhcp.type': { type: 'number', proto: 'dhcp', enum: DHCP_MSGTYPE_ENUM, get: (e) => (isDhcp(e) ? DHCP_MSGTYPE_ENUM[String(L7(e).messageType).toLowerCase()] ?? null : null) },
  'dhcp.hostname': { type: 'string', proto: 'dhcp', get: (e) => (isDhcp(e) ? L7(e).hostname : null) },
  'dhcp.ip.your': { type: 'ip', proto: 'dhcp', get: (e) => (isDhcp(e) ? L7(e).yourIp : null) },
  'dhcp.ip.client': { type: 'ip', proto: 'dhcp', get: (e) => (isDhcp(e) ? L7(e).clientIp : null) },

  // ---- ntp ----
  'ntp.mode': { type: 'string', proto: 'ntp', get: (e) => (isNtp(e) ? String(L7(e).mode) : null) },
  'ntp.version': { type: 'number', proto: 'ntp', get: (e) => (isNtp(e) ? L7(e).version : null) },

  // ---- ssdp (text-protocol summary only) ----
  'ssdp.line': { type: 'string', proto: 'ssdp', get: (e) => (isSsdp(e) ? L7(e).firstLine : null) },

  // ---- expert info ----
  'expert.severity': { type: 'string', proto: 'expert', get: (e) => expert(e).map((x) => x.severity) },
  'expert.message': { type: 'string', proto: 'expert', get: (e) => expert(e).map((x) => x.note) },
};

/** tcp.flags as the packed 6-bit value Wireshark shows, so `tcp.flags & 0x02` works. */
function tcpFlagBits(flags) {
  return (flags.FIN ? 0x01 : 0) | (flags.SYN ? 0x02 : 0) | (flags.RST ? 0x04 : 0) |
    (flags.PSH ? 0x08 : 0) | (flags.ACK ? 0x10 : 0) | (flags.URG ? 0x20 : 0);
}

/** Bare protocol-name presence tests (`tcp`, `dns`, `broadcast`, ...). Anything
 * not listed here but appearing as a dotted field's namespace still degrades
 * gracefully via namespace fallback in resolveField() below. */
export const PROTOCOL_PRESENCE = {
  eth: () => true, frame: () => true,
  ip: isIp4, ipv4: isIp4, ipv6: isIp6, arp: isArp,
  tcp: isTcp, udp: isUdp, icmp: (e) => L4(e)?.type === 'ICMP', icmpv6: (e) => L4(e)?.type === 'ICMPv6',
  dns: isDns, mdns: (e) => L7(e)?.type === 'mDNS', tls: isTls, ssl: isTls, http: isHttp,
  dhcp: isDhcp, ntp: isNtp, ssdp: isSsdp, vlan: (e) => L2(e)?.vlanId != null,
  quic: (e) => (e.frame.tags || []).includes('QUIC'), http2: (e) => (e.frame.tags || []).includes('HTTP2'),
  broadcast: (e) => !!L2(e)?.isBroadcast, multicast: (e) => !!L2(e)?.isMulticast,
  unicast: (e) => !L2(e)?.isBroadcast && !L2(e)?.isMulticast,
  vxlan: () => false, expert: (e) => expert(e).length > 0,
};

/**
 * Resolves a dotted field name against one packet entry. Returns:
 *   { present, values: [...], type, enum }
 * `present` distinguishes "field genuinely has 0 matches" (false) from
 * "field is not modeled AND its protocol isn't even in this packet" (also
 * false, but for a different reason) — both correctly fail an exists test,
 * which is exactly the behavior Wireshark's implicit exists check has.
 */
export function resolveField(rawName, entry) {
  const name = rawName.toLowerCase();
  const desc = FIELDS[name];
  if (desc) {
    const raw = desc.get(entry);
    const values = raw == null ? [] : Array.isArray(raw) ? raw.filter((v) => v != null) : [raw];
    return { present: values.length > 0, values, type: desc.type, enumMap: desc.enum || null };
  }
  // Namespace fallback: unmodeled leaf field, but we recognize the protocol —
  // report existence based on whether that protocol/layer is present at all,
  // so `tls.handshake.extensions_supported_groups` (not deep-decoded) still
  // behaves sanely instead of silently and permanently failing.
  const prefix = name.split('.')[0];
  if (PROTOCOL_PRESENCE[prefix]) {
    const isPresent = PROTOCOL_PRESENCE[prefix](entry);
    return { present: isPresent, values: isPresent ? [true] : [], type: 'bool', enumMap: null };
  }
  return { present: false, values: [], type: 'string', enumMap: null, unknown: true };
}

/** Bare-word protocol test, e.g. `tcp`, `dns`, `broadcast` (no dot at all). */
export function testProtocolWord(word, entry) {
  const fn = PROTOCOL_PRESENCE[word.toLowerCase()];
  return fn ? !!fn(entry) : null;
}

/** Flat lowercase text blob used only as the last-resort fallback for plain
 * (non-filter-syntax) search terms — never used once a real field/operator
 * is recognized. */
export function haystackOf(entry) {
  const l7 = L7(entry);
  return [
    L3(entry)?.srcIp, L3(entry)?.dstIp, L2(entry)?.srcMac, L2(entry)?.dstMac,
    L4(entry)?.type, l7?.type, ...(entry.frame.tags || []),
    l7?.name, l7?.serverName, l7?.method, l7?.host, entry.frame.summary,
  ].filter(Boolean).join(' ').toLowerCase();
}
