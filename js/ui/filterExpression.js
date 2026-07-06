/**
 * filterExpression.js
 * A Wireshark-style filter expression engine that evaluates directly
 * against individual packets (the same granularity Wireshark's display
 * filter uses), which is what lets a filter like `tls && tcp.port==853`
 * genuinely narrow down to only the matching traffic everywhere in the
 * app (3D scene, packet list, dashboard) instead of just dimming things.
 *
 * Supports field comparisons (ip.addr==10.0.0.1), boolean composition
 * (and/or/not, &&/||/!), parentheses, and regex matching
 * (field ~ /pattern/ or field ~ "pattern"). Bare words (e.g. just typing
 * "dns") match against protocol tags / a text haystack.
 *
 * If parsing fails for any reason, evaluate() falls back to a plain
 * case-insensitive substring search so basic typing never "breaks".
 */

const TOKEN_RE = /\s*(==|!=|>=|<=|&&|\|\||~|>|<|!|\(|\)|"[^"]*"|\/[^/]*\/|[^\s()=!<>~&|]+)/g;

function tokenize(input) {
  const tokens = [];
  let match;
  TOKEN_RE.lastIndex = 0;
  while ((match = TOKEN_RE.exec(input))) {
    if (match[1] !== undefined && match[1] !== '') tokens.push(match[1]);
  }
  return tokens;
}

class Parser {
  constructor(tokens) {
    this.tokens = tokens;
    this.pos = 0;
  }
  peek() { return this.tokens[this.pos]; }
  next() { return this.tokens[this.pos++]; }
  isWord(tok, ...words) { return tok && words.includes(tok.toLowerCase()); }

  parseExpr() { return this.parseOr(); }

  parseOr() {
    let left = this.parseAnd();
    while (this.isWord(this.peek(), 'or', '||')) {
      this.next();
      const right = this.parseAnd();
      left = { type: 'or', left, right };
    }
    return left;
  }

  parseAnd() {
    let left = this.parseNot();
    while (this.peek() && !this.isWord(this.peek(), 'or', '||') && this.peek() !== ')') {
      if (this.isWord(this.peek(), 'and', '&&')) this.next();
      const right = this.parseNot();
      left = { type: 'and', left, right };
    }
    return left;
  }

  parseNot() {
    if (this.isWord(this.peek(), 'not', '!')) {
      this.next();
      return { type: 'not', expr: this.parseNot() };
    }
    return this.parsePrimary();
  }

  parsePrimary() {
    if (this.peek() === '(') {
      this.next();
      const expr = this.parseExpr();
      if (this.peek() === ')') this.next();
      return expr;
    }
    const tok = this.next();
    const opSet = ['==', '!=', '>=', '<=', '>', '<', '~'];
    if (opSet.includes(this.peek())) {
      const op = this.next();
      const valueTok = this.next();
      return { type: 'cmp', field: tok, op, value: stripQuotes(valueTok) };
    }
    return { type: 'bare', value: stripQuotes(tok) };
  }
}

function stripQuotes(tok) {
  if (!tok) return tok;
  if (tok.startsWith('"') && tok.endsWith('"')) return tok.slice(1, -1);
  if (tok.startsWith('/') && tok.endsWith('/')) return { regex: tok.slice(1, -1) };
  return tok;
}

export function parseExpression(input) {
  const tokens = tokenize(input.trim());
  if (!tokens.length) return null;
  const parser = new Parser(tokens);
  const ast = parser.parseExpr();
  if (parser.pos < tokens.length) throw new Error('Unexpected trailing tokens');
  return ast;
}

// Maps Wireshark-style dotted field names to internal context keys built
// per-packet in buildPacketContext() below. Protocol-scoped fields
// (tcp.port vs udp.port, tcp.srcport vs udp.srcport, etc.) resolve to
// keys that are only populated when the packet actually is that protocol,
// so `tcp.port==853` never accidentally matches a UDP packet on port 853.
const FIELD_ALIASES = {
  'ip.addr': 'addr', 'ip.src': 'src', 'ip.dst': 'dst', 'host': 'addr', 'addr': 'addr',
  'ipv6.addr': 'addr', 'ipv6.src': 'src', 'ipv6.dst': 'dst',
  'eth.addr': 'ethaddr', 'eth.src': 'ethsrc', 'eth.dst': 'ethdst',

  'port': 'port', 'srcport': 'srcport', 'dstport': 'dstport',
  'tcp.port': 'tcpport', 'tcp.srcport': 'tcpsrcport', 'tcp.dstport': 'tcpdstport',
  'udp.port': 'udpport', 'udp.srcport': 'udpsrcport', 'udp.dstport': 'udpdstport',

  'tcp.flags.syn': 'flagSyn', 'tcp.flags.ack': 'flagAck', 'tcp.flags.fin': 'flagFin',
  'tcp.flags.rst': 'flagRst', 'tcp.flags.push': 'flagPsh', 'tcp.flags.psh': 'flagPsh',
  'tcp.flags.urg': 'flagUrg',
  'tcp.window_size': 'tcpWindow', 'tcp.seq': 'tcpSeq', 'tcp.ack': 'tcpAck',

  'protocol': 'protocol', 'proto': 'protocol', 'ip.proto': 'protocol', 'frame.protocols': 'protocol',
  'app': 'app', 'app.protocol': 'app',

  'frame.len': 'bytes', 'bytes': 'bytes', 'len': 'bytes',
  'flow.bytes': 'flowBytes', 'flow.packets': 'flowPackets', 'packets': 'flowPackets',
  'tag': 'tags', 'tags': 'tags', 'tcp.flags': 'flagsList', 'flags': 'flagsList',
  'duration': 'flowDuration',

  'vlan.id': 'vlanId',

  'dns.qry.name': 'dnsName', 'dns.resp.name': 'dnsName', 'dns.qry.type': 'dnsType',
  'dns.flags.response': 'dnsResponse', 'dns.qdcount': 'dnsQdCount', 'dns.ancount': 'dnsAnCount',
  'dns.rcode': 'dnsRcode',

  'tls.handshake.type': 'tlsHandshake', 'tls.handshake.extensions_server_name': 'sni',
  'tls.record.version': 'tlsVersion', 'ssl.handshake.type': 'tlsHandshake',

  'http.request.method': 'httpMethod', 'http.method': 'httpMethod',

  'arp.opcode': 'arpOp', 'arp.src.proto_ipv4': 'arpSenderIp', 'arp.dst.proto_ipv4': 'arpTargetIp',

  'icmp.type': 'icmpType', 'icmp.code': 'icmpCode',
};

/** Builds the field context for a single decoded packet entry (from graphModel.packets). */
export function buildPacketContext(entry) {
  const frame = entry.frame;
  const l = frame.layers;
  const l2 = l.l2, l3 = l.l3, l4 = l.l4, l7 = l.l7;

  const protocol = l4?.type || l3?.type || 'OTHER';
  const app = l7?.type || null;
  const flagNames = l4?.type === 'TCP' ? Object.entries(l4.flags).filter(([, v]) => v).map(([k]) => k) : [];
  const isTcp = l4?.type === 'TCP';
  const isUdp = l4?.type === 'UDP';

  const ctx = {
    addr: [l3?.srcIp, l3?.dstIp, l3?.senderIp, l3?.targetIp, l2?.srcMac, l2?.dstMac].filter(Boolean),
    src: l3?.srcIp || l3?.senderIp || l2?.srcMac || null,
    dst: l3?.dstIp || l3?.targetIp || l2?.dstMac || null,
    ethsrc: l2?.srcMac || null,
    ethdst: l2?.dstMac || null,
    ethaddr: [l2?.srcMac, l2?.dstMac].filter(Boolean),

    port: [l4?.srcPort, l4?.dstPort].filter((p) => p != null),
    srcport: l4?.srcPort ?? null,
    dstport: l4?.dstPort ?? null,
    tcpport: isTcp ? [l4?.srcPort, l4?.dstPort].filter((p) => p != null) : [],
    tcpsrcport: isTcp ? l4?.srcPort ?? null : null,
    tcpdstport: isTcp ? l4?.dstPort ?? null : null,
    udpport: isUdp ? [l4?.srcPort, l4?.dstPort].filter((p) => p != null) : [],
    udpsrcport: isUdp ? l4?.srcPort ?? null : null,
    udpdstport: isUdp ? l4?.dstPort ?? null : null,

    flagSyn: isTcp ? !!l4.flags.SYN : false,
    flagAck: isTcp ? !!l4.flags.ACK : false,
    flagFin: isTcp ? !!l4.flags.FIN : false,
    flagRst: isTcp ? !!l4.flags.RST : false,
    flagPsh: isTcp ? !!l4.flags.PSH : false,
    flagUrg: isTcp ? !!l4.flags.URG : false,
    flagsList: flagNames,
    tcpWindow: isTcp ? l4.window : null,
    tcpSeq: isTcp ? l4.seq : null,
    tcpAck: isTcp ? l4.ack : null,

    protocol,
    app,
    bytes: entry.length,
    flowBytes: null, flowPackets: null, flowDuration: null, // filled in by main.js when a flow is known
    tags: frame.tags,
    vlanId: l2?.vlanId ?? null,

    dnsName: l7?.name ?? null,
    dnsType: l7?.queryType ?? null,
    dnsResponse: l7?.isResponse === true,
    dnsQdCount: l7?.qdCount ?? null,
    dnsAnCount: l7?.anCount ?? null,
    dnsRcode: l7?.rcode ?? null,

    tlsHandshake: l7?.type === 'TLS' ? l7.handshakeType : null,
    sni: l7?.type === 'TLS' ? l7.serverName : null,
    tlsVersion: l7?.type === 'TLS' ? l7.version : null,

    httpMethod: l7?.type === 'HTTP' ? l7.method : null,

    arpOp: l3?.type === 'ARP' ? l3.op : null,
    arpSenderIp: l3?.type === 'ARP' ? l3.senderIp : null,
    arpTargetIp: l3?.type === 'ARP' ? l3.targetIp : null,

    icmpType: (l4?.type === 'ICMP' || l4?.type === 'ICMPv6') ? l4.icmpType : null,
    icmpCode: (l4?.type === 'ICMP' || l4?.type === 'ICMPv6') ? l4.icmpCode : null,
  };

  ctx._haystack = [
    ctx.src, ctx.dst, ctx.protocol, ctx.app, ...(ctx.tags || []),
    ctx.dnsName, ctx.sni, ctx.httpMethod, frame.summary,
  ].filter(Boolean).join(' ').toLowerCase();

  return ctx;
}

export function evaluateOnPacket(ast, entry) {
  return evalNode(ast, buildPacketContext(entry));
}

function evalNode(node, ctx) {
  switch (node.type) {
    case 'and': return evalNode(node.left, ctx) && evalNode(node.right, ctx);
    case 'or': return evalNode(node.left, ctx) || evalNode(node.right, ctx);
    case 'not': return !evalNode(node.expr, ctx);
    case 'bare': {
      const needle = String(node.value).toLowerCase();
      return ctx._haystack.includes(needle);
    }
    case 'cmp': {
      const key = FIELD_ALIASES[node.field.toLowerCase()] || node.field.toLowerCase();
      const fieldVal = ctx[key];
      return compare(fieldVal, node.op, node.value);
    }
    default:
      return false;
  }
}

function compare(fieldVal, op, rawValue) {
  if (typeof fieldVal === 'boolean') {
    const truthy = ['1', 'true', 'yes'].includes(String(rawValue).toLowerCase());
    const falsy = ['0', 'false', 'no'].includes(String(rawValue).toLowerCase());
    const wants = truthy ? true : falsy ? false : !!rawValue;
    return op === '!=' ? fieldVal !== wants : fieldVal === wants;
  }

  if (rawValue && typeof rawValue === 'object' && 'regex' in rawValue) {
    let re;
    try { re = new RegExp(rawValue.regex, 'i'); } catch { return false; }
    const values = Array.isArray(fieldVal) ? fieldVal : [fieldVal];
    return values.some((v) => v != null && re.test(String(v)));
  }
  if (op === '~') {
    let re;
    try { re = new RegExp(String(rawValue), 'i'); } catch { return false; }
    const values = Array.isArray(fieldVal) ? fieldVal : [fieldVal];
    return values.some((v) => v != null && re.test(String(v)));
  }

  const numericValue = Number(rawValue);
  const isNumericOp = ['>', '<', '>=', '<='].includes(op);
  if (isNumericOp) {
    const values = Array.isArray(fieldVal) ? fieldVal : [fieldVal];
    return values.some((v) => {
      const n = Number(v);
      if (Number.isNaN(n) || Number.isNaN(numericValue)) return false;
      if (op === '>') return n > numericValue;
      if (op === '<') return n < numericValue;
      if (op === '>=') return n >= numericValue;
      return n <= numericValue;
    });
  }

  const values = (Array.isArray(fieldVal) ? fieldVal : [fieldVal]).map((v) => String(v).toLowerCase());
  const needle = String(rawValue).toLowerCase();
  const matches = values.includes(needle);
  return op === '!=' ? !matches : matches;
}

/**
 * Compiles a raw user input string into a predicate function over packet
 * entries (as stored in model.packets). Never throws: on any parse error,
 * falls back to substring search over the packet's text haystack.
 */
export function compilePacketFilter(input) {
  const trimmed = (input || '').trim();
  if (!trimmed) return () => true;
  try {
    const ast = parseExpression(trimmed);
    if (!ast) return () => true;
    return (entry) => evalNode(ast, buildPacketContext(entry));
  } catch {
    const needle = trimmed.toLowerCase();
    return (entry) => buildPacketContext(entry)._haystack.includes(needle);
  }
}
