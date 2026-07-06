/**
 * filterExpression.js
 * A small Wireshark-style filter expression engine: supports field
 * comparisons (ip.addr==10.0.0.1), boolean composition (and/or/not, &&/||/!),
 * parentheses, and regex matching (field ~ /pattern/ or field ~ "pattern").
 * Bare words (e.g. just typing "dns") match against protocol/tags.
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

const FIELD_ALIASES = {
  'ip.addr': 'addr', 'ip.src': 'src', 'ip.dst': 'dst', 'host': 'addr', 'addr': 'addr',
  'tcp.port': 'port', 'udp.port': 'port', 'port': 'port',
  'tcp.srcport': 'srcport', 'udp.srcport': 'srcport', 'srcport': 'srcport',
  'tcp.dstport': 'dstport', 'udp.dstport': 'dstport', 'dstport': 'dstport',
  'protocol': 'protocol', 'proto': 'protocol', 'ip.proto': 'protocol',
  'app': 'app', 'app.protocol': 'app',
  'bytes': 'bytes', 'packets': 'packets', 'pkts': 'packets',
  'tag': 'tags', 'tags': 'tags', 'tcp.flags': 'flags', 'flags': 'flags',
  'duration': 'duration',
};

function buildFlowContext(flow) {
  return {
    addr: [flow.hostA, flow.hostB],
    src: flow.hostA,
    dst: flow.hostB,
    port: [flow.portA, flow.portB].filter((p) => p != null),
    srcport: flow.portA,
    dstport: flow.portB,
    protocol: flow.protocol,
    app: flow.appProtocol,
    bytes: flow.bytes,
    packets: flow.packets,
    tags: [...flow.tags],
    flags: [...flow.flagsSeen],
    duration: flow.lastSeen - flow.firstSeen,
    _haystack: `${flow.hostA} ${flow.hostB} ${flow.portA ?? ''} ${flow.portB ?? ''} ${flow.protocol} ${flow.appProtocol ?? ''} ${[...flow.tags].join(' ')}`.toLowerCase(),
  };
}

export function evaluateOnFlow(ast, flow) {
  const ctx = buildFlowContext(flow);
  return evalNode(ast, ctx);
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
 * Compiles a raw user input string into a predicate function over flows.
 * Never throws: on any parse error, falls back to substring search.
 */
export function compileFlowFilter(input) {
  const trimmed = (input || '').trim();
  if (!trimmed) return () => true;
  try {
    const ast = parseExpression(trimmed);
    if (!ast) return () => true;
    return (flow) => evaluateOnFlow(ast, flow);
  } catch {
    const needle = trimmed.toLowerCase();
    return (flow) => buildFlowContext(flow)._haystack.includes(needle);
  }
}
