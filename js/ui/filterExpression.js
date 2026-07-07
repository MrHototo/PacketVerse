/**
 * filterExpression.js
 *
 * A genuine implementation of (a well-scoped, documented subset of)
 * Wireshark's display filter grammar — not a set of per-field special
 * cases. The tokenizer/parser below build a real AST; evaluation is fully
 * generic and type-driven against fieldRegistry.js, so any field added to
 * the registry automatically gets every operator (==, !=, >, <, contains,
 * matches, in{}, ranges, CIDR, slices, bitwise AND, functions...) for free.
 *
 * Supported (see docs/FILTER_SYNTAX.md for the full reference + explicit
 * exclusions): field/protocol existence tests; eq/ne/gt/lt/ge/le and their
 * symbolic + any/all-quantified forms; contains; matches/~ (PCRE-ish regex,
 * case-insensitive by default, "(?-i)" for case-sensitive); membership via
 * `in {a, b, c..d}` including numeric/IP ranges and CIDR entries; logical
 * not/and/xor/or (and !, &&, ||) with correct precedence and parentheses;
 * hex/octal/binary/char integer literals; quoted + raw string literals with
 * escapes; MAC/byte-sequence literals; IPv4/IPv6 literals with CIDR;
 * bitwise AND (&, bitand, bitwise_and); the slice operator ([i:j], [i-j],
 * [i], [:j], [i:], comma-combined slices); and the functions upper(), 
 * lower(), len(), count(), string(), vals(), dec(), hex(), abs(), max(),
 * min(), ip_multicast(), ip_rfc1918(), ip_linklocal(), ip_ula().
 *
 * NOT implemented (documented, not silently mishandled): macros ($name),
 * field references (${frame.time_relative}), arithmetic (+ - * /), the
 * layer (#N) and raw (@) operators. Any of these tokens will currently be
 * rejected by the parser rather than mis-evaluated.
 *
 * On any parse error, compilePacketFilter() falls back to a plain
 * case-insensitive substring search so basic typing never "breaks".
 */

import { resolveField, testProtocolWord, haystackOf } from '../pcap/fieldRegistry.js';
import { isIPv4, isIPv6, cidrMatch, ipSortKey, ipv4ToInt, ipv6ToBigInt, parseByteLiteral } from '../utils/net.js';

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

const KEYWORD_OPS = new Set([
  'eq', 'ne', 'gt', 'lt', 'ge', 'le', 'contains', 'matches', 'in',
  'and', 'or', 'xor', 'not', 'any', 'all', 'bitand', 'bitwise_and',
  'any_eq', 'any_ne', 'all_eq', 'all_ne', 'true', 'false',
]);

function isIdentStart(c) { return /[a-zA-Z_$]/.test(c); }
function isIdentChar(c) { return /[a-zA-Z0-9_.]/.test(c); }

function tokenize(input) {
  const tokens = [];
  let i = 0;
  const n = input.length;
  let bracketDepth = 0; // inside [...] slice syntax, numbers/colons/dashes are
                        // plain slice syntax, not IPv4/byte-sequence literals.
  while (i < n) {
    const c = input[i];
    if (/\s/.test(c)) { i++; continue; }

    // Multi-char operators (longest match first).
    const three = input.slice(i, i + 3);
    if (three === '===') { tokens.push({ t: 'op', v: '==' }); i += 3; continue; }
    const two = input.slice(i, i + 2);
    if (['==', '!=', '>=', '<=', '&&', '||', '!=', '..'].includes(two)) {
      tokens.push({ t: two === '..' ? 'range' : 'op', v: two === '&&' ? 'and' : two === '||' ? 'or' : two });
      i += 2; continue;
    }

    if ('()'.includes(c)) { tokens.push({ t: c }); i++; continue; }
    if ('{}'.includes(c)) { tokens.push({ t: c }); i++; continue; }
    if (c === '[') { tokens.push({ t: c }); bracketDepth++; i++; continue; }
    if (c === ']') { tokens.push({ t: c }); bracketDepth = Math.max(0, bracketDepth - 1); i++; continue; }
    if (c === ',') { tokens.push({ t: ',' }); i++; continue; }
    if (c === '~') { tokens.push({ t: 'op', v: '~' }); i++; continue; }
    if (c === '#') { throw new Error('The layer operator (#) is not supported yet.'); }
    if (c === '@') { throw new Error('The raw/@ operator is not supported yet.'); }
    if (c === '$') { throw new Error('Macros and field references ($name) are not supported yet.'); }
    if ('=><!'.includes(c)) { tokens.push({ t: 'op', v: c === '=' ? '==' : c }); i++; continue; }
    if (c === '&') { tokens.push({ t: 'bitand' }); i++; continue; }
    if (c === '-') {
      // Could be a slice range separator (handled contextually by the
      // caller when inside []), a negative-offset in a slice, or (rarely)
      // a bare minus — arithmetic subtraction itself is out of scope.
      tokens.push({ t: 'dash' }); i++; continue;
    }
    if (c === ':') { tokens.push({ t: ':' }); i++; continue; }

    // Raw string: r"..." — backslashes are preserved literally.
    if (c === 'r' && input[i + 1] === '"') {
      let j = i + 2; let out = '';
      while (j < n && input[j] !== '"') {
        if (input[j] === '\\' && input[j + 1] === '"') { out += '"'; j += 2; continue; }
        out += input[j]; j++;
      }
      tokens.push({ t: 'string', v: out });
      i = j + 1; continue;
    }

    // Double-quoted string with escapes.
    if (c === '"') {
      let j = i + 1; let out = '';
      while (j < n && input[j] !== '"') {
        if (input[j] === '\\') { const r = readEscape(input, j + 1); out += r.ch; j = r.next; }
        else { out += input[j]; j++; }
      }
      tokens.push({ t: 'string', v: out });
      i = j + 1; continue;
    }

    // Regex literal shorthand: /pattern/ (documented extension alongside
    // the spec-accurate quoted-string form used with matches/~).
    if (c === '/') {
      let j = i + 1; let out = '';
      while (j < n && input[j] !== '/') { out += input[j]; j++; }
      tokens.push({ t: 'regex', v: out });
      i = j + 1; continue;
    }

    // Character constant: 'x' or '\xNN' or '\NNN'
    if (c === "'") {
      let j = i + 1; let val;
      if (input[j] === '\\') { const r = readEscape(input, j + 1); val = r.ch.charCodeAt(0); j = r.next; }
      else { val = input.charCodeAt(j); j++; }
      if (input[j] === "'") j++;
      tokens.push({ t: 'number', v: val });
      i = j; continue;
    }

    // Numbers: hex / octal(0o) / binary(0b) / legacy-octal(0NNN) / decimal.
    if (/[0-9]/.test(c)) {
      let j = i;
      let raw = '';
      if (bracketDepth > 0 && !(input.slice(j, j + 2).toLowerCase() === '0x')) {
        while (j < n && /[0-9]/.test(input[j])) { raw += input[j]; j++; }
        tokens.push({ t: 'number', v: parseInt(raw, 10) });
        i = j; continue;
      }
      if (input.slice(j, j + 2).toLowerCase() === '0x') {
        j += 2; while (j < n && /[0-9a-fA-F]/.test(input[j])) { raw += input[j]; j++; }
        tokens.push({ t: 'number', v: parseInt(raw, 16) }); i = j; continue;
      }
      if (input.slice(j, j + 2).toLowerCase() === '0b') {
        j += 2; while (j < n && /[01]/.test(input[j])) { raw += input[j]; j++; }
        tokens.push({ t: 'number', v: parseInt(raw, 2) }); i = j; continue;
      }
      if (input.slice(j, j + 2).toLowerCase() === '0o') {
        j += 2; while (j < n && /[0-7]/.test(input[j])) { raw += input[j]; j++; }
        tokens.push({ t: 'number', v: parseInt(raw, 8) }); i = j; continue;
      }
      // Could be: legacy octal (0 followed only by octal digits), a plain
      // decimal/float, an IPv4 literal, or a byte-sequence literal — those
      // last two need to look ahead past dots, so scan the full "word".
      while (j < n && /[0-9a-fA-F.:\-]/.test(input[j]) && !(input[j] === '.' && input[j + 1] === '.')) { raw += input[j]; j++; }
      // Allow one trailing dot-continuation typical of IPv4/byte literals
      // already consumed above; nothing further to do here.
      if (isIPv4(raw) || (raw.includes('.') && input[j] === '/' )) {
        // IPv4 literal, optionally with /CIDR immediately following.
        let cidr = raw;
        if (input[j] === '/') {
          let k = j + 1; let bits = '';
          while (k < n && /[0-9]/.test(input[k])) { bits += input[k]; k++; }
          cidr += '/' + bits; j = k;
        }
        tokens.push({ t: 'ip', v: cidr }); i = j; continue;
      }
      if (raw.includes(':') || raw.includes('-') || (raw.includes('.') && /[a-fA-F]/.test(raw))) {
        const bytes = parseByteLiteral(raw);
        if (bytes) { tokens.push({ t: 'bytes', v: bytes }); i = j; continue; }
      }
      if (/^0[0-7]+$/.test(raw)) { tokens.push({ t: 'number', v: parseInt(raw, 8) }); i = j; continue; }
      const asNum = Number(raw);
      if (!Number.isNaN(asNum) && /^[0-9.]+$/.test(raw)) { tokens.push({ t: 'number', v: asNum }); i = j; continue; }
      // Fall through: treat as identifier-ish (rare malformed input).
      tokens.push({ t: 'ident', v: raw }); i = j; continue;
    }

    // IPv6 literal (contains ':' and hex groups) or identifiers/keywords.
    if (isIdentStart(c) || c === ':') {
      let j = i;
      while (j < n && (isIdentChar(input[j]) || input[j] === ':' || input[j] === '-')) j++;
      const raw = input.slice(i, j);
      let full = raw;
      if (input[j] === '/' && /:/.test(raw)) {
        let k = j + 1; let bits = '';
        while (k < n && /[0-9]/.test(input[k])) { bits += input[k]; k++; }
        full = raw + '/' + bits; j = k;
      }
      if (isIPv6(raw.split('/')[0])) { tokens.push({ t: 'ip', v: full }); i = j; continue; }
      // Colon/hyphen-separated hex-pair sequences that aren't valid IPv6
      // (most commonly MAC addresses, e.g. "ff:ff:ff:ff:ff:ff") are byte
      // literals, not identifiers.
      if ((raw.includes(':') || raw.includes('-')) && !raw.includes('..')) {
        const asBytes = parseByteLiteral(raw);
        if (asBytes) { tokens.push({ t: 'bytes', v: asBytes }); i = j; continue; }
      }
      const lower = raw.toLowerCase();
      if (lower === 'true' || lower === 'false') { tokens.push({ t: 'bool', v: lower === 'true' }); i = j; continue; }
      tokens.push({ t: KEYWORD_OPS.has(lower) ? 'kw' : 'ident', v: raw }); i = j; continue;
    }

    throw new Error(`Unexpected character '${c}' at position ${i}`);
  }
  return tokens;
}

function readEscape(input, j) {
  const c = input[j];
  const simple = { n: '\n', t: '\t', r: '\r', a: '\x07', b: '\b', f: '\f', v: '\v', '\\': '\\', '"': '"', "'": "'" };
  if (simple[c] !== undefined) return { ch: simple[c], next: j + 1 };
  if (c === 'x') { const hex = input.slice(j + 1, j + 3); return { ch: String.fromCharCode(parseInt(hex, 16) || 0), next: j + 3 }; }
  if (/[0-7]/.test(c)) { const oct = input.slice(j, j + 3); return { ch: String.fromCharCode(parseInt(oct, 8) || 0), next: j + oct.length }; }
  return { ch: c, next: j + 1 };
}

// ---------------------------------------------------------------------------
// Parser (recursive descent). Precedence, highest to lowest:
//   exists (implicit) > not > and > xor > or
// ---------------------------------------------------------------------------

class Parser {
  constructor(tokens) { this.tokens = tokens; this.pos = 0; }
  peek(k = 0) { return this.tokens[this.pos + k]; }
  next() { return this.tokens[this.pos++]; }
  atEnd() { return this.pos >= this.tokens.length; }
  isKw(tok, ...words) { return tok && (tok.t === 'kw' || tok.t === 'op') && words.includes(String(tok.v).toLowerCase()); }

  parseExpr() { return this.parseOr(); }

  parseOr() {
    let left = this.parseXor();
    while (this.isKw(this.peek(), 'or')) { this.next(); left = { type: 'or', left, right: this.parseXor() }; }
    return left;
  }
  parseXor() {
    let left = this.parseAnd();
    while (this.isKw(this.peek(), 'xor')) { this.next(); left = { type: 'xor', left, right: this.parseAnd() }; }
    return left;
  }
  parseAnd() {
    let left = this.parseNot();
    while (this.isKw(this.peek(), 'and')) { this.next(); left = { type: 'and', left, right: this.parseNot() }; }
    return left;
  }
  parseNot() {
    if (this.isKw(this.peek(), 'not', '!')) { this.next(); return { type: 'not', expr: this.parseNot() }; }
    return this.parseGroupOrTest();
  }
  parseGroupOrTest() {
    if (this.peek()?.t === '(') {
      this.next();
      const expr = this.parseExpr();
      if (this.peek()?.t !== ')') throw new Error('Expected closing )');
      this.next();
      return expr;
    }
    return this.parseTest();
  }

  /** A single comparison/exists test: [any|all] valueExpr [ op valueExpr | contains v | matches v | in {set} ] */
  parseTest() {
    let quant = null;
    if (this.isKw(this.peek(), 'any', 'all')) { quant = String(this.next().v).toLowerCase(); }

    const left = this.parseValueExpr();

    const tok = this.peek();
    if (tok && tok.t === 'op' && ['==', '!=', '>', '<', '>=', '<=', '~'].includes(tok.v)) {
      this.next();
      const right = this.parseValueExpr();
      return { type: 'cmp', quant, op: tok.v, left, right };
    }
    if (this.isKw(tok, 'eq', 'ne', 'gt', 'lt', 'ge', 'le', 'any_eq', 'any_ne', 'all_eq', 'all_ne')) {
      const word = String(this.next().v).toLowerCase();
      const opMap = { eq: '==', ne: '!=', gt: '>', lt: '<', ge: '>=', le: '<=', any_eq: '==', any_ne: '!=', all_eq: '==', all_ne: '!=' };
      const quantMap = { any_eq: 'any', any_ne: 'any', all_eq: 'all', all_ne: 'all' };
      const right = this.parseValueExpr();
      return { type: 'cmp', quant: quantMap[word] || quant, op: opMap[word], right, left };
    }
    if (this.isKw(tok, 'contains')) {
      this.next();
      return { type: 'cmp', quant, op: 'contains', left, right: this.parseValueExpr() };
    }
    if (this.isKw(tok, 'matches')) {
      this.next();
      return { type: 'cmp', quant, op: '~', left, right: this.parseValueExpr() };
    }
    if (this.isKw(tok, 'in')) {
      this.next();
      return { type: 'in', quant, left, set: this.parseSet() };
    }
    // No operator: bare existence/truthiness test.
    return { type: 'exists', left, quant };
  }

  parseSet() {
    if (this.peek()?.t !== '{') throw new Error('Expected { after "in"');
    this.next();
    const entries = [];
    while (this.peek() && this.peek().t !== '}') {
      if (this.peek().t === ',') { this.next(); continue; }
      const from = this.parseLiteralValue();
      if (this.peek()?.t === 'range') {
        this.next();
        const to = this.parseLiteralValue();
        entries.push({ range: true, from, to });
      } else {
        entries.push({ range: false, value: from });
      }
    }
    if (this.peek()?.t !== '}') throw new Error('Expected closing } for set');
    this.next();
    return entries;
  }

  /** Value expression: field ref (with optional slice), literal, function call,
   * or a bitwise-AND chain of any of those. */
  parseValueExpr() {
    let left = this.parseValuePrimary();
    while (this.peek()?.t === 'bitand' || this.isKw(this.peek(), 'bitand', 'bitwise_and')) {
      this.next();
      const right = this.parseValuePrimary();
      left = { vtype: 'bitand', left, right };
    }
    return left;
  }

  parseValuePrimary() {
    const tok = this.peek();
    if (!tok) throw new Error('Unexpected end of filter');

    if (tok.t === '(') { this.next(); const v = this.parseValueExpr(); if (this.peek()?.t !== ')') throw new Error('Expected )'); this.next(); return v; }
    if (tok.t === 'number') { this.next(); return { vtype: 'literal', litType: 'number', value: tok.v }; }
    if (tok.t === 'bool') { this.next(); return { vtype: 'literal', litType: 'bool', value: tok.v }; }
    if (tok.t === 'string') { this.next(); return { vtype: 'literal', litType: 'string', value: tok.v }; }
    if (tok.t === 'regex') { this.next(); return { vtype: 'literal', litType: 'regex', value: tok.v }; }
    if (tok.t === 'bytes') { this.next(); return { vtype: 'literal', litType: 'bytes', value: tok.v }; }
    if (tok.t === 'ip') { this.next(); return { vtype: 'literal', litType: 'ip', value: tok.v }; }

    if (tok.t === 'ident') {
      this.next();
      if (this.peek()?.t === '(') return this.parseCall(tok.v);
      let node = { vtype: 'field', name: tok.v };
      if (this.peek()?.t === '[') node = { vtype: 'slice', of: node, slices: this.parseSliceList() };
      return node;
    }
    throw new Error(`Unexpected token: ${JSON.stringify(tok)}`);
  }

  parseCall(name) {
    this.next(); // '('
    const args = [];
    while (this.peek() && this.peek().t !== ')') {
      if (this.peek().t === ',') { this.next(); continue; }
      args.push(this.parseValueExpr());
    }
    if (this.peek()?.t !== ')') throw new Error(`Expected ) closing ${name}(...)`);
    this.next();
    return { vtype: 'call', fn: name.toLowerCase(), args };
  }

  parseSliceList() {
    this.next(); // '['
    const parts = [];
    while (this.peek() && this.peek().t !== ']') {
      if (this.peek().t === ',') { this.next(); continue; }
      parts.push(this.parseOneSlice());
    }
    if (this.peek()?.t !== ']') throw new Error('Expected closing ]');
    this.next();
    return parts;
  }
  parseOneSlice() {
    const readNum = () => {
      let neg = false;
      if (this.peek()?.t === 'dash') { this.next(); neg = true; }
      const t = this.next();
      if (!t || t.t !== 'number') throw new Error('Expected a number inside [...]');
      return neg ? -t.v : t.v;
    };
    if (this.peek()?.t === ':') { this.next(); const j = readNum(); return { start: 0, len: j }; }
    const i = readNum();
    if (this.peek()?.t === ':') {
      this.next();
      if (this.peek() && this.peek().t !== ',' && this.peek().t !== ']') return { start: i, len: readNum() };
      return { start: i, len: null }; // "to end"
    }
    if (this.peek()?.t === 'dash') { this.next(); const end = readNum(); return { start: i, end }; }
    return { start: i, len: 1 };
  }

  parseLiteralValue() {
    const t = this.next();
    if (t.t === 'number') return { litType: 'number', value: t.v };
    if (t.t === 'string') return { litType: 'string', value: t.v };
    if (t.t === 'ip') return { litType: 'ip', value: t.v };
    if (t.t === 'bytes') return { litType: 'bytes', value: t.v };
    if (t.t === 'bool') return { litType: 'bool', value: t.v };
    throw new Error('Expected a literal value in set');
  }
}

export function parseExpression(input) {
  const tokens = tokenize(input.trim());
  if (!tokens.length) return null;
  const parser = new Parser(tokens);
  const ast = parser.parseExpr();
  if (!parser.atEnd()) throw new Error('Unexpected trailing tokens');
  return ast;
}

// ---------------------------------------------------------------------------
// Evaluator — fully generic over field type; never special-cases a field name.
// ---------------------------------------------------------------------------

/** Resolves a value-expression node to { values: [...], type } against one packet. */
function evalValue(node, entry) {
  switch (node.vtype) {
    case 'literal':
      return { values: [node.value], type: node.litType === 'regex' ? 'string' : node.litType };
    case 'field': {
      const dotted = node.name.includes('.');
      const r = dotted ? resolveField(node.name, entry) : resolveBareAsField(node.name, entry);
      return { values: r.values, type: r.type, enumMap: r.enumMap, present: r.present, notAField: r.notAField };
    }
    case 'slice': {
      const base = evalValue(node.of, entry);
      const sliced = base.values.map((v) => applySlices(v, node.slices)).filter((v) => v != null);
      return { values: sliced, type: 'bytes' };
    }
    case 'bitand': {
      const l = evalValue(node.left, entry);
      const r = evalValue(node.right, entry);
      const lv = l.values.map(Number).filter((v) => !Number.isNaN(v));
      const rv = r.values.map(Number).filter((v) => !Number.isNaN(v));
      const out = [];
      for (const a of lv) for (const b of rv) out.push(a & b);
      return { values: out, type: 'number' };
    }
    case 'call':
      return evalCall(node, entry);
    default:
      return { values: [], type: 'string' };
  }
}

function resolveBareAsField(name, entry) {
  const test = testProtocolWord(name, entry);
  if (test !== null) return { values: test ? [true] : [], type: 'bool', present: test };
  // Not a recognized protocol/field word. This word could still be an
  // *unquoted* byte literal used as the operand of a comparison (a common
  // shorthand, e.g. `eth.dst[-1:] == ff`) — give comparisons something real
  // to compare against, while keeping notAField so a genuinely bare,
  // operator-less use of the same word (typing just "ff" alone) still
  // degrades to a plain-text search rather than silently becoming a
  // byte-literal existence test.
  const guess = guessBareLiteral(name);
  return { values: guess ? guess.values : [], type: guess ? guess.type : 'string', present: false, notAField: true };
}

/** Interprets a bare, unrecognized word as an unquoted hex byte-string
 * literal if it plausibly is one (even-length pure hex digits). */
function guessBareLiteral(name) {
  if (/^[0-9a-fA-F]+$/.test(name) && name.length % 2 === 0 && name.length <= 32) {
    const bytes = [];
    for (let i = 0; i < name.length; i += 2) bytes.push(parseInt(name.slice(i, i + 2), 16));
    return { values: [Uint8Array.from(bytes)], type: 'bytes' };
  }
  return null;
}

function applySlices(value, slices) {
  const bytes = toByteArrayLike(value);
  if (!bytes) return null;
  const parts = [];
  for (const s of slices) {
    let start = s.start < 0 ? bytes.length + s.start : s.start;
    let end;
    if (s.end !== undefined) end = (s.end < 0 ? bytes.length + s.end : s.end) + 1;
    else if (s.len == null) end = bytes.length;
    else end = start + s.len;
    parts.push(...bytes.slice(Math.max(0, start), Math.max(0, end)));
  }
  return Uint8Array.from(parts);
}

function toByteArrayLike(value) {
  if (value instanceof Uint8Array) return value;
  if (typeof value === 'string') {
    // MAC addresses / hex byte-strings (e.g. "00:11:22:33:44:55") must be
    // parsed as their actual byte values, not the string's UTF-16 char
    // codes — this is what makes eth.src[0:3] slice the real address bytes.
    const asBytes = parseByteLiteral(value);
    if (asBytes) return asBytes;
    return Uint8Array.from(Array.from(value).map((c) => c.charCodeAt(0) & 0xff));
  }
  return null;
}

function evalCall(node, entry) {
  const args = node.args.map((a) => evalValue(a, entry));
  const firstVals = args[0]?.values ?? [];
  switch (node.fn) {
    case 'upper': return { values: firstVals.map((v) => String(v).toUpperCase()), type: 'string' };
    case 'lower': return { values: firstVals.map((v) => String(v).toLowerCase()), type: 'string' };
    case 'len': return { values: [firstVals.length ? String(firstVals[0]).length : 0], type: 'number' };
    case 'count': return { values: [firstVals.length], type: 'number' };
    case 'string': return { values: firstVals.map((v) => (v instanceof Uint8Array ? Array.from(v).map((b) => b.toString(16)).join('') : String(v))), type: 'string' };
    case 'vals': {
      const enumMap = args[0]?.enumMap;
      if (!enumMap) return { values: firstVals.map(String), type: 'string' };
      const rev = Object.fromEntries(Object.entries(enumMap).map(([k, v]) => [v, k]));
      return { values: firstVals.map((v) => rev[v] || String(v)), type: 'string' };
    }
    case 'dec': return { values: firstVals.map((v) => String(Math.trunc(Number(v)))), type: 'string' };
    case 'hex': return { values: firstVals.map((v) => Number(v).toString(16)), type: 'string' };
    case 'float': case 'double': return { values: firstVals.map(Number), type: 'number' };
    case 'abs': return { values: firstVals.map((v) => Math.abs(Number(v))), type: 'number' };
    case 'max': return { values: [Math.max(...args.flatMap((a) => a.values.map(Number)))], type: 'number' };
    case 'min': return { values: [Math.min(...args.flatMap((a) => a.values.map(Number)))], type: 'number' };
    case 'ip_multicast': return { values: firstVals.map((v) => isMulticastIp(String(v))), type: 'bool' };
    case 'ip_rfc1918': return { values: firstVals.map((v) => isRfc1918(String(v))), type: 'bool' };
    case 'ip_linklocal': return { values: firstVals.map((v) => isLinkLocal(String(v))), type: 'bool' };
    case 'ip_ula': return { values: firstVals.map((v) => String(v).toLowerCase().startsWith('fc') || String(v).toLowerCase().startsWith('fd')), type: 'bool' };
    default: throw new Error(`Unknown function ${node.fn}()`);
  }
}
function isMulticastIp(ip) {
  if (isIPv4(ip)) { const n = ipv4ToInt(ip); return n != null && (n >>> 24) >= 224 && (n >>> 24) <= 239; }
  return ip.toLowerCase().startsWith('ff');
}
function isRfc1918(ip) {
  if (!isIPv4(ip)) return false;
  return cidrMatch(ip, '10.0.0.0/8') || cidrMatch(ip, '172.16.0.0/12') || cidrMatch(ip, '192.168.0.0/16');
}
function isLinkLocal(ip) {
  if (isIPv4(ip)) return cidrMatch(ip, '169.254.0.0/16');
  return ip.toLowerCase().startsWith('fe8') || ip.toLowerCase().startsWith('fe9') || ip.toLowerCase().startsWith('fea') || ip.toLowerCase().startsWith('feb');
}

/** Generic, type-aware comparison between two resolved multi-valued operands. */
function compareResolved(left, op, right, quantify) {
  const lv = left.values;
  const rv = right.values;
  if (!lv.length || !rv.length) return false;

  const test = (a, b) => compareOne(a, op, b, left.type, right.type, left.enumMap);
  const results = [];
  for (const a of lv) for (const b of rv) results.push(test(a, b));
  return quantify === 'all' ? results.every(Boolean) : results.some(Boolean);
}

function compareOne(a, op, b, leftType, rightType, enumMap) {
  // Enum name lookup: `tls.handshake.type == "client_hello"`.
  if (typeof a === 'number' && enumMap && typeof b === 'string') {
    const mapped = enumMap[b.toLowerCase().replace(/[\s-]/g, '_')];
    if (mapped !== undefined) b = mapped;
  }
  // CIDR: ip == a.b.c.d/n
  if ((leftType === 'ip' || rightType === 'ip') && typeof b === 'string' && b.includes('/') && (op === '==' || op === '!=')) {
    const matches = cidrMatch(String(a), b);
    return op === '!=' ? !matches : matches;
  }
  if (op === 'contains') {
    if (a instanceof Uint8Array || b instanceof Uint8Array) return bytesContain(toComparableBytes(a), toComparableBytes(b));
    return String(a).toLowerCase().includes(String(b).toLowerCase());
  }
  // MAC addresses / byte-string fields: compare actual byte values (not the
  // stringified form of a Uint8Array, which would render as "1,2,3,...").
  if ((leftType === 'mac' || leftType === 'bytes' || rightType === 'mac' || rightType === 'bytes' || a instanceof Uint8Array || b instanceof Uint8Array) && (op === '==' || op === '!=')) {
    // A bare number (e.g. `eth.src[0] == 0` or `frame[4] == 0xff`) implicitly
    // converts to a single byte (or the other side's byte length, for
    // multi-byte slices) rather than requiring exact byte-literal syntax.
    const lenHint = a instanceof Uint8Array ? a.length : (b instanceof Uint8Array ? b.length : 1);
    const ab = toComparableBytes(a, lenHint); const bb = toComparableBytes(b, lenHint);
    const eq = ab && bb && ab.length === bb.length && ab.every((x, idx) => x === bb[idx]);
    return op === '!=' ? !eq : !!eq;
  }
  if (op === '~') {
    let pattern = String(b);
    let flags = 'i';
    const csMatch = pattern.match(/^\(\?-i\)/);
    if (csMatch) { pattern = pattern.slice(csMatch[0].length); flags = ''; }
    let re;
    try { re = new RegExp(pattern, flags); } catch { return false; }
    return re.test(String(a));
  }
  if (leftType === 'ip' || rightType === 'ip') {
    if (op === '==' || op === '!=') { const eq = String(a).toLowerCase() === String(b).toLowerCase(); return op === '!=' ? !eq : eq; }
    const ka = ipSortKey(String(a)); const kb = ipSortKey(String(b));
    if (ka == null || kb == null) return false;
    return numericCompare(ka, op, kb);
  }
  if (typeof a === 'boolean' || typeof b === 'boolean' || leftType === 'bool') {
    const av = coerceBool(a); const bv = coerceBool(b);
    return op === '!=' ? av !== bv : av === bv;
  }
  const an = Number(a); const bn = Number(b);
  if (!Number.isNaN(an) && !Number.isNaN(bn) && typeof a !== 'string' || (leftType === 'number' && rightType === 'number')) {
    return numericCompare(an, op, bn);
  }
  const as = String(a).toLowerCase(); const bs = String(b).toLowerCase();
  if (['>', '<', '>=', '<='].includes(op)) return numericCompare(as, op, bs); // lexicographic
  const eq = as === bs;
  return op === '!=' ? !eq : eq;
}
function numericCompare(a, op, b) {
  if (op === '>') return a > b; if (op === '<') return a < b;
  if (op === '>=') return a >= b; if (op === '<=') return a <= b;
  const eq = a === b; return op === '!=' ? !eq : eq;
}
function coerceBool(v) {
  if (typeof v === 'boolean') return v;
  const s = String(v).toLowerCase();
  return s === 'true' || s === '1' || s === 'yes';
}
function toBytes(v) { return v instanceof Uint8Array ? v : Uint8Array.from(String(v).split('').map((c) => c.charCodeAt(0))); }
/** Like toBytes(), but tries to parse hex/MAC-formatted strings as their
 * actual byte values first (falls back to raw char codes otherwise). */
function toComparableBytes(v, lengthHint = 1) {
  if (v instanceof Uint8Array) return v;
  if (typeof v === 'number') {
    const out = []; let n = v;
    for (let i = 0; i < lengthHint; i++) { out.unshift(n & 0xff); n = Math.floor(n / 256); }
    return Uint8Array.from(out);
  }
  const parsed = parseByteLiteral(String(v));
  return parsed || toBytes(v);
}
function bytesContain(hay, needle) {
  outer: for (let i = 0; i <= hay.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return true;
  }
  return needle.length === 0;
}

function evalInSet(left, set, quantify) {
  const values = left.values;
  if (!values.length) return false;
  const test = (v) => set.some((entry) => {
    if (entry.range) {
      const from = entry.from.value, to = entry.to.value;
      if (left.type === 'ip' || entry.from.litType === 'ip') {
        const k = ipSortKey(String(v)); const kf = ipSortKey(String(from)); const kt = ipSortKey(String(to));
        return k != null && kf != null && kt != null && k >= kf && k <= kt;
      }
      const n = Number(v);
      return n >= Number(from) && n <= Number(to);
    }
    return compareOne(v, '==', entry.value.value, left.type, entry.value.litType);
  });
  return quantify === 'all' ? values.every(test) : values.some(test);
}

function evalNode(node, entry) {
  switch (node.type) {
    case 'and': return evalNode(node.left, entry) && evalNode(node.right, entry);
    case 'or': return evalNode(node.left, entry) || evalNode(node.right, entry);
    case 'xor': return evalNode(node.left, entry) !== evalNode(node.right, entry);
    case 'not': return !evalNode(node.expr, entry);
    case 'exists': {
      if (node.left.vtype === 'field' && !node.left.name.includes('.')) {
        const test = testProtocolWord(node.left.name, entry);
        if (test !== null) return test;
      }
      const r = evalValue(node.left, entry);
      if (r.notAField) return textFallback(node.left.name, entry);
      if (node.left.vtype === 'bitand') return r.values.some((v) => Number(v) !== 0);
      if (typeof r.values[0] === 'boolean') return r.values.some(Boolean);
      return r.values.length > 0;
    }
    case 'cmp': {
      const left = evalValue(node.left, entry);
      const right = evalValue(node.right, entry);
      return compareResolved(left, node.op, right, node.quant);
    }
    case 'in': {
      const left = evalValue(node.left, entry);
      return evalInSet(left, node.set, node.quant);
    }
    default: return false;
  }
}

function textFallback(word, entry) {
  return haystackOf(entry).includes(String(word).toLowerCase());
}

export function evaluateOnPacket(ast, entry) {
  return evalNode(ast, entry);
}

/**
 * Compiles a raw user input string into a predicate function over packet
 * entries (as stored in model.packets). Never throws: on any parse error,
 * falls back to substring search over the packet's text haystack, so plain
 * typing (e.g. "google") always still works even though it isn't filter
 * syntax.
 */
export function compilePacketFilter(input) {
  const trimmed = (input || '').trim();
  if (!trimmed) return () => true;
  try {
    const ast = parseExpression(trimmed);
    if (!ast) return () => true;
    return (entry) => evalNode(ast, entry);
  } catch {
    const needle = trimmed.toLowerCase();
    return (entry) => haystackOf(entry).includes(needle);
  }
}
