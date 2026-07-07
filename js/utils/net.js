/** Small IP/CIDR/byte-literal helpers shared by the filter engine. */

export function ipv4ToInt(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  const parts = m.slice(1, 5).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

export function isIPv4(str) {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(str) && ipv4ToInt(str) != null;
}

export function isIPv6(str) {
  if (!/^[0-9a-fA-F:]*:[0-9a-fA-F:]*$/.test(str) || !str.includes(':') || str.length < 2) return false;
  // Disambiguate from a 6-group colon-separated MAC address (e.g.
  // "ff:ff:ff:ff:ff:ff"): a real IPv6 literal either uses "::" or has
  // exactly 8 groups; a MAC always has exactly 6 groups of <=2 hex digits.
  if (!str.includes('::')) {
    const groups = str.split(':');
    if (groups.length === 6 && groups.every((g) => /^[0-9a-fA-F]{1,2}$/.test(g))) return false;
    if (groups.length !== 8) return groups.length === 8; // require full form otherwise
  }
  return true;
}

/** Expands an IPv6 string to a normalized 32-hex-digit form for comparison
 * (good enough for equality/CIDR checks — not a fully spec-perfect parser). */
export function ipv6ToBigInt(ip) {
  const parts = ip.split('::');
  let head = parts[0] ? parts[0].split(':').filter((x) => x !== '') : [];
  let tail = parts.length > 1 && parts[1] ? parts[1].split(':').filter((x) => x !== '') : [];
  if (parts.length === 1) head = ip.split(':');
  const missing = 8 - head.length - tail.length;
  const groups = [...head, ...Array(Math.max(missing, 0)).fill('0'), ...tail].map((g) => g || '0');
  let big = 0n;
  for (const g of groups.slice(0, 8)) big = (big << 16n) | BigInt(parseInt(g, 16) || 0);
  return big;
}

/** Tests `ip == cidr` (e.g. ip.addr == 10.0.0.0/24 or 2001:db8::/32). */
export function cidrMatch(ip, cidr) {
  const slash = cidr.indexOf('/');
  const network = slash >= 0 ? cidr.slice(0, slash) : cidr;
  const bits = slash >= 0 ? parseInt(cidr.slice(slash + 1), 10) : null;
  if (isIPv4(ip) && isIPv4(network)) {
    const ipInt = ipv4ToInt(ip);
    const netInt = ipv4ToInt(network);
    if (bits == null) return ipInt === netInt;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (ipInt & mask) === (netInt & mask);
  }
  if (isIPv6(ip) && isIPv6(network)) {
    const ipBig = ipv6ToBigInt(ip);
    const netBig = ipv6ToBigInt(network);
    if (bits == null) return ipBig === netBig;
    const shift = BigInt(128 - bits);
    return (ipBig >> shift) === (netBig >> shift);
  }
  return false;
}

/** Numeric ordering key for an IP address (used for gt/lt/ge/le and ranges). */
export function ipSortKey(ip) {
  if (isIPv4(ip)) return BigInt(ipv4ToInt(ip) >>> 0);
  if (isIPv6(ip)) return ipv6ToBigInt(ip);
  return null;
}

export function macToInt(mac) {
  const hex = mac.replace(/[:.\-]/g, '');
  if (!/^[0-9a-fA-F]{12}$/.test(hex)) return null;
  return BigInt('0x' + hex);
}

/** Parses a colon/hyphen/dot-separated hex-pair byte literal, e.g. "ff:ff:ff",
 * "aa-bb-cc", "0.1.0.d" -> Uint8Array, or null if it doesn't look like one. */
export function parseByteLiteral(str) {
  const sep = str.includes(':') ? ':' : str.includes('-') ? '-' : str.includes('.') ? '.' : null;
  if (!sep) return /^[0-9a-fA-F]{2}$/.test(str) ? Uint8Array.from([parseInt(str, 16)]) : null;
  const groups = str.split(sep);
  if (!groups.every((g) => /^[0-9a-fA-F]{1,2}$/.test(g))) return null;
  // Disambiguate from an IPv4 literal: only treat dot-separated groups as bytes
  // when at least one group needs a hex letter or a leading zero pair like "0d".
  if (sep === '.' && groups.every((g) => /^\d{1,3}$/.test(g)) && groups.length === 4) {
    if (groups.some((g) => Number(g) > 255)) return null;
    if (!groups.some((g) => /[a-fA-F]/.test(g))) return null; // plain decimal -> let IPv4 parsing claim it
  }
  return Uint8Array.from(groups.map((g) => parseInt(g, 16)));
}

export function bytesToHexColon(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join(':');
}
