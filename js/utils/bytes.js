/** Small byte/formatting helpers shared across the app. */

export function macToString(bytes, offset) {
  return Array.from(bytes.slice(offset, offset + 6))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(':');
}

export function ipv4ToString(bytes, offset) {
  return `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`;
}

export function ipv6ToString(bytes, offset) {
  const groups = [];
  for (let i = 0; i < 8; i++) {
    const val = (bytes[offset + i * 2] << 8) | bytes[offset + i * 2 + 1];
    groups.push(val.toString(16));
  }
  return groups.join(':').replace(/(^|:)0(:0)+(:|$)/, '::');
}

export function toHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(' ');
}

export function toAscii(bytes) {
  return Array.from(bytes)
    .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
    .join('');
}

export function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

export function formatTimestamp(tsSeconds, tsMicros) {
  const d = new Date(tsSeconds * 1000 + Math.round(tsMicros / 1000));
  return d.toISOString().replace('T', ' ').replace('Z', '');
}
