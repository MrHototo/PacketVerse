/**
 * tls.js
 * Deeper TLS record/handshake decoding used by protocolDecoder.js:
 *  - ClientHello: cipher suites, extensions (SNI, ALPN, supported_versions)
 *  - ServerHello: negotiated cipher suite, negotiated version
 *  - Certificate message: walks the certificate chain and extracts
 *    Subject/Issuer CN, validity dates, and serial number from each DER
 *    certificate via a minimal, dependency-free ASN.1 walker.
 *
 * This is intentionally best-effort: real captures often split TLS
 * handshakes (especially Certificate messages) across multiple TCP
 * segments, and single-packet decoding can't reassemble that without a
 * a TCP stream context. When a message is fragmented/short, functions
 * here fail gracefully (return partial data or null) rather than throw.
 */

export const TLS_VERSION_MAP = {
  0x0300: 'SSL 3.0', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3',
};

export const CIPHER_SUITE_NAMES = {
  0x1301: 'TLS_AES_128_GCM_SHA256', 0x1302: 'TLS_AES_256_GCM_SHA384', 0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
  0xc02b: 'ECDHE-ECDSA-AES128-GCM-SHA256', 0xc02c: 'ECDHE-ECDSA-AES256-GCM-SHA384',
  0xc02f: 'ECDHE-RSA-AES128-GCM-SHA256', 0xc030: 'ECDHE-RSA-AES256-GCM-SHA384',
  0xcca8: 'ECDHE-RSA-CHACHA20-POLY1305', 0xcca9: 'ECDHE-ECDSA-CHACHA20-POLY1305',
  0x009c: 'RSA-AES128-GCM-SHA256', 0x009d: 'RSA-AES256-GCM-SHA384',
  0x002f: 'RSA-AES128-SHA', 0x0035: 'RSA-AES256-SHA', 0x000a: 'RSA-3DES-EDE-CBC-SHA', 0x00ff: 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV',
};

const EXT_NAMES = {
  0: 'server_name', 5: 'status_request', 10: 'supported_groups', 11: 'ec_point_formats',
  13: 'signature_algorithms', 16: 'application_layer_protocol_negotiation (ALPN)',
  18: 'signed_certificate_timestamp', 21: 'padding', 23: 'extended_master_secret',
  35: 'session_ticket', 41: 'pre_shared_key', 43: 'supported_versions', 45: 'psk_key_exchange_modes',
  51: 'key_share',
};

function u16(data, o) { return (data[o] << 8) | data[o + 1]; }
function u24(data, o) { return (data[o] << 16) | (data[o + 1] << 8) | data[o + 2]; }

/** Decodes one TLS record's handshake body (ClientHello / ServerHello / Certificate). */
export function decodeHandshakeRecord(data, offset) {
  // TLS record header: type(1) version(2) length(2); handshake header inside: msgType(1) len(3)
  if (offset + 9 > data.length) return null;
  const recordVersion = u16(data, offset + 1);
  const msgType = data[offset + 5];
  const body = { recordVersion, msgType };

  if (msgType === 0x01) return { ...body, ...decodeClientHello(data, offset) };
  if (msgType === 0x02) return { ...body, ...decodeServerHello(data, offset) };
  if (msgType === 0x0b) return { ...body, ...decodeCertificateMessage(data, offset) };
  return body;
}

function decodeClientHello(data, offset) {
  const handshakeType = 'ClientHello';
  let cursor = offset + 9; // record(5) + handshakeType(1) + handshakeLen(3), then clientVersion(2)
  const clientVersion = u16(data, cursor);
  cursor += 2 + 32; // version + random
  const sessionIdLen = data[cursor];
  cursor += 1 + sessionIdLen;
  const cipherSuitesLen = u16(data, cursor);
  cursor += 2;
  const cipherSuites = [];
  for (let i = 0; i < cipherSuitesLen && cursor + i + 1 < data.length; i += 2) {
    const cs = u16(data, cursor + i);
    cipherSuites.push({ id: cs, name: CIPHER_SUITE_NAMES[cs] || `0x${cs.toString(16).padStart(4, '0')}` });
  }
  cursor += cipherSuitesLen;
  const compressionLen = data[cursor];
  cursor += 1 + compressionLen;

  let serverName = null;
  let alpn = [];
  let supportedVersions = [];
  const extensions = [];
  if (cursor + 2 <= data.length) {
    const extTotalLen = u16(data, cursor);
    cursor += 2;
    const extEnd = Math.min(cursor + extTotalLen, data.length);
    while (cursor + 4 <= extEnd) {
      const extType = u16(data, cursor);
      const extLen = u16(data, cursor + 2);
      const extDataStart = cursor + 4;
      extensions.push({ type: extType, name: EXT_NAMES[extType] || `type_${extType}`, length: extLen });
      if (extType === 0 && extDataStart + 5 <= data.length) {
        const nameLen = u16(data, extDataStart + 3);
        serverName = safeAscii(data, extDataStart + 5, extDataStart + 5 + nameLen);
      } else if (extType === 16) {
        let p = extDataStart + 2; // skip ALPN protocol-list length
        const end = extDataStart + extLen;
        while (p < end && p < data.length) {
          const len = data[p];
          alpn.push(safeAscii(data, p + 1, p + 1 + len));
          p += 1 + len;
        }
      } else if (extType === 43) {
        let p = extDataStart + 1; // skip list length byte
        const end = extDataStart + extLen;
        while (p + 1 < end && p + 1 < data.length) {
          const v = u16(data, p);
          supportedVersions.push(TLS_VERSION_MAP[v] || `0x${v.toString(16)}`);
          p += 2;
        }
      }
      cursor += 4 + extLen;
    }
  }

  return {
    handshakeType,
    clientVersion: TLS_VERSION_MAP[clientVersion] || `0x${clientVersion.toString(16)}`,
    serverName,
    cipherSuites,
    cipherSuiteCount: cipherSuites.length,
    alpn,
    supportedVersions,
    extensions,
  };
}

function decodeServerHello(data, offset) {
  let cursor = offset + 9;
  const serverVersion = u16(data, cursor);
  cursor += 2 + 32;
  const sessionIdLen = data[cursor];
  cursor += 1 + sessionIdLen;
  const cipherSuite = cursor + 2 <= data.length ? u16(data, cursor) : null;
  cursor += 2;
  const compressionMethod = data[cursor];
  cursor += 1;
  let negotiatedVersion = TLS_VERSION_MAP[serverVersion] || `0x${serverVersion.toString(16)}`;
  const extensions = [];
  if (cursor + 2 <= data.length) {
    const extTotalLen = u16(data, cursor);
    cursor += 2;
    const extEnd = Math.min(cursor + extTotalLen, data.length);
    while (cursor + 4 <= extEnd) {
      const extType = u16(data, cursor);
      const extLen = u16(data, cursor + 2);
      if (extType === 43 && cursor + 6 <= data.length) {
        const v = u16(data, cursor + 4);
        negotiatedVersion = TLS_VERSION_MAP[v] || negotiatedVersion; // TLS1.3 signals real version here
      }
      extensions.push({ type: extType, name: EXT_NAMES[extType] || `type_${extType}`, length: extLen });
      cursor += 4 + extLen;
    }
  }
  return {
    handshakeType: 'ServerHello',
    negotiatedVersion,
    cipherSuite: cipherSuite != null ? { id: cipherSuite, name: CIPHER_SUITE_NAMES[cipherSuite] || `0x${cipherSuite.toString(16).padStart(4, '0')}` } : null,
    extensions,
  };
}

function decodeCertificateMessage(data, offset) {
  let cursor = offset + 9;
  if (cursor + 3 > data.length) return { handshakeType: 'Certificate', certificates: [] };
  const certsTotalLen = u24(data, cursor);
  cursor += 3;
  const end = Math.min(cursor + certsTotalLen, data.length);
  const certificates = [];
  let guard = 0;
  while (cursor + 3 <= end && guard < 16) {
    guard++;
    const certLen = u24(data, cursor);
    cursor += 3;
    const certBytes = data.slice(cursor, cursor + certLen);
    cursor += certLen;
    // TLS 1.3 certificate entries have a trailing extensions block (2-byte length) per cert.
    if (cursor + 2 <= end) {
      const extLen = u16(data, cursor);
      if (cursor + 2 + extLen <= end + 4) cursor += 2 + extLen;
    }
    const parsed = certBytes.length ? parseX509Certificate(certBytes) : null;
    certificates.push(parsed || { error: 'Certificate truncated across TCP segments (single-packet decode limitation)' });
    if (cursor <= 0 || certLen === 0) break;
  }
  return { handshakeType: 'Certificate', certificateCount: certificates.length, certificates };
}

function safeAscii(data, start, end) {
  end = Math.min(end, data.length);
  if (start < 0 || start >= end) return '';
  return String.fromCharCode(...data.slice(start, end));
}

// ---------------------------------------------------------------------------
// Minimal ASN.1 DER walker + X.509 certificate field extractor.
// Only decodes exactly what's needed (tag/length/value framing, INTEGER,
// SEQUENCE, SET, OID, UTCTime/GeneralizedTime, printable strings) — not a
// general-purpose ASN.1 library.
// ---------------------------------------------------------------------------

const OID_CN = '2.5.4.3';
const OID_O = '2.5.4.10';

function readLength(data, pos) {
  const first = data[pos];
  if (first < 0x80) return { length: first, next: pos + 1 };
  const numBytes = first & 0x7f;
  let length = 0;
  for (let i = 0; i < numBytes; i++) length = (length << 8) | data[pos + 1 + i];
  return { length, next: pos + 1 + numBytes };
}

/** Returns { tag, length, valueStart, next } for the TLV element starting at `pos`. */
function readTlv(data, pos) {
  if (pos >= data.length) return null;
  const tag = data[pos];
  const { length, next } = readLength(data, pos + 1);
  return { tag, length, valueStart: next, next: next + length };
}

function decodeOid(bytes) {
  if (!bytes.length) return '';
  const parts = [];
  const first = bytes[0];
  parts.push(Math.floor(first / 40), first % 40);
  let val = 0;
  for (let i = 1; i < bytes.length; i++) {
    val = (val << 7) | (bytes[i] & 0x7f);
    if (!(bytes[i] & 0x80)) { parts.push(val); val = 0; }
  }
  return parts.join('.');
}

function decodeAsn1Time(bytes) {
  const s = String.fromCharCode(...bytes);
  // UTCTime: YYMMDDHHMMSSZ  |  GeneralizedTime: YYYYMMDDHHMMSSZ
  const m = s.match(/^(\d{2}|\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/);
  if (!m) return s;
  let [, yy, mo, dd, hh, mi, ss] = m;
  const year = yy.length === 2 ? (Number(yy) < 50 ? 2000 + Number(yy) : 1900 + Number(yy)) : Number(yy);
  return new Date(Date.UTC(year, Number(mo) - 1, Number(dd), Number(hh), Number(mi), Number(ss))).toISOString();
}

/** Walks a Name (SEQUENCE of SET of AttributeTypeAndValue) and returns {CN, O}. */
function decodeName(data, start, end) {
  const out = {};
  let pos = start;
  while (pos < end) {
    const setTlv = readTlv(data, pos);
    if (!setTlv) break;
    // Inside the SET is one SEQUENCE { OID, value }
    const seqTlv = readTlv(data, setTlv.valueStart);
    if (seqTlv) {
      const oidTlv = readTlv(data, seqTlv.valueStart);
      if (oidTlv) {
        const oid = decodeOid(data.slice(oidTlv.valueStart, oidTlv.next));
        const valTlv = readTlv(data, oidTlv.next);
        if (valTlv) {
          const text = String.fromCharCode(...data.slice(valTlv.valueStart, valTlv.next));
          if (oid === OID_CN) out.CN = text;
          else if (oid === OID_O) out.O = text;
        }
      }
    }
    pos = setTlv.next;
  }
  return out;
}

/** Best-effort X.509 (DER) certificate field extractor. Returns null if the
 * bytes don't look like a well-formed certificate (e.g. truncated capture). */
export function parseX509Certificate(bytes) {
  try {
    const outer = readTlv(bytes, 0); // Certificate SEQUENCE
    if (!outer || outer.tag !== 0x30) return null;
    const tbs = readTlv(bytes, outer.valueStart); // tbsCertificate SEQUENCE
    if (!tbs || tbs.tag !== 0x30) return null;

    let pos = tbs.valueStart;
    let versionEl = readTlv(bytes, pos);
    let version = 1;
    if (versionEl && versionEl.tag === 0xa0) { // context-specific [0] EXPLICIT version
      const inner = readTlv(bytes, versionEl.valueStart);
      version = inner ? bytesToInt(bytes.slice(inner.valueStart, inner.next)) + 1 : 1;
      pos = versionEl.next;
    }
    const serialEl = readTlv(bytes, pos); // INTEGER serialNumber
    const serial = serialEl ? bytesToHex(bytes.slice(serialEl.valueStart, serialEl.next)) : null;
    pos = serialEl ? serialEl.next : pos;

    const sigAlgEl = readTlv(bytes, pos); // SEQUENCE signature AlgorithmIdentifier
    pos = sigAlgEl ? sigAlgEl.next : pos;

    const issuerEl = readTlv(bytes, pos); // Name
    const issuer = issuerEl ? decodeName(bytes, issuerEl.valueStart, issuerEl.next) : {};
    pos = issuerEl ? issuerEl.next : pos;

    const validityEl = readTlv(bytes, pos); // SEQUENCE { notBefore, notAfter }
    let notBefore = null, notAfter = null;
    if (validityEl) {
      const nb = readTlv(bytes, validityEl.valueStart);
      if (nb) notBefore = decodeAsn1Time(bytes.slice(nb.valueStart, nb.next));
      const na = nb ? readTlv(bytes, nb.next) : null;
      if (na) notAfter = decodeAsn1Time(bytes.slice(na.valueStart, na.next));
      pos = validityEl.next;
    }

    const subjectEl = readTlv(bytes, pos); // Name
    const subject = subjectEl ? decodeName(bytes, subjectEl.valueStart, subjectEl.next) : {};

    const now = Date.now();
    const expired = notAfter ? new Date(notAfter).getTime() < now : null;
    const notYetValid = notBefore ? new Date(notBefore).getTime() > now : null;

    return {
      version,
      serialNumber: serial,
      issuerCN: issuer.CN || null,
      issuerO: issuer.O || null,
      subjectCN: subject.CN || null,
      subjectO: subject.O || null,
      notBefore,
      notAfter,
      isExpired: expired,
      isNotYetValid: notYetValid,
      isSelfSigned: !!(issuer.CN && subject.CN && issuer.CN === subject.CN),
      sizeBytes: bytes.length,
    };
  } catch {
    return null;
  }
}

function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join(':');
}
function bytesToInt(bytes) {
  let v = 0;
  for (const b of bytes) v = (v << 8) | b;
  return v;
}
