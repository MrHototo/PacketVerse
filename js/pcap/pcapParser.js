/**
 * pcapParser.js
 * Zero-dependency binary parser for both classic PCAP and PCAPNG capture
 * files. Runs entirely client-side — no upload, no server round trip.
 *
 * Output: an array of RawPacket objects:
 *   { tsSeconds: number, tsMicros: number, capturedLength: number,
 *     originalLength: number, data: Uint8Array, linkType: number }
 */

const PCAP_MAGIC_US = 0xa1b2c3d4;
const PCAP_MAGIC_US_SWAPPED = 0xd4c3b2a1;
const PCAP_MAGIC_NS = 0xa1b23c4d;
const PCAP_MAGIC_NS_SWAPPED = 0x4d3cb2a1;
const PCAPNG_BLOCK_MAGIC = 0x0a0d0d0a;

export class ParseProgressError extends Error {}

/**
 * Parses an ArrayBuffer containing a .pcap or .pcapng capture.
 * @param {ArrayBuffer} buffer
 * @param {(done: number, total: number) => void} [onProgress]
 * @returns {{ packets: object[], linkTypes: number[] }}
 */
export function parseCapture(buffer, onProgress) {
  if (buffer.byteLength < 4) throw new Error('File too small to be a capture.');
  const view = new DataView(buffer);
  const magic = view.getUint32(0, false);

  if (magic === PCAPNG_BLOCK_MAGIC) {
    return parsePcapNg(buffer, onProgress);
  }
  if (
    magic === PCAP_MAGIC_US ||
    magic === PCAP_MAGIC_US_SWAPPED ||
    magic === PCAP_MAGIC_NS ||
    magic === PCAP_MAGIC_NS_SWAPPED
  ) {
    return parseClassicPcap(buffer, onProgress);
  }
  throw new Error(
    'Unrecognized file format. Expected a .pcap or .pcapng capture.'
  );
}

function parseClassicPcap(buffer, onProgress) {
  const view = new DataView(buffer);
  const magic = view.getUint32(0, false);
  const little =
    magic === PCAP_MAGIC_US_SWAPPED || magic === PCAP_MAGIC_NS_SWAPPED;
  const nanoRes = magic === PCAP_MAGIC_NS || magic === PCAP_MAGIC_NS_SWAPPED;

  const linkType = view.getUint32(20, little);
  let offset = 24; // global header size
  const packets = [];
  const total = buffer.byteLength;

  while (offset + 16 <= total) {
    const tsSec = view.getUint32(offset, little);
    const tsSubSec = view.getUint32(offset + 4, little);
    const inclLen = view.getUint32(offset + 8, little);
    const origLen = view.getUint32(offset + 12, little);
    offset += 16;
    if (offset + inclLen > total) break; // truncated capture, stop gracefully

    const data = new Uint8Array(buffer, offset, inclLen);
    packets.push({
      tsSeconds: tsSec,
      tsMicros: nanoRes ? Math.round(tsSubSec / 1000) : tsSubSec,
      capturedLength: inclLen,
      originalLength: origLen,
      data,
      linkType,
    });
    offset += inclLen;
    if (onProgress && packets.length % 2000 === 0) onProgress(offset, total);
  }
  if (onProgress) onProgress(total, total);
  return { packets, linkTypes: [linkType] };
}

function parsePcapNg(buffer, onProgress) {
  const total = buffer.byteLength;
  let offset = 0;
  let little = true; // determined per-section from the Section Header Block
  const interfaces = []; // { linkType, tsResolution }
  const packets = [];

  while (offset + 12 <= total) {
    const headerView = new DataView(buffer, offset, 8);
    const blockType = headerView.getUint32(0, little);

    // Section Header Block re-establishes byte order for its section.
    if (blockType === PCAPNG_BLOCK_MAGIC) {
      const bomView = new DataView(buffer, offset + 8, 4);
      const bom = bomView.getUint32(0, false);
      little = bom !== 0x1a2b3c4d; // big-endian magic is 0x1A2B3C4D
    }

    const lenView = new DataView(buffer, offset, 12);
    const blockLen = little
      ? lenView.getUint32(4, true)
      : lenView.getUint32(4, false);
    if (blockLen < 12 || offset + blockLen > total) break; // malformed/truncated

    const block = new DataView(buffer, offset, blockLen);
    const type = block.getUint32(0, little);

    if (type === 0x00000001) {
      // Interface Description Block: linktype(2) + reserved(2) + snaplen(4)
      const linkType = block.getUint16(8, little);
      interfaces.push({ linkType, tsResolution: 6 }); // default microseconds
    } else if (type === 0x00000006) {
      // Enhanced Packet Block
      const ifaceId = block.getUint32(8, little);
      const tsHigh = block.getUint32(12, little);
      const tsLow = block.getUint32(16, little);
      const capturedLen = block.getUint32(20, little);
      const originalLen = block.getUint32(24, little);
      const dataStart = offset + 28;
      if (dataStart + capturedLen <= offset + blockLen) {
        const data = new Uint8Array(buffer, dataStart, capturedLen);
        const iface = interfaces[ifaceId] || { linkType: 1, tsResolution: 6 };
        const tsCombined = tsHigh * 2 ** 32 + tsLow; // ticks since epoch
        const divisor = 10 ** iface.tsResolution; // ticks per second
        const tsSeconds = Math.floor(tsCombined / divisor);
        const tsMicros = Math.floor(
          ((tsCombined % divisor) * 1e6) / divisor
        );
        packets.push({
          tsSeconds,
          tsMicros,
          capturedLength: capturedLen,
          originalLength: originalLen,
          data,
          linkType: iface.linkType,
        });
      }
    }
    // Other block types (Simple Packet, Name Resolution, Statistics, custom
    // blocks) are intentionally skipped for this lightweight MVP parser.

    offset += blockLen;
    if (onProgress && packets.length % 2000 === 0) onProgress(offset, total);
  }
  if (onProgress) onProgress(total, total);
  const linkTypes = [...new Set(interfaces.map((i) => i.linkType))];
  return { packets, linkTypes: linkTypes.length ? linkTypes : [1] };
}
