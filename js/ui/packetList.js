/**
 * packetList.js
 * A Wireshark-style packet list table: No. / Time / Source / Destination /
 * Protocol / Length / Info columns, respecting whatever filter + time range
 * is currently active. Clicking a row opens that packet in the Inspector
 * and focuses its conversation in the 3D scene — this is the direct,
 * list-driven way to browse and drill into traffic, complementing
 * click-in-3D navigation.
 */
import { colorForProtocol, hexToCss } from '../utils/colors.js';

const MAX_ROWS = 1500;

export class PacketList {
  constructor(container, { onSelectPacket } = {}) {
    this.container = container;
    this.onSelectPacket = onSelectPacket || (() => {});
    this.packets = [];
    this.t0 = 0;
    this.selectedIndex = null;
    this._renderShell();
  }

  _renderShell() {
    this.container.innerHTML = `
      <div class="pktlist-head">
        <span class="pktlist-col pktlist-no">No.</span>
        <span class="pktlist-col pktlist-time">Time</span>
        <span class="pktlist-col pktlist-src">Source</span>
        <span class="pktlist-col pktlist-dst">Destination</span>
        <span class="pktlist-col pktlist-proto">Protocol</span>
        <span class="pktlist-col pktlist-len">Length</span>
        <span class="pktlist-col pktlist-info">Info</span>
      </div>
      <div class="pktlist-body" id="pktlist-body"></div>
      <div class="pktlist-footer" id="pktlist-footer"></div>
    `;
    this.body = this.container.querySelector('#pktlist-body');
    this.footer = this.container.querySelector('#pktlist-footer');
  }

  /** @param {Array} packets already time/filter-narrowed, ideally sorted by ts. */
  setPackets(packets, t0) {
    this.packets = packets;
    this.t0 = t0 ?? (packets[0]?.ts || 0);
    this._render();
  }

  _render() {
    const shown = this.packets.slice(0, MAX_ROWS);
    this.body.innerHTML = shown.length
      ? shown.map((p, i) => rowHtml(p, i, this.t0)).join('')
      : `<div class="pktlist-empty">No packets match the current filter${''}.</div>`;

    this.footer.textContent = this.packets.length > MAX_ROWS
      ? `Showing first ${MAX_ROWS.toLocaleString()} of ${this.packets.length.toLocaleString()} matching packets — narrow your filter to see more precisely.`
      : `${this.packets.length.toLocaleString()} packet${this.packets.length === 1 ? '' : 's'}${this.packets.length ? ' matching current filter/time range' : ''}`;

    this.body.querySelectorAll('[data-pidx]').forEach((row) => {
      row.addEventListener('click', () => {
        this.body.querySelectorAll('.pktlist-row.selected').forEach((r) => r.classList.remove('selected'));
        row.classList.add('selected');
        const entry = shown[Number(row.dataset.pidx)];
        if (entry) this.onSelectPacket(entry);
      });
    });
  }
}

function rowHtml(p, i, t0) {
  const l = p.frame.layers;
  const src = p.frame.endpointA || l.l2?.srcMac || '?';
  const dst = p.frame.endpointB || l.l2?.dstMac || '?';
  const proto = l.l7?.type || l.l4?.type || l.l3?.type || 'OTHER';
  const t = Math.max(0, p.ts - t0).toFixed(6);
  const color = hexToCss(colorForProtocol(proto));
  return `<div class="pktlist-row" data-pidx="${i}" title="Click to inspect this packet">
    <span class="pktlist-col pktlist-no">${p.index + 1}</span>
    <span class="pktlist-col pktlist-time">${t}</span>
    <span class="pktlist-col pktlist-src mono">${escapeHtml(String(src))}</span>
    <span class="pktlist-col pktlist-dst mono">${escapeHtml(String(dst))}</span>
    <span class="pktlist-col pktlist-proto"><span class="proto-chip" style="border-color:${color};color:${color}">${escapeHtml(proto)}</span></span>
    <span class="pktlist-col pktlist-len">${p.length}</span>
    <span class="pktlist-col pktlist-info">${escapeHtml(p.frame.summary || '')}</span>
  </div>`;
}

function escapeHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
