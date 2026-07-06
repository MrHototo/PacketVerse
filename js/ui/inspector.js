/**
 * inspector.js
 * Right-hand detail panel with breadcrumb drill-down: Host -> its flows ->
 * a flow's detail (+ Follow Stream) -> its packets -> full Wireshark-style
 * packet decode (Frame / Ethernet II / Internet Protocol / TCP-UDP-ICMP /
 * application layer, hex/ASCII, plain-English explanation). Every list row
 * is clickable. Lists respect the currently active filter/time-range so
 * drilling into a host or flow only shows what's actually still visible
 * elsewhere in the app.
 */
import { toHex, toAscii, formatBytes, formatTimestamp } from '../utils/bytes.js';
import { explainFlow, explainPacket } from './explainer.js';

const SKIP_FIELDS = new Set(['type', 'headerEnd', 'protoNum']);

const FIELD_LABELS = {
  srcMac: 'Source', dstMac: 'Destination', etherType: 'Type', vlanId: 'VLAN ID',
  isBroadcast: 'Destination is broadcast', isMulticast: 'Destination is multicast',
  ihl: 'Header Length', totalLength: 'Total Length', ttl: 'Time to Live',
  protocol: 'Protocol', srcIp: 'Source Address', dstIp: 'Destination Address',
  payloadLength: 'Payload Length', hopLimit: 'Hop Limit',
  op: 'Opcode', senderMac: 'Sender MAC Address', senderIp: 'Sender IP Address',
  targetMac: 'Target MAC Address', targetIp: 'Target IP Address',
  srcPort: 'Source Port', dstPort: 'Destination Port', seq: 'Sequence Number',
  ack: 'Acknowledgment Number', window: 'Window Size', length: 'Length',
  icmpType: 'Type', icmpCode: 'Code',
  isResponse: 'Is Response', rcode: 'Response Code', name: 'Name',
  queryType: 'Query Type', qdCount: 'Questions', anCount: 'Answers',
  handshakeType: 'Handshake Type', version: 'Record Version', serverName: 'Server Name (SNI)',
  method: 'Method',
};

export class Inspector {
  constructor(panelEl, breadcrumbEl, { model, onFocusHost, onFocusFlow } = {}) {
    this.panel = panelEl;
    this.breadcrumbEl = breadcrumbEl;
    this.model = model || null;
    this.onFocusHost = onFocusHost || (() => {});
    this.onFocusFlow = onFocusFlow || (() => {});
    this.stack = [];
    this.filterState = { filterActive: false, activeFlowKeys: null, activePacketIndexSet: null };
    this.showEmpty();
  }

  setModel(model) {
    this.model = model;
  }

  /** Called by main.js whenever the filter/time-range changes, so open drill-down
   * lists stay consistent with what's actually visible in the 3D scene / packet list. */
  setFilterState(state) {
    this.filterState = state;
    if (this.stack.length) this._render();
  }

  showEmpty() {
    this.stack = [];
    this._renderBreadcrumb();
    this.panel.innerHTML = `
      <div class="inspector-empty">
        <p>Click any node, connection, or packet-list row to see details here.</p>
        <p class="hint">Hover for a quick summary, click for the full breakdown — then drill from host &rarr; conversation &rarr; packet, or follow a stream.</p>
      </div>`;
  }

  showHost(host) {
    this._navigate({ type: 'host', data: host, label: shorten(host.id) }, true);
  }
  showFlow(flow) {
    this._navigate({ type: 'flow', data: flow, label: `${shorten(flow.hostA)} \u2194 ${shorten(flow.hostB)}` }, true);
  }
  showPacket(entry) {
    this._navigate({ type: 'packet', data: entry, label: `Packet #${entry.index + 1}` }, true);
  }

  _navigate(node, reset) {
    if (reset) this.stack = [node];
    else this.stack.push(node);
    this._render();
  }

  _render() {
    this._renderBreadcrumb();
    const top = this.stack[this.stack.length - 1];
    if (!top) return this.showEmpty();
    if (top.type === 'host') this._renderHost(top.data);
    else if (top.type === 'flow') this._renderFlow(top.data);
    else if (top.type === 'stream') this._renderStream(top.data);
    else this._renderPacket(top.data);
  }

  _renderBreadcrumb() {
    if (!this.breadcrumbEl) return;
    if (this.stack.length <= 1) {
      this.breadcrumbEl.innerHTML = '';
      return;
    }
    this.breadcrumbEl.innerHTML = this.stack
      .map((node, i) => {
        const isLast = i === this.stack.length - 1;
        return isLast
          ? `<span class="breadcrumb-current">${escapeHtml(node.label)}</span>`
          : `<a class="breadcrumb-item" data-idx="${i}">${escapeHtml(node.label)}</a><span class="breadcrumb-sep">/</span>`;
      })
      .join('');
    this.breadcrumbEl.querySelectorAll('.breadcrumb-item').forEach((el) => {
      el.addEventListener('click', () => {
        this.stack = this.stack.slice(0, Number(el.dataset.idx) + 1);
        this._render();
      });
    });
  }

  _renderHost(host) {
    const allFlows = this._flowsForHost(host.id);
    const { filterActive, activeFlowKeys } = this.filterState;
    const flows = filterActive && activeFlowKeys ? allFlows.filter((f) => activeFlowKeys.has(f.key)) : allFlows;
    const sortedFlows = [...flows].sort((a, b) => b.bytes - a.bytes);
    const filterNote = filterActive
      ? `<p class="hint">${flows.length} of ${allFlows.length} conversations shown — narrowed by the current filter.</p>`
      : '';
    this.panel.innerHTML = `
      <h3>${escapeHtml(host.id)}</h3>
      <div class="kv"><span>Role</span><b>${host.isCluster ? 'Subnet cluster' : host.isIp ? 'IP host' : 'MAC-only host'}</b></div>
      <div class="kv"><span>Packets</span><b>${host.packets}</b></div>
      <div class="kv"><span>Bytes</span><b>${formatBytes(host.bytes)}</b></div>
      <div class="kv"><span>Protocols seen</span><b>${[...host.protocols].join(', ') || '—'}</b></div>
      <div class="kv"><span>First seen</span><b>${new Date(host.firstSeen * 1000).toLocaleTimeString()}</b></div>
      <div class="kv"><span>Last seen</span><b>${new Date(host.lastSeen * 1000).toLocaleTimeString()}</b></div>
      <div class="explain">${host.isCluster
        ? `This is a collapsed group of ${host.memberIds?.length ?? 0} hosts on the same subnet, shown as one node to reduce clutter. Click it in the 3D view to expand.`
        : `This device sent or received ${host.packets} packets in the capture, communicating using ${[...host.protocols].slice(0, 4).join(', ') || 'unknown protocols'}.`}</div>
      <h4>Conversations (${sortedFlows.length}) <span class="hint">— click to drill in</span></h4>
      ${filterNote}
      <div class="drill-list">
        ${sortedFlows
          .slice(0, 60)
          .map(
            (f) => `
          <div class="drill-row" data-flow-key="${escapeAttr(f.key)}">
            <span class="drill-main">${escapeHtml(shorten(f.hostA))} \u2194 ${escapeHtml(shorten(f.hostB))} (${escapeHtml(f.appProtocol || f.protocol)})</span>
            <span class="drill-meta">${formatBytes(f.bytes)}</span>
          </div>`
          )
          .join('') || '<p class="hint">No conversations to show for the current filter/time range.</p>'}
      </div>
    `;
    this.panel.querySelectorAll('[data-flow-key]').forEach((row) => {
      row.addEventListener('click', () => {
        const flow = this._flowByKey(row.dataset.flowKey);
        if (!flow) return;
        this.onFocusFlow(flow);
        this._navigate({ type: 'flow', data: flow, label: `${shorten(flow.hostA)} \u2194 ${shorten(flow.hostB)}` }, false);
      });
    });
  }

  _renderFlow(flow) {
    const explanation = explainFlow(flow);
    const allPackets = this._packetsForFlow(flow);
    const { filterActive, activePacketIndexSet } = this.filterState;
    const packets = filterActive && activePacketIndexSet
      ? allPackets.filter((p) => activePacketIndexSet.has(p.index))
      : allPackets;
    const filterNote = filterActive
      ? `<p class="hint">${packets.length} of ${allPackets.length} packets shown — narrowed by the current filter.</p>`
      : '';
    this.panel.innerHTML = `
      <h3>${escapeHtml(flow.hostA)} \u2194 ${escapeHtml(flow.hostB)}</h3>
      <div class="kv"><span>Protocol</span><b>${flow.protocol}${flow.appProtocol ? ' / ' + flow.appProtocol : ''}</b></div>
      <div class="kv"><span>Ports</span><b>${flow.portA ?? '—'} \u2192 ${flow.portB ?? '—'}</b></div>
      <div class="kv"><span>Packets</span><b>${flow.packets}</b></div>
      <div class="kv"><span>Bytes</span><b>${formatBytes(flow.bytes)}</b></div>
      <div class="kv"><span>Duration</span><b>${(flow.lastSeen - flow.firstSeen).toFixed(2)}s</b></div>
      <div class="kv"><span>TCP flags seen</span><b>${[...flow.flagsSeen].join(', ') || '—'}</b></div>
      <div class="explain">${explanation.plain}</div>
      <div class="drill-actions">
        <button class="btn btn-ghost" id="follow-stream-btn">\u21c6 Follow this stream</button>
      </div>
      <h4>Packets (${packets.length}) <span class="hint">— click to inspect</span></h4>
      ${filterNote}
      <div class="drill-list">
        ${packets
          .slice(0, 200)
          .map(
            (p) => `
          <div class="drill-row" data-packet-index="${p.index}">
            <span class="drill-main">#${p.index + 1} — ${escapeHtml(p.frame.summary || '')}</span>
            <span class="drill-meta">${p.length}B</span>
          </div>`
          )
          .join('') || '<p class="hint">No packets to show for the current filter/time range.</p>'}
        ${packets.length > 200 ? `<p class="hint">Showing first 200 of ${packets.length} packets.</p>` : ''}
      </div>
    `;
    this.panel.querySelectorAll('[data-packet-index]').forEach((row) => {
      row.addEventListener('click', () => {
        const entry = this.model?.packets[Number(row.dataset.packetIndex)];
        if (!entry) return;
        this._navigate({ type: 'packet', data: entry, label: `Packet #${entry.index + 1}` }, false);
      });
    });
    this.panel.querySelector('#follow-stream-btn')?.addEventListener('click', () => {
      this._navigate({ type: 'stream', data: flow, label: 'Follow stream' }, false);
    });
  }

  _renderStream(flow) {
    const packets = this._packetsForFlow(flow);
    const blocks = [];
    let shownBytes = 0;
    const MAX_PACKETS = 400;
    for (const p of packets.slice(0, MAX_PACKETS)) {
      const offset = p.frame.payloadOffset;
      if (offset == null || offset >= p.data.length) continue;
      const payload = p.data.slice(offset);
      if (!payload.length) continue;
      const isAtoB = p.frame.endpointA === flow.hostA;
      const ascii = toAscii(payload).slice(0, 2000);
      shownBytes += payload.length;
      blocks.push(`
        <div class="stream-block ${isAtoB ? 'stream-a' : 'stream-b'}">
          <div class="stream-meta">#${p.index + 1} \u00b7 ${isAtoB ? escapeHtml(shorten(flow.hostA)) + ' \u2192 ' + escapeHtml(shorten(flow.hostB)) : escapeHtml(shorten(flow.hostB)) + ' \u2192 ' + escapeHtml(shorten(flow.hostA))} \u00b7 ${payload.length}B</div>
          <pre class="stream-payload">${escapeHtml(ascii)}${payload.length > 2000 ? '\u2026' : ''}</pre>
        </div>`);
    }
    this.panel.innerHTML = `
      <h3>Follow Stream</h3>
      <div class="kv"><span>Conversation</span><b>${escapeHtml(flow.hostA)} \u2194 ${escapeHtml(flow.hostB)}</b></div>
      <div class="kv"><span>Payload shown</span><b>${formatBytes(shownBytes)} across ${Math.min(packets.length, MAX_PACKETS)} packets</b></div>
      <p class="hint">This is a simplified, chronological view of application-layer bytes per packet (colored by direction) — unlike Wireshark's TCP reassembly, out-of-order or retransmitted segments are not reordered or deduplicated here.</p>
      <div class="stream-view">
        ${blocks.join('') || '<p class="hint">No decodable application-layer payload was found in this conversation.</p>'}
      </div>
    `;
  }

  _renderPacket(entry) {
    const explanation = explainPacket(entry);
    const hex = toHex(entry.data);
    const ascii = toAscii(entry.data);
    const flow = entry.flowKey ? this._flowByKey(entry.flowKey) : null;
    this.panel.innerHTML = `
      <h3>Packet #${entry.index + 1}</h3>
      <div class="kv"><span>Time</span><b>${formatTimestamp(entry.tsSeconds, entry.tsMicros)}</b></div>
      <div class="kv"><span>Length</span><b>${entry.length} bytes</b></div>
      <div class="kv"><span>Summary</span><b>${escapeHtml(entry.frame.summary)}</b></div>
      <div class="explain"><b>In plain English:</b> ${explanation.plain}</div>
      <div class="explain-tech">${escapeHtml(explanation.technical)}</div>
      ${flow ? `<div class="drill-actions">
        <button class="btn btn-ghost" id="view-convo-btn">\u2194 View full conversation</button>
        <button class="btn btn-ghost" id="follow-stream-btn2">\u21c6 Follow this stream</button>
      </div>` : ''}
      <h4>Layers</h4>
      ${renderFrameBlock(entry)}
      ${renderLayers(entry.frame.layers)}
      <h4>Hex / ASCII</h4>
      <div class="hexview">${hex.slice(0, 4000)}${hex.length > 4000 ? '\u2026' : ''}</div>
      <div class="asciiview">${escapeHtml(ascii.slice(0, 400))}${ascii.length > 400 ? '\u2026' : ''}</div>
    `;
    this.panel.querySelector('#view-convo-btn')?.addEventListener('click', () => {
      this._navigate({ type: 'flow', data: flow, label: `${shorten(flow.hostA)} \u2194 ${shorten(flow.hostB)}` }, false);
    });
    this.panel.querySelector('#follow-stream-btn2')?.addEventListener('click', () => {
      this._navigate({ type: 'flow', data: flow, label: `${shorten(flow.hostA)} \u2194 ${shorten(flow.hostB)}` }, false);
      this._navigate({ type: 'stream', data: flow, label: 'Follow stream' }, false);
    });
  }

  _flowsForHost(hostId) {
    if (!this.model) return [];
    const out = [];
    for (const flow of this.model.flows.values()) {
      if (flow.hostA === hostId || flow.hostB === hostId) out.push(flow);
    }
    return out;
  }

  _flowByKey(key) {
    return this.model?.flows.get(key) || null;
  }

  _packetsForFlow(flow) {
    if (!this.model) return [];
    if (flow.packetIndices && flow.packetIndices.length) {
      return flow.packetIndices.map((i) => this.model.packets[i]).filter(Boolean);
    }
    return this.model.packets.filter((p) => p.flowKey === flow.key);
  }
}

/** Synthesizes a Wireshark-style "Frame" section from packet metadata (not a real protocol layer). */
function renderFrameBlock(entry) {
  const rows = [
    ['Frame Number', entry.index + 1],
    ['Captured Length', `${entry.capturedLength} bytes`],
    ['Length on Wire', `${entry.length} bytes`],
    ['Capture Time', formatTimestamp(entry.tsSeconds, entry.tsMicros)],
    ['Protocols in Frame', entry.frame.tags.join(', ') || '—'],
  ]
    .map(([label, val]) => `<div class="kv small"><span>${escapeHtml(label)}</span><b>${escapeHtml(String(val))}</b></div>`)
    .join('');
  return `<details class="layer-block" open><summary class="layer-title">Frame</summary>${rows}</details>`;
}

function layerTitle(key, obj) {
  if (key === 'l2') return obj.vlanId != null ? 'Ethernet II + 802.1Q Virtual LAN' : 'Ethernet II';
  if (key === 'l3') {
    if (obj.type === 'IPv4') return 'Internet Protocol Version 4';
    if (obj.type === 'IPv6') return 'Internet Protocol Version 6';
    if (obj.type === 'ARP') return `Address Resolution Protocol (${obj.op === 'REQUEST' ? 'request' : obj.op === 'REPLY' ? 'reply' : obj.op})`;
    return obj.type || 'Network Layer';
  }
  if (key === 'l4') {
    if (obj.type === 'TCP') return `Transmission Control Protocol, Src Port: ${obj.srcPort}, Dst Port: ${obj.dstPort}`;
    if (obj.type === 'UDP') return `User Datagram Protocol, Src Port: ${obj.srcPort}, Dst Port: ${obj.dstPort}`;
    if (obj.type === 'ICMP') return 'Internet Control Message Protocol';
    if (obj.type === 'ICMPv6') return 'Internet Control Message Protocol v6';
    return obj.type || 'Transport Layer';
  }
  if (key === 'l7') {
    if (obj.type === 'DNS' || obj.type === 'mDNS') return `Domain Name System (${obj.isResponse ? 'response' : 'query'})`;
    if (obj.type === 'TLS') return 'Transport Layer Security';
    if (obj.type === 'HTTP') return 'Hypertext Transfer Protocol';
    if (obj.type === 'DHCP') return 'Dynamic Host Configuration Protocol';
    if (obj.type === 'NTP') return 'Network Time Protocol';
    if (obj.type === 'SSDP') return 'Simple Service Discovery Protocol';
    return obj.type || 'Application Layer';
  }
  return key;
}

function renderLayers(layers) {
  return ['l2', 'l3', 'l4', 'l7']
    .filter((k) => layers[k])
    .map((k) => {
      const obj = layers[k];
      const title = layerTitle(k, obj);
      let rows = Object.entries(obj)
        .filter(([field]) => !SKIP_FIELDS.has(field))
        .map(([field, val]) => renderField(field, val))
        .join('');
      return `<details class="layer-block" open><summary class="layer-title">${escapeHtml(title)}</summary>${rows}</details>`;
    })
    .join('');
}

function renderField(field, val) {
  if (field === 'flags' && val && typeof val === 'object') {
    const set = Object.entries(val).filter(([, v]) => v).map(([k]) => k);
    return `<div class="kv small"><span>Flags</span><b>${set.length ? set.join(', ') : 'none set'}</b></div>`;
  }
  if (field === 'etherType' && typeof val === 'number') {
    const known = { 0x0800: 'IPv4', 0x86dd: 'IPv6', 0x0806: 'ARP' }[val];
    return `<div class="kv small"><span>${FIELD_LABELS.etherType}</span><b>0x${val.toString(16).padStart(4, '0')}${known ? ' (' + known + ')' : ''}</b></div>`;
  }
  if (val && typeof val === 'object') return '';
  const label = FIELD_LABELS[field] || titleize(field);
  return `<div class="kv small"><span>${escapeHtml(label)}</span><b>${escapeHtml(String(val))}</b></div>`;
}

function titleize(str) {
  return String(str).replace(/([A-Z])/g, ' $1').replace(/^./, (c) => c.toUpperCase());
}

function shorten(id) {
  return id && id.length > 22 ? id.slice(0, 20) + '\u2026' : id;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}
function escapeAttr(str) {
  return String(str).replace(/"/g, '&quot;');
}
