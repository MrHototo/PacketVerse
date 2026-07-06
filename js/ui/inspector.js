/**
 * inspector.js
 * Right-hand detail panel with breadcrumb drill-down: Host -> its flows ->
 * a flow's detail -> its packets -> full packet decode (hex/ASCII/OSI
 * layers + plain-English explanation). Every list row is clickable, so a
 * user can start broad (a host) and progressively narrow to one packet.
 */
import { toHex, toAscii, formatBytes, formatTimestamp } from '../utils/bytes.js';
import { explainFlow, explainPacket } from './explainer.js';

export class Inspector {
  constructor(panelEl, breadcrumbEl, { model, onFocusHost, onFocusFlow } = {}) {
    this.panel = panelEl;
    this.breadcrumbEl = breadcrumbEl;
    this.model = model || null;
    this.onFocusHost = onFocusHost || (() => {});
    this.onFocusFlow = onFocusFlow || (() => {});
    this.stack = [];
    this.showEmpty();
  }

  setModel(model) {
    this.model = model;
  }

  showEmpty() {
    this.stack = [];
    this._renderBreadcrumb();
    this.panel.innerHTML = `
      <div class="inspector-empty">
        <p>Click any node, connection, or dashboard row to see details here.</p>
        <p class="hint">Hover for a quick summary, click for the full breakdown — then drill from host &rarr; conversation &rarr; packet.</p>
      </div>`;
  }

  /** Entry points from outside the panel (3D scene click, dashboard click) reset the drill stack. */
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
    const flows = this._flowsForHost(host.id);
    const sortedFlows = [...flows].sort((a, b) => b.bytes - a.bytes);
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
          .join('') || '<p class="hint">No conversations in the current filter/time range.</p>'}
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
    const packets = this._packetsForFlow(flow);
    this.panel.innerHTML = `
      <h3>${escapeHtml(flow.hostA)} \u2194 ${escapeHtml(flow.hostB)}</h3>
      <div class="kv"><span>Protocol</span><b>${flow.protocol}${flow.appProtocol ? ' / ' + flow.appProtocol : ''}</b></div>
      <div class="kv"><span>Ports</span><b>${flow.portA ?? '—'} \u2192 ${flow.portB ?? '—'}</b></div>
      <div class="kv"><span>Packets</span><b>${flow.packets}</b></div>
      <div class="kv"><span>Bytes</span><b>${formatBytes(flow.bytes)}</b></div>
      <div class="kv"><span>Duration</span><b>${(flow.lastSeen - flow.firstSeen).toFixed(2)}s</b></div>
      <div class="kv"><span>TCP flags seen</span><b>${[...flow.flagsSeen].join(', ') || '—'}</b></div>
      <div class="explain">${explanation.plain}</div>
      <h4>Packets (${packets.length}) <span class="hint">— click to inspect</span></h4>
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
          .join('') || '<p class="hint">No packets available for this conversation in the current range.</p>'}
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
  }

  _renderPacket(entry) {
    const explanation = explainPacket(entry);
    const hex = toHex(entry.data);
    const ascii = toAscii(entry.data);
    this.panel.innerHTML = `
      <h3>Packet #${entry.index + 1}</h3>
      <div class="kv"><span>Time</span><b>${formatTimestamp(entry.tsSeconds, entry.tsMicros)}</b></div>
      <div class="kv"><span>Length</span><b>${entry.length} bytes</b></div>
      <div class="kv"><span>Summary</span><b>${escapeHtml(entry.frame.summary)}</b></div>
      <div class="explain"><b>In plain English:</b> ${explanation.plain}</div>
      <div class="explain-tech">${escapeHtml(explanation.technical)}</div>
      <h4>Layers</h4>
      ${renderLayers(entry.frame.layers)}
      <h4>Hex / ASCII</h4>
      <div class="hexview">${hex.slice(0, 4000)}${hex.length > 4000 ? '\u2026' : ''}</div>
      <div class="asciiview">${escapeHtml(ascii.slice(0, 400))}${ascii.length > 400 ? '\u2026' : ''}</div>
    `;
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

function renderLayers(layers) {
  return ['l2', 'l3', 'l4', 'l7']
    .filter((k) => layers[k])
    .map((k) => {
      const label = { l2: 'Link (L2)', l3: 'Network (L3)', l4: 'Transport (L4)', l7: 'Application (L7)' }[k];
      const rows = Object.entries(layers[k])
        .map(([field, val]) => `<div class="kv small"><span>${field}</span><b>${escapeHtml(String(val))}</b></div>`)
        .join('');
      return `<div class="layer-block"><div class="layer-title">${label}</div>${rows}</div>`;
    })
    .join('');
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
