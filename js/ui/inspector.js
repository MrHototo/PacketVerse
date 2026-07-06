/**
 * inspector.js
 * Right-hand detail panel: renders host, flow, or packet detail plus the
 * plain-English explanation, and (for packets) a synchronized hex/ASCII view.
 */
import { toHex, toAscii, formatBytes, formatTimestamp } from '../utils/bytes.js';
import { explainFlow, explainPacket } from './explainer.js';

export class Inspector {
  constructor(panelEl) {
    this.panel = panelEl;
    this.showEmpty();
  }

  showEmpty() {
    this.panel.innerHTML = `
      <div class="inspector-empty">
        <p>Click any node, connection, or packet to see details here.</p>
        <p class="hint">Hover for a quick summary, click for the full breakdown.</p>
      </div>`;
  }

  showHost(host) {
    this.panel.innerHTML = `
      <h3>${escapeHtml(host.id)}</h3>
      <div class="kv"><span>Role</span><b>${host.isIp ? 'IP host' : 'MAC-only host'}</b></div>
      <div class="kv"><span>Packets</span><b>${host.packets}</b></div>
      <div class="kv"><span>Bytes</span><b>${formatBytes(host.bytes)}</b></div>
      <div class="kv"><span>Protocols seen</span><b>${[...host.protocols].join(', ') || '—'}</b></div>
      <div class="kv"><span>First seen</span><b>${new Date(host.firstSeen * 1000).toLocaleTimeString()}</b></div>
      <div class="kv"><span>Last seen</span><b>${new Date(host.lastSeen * 1000).toLocaleTimeString()}</b></div>
      <div class="explain">This device sent or received ${host.packets} packets in the capture, communicating using ${[...host.protocols].slice(0, 4).join(', ') || 'unknown protocols'}.</div>
    `;
  }

  showFlow(flow) {
    const explanation = explainFlow(flow);
    this.panel.innerHTML = `
      <h3>${escapeHtml(flow.hostA)} \u2194 ${escapeHtml(flow.hostB)}</h3>
      <div class="kv"><span>Protocol</span><b>${flow.protocol}${flow.appProtocol ? ' / ' + flow.appProtocol : ''}</b></div>
      <div class="kv"><span>Ports</span><b>${flow.portA ?? '—'} \u2192 ${flow.portB ?? '—'}</b></div>
      <div class="kv"><span>Packets</span><b>${flow.packets}</b></div>
      <div class="kv"><span>Bytes</span><b>${formatBytes(flow.bytes)}</b></div>
      <div class="kv"><span>Duration</span><b>${(flow.lastSeen - flow.firstSeen).toFixed(2)}s</b></div>
      <div class="kv"><span>TCP flags seen</span><b>${[...flow.flagsSeen].join(', ') || '—'}</b></div>
      <div class="explain">${explanation.plain}</div>
    `;
  }

  showPacket(entry) {
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

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}
