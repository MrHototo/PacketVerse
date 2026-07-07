/**
 * statsPanel.js
 * Renders the Conversations, Endpoints, and Name Resolution tables —
 * Wireshark's "Statistics" menu equivalents. All three respect whatever
 * hosts/flows/packets are currently visible (post filter + ego-network
 * focus), and rows are clickable to focus that host/flow in the 3D scene.
 */
import { formatBytes } from '../utils/bytes.js';
import { hexToCss, colorForProtocol } from '../utils/colors.js';

export function renderConversations(container, flows, { onSelectFlow } = {}) {
  const rows = [...flows.values()].sort((a, b) => b.bytes - a.bytes).slice(0, 300);
  container.innerHTML = `
    <div class="stat-table-wrap">
      <table class="stat-table">
        <thead><tr>
          <th>Host A</th><th>Host B</th><th>Protocol</th><th>Packets</th><th>Bytes</th><th>Duration</th>
        </tr></thead>
        <tbody>
          ${rows.map((f) => `
            <tr data-flow-key="${escapeAttr(f.key)}">
              <td class="mono">${escapeHtml(f.hostA)}${f.portA != null ? ':' + f.portA : ''}</td>
              <td class="mono">${escapeHtml(f.hostB)}${f.portB != null ? ':' + f.portB : ''}</td>
              <td><span class="proto-chip" style="border-color:${hexToCss(colorForProtocol(f.appProtocol || f.protocol))};color:${hexToCss(colorForProtocol(f.appProtocol || f.protocol))}">${escapeHtml(f.appProtocol || f.protocol)}</span></td>
              <td>${f.packets}</td>
              <td>${formatBytes(f.bytes)}</td>
              <td>${(f.lastSeen - f.firstSeen).toFixed(2)}s</td>
            </tr>`).join('') || '<tr><td colspan="6" class="hint">No conversations in the current view.</td></tr>'}
        </tbody>
      </table>
    </div>
    <p class="hint">${flows.size.toLocaleString()} conversation${flows.size === 1 ? '' : 's'} shown (top 300 by volume) — click a row to focus it.</p>
  `;
  if (onSelectFlow) {
    container.querySelectorAll('[data-flow-key]').forEach((row) => {
      row.addEventListener('click', () => {
        const flow = flows.get(row.dataset.flowKey);
        if (flow) onSelectFlow(flow);
      });
    });
  }
}

export function renderEndpoints(container, hosts, { onSelectHost } = {}) {
  const rows = [...hosts.values()].sort((a, b) => b.bytes - a.bytes).slice(0, 300);
  container.innerHTML = `
    <div class="stat-table-wrap">
      <table class="stat-table">
        <thead><tr>
          <th>Address</th><th>Packets</th><th>Bytes</th><th>Protocols</th><th>First seen</th><th>Last seen</th>
        </tr></thead>
        <tbody>
          ${rows.map((h) => `
            <tr data-host-id="${escapeAttr(h.id)}">
              <td class="mono">${escapeHtml(h.isCluster ? h.label : h.id)}</td>
              <td>${h.packets}</td>
              <td>${formatBytes(h.bytes)}</td>
              <td>${[...h.protocols].slice(0, 4).join(', ')}</td>
              <td>${new Date(h.firstSeen * 1000).toLocaleTimeString()}</td>
              <td>${new Date(h.lastSeen * 1000).toLocaleTimeString()}</td>
            </tr>`).join('') || '<tr><td colspan="6" class="hint">No endpoints in the current view.</td></tr>'}
        </tbody>
      </table>
    </div>
    <p class="hint">${hosts.size.toLocaleString()} endpoint${hosts.size === 1 ? '' : 's'} shown (top 300 by volume) — click a row to focus it.</p>
  `;
  if (onSelectHost) {
    container.querySelectorAll('[data-host-id]').forEach((row) => {
      row.addEventListener('click', () => onSelectHost(row.dataset.hostId));
    });
  }
}

/** Name resolution table: IP -> hostname(s) learned from DNS answers, TLS SNI, and HTTP Host headers. */
export function renderNameResolution(container, nameTable) {
  const rows = [...(nameTable?.entries() || [])].sort((a, b) => a[0].localeCompare(b[0]));
  container.innerHTML = `
    <div class="stat-table-wrap">
      <table class="stat-table">
        <thead><tr><th>IP Address</th><th>Resolved name(s)</th></tr></thead>
        <tbody>
          ${rows.map(([ip, names]) => `
            <tr><td class="mono">${escapeHtml(ip)}</td><td class="mono">${[...names].map(escapeHtml).join(', ')}</td></tr>
          `).join('') || '<tr><td colspan="2" class="hint">No names resolved yet — seen in DNS answers, TLS SNI, or HTTP Host headers.</td></tr>'}
        </tbody>
      </table>
    </div>
    <p class="hint">${rows.length} address${rows.length === 1 ? '' : 'es'} resolved to a name.</p>
  `;
}

function escapeHtml(str) { return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
function escapeAttr(str) { return String(str).replace(/"/g, '&quot;'); }
