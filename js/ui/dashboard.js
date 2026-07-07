/**
 * dashboard.js
 * Renders the real-time statistics panel (top talkers, protocol mix, etc.)
 * from the current (filtered) hosts/flows. Pure DOM, no chart library —
 * keeps the bundle dependency-free and fast to load. Rows are clickable:
 * clicking a host or protocol drills the filter bar + 3D focus to it.
 */
import { formatBytes } from '../utils/bytes.js';
import { hexToCss, colorForProtocol } from '../utils/colors.js';
import { maxOf } from '../utils/mathSafe.js';

export function renderDashboard(container, { hosts, flows, packets }, callbacks = {}) {
  const { onSelectHost, onSelectProtocol } = callbacks;
  const totalPackets = packets.length;
  const totalBytes = packets.reduce((sum, p) => sum + p.length, 0);

  const protocolCounts = {};
  for (const flow of flows.values()) {
    const key = flow.appProtocol || flow.protocol;
    protocolCounts[key] = (protocolCounts[key] || 0) + flow.packets;
  }
  const maxProtoCount = Math.max(1, maxOf(Object.values(protocolCounts)));

  const topTalkers = [...hosts.values()].sort((a, b) => b.bytes - a.bytes).slice(0, 8);
  const maxTalkerBytes = Math.max(1, maxOf(topTalkers.map((h) => h.bytes)));

  container.innerHTML = `
    <div class="stat-row">
      <div class="stat-card"><div class="stat-value">${totalPackets.toLocaleString()}</div><div class="stat-label">Packets</div></div>
      <div class="stat-card"><div class="stat-value">${formatBytes(totalBytes)}</div><div class="stat-label">Volume</div></div>
      <div class="stat-card"><div class="stat-value">${flows.size.toLocaleString()}</div><div class="stat-label">Conversations</div></div>
      <div class="stat-card"><div class="stat-value">${hosts.size.toLocaleString()}</div><div class="stat-label">Hosts</div></div>
    </div>
    <h4>Protocol distribution <span class="hint">(click to filter)</span></h4>
    <div class="bar-list" id="db-protocol-list">
      ${Object.entries(protocolCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
        .map(
          ([proto, count]) => `
        <div class="bar-row" data-proto="${escapeAttr(proto)}">
          <span class="bar-label">${proto}</span>
          <div class="bar-track"><div class="bar-fill" style="width:${(count / maxProtoCount) * 100}%;background:${hexToCss(colorForProtocol(proto))}"></div></div>
          <span class="bar-count">${count}</span>
        </div>`
        )
        .join('')}
    </div>
    <h4>Top talkers <span class="hint">(click to focus)</span></h4>
    <div class="bar-list" id="db-talker-list">
      ${topTalkers
        .map(
          (h) => `
        <div class="bar-row" data-host="${escapeAttr(h.id)}">
          <span class="bar-label mono">${h.id}</span>
          <div class="bar-track"><div class="bar-fill" style="width:${(h.bytes / maxTalkerBytes) * 100}%;background:#4d9de0"></div></div>
          <span class="bar-count">${formatBytes(h.bytes)}</span>
        </div>`
        )
        .join('')}
    </div>
  `;

  if (onSelectProtocol) {
    container.querySelectorAll('#db-protocol-list .bar-row').forEach((row) => {
      row.addEventListener('click', () => onSelectProtocol(row.dataset.proto));
    });
  }
  if (onSelectHost) {
    container.querySelectorAll('#db-talker-list .bar-row').forEach((row) => {
      row.addEventListener('click', () => onSelectHost(row.dataset.host));
    });
  }

  return protocolCounts;
}

function escapeAttr(str) {
  return String(str).replace(/"/g, '&quot;');
}
