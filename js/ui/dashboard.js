/**
 * dashboard.js
 * Renders the real-time statistics panel (top talkers, protocol mix, etc.)
 * from the current (filtered) hosts/flows. Pure DOM, no chart library —
 * keeps the bundle dependency-free and fast to load.
 */
import { formatBytes } from '../utils/bytes.js';
import { hexToCss, colorForProtocol } from '../utils/colors.js';

export function renderDashboard(container, { hosts, flows, packets }) {
  const totalPackets = packets.length;
  const totalBytes = packets.reduce((sum, p) => sum + p.length, 0);

  const protocolCounts = {};
  for (const flow of flows.values()) {
    const key = flow.appProtocol || flow.protocol;
    protocolCounts[key] = (protocolCounts[key] || 0) + flow.packets;
  }
  const maxProtoCount = Math.max(1, ...Object.values(protocolCounts));

  const topTalkers = [...hosts.values()].sort((a, b) => b.bytes - a.bytes).slice(0, 6);
  const maxTalkerBytes = Math.max(1, ...topTalkers.map((h) => h.bytes));

  container.innerHTML = `
    <div class="stat-row">
      <div class="stat-card"><div class="stat-value">${totalPackets.toLocaleString()}</div><div class="stat-label">Packets</div></div>
      <div class="stat-card"><div class="stat-value">${formatBytes(totalBytes)}</div><div class="stat-label">Volume</div></div>
      <div class="stat-card"><div class="stat-value">${flows.size.toLocaleString()}</div><div class="stat-label">Conversations</div></div>
      <div class="stat-card"><div class="stat-value">${hosts.size.toLocaleString()}</div><div class="stat-label">Hosts</div></div>
    </div>
    <h4>Protocol distribution</h4>
    <div class="bar-list">
      ${Object.entries(protocolCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
        .map(
          ([proto, count]) => `
        <div class="bar-row">
          <span class="bar-label">${proto}</span>
          <div class="bar-track"><div class="bar-fill" style="width:${(count / maxProtoCount) * 100}%;background:${hexToCss(colorForProtocol(proto))}"></div></div>
          <span class="bar-count">${count}</span>
        </div>`
        )
        .join('')}
    </div>
    <h4>Top talkers</h4>
    <div class="bar-list">
      ${topTalkers
        .map(
          (h) => `
        <div class="bar-row">
          <span class="bar-label mono">${h.id}</span>
          <div class="bar-track"><div class="bar-fill" style="width:${(h.bytes / maxTalkerBytes) * 100}%;background:#4d9de0"></div></div>
          <span class="bar-count">${formatBytes(h.bytes)}</span>
        </div>`
        )
        .join('')}
    </div>
  `;
  return protocolCounts;
}
