/**
 * main.js
 * Application entry point: wires file upload/parsing, the graph model,
 * the 3D scene, timeline, filters, inspector, dashboard, and security
 * findings together. Everything runs client-side in the browser.
 */
import { parseCapture } from './pcap/pcapParser.js';
import { decodeFrame } from './pcap/protocolDecoder.js';
import { buildGraphModel, flowsInRange } from './pcap/graphModel.js';
import { runSecurityChecks } from './pcap/securityEngine.js';
import { Scene3D } from './viz/scene3d.js';
import { Timeline } from './ui/timeline.js';
import { FilterBar } from './ui/filters.js';
import { Inspector } from './ui/inspector.js';
import { renderDashboard } from './ui/dashboard.js';
import { PROTOCOL_COLORS, hexToCss } from './utils/colors.js';

const els = {
  dropZone: document.getElementById('drop-zone'),
  fileInput: document.getElementById('file-input'),
  app: document.getElementById('app'),
  sceneContainer: document.getElementById('scene-container'),
  timelineCanvas: document.getElementById('timeline-canvas'),
  search: document.getElementById('search-input'),
  presets: document.getElementById('preset-chips'),
  inspectorPanel: document.getElementById('inspector-panel'),
  dashboardPanel: document.getElementById('dashboard-panel'),
  findingsPanel: document.getElementById('findings-panel'),
  tooltip: document.getElementById('tooltip'),
  fileMeta: document.getElementById('file-meta'),
  resetViewBtn: document.getElementById('reset-view-btn'),
  resetTimeBtn: document.getElementById('reset-time-btn'),
  themeToggle: document.getElementById('theme-toggle'),
  loadDemoBtn: document.getElementById('load-demo-btn'),
  progressBar: document.getElementById('progress-bar'),
  clearFocusBtn: document.getElementById('clear-focus-btn'),
  toggleLabels: document.getElementById('toggle-labels'),
  legendPanel: document.getElementById('legend-panel'),
};

let model = null;
let scene = null;
let timeline = null;
let filterBar = null;
let inspector = null;
let currentRange = null;

init();

function init() {
  inspector = new Inspector(els.inspectorPanel);
  els.fileInput.addEventListener('change', (e) => {
    if (e.target.files[0]) loadFile(e.target.files[0]);
  });
  ['dragover', 'dragenter'].forEach((evt) =>
    els.dropZone.addEventListener(evt, (e) => {
      e.preventDefault();
      els.dropZone.classList.add('drag-active');
    })
  );
  ['dragleave', 'drop'].forEach((evt) =>
    els.dropZone.addEventListener(evt, (e) => {
      e.preventDefault();
      els.dropZone.classList.remove('drag-active');
    })
  );
  els.dropZone.addEventListener('drop', (e) => {
    const file = e.dataTransfer.files[0];
    if (file) loadFile(file);
  });
  els.themeToggle.addEventListener('click', () => {
    document.body.classList.toggle('light');
  });
  els.loadDemoBtn.addEventListener('click', loadSyntheticDemo);
}

async function loadFile(file) {
  showProgress(0);
  els.fileMeta.textContent = `Parsing ${file.name} (${(file.size / 1024).toFixed(1)} KB)…`;
  const buffer = await file.arrayBuffer();
  let parsed;
  try {
    parsed = parseCapture(buffer, (done, total) => showProgress(done / total));
  } catch (err) {
    els.fileMeta.textContent = `Failed to parse: ${err.message}`;
    showProgress(null);
    return;
  }
  buildAndRender(parsed.packets, file.name);
}

function buildAndRender(rawPackets, label) {
  const decoded = rawPackets.map((p) => decodeFrame(p.data, p.linkType));
  model = buildGraphModel(rawPackets, decoded);
  currentRange = { ...model.timeRange };

  els.fileMeta.textContent = `${label} — ${model.packets.length.toLocaleString()} packets, ${model.hosts.size} hosts, ${model.flows.size} conversations`;
  showProgress(null);
  els.app.classList.add('loaded');

  if (!scene) {
    scene = new Scene3D(els.sceneContainer, {
      onSelect: handleSelect,
      onHover: handleHover,
    });
  }
  timeline = new Timeline(els.timelineCanvas);
  timeline.setData(model.packets, model.timeRange);
  els.timelineCanvas.addEventListener('timeline:range', (e) => {
    currentRange = e.detail;
    refreshViews();
  });

  filterBar = new FilterBar({
    searchInput: els.search,
    presetContainer: els.presets,
    onChange: refreshViews,
  });

  refreshViews(true);
  scene.resetCamera();
}

function refreshViews(rebuild = false) {
  if (!model) return;
  const inRange = flowsInRange(model.flows, currentRange.start, currentRange.end);
  const filtered = inRange.filter((f) => filterBar.matches(f));
  const filteredHosts = new Map();
  for (const f of filtered) {
    if (model.hosts.has(f.hostA)) filteredHosts.set(f.hostA, model.hosts.get(f.hostA));
    if (model.hosts.has(f.hostB)) filteredHosts.set(f.hostB, model.hosts.get(f.hostB));
  }
  const filteredFlowMap = new Map(filtered.map((f) => [f.key, f]));

  if (rebuild) {
    scene.setGraph(model.hosts, model.flows);
    const protocolCounts = {};
    for (const f of model.flows.values()) {
      const k = f.appProtocol || f.protocol;
      protocolCounts[k] = (protocolCounts[k] || 0) + 1;
    }
    filterBar.renderPresets(protocolCounts);
    renderFindings();
  }

  scene.setActivity(new Set(filteredFlowMap.keys()));

  const inRangePackets = model.packets.filter(
    (p) => p.ts >= currentRange.start && p.ts <= currentRange.end
  );
  renderDashboard(els.dashboardPanel, {
    hosts: filteredHosts.size ? filteredHosts : model.hosts,
    flows: filteredFlowMap.size ? filteredFlowMap : model.flows,
    packets: inRangePackets,
  });
}

function renderFindings() {
  const findings = runSecurityChecks(model);
  if (!findings.length) {
    els.findingsPanel.innerHTML = '<p class="hint">No anomalies flagged by the built-in heuristics.</p>';
    return;
  }
  els.findingsPanel.innerHTML = findings
    .map(
      (f) => `
      <div class="finding finding-${f.severity}">
        <div class="finding-head"><b>${f.type}</b><span class="badge badge-${f.severity}">${f.severity}</span></div>
        <div class="finding-conf">Confidence: ${(f.confidence * 100).toFixed(0)}%</div>
        <p>${f.explanation}</p>
        <p class="hint"><b>Suggested next step:</b> ${f.nextSteps}</p>
      </div>`
    )
    .join('');
}

function handleSelect(userData) {
  if (!userData) {
    scene?.clearFocus();
    inspector.showEmpty();
    return;
  }
  if (userData.kind === 'host') {
    scene?.focusOn('host', userData.id);
    inspector.showHost(userData.host);
  }
  if (userData.kind === 'flow') {
    scene?.focusOn('flow', userData.key);
    inspector.showFlow(userData.flow);
  }
}

function handleHover(userData, event) {
  if (!userData) {
    els.tooltip.style.display = 'none';
    return;
  }
  const text =
    userData.kind === 'host'
      ? `${userData.host.id} — ${userData.host.packets} pkts`
      : `${userData.flow.hostA} \u2194 ${userData.flow.hostB} (${userData.flow.protocol})`;
  els.tooltip.textContent = text;
  els.tooltip.style.display = 'block';
  els.tooltip.style.left = `${event.clientX + 12}px`;
  els.tooltip.style.top = `${event.clientY + 12}px`;
}

function showProgress(fraction) {
  if (fraction === null) {
    els.progressBar.style.width = '0%';
    els.progressBar.style.opacity = '0';
    return;
  }
  els.progressBar.style.opacity = '1';
  els.progressBar.style.width = `${Math.round(fraction * 100)}%`;
}

els.resetViewBtn?.addEventListener('click', () => scene?.resetCamera());
els.resetTimeBtn?.addEventListener('click', () => timeline?.resetRange());
els.clearFocusBtn?.addEventListener('click', () => {
  scene?.clearFocus();
  inspector?.showEmpty();
});
els.toggleLabels?.addEventListener('change', (e) => scene?.setLabelsVisible(e.target.checked));
renderLegend();


/** Generates a small synthetic capture in-memory so the app is explorable
 * without needing a real .pcap file on hand — useful for first-time users
 * and for the GitHub Pages demo. */
function loadSyntheticDemo() {
  const { packets, decoded } = buildSyntheticCapture();
  model = buildGraphModel(packets, decoded);
  currentRange = { ...model.timeRange };
  els.fileMeta.textContent = `Synthetic demo capture — ${model.packets.length} packets, ${model.hosts.size} hosts`;
  els.app.classList.add('loaded');
  if (!scene) scene = new Scene3D(els.sceneContainer, { onSelect: handleSelect, onHover: handleHover });
  timeline = new Timeline(els.timelineCanvas);
  timeline.setData(model.packets, model.timeRange);
  els.timelineCanvas.addEventListener('timeline:range', (e) => {
    currentRange = e.detail;
    refreshViews();
  });
  filterBar = new FilterBar({ searchInput: els.search, presetContainer: els.presets, onChange: refreshViews });
  refreshViews(true);
  scene.resetCamera();
}

function buildSyntheticCapture() {
  // Hand-built small set of realistic-looking frames (DNS query/response,
  // TCP handshake, TLS ClientHello, ARP) purely for demo purposes.
  // Kept intentionally simple; real files are decoded via pcapParser.js.
  const packets = [];
  const decoded = [];
  let t = Math.floor(Date.now() / 1000) - 30;
  const hostsIp = ['10.0.0.5', '10.0.0.1', '142.250.80.14', '10.0.0.9'];
  for (let i = 0; i < 120; i++) {
    t += Math.random() * 0.3;
    const proto = ['DNS', 'TCP', 'TLS', 'ARP', 'UDP'][i % 5];
    const frame = buildSyntheticFrame(proto, hostsIp, i);
    decoded.push(frame);
    packets.push({
      tsSeconds: Math.floor(t),
      tsMicros: Math.floor((t % 1) * 1e6),
      capturedLength: 64,
      originalLength: 64 + (i % 50),
      data: new Uint8Array(64),
      linkType: 1,
    });
  }
  return { packets, decoded };
}

function buildSyntheticFrame(proto, hostsIp, i) {
  const a = hostsIp[i % hostsIp.length];
  const b = hostsIp[(i + 1) % hostsIp.length];
  const base = {
    layers: { l2: { srcMac: '02:00:00:00:00:01', dstMac: '02:00:00:00:00:02', etherType: 0x0800, isBroadcast: false, isMulticast: false }, l3: null, l4: null, l7: null },
    tags: ['IPv4'],
    endpointA: a,
    endpointB: b,
  };
  if (proto === 'DNS') {
    base.layers.l3 = { type: 'IPv4', srcIp: a, dstIp: b, protocol: 'UDP', ttl: 64 };
    base.layers.l4 = { type: 'UDP', srcPort: 51000 + i, dstPort: 53 };
    base.layers.l7 = { type: 'DNS', isResponse: i % 2 === 1, name: 'example.com', queryType: 'A', qdCount: 1, anCount: i % 2 };
    base.tags.push('UDP', 'DNS');
  } else if (proto === 'TLS') {
    base.layers.l3 = { type: 'IPv4', srcIp: a, dstIp: b, protocol: 'TCP', ttl: 64 };
    base.layers.l4 = { type: 'TCP', srcPort: 51500 + i, dstPort: 443, flags: { SYN: false, ACK: true, FIN: false, RST: false, PSH: true, URG: false } };
    base.layers.l7 = { type: 'TLS', handshakeType: 'ClientHello', version: 'TLS 1.2/1.3', serverName: 'www.example.com' };
    base.tags.push('TCP', 'TLS');
  } else if (proto === 'ARP') {
    base.layers.l3 = { type: 'ARP', op: 'REQUEST', senderIp: a, targetIp: b, senderMac: '02:00:00:00:00:01', targetMac: '00:00:00:00:00:00' };
    base.endpointA = a;
    base.endpointB = b;
    base.tags = ['ARP', 'Broadcast'];
  } else if (proto === 'UDP') {
    base.layers.l3 = { type: 'IPv4', srcIp: a, dstIp: b, protocol: 'UDP', ttl: 64 };
    base.layers.l4 = { type: 'UDP', srcPort: 5353, dstPort: 5353 };
    base.tags.push('UDP', 'mDNS');
  } else {
    base.layers.l3 = { type: 'IPv4', srcIp: a, dstIp: b, protocol: 'TCP', ttl: 64 };
    base.layers.l4 = { type: 'TCP', srcPort: 52000 + i, dstPort: 80, flags: { SYN: i % 10 === 0, ACK: true, FIN: false, RST: false, PSH: true, URG: false } };
    base.tags.push('TCP');
  }
  base.summary = `${proto} demo packet`;
  return base;
}

function renderLegend() {
  if (!els.legendPanel) return;
  els.legendPanel.innerHTML = Object.entries(PROTOCOL_COLORS)
    .map(
      ([proto, hex]) =>
        `<div class="legend-row"><span class="legend-swatch" style="background:${hexToCss(hex)}"></span>${proto}</div>`
    )
    .join('');
}
