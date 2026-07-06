/**
 * main.js
 * Application entry point: wires file upload/parsing, the graph model,
 * clustering, the 3D scene, timeline, filters, packet list, inspector,
 * dashboard, and security findings together. Everything runs client-side.
 *
 * Filtering model: the filter bar compiles a predicate evaluated per
 * PACKET (Wireshark-display-filter granularity). Every refresh, we compute
 * the filtered packet set, derive which raw flows they belong to, map those
 * to the (possibly clustered) display-graph flow keys, and use that single
 * "active set" to drive the 3D scene, the packet list, the dashboard, and
 * the inspector's drill-down lists — so one filter genuinely narrows down
 * every view at once instead of just dimming the 3D scene.
 */
import { parseCapture } from './pcap/pcapParser.js';
import { decodeFrame } from './pcap/protocolDecoder.js';
import { buildGraphModel, flowsInRange } from './pcap/graphModel.js';
import { computeDisplayGraph } from './pcap/clustering.js';
import { runSecurityChecks } from './pcap/securityEngine.js';
import { Scene3D } from './viz/scene3d.js';
import { Timeline } from './ui/timeline.js';
import { FilterBar } from './ui/filters.js';
import { Inspector } from './ui/inspector.js';
import { PacketList } from './ui/packetList.js';
import { renderDashboard } from './ui/dashboard.js';
import { PROTOCOL_COLORS, hexToCss } from './utils/colors.js';

const els = {
  dropZone: document.getElementById('drop-zone'),
  fileInput: document.getElementById('file-input'),
  app: document.getElementById('app'),
  sceneContainer: document.getElementById('scene-container'),
  timelineCanvas: document.getElementById('timeline-canvas'),
  timelineWrap: document.getElementById('timeline-wrap'),
  search: document.getElementById('search-input'),
  presets: document.getElementById('preset-chips'),
  presetsPanel: document.getElementById('preset-chips-panel'),
  inspectorPanel: document.getElementById('inspector-panel'),
  inspectorBreadcrumb: document.getElementById('inspector-breadcrumb'),
  dashboardPanel: document.getElementById('dashboard-panel'),
  findingsPanel: document.getElementById('findings-panel'),
  tooltip: document.getElementById('tooltip'),
  fileMeta: document.getElementById('file-meta'),
  resetViewBtn: document.getElementById('reset-view-btn'),
  themeToggle: document.getElementById('theme-toggle'),
  loadDemoBtn: document.getElementById('load-demo-btn'),
  progressBar: document.getElementById('progress-bar'),
  clearFocusBtn: document.getElementById('clear-focus-btn'),
  toggleLabels: document.getElementById('toggle-labels'),
  toggleParticles: document.getElementById('toggle-particles'),
  legendPanel: document.getElementById('legend-panel'),
  filterHelpBtn: document.getElementById('filter-help-btn'),
  filterHelpPopover: document.getElementById('filter-help-popover'),
  clearFilterBtn: document.getElementById('clear-filter-btn'),
  fitFilteredBtn: document.getElementById('fit-filtered-btn'),
  zoomInBtn: document.getElementById('zoom-in-btn'),
  zoomOutBtn: document.getElementById('zoom-out-btn'),
  expandAllBtn: document.getElementById('expand-all-btn'),
  collapseAllBtn: document.getElementById('collapse-all-btn'),
  toggleLeftPanel: document.getElementById('toggle-left-panel'),
  toggleRightPanel: document.getElementById('toggle-right-panel'),
  sidebarLeft: document.getElementById('sidebar-left'),
  sidebarRight: document.getElementById('sidebar-right'),
  collapseTimelineBtn: document.getElementById('collapse-timeline-btn'),
  packetListWrap: document.getElementById('packetlist-wrap'),
  packetListContainer: document.getElementById('packet-list'),
  collapsePacketListBtn: document.getElementById('collapse-packetlist-btn'),
  filterStatus: document.getElementById('filter-status'),
};

let model = null;
let scene = null;
let timeline = null;
let filterBar = null;
let inspector = null;
let packetList = null;
let currentRange = null;
let displayGraph = null;
const expandedClusters = new Set();

init();

function init() {
  inspector = new Inspector(els.inspectorPanel, els.inspectorBreadcrumb, {
    onFocusHost: (host) => scene?.focusOn('host', host.id),
    onFocusFlow: (flow) => scene?.focusOn('flow', flow.key),
  });

  packetList = new PacketList(els.packetListContainer, {
    onSelectPacket: (entry) => {
      inspector.showPacket(entry);
      const displayKey = displayGraph?.rawFlowKeyToDisplayKey?.get(entry.flowKey);
      if (displayKey) scene?.focusOn('flow', displayKey);
    },
  });

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

  els.filterHelpBtn?.addEventListener('click', () => {
    els.filterHelpPopover.classList.toggle('hidden');
  });
  document.addEventListener('click', (e) => {
    if (
      els.filterHelpPopover &&
      !els.filterHelpPopover.classList.contains('hidden') &&
      !els.filterHelpPopover.contains(e.target) &&
      e.target !== els.filterHelpBtn
    ) {
      els.filterHelpPopover.classList.add('hidden');
    }
  });
  els.clearFilterBtn?.addEventListener('click', () => filterBar?.clear());
  els.fitFilteredBtn?.addEventListener('click', () => scene?.fitToVisible());

  els.zoomInBtn?.addEventListener('click', () => scene?.zoomIn());
  els.zoomOutBtn?.addEventListener('click', () => scene?.zoomOut());
  els.resetViewBtn?.addEventListener('click', () => scene?.resetCamera());
  els.clearFocusBtn?.addEventListener('click', () => {
    scene?.clearFocus();
    inspector?.showEmpty();
  });
  els.toggleLabels?.addEventListener('change', (e) => scene?.setLabelsVisible(e.target.checked));
  els.toggleParticles?.addEventListener('change', (e) => scene?.setParticlesEnabled(e.target.checked));

  els.expandAllBtn?.addEventListener('click', () => {
    if (!displayGraph) return;
    for (const key of displayGraph.clusters.keys()) expandedClusters.add(key);
    rebuildGraph();
  });
  els.collapseAllBtn?.addEventListener('click', () => {
    expandedClusters.clear();
    rebuildGraph();
  });

  els.toggleLeftPanel?.addEventListener('click', () => togglePanel('left'));
  els.toggleRightPanel?.addEventListener('click', () => togglePanel('right'));
  els.collapseTimelineBtn?.addEventListener('click', () => {
    els.timelineWrap.classList.toggle('timeline-collapsed');
  });
  els.collapsePacketListBtn?.addEventListener('click', () => {
    els.packetListWrap.classList.toggle('packetlist-collapsed');
  });

  renderLegend();
}

function togglePanel(side) {
  const drawer = side === 'left' ? els.sidebarLeft : els.sidebarRight;
  const tab = side === 'left' ? els.toggleLeftPanel : els.toggleRightPanel;
  const collapsed = drawer.classList.toggle('panel-collapsed');
  tab.classList.toggle('panel-collapsed', collapsed);
  els.timelineWrap.classList.toggle(`panel-collapsed-${side}`, collapsed);
  els.packetListWrap.classList.toggle(`panel-collapsed-${side}`, collapsed);
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
  const decoded = parsed.packets.map((p) => decodeFrame(p.data, p.linkType));
  finishLoad(parsed.packets, decoded, file.name);
}

/** Shared setup path for both real uploads and the synthetic demo capture. */
function finishLoad(rawPackets, decoded, label) {
  model = buildGraphModel(rawPackets, decoded);
  currentRange = { ...model.timeRange };
  expandedClusters.clear();

  els.fileMeta.textContent = `${label} — ${model.packets.length.toLocaleString()} packets, ${model.hosts.size} hosts, ${model.flows.size} conversations`;
  showProgress(null);
  els.app.classList.add('loaded');

  if (!scene) {
    scene = new Scene3D(els.sceneContainer, {
      onSelect: handleSelect,
      onHover: handleHover,
    });
  }
  inspector.setModel(model);

  timeline = new Timeline(els.timelineCanvas);
  timeline.setData(model.packets, model.timeRange);
  els.timelineCanvas.addEventListener('timeline:range', (e) => {
    currentRange = e.detail;
    refreshViews();
  });

  filterBar = new FilterBar({
    searchInput: els.search,
    presetContainers: [els.presets, els.presetsPanel],
    onChange: refreshViews,
  });

  rebuildGraph();
  scene.resetCamera();
}

/** Recomputes the (possibly clustered) display graph and pushes it into the 3D scene. */
function rebuildGraph() {
  if (!model) return;
  displayGraph = computeDisplayGraph(model.hosts, model.flows, expandedClusters);
  scene.setGraph(displayGraph.hosts, displayGraph.flows);

  const protocolCounts = {};
  for (const f of model.flows.values()) {
    const k = f.appProtocol || f.protocol;
    protocolCounts[k] = (protocolCounts[k] || 0) + 1;
  }
  filterBar.renderPresets(protocolCounts);
  renderFindings();
  refreshViews();
}

function refreshViews() {
  if (!model || !displayGraph) return;

  const inRangePackets = model.packets.filter(
    (p) => p.ts >= currentRange.start && p.ts <= currentRange.end
  );
  const filterActive = filterBar.isActive();
  const filteredPackets = filterActive ? inRangePackets.filter((p) => filterBar.matchesPacket(p)) : inRangePackets;

  // Derive which raw flows the filtered packets belong to, then map those
  // onto the (possibly clustered) display-graph flow keys.
  const activeRawFlowKeys = new Set();
  const activePacketIndexSet = new Set();
  for (const p of filteredPackets) {
    if (p.flowKey) activeRawFlowKeys.add(p.flowKey);
    activePacketIndexSet.add(p.index);
  }
  const effectiveDisplayKeys = new Set();
  for (const rawKey of activeRawFlowKeys) {
    const dk = displayGraph.rawFlowKeyToDisplayKey.get(rawKey);
    if (dk) effectiveDisplayKeys.add(dk);
  }

  scene.setActivity(effectiveDisplayKeys, filterActive);

  const filteredHosts = new Map();
  const filteredFlowMap = new Map();
  for (const [key, flow] of displayGraph.flows) {
    if (!filterActive || effectiveDisplayKeys.has(key)) {
      filteredFlowMap.set(key, flow);
      if (displayGraph.hosts.has(flow.hostA)) filteredHosts.set(flow.hostA, displayGraph.hosts.get(flow.hostA));
      if (displayGraph.hosts.has(flow.hostB)) filteredHosts.set(flow.hostB, displayGraph.hosts.get(flow.hostB));
    }
  }

  inspector.setFilterState({ filterActive, activeFlowKeys: activeRawFlowKeys, activePacketIndexSet });
  packetList.setPackets(filteredPackets, model.timeRange.start);
  updateFilterStatus(filterActive, filteredPackets.length, inRangePackets.length);

  renderDashboard(
    els.dashboardPanel,
    {
      hosts: filteredHosts.size || filterActive ? filteredHosts : displayGraph.hosts,
      flows: filteredFlowMap.size || filterActive ? filteredFlowMap : displayGraph.flows,
      packets: filteredPackets,
    },
    {
      onSelectHost: (hostId) => {
        filterBar.setTerm(`ip.addr==${hostId}`);
        const host = displayGraph.hosts.get(hostId);
        if (host) {
          scene.focusOn('host', hostId);
          inspector.showHost(host);
        }
      },
      onSelectProtocol: (proto) => filterBar.appendTerm(proto),
    }
  );
}

function updateFilterStatus(filterActive, matched, total) {
  if (!els.filterStatus) return;
  if (!filterActive) {
    els.filterStatus.textContent = '';
    els.filterStatus.classList.add('hidden');
    return;
  }
  els.filterStatus.classList.remove('hidden');
  els.filterStatus.textContent = `Showing ${matched.toLocaleString()} of ${total.toLocaleString()} packets in range`;
}

function renderFindings() {
  const findings = runSecurityChecks(model);
  if (!findings.length) {
    els.findingsPanel.innerHTML = '<p class="hint">No anomalies flagged by the built-in heuristics.</p>';
    return;
  }
  els.findingsPanel.innerHTML = findings
    .map(
      (f, i) => `
      <div class="finding finding-${f.severity}" data-finding-idx="${i}">
        <div class="finding-head"><b>${f.type}</b><span class="badge badge-${f.severity}">${f.severity}</span></div>
        <div class="finding-conf">Confidence: ${(f.confidence * 100).toFixed(0)}%</div>
        <p>${f.explanation}</p>
        <p class="hint"><b>Suggested next step:</b> ${f.nextSteps}</p>
      </div>`
    )
    .join('');
  els.findingsPanel.querySelectorAll('[data-finding-idx]').forEach((el, i) => {
    el.addEventListener('click', () => {
      const finding = findings[i];
      const hostId = finding.affected?.[0];
      if (hostId && displayGraph?.hosts.has(hostId)) {
        scene.focusOn('host', hostId);
        inspector.showHost(displayGraph.hosts.get(hostId));
      }
    });
  });
}

function handleSelect(userData) {
  if (!userData) {
    scene?.clearFocus();
    inspector.showEmpty();
    return;
  }
  if (userData.kind === 'cluster') {
    expandedClusters.add(userData.id);
    rebuildGraph();
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
  let text;
  if (userData.kind === 'cluster') {
    text = `${userData.host.id.replace('cluster:', '')} — ${userData.host.memberIds?.length ?? 0} hosts (click to expand)`;
  } else if (userData.kind === 'host') {
    text = `${userData.host.id} — ${userData.host.packets} pkts`;
  } else {
    text = `${userData.flow.hostA} \u2194 ${userData.flow.hostB} (${userData.flow.protocol})`;
  }
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

/** Generates a small synthetic capture in-memory so the app is explorable
 * without needing a real .pcap file on hand — useful for first-time users
 * and for the GitHub Pages demo. */
function loadSyntheticDemo() {
  const { packets, decoded } = buildSyntheticCapture();
  finishLoad(packets, decoded, 'Synthetic demo capture');
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
    payloadOffset: null,
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
