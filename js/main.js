/**
 * main.js
 * Application entry point: wires file upload/parsing, the graph model,
 * clustering, the 3D scene, timeline, filters, packet list, inspector,
 * dashboard/statistics, and security findings together. Everything runs
 * client-side.
 *
 * Two independent, composable narrowing mechanisms drive what's actually
 * rendered and listed everywhere in the app:
 *   1. FILTER — a Wireshark-style display filter (filterBar), evaluated per
 *      packet, that defines "the matching subset of the whole capture."
 *   2. FOCUS — an ego-network selection (focusStack) entered by clicking a
 *      host/flow in the 3D scene, that progressively reveals only the
 *      directly-related neighborhood (N hops out) instead of the whole graph.
 * The *intersection* of these two (computeVisibleGraph) is what's actually
 * pushed into the 3D scene via scene.setGraph() — a genuine rebuild, not a
 * dim/hide overlay — and the same intersection also drives the packet list,
 * inspector drill-down lists, and every statistics tab, so one action
 * narrows the whole app consistently, like navigating a graph database.
 */
import { parseCapture } from './pcap/pcapParser.js';
import { decodeFrame } from './pcap/protocolDecoder.js';
import { buildGraphModel, flowsInRange } from './pcap/graphModel.js';
import { computeDisplayGraph } from './pcap/clustering.js';
import { computeEgoNetwork } from './pcap/egoNetwork.js';
import { runSecurityChecks } from './pcap/securityEngine.js';
import { buildFindingsIndex } from './ui/packetContext.js';
import { Scene3D } from './viz/scene3d.js';
import { Scene2D } from './viz/scene2d.js';
import { Timeline } from './ui/timeline.js';
import { FilterBar } from './ui/filters.js';
import { Inspector } from './ui/inspector.js';
import { PacketList } from './ui/packetList.js';
import { renderDashboard } from './ui/dashboard.js';
import { renderConversations, renderEndpoints, renderNameResolution } from './ui/statsPanel.js';
import { PROTOCOL_COLORS, hexToCss } from './utils/colors.js';

const els = {
  dropZone: document.getElementById('drop-zone'),
  fileInput: document.getElementById('file-input'),
  app: document.getElementById('app'),
  sceneContainer3d: document.getElementById('scene-container-3d'),
  sceneContainer2d: document.getElementById('scene-container-2d'),
  vizMode3dBtn: document.getElementById('viz-mode-3d-btn'),
  vizMode2dBtn: document.getElementById('viz-mode-2d-btn'),
  renderErrorBanner: document.getElementById('render-error-banner'),
  renderErrorDetail: document.getElementById('render-error-detail'),
  renderErrorDismiss: document.getElementById('render-error-dismiss'),
  timelineCanvas: document.getElementById('timeline-canvas'),
  timelineWrap: document.getElementById('timeline-wrap'),
  bottomStack: document.getElementById('bottom-stack'),
  search: document.getElementById('search-input'),
  presetsPanel: document.getElementById('preset-chips-panel'),
  inspectorPanel: document.getElementById('inspector-panel'),
  inspectorBreadcrumb: document.getElementById('inspector-breadcrumb'),
  dashboardPanel: document.getElementById('dashboard-panel'),
  conversationsPanel: document.getElementById('conversations-panel'),
  endpointsPanel: document.getElementById('endpoints-panel'),
  namesPanel: document.getElementById('names-panel'),
  statsTabs: document.getElementById('stats-tabs'),
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
  focusBar: document.getElementById('focus-bar'),
  focusBreadcrumb: document.getElementById('focus-breadcrumb'),
  focusBarSummary: document.getElementById('focus-bar-summary'),
  focusBarHandle: document.getElementById('focus-bar-handle'),
  expandFocusBtn: document.getElementById('expand-focus-btn'),
  exitFocusBtn: document.getElementById('exit-focus-btn'),
  collapseFocusBtn: document.getElementById('collapse-focus-btn'),
  closeFocusBtn: document.getElementById('close-focus-btn'),
  sceneControls: document.getElementById('scene-controls'),
  sceneControlsHandle: document.getElementById('scene-controls-handle'),
  sceneControlsCollapseBtn: document.getElementById('scene-controls-collapse-btn'),
};

let model = null;
let scene3d = null;
let scene2d = null;
// (removed unused renderersInitialized flag -- each component now guards its own construction, see finishLoadInner)
let viz = null; // whichever of scene3d/scene2d is currently active — all camera-only ops go through this
let vizMode = (localStorage.getItem('packetverse.vizMode') === '2d') ? '2d' : '3d';
let timeline = null;
let filterBar = null;
let inspector = null;
let packetList = null;
let currentRange = null;
let displayGraph = null;
let findingsIndex = null; // built by the heuristic engine, cross-referenced *in context* by the Inspector
const expandedClusters = new Set();

// The ego-network navigation stack. Each entry: { kind: 'host'|'flow', id, hops }.
// Empty stack = "no focus", i.e. show the whole (filtered) graph.
let focusStack = [];

init();

function init() {
  // Keep the zoom-control column pinned just above the bottom stack's real,
  // *current* height at all times -- collapsing/expanding either the packet
  // list or the timeline (or the window resizing) all change that height,
  // and this one observer keeps the CSS var correct for every case instead
  // of every call site needing to remember to recompute a pixel offset.
  if (els.bottomStack && typeof ResizeObserver !== 'undefined') {
    const syncBottomStackHeight = () => {
      document.documentElement.style.setProperty('--bottom-stack-h', `${els.bottomStack.offsetHeight}px`);
    };
    new ResizeObserver(syncBottomStackHeight).observe(els.bottomStack);
    syncBottomStackHeight();
  }

  inspector = new Inspector(els.inspectorPanel, els.inspectorBreadcrumb, {
    onFocusHost: (host) => pushFocus({ kind: 'host', id: host.id, hops: 1 }),
    onFocusFlow: (flow) => pushFocus({ kind: 'flow', id: flow.key, hops: 1 }),
    onFollowStream: (flow) => followStream(flow),
    onExitStream: () => exitStreamFocus(),
  });

  packetList = new PacketList(els.packetListContainer, {
    onSelectPacket: (entry) => {
      inspector.showPacket(entry);
      revealInspector();
      focusFlowVisually(entry.flowKey, entry.frame?.endpointA, entry.frame?.endpointB);
    },
  });

  els.fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    // Reset the input's value immediately (before the async parse/decode
    // work below even starts) so selecting the exact same file again later
    // -- e.g. retrying after a failed load -- reliably fires a fresh
    // 'change' event. Some browsers silently skip 'change' if the picked
    // path is identical to the input's current value.
    e.target.value = '';
    if (file) loadFile(file);
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
  els.fitFilteredBtn?.addEventListener('click', () => viz?.fitToVisible());

  els.zoomInBtn?.addEventListener('click', () => viz?.zoomIn());
  els.zoomOutBtn?.addEventListener('click', () => viz?.zoomOut());
  els.resetViewBtn?.addEventListener('click', () => viz?.resetCamera(true));
  els.clearFocusBtn?.addEventListener('click', () => exitFocus());
  els.exitFocusBtn?.addEventListener('click', () => exitFocus());
  els.closeFocusBtn?.addEventListener('click', () => exitFocus());
  els.expandFocusBtn?.addEventListener('click', () => expandFocus());
  els.toggleLabels?.addEventListener('change', (e) => { scene3d?.setLabelsVisible(e.target.checked); scene2d?.setLabelsVisible(e.target.checked); });
  els.toggleParticles?.addEventListener('change', (e) => { scene3d?.setParticlesEnabled(e.target.checked); scene2d?.setParticlesEnabled(e.target.checked); });

  // Focus bar: collapsible (chevron -> compact one-line summary) and
  // draggable (via its \u2316 handle) -- see makeDraggable()/layoutTopStack()
  // above. Close (\u2715) is equivalent to "Exit focus", just reachable
  // without reading the button label.
  const focusCollapsedPref = localStorage.getItem('pv_focusBarCollapsed') === 'true';
  els.focusBar?.classList.toggle('focus-bar-collapsed', focusCollapsedPref);
  els.collapseFocusBtn?.addEventListener('click', () => {
    const collapsed = els.focusBar.classList.toggle('focus-bar-collapsed');
    els.collapseFocusBtn.classList.toggle('pressed', collapsed);
    localStorage.setItem('pv_focusBarCollapsed', String(collapsed));
    if (!collapsed) requestAnimationFrame(layoutTopStack);
  });
  makeDraggable(els.focusBar, els.focusBarHandle, 'pv_focusBarPos');

  // Scene-options panel: collapsible (defaults to collapsed so it never
  // competes for attention on load) and draggable via its header.
  const sceneCollapsedPref = localStorage.getItem('pv_sceneControlsCollapsed');
  const sceneCollapsed = sceneCollapsedPref === null ? true : sceneCollapsedPref === 'true';
  els.sceneControls?.classList.toggle('scene-controls-collapsed', sceneCollapsed);
  els.sceneControlsCollapseBtn?.addEventListener('click', () => {
    const collapsed = els.sceneControls.classList.toggle('scene-controls-collapsed');
    localStorage.setItem('pv_sceneControlsCollapsed', String(collapsed));
  });
  makeDraggable(els.sceneControls, els.sceneControlsHandle, 'pv_sceneControlsPos');

  els.vizMode3dBtn?.addEventListener('click', () => setVizMode('3d'));
  els.vizMode2dBtn?.addEventListener('click', () => setVizMode('2d'));

  els.expandAllBtn?.addEventListener('click', () => {
    if (!displayGraph) return;
    for (const key of displayGraph.clusters.keys()) expandedClusters.add(key);
    rebuildGraph();
  });
  els.collapseAllBtn?.addEventListener('click', () => {
    expandedClusters.clear();
    rebuildGraph();
  });

  els.toggleLeftPanel?.addEventListener('click', () => togglePanel('left', true));
  els.toggleRightPanel?.addEventListener('click', () => togglePanel('right', true));

  // Default both side drawers to collapsed so the visualization gets the
  // full stage on first load, matching a Google-Maps-style "map first,
  // panels on demand" layout instead of boxing the 3D scene in on every
  // side at once. Whatever the user leaves them as is remembered across
  // sessions (mirrors the 2D/3D view preference below).
  const leftPref = localStorage.getItem('pv_leftPanelOpen');
  const rightPref = localStorage.getItem('pv_rightPanelOpen');
  if (leftPref !== 'true') togglePanel('left', false, true);
  if (rightPref !== 'true') togglePanel('right', false, true);
  els.collapseTimelineBtn?.addEventListener('click', () => {
    els.timelineWrap.classList.toggle('timeline-collapsed');
  });
  els.collapsePacketListBtn?.addEventListener('click', () => {
    els.packetListWrap.classList.toggle('packetlist-collapsed');
  });

  els.statsTabs?.addEventListener('click', (e) => {
    const btn = e.target.closest('.tab-btn');
    if (!btn) return;
    const tab = btn.dataset.tab;
    els.statsTabs.querySelectorAll('.tab-btn').forEach((b) => b.classList.toggle('tab-active', b === btn));
    document.querySelectorAll('.tab-pane').forEach((p) => p.classList.toggle('tab-pane-active', p.dataset.pane === tab));
  });

  renderLegend();
}

function showRenderError(err, which) {
  if (!els.renderErrorBanner) return;
  els.renderErrorDetail.textContent = `[${which}] ${err?.message || err}`;
  els.renderErrorBanner.classList.remove('hidden');
}
els.renderErrorDismiss?.addEventListener('click', () => {
  els.renderErrorBanner.classList.add('hidden');
});

/** @param {boolean} persist whether this call should update the remembered
 * open/closed preference (user-initiated clicks do; the one-time startup
 * default-collapse call does not, or every fresh session would just
 * silently overwrite whatever the user chose last time before it's read). */
/** Auto-reveals the right-hand Inspector drawer whenever the user actively
 * selects/drills into something (packet row, graph node/edge, focus push) --
 * without this, a first-time visitor whose drawer starts collapsed (see the
 * default-collapsed logic below) can click a packet and see literally nothing
 * happen, because the Inspector's content *did* update, just off-screen.
 * Deliberately does not persist the change to localStorage: it is a
 * temporary "show me what I just asked for" reveal, not a change to the
 * user's remembered open/closed preference, so an explicit close afterwards
 * is still respected next time they load the app. */
function revealInspector() {
  if (els.sidebarRight?.classList.contains('panel-collapsed')) {
    togglePanel('right', false, false);
  }
}

/** Makes `panelEl` draggable by pointer-dragging `handleEl`, clamped to stay
 * fully within the viewport, and remembers the chosen position across
 * sessions under `storageKey`. Used for the floating Scene-options and Focus
 * panels so the user can move either one out of the way of anything else on
 * screen, on top of the automatic non-overlapping defaults below. */
function makeDraggable(panelEl, handleEl, storageKey) {
  if (!panelEl || !handleEl) return;
  const saved = localStorage.getItem(storageKey);
  if (saved) {
    try {
      const { left, top } = JSON.parse(saved);
      panelEl.style.left = `${left}px`;
      panelEl.style.top = `${top}px`;
      panelEl.style.right = 'auto';
      panelEl.style.transform = 'none';
      panelEl.classList.add('dragged');
    } catch { /* ignore malformed saved position */ }
  }

  let dragging = false, startX = 0, startY = 0, startLeft = 0, startTop = 0;
  handleEl.addEventListener('pointerdown', (e) => {
    dragging = true;
    handleEl.setPointerCapture(e.pointerId);
    const rect = panelEl.getBoundingClientRect();
    startX = e.clientX; startY = e.clientY;
    startLeft = rect.left; startTop = rect.top;
    panelEl.style.transform = 'none';
    e.preventDefault();
  });
  handleEl.addEventListener('pointermove', (e) => {
    if (!dragging) return;
    const parentRect = panelEl.offsetParent?.getBoundingClientRect() || { left: 0, top: 0, width: window.innerWidth, height: window.innerHeight };
    let left = startLeft + (e.clientX - startX) - parentRect.left;
    let top = startTop + (e.clientY - startY) - parentRect.top;
    const maxLeft = parentRect.width - panelEl.offsetWidth - 4;
    const maxTop = parentRect.height - panelEl.offsetHeight - 4;
    left = Math.max(4, Math.min(left, Math.max(4, maxLeft)));
    top = Math.max(4, Math.min(top, Math.max(4, maxTop)));
    panelEl.style.left = `${left}px`;
    panelEl.style.top = `${top}px`;
    panelEl.style.right = 'auto';
    panelEl.classList.add('dragged');
  });
  handleEl.addEventListener('pointerup', (e) => {
    if (!dragging) return;
    dragging = false;
    try { handleEl.releasePointerCapture(e.pointerId); } catch { /* already released */ }
    localStorage.setItem(storageKey, JSON.stringify({ left: parseFloat(panelEl.style.left), top: parseFloat(panelEl.style.top) }));
  });
}

/** Historically this measured and hand-stacked the top-center bars with
 * JS-computed pixel offsets. That approach was fragile (it required every
 * caller to remember to re-run it after anything that could change a
 * bar's height) and was the root cause of the filter-bar/chip-row/focus-bar
 * overlap bugs reported in practice. It's been replaced by a real CSS flex
 * column (#top-stack in index.html + .top-stack in styles.css), which
 * stacks these bars correctly *by construction* with zero JS involvement --
 * so this function is now a deliberate no-op, kept only so its (now historical)
 * call sites elsewhere don't need to be hunted down and removed one by one. */
function layoutTopStack() { /* no-op: see comment above */ }

function togglePanel(side, persist = true, forceCollapsed = null) {
  const drawer = side === 'left' ? els.sidebarLeft : els.sidebarRight;
  const tab = side === 'left' ? els.toggleLeftPanel : els.toggleRightPanel;
  const collapsed = forceCollapsed !== null ? (drawer.classList.toggle('panel-collapsed', forceCollapsed), forceCollapsed) : drawer.classList.toggle('panel-collapsed');
  tab.classList.toggle('panel-collapsed', collapsed);
  els.bottomStack?.classList.toggle(`panel-collapsed-${side}`, collapsed);
  if (persist) localStorage.setItem(side === 'left' ? 'pv_leftPanelOpen' : 'pv_rightPanelOpen', String(!collapsed));
}

/** Transparently gunzips a buffer whose first two bytes are the gzip magic
 * (0x1f 0x8b) using the browser-native DecompressionStream. Capture files are
 * very commonly distributed gzip-compressed (e.g. capture.pcap.gz,
 * nios-traffic.cap.gz), so we handle that here rather than making the user
 * decompress by hand. Non-gzip buffers are returned untouched. If the browser
 * lacks DecompressionStream, we surface a clear, actionable error instead of a
 * cryptic "Unrecognized file format" from the binary parser. */
async function maybeGunzip(buffer) {
  const head = new Uint8Array(buffer, 0, Math.min(2, buffer.byteLength));
  if (head.length < 2 || head[0] !== 0x1f || head[1] !== 0x8b) return buffer;
  if (typeof DecompressionStream === 'undefined') {
    throw new Error('This looks like a gzip-compressed capture, but this browser can’t decompress it. Please gunzip the file first, then upload the raw .pcap/.pcapng/.cap.');
  }
  const stream = new Response(buffer).body.pipeThrough(new DecompressionStream('gzip'));
  return await new Response(stream).arrayBuffer();
}

async function loadFile(file) {
  showProgress(0);
  els.fileMeta.textContent = `Parsing ${file.name} (${(file.size / 1024).toFixed(1)} KB)…`;
  let buffer = await file.arrayBuffer();
  let parsed;
  try {
    // Auto-decompress .gz captures first — the underlying format detection is
    // by magic bytes (not file extension), so once decompressed a NIOS .cap,
    // a .dmp, a .pkt, etc. all parse as whatever they actually are (classic
    // libpcap or pcapng) regardless of the name they were saved under.
    buffer = await maybeGunzip(buffer);
    parsed = parseCapture(buffer, (done, total) => showProgress(done / total));
  } catch (err) {
    els.fileMeta.textContent = `Failed to parse ${file.name}: ${err.message}`;
    showProgress(null);
    return;
  }
  const decoded = parsed.packets.map((p) => decodeFrame(p.data, p.linkType));
  finishLoad(parsed.packets, decoded, file.name);
}

/** Shared setup path for both real uploads and the synthetic demo capture. */
function finishLoad(rawPackets, decoded, label) {
  try {
    finishLoadInner(rawPackets, decoded, label);
  } catch (err) {
    console.error('[PacketVerse] finishLoad failed:', err);
    showRenderError(err, 'load');
  }
}

/** Actual first-load setup body, split out so finishLoad() can wrap it in a
 * single try/catch — previously an exception anywhere in here (e.g. during
 * one-time Scene3D/FilterBar/Timeline construction) would silently abort
 * mid-function: the file-meta text (set moments earlier) stayed populated,
 * but rebuildGraph()/viz.resetCamera() at the bottom never ran, leaving a
 * populated header with a fully blank, un-diagnosable canvas. */
function finishLoadInner(rawPackets, decoded, label) {
  model = buildGraphModel(rawPackets, decoded);
  currentRange = { ...model.timeRange };
  expandedClusters.clear();
  focusStack = [];

  els.fileMeta.textContent = `${label} — ${model.packets.length.toLocaleString()} packets, ${model.hosts.size} hosts, ${model.flows.size} conversations`;
  showProgress(null);
  els.app.classList.add('loaded');

  // Each renderer/component is now guarded independently by "do I already
  // exist" rather than one shared `renderersInitialized` flag. Previously, if
  // *anything* later in this block threw (e.g. the rebuildGraph() crash fixed
  // above), the shared flag had already been set permanently, which caused a
  // real, observed second bug: whichever component never finished
  // constructing on the failed first attempt stayed `null` forever, and the
  // very next load would skip its construction entirely (since the shared
  // flag was already true) and crash trying to call a method on `null` --
  // exactly the "Cannot read properties of null (reading 'clear')" report.
  // Guarding each piece by its own existence means a partial failure can
  // always be retried cleanly on the next load instead of wedging state.
  const firstConstruction = !scene2d && !timeline && !filterBar;
  if (!scene3d && !scene2d) {
    console.log('[PacketVerse] first-load: constructing renderers. container size:',
      els.sceneContainer3d?.clientWidth, 'x', els.sceneContainer3d?.clientHeight);
    try {
      scene3d = new Scene3D(els.sceneContainer3d, {
        onSelect: selectObject,
        onDoubleSelect: isolateObject,
        onHover: handleHover,
        onError: showRenderError,
      });
    } catch (err) {
      // Most likely cause: no WebGL support/context available in this browser
      // environment. Rather than leaving the whole app dead, fall back to the
      // 2D (plain Canvas2D, no WebGL required) view automatically.
      console.error('[PacketVerse] 3D initialization failed, falling back to 2D:', err);
      scene3d = null;
      vizMode = '2d';
      showRenderError(err, '3d-init');
    }
  }
  if (!scene2d) {
    scene2d = new Scene2D(els.sceneContainer2d, {
      onSelect: selectObject,
      onDoubleSelect: isolateObject,
      onHover: handleHover,
      onError: showRenderError,
    });
    console.log('[PacketVerse] first-load: renderers constructed. scene3d:', !!scene3d, 'scene2d:', !!scene2d, 'mode:', vizMode);
    applyVizModeUI(false);
  }

  // Timeline/FilterBar: constructed once each and reused thereafter, same
  // reasoning as above -- re-creating them on every load used to silently
  // stack duplicate mousedown/mousemove/mouseup/resize/input listeners.
  if (!timeline) {
    timeline = new Timeline(els.timelineCanvas);
    els.timelineCanvas.addEventListener('timeline:range', (e) => {
      currentRange = e.detail;
      refreshViews();
    });
  }
  if (!filterBar) {
    filterBar = new FilterBar({
      searchInput: els.search,
      presetContainers: [els.presetsPanel], // top floating row removed: redundant with the left drawer's "Quick protocol filters" panel
      onChange: refreshViews,
    });
  } else if (!firstConstruction) {
    filterBar.clear(); // start every newly-loaded (non-first) capture with a clean, unfiltered view
  }
  inspector.setModel(model);
  timeline.setData(model.packets, model.timeRange);

  rebuildGraph();
  viz?.resetCamera(false);
  // Belt-and-suspenders for the very first load only: re-measure and re-fit one
  // frame later. Every code path here has been verified safe on an already-sized
  // container, but this closes off any remaining browser-specific layout-timing
  // edge case (e.g. a deferred reflow) that pure static tracing can't rule out.
  requestAnimationFrame(() => {
    viz?.resize();
    viz?.fitToVisible(false);
  });
  console.log('[PacketVerse] load complete. hosts:', model.hosts.size, 'flows:', model.flows.size,
    'viz container size:', els.sceneContainer3d?.clientWidth, 'x', els.sceneContainer3d?.clientHeight,
    'active renderer:', vizMode);
  requestAnimationFrame(layoutTopStack);
}

// ---------------------------------------------------------------------------
// Viz-mode (2D/3D) switching. Both renderers are kept live and in sync with
// the same graph/focus state at all times — switching is instant (no
// recompute) and each remembers its own camera framing. Preference persists
// across sessions via localStorage.
// ---------------------------------------------------------------------------

function setVizMode(mode) {
  if (mode !== '2d' && mode !== '3d') return;
  vizMode = mode;
  localStorage.setItem('packetverse.vizMode', mode);
  applyVizModeUI(true);
}

function applyVizModeUI(animateFit) {
  const is3d = vizMode === '3d';
  els.sceneContainer3d?.classList.toggle('hidden', !is3d);
  els.sceneContainer2d?.classList.toggle('hidden', is3d);
  els.vizMode3dBtn?.classList.toggle('viz-mode-active', is3d);
  els.vizMode2dBtn?.classList.toggle('viz-mode-active', !is3d);
  viz = is3d ? scene3d : scene2d;
  if (!viz) return;
  // The just-shown container may have been `display:none` (0 size) until
  // now, so resize before framing or the fit-to-view math would use stale
  // dimensions.
  viz.resize();
  viz?.fitToVisible(animateFit);
}

/** Pushes the current visible graph to BOTH renderers (not just the active
 * one) so switching modes never shows stale data or requires a recompute. */
function setGraphAll(hosts, flows) {
  scene3d?.setGraph(hosts, flows);
  scene2d?.setGraph(hosts, flows);
}
function setPrimaryFocusAll(kind, id) {
  scene3d?.setPrimaryFocus(kind, id);
  scene2d?.setPrimaryFocus(kind, id);
}

/** The single, correct way to visually focus a flow from anywhere in the
 * app (packet list, "View full conversation", clicking a conversation in
 * the dashboard, etc). Packets and the Inspector operate in RAW flow-key
 * space, but the 3D/2D scenes render DISPLAY-space edges -- these differ
 * whenever subnet clustering is active, so a raw key must be translated
 * before it means anything to the scene. If the flow's edge isn't
 * currently rendered at all (most commonly: both endpoints are collapsed
 * into the same subnet cluster, so it's "internal" traffic hidden by
 * design), this falls back to highlighting the cluster/host node at
 * either end instead of silently doing nothing -- every click now visibly
 * reacts to something, and the camera always moves toward it. */
function focusFlowVisually(rawOrDisplayKey, hostAId, hostBId) {
  if (!displayGraph || !rawOrDisplayKey) return;
  const displayKey = displayGraph.rawFlowKeyToDisplayKey.get(rawOrDisplayKey) || rawOrDisplayKey;
  if (displayGraph.flows.has(displayKey)) {
    setPrimaryFocusAll('flow', displayKey);
    scene3d?.centerOnEdge(displayKey);
    scene2d?.centerOnEdge(displayKey);
    return;
  }
  const a = hostAId != null ? displayGraph.hostToDisplayId?.get(hostAId) : null;
  const b = hostBId != null ? displayGraph.hostToDisplayId?.get(hostBId) : null;
  const targetHost = (a && displayGraph.hosts.has(a)) ? a : (b && displayGraph.hosts.has(b)) ? b : null;
  if (targetHost) {
    setPrimaryFocusAll('host', targetHost);
    scene3d?.centerOn(targetHost);
    scene2d?.centerOn(targetHost);
  } else {
    clearPrimaryFocusAll();
  }
}
function clearPrimaryFocusAll() {
  scene3d?.clearPrimaryFocus();
  scene2d?.clearPrimaryFocus();
}

/** Recomputes the (possibly clustered) display graph from the full model.
 * This is the "base" graph before filter/focus narrowing is applied. */
function rebuildGraph() {
  try {
    rebuildGraphInner();
  } catch (err) {
    console.error('[PacketVerse] rebuildGraph failed:', err);
    showRenderError(err, 'graph');
  }
}

function rebuildGraphInner() {
  if (!model) return;
  console.log('[PacketVerse] rebuildGraph: packets=', model.packets.length,
    'hosts=', model.hosts.size, 'flows=', model.flows.size);
  displayGraph = computeDisplayGraph(model.hosts, model.flows, expandedClusters);
  console.log('[PacketVerse] rebuildGraph: displayGraph hosts=', displayGraph.hosts.size,
    'flows=', displayGraph.flows.size, 'clusters=', displayGraph.clusters?.size ?? 0);

  const protocolCounts = {};
  for (const f of model.flows.values()) {
    const k = f.appProtocol || f.protocol;
    protocolCounts[k] = (protocolCounts[k] || 0) + 1;
  }
  filterBar?.renderPresets(protocolCounts);
  renderFindings();
  refreshViews();
}

/**
 * The core narrowing pipeline. Computes:
 *   1. The packet-level filter match set (within the current time range).
 *   2. The display-graph subset (hosts/flows) that filter set maps onto.
 *   3. If a focus is active, the ego-network subset of THAT within N hops.
 * Then pushes the final result into the 3D scene (a real rebuild) and every
 * other view (packet list, inspector, dashboard, stats tabs) so they all
 * agree on "what's currently in view."
 */
function refreshViews() {
  try {
    refreshViewsInner();
  } catch (err) {
    console.error('[PacketVerse] refreshViews failed:', err);
    showRenderError(err, 'refresh');
  }
}

function refreshViewsInner() {
  if (!model || !displayGraph) return;

  const inRangePackets = model.packets.filter(
    (p) => p.ts >= currentRange.start && p.ts <= currentRange.end
  );
  const filterActive = filterBar.isActive();
  const filteredPackets = filterActive ? inRangePackets.filter((p) => filterBar.matchesPacket(p)) : inRangePackets;

  // Which raw flows survive the filter, mapped onto (possibly clustered) display-graph keys.
  const activeRawFlowKeys = new Set();
  for (const p of filteredPackets) {
    if (p.flowKey) activeRawFlowKeys.add(p.flowKey);
  }
  const filteredDisplayKeys = new Set();
  for (const rawKey of activeRawFlowKeys) {
    const dk = displayGraph.rawFlowKeyToDisplayKey.get(rawKey);
    if (dk) filteredDisplayKeys.add(dk);
  }

  let filteredHosts, filteredFlows;
  if (!filterActive) {
    filteredHosts = displayGraph.hosts;
    filteredFlows = displayGraph.flows;
  } else {
    filteredFlows = new Map();
    filteredHosts = new Map();
    for (const [key, flow] of displayGraph.flows) {
      if (!filteredDisplayKeys.has(key)) continue;
      filteredFlows.set(key, flow);
      if (displayGraph.hosts.has(flow.hostA)) filteredHosts.set(flow.hostA, displayGraph.hosts.get(flow.hostA));
      if (displayGraph.hosts.has(flow.hostB)) filteredHosts.set(flow.hostB, displayGraph.hosts.get(flow.hostB));
    }
  }

  // Ego-network focus narrows the filtered subgraph further (intersection, not replacement) —
  // clicking into a node while a filter is active stays consistent with that filter.
  const focus = focusStack[focusStack.length - 1] || null;
  let visibleHosts = filteredHosts;
  let visibleFlows = filteredFlows;
  if (focus && focus.kind === 'stream') {
    // Follow Stream isolation: show *exactly* the one conversation being
    // followed (not the general ego-network of its endpoints, which could
    // pull in unrelated flows those hosts happen to also have) — unless the
    // user explicitly asked to expand outward, in which case it behaves like
    // a normal 2-host ego network from there on.
    if (focus.hops > 0) {
      const ego = computeEgoNetwork(filteredHosts, filteredFlows, [focus.hostA, focus.hostB], focus.hops);
      visibleHosts = ego.hosts;
      visibleFlows = ego.flows;
    } else {
      visibleHosts = new Map();
      visibleFlows = new Map();
      if (filteredHosts.has(focus.hostA)) visibleHosts.set(focus.hostA, filteredHosts.get(focus.hostA));
      if (filteredHosts.has(focus.hostB)) visibleHosts.set(focus.hostB, filteredHosts.get(focus.hostB));
      if (filteredFlows.has(focus.id)) visibleFlows.set(focus.id, filteredFlows.get(focus.id));
    }
  } else if (focus) {
    const focusHostIds = focus.kind === 'host'
      ? [focus.id]
      : (() => {
          const f = filteredFlows.get(focus.id) || displayGraph.flows.get(focus.id);
          return f ? [f.hostA, f.hostB] : [];
        })();
    const ego = computeEgoNetwork(filteredHosts, filteredFlows, focusHostIds, focus.hops);
    visibleHosts = ego.hosts;
    visibleFlows = ego.flows;
  }

  setGraphAll(visibleHosts, visibleFlows);
  renderFocusBar();

  // Every other view (packet list, inspector, dashboard, stats tabs) reflects
  // this exact same visible set, so nothing disagrees with the 3D scene.
  const visibleDisplayKeySet = new Set(visibleFlows.keys());
  const anyNarrowing = filterActive || !!focus;
  const visiblePackets = anyNarrowing
    ? filteredPackets.filter((p) => {
        const dk = displayGraph.rawFlowKeyToDisplayKey.get(p.flowKey);
        return dk ? visibleDisplayKeySet.has(dk) : !focus; // packets with no flow (rare) stay visible unless focus-narrowed
      })
    : filteredPackets;

  const visibleRawFlowKeys = new Set();
  const visiblePacketIndexSet = new Set();
  for (const p of visiblePackets) {
    if (p.flowKey) visibleRawFlowKeys.add(p.flowKey);
    visiblePacketIndexSet.add(p.index);
  }

  inspector.setFilterState({ filterActive: anyNarrowing, activeFlowKeys: visibleRawFlowKeys, activePacketIndexSet: visiblePacketIndexSet });
  packetList.setPackets(visiblePackets, model.timeRange.start);
  updateFilterStatus(filterActive, filteredPackets.length, inRangePackets.length, focus, visibleHosts.size);

  renderDashboard(
    els.dashboardPanel,
    { hosts: visibleHosts, flows: visibleFlows, packets: visiblePackets },
    {
      onSelectHost: (hostId) => {
        const host = visibleHosts.get(hostId) || displayGraph.hosts.get(hostId);
        if (host) pushFocus({ kind: 'host', id: hostId, hops: 1 });
      },
      onSelectProtocol: (proto) => filterBar.appendTerm(proto),
    }
  );
  renderConversations(els.conversationsPanel, visibleFlows, {
    onSelectFlow: (flow) => pushFocus({ kind: 'flow', id: flow.key, hops: 1 }),
  });
  renderEndpoints(els.endpointsPanel, visibleHosts, {
    onSelectHost: (hostId) => pushFocus({ kind: 'host', id: hostId, hops: 1 }),
  });
  renderNameResolution(els.namesPanel, model.nameTable);
  // Re-stack the floating top-center bars now that filter-status/focus-bar
  // visibility (and the chip row's wrap height) may have just changed, so
  // nothing floating above ever ends up covering something below it.
  requestAnimationFrame(layoutTopStack);
}

// ---------------------------------------------------------------------------
// Ego-network focus stack: push (click into a node), expand (+1 hop),
// pop/exit (breadcrumb navigation) — this is the "graph database traversal"
// navigation model, replacing the old dim-everything-else approach.
// ---------------------------------------------------------------------------

/** Double-click action: isolates the clicked host/flow's neighborhood —
 * this is the graph-database-style "traverse into" step. Single clicks
 * (selectObject, below) only select+center and never narrow the graph. */
function pushFocus(entry) {
  focusStack.push(entry);
  refreshViews();
  if (entry.kind === 'flow') {
    const rawFlow = model?.flows.get(entry.id);
    focusFlowVisually(entry.id, rawFlow?.hostA, rawFlow?.hostB);
  } else {
    setPrimaryFocusAll(entry.kind, entry.id);
  }
  viz?.fitToVisible();
  const host = displayGraph?.hosts.get(entry.kind === 'host' ? entry.id : '');
  if (entry.kind === 'host' && host) { inspector.showHost(host); revealInspector(); }
  else if (entry.kind === 'flow') {
    const flow = displayGraph?.flows.get(entry.id);
    if (flow) { inspector.showFlow(flow); revealInspector(); }
  }
}

function expandFocus() {
  const top = focusStack[focusStack.length - 1];
  if (!top) return;
  top.hops += 1;
  refreshViews();
  viz?.fitToVisible();
}

function popFocusTo(index) {
  focusStack = focusStack.slice(0, index + 1);
  refreshViews();
  viz?.fitToVisible();
}

function exitFocus() {
  if (!focusStack.length) {
    clearPrimaryFocusAll();
    inspector.showEmpty();
    return;
  }
  focusStack = [];
  refreshViews();
  viz?.fitToVisible();
}

/** Follow Stream: pushes a dedicated 'stream' focus entry that isolates the
 * visualization down to exactly the one conversation being followed — the
 * graph rebuilds around it, the camera fits it, and the packet list/inspector
 * narrow to just its packets, all via the same refreshViews() pipeline every
 * other filter/focus change already goes through. */
function followStream(flow) {
  if (!displayGraph) return;
  const displayKey = displayGraph.rawFlowKeyToDisplayKey.get(flow.key) || flow.key;
  const displayFlow = displayGraph.flows.get(displayKey);
  if (!displayFlow) return;
  focusStack.push({ kind: 'stream', id: displayKey, hostA: displayFlow.hostA, hostB: displayFlow.hostB, hops: 0 });
  refreshViews();
  setPrimaryFocusAll('flow', displayKey);
  viz?.fitToVisible();
}

/** Exits Follow Stream mode, popping only the stream layer off the focus
 * stack — this naturally "restores the previous visualization and filters"
 * (whatever filter text and/or ego-network focus was active underneath is
 * untouched, since it was never modified when entering stream mode). */
function exitStreamFocus() {
  const top = focusStack[focusStack.length - 1];
  if (top?.kind === 'stream') {
    focusStack.pop();
  } else {
    focusStack = [];
  }
  refreshViews();
  viz?.fitToVisible();
  const remaining = focusStack[focusStack.length - 1];
  if (remaining) setPrimaryFocusAll(remaining.kind === 'stream' ? 'flow' : remaining.kind, remaining.kind === 'stream' ? remaining.id : remaining.id);
  else clearPrimaryFocusAll();
  inspector.showEmpty();
}

/** Single-click action: pure selection — emphasizes the clicked object and
 * centers/zooms the camera on it, WITHOUT narrowing what's rendered. This is
 * what makes clicking feel predictable rather than immediately cutting away
 * the rest of the graph; double-click (isolateObject) is the deliberate
 * "narrow the investigation" action. */
function selectObject(userData) {
  if (!userData) {
    clearPrimaryFocusAll();
    inspector.showEmpty();
    return;
  }
  if (userData.kind === 'cluster') {
    expandedClusters.add(userData.id);
    rebuildGraph();
    return;
  }
  if (userData.kind === 'host') {
    setPrimaryFocusAll('host', userData.id);
    viz?.centerOn(userData.id);
    inspector.showHost(userData.host);
    revealInspector();
  } else if (userData.kind === 'flow') {
    setPrimaryFocusAll('flow', userData.key);
    viz?.centerOn(userData.flow.hostA);
    inspector.showFlow(userData.flow);
    revealInspector();
  }
}

/** Double-click action: isolates the clicked object's neighborhood (see
 * pushFocus above) — the actual "traverse the graph database" step. */
function isolateObject(userData) {
  if (!userData || userData.kind === 'cluster') return;
  if (userData.kind === 'host') pushFocus({ kind: 'host', id: userData.id, hops: 1 });
  else if (userData.kind === 'flow') pushFocus({ kind: 'flow', id: userData.key, hops: 1 });
}

function renderFocusBar() {
  if (!els.focusBar) return;
  if (!focusStack.length) {
    els.focusBar.classList.add('hidden');
    return;
  }
  els.focusBar.classList.remove('hidden');
  const crumbs = [`<button class="fb-item" data-focus-idx="-1">All traffic</button>`];
  focusStack.forEach((f, i) => {
    const isLast = i === focusStack.length - 1;
    const label = f.kind === 'host' ? shortenLabel(f.id) : f.kind === 'stream' ? `\u21c6 Stream: ${flowLabel(f.id)}` : flowLabel(f.id);
    const hopNote = f.hops > 1 ? ` (+${f.hops} hops)` : '';
    crumbs.push(`<span class="fb-sep">\u203a</span>`);
    crumbs.push(
      isLast
        ? `<span class="fb-item fb-current">${escapeHtml(label)}${hopNote}</span>`
        : `<button class="fb-item" data-focus-idx="${i}">${escapeHtml(label)}</button>`
    );
  });
  els.focusBreadcrumb.innerHTML = crumbs.join('');
  els.focusBreadcrumb.querySelectorAll('[data-focus-idx]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const idx = Number(btn.dataset.focusIdx);
      if (idx < 0) exitFocus();
      else popFocusTo(idx);
    });
  });
  // Compact one-line summary shown instead of the full breadcrumb when the
  // bar is collapsed (see collapse-focus-btn below).
  if (els.focusBarSummary) {
    const top = focusStack[focusStack.length - 1];
    const label = top.kind === 'host' ? shortenLabel(top.id) : top.kind === 'stream' ? `Stream: ${flowLabel(top.id)}` : flowLabel(top.id);
    els.focusBarSummary.textContent = `\u2316 Focused on ${label}${focusStack.length > 1 ? ` (+${focusStack.length - 1} more)` : ''}`;
  }
}

function shortenLabel(id) {
  return id.length > 24 ? id.slice(0, 22) + '\u2026' : id;
}
function flowLabel(flowKey) {
  const flow = displayGraph?.flows.get(flowKey);
  return flow ? `${shortenLabel(flow.hostA)} \u2194 ${shortenLabel(flow.hostB)}` : flowKey;
}
function escapeHtml(str) {
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function updateFilterStatus(filterActive, matched, total, focus, visibleHostCount) {
  if (!els.filterStatus) return;
  if (!filterActive && !focus) {
    els.filterStatus.textContent = '';
    els.filterStatus.classList.add('hidden');
    return;
  }
  els.filterStatus.classList.remove('hidden');
  const parts = [];
  if (filterActive) parts.push(`Showing ${matched.toLocaleString()} of ${total.toLocaleString()} packets in range`);
  if (focus) parts.push(`focused on ${visibleHostCount.toLocaleString()} host${visibleHostCount === 1 ? '' : 's'} within ${focus.hops} hop${focus.hops === 1 ? '' : 's'}`);
  els.filterStatus.textContent = parts.join(' \u00b7 ');
}

/** Runs the deterministic heuristic engine once per capture/re-cluster and
 * indexes results by host so the Inspector can fold them in as supporting
 * context on whatever the user is currently looking at (see
 * "Analyst guidance" in js/ui/packetContext.js), instead of a standalone,
 * always-the-same list shown regardless of selection. */
function renderFindings() {
  const findings = runSecurityChecks(model);
  findingsIndex = buildFindingsIndex(findings);
  inspector.setFindingsIndex(findingsIndex);
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
    text = `${userData.host.id} — ${userData.host.packets} pkts (click to focus)`;
  } else {
    text = `${userData.flow.hostA} \u2194 ${userData.flow.hostB} (${userData.flow.protocol}) — click to focus`;
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
  // Ports/sessions are derived from the (a,b) pair, NOT from the running
  // packet index `i` — reusing the same source port for repeated traffic
  // between the same two hosts is what makes this look like a *handful* of
  // real ongoing conversations (matching how buildFlowKey groups packets
  // into flows) rather than ~80 one-packet "flows" for only 4 hosts. That
  // earlier per-packet-unique-port version was overloading the force layout
  // with dozens of redundant parallel edges between the same pair, which is
  // what caused the visualization to visibly overshoot/oscillate on load.
  const session = (i % hostsIp.length) * 100;
  if (proto === 'DNS') {
    base.layers.l3 = { type: 'IPv4', srcIp: a, dstIp: b, protocol: 'UDP', ttl: 64 };
    base.layers.l4 = { type: 'UDP', srcPort: 51000 + session, dstPort: 53 };
    base.layers.l7 = { type: 'DNS', isResponse: i % 2 === 1, name: 'example.com', queryType: 'A', qdCount: 1, anCount: i % 2 };
    base.tags.push('UDP', 'DNS');
  } else if (proto === 'TLS') {
    base.layers.l3 = { type: 'IPv4', srcIp: a, dstIp: b, protocol: 'TCP', ttl: 64 };
    base.layers.l4 = { type: 'TCP', srcPort: 51500 + session, dstPort: 443, flags: { SYN: false, ACK: true, FIN: false, RST: false, PSH: true, URG: false } };
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
    base.layers.l4 = { type: 'TCP', srcPort: 52000 + session, dstPort: 80, flags: { SYN: i % 10 === 0, ACK: true, FIN: false, RST: false, PSH: true, URG: false } };
    base.tags.push('TCP');
  }
  base.summary = `${proto} demo packet`;
  return base;
}

function renderLegend() {
  if (!els.legendPanel) return;
  const protoRows = Object.entries(PROTOCOL_COLORS)
    .map(
      ([proto, hex]) =>
        `<div class="legend-row"><span class="legend-swatch" style="background:${hexToCss(hex)}"></span>${proto}</div>`
    )
    .join('');
  // Beyond "what color is what protocol", the thing users actually get
  // stuck on is what size/shape/brightness/motion *mean* — so the legend
  // also documents the full visual language of the 3D/2D scene in one
  // place, phrased in plain English rather than assuming it's self-evident.
  els.legendPanel.innerHTML = `
    <div class="legend-section-title">Connection color = protocol</div>
    ${protoRows}
    <div class="legend-section-title">What the shapes mean</div>
    <div class="legend-row"><span class="legend-glyph legend-glyph-sphere"></span>A device (host) — one IP or MAC address that sent or received traffic.</div>
    <div class="legend-row"><span class="legend-glyph legend-glyph-cluster"></span>A collapsed subnet — several hosts on the same /24 network, grouped into one node to reduce clutter. Click it to expand.</div>
    <div class="legend-row"><span class="legend-glyph legend-glyph-line"></span>A conversation between two devices — an animated line, colored by the protocol carrying the most traffic in it.</div>
    <div class="legend-section-title">What size &amp; motion mean</div>
    <div class="legend-row">Bigger sphere → more total bytes sent/received by that host.</div>
    <div class="legend-row">Thicker, brighter line → more bytes exchanged in that conversation.</div>
    <div class="legend-row">Moving dots along a line → packets actually flowing; faster dots = higher packet rate.</div>
    <div class="legend-row">Dim / faded objects → exist in the capture but excluded by the current filter, time range, or focus.</div>
    <div class="legend-section-title">Colors that aren't protocols</div>
    <div class="legend-row"><span class="legend-swatch" style="background:#e9b44c"></span>Amber wireframe = a collapsed subnet cluster, not a single device.</div>
    <div class="legend-row"><span class="legend-swatch" style="background:#9e9e9e"></span>Gray = broadcast/ARP-only traffic (no higher-layer protocol seen).</div>
  `;
}
