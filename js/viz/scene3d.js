/**
 * scene3d.js
 * Three.js scene: renders hosts as nodes and flows as thick, glowing,
 * animated edges; handles camera controls, hover/click raycasting, host
 * labels, click-to-focus traffic highlighting, and bloom post-processing.
 */
import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import { Line2 } from 'three/addons/lines/Line2.js';
import { LineMaterial } from 'three/addons/lines/LineMaterial.js';
import { LineGeometry } from 'three/addons/lines/LineGeometry.js';
import { EffectComposer } from 'three/addons/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/addons/postprocessing/RenderPass.js';
import { UnrealBloomPass } from 'three/addons/postprocessing/UnrealBloomPass.js';
import { colorForProtocol } from '../utils/colors.js';
import { ForceLayout3D } from './forceLayout.js';

const DIM_OPACITY = 0.08;
const ACTIVE_OPACITY = 0.9;

export class Scene3D {
  constructor(container, { onSelect, onHover, onDoubleSelect, onError } = {}) {
    this.container = container;
    this.onSelect = onSelect || (() => {});
    this.onHover = onHover || (() => {});
    this.onDoubleSelect = onDoubleSelect || (() => {});
    this.onError = onError || (() => {});
    this._renderFailed = false; // once true, stop trying every frame (avoids console/error-banner spam)
    this.showLabels = true;
    this.particlesEnabled = true;
    this.primaryFocus = null; // cosmetic emphasis only — visibility is controlled entirely by setGraph()
    this._flight = null; // active camera fly-to tween, if any
    this._clickTimer = null; // debounces single- vs double-click so a dblclick doesn't also fire a single select
    this._dragMoved = false; // suppresses click-to-select when the gesture was actually an orbit drag

    this.scene = new THREE.Scene();
    this.scene.background = new THREE.Color(0x090d13);
    this.scene.fog = new THREE.FogExp2(0x090d13, 0.0016);

    this.camera = new THREE.PerspectiveCamera(55, 1, 0.1, 8000);
    this.camera.position.set(0, 90, 340);

    this.renderer = new THREE.WebGLRenderer({ antialias: true });
    this.renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
    container.appendChild(this.renderer.domElement);

    this.controls = new OrbitControls(this.camera, this.renderer.domElement);
    this.controls.enableDamping = true;
    this.controls.dampingFactor = 0.08;
    this.controls.minDistance = 20;
    this.controls.maxDistance = 3000;

    this.scene.add(new THREE.AmbientLight(0x8899aa, 1.1));
    const dirLight = new THREE.DirectionalLight(0xffffff, 0.5);
    dirLight.position.set(150, 250, 150);
    this.scene.add(dirLight);

    this.nodeGroup = new THREE.Group();
    this.edgeGroup = new THREE.Group();
    this.labelGroup = new THREE.Group();
    this.scene.add(this.nodeGroup, this.edgeGroup, this.labelGroup);

    this.nodeMeshes = new Map(); // hostId -> mesh
    this.nodeHalos = new Map(); // hostId -> halo sprite (glow)
    this.labels = new Map(); // hostId -> sprite
    this.edgeLines = new Map(); // flowKey -> { line, material, particle, flow }
    this.adjacency = new Map(); // hostId -> Set(flowKey)
    this.layout = null;

    this.raycaster = new THREE.Raycaster();
    this.pointer = new THREE.Vector2();
    this.clock = new THREE.Clock();
    this.settleTicks = 0;

    this._setupComposer();
    this._bindEvents();
    this._animate();
    this.resize();
    // Defensive: re-sync the renderer's size whenever the container's actual
    // box changes for ANY reason — becoming visible after being display:none
    // (e.g. switching modes), a panel collapsing/expanding, a window resize
    // that the `window resize` listener alone might miss, etc. This is what
    // actually eliminates the whole "blank 0x0 canvas" failure class, rather
    // than relying on every call site to remember to call resize() at the
    // exact right moment.
    if (typeof ResizeObserver !== 'undefined') {
      this._resizeObserver = new ResizeObserver(() => this.resize());
      this._resizeObserver.observe(this.container);
    }
  }

  _setupComposer() {
    this.composer = new EffectComposer(this.renderer);
    this.renderPass = new RenderPass(this.scene, this.camera);
    this.composer.addPass(this.renderPass);
    this.bloomPass = new UnrealBloomPass(new THREE.Vector2(1, 1), 0.75, 0.6, 0.15);
    this.composer.addPass(this.bloomPass);
  }

  _bindEvents() {
    window.addEventListener('resize', () => this.resize());
    this.renderer.domElement.addEventListener('pointermove', (e) => this._onPointerMove(e));
    this.renderer.domElement.addEventListener('pointerdown', (e) => {
      this._dragMoved = false;
      this._isPointerDown = true;
      this._downPos = { x: e.clientX, y: e.clientY };
    });
    window.addEventListener('pointerup', (e) => {
      this._isPointerDown = false;
      if (this._downPos && Math.hypot(e.clientX - this._downPos.x, e.clientY - this._downPos.y) > 4) {
        this._dragMoved = true;
      }
    });
    this.renderer.domElement.addEventListener('click', (e) => this._onClick(e));
    this.renderer.domElement.addEventListener('dblclick', (e) => this._onDoubleClick(e));
  }

  resize() {
    const w = Math.max(1, this.container.clientWidth);
    const h = Math.max(1, this.container.clientHeight);
    this.camera.aspect = w / h;
    this.camera.updateProjectionMatrix();
    this.renderer.setSize(w, h);
    this.composer.setSize(w, h);
    this.bloomPass.setSize(w, h);
    const pr = this.renderer.getPixelRatio();
    for (const entry of this.edgeLines.values()) {
      entry.material.resolution.set(w * pr, h * pr);
    }
  }

  setLabelsVisible(visible) {
    this.showLabels = visible;
    this.labelGroup.visible = visible;
  }

  setParticlesEnabled(enabled) {
    this.particlesEnabled = enabled;
    // Re-apply current focus/dim state so particle visibility is recomputed
    // immediately using the new flag -- reuses the exact same per-edge logic
    // setPrimaryFocus already uses, so there's only one place this is decided.
    this._applyVisualState();
  }

  /** Re-derives per-edge/per-node visual state (particle visibility, opacity,
   * emissive intensity) from current `particlesEnabled` + `primaryFocus`,
   * without changing what focus is active. Called whenever a toggle changes
   * (e.g. the "Flow animation" checkbox) so the effect is immediate instead
   * of only taking effect on the next selection change. */
  _applyVisualState() {
    this.setPrimaryFocus(this.primaryFocus?.kind ?? null, this.primaryFocus?.id ?? null);
  }

  /** Dolly the camera toward/away from the current orbit target (Google-Maps-style +/- zoom). */
  zoomBy(factor) {
    const dir = this.camera.position.clone().sub(this.controls.target);
    const dist = dir.length();
    const next = THREE.MathUtils.clamp(dist * factor, this.controls.minDistance, this.controls.maxDistance);
    dir.setLength(next);
    this.camera.position.copy(this.controls.target).add(dir);
  }
  zoomIn() { this.zoomBy(0.78); }
  zoomOut() { this.zoomBy(1.28); }

  /** Rebuilds meshes to match the currently *visible* hosts/flows (the result of
   * filter ∩ ego-network-focus intersection computed in main.js). This is a real
   * rebuild — objects that don't belong in the new set are disposed, not just
   * hidden — so navigating is genuinely "traversing a reduced graph" rather than
   * dimming parts of one giant unchanging scene. Node positions are preserved
   * across rebuilds (via the previous layout) so the graph doesn't jump/reset
   * every time a filter or focus changes; only genuinely new nodes get a fresh
   * random start position, then the physics settles them in. */
  setGraph(hosts, flows) {
    const previousLayout = this.layout;
    this._disposeGroup(this.nodeGroup);
    this._disposeGroup(this.edgeGroup);
    this._disposeGroup(this.labelGroup);
    this.nodeMeshes.clear();
    this.nodeHalos.clear();
    this.labels.clear();
    this.edgeLines.clear();
    this.adjacency.clear();
    this.settleTicks = 0;

    const ids = [...hosts.keys()];
    this.layout = new ForceLayout3D(ids);
    if (previousLayout) {
      // Carry over prior positions so a filter/focus change re-settles the
      // existing arrangement rather than reshuffling everything from
      // scratch — a moderate (not full) reheat is enough to accommodate
      // whatever edges/nodes actually changed.
      let anyCarried = false;
      for (const id of ids) {
        const prev = previousLayout.positions.get(id);
        if (prev) { this.layout.positions.set(id, { ...prev }); anyCarried = true; }
      }
      this.layout.reheat(anyCarried ? 0.5 : 1);
    }

    const maxBytes = Math.max(1, ...[...hosts.values()].map((h) => h.bytes));
    for (const host of hosts.values()) {
      const size = 2.6 + 7 * Math.cbrt(host.bytes / maxBytes);
      const color = nodeColorFor(host);

      const clusterSize = host.isCluster ? size * 1.6 : size;
      const geometry = host.isCluster
        ? new THREE.IcosahedronGeometry(clusterSize, 1)
        : new THREE.SphereGeometry(size, 20, 20);
      const material = new THREE.MeshStandardMaterial({
        color,
        emissive: color,
        emissiveIntensity: 0.85,
        roughness: 0.35,
        metalness: 0.15,
        wireframe: !!host.isCluster,
      });
      const mesh = new THREE.Mesh(geometry, material);
      mesh.userData = { kind: host.isCluster ? 'cluster' : 'host', id: host.id, host, baseColor: color, baseSize: clusterSize };
      this.nodeGroup.add(mesh);
      this.nodeMeshes.set(host.id, mesh);

      const halo = makeHaloSprite(color, clusterSize * (host.isCluster ? 7 : 5));
      this.labelGroup.add(halo);
      this.nodeHalos.set(host.id, halo);

      const label = makeTextSprite(host.isCluster ? `\u25C8 ${shortenId(host.id.replace('cluster:', ''))} (${host.memberIds?.length ?? '?'} hosts)` : shortenId(host.id));
      label.visible = this.showLabels;
      this.labelGroup.add(label);
      this.labels.set(host.id, label);

      this.adjacency.set(host.id, new Set());
    }

    const w = Math.max(1, this.container.clientWidth);
    const h = Math.max(1, this.container.clientHeight);
    const pr = this.renderer.getPixelRatio();

    const maxFlowBytes = Math.max(1, ...[...flows.values()].map((f) => f.bytes));
    for (const flow of flows.values()) {
      if (!hosts.has(flow.hostA) || !hosts.has(flow.hostB)) continue;
      const color = colorForProtocol(flow.appProtocol || flow.protocol);
      const widthPx = 1.4 + 5 * Math.cbrt(flow.bytes / maxFlowBytes);

      const geometry = new LineGeometry();
      geometry.setPositions([0, 0, 0, 0, 0, 0]);
      const material = new LineMaterial({
        color,
        linewidth: widthPx,
        transparent: true,
        opacity: ACTIVE_OPACITY,
        resolution: new THREE.Vector2(w * pr, h * pr),
      });
      const line = new Line2(geometry, material);
      line.computeLineDistances();
      line.userData = { kind: 'flow', key: flow.key, flow, baseColor: color, baseWidth: widthPx };
      this.edgeGroup.add(line);

      const particleGeom = new THREE.SphereGeometry(Math.max(0.9, widthPx * 0.35), 8, 8);
      const particleMat = new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.95 });
      const particle = new THREE.Mesh(particleGeom, particleMat);
      this.edgeGroup.add(particle);

      this.edgeLines.set(flow.key, { line, material, particle, flow, t: Math.random(), baseColor: color });
      this.adjacency.get(flow.hostA)?.add(flow.key);
      this.adjacency.get(flow.hostB)?.add(flow.key);
    }

    // Newly-created particle meshes default to visible=true -- reconcile them
    // with whatever the user currently has toggled (Flow animation checkbox)
    // and whatever focus is active, instead of silently re-enabling animation
    // on every filter/focus rebuild.
    this._applyVisualState();
  }

  /** Cosmetic-only emphasis: everything currently in the scene has already
   * passed the filter/ego-network intersection (computed in main.js and
   * applied via setGraph), so there's nothing left to hide here — this just
   * makes the exact selected node/edge visually pop (brighter glow, thicker
   * line) relative to its neighbors, which are still fully part of the
   * "current investigation" and shouldn't be dimmed away. Pass null to clear. */
  setPrimaryFocus(kind, id) {
    this.primaryFocus = kind ? { kind, id } : null;

    let hostIds = null, flowKeys = null;
    if (this.primaryFocus?.kind === 'host') {
      flowKeys = this.adjacency.get(id) || new Set();
      hostIds = new Set([id]);
    } else if (this.primaryFocus?.kind === 'flow') {
      const entry = this.edgeLines.get(id);
      flowKeys = new Set(entry ? [id] : []);
      hostIds = new Set(entry ? [entry.flow.hostA, entry.flow.hostB] : []);
    }

    for (const [key, entry] of this.edgeLines) {
      const isPrimary = !!flowKeys && flowKeys.has(key);
      entry.material.opacity = !this.primaryFocus ? ACTIVE_OPACITY : isPrimary ? ACTIVE_OPACITY : DIM_OPACITY;
      entry.particle.visible = this.particlesEnabled && (!this.primaryFocus || isPrimary);
    }
    for (const [nid, mesh] of this.nodeMeshes) {
      const isPrimary = !!hostIds && hostIds.has(nid);
      mesh.material.emissiveIntensity = !this.primaryFocus ? 0.85 : isPrimary ? 1.1 : 0.5;
      const halo = this.nodeHalos.get(nid);
      if (halo) halo.material.opacity = !this.primaryFocus ? 0.4 : isPrimary ? 0.75 : 0.15;
    }
  }

  clearPrimaryFocus() {
    this.setPrimaryFocus(null, null);
  }

  /** Smoothly flies the camera to look at a specific node (or the graph centroid
   * if id is null), eased over `duration` seconds — this is what makes clicking
   * into a node feel like "traveling" to it rather than an abrupt cut. */
  flyToNode(id, duration = 0.9) {
    if (!this.layout) return;
    const p = id ? this.layout.get(id) : { x: 0, y: 0, z: 0 };
    const dir = new THREE.Vector3(0.35, 0.5, 1).normalize();
    const dist = 70;
    this._startFlight(
      new THREE.Vector3(p.x + dir.x * dist, p.y + dir.y * dist, p.z + dir.z * dist),
      new THREE.Vector3(p.x, p.y, p.z),
      duration
    );
  }

  /** Alias kept for parity with Scene2D's API so main.js can drive either
   * renderer identically. */
  centerOn(id, duration = 0.9) { this.flyToNode(id, duration); }

  _startFlight(camTarget, orbitTarget, duration) {
    this._flight = {
      t: 0,
      duration,
      fromCam: this.camera.position.clone(),
      toCam: camTarget,
      fromTarget: this.controls.target.clone(),
      toTarget: orbitTarget,
    };
  }

  /** Reframes the camera to fit every node currently in the scene (i.e. the
   * active filter/focus subgraph, since that's all that's ever rendered now). */
  fitToVisible(animated = true) {
    if (!this.layout) return;
    let maxDist = 60;
    let any = false;
    let cx = 0, cy = 0, cz = 0, n = 0;
    for (const id of this.nodeMeshes.keys()) {
      any = true;
      const p = this.layout.get(id);
      maxDist = Math.max(maxDist, Math.hypot(p.x, p.y, p.z));
      cx += p.x; cy += p.y; cz += p.z; n++;
    }
    if (!any) return this.resetCamera();
    const dist = Math.max(120, maxDist * 2.6);
    const target = new THREE.Vector3(cx / n, cy / n, cz / n);
    const camPos = new THREE.Vector3(target.x + dist * 0.25, target.y + dist * 0.35, target.z + dist);
    if (animated) this._startFlight(camPos, target, 0.8);
    else { this.camera.position.copy(camPos); this.controls.target.copy(target); }
  }

  _onPointerMove(event) {
    const rect = this.renderer.domElement.getBoundingClientRect();
    this.pointer.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
    this.pointer.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
    const hit = this._pick();
    this.renderer.domElement.style.cursor = hit ? 'pointer' : 'grab';
    this.onHover(hit ? hit.userData : null, event);
  }

  _onClick(event) {
    if (this._dragMoved) return; // was an orbit drag, not an intentional click
    const hit = this._pick();
    if (this._clickTimer) clearTimeout(this._clickTimer);
    // Delay the single-click action briefly so a following dblclick can
    // cancel it — otherwise every double-click would also fire a spurious
    // single-select first, which felt disorienting during testing.
    this._clickTimer = setTimeout(() => {
      this.onSelect(hit ? hit.userData : null);
      this._clickTimer = null;
    }, 220);
  }

  _onDoubleClick(event) {
    if (this._clickTimer) { clearTimeout(this._clickTimer); this._clickTimer = null; }
    const hit = this._pick();
    if (hit) this.onDoubleSelect(hit.userData);
  }

  _pick() {
    this.raycaster.setFromCamera(this.pointer, this.camera);
    this.raycaster.params.Line2 = { threshold: 3 };
    const targets = [
      ...this.nodeGroup.children.filter((c) => c.visible),
      ...this.edgeGroup.children.filter((c) => c.userData?.kind === 'flow' && c.visible),
    ];
    const intersects = this.raycaster.intersectObjects(targets, false);
    return intersects.length ? intersects[0].object : null;
  }

  _animate() {
    requestAnimationFrame(() => this._animate());
    if (this._renderFailed) return; // a prior frame already threw; don't spam errors forever
    try {
      this._tick();
    } catch (err) {
      this._renderFailed = true;
      console.error('[PacketVerse] 3D render loop failed:', err);
      this.onError(err, '3d');
    }
  }

  _tick() {
    const dt = Math.min(0.05, this.clock.getDelta());

    if (this.layout && !this.layout.isSettled) {
      // alpha-decay convergence (see forceLayout.js) — this naturally stops
      // once the graph settles, rather than running forever every frame.
      this.layout.tick([...this.edgeLines.values()].map((e) => ({ a: e.flow.hostA, b: e.flow.hostB, weight: e.flow.bytes })));
    }
    if (this.layout) {
      for (const [id, mesh] of this.nodeMeshes) {
        const p = this.layout.get(id);
        mesh.position.set(p.x, p.y, p.z);
        const halo = this.nodeHalos.get(id);
        if (halo) halo.position.set(p.x, p.y, p.z);
        const label = this.labels.get(id);
        if (label) label.position.set(p.x, p.y + mesh.userData.baseSize + 4, p.z);
      }
      for (const entry of this.edgeLines.values()) {
        const pa = this.layout.get(entry.flow.hostA);
        const pb = this.layout.get(entry.flow.hostB);
        entry.line.geometry.setPositions([pa.x, pa.y, pa.z, pb.x, pb.y, pb.z]);
        entry.line.computeLineDistances();

        if (entry.particle.visible) {
          entry.t = (entry.t + dt * 0.35) % 1;
          entry.particle.position.set(
            pa.x + (pb.x - pa.x) * entry.t,
            pa.y + (pb.y - pa.y) * entry.t,
            pa.z + (pb.z - pa.z) * entry.t
          );
        }
      }
    }

    if (this._flight) {
      const f = this._flight;
      f.t = Math.min(1, f.t + dt / f.duration);
      const e = easeInOutCubic(f.t);
      this.camera.position.lerpVectors(f.fromCam, f.toCam, e);
      this.controls.target.lerpVectors(f.fromTarget, f.toTarget, e);
      this.camera.lookAt(this.controls.target);
      if (f.t >= 1) this._flight = null;
    } else {
      // "Zooming should always focus on the selected object": while a node
      // is selected (and the user isn't mid-drag), keep the orbit target
      // gently locked onto its live position — so scroll-wheel zoom, which
      // always dollies toward controls.target, stays centered on it even
      // as the layout finishes settling.
      if (this.primaryFocus?.kind === 'host' && !this._isPointerDown) {
        const p = this.layout?.get(this.primaryFocus.id);
        if (p) this.controls.target.lerp(new THREE.Vector3(p.x, p.y, p.z), 0.06);
      }
      // OrbitControls.update() re-derives its internal spherical state from
      // camera.position/controls.target every call. Calling it *during* a
      // programmatic flight (while we're also directly lerping position and
      // target independently) lets the two fight over the camera each frame
      // — most visibly when the straight-line lerp path passes close to the
      // target, which OrbitControls' min-distance clamp then yanks back out
      // of, producing a rapid, unstable jitter/spin. Skipping controls.update()
      // for the duration of a flight avoids that entirely; once the flight
      // ends, update() resumes and re-syncs cleanly from wherever we landed.
      this.controls.update();
    }
    this.composer.render();
  }

  resetCamera(animated = false) {
    // Frame the camera to fit the current graph's bounding radius.
    let maxDist = 120;
    if (this.layout) {
      for (const id of this.nodeMeshes.keys()) {
        const p = this.layout.get(id);
        maxDist = Math.max(maxDist, Math.hypot(p.x, p.y, p.z));
      }
    }
    const dist = Math.max(160, maxDist * 2.4);
    const camPos = new THREE.Vector3(dist * 0.25, dist * 0.35, dist);
    const target = new THREE.Vector3(0, 0, 0);
    if (animated) this._startFlight(camPos, target, 0.8);
    else { this.camera.position.copy(camPos); this.controls.target.copy(target); }
  }

  _disposeGroup(group) {
    for (const child of [...group.children]) {
      group.remove(child);
      child.geometry?.dispose?.();
      child.material?.dispose?.();
      child.material?.map?.dispose?.();
    }
  }
}

function nodeColorFor(host) {
  if (host.isCluster) return 0xe9b44c;
  if (host.protocols.has('Broadcast')) return 0x9e9e9e;
  if (host.protocols.has('Multicast')) return 0xb0bec5;
  if (host.protocols.has('DNS')) return 0x4caf50;
  if (host.protocols.has('TLS')) return 0x9b59b6;
  if (host.protocols.has('ARP') && host.protocols.size === 1) return 0x9e9e9e;
  return 0x4d9de0;
}

function shortenId(id) {
  return id.length > 20 ? id.slice(0, 18) + '\u2026' : id;
}

function makeHaloSprite(colorHex, size) {
  const canvas = document.createElement('canvas');
  canvas.width = canvas.height = 128;
  const ctx = canvas.getContext('2d');
  const grd = ctx.createRadialGradient(64, 64, 0, 64, 64, 64);
  const c = new THREE.Color(colorHex);
  grd.addColorStop(0, `rgba(${c.r * 255},${c.g * 255},${c.b * 255},0.55)`);
  grd.addColorStop(1, 'rgba(0,0,0,0)');
  ctx.fillStyle = grd;
  ctx.fillRect(0, 0, 128, 128);
  const texture = new THREE.CanvasTexture(canvas);
  const material = new THREE.SpriteMaterial({ map: texture, transparent: true, depthWrite: false, opacity: 0.4 });
  const sprite = new THREE.Sprite(material);
  sprite.scale.set(size, size, 1);
  return sprite;
}

function makeTextSprite(text) {
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');
  const fontSize = 28;
  ctx.font = `${fontSize}px monospace`;
  const width = Math.ceil(ctx.measureText(text).width) + 16;
  canvas.width = width;
  canvas.height = fontSize + 12;
  ctx.font = `${fontSize}px monospace`;
  ctx.fillStyle = 'rgba(10,14,20,0.55)';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = '#e6ebf2';
  ctx.textBaseline = 'middle';
  ctx.fillText(text, 8, canvas.height / 2);
  const texture = new THREE.CanvasTexture(canvas);
  const material = new THREE.SpriteMaterial({ map: texture, transparent: true, depthWrite: false });
  const sprite = new THREE.Sprite(material);
  const scale = 0.11;
  sprite.scale.set(canvas.width * scale, canvas.height * scale, 1);
  return sprite;
}

function easeInOutCubic(t) {
  return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
}
