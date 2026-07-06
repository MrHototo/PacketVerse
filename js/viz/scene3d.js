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
  constructor(container, { onSelect, onHover } = {}) {
    this.container = container;
    this.onSelect = onSelect || (() => {});
    this.onHover = onHover || (() => {});
    this.showLabels = true;
    this.focusId = null; // currently focused host id, or null

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
    this.renderer.domElement.addEventListener('click', (e) => this._onClick(e));
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

  /** Rebuilds meshes to match the current (filtered) hosts/flows. */
  setGraph(hosts, flows) {
    this._disposeGroup(this.nodeGroup);
    this._disposeGroup(this.edgeGroup);
    this._disposeGroup(this.labelGroup);
    this.nodeMeshes.clear();
    this.nodeHalos.clear();
    this.labels.clear();
    this.edgeLines.clear();
    this.adjacency.clear();
    this.focusId = null;
    this.settleTicks = 0;

    const ids = [...hosts.keys()];
    this.layout = new ForceLayout3D(ids);

    const maxBytes = Math.max(1, ...[...hosts.values()].map((h) => h.bytes));
    for (const host of hosts.values()) {
      const size = 2.6 + 7 * Math.cbrt(host.bytes / maxBytes);
      const color = nodeColorFor(host);

      const geometry = new THREE.SphereGeometry(size, 20, 20);
      const material = new THREE.MeshStandardMaterial({
        color,
        emissive: color,
        emissiveIntensity: 0.85,
        roughness: 0.35,
        metalness: 0.15,
      });
      const mesh = new THREE.Mesh(geometry, material);
      mesh.userData = { kind: 'host', id: host.id, host, baseColor: color, baseSize: size };
      this.nodeGroup.add(mesh);
      this.nodeMeshes.set(host.id, mesh);

      const halo = makeHaloSprite(color, size * 5);
      this.labelGroup.add(halo);
      this.nodeHalos.set(host.id, halo);

      const label = makeTextSprite(shortenId(host.id));
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
  }

  /** Dims/brightens edges based on which flows are within the active time-range/filter selection. */
  setActivity(activeFlowKeys) {
    this.activeFlowKeys = activeFlowKeys;
    this._applyVisualState();
  }

  /** Highlights a host or flow and its directly connected traffic; dims everything else. Pass null to clear. */
  focusOn(kind, id) {
    this.focusId = kind ? { kind, id } : null;
    this._applyVisualState();
  }

  clearFocus() {
    this.focusOn(null, null);
  }

  _applyVisualState() {
    const active = this.activeFlowKeys || null;
    const focus = this.focusId;
    let focusedFlowKeys = null;
    let focusedHostIds = null;

    if (focus?.kind === 'host') {
      focusedFlowKeys = this.adjacency.get(focus.id) || new Set();
      focusedHostIds = new Set([focus.id, ...[...focusedFlowKeys].flatMap((k) => {
        const f = this.edgeLines.get(k)?.flow;
        return f ? [f.hostA, f.hostB] : [];
      })]);
    } else if (focus?.kind === 'flow') {
      const entry = this.edgeLines.get(focus.id);
      focusedFlowKeys = new Set(entry ? [focus.id] : []);
      focusedHostIds = new Set(entry ? [entry.flow.hostA, entry.flow.hostB] : []);
    }

    for (const [key, entry] of this.edgeLines) {
      const inRange = !active || active.has(key);
      const inFocus = !focus || (focusedFlowKeys && focusedFlowKeys.has(key));
      const visible = inRange;
      entry.line.visible = visible;
      entry.particle.visible = visible && inFocus;
      entry.material.opacity = !visible ? 0 : inFocus ? ACTIVE_OPACITY : DIM_OPACITY;
    }

    for (const [id, mesh] of this.nodeMeshes) {
      const inFocus = !focus || (focusedHostIds && focusedHostIds.has(id));
      mesh.material.emissiveIntensity = inFocus ? 0.85 : 0.15;
      mesh.material.opacity = inFocus ? 1 : 0.35;
      mesh.material.transparent = !inFocus;
      const halo = this.nodeHalos.get(id);
      if (halo) halo.material.opacity = inFocus ? 0.55 : 0.05;
    }
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
    const hit = this._pick();
    this.onSelect(hit ? hit.userData : null);
  }

  _pick() {
    this.raycaster.setFromCamera(this.pointer, this.camera);
    this.raycaster.params.Line2 = { threshold: 3 };
    const targets = [...this.nodeGroup.children, ...this.edgeGroup.children.filter((c) => c.userData?.kind === 'flow' && c.visible)];
    const intersects = this.raycaster.intersectObjects(targets, false);
    return intersects.length ? intersects[0].object : null;
  }

  _animate() {
    requestAnimationFrame(() => this._animate());
    const dt = Math.min(0.05, this.clock.getDelta());

    if (this.layout) {
      // Run the physics a bit faster while the graph first settles, then ease off.
      const ticks = this.settleTicks < 90 ? 2 : 1;
      this.settleTicks += 1;
      for (let i = 0; i < ticks; i++) {
        this.layout.tick([...this.edgeLines.values()].map((e) => ({ a: e.flow.hostA, b: e.flow.hostB, weight: e.flow.bytes })));
      }
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

    this.controls.update();
    this.composer.render();
  }

  resetCamera() {
    // Frame the camera to fit the current graph's bounding radius.
    let maxDist = 120;
    if (this.layout) {
      for (const id of this.nodeMeshes.keys()) {
        const p = this.layout.get(id);
        maxDist = Math.max(maxDist, Math.hypot(p.x, p.y, p.z));
      }
    }
    const dist = Math.max(160, maxDist * 2.4);
    this.camera.position.set(dist * 0.25, dist * 0.35, dist);
    this.controls.target.set(0, 0, 0);
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
