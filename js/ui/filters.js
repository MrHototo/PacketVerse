/**
 * filters.js
 * Wireshark-style filter bar: a free-text expression box (parsed by
 * filterExpression.js, evaluated per-packet) plus quick protocol chips.
 * Produces a single predicate function that main.js applies to the packet
 * list before deriving which flows/hosts are "active" everywhere else
 * (3D scene, packet list, dashboard) — so a filter genuinely narrows the
 * whole app down to matching traffic instead of just dimming it.
 */
import { compilePacketFilter } from './filterExpression.js';

const DEBOUNCE_MS = 150;

export class FilterBar {
  constructor({ searchInput, presetContainers, onChange, fitButton }) {
    this.searchInput = searchInput;
    this.presetContainers = (presetContainers || []).filter(Boolean);
    this.onChange = onChange;
    this.activeProtocols = new Set();
    this.predicate = () => true;
    this.lastProtocolCounts = {};
    this._debounceTimer = null;

    this.searchInput.addEventListener('input', () => {
      clearTimeout(this._debounceTimer);
      this._debounceTimer = setTimeout(() => {
        this.predicate = compilePacketFilter(this.searchInput.value);
        this._emit();
      }, DEBOUNCE_MS);
    });
    this.searchInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        clearTimeout(this._debounceTimer);
        this.predicate = compilePacketFilter(this.searchInput.value);
        this._emit(true);
      }
    });
  }

  renderPresets(protocolCounts) {
    this.lastProtocolCounts = protocolCounts;
    const sorted = Object.entries(protocolCounts).sort((a, b) => b[1] - a[1]);
    for (const container of this.presetContainers) {
      container.innerHTML = '';
      for (const [proto] of sorted) {
        const chip = document.createElement('button');
        chip.className = 'chip';
        chip.textContent = proto;
        if (this.activeProtocols.has(proto)) chip.classList.add('chip-active');
        chip.addEventListener('click', () => {
          if (this.activeProtocols.has(proto)) this.activeProtocols.delete(proto);
          else this.activeProtocols.add(proto);
          this.renderPresets(this.lastProtocolCounts);
          this._emit(true);
        });
        container.appendChild(chip);
      }
    }
  }

  clear() {
    this.activeProtocols.clear();
    this.predicate = () => true;
    this.searchInput.value = '';
    this.renderPresets(this.lastProtocolCounts);
    this._emit(true);
  }

  /** Replaces the expression box entirely with `term` (e.g. clicking a dashboard row). */
  setTerm(term) {
    this.searchInput.value = term;
    this.predicate = compilePacketFilter(term);
    this._emit(true);
  }

  /** Appends `term` to whatever is already typed, ANDed together. */
  appendTerm(term) {
    const current = this.searchInput.value.trim();
    const next = current ? `${current} and ${term}` : term;
    this.setTerm(next);
  }

  /** True if any search text or protocol chip is currently constraining the view. */
  isActive() {
    return this.activeProtocols.size > 0 || this.searchInput.value.trim().length > 0;
  }

  /** Evaluates the compiled expression + active protocol chips against one packet entry. */
  matchesPacket(entry) {
    if (this.activeProtocols.size > 0) {
      const frame = entry.frame;
      const proto = frame.layers.l7?.type || frame.layers.l4?.type || frame.layers.l3?.type;
      const tagsAndProto = new Set([...frame.tags, proto]);
      const hit = [...this.activeProtocols].some((p) => tagsAndProto.has(p));
      if (!hit) return false;
    }
    return this.predicate(entry);
  }

  _emit(committed = false) {
    this.onChange(committed);
  }
}
