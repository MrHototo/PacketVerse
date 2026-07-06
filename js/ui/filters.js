/**
 * filters.js
 * Wireshark-style filter bar: a free-text expression box (parsed by
 * filterExpression.js) plus quick protocol chips. Produces a single
 * predicate function that main.js applies to the flow list before handing
 * it to the 3D scene, timeline, and dashboard — one filter state drives
 * every view. Dashboard rows can call appendTerm()/setTerm() to build up
 * filters by clicking instead of typing.
 */
import { compileFlowFilter } from './filterExpression.js';

export class FilterBar {
  constructor({ searchInput, presetContainers, onChange }) {
    this.searchInput = searchInput;
    this.presetContainers = (presetContainers || []).filter(Boolean);
    this.onChange = onChange;
    this.activeProtocols = new Set();
    this.predicate = () => true;
    this.lastProtocolCounts = {};

    this.searchInput.addEventListener('input', () => {
      this.predicate = compileFlowFilter(this.searchInput.value);
      this._emit();
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
          this._emit();
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
    this._emit();
  }

  /** Replaces the expression box entirely with `term` (e.g. clicking a dashboard row). */
  setTerm(term) {
    this.searchInput.value = term;
    this.predicate = compileFlowFilter(term);
    this._emit();
  }

  /** Appends `term` to whatever is already typed, ANDed together. */
  appendTerm(term) {
    const current = this.searchInput.value.trim();
    const next = current ? `${current} and ${term}` : term;
    this.setTerm(next);
  }

  matches(flow) {
    if (this.activeProtocols.size > 0) {
      const tagsAndProto = new Set([...flow.tags, flow.protocol, flow.appProtocol]);
      const hit = [...this.activeProtocols].some((p) => tagsAndProto.has(p));
      if (!hit) return false;
    }
    return this.predicate(flow);
  }

  _emit() {
    this.onChange();
  }
}
