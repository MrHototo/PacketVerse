/**
 * filters.js
 * Lightweight search + protocol quick-filter bar. Produces a predicate
 * function that main.js applies to the flow list before handing it to the
 * 3D scene, timeline, and dashboard — one filter state drives every view.
 */
export class FilterBar {
  constructor({ searchInput, presetContainer, onChange }) {
    this.searchInput = searchInput;
    this.presetContainer = presetContainer;
    this.onChange = onChange;
    this.activeProtocols = new Set();
    this.searchTerm = '';

    this.searchInput.addEventListener('input', () => {
      this.searchTerm = this.searchInput.value.trim().toLowerCase();
      this._emit();
    });
  }

  renderPresets(protocolCounts) {
    this.presetContainer.innerHTML = '';
    const sorted = Object.entries(protocolCounts).sort((a, b) => b[1] - a[1]);
    for (const [proto] of sorted) {
      const chip = document.createElement('button');
      chip.className = 'chip';
      chip.textContent = proto;
      chip.addEventListener('click', () => {
        if (this.activeProtocols.has(proto)) {
          this.activeProtocols.delete(proto);
          chip.classList.remove('chip-active');
        } else {
          this.activeProtocols.add(proto);
          chip.classList.add('chip-active');
        }
        this._emit();
      });
      this.presetContainer.appendChild(chip);
    }
  }

  clear() {
    this.activeProtocols.clear();
    this.searchTerm = '';
    this.searchInput.value = '';
    [...this.presetContainer.children].forEach((c) => c.classList.remove('chip-active'));
    this._emit();
  }

  matches(flow) {
    if (this.activeProtocols.size > 0) {
      const tagsAndProto = new Set([...flow.tags, flow.protocol, flow.appProtocol]);
      const hit = [...this.activeProtocols].some((p) => tagsAndProto.has(p));
      if (!hit) return false;
    }
    if (this.searchTerm) {
      const haystack = `${flow.hostA} ${flow.hostB} ${flow.portA} ${flow.portB} ${flow.protocol} ${flow.appProtocol || ''}`.toLowerCase();
      if (!haystack.includes(this.searchTerm)) return false;
    }
    return true;
  }

  _emit() {
    this.onChange();
  }
}
