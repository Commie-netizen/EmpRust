// Timeline under the graph: the graph as it was at a date (server `until` parameter).
import { h, clear, icon, fmtDateLong } from "./dom.js";
import { nodeTime } from "./graph.js";

const DAY = 864e5;

export class Timeline {
  constructor(root, { onChange }) {
    this.root = root;
    this.onChange = onChange;
    this.min = 0; this.max = 0; this.days = 0;
    this.playing = false;
    this.busy = false;
    this.again = false;
    this.build();
  }

  build() {
    clear(this.root);
    this.play = h("button", { class: "icon-btn", "aria-label": "Lecture de la chronologie", title: "Lecture", on: { click: () => this.toggle() } }, icon("play"));
    this.range = h("input", { type: "range", id: "tl-range", min: "0", max: "0", value: "0", step: "1", "aria-label": "Date affichée du graphe" });
    this.date = h("span", { class: "tl-date", "aria-live": "off" });
    this.basis = h("span", { class: "tl-basis" });
    this.range.addEventListener("input", () => { this.stop(); this.changed(); });
    this.reset = h("button", { class: "btn btn-small", text: "Tout", title: "Afficher toute l'archive", on: { click: () => { this.stop(); this.range.value = this.range.max; this.changed(); } } });
    this.root.append(this.play, this.range, this.date, this.reset, this.basis);
  }

  /** Set the range from the full graph's nodes and say which dates drive it. */
  clear() {
    this.stop();
    this.busy = false; this.again = false;
    this.min = 0; this.max = 0; this.days = 0;
    this.range.max = "0"; this.range.value = "0";
    this.date.textContent = ""; this.basis.textContent = "";
    this.root.hidden = true;
  }

  setNodes(nodes) {
    const notes = nodes.filter((n) => n.node_type !== "tag");
    if (!notes.length) { this.clear(); return; }
    this.root.hidden = false;
    const times = notes.map(nodeTime).filter(Number.isFinite);
    this.min = Math.min(...times);
    this.max = Math.max(Date.now(), ...times);
    this.days = Math.max(1, Math.ceil((this.max - this.min) / DAY));
    this.range.max = String(this.days);
    this.range.value = String(this.days);
    const claimed = notes.filter((n) => n.authored_at).length;
    const ledger = notes.length - claimed;
    this.basis.textContent = claimed
      ? `Chronologie selon la date déclarée du fichier pour ${claimed} note${claimed > 1 ? "s" : ""} (non prouvée), selon la date du registre pour ${ledger}.`
      : "Chronologie selon les dates du registre (enregistrement local).";
    this.label();
  }

  value() {
    const v = +this.range.value;
    return v >= this.days ? null : new Date(this.min + (v + 1) * DAY - 1);
  }

  label() {
    const until = this.value();
    this.date.textContent = until ? `au ${fmtDateLong(until)}` : "aujourd'hui (tout)";
  }

  async changed() {
    this.label();
    const until = this.value();
    if (this.busy) { this.again = true; return; }
    this.busy = true;
    try { await this.onChange(until ? until.toISOString() : null); }
    finally { this.busy = false; }
    if (this.again) { this.again = false; await this.changed(); }
  }

  toggle() { if (this.playing) this.stop(); else this.start(); }

  start() {
    if (+this.range.value >= this.days) this.range.value = "0";
    this.playing = true;
    this.play.replaceChildren(icon("pause"));
    this.play.setAttribute("aria-label", "Pause de la chronologie");
    const step = Math.max(1, Math.round(this.days / 70));
    const loop = async () => {
      if (!this.playing) return;
      const next = Math.min(this.days, +this.range.value + step);
      this.range.value = String(next);
      await this.changed();
      if (next >= this.days) { this.stop(); return; }
      this.timer = setTimeout(loop, 260);
    };
    loop();
  }

  stop() {
    this.playing = false;
    clearTimeout(this.timer);
    this.play.replaceChildren(icon("play"));
    this.play.setAttribute("aria-label", "Lecture de la chronologie");
  }
}
