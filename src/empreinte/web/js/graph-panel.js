// The floating settings panel of the graph: Filtres, Groupes, Afficher, Forces.
import { h, clear, icon, debounce } from "./dom.js";
import { DEFAULT_SETTINGS } from "./graph.js";

const PALETTE = ["#e5484d", "#f5a524", "#46a758", "#3e9ae8", "#a882ff", "#e54d9a", "#2ec4b6", "#c9a227"];
let uid = 0;

function toggle(label, checked, onChange) {
  const id = `gp-${++uid}`;
  const input = h("input", { type: "checkbox", id, checked, on: { change: () => onChange(input.checked) } });
  return h("div", { class: "gp-row" }, h("label", { for: id, text: label }),
    h("span", { class: "switch" }, input, h("span", { "aria-hidden": "true" })));
}

function slider(label, value, min, max, step, onInput) {
  const id = `gp-${++uid}`;
  const input = h("input", { type: "range", id, min, max, step, value: String(value),
    on: { input: () => onInput(parseFloat(input.value)) } });
  return { el: h("div", { class: "gp-range" }, h("label", { for: id, text: label }), input), input };
}

export class GraphPanel {
  /** onChange(partialSettings) is called on every change; onAnimate() for "Animer". */
  constructor(root, { onChange, onAnimate, onFit }) {
    this.root = root;
    this.onChange = onChange;
    this.onAnimate = onAnimate;
    this.onFit = onFit;
    this.settings = structuredClone(DEFAULT_SETTINGS);
    this.open = { filters: true, groups: false, display: false, forces: false };
    this.pending = new Set(); // debounced inputs, cancelled on lock and on every re-render
  }

  /** A debounced handler that cancelPending() can cancel. */
  later(fn, ms) {
    const run = debounce(fn, ms);
    this.pending.add(run);
    return run;
  }

  /** Cancel every debounced input still waiting (called on lock, before wiping). */
  cancelPending() {
    for (const run of this.pending) run.cancel();
    this.pending.clear();
  }

  set(settings) {
    this.cancelPending();
    this.settings = { ...structuredClone(DEFAULT_SETTINGS), ...settings };
    this.render();
  }

  emit(partial) {
    Object.assign(this.settings, partial);
    this.onChange(partial);
  }

  section(key, title, ...content) {
    const det = h("details", { open: this.open[key] || undefined },
      h("summary", { text: title }), h("div", { class: "gp-section" }, ...content));
    det.addEventListener("toggle", () => { this.open[key] = det.open; });
    return det;
  }

  render() {
    const S = this.settings;
    clear(this.root);
    const collapsed = this.root.classList.contains("collapsed");
    const head = h("div", { class: "gp-head" },
      h("button", { class: "icon-btn", title: "Recentrer le graphe", "aria-label": "Recentrer le graphe", on: { click: () => this.onFit() } }, icon("expand")),
      h("button", { class: "icon-btn", title: "Réinitialiser les réglages", "aria-label": "Réinitialiser les réglages du graphe",
        on: { click: () => { const groups = this.settings.groups; this.set({ groups }); this.onChange({ ...this.settings }); } } }, icon("reset")),
      h("button", { class: "icon-btn", title: collapsed ? "Ouvrir les réglages" : "Fermer les réglages",
        "aria-label": collapsed ? "Ouvrir les réglages du graphe" : "Fermer les réglages du graphe", "aria-expanded": String(!collapsed),
        on: { click: () => { this.root.classList.toggle("collapsed"); this.render(); } } }, icon(collapsed ? "gear" : "close")));

    const searchId = `gp-${++uid}`;
    const search = h("input", { type: "search", id: searchId, placeholder: "Rechercher des fichiers...", value: S.search,
      autocomplete: "off", spellcheck: "false" });
    const pushSearch = this.later(() => this.emit({ search: search.value }), 180);
    search.addEventListener("input", pushSearch);

    const filters = this.section("filters", "Filtres",
      h("label", { class: "sr-only", for: searchId, text: "Filtrer le graphe (path:, tag:, texte)" }), search,
      toggle("Étiquettes", S.tags, (v) => this.emit({ tags: v })),
      toggle("Pièces jointes", S.attachments, (v) => this.emit({ attachments: v })),
      toggle("Notes existantes uniquement", S.existingOnly, (v) => this.emit({ existingOnly: v })),
      toggle("Orphelins", S.orphans, (v) => this.emit({ orphans: v })));

    const groupList = h("div", { class: "gp-section", style: { padding: "0" } });
    const renderGroups = () => {
      clear(groupList);
      S.groups.forEach((g, i) => {
        const qid = `gp-${++uid}`;
        const color = h("input", { type: "color", value: g.color, "aria-label": `Couleur du groupe ${i + 1}`,
          on: { input: () => { g.color = color.value; this.emit({ groups: [...S.groups] }); } } });
        const query = h("input", { type: "text", id: qid, value: g.query, placeholder: "path:, tag: ou texte",
          "aria-label": `Requête du groupe ${i + 1}`, spellcheck: "false" });
        query.addEventListener("input", this.later(() => { g.query = query.value; this.emit({ groups: [...S.groups] }); }, 200));
        const remove = h("button", { class: "icon-btn", "aria-label": `Supprimer le groupe ${i + 1}`, title: "Supprimer",
          on: { click: () => { S.groups.splice(i, 1); this.emit({ groups: [...S.groups] }); renderGroups(); } } }, icon("close"));
        groupList.appendChild(h("div", { class: "group-row" }, color, query, remove));
      });
    };
    renderGroups();
    const groups = this.section("groups", "Groupes", groupList,
      h("button", { class: "btn btn-small btn-primary", on: { click: () => {
        S.groups.push({ query: "", color: PALETTE[S.groups.length % PALETTE.length] });
        renderGroups();
        const inputs = groupList.querySelectorAll("input[type=text]");
        if (inputs.length) inputs[inputs.length - 1].focus();
      } } }, "Nouveau groupe"));

    const display = this.section("display", "Afficher",
      toggle("Flèches", S.arrows, (v) => this.emit({ arrows: v })),
      toggle("Légende des couleurs", S.legend, (v) => this.emit({ legend: v })),
      slider("Seuil d'apparition du texte", S.textFade, -3, 3, 0.1, (v) => this.emit({ textFade: v })).el,
      slider("Taille des nœuds", S.nodeSize, 0.3, 3, 0.05, (v) => this.emit({ nodeSize: v })).el,
      slider("Épaisseur des liens", S.linkThickness, 0.2, 4, 0.05, (v) => this.emit({ linkThickness: v })).el,
      h("button", { class: "btn btn-small btn-primary", on: { click: () => this.onAnimate() } }, "Animer"));

    const forces = this.section("forces", "Forces",
      slider("Force centrale", S.center, 0, 1, 0.01, (v) => this.emit({ center: v })).el,
      slider("Force de répulsion", S.repel, 0, 20, 0.1, (v) => this.emit({ repel: v })).el,
      slider("Force des liens", S.link, 0, 1, 0.01, (v) => this.emit({ link: v })).el,
      slider("Distance des liens", S.distance, 30, 500, 1, (v) => this.emit({ distance: v })).el);

    this.root.append(head, h("div", { class: "gp-body" }, filters, groups, display, forces));
  }
}
