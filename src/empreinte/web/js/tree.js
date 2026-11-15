// The folder tree of the sidebar: folders open and close, notes open in the reader.
import { h, clear, icon } from "./dom.js";
import { emit } from "./state.js";

export function buildTree(entries) {
  const root = { name: "", folders: new Map(), files: [], count: 0 };
  for (const e of entries) {
    const parts = e.path.split("/");
    let node = root;
    node.count++;
    for (const part of parts.slice(0, -1)) {
      if (!node.folders.has(part)) node.folders.set(part, { name: part, folders: new Map(), files: [], count: 0 });
      node = node.folders.get(part);
      node.count++;
    }
    node.files.push(e);
  }
  return root;
}

const collator = new Intl.Collator("fr", { sensitivity: "base", numeric: true });

export class Tree {
  constructor(root) {
    this.root = root;
    this.open = new Set();
    this.active = null;
    this.filter = "";
    this.entries = [];
  }

  setEntries(entries) { this.entries = entries; this.render(); }
  setActive(id) {
    this.active = id;
    for (const b of this.root.querySelectorAll(".tree-file")) b.classList.toggle("active", b.dataset.id === id);
  }
  setFilter(text) { this.filter = text.trim().toLowerCase(); this.render(); }
  collapseAll() { this.open.clear(); this.render(); }
  clear() { this.entries = []; this.open.clear(); this.active = null; this.filter = ""; clear(this.root); }

  render() {
    const list = this.filter
      ? this.entries.filter((e) => e.title.toLowerCase().includes(this.filter) || e.path.toLowerCase().includes(this.filter))
      : this.entries;
    const tree = buildTree(list);
    clear(this.root);
    this.root.appendChild(this.renderFolder(tree, "", 1));
    if (!list.length) this.root.appendChild(h("p", { class: "faint", style: { padding: "6px 8px" }, text: this.filter ? "Aucun fichier ne correspond." : "Archive vide." }));
  }

  renderFolder(folder, prefix, level) {
    const group = h("div", { role: "group" });
    const folders = [...folder.folders.values()].sort((a, b) => collator.compare(a.name, b.name));
    for (const f of folders) {
      const key = `${prefix}${f.name}/`;
      const isOpen = this.filter ? true : this.open.has(key);
      const btn = h("button", { class: "tree-item tree-folder", role: "treeitem", "aria-expanded": String(isOpen), "aria-level": String(level),
        on: { click: () => { if (this.open.has(key)) this.open.delete(key); else this.open.add(key); this.render(); } } },
        icon("chevron", "chev"), h("span", { class: "label", text: f.name }), h("span", { class: "tree-count", text: String(f.count) }));
      group.appendChild(btn);
      if (isOpen) {
        const kids = this.renderFolder(f, key, level + 1);
        kids.classList.add("tree-children");
        group.appendChild(kids);
      }
    }
    const files = folder.files.slice().sort((a, b) => collator.compare(a.title, b.title));
    for (const e of files) {
      const ext = e.path.includes(".") ? e.path.split(".").pop() : "";
      group.appendChild(h("button", { class: `tree-item tree-file${e.entry_id === this.active ? " active" : ""}`, role: "treeitem",
        "aria-level": String(level), dataset: { id: e.entry_id }, title: e.path,
        on: { click: () => emit("open", { id: e.entry_id, fromTree: true }) } },
        h("span", { class: "label", text: e.title }), ext && ext !== "md" ? h("span", { class: "ext", text: ext }) : null));
    }
    return group;
  }
}
