// Shared in-memory state of the unlocked session. Cleared on lock; never persisted.

export const state = {
  entries: [],
  byId: new Map(),
  features: { import: false, previews: false, export: false },
  demo: false,
  currentNote: null,
  graphSelection: new Set(),
};

export const bus = new EventTarget();

export function emit(type, detail = {}) { bus.dispatchEvent(new CustomEvent(type, { detail })); }
export function on(type, fn) { bus.addEventListener(type, (e) => fn(e.detail)); }

export function setEntries(list) {
  state.entries = list;
  state.byId = new Map(list.map((e) => [e.entry_id, e]));
}

export function clearState() {
  state.entries = [];
  state.byId = new Map();
  state.currentNote = null;
  state.graphSelection = new Set();
}

export function titleOf(id) {
  const e = state.byId.get(id);
  return e ? e.title : id.slice(0, 8);
}
