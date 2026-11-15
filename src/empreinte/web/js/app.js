// Entry point: session, views, sidebar, graph, keyboard.
import { h, $, clear, icon, toast, confirmDialog, cancelDialogs, debounce } from "./dom.js";
import { get, post, put, qs, onLocked, invalidate, lockSession, ended } from "./api.js";
import { showAuth } from "./auth.js";
import { state, on, emit, setEntries, clearState } from "./state.js";
import { Tree } from "./tree.js";
import { GraphView, DEFAULT_SETTINGS } from "./graph.js";
import { GraphPanel } from "./graph-panel.js";
import { Timeline } from "./timeline.js";
import { renderNote } from "./reader.js";
import { renderActivity } from "./views/activity.js";
import { renderSearch, focusSearch, resetSearch } from "./views/search.js";
import { renderLedger } from "./views/ledger.js";
import { renderLicenses, resetLicenses } from "./views/licenses.js";
import { renderWatch, resetWatch, onCaptured } from "./watch.js";

const VIEWS = ["graph", "reading", "activity", "search", "ledger", "licenses"];
const RAIL_ICONS = { graph: "graph", reading: "reading", activity: "activity", search: "search", ledger: "ledger", licenses: "licenses" };

let current = "graph";
let status = null;
let poller = null;
let untilIso = null;
let graphSeq = 0;

const tree = new Tree($("#tree"));
const pane = $("#reader-pane");
const graph = new GraphView($("#graph-canvas"), {
  onOpen: (id) => emit("open", { id }),
  onSelection: (sel) => { state.graphSelection = new Set(sel); },
  onStatus: (text) => { $("#graph-status").textContent = text; },
  onLegend: renderLegend,
  // Room taken by the floating panel on the right, so the fit centres the graph beside it.
  insets: () => {
    const p = $("#graph-panel");
    if (!p || p.classList.contains("collapsed") || !pane.hidden || window.innerWidth < 700) return { right: 0 };
    return { right: p.offsetWidth + 16 };
  },
});

/** Colour legend at the bottom left of the graph (text only, through textContent). */
function renderLegend(items) {
  const box = $("#graph-legend");
  clear(box);
  box.hidden = !items.length;
  for (const item of items) {
    const swatch = h("i", { "aria-hidden": "true" });
    swatch.style.background = item.color;
    box.appendChild(h("span", { class: "legend-item" }, swatch, item.label || "(racine)"));
  }
}
const panel = new GraphPanel($("#graph-panel"), {
  onChange: (partial) => {
    const refetch = graph.update(partial);
    if (refetch) loadGraph();
    savePrefs();
  },
  onAnimate: () => graph.animate(),
  onFit: () => graph.fit(),
});
const timeline = new Timeline($("#timeline"), { onChange: async (iso) => {
  untilIso = iso;
  try { await loadGraph(); } catch (err) { if (!ended(err)) toast(err.message, true); }
} });

// ------------------------------------------------------------------ chrome
for (const btn of document.querySelectorAll(".rail-btn[data-view]")) {
  btn.appendChild(icon(RAIL_ICONS[btn.dataset.view]));
  btn.addEventListener("click", () => showView(btn.dataset.view));
}
$("#lock-btn").appendChild(icon("lock"));
$("#toggle-sidebar").appendChild(icon("sidebar"));
$("#collapse-all").appendChild(icon("collapse"));
$("#collapse-all").addEventListener("click", () => tree.collapseAll());
$("#tree-filter").addEventListener("input", debounce((e) => tree.setFilter(e.target.value), 120));
$("#lock-btn").addEventListener("click", () => lock("Archive verrouillée."));
$("#toggle-sidebar").addEventListener("click", () => {
  const app = $("#app");
  const narrow = window.matchMedia("(max-width: 900px)").matches;
  if (narrow) app.classList.toggle("sidebar-open"); else app.classList.toggle("no-sidebar");
  const visible = narrow ? app.classList.contains("sidebar-open") : !app.classList.contains("no-sidebar");
  $("#toggle-sidebar").setAttribute("aria-expanded", String(visible));
});
$("#import-btn").addEventListener("click", importFolder);

function showView(view, opts = {}) {
  if (!VIEWS.includes(view)) return;
  current = view;
  for (const v of VIEWS) $(`#view-${v}`).hidden = v !== view;
  for (const b of document.querySelectorAll(".rail-btn[data-view]")) {
    if (b.dataset.view === view) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current");
  }
  if (window.matchMedia("(max-width: 900px)").matches) $("#app").classList.remove("sidebar-open");
  const root = $(`#view-${view}`);
  if (view === "graph") {
    graph.resize();
    if (opts.focus) setTimeout(() => graph.focusNode(opts.focus), 50);
  } else if (view === "reading") {
    const id = opts.id || state.currentNote;
    if (id) renderNote(root, id, { pane: false });
    else { clear(root).appendChild(h("div", { class: "inner" }, h("h1", { text: "Lecture" }), h("p", { class: "lead", text: "Choisissez une note dans l'arborescence, le graphe ou la recherche." }))); }
  } else if (view === "activity") renderActivity(root);
  else if (view === "search") { renderSearch(root); focusSearch(root); }
  else if (view === "ledger") renderLedger(root);
  else if (view === "licenses") renderLicenses(root);
}

function closePane() {
  pane.hidden = true;
  clear(pane);
  $("#graph-canvas").focus({ preventScroll: true });
}

on("open", ({ id, pane: inPane }) => {
  if (!state.byId.has(id)) { toast("Cette note n'existe plus."); return; }
  tree.setActive(id);
  state.currentNote = id;
  if (current === "graph" || inPane) {
    if (current !== "graph") showView("graph");
    pane.hidden = false;
    renderNote(pane, id, { pane: true, onClose: closePane });
    graph.hover = null;
  } else {
    showView("reading", { id });
  }
});
on("view", ({ view, id, focus }) => {
  if (view === "graph") closePane();
  showView(view, { id, focus });
});
on("changed", async () => {
  try { await loadEntries(); await loadGraph(true); }
  catch (err) { if (!ended(err)) toast(err.message, true); }
});

// A capture by the watcher: refresh the tree, the graph (keeping a timeline position the
// user chose) and the activity view if it is open.
onCaptured(async () => {
  try {
    await loadEntries();
    await loadGraph(untilIso === null);
    if (current === "activity") renderActivity($("#view-activity"));
  } catch (err) { if (!ended(err)) toast(err.message, true); }
});

// ------------------------------------------------------------------ data
async function loadEntries() {
  const entries = await get("/api/entries");
  setEntries(entries);
  tree.setEntries(entries);
  $("#vault-count").textContent = `${entries.length} fichier${entries.length > 1 ? "s" : ""}`;
}

async function loadGraph(resetRange = false) {
  if (resetRange) { timeline.stop(); untilIso = null; }
  const seq = ++graphSeq;
  const tags = graph.settings.tags ? 1 : 0;
  const g = await get(`/api/graph${qs({ until: untilIso, tags })}`);
  if (seq !== graphSeq) return;
  graph.setGraph(g);
  if (resetRange) timeline.setNodes(g.nodes);
}

async function loadPrefs() {
  let prefs = {};
  try { prefs = await get("/api/prefs"); } catch { prefs = {}; }
  const settings = { ...DEFAULT_SETTINGS };
  if (prefs && typeof prefs.graph === "object" && prefs.graph) {
    for (const [k, v] of Object.entries(prefs.graph)) {
      if (!(k in DEFAULT_SETTINGS)) continue;
      if (k === "groups") {
        if (Array.isArray(v)) settings.groups = v.filter((g) => g && typeof g.query === "string" && /^#[0-9a-f]{6}$/i.test(g.color))
          .slice(0, 30).map((g) => ({ query: g.query.slice(0, 200), color: g.color }));
      } else if (typeof v === typeof DEFAULT_SETTINGS[k]) settings[k] = v;
    }
  }
  settings.search = "";
  graph.settings = { ...settings };
  graph.applyForces();
  panel.set(settings);
}

const savePrefs = debounce(async () => {
  const { search, ...rest } = graph.settings;
  try { await put("/api/prefs", { graph: rest }); } catch { /* not critical */ }
}, 800);

async function enterApp() {
  $("#auth").hidden = true;
  clear($("#auth-body"));
  $("#app").hidden = false;
  if (window.matchMedia("(max-width: 700px)").matches) { $("#graph-panel").classList.add("collapsed"); }
  state.features = status.features;
  state.demo = status.demo;
  $("#import-btn").hidden = !status.features.import;
  $("#vault-name").textContent = status.demo ? "Archive de démonstration" : "Archive";
  showView("graph");
  try {
    await loadPrefs();
    await loadEntries();
    untilIso = null;
    await loadGraph(true);
    graph.fit();
    $("#graph-canvas").focus({ preventScroll: true });
  } catch (err) {
    if (!ended(err)) toast(err.message, true);
  }
  renderWatch(status.watch, status.features.watch);
  clearInterval(poller);
  // Status polls do not count as activity for the idle lock; faster while capture is on.
  poller = setInterval(checkStatus, status.features.watch ? 5000 : 15000);
}

async function checkStatus() {
  try {
    const s = await get("/api/status");
    if ($("#app").hidden) return;
    if (!s.unlocked) { wipe("Archive verrouillée après une période d'inactivité."); return; }
    renderWatch(s.watch, s.features.watch);
  } catch (err) {
    if (err.code === "bad_token" && !$("#app").hidden) wipe(RESTARTED);
  }
}

/** Forget everything decrypted that the page holds, then show the unlock screen. */
async function wipe(message, lockServer = false) {
  const locking = lockServer ? lockSession() : null;
  if (!lockServer) invalidate();
  graphSeq++;
  $("#app").hidden = true;
  $("#auth").hidden = true;
  clearInterval(poller);
  savePrefs.cancel();
  panel.cancelPending();
  clearState();
  resetSearch();
  resetLicenses();
  resetWatch();
  graph.clear();
  renderLegend([]);
  graph.settings = { ...DEFAULT_SETTINGS, groups: [] };
  panel.set(graph.settings);
  tree.clear();
  $("#tree-filter").value = "";
  timeline.clear();
  untilIso = null;
  pane.hidden = true;
  clear(pane);
  for (const v of VIEWS) if (v !== "graph") clear($(`#view-${v}`));
  $("#graph-status").textContent = "";
  cancelDialogs();
  $("#toast").hidden = true;
  $("#toast").textContent = "";
  for (const tip of document.querySelectorAll(".chart-tip")) tip.remove();
  if (locking) {
    try { await locking; }
    catch { message = "Page verrouillée. Le verrouillage du serveur n'a pas pu être confirmé ; fermez le serveur local si nécessaire."; }
  }
  try { status = await get("/api/status"); } catch { status = status || { exists: true, demo: false, retry_after: 0 }; }
  showAuth(status, { onUnlocked: unlocked, message });
}

async function lock(message) {
  await wipe(message, true);
}

const RESTARTED = "Le serveur local a redémarré : rechargez la page.";
onLocked((err) => { if (!$("#app").hidden) wipe(err.code === "bad_token" ? RESTARTED : "Archive verrouillée."); });

async function unlocked() {
  status = await get("/api/status");
  enterApp();
}

async function importFolder() {
  const input = h("input", { type: "text", id: "import-path", placeholder: "C:\\Users\\vous\\Documents\\Notes", spellcheck: "false" });
  const ok = await confirmDialog("Importer un dossier", h("div", {},
    h("p", { class: "muted", text: "Chemin absolu d'un dossier de cette machine. Ses fichiers sont chiffrés dans l'archive ; leur date de fichier est gardée comme date déclarée, la date prouvable sera celle d'aujourd'hui." }),
    h("label", { for: "import-path", text: "Dossier" }), input), { ok: "Importer" });
  if (!ok || !input.value.trim()) return;
  try {
    const res = await post("/api/import", { path: input.value.trim() });
    const parts = Object.entries(res).map(([k, v]) => `${k} : ${typeof v === "object" ? JSON.stringify(v) : v}`);
    toast(`Import terminé. ${parts.join(", ")}`);
    emit("changed", {});
  } catch (err) { if (!ended(err)) toast(err.message, true); }
}

// --------------------------------------------------------------- keyboard
document.addEventListener("keydown", (e) => {
  const typing = e.target instanceof HTMLElement && (e.target.matches("input, textarea, select") || e.target.isContentEditable);
  if ($("#app").hidden) return;
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); showView("search"); return; }
  if (e.key === "/" && !typing) { e.preventDefault(); showView("search"); return; }
  if (e.key === "Escape") {
    if ($("#dialog").open) return;
    if (!pane.hidden) { closePane(); e.preventDefault(); return; }
    if ($("#app").classList.contains("sidebar-open")) { $("#app").classList.remove("sidebar-open"); return; }
    if (graph.anim) { graph.stopAnimation(); return; }
    if (current !== "graph") { showView("graph"); }
  }
});

// ------------------------------------------------------------------- boot
async function boot() {
  try {
    status = await get("/api/status");
  } catch (err) {
    $("#auth").hidden = false;
    $("#auth-body").appendChild(h("p", { class: "error", text: err.message }));
    return;
  }
  showAuth(status, { onUnlocked: unlocked });
}
boot();
