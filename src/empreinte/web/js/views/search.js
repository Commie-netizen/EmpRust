// Recherche: full-text search, and "Première apparition" of a term with provable dates.
import { h, clear, fmtDateTime, highlight } from "../dom.js";
import { post, ended } from "../api.js";
import { emit } from "../state.js";

let lastQuery = "";
let lastTerm = "";

export function focusSearch(root) {
  const input = root.querySelector("#search-q");
  if (input) { input.focus(); input.select(); }
}

function terms(q) { return q.split(/\s+/).filter((t) => t.length > 1); }

export function renderSearch(root) {
  clear(root);
  const inner = h("div", { class: "inner" });
  root.appendChild(inner);

  const q = h("input", { type: "search", id: "search-q", value: lastQuery, placeholder: "Mots à chercher dans toutes les notes", autocomplete: "off" });
  const results = h("div", { "aria-live": "polite" });
  const run = async () => {
    lastQuery = q.value.trim();
    if (!lastQuery) { clear(results); return; }
    clear(results).appendChild(h("p", { class: "muted", text: "Recherche..." }));
    try {
      const hits = await post("/api/search", { q: lastQuery, limit: 50 });
      clear(results);
      results.appendChild(h("p", { class: "faint", text: hits.length ? `${hits.length} résultat${hits.length > 1 ? "s" : ""}` : "Aucun résultat." }));
      const list = h("ul", { class: "hits" });
      for (const hit of hits) {
        list.appendChild(h("li", { class: "hit" },
          h("button", { class: "hit-title", text: hit.title, on: { click: () => emit("open", { id: hit.entry_id }) } }),
          h("div", { class: "faint", style: { fontSize: "12px" }, text: `${hit.path}  ·  enregistrée le ${fmtDateTime(hit.updated_at)} (registre)` }),
          highlight(h("div", { class: "hit-snippet" }), hit.snippet, terms(lastQuery))));
      }
      results.appendChild(list);
    } catch (err) { if (!ended(err)) clear(results).appendChild(h("p", { class: "error", text: err.message })); }
  };
  const form = h("form", { class: "search-box", role: "search" },
    h("label", { class: "sr-only", for: "search-q", text: "Recherche plein texte" }), q,
    h("button", { type: "submit", class: "btn btn-primary", text: "Chercher" }));
  form.addEventListener("submit", (e) => { e.preventDefault(); run(); });

  const term = h("input", { type: "search", id: "first-term", value: lastTerm, placeholder: "Un mot, une expression", autocomplete: "off" });
  const firsts = h("div", { "aria-live": "polite" });
  const runFirst = async () => {
    lastTerm = term.value.trim();
    if (!lastTerm) { clear(firsts); return; }
    clear(firsts).appendChild(h("p", { class: "muted", text: "Recherche dans toutes les versions..." }));
    try {
      const mentions = await post("/api/mentions", { term: lastTerm, limit: 200 });
      clear(firsts);
      if (!mentions.length) { firsts.appendChild(h("p", { class: "faint", text: "Ce terme n'apparaît dans aucune version." })); return; }
      const first = mentions[0];
      firsts.appendChild(h("div", { class: "card" },
        h("div", { class: "faint", text: "Première trace enregistrée" }),
        h("div", { style: { fontSize: "18px", fontWeight: "600" }, text: fmtDateTime(first.timestamp) }),
        h("div", {}, "dans ", h("a", { href: "#", class: "wikilink", text: first.title, on: { click: (e) => { e.preventDefault(); emit("open", { id: first.entry_id }); } } }), ` (version ${first.version})`),
        h("p", { class: "faint", style: { fontSize: "12.5px", margin: "6px 0 0" }, text: "Date du registre : c'est la date démontrable, que l'ancre externe rend vérifiable par un tiers quand elle la couvre. La date de fichier éventuelle n'est qu'une déclaration." })));
      const table = h("table", { class: "data-table" },
        h("thead", {}, h("tr", {}, ...["Enregistrée le (registre)", "Date du fichier (déclarée)", "Note", "Version", "Extrait"].map((t) => h("th", { text: t })))),
        h("tbody", {}, ...mentions.map((m) => h("tr", {},
          h("td", { text: fmtDateTime(m.timestamp) }),
          h("td", { class: m.authored_at ? "" : "faint", text: m.authored_at ? fmtDateTime(m.authored_at) : "aucune" }),
          h("td", {}, h("a", { href: "#", class: "wikilink", text: m.title, on: { click: (e) => { e.preventDefault(); emit("open", { id: m.entry_id }); } } })),
          h("td", { text: `v${m.version}` }),
          highlight(h("td", { class: "hit-snippet" }), m.snippet, [lastTerm])))));
      firsts.appendChild(h("div", { class: "table-wrap" }, table));
    } catch (err) { if (!ended(err)) clear(firsts).appendChild(h("p", { class: "error", text: err.message })); }
  };
  const form2 = h("form", { class: "search-box" },
    h("label", { class: "sr-only", for: "first-term", text: "Terme dont chercher la première apparition" }), term,
    h("button", { type: "submit", class: "btn btn-primary", text: "Trouver" }));
  form2.addEventListener("submit", (e) => { e.preventDefault(); runFirst(); });

  inner.append(
    h("h1", { text: "Recherche" }),
    h("p", { class: "lead", text: "Dans le texte de toutes les notes. Ctrl+K ou / pour revenir ici." }),
    form, results,
    h("h2", { text: "Première apparition" }),
    h("p", { class: "faint", style: { fontSize: "13px" }, text: "Toutes les versions où un terme apparaît, de la plus ancienne à la plus récente, avec leur date enregistrée." }),
    form2, firsts);
  if (lastQuery) run();
  if (lastTerm) runFirst();
}

/** Forget the last queries (called on lock). */
export function resetSearch() { lastQuery = ""; lastTerm = ""; }
