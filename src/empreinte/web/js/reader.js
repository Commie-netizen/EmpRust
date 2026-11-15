// Reading a note: rendered text, tags, links, versions with ledger dates, provenance.
import { h, clear, fmtDateTime, fmtBytes, short, toast, confirmDialog } from "./dom.js";
import { get, post, qs, ended } from "./api.js";
import { render as renderMarkdown } from "./markdown.js";
import { state, emit, titleOf } from "./state.js";

const KIND_LABEL = { note: "note", draft: "brouillon", log: "journal", code: "code", file: "pièce jointe" };
const tokens = new WeakMap();

// Same rule as parse.is_text on the server: textual types, structured text included.
const TEXT_TYPES = new Set(["application/json", "application/xml", "application/javascript", "application/x-python",
  "application/sql", "application/x-sh", "application/toml", "application/yaml", "application/x-yaml", "image/svg+xml"]);

export function mediaOf(mediaType) { return String(mediaType || "").toLowerCase().split(";")[0].trim(); }
export function isMarkdown(mediaType) { const m = mediaOf(mediaType); return m === "text/markdown" || m === "text/x-markdown"; }
export function isTextual(mediaType) {
  const m = mediaOf(mediaType);
  return m.startsWith("text/") || m.endsWith("+json") || m.endsWith("+xml") || TEXT_TYPES.has(m);
}

// Wording shared by the reading header and the provenance card.
export const WORDS = {
  recorded: "Enregistré le",
  recordedNote: "Registre local, horloge de cette machine : prouve l'ordre des versions, pas la date à lui seul.",
  claimed: "Date du fichier (déclarée)",
  claimedNote: "Date lue sur le fichier importé. Ce n'est qu'une déclaration, rien ne la prouve.",
};

function noteLink(id) {
  return h("a", { href: "#", class: "wikilink", text: titleOf(id),
    on: { click: (e) => { e.preventDefault(); emit("open", { id }); } } });
}

const STATE_LABEL = { proven: "authentifiée", claimed: "non authentifiée", invalid: "invalide" };

function earliestIn(statuses, wanted) {
  return statuses.filter((a) => a.state === wanted && a.anchored_at)
    .reduce((a, b) => (!a || b.anchored_at < a.anchored_at ? b : a), null);
}

/** One line per anchor, as re-checked by the vault (AnchorStatus). */
export function anchorStatusList(statuses) {
  return h("ul", { class: "anchor-status" }, ...statuses.map((a) => h("li", {},
    h("span", { class: `badge ${a.state === "proven" ? "badge-ok" : a.state === "claimed" ? "badge-warn" : "badge-bad"}`, text: STATE_LABEL[a.state] || a.state }),
    ` ${a.authority}${a.signer ? ` (signataire : ${a.signer})` : ""}, jusqu'à la séquence ${a.seq_upto}`,
    a.anchored_at ? `, ${a.state === "proven" ? "date attestée" : "date déclarée"} ${fmtDateTime(a.anchored_at)}` : "",
    a.error ? h("div", { class: "faint", text: a.error }) : null)));
}

/** The provenance card. An authority is named as authenticated only from an AnchorStatus
 * whose state is "proven"; "claimed" ones are a claim; "invalid" ones show their error. */
export function provenanceCard(proof, version) {
  const rec = proof.record;
  const dl = h("dl");
  const row = (label, ...value) => dl.append(h("dt", { text: label }), h("dd", {}, ...value));
  const statuses = Array.isArray(proof.anchor_status) ? proof.anchor_status : null;
  const proven = statuses ? earliestIn(statuses, "proven") : null;
  const claimed = statuses ? earliestIn(statuses, "claimed") : null;
  if (proof.proven_before) {
    const who = proven ? `${proven.authority}${proven.signer ? `, signataire ${proven.signer}` : ""}, registre couvert jusqu'à la séquence ${proven.seq_upto}` : "";
    row("Prouvé depuis", h("strong", { class: "proven", text: fmtDateTime(proof.proven_before) }),
      h("div", { class: "faint", text: `Une autorité d'horodatage authentifiée atteste que cette version existait au plus tard à cette date${who ? ` (${who})` : ""}. Un tiers peut le vérifier sans l'archive.` }));
  } else if (proof.claimed_before) {
    row("Horodatage extérieur", h("strong", { class: "claimed", text: `déclaré le ${fmtDateTime(proof.claimed_before)}` }),
      h("div", { class: "faint", text: `Un jeton d'horodatage${claimed ? ` de ${claimed.authority}` : ""} couvre cette version, mais cette autorité n'a pas pu être authentifiée : c'est sa déclaration, pas une preuve.` }));
  } else {
    row("Horodatage extérieur", h("span", { class: "muted", text: "aucun ne couvre encore cette version" }),
      h("div", { class: "faint", text: "Sa date ne repose pour l'instant que sur le registre local : aucun tiers ne peut encore la vérifier. Un ancrage depuis le Registre la couvrirait, avec tout ce qui a été enregistré avant elle." }));
  }
  if (!proof.proven_before && proof.claimed_before) {
    row("Couverture", h("span", { class: "badge badge-warn", text: "non couverte par une ancre authentifiée" }),
      h("div", { class: "faint", text: "Aucun tiers ne peut encore vérifier la date de cette version. Un ancrage depuis le Registre la couvrirait, avec tout ce qui a été enregistré avant elle." }));
  }
  if (statuses && statuses.length) row("Ancres", anchorStatusList(statuses));
  if (proof.anchor_errors && proof.anchor_errors.length) {
    row("Ancres écartées", h("ul", { class: "anchor-errors" }, ...proof.anchor_errors.map((e) => h("li", { text: e }))));
  }
  row(WORDS.recorded, h("span", { text: fmtDateTime(rec.timestamp) }), h("div", { class: "faint", text: WORDS.recordedNote }));
  if (version && version.source_mtime) {
    row(WORDS.claimed, h("span", { class: "claimed", text: fmtDateTime(version.source_mtime) }),
      h("div", { class: "faint", text: WORDS.claimedNote }));
  } else {
    row(WORDS.claimed, h("span", { class: "faint", text: "aucune" }));
  }
  row("Chaîne revérifiée", proof.verified ? h("span", { class: "badge badge-ok", text: "oui, à l'instant" })
    : h("span", { class: "badge badge-bad", text: "non" }),
    h("div", { class: "faint", text: `${proof.n_following} enregistrement${proof.n_following > 1 ? "s" : ""} chaîné${proof.n_following > 1 ? "s" : ""} après celui-ci.` }));
  row("Enregistrement", h("span", { class: "mono", text: `n° ${rec.seq}, ${rec.kind}, v${rec.version}` }));
  row("Engagement", h("span", { class: "mono", title: rec.commitment, text: short(rec.commitment, 16) }));
  row("Hachage", h("span", { class: "mono", title: rec.record_hash, text: short(rec.record_hash, 16) }));
  row("Signature", rec.signature ? h("span", { class: "mono", title: rec.signature, text: short(rec.signature, 16) })
    : h("span", { class: "faint", text: "absente (archive de démonstration ou de test)" }));
  return h("div", { class: "prov" }, h("strong", { text: `Provenance de la version ${rec.version}` }), dl);
}

function previewBox(p, into, id) {
  const status = p.approved
    ? h("span", { class: "badge badge-ok", text: "Approuvé" })
    : h("span", { class: "badge badge-warn", text: "Brouillon, à relire avant toute diffusion" });
  const box = h("div", { class: "preview-box" },
    h("div", { class: "row" }, status, h("span", { class: "faint", text: `aperçu de la v${p.version}, ${p.words} mots, par ${p.model}` })),
    p.current === false ? h("p", { class: "badge badge-warn", text: "Porte sur une ancienne version : régénérez-le." }) : null,
    p.source_partial ? h("p", { class: "faint", text: "Aperçu fondé sur des extraits : certains passages n'ont pas été transmis au modèle." }) : null,
    h("p", { text: p.summary }),
    p.keywords.length ? h("div", {}, ...p.keywords.map((k) => h("span", { class: "chip", text: k }))) : null);
  if (!p.approved && p.current !== false && p.digest) {
    box.appendChild(h("button", { class: "btn btn-small", text: "Approuver", on: { click: async () => {
      try {
        // Names the exact preview shown: the server refuses if another one is stored now.
        const approved = await post(`/api/previews/${id}/approve`, { digest: p.digest });
        clear(into).appendChild(previewBox(approved, into, id));
        toast("Aperçu approuvé.");
      } catch (err) { if (!ended(err)) toast(err.message, true); }
    } } }));
  }
  return box;
}

export async function requestPreview(id, into) {
  try {
    const [p] = await post("/api/previews", { entry_ids: [id] });
    clear(into).appendChild(previewBox(p, into, id));
  } catch (err) {
    if (!ended(err)) toast(err.message, true);
  }
}

async function showStoredPreview(id, into) {
  try {
    const p = await get(`/api/previews/${id}`);
    if (!into.firstChild) into.appendChild(previewBox(p, into, id));
  } catch { /* none stored */ }
}

/** The server's link_targets map is the only source: exact raw target, nothing else. */
function resolverFor(map) {
  return (target) => (Object.prototype.hasOwnProperty.call(map, target) ? map[target] : null);
}

function bodyFor(text, meta, linkTargets, pane) {
  const media = mediaOf(text.media_type);
  if (isMarkdown(media)) {
    const resolve = resolverFor(linkTargets || {});
    return h("article", { class: "md" }, renderMarkdown(text.text, {
      resolve,
      onWikilink: (id) => emit("open", { id, pane }),
    }));
  }
  if (isTextual(media) || text.text) {
    // Structured or plain text: shown as escaped source, never interpreted (SVG included).
    return h("div", {},
      h("div", { class: "faint", style: { fontSize: "12.5px", marginBottom: "4px" }, text: `${media}, affiché comme texte source` }),
      h("pre", { class: "source" }, h("code", { text: text.text })));
  }
  return h("p", { class: "muted", text: `Fichier ${media}, ${fmtBytes(meta.size)}. Le contenu binaire n'est pas affiché.` });
}

/** Render note `id` into `root`. options: {pane: bool, onClose, version}. */
export async function renderNote(root, id, options = {}) {
  const token = Symbol(id);
  tokens.set(root, token);
  clear(root).appendChild(h("p", { class: "muted", text: "Chargement..." }));
  let entry, text, versions, proof;
  try {
    [entry, text, versions, proof] = await Promise.all([
      get(`/api/entries/${id}`),
      get(`/api/entries/${id}/text${qs({ version: options.version })}`),
      get(`/api/entries/${id}/versions`),
      get(`/api/entries/${id}/proof${qs({ version: options.version })}`),
    ]);
  } catch (err) {
    if (ended(err) || tokens.get(root) !== token) return;
    clear(root).appendChild(h("p", { class: "error", text: err.code === "not_found" ? "Cette note n'existe plus." : err.message }));
    return;
  }
  if (tokens.get(root) !== token) return;
  state.currentNote = id;
  const meta = entry.meta;
  const shown = versions.find((v) => v.version === text.version) || versions[versions.length - 1];
  clear(root);

  const actions = h("div", { class: "note-actions" });
  if (options.pane) {
    actions.append(
      h("button", { class: "btn btn-small", on: { click: () => emit("view", { view: "reading", id }) } }, "Ouvrir en lecture"),
      h("button", { class: "btn btn-small", "aria-label": "Fermer la note", on: { click: () => options.onClose && options.onClose() } }, "Fermer"));
  } else {
    actions.append(h("button", { class: "btn btn-small", on: { click: () => emit("view", { view: "graph", focus: id }) } }, "Voir dans le graphe"));
  }
  const previewSlot = h("div");
  if (state.features.previews && isTextual(meta.media_type)) {
    actions.append(h("button", { class: "btn btn-small", on: { click: () => requestPreview(id, previewSlot) } }, "Aperçu"));
  }
  actions.append(h("button", { class: "btn btn-small btn-danger", on: { click: async () => {
    const ok = await confirmDialog("Retirer cette note ?",
      "La note disparaît de l'archive vivante. Son historique reste dans le registre, qui enregistre ce retrait.",
      { ok: "Retirer", danger: true });
    if (!ok) return;
    try {
      await post(`/api/entries/${id}/remove`, { confirm: true });
      toast("Note retirée.");
      emit("changed", {});
      if (options.onClose) options.onClose();
    } catch (err) { if (!ended(err)) toast(err.message, true); }
  } } }, "Retirer"));

  const dates = h("div", { class: "note-dates" },
    h("span", {}, `${WORDS.recorded} ${fmtDateTime(shown.timestamp)} `, h("span", { class: "faint", text: "(registre local)" })),
    shown.source_mtime
      ? h("span", { class: "claimed" }, `${WORDS.claimed} : ${fmtDateTime(shown.source_mtime)}`)
      : h("span", { class: "faint", text: `${WORDS.claimed} : aucune` }));

  const tags = [...new Set([...meta.tags, ...entry.parsed.tags])];
  const head = h("header", { class: "note-head" },
    h("h1", { text: meta.title }),
    h("div", { class: "note-path", text: `${meta.path}  ·  ${KIND_LABEL[meta.kind] || meta.kind}  ·  ${mediaOf(meta.media_type)}  ·  ${fmtBytes(meta.size)}` }),
    dates,
    tags.length ? h("div", { style: { marginTop: "6px" } }, ...tags.map((t) => h("span", { class: "chip", text: `#${t}` }))) : null,
    actions, previewSlot);

  const body = h("div");
  if (shown.version !== meta.n_versions) {
    body.appendChild(h("p", { class: "badge badge-warn", text: `Version ${shown.version} sur ${meta.n_versions}, enregistrée le ${fmtDateTime(shown.timestamp)}` }));
  }
  body.appendChild(bodyFor(text, meta, entry.link_targets, options.pane));

  const links = h("section", {},
    h("h2", { text: "Liens" }),
    h("div", { class: "links-grid" },
      h("div", {}, h("h3", { class: "faint", style: { fontSize: "13px", margin: "0 0 4px" }, text: `Rétroliens (${entry.backlinks.length})` }),
        entry.backlinks.length ? h("ul", { class: "link-list" }, ...entry.backlinks.map((b) => h("li", {}, noteLink(b))))
          : h("p", { class: "faint", text: "Aucune note ne mène ici." })),
      h("div", {}, h("h3", { class: "faint", style: { fontSize: "13px", margin: "0 0 4px" }, text: `Liens sortants (${entry.outlinks.length})` }),
        entry.outlinks.length ? h("ul", { class: "link-list" }, ...entry.outlinks.map((b) => h("li", {}, noteLink(b))))
          : h("p", { class: "faint", text: "Aucun lien résolu." }))));

  const vTable = h("table", { class: "versions-table" },
    h("thead", {}, h("tr", {}, ...["Version", `${WORDS.recorded} (registre)`, WORDS.claimed, "Taille", "Engagement", ""].map((t) => h("th", { text: t })))),
    h("tbody", {}, ...versions.slice().reverse().map((v) => h("tr", {},
      h("td", { text: `v${v.version}` }),
      h("td", { text: fmtDateTime(v.timestamp) }),
      h("td", { class: v.source_mtime ? "" : "faint", text: v.source_mtime ? fmtDateTime(v.source_mtime) : "aucune" }),
      h("td", { text: fmtBytes(v.size) }),
      h("td", { class: "mono", title: v.commitment, text: short(v.commitment, 8) }),
      h("td", {}, v.version === shown.version ? h("span", { class: "faint", text: "affichée" })
        : h("button", { class: "btn btn-small", "aria-label": `Afficher la version ${v.version}`,
          on: { click: () => renderNote(root, id, { ...options, version: v.version }) } }, "Afficher"))))));

  root.append(head, body, links,
    h("section", {}, h("h2", { text: `Versions (${versions.length})` }), h("div", { class: "table-wrap" }, vTable)),
    h("section", {}, h("h2", { text: "Provenance" }), provenanceCard(proof, shown)));
  showStoredPreview(id, previewSlot);
}
