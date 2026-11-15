// Registre: the hash chain as a table, integrity check, anchors, explicit anchoring.
import { h, clear, fmtDateTime, short, fmtBytes, confirmDialog, toast } from "../dom.js";
import { get, post, qs, ended } from "../api.js";
import { state, emit } from "../state.js";
import { anchorStatusList } from "../reader.js";

const METHOD_LABEL = { rfc3161: "RFC 3161 (autorité d'horodatage)", opentimestamps: "OpenTimestamps" };

const PAGE = 50;
const KIND = { put: "version", remove: "retrait", license: "licence", royalty: "redevance" };
let offset = 0;

export async function renderLedger(root) {
  clear(root);
  const inner = h("div", { class: "inner" });
  root.appendChild(inner);
  inner.append(h("h1", { text: "Registre" }),
    h("p", { class: "lead", text: "Chaque version, retrait, licence et redevance ajoute une ligne chaînée à la précédente par son hachage. Ce registre ne contient ni texte ni nom : il peut être montré à n'importe qui." }));

  const report = h("div", { "aria-live": "polite" });
  const verifyBtn = h("button", { class: "btn btn-primary", text: "Vérifier l'intégrité", on: { click: async () => {
    verifyBtn.disabled = true;
    clear(report).appendChild(h("p", { class: "muted", text: "Vérification de toute la chaîne..." }));
    try {
      const r = await post("/api/verify", {});
      clear(report).appendChild(h("div", { class: "card" },
        h("div", { class: "row" }, h("span", { class: `badge ${r.ok ? "badge-ok" : "badge-bad"}`, text: r.ok ? "Intègre" : "Anomalies détectées" }),
          h("span", { class: "muted", text: `${r.n_records} enregistrements, ${r.signatures_checked} signatures, ${r.blobs_checked} blocs chiffrés, ${r.anchors_checked} ancres vérifiés` })),
        h("div", { class: "mono faint", style: { marginTop: "6px" }, title: r.head_hash, text: `Tête de chaîne : ${r.head_hash}` }),
        r.errors.length ? h("ul", { class: "error" }, ...r.errors.map((e) => h("li", { text: e }))) : null,
        Array.isArray(r.anchor_status) && r.anchor_status.length
          ? h("div", { style: { marginTop: "8px" } }, h("strong", { text: "Ancres revérifiées" }), anchorStatusList(r.anchor_status)) : null));
    } catch (err) {
      if (ended(err)) return;
      clear(report).appendChild(h("p", { class: "error", text: err.message }));
    }
    verifyBtn.disabled = false;
  } } });

  // Only the methods this vault really implements (status.features.anchor_methods).
  const methods = (state.features.anchor_methods || []).filter((m) => METHOD_LABEL[m]);
  const method = h("select", { id: "anchor-method" }, ...methods.map((m) => h("option", { value: m, text: METHOD_LABEL[m] })));
  const anchorBtn = h("button", { class: "btn", text: "Ancrer maintenant", on: { click: async () => {
    const ok = await confirmDialog("Ancrer la chaîne maintenant ?",
      h("div", {},
        h("p", { text: "Seule l'empreinte de 32 octets de la tête de chaîne est envoyée à une autorité d'horodatage extérieure : aucun texte, aucun titre, aucun nom ne quitte cette machine." }),
        h("p", { class: "faint", text: "C'est la seule connexion réseau d'Empreinte. Elle rend la date de tout ce qui est déjà enregistré vérifiable par un tiers." })),
      { ok: "Envoyer l'empreinte" });
    if (!ok) return;
    anchorBtn.disabled = true;
    try {
      const a = await post("/api/anchor", { method: method.value, confirm: true });
      toast(`Ancre obtenue jusqu'à la séquence ${a.seq_upto}.`);
      renderLedger(root);
    } catch (err) { if (ended(err)) return; toast(err.message, true); anchorBtn.disabled = false; }
  } } });
  if (methods.length) {
    inner.append(h("div", { class: "row" }, verifyBtn,
      h("label", { class: "sr-only", for: "anchor-method", text: "Méthode d'ancrage" }), h("div", { style: { width: "260px" } }, method), anchorBtn), report);
  } else {
    inner.append(h("div", { class: "row" }, verifyBtn,
      h("span", { class: "muted", text: "Aucun horodatage extérieur n'est disponible pour cette archive." })), report);
  }

  const anchorsSlot = h("div");
  const tableSlot = h("div");
  inner.append(h("h2", { text: "Ancres externes" }), anchorsSlot, h("h2", { text: "Enregistrements" }), tableSlot);

  try {
    const anchors = await get("/api/anchors");
    if (!anchors.length) anchorsSlot.appendChild(h("p", { class: "faint", text: "Aucune ancre : les dates reposent seulement sur le registre local." }));
    else anchorsSlot.appendChild(h("div", { class: "table-wrap" }, h("table", { class: "data-table" },
      h("thead", {}, h("tr", {}, ...["Couvre jusqu'à", "Date indiquée par l'autorité", "Méthode", "Autorité", "Tête ancrée"].map((t) => h("th", { text: t })))),
      h("tbody", {}, ...anchors.slice().reverse().map((a) => h("tr", {},
        h("td", { text: `séquence ${a.seq_upto}` }),
        h("td", { text: a.anchored_at ? fmtDateTime(a.anchored_at) : "en attente" }),
        h("td", { text: a.method }),
        h("td", { text: a.authority }),
        h("td", { class: "mono", title: a.head_hash, text: short(a.head_hash, 12) })))))));
  } catch (err) { if (ended(err)) return; anchorsSlot.appendChild(h("p", { class: "error", text: err.message })); }
  await renderPage(tableSlot);
}

async function renderPage(slot) {
  clear(slot).appendChild(h("p", { class: "muted", text: "Chargement..." }));
  let page;
  try { page = await get(`/api/ledger${qs({ offset, limit: PAGE, order: "desc" })}`); }
  catch (err) { if (!ended(err)) clear(slot).appendChild(h("p", { class: "error", text: err.message })); return; }
  clear(slot);
  const known = (id) => id && state.byId.has(id);
  const table = h("table", { class: "data-table" },
    h("thead", {}, h("tr", {}, ...["Séq.", "Type", "Identifiant", "Version", "Taille", "Engagement", "Hachage", "Précédent", "Horodatage (registre)"].map((t) => h("th", { text: t })))),
    h("tbody", {}, ...page.records.map((r) => h("tr", {},
      h("td", { text: String(r.seq) }),
      h("td", { text: KIND[r.kind] || r.kind }),
      h("td", { class: "mono" }, r.entry_id
        ? (known(r.entry_id)
          ? h("a", { href: "#", class: "wikilink", title: `${r.entry_id} (ouvrir la note)`, text: short(r.entry_id, 8), on: { click: (e) => { e.preventDefault(); emit("open", { id: r.entry_id }); } } })
          : h("span", { title: r.entry_id, text: short(r.entry_id, 8) }))
        : h("span", { class: "faint", text: "aucun" })),
      h("td", { text: r.version ? `v${r.version}` : "" }),
      h("td", { text: r.size ? fmtBytes(r.size) : "" }),
      h("td", { class: "mono", title: r.commitment, text: short(r.commitment, 8) }),
      h("td", { class: "mono", title: r.record_hash, text: short(r.record_hash, 8) }),
      h("td", { class: "mono faint", title: r.prev_hash, text: short(r.prev_hash, 8) }),
      h("td", { text: fmtDateTime(r.timestamp) })))));
  const from = page.total ? page.offset + 1 : 0, to = Math.min(page.total, page.offset + page.records.length);
  const nav = h("div", { class: "row", style: { margin: "10px 0" } },
    h("button", { class: "btn btn-small", disabled: offset === 0, text: "Plus récents", on: { click: () => { offset = Math.max(0, offset - PAGE); renderPage(slot); } } }),
    h("span", { class: "muted", text: `${from} à ${to} sur ${page.total}, du plus récent au plus ancien` }),
    h("button", { class: "btn btn-small", disabled: to >= page.total, text: "Plus anciens", on: { click: () => { offset += PAGE; renderPage(slot); } } }));
  slot.append(nav, h("div", { class: "table-wrap" }, table));
}
