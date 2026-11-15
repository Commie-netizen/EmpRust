// Licences: grants, creating one, exporting the bundle, the royalty register, previews.
import { h, clear, fmtDate, fmtDateTime, fmtMoney, short, toast, confirmDialog } from "../dom.js";
import { get, post, ended } from "../api.js";
import { state, emit, titleOf } from "../state.js";
import { requestPreview } from "../reader.js";

const MODEL = { none: "sans redevance", flat: "forfait", per_use: "par utilisation", revenue_share: "partage de revenus" };
const picked = new Map(); // entry_id -> version (null = latest)
const listed = new Map(); // catalogue: entry_id -> {show_title, show_path, show_tags}
const ANCHORED = {
  proven: ["badge-ok", "date prouvée"],
  claimed: ["badge-warn", "date seulement déclarée"],
  none: ["", "pas encore prouvable par un tiers"],
};

function royaltyText(r) {
  if (r.model === "none") return "Sans redevance";
  if (r.model === "revenue_share") return `Partage de revenus : ${String(r.amount).replace(".", ",")} % (${r.currency})`;
  if (r.model === "per_use") return `Par utilisation : ${fmtMoney(r.amount, r.currency)}`;
  return `Forfait : ${fmtMoney(r.amount, r.currency)}`;
}

function field(id, label, input) { input.id = id; return h("div", { class: "field" }, h("label", { for: id, text: label }), input); }

export function resetLicenses() { picked.clear(); listed.clear(); }

export async function renderLicenses(root) {
  clear(root);
  const inner = h("div", { class: "inner" });
  root.appendChild(inner);
  inner.append(h("h1", { text: "Licences" }),
    h("p", { class: "lead", text: "Céder un droit d'usage note par note, avec la preuve de date de chaque version attachée. Chaque licence et chaque paiement reçu sont inscrits au registre." }));
  const listSlot = h("div");
  const royaltySlot = h("div");
  const catalogueSlot = h("div");
  inner.append(h("h2", { text: "Licences accordées" }), listSlot, h("h2", { text: "Registre des redevances" }), royaltySlot,
    h("h2", { text: "Nouvelle licence" }), grantForm(() => renderLicenses(root)),
    h("h2", { text: "Catalogue public" }), catalogueSlot);
  renderCatalogue(catalogueSlot);

  let grants, events;
  try { [grants, events] = await Promise.all([get("/api/licenses"), get("/api/royalties")]); }
  catch (err) { if (!ended(err)) listSlot.appendChild(h("p", { class: "error", text: err.message })); return; }

  if (!grants.length) listSlot.appendChild(h("p", { class: "faint", text: "Aucune licence pour l'instant." }));
  for (const g of grants.slice().reverse()) listSlot.appendChild(grantCard(g, () => renderLicenses(root)));

  // Royalty register with totals per licence and per currency.
  if (!events.length) { royaltySlot.appendChild(h("p", { class: "faint", text: "Aucun paiement enregistré." })); return; }
  const byLicense = new Map(grants.map((g) => [g.license_id, g]));
  const perLicense = new Map(), perCurrency = new Map();
  for (const e of events) {
    const k = `${e.license_id}|${e.currency}`;
    perLicense.set(k, (perLicense.get(k) || 0) + e.amount);
    perCurrency.set(e.currency, (perCurrency.get(e.currency) || 0) + e.amount);
  }
  royaltySlot.append(
    h("div", { class: "table-wrap" }, h("table", { class: "data-table" },
      h("thead", {}, h("tr", {}, ...["Reçu le", "Licence", "Période", "Montant", "Note", "Séq."].map((t) => h("th", { text: t })))),
      h("tbody", {}, ...events.slice().reverse().map((e) => h("tr", {},
        h("td", { text: fmtDate(e.received_on) }),
        h("td", { text: byLicense.get(e.license_id) ? byLicense.get(e.license_id).licensee : e.license_id }),
        h("td", { text: e.period }),
        h("td", { text: fmtMoney(e.amount, e.currency) }),
        h("td", { text: e.note }),
        h("td", { text: String(e.seq) })))))),
    h("div", { class: "grid-2", style: { marginTop: "12px" } },
      h("div", { class: "card" }, h("strong", { text: "Total par licence" }),
        h("ul", { class: "link-list" }, ...[...perLicense.entries()].map(([k, v]) => {
          const [id, cur] = k.split("|");
          return h("li", { text: `${byLicense.get(id) ? byLicense.get(id).licensee : id} : ${fmtMoney(v, cur)}` });
        }))),
      h("div", { class: "card" }, h("strong", { text: "Total par devise" }),
        h("ul", { class: "link-list" }, ...[...perCurrency.entries()].map(([cur, v]) => h("li", { text: fmtMoney(v, cur) }))))));
}

// ------------------------------------------------------------------ public catalogue
// What a prospective licensee may see before any licence: approved previews and date
// proofs, no text. Only entries with an approved preview can be ticked.
async function renderCatalogue(slot) {
  clear(slot).append(
    h("p", { class: "muted", text: "À remettre à un licencié potentiel avant toute licence. Pour chaque note choisie : son aperçu approuvé, son nombre de mots, son type de fichier, et les éléments de vérification de sa date, selon son ancrage. Aucun texte de note n'y figure ; titre, chemin et étiquettes seulement si vous les cochez." }),
    h("p", { class: "faint", style: { fontSize: "12.5px" }, text: "Un catalogue ne prouve une date que pour une entrée avec une ancre prouvée. Une ancre seulement déclarée porte une affirmation d'une autorité non authentifiée. Sans ancre, une entrée ne prouve encore rien sur les dates. Les résumés et mots-clés sont des déclarations du propriétaire, pas des faits vérifiés. Il ne prouve ni sa qualité, ni son originalité, ni qui l'a écrite au-delà du détenteur de la clé de cette archive." }),
    h("p", { class: "muted", text: "Chargement..." }));
  let data;
  try { data = await get("/api/catalogue"); }
  catch (err) { if (!ended(err)) clear(slot).appendChild(h("p", { class: "error", text: err.message })); return; }
  slot.lastChild.remove();
  const candidates = data.candidates;
  const byId = new Map(candidates.map((c) => [c.entry_id, c]));
  for (const id of [...listed.keys()]) if (!byId.has(id) || !byId.get(id).eligible) listed.delete(id);

  const filter = h("input", { type: "search", placeholder: "Filtrer les notes", "aria-label": "Filtrer les notes du catalogue" });
  const onlyEligible = h("input", { type: "checkbox", id: "cat-eligible", checked: true });
  const list = h("div", { class: "picker", role: "group", "aria-label": "Notes du catalogue", style: { maxHeight: "360px" } });
  const count = h("span", { class: "muted" });
  const err = h("p", { class: "error", role: "alert" });
  const result = h("div");
  const nEligible = candidates.filter((c) => c.eligible).length;

  const renderCount = () => {
    count.textContent = `${listed.size} note${listed.size > 1 ? "s" : ""} choisie${listed.size > 1 ? "s" : ""} sur ${nEligible} avec un aperçu approuvé`;
  };
  const showBox = (id, key, label) => {
    const opts = listed.get(id);
    const box = h("input", { type: "checkbox", checked: !!(opts && opts[key]), disabled: !opts,
      on: { change: () => { const o = listed.get(id); if (o) o[key] = box.checked; } } });
    return h("label", {}, box, label);
  };
  const renderList = () => {
    clear(list);
    const q = filter.value.trim().toLowerCase();
    let shown = 0;
    for (const e of state.entries) {
      const c = byId.get(e.entry_id);
      if (!c || (onlyEligible.checked && !c.eligible)) continue;
      if (q && !e.title.toLowerCase().includes(q) && !e.path.toLowerCase().includes(q)) continue;
      if (++shown > 400) break;
      const box = h("input", { type: "checkbox", checked: listed.has(e.entry_id), disabled: !c.eligible,
        "aria-label": `Inclure ${e.title} dans le catalogue`,
        on: { change: () => {
          if (box.checked) listed.set(e.entry_id, { show_title: false, show_path: false, show_tags: false });
          else listed.delete(e.entry_id);
          renderList(); renderCount();
        } } });
      const [cls, label] = ANCHORED[c.anchored] || ANCHORED.none;
      const why = c.eligible
        ? h("div", { class: "catalogue-why" },
          h("div", { class: "faint", text: c.summary }),
          !c.latest ? h("div", { class: "faint", text: `L'aperçu approuvé décrit la version ${c.version}, pas la dernière : c'est elle qui serait listée.` }) : null,
          h("div", { class: "catalogue-show" }, h("span", { text: "Montrer aussi :" }),
            showBox(e.entry_id, "show_title", "le titre"), showBox(e.entry_id, "show_path", "le chemin"), showBox(e.entry_id, "show_tags", "les étiquettes")))
        : h("div", { class: "catalogue-why faint", text: `Non sélectionnable : ${c.reason}` });
      list.appendChild(h("div", { class: "catalogue-row" }, box,
        h("span", { text: e.title }),
        c.eligible ? h("span", { class: `badge ${cls}`, text: label }) : h("span"),
        why));
    }
    if (!shown) list.appendChild(h("p", { class: "faint", text: nEligible ? "Aucune note ne correspond." : "Aucune note n'a encore d'aperçu approuvé : générez un aperçu depuis une note, relisez-le, puis approuvez-le." }));
  };
  filter.addEventListener("input", renderList);
  onlyEligible.addEventListener("change", renderList);
  renderList(); renderCount();

  const exportBtn = h("button", { class: "btn btn-primary", text: "Exporter le catalogue", on: { click: async () => {
    err.textContent = "";
    if (!listed.size) { err.textContent = "Choisissez au moins une note avec un aperçu approuvé."; return; }
    const items = [...listed.entries()].map(([entry_id, o]) => ({ entry_id, ...o }));
    const shownFields = (key) => items.filter((i) => i[key]).length;
    const ok = await confirmDialog("Exporter un catalogue public ?", h("div", {},
      h("p", { text: `${items.length} note${items.length > 1 ? "s" : ""}. Ce fichier est fait pour être donné : tout ce qu'il contient doit pouvoir être lu par n'importe qui.` }),
      h("ul", {},
        h("li", { text: "aperçus approuvés, nombre de mots, type de fichier, taille exacte et date du registre de chaque version" }),
        h("li", { text: `titres : ${shownFields("show_title")}, chemins : ${shownFields("show_path")}, étiquettes : ${shownFields("show_tags")}` }),
        h("li", { text: "le nombre d'enregistrements du registre entre chaque version et son ancre, pas leur contenu" })),
      h("p", { class: "faint", text: "Aucun texte de note n'est écrit. L'identifiant de chaque version dans le registre y figure, car la preuve de date en a besoin." })),
      { ok: "Exporter" });
    if (!ok) return;
    exportBtn.disabled = true;
    try {
      const pub = await post("/api/catalogue", { items, confirm: true });
      clear(result).appendChild(h("p", { class: "muted", style: { fontSize: "13px" } },
        "Catalogue écrit dans ", h("span", { class: "mono", text: pub.path }), `, empreinte ${short(pub.catalogue_hash, 16)}.`));
      toast("Catalogue exporté.");
      data.publications.push(pub);
      renderPublications(pubSlot, data.publications);
    } catch (ex) { if (!ended(ex)) err.textContent = ex.message; }
    exportBtn.disabled = false;
  } } });

  const pubSlot = h("div");
  slot.append(
    h("div", { class: "card" },
      h("div", { class: "row" }, filter,
        h("label", { for: "cat-eligible", class: "muted", style: { display: "inline-flex", gap: "4px", alignItems: "center" } }, onlyEligible, "seulement les notes sélectionnables")),
      list, count, err,
      state.features.export ? h("div", { class: "row", style: { marginTop: "10px" } }, exportBtn)
        : h("p", { class: "faint", text: "L'export n'est pas configuré pour cette archive." }),
      result),
    h("h3", { text: "Catalogues publiés" }), pubSlot);
  renderPublications(pubSlot, data.publications);
}

function renderPublications(slot, pubs) {
  clear(slot);
  if (!pubs.length) { slot.appendChild(h("p", { class: "faint", text: "Aucun catalogue exporté pour l'instant." })); return; }
  slot.appendChild(h("div", { class: "table-wrap" }, h("table", { class: "data-table" },
    h("thead", {}, h("tr", {}, ...["Exporté le", "Notes", "Datées par une ancre prouvée", "Dossier", "Empreinte"].map((t) => h("th", { text: t })))),
    h("tbody", {}, ...pubs.slice().reverse().map((p) => h("tr", {},
      h("td", { text: fmtDateTime(p.exported_at) }),
      h("td", { title: p.entries.map((e) => titleOf(e.entry_id)).join(", "), text: String(p.entries.length) }),
      h("td", { text: String(p.entries.filter((e) => e.anchor_state === "proven").length) }),
      h("td", { class: "mono", text: p.path }),
      h("td", { class: "mono", title: p.catalogue_hash, text: short(p.catalogue_hash, 10) })))))));
}

function grantCard(g, refresh) {
  const exportSlot = h("div");
  const actions = h("div", { class: "row", style: { marginTop: "10px" } });
  if (state.features.export) {
    actions.appendChild(h("button", { class: "btn btn-small", text: "Exporter le bundle", on: { click: async () => {
      try {
        const res = await post(`/api/licenses/${encodeURIComponent(g.license_id)}/export`, {});
        clear(exportSlot).appendChild(h("p", { class: "muted", style: { fontSize: "13px" } },
          "Bundle écrit dans ", h("span", { class: "mono", text: res.path }), res.bundle_hash ? `, empreinte du manifeste ${short(res.bundle_hash, 16)}` : ""));
      } catch (err) { if (!ended(err)) toast(err.message, true); }
    } } }));
  }
  const pay = royaltyForm(g, refresh);
  pay.hidden = true;
  actions.appendChild(h("button", { class: "btn btn-small", text: "Enregistrer un paiement", "aria-expanded": "false",
    on: { click: (e) => { pay.hidden = !pay.hidden; e.currentTarget.setAttribute("aria-expanded", String(!pay.hidden)); } } }));

  const items = h("ul", { class: "link-list" }, ...g.items.map((it) => {
    const slot = h("div");
    return h("li", {},
      state.byId.has(it.entry_id)
        ? h("a", { href: "#", class: "wikilink", text: it.title, on: { click: (e) => { e.preventDefault(); emit("open", { id: it.entry_id }); } } })
        : h("span", { text: it.title }),
      h("span", { class: "faint mono", title: it.commitment, text: `  v${it.version}  ${short(it.commitment, 8)}` }),
      state.features.previews ? h("button", { class: "link-btn", style: { fontSize: "12.5px" }, text: "Aperçu", on: { click: () => requestPreview(it.entry_id, slot) } }) : null,
      slot);
  }));
  const expired = g.valid_until && new Date(g.valid_until) < new Date();
  return h("div", { class: "card" },
    h("div", { class: "row", style: { justifyContent: "space-between" } },
      h("strong", { style: { fontSize: "15px" }, text: g.licensee }),
      h("span", { class: `badge ${expired ? "badge-warn" : "badge-ok"}`, text: g.valid_until ? `${expired ? "expirée le" : "valable jusqu'au"} ${fmtDate(g.valid_until)}` : "sans échéance" })),
    h("div", { class: "muted", text: g.usage }),
    g.terms ? h("p", { style: { fontSize: "13px" }, text: g.terms }) : null,
    h("div", { style: { fontSize: "13px" } }, royaltyText(g.royalty), g.royalty.note ? `, ${g.royalty.note}` : ""),
    h("div", { class: "faint", style: { fontSize: "12.5px" }, text: `Accordée le ${fmtDateTime(g.created_at)} (registre, séquence ${g.seq}), ${g.items.length} élément${g.items.length > 1 ? "s" : ""}` + (g.bundle_hash ? `, bundle ${short(g.bundle_hash, 10)}` : "") }),
    h("details", { style: { marginTop: "6px" } }, h("summary", { text: "Éléments licenciés" }), items),
    actions, exportSlot, pay);
}

function royaltyForm(g, refresh) {
  const sfx = g.license_id;
  const amount = h("input", { type: "number", step: "0.01", required: true });
  const currency = h("input", { type: "text", value: g.royalty.currency || "EUR", maxlength: "3", pattern: "[A-Z]{3}" });
  const day = h("input", { type: "date", value: new Date().toISOString().slice(0, 10) });
  const period = h("input", { type: "text", maxlength: "40", placeholder: "ex. 2026-T4" });
  const note = h("input", { type: "text", maxlength: "500" });
  const err = h("p", { class: "error", role: "alert" });
  const form = h("form", { class: "card", style: { marginTop: "10px", background: "var(--bg)" } },
    h("div", { class: "grid-2" }, field(`ra-${sfx}`, "Montant", amount), field(`rc-${sfx}`, "Devise", currency),
      field(`rd-${sfx}`, "Reçu le", day), field(`rp-${sfx}`, "Période", period)),
    field(`rn-${sfx}`, "Note", note), err, h("button", { type: "submit", class: "btn btn-primary btn-small", text: "Inscrire au registre" }));
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await post("/api/royalties", { license_id: g.license_id, amount: parseFloat(amount.value), currency: currency.value.trim().toUpperCase(),
        received_on: day.value || null, period: period.value, note: note.value });
      toast("Paiement enregistré.");
      refresh();
    } catch (ex) { if (!ended(ex)) err.textContent = ex.message; }
  });
  return form;
}

function grantForm(refresh) {
  const licensee = h("input", { type: "text", maxlength: "200", required: true });
  const usage = h("input", { type: "text", maxlength: "1000", required: true, placeholder: "ex. publication dans un recueil imprimé" });
  const terms = h("textarea", { maxlength: "20000", rows: "3" });
  const model = h("select", {}, ...Object.entries(MODEL).map(([v, t]) => h("option", { value: v, text: t })));
  const amount = h("input", { type: "number", step: "0.01", min: "0", value: "0" });
  const currency = h("input", { type: "text", value: "EUR", maxlength: "3" });
  const rnote = h("input", { type: "text", maxlength: "500" });
  const until = h("input", { type: "date" });
  const err = h("p", { class: "error", role: "alert" });

  const chosen = h("ul", { class: "link-list" });
  const count = h("span", { class: "muted" });
  const filter = h("input", { type: "search", placeholder: "Filtrer les notes", "aria-label": "Filtrer les notes à licencier" });
  const picker = h("div", { class: "picker", role: "group", "aria-label": "Notes à licencier" });
  const renderChosen = () => {
    clear(chosen);
    for (const id of picked.keys()) {
      chosen.appendChild(h("li", {}, h("span", { text: titleOf(id) }), " ",
        h("button", { type: "button", class: "link-btn", "aria-label": `Retirer ${titleOf(id)} de la licence`, text: "retirer",
          on: { click: () => { picked.delete(id); renderChosen(); renderPicker(); } } })));
    }
    count.textContent = `${picked.size} note${picked.size > 1 ? "s" : ""} choisie${picked.size > 1 ? "s" : ""}`;
  };
  const renderPicker = () => {
    clear(picker);
    const q = filter.value.trim().toLowerCase();
    let folder = null;
    const list = state.entries.filter((e) => !q || e.title.toLowerCase().includes(q) || e.path.toLowerCase().includes(q)).slice(0, 400);
    for (const e of list) {
      const f = e.path.includes("/") ? e.path.slice(0, e.path.lastIndexOf("/")) : "(racine)";
      if (f !== folder) { folder = f; picker.appendChild(h("div", { class: "picker-folder", text: f })); }
      const box = h("input", { type: "checkbox", checked: picked.has(e.entry_id),
        on: { change: () => { if (box.checked) picked.set(e.entry_id, null); else picked.delete(e.entry_id); renderChosen(); } } });
      picker.appendChild(h("label", {}, box, h("span", { text: e.title })));
    }
    if (!list.length) picker.appendChild(h("p", { class: "faint", text: "Aucune note." }));
  };
  filter.addEventListener("input", renderPicker);
  const fromGraph = h("button", { type: "button", class: "btn btn-small", on: { click: () => {
    for (const id of state.graphSelection) if (state.byId.has(id)) picked.set(id, null);
    renderChosen(); renderPicker();
  } } }, `Ajouter la sélection du graphe (${state.graphSelection.size})`);
  renderPicker(); renderChosen();

  const form = h("form", { class: "card" },
    h("div", { class: "grid-2" }, field("lic-who", "Bénéficiaire", licensee), field("lic-until", "Fin de validité", until)),
    field("lic-usage", "Usage autorisé", usage),
    field("lic-terms", "Conditions", terms),
    h("div", { class: "grid-2" }, field("lic-model", "Modèle de redevance", model), field("lic-amount", "Montant ou pourcentage", amount),
      field("lic-cur", "Devise", currency), field("lic-rnote", "Précision sur la redevance", rnote)),
    h("div", { class: "field" }, h("span", { class: "muted", style: { fontSize: "13px" }, text: "Notes licenciées (dernière version de chacune)" }),
      h("div", { class: "row" }, filter, fromGraph), picker, count, chosen),
    h("p", { class: "faint", style: { fontSize: "12.5px" }, text: "Les titres des notes choisies sont communiqués au bénéficiaire ; le texte ne l'est que dans le bundle exporté." }),
    err, h("button", { type: "submit", class: "btn btn-primary", text: "Accorder la licence" }));
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    err.textContent = "";
    if (!licensee.value.trim() || !usage.value.trim()) { err.textContent = "Bénéficiaire et usage sont requis."; return; }
    if (!picked.size) { err.textContent = "Choisissez au moins une note."; return; }
    try {
      await post("/api/licenses", {
        licensee: licensee.value.trim(), usage: usage.value.trim(), terms: terms.value,
        items: [...picked.entries()].map(([entry_id, version]) => ({ entry_id, version })),
        royalty: { model: model.value, amount: parseFloat(amount.value || "0"), currency: currency.value.trim().toUpperCase(), note: rnote.value },
        valid_until: until.value || null,
      });
      picked.clear();
      toast("Licence accordée et inscrite au registre.");
      refresh();
    } catch (ex) { if (!ended(ex)) err.textContent = ex.message; }
  });
  return form;
}
