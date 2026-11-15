// Licences: grants, creating one, exporting the bundle, the royalty register, previews.
import { h, clear, fmtDate, fmtDateTime, fmtMoney, short, toast } from "../dom.js";
import { get, post, ended } from "../api.js";
import { state, emit, titleOf } from "../state.js";
import { requestPreview } from "../reader.js";

const MODEL = { none: "sans redevance", flat: "forfait", per_use: "par utilisation", revenue_share: "partage de revenus" };
const picked = new Map(); // entry_id -> version (null = latest)

function royaltyText(r) {
  if (r.model === "none") return "Sans redevance";
  if (r.model === "revenue_share") return `Partage de revenus : ${String(r.amount).replace(".", ",")} % (${r.currency})`;
  if (r.model === "per_use") return `Par utilisation : ${fmtMoney(r.amount, r.currency)}`;
  return `Forfait : ${fmtMoney(r.amount, r.currency)}`;
}

function field(id, label, input) { input.id = id; return h("div", { class: "field" }, h("label", { for: id, text: label }), input); }

export function resetLicenses() { picked.clear(); }

export async function renderLicenses(root) {
  clear(root);
  const inner = h("div", { class: "inner" });
  root.appendChild(inner);
  inner.append(h("h1", { text: "Licences" }),
    h("p", { class: "lead", text: "Céder un droit d'usage note par note, avec la preuve de date de chaque version attachée. Chaque licence et chaque paiement reçu sont inscrits au registre." }));
  const listSlot = h("div");
  const royaltySlot = h("div");
  inner.append(h("h2", { text: "Licences accordées" }), listSlot, h("h2", { text: "Registre des redevances" }), royaltySlot,
    h("h2", { text: "Nouvelle licence" }), grantForm(() => renderLicenses(root)));

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
