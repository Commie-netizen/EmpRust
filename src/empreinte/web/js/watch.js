// Continuous capture: the watched folders in the sidebar footer, from /api/status.
// Paths are shown through textContent only; adding or removing a folder never removes
// anything from the archive.
import { h, $, clear, toast, confirmDialog, fmtDateTime } from "./dom.js";
import { post, ended } from "./api.js";

let lastCaptures = null;
let onCapture = () => {};
let enabled = false;

/** `fn` runs when the server reports captures made since the last summary seen. */
export function onCaptured(fn) { onCapture = fn; }

export function resetWatch() {
  lastCaptures = null;
  enabled = false;
  clear($("#watch-list"));
  $("#watch-last").textContent = "";
  $("#watch").hidden = true;
}

function baseName(path) {
  const parts = String(path).split(/[\\/]+/).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : String(path);
}

/** Show a watch summary ({folders, captures, last_capture, pending, quiet, last_error}). */
export function renderWatch(summary, featureOn) {
  enabled = !!featureOn && !!summary;
  const box = $("#watch");
  box.hidden = !enabled;
  if (!enabled) return;
  const list = clear($("#watch-list"));
  for (const f of summary.folders) {
    const name = baseName(f.path) + (f.prefix ? `  (${f.prefix}/)` : "");
    list.appendChild(h("li", {},
      h("span", { class: "watch-path", title: f.path, text: name }),
      f.error ? h("span", { class: "watch-error", title: f.error, text: "illisible" }) : null,
      h("button", { class: "link-btn", "aria-label": `Ne plus suivre ${f.path}`, text: "retirer",
        on: { click: () => removeFolder(f.path) } })));
  }
  let text;
  if (!summary.folders.length) text = "Aucun dossier suivi.";
  else if (summary.last_capture) text = `Dernière capture : ${fmtDateTime(summary.last_capture)}`;
  else text = "Aucune capture depuis l'ouverture.";
  if (summary.pending) text += ` ${summary.pending} fichier${summary.pending > 1 ? "s" : ""} en attente de ${Math.round(summary.quiet)} s sans modification.`;
  $("#watch-last").textContent = text;
  $("#watch-last").title = summary.last_error || "";
  if (lastCaptures !== null && summary.captures > lastCaptures) onCapture();
  lastCaptures = summary.captures;
}

async function addFolder() {
  const path = h("input", { type: "text", id: "watch-path", placeholder: "C:\\Users\\vous\\Documents\\Notes", spellcheck: "false" });
  const prefix = h("input", { type: "text", id: "watch-prefix", maxlength: "200", spellcheck: "false" });
  const ok = await confirmDialog("Suivre un dossier", h("div", {},
    h("p", { class: "muted", text: "Tant que l'archive est déverrouillée, chaque fichier créé ou modifié dans ce dossier est chiffré dans l'archive dès qu'il n'a plus changé pendant une minute. Un fichier supprimé ou renommé ne retire rien de l'archive." }),
    h("label", { for: "watch-path", text: "Dossier (chemin absolu)" }), path,
    h("label", { for: "watch-prefix", text: "Ranger sous le dossier logique (facultatif)" }), prefix), { ok: "Suivre" });
  if (!ok || !path.value.trim()) return;
  try {
    const res = await post("/api/watch", { action: "add", path: path.value.trim(), prefix: prefix.value.trim() });
    renderWatch(res, true);
    toast("Dossier suivi.");
  } catch (err) { if (!ended(err)) toast(err.message, true); }
}

async function removeFolder(path) {
  const ok = await confirmDialog("Ne plus suivre ce dossier ?", h("div", {},
    h("p", { class: "mono", text: path }),
    h("p", { class: "muted", text: "Rien n'est retiré de l'archive : les versions déjà capturées restent dans le registre." })), { ok: "Ne plus suivre" });
  if (!ok) return;
  try {
    renderWatch(await post("/api/watch", { action: "remove", path }), true);
  } catch (err) { if (!ended(err)) toast(err.message, true); }
}

$("#watch-add").addEventListener("click", addFolder);
