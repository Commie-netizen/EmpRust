// Unlock and creation screens. The passphrase only ever travels in a POST body.
import { h, clear, $ } from "./dom.js";
import { post, setUnlockToken, authMessage } from "./api.js";

/** Rough strength estimate in bits, with a French hint. */
export function strength(pass) {
  if (!pass) return { bits: 0, label: "", color: "transparent" };
  let pool = 0;
  if (/[a-z]/.test(pass)) pool += 26;
  if (/[A-Z]/.test(pass)) pool += 26;
  if (/\d/.test(pass)) pool += 10;
  if (/[^A-Za-z0-9]/.test(pass)) pool += 33;
  const unique = new Set(pass).size;
  let bits = Math.log2(Math.max(pool, 2)) * Math.min(pass.length, unique * 2.5);
  const words = pass.trim().split(/[\s\-_.]+/).filter((w) => w.length >= 3).length;
  if (words >= 4) bits = Math.max(bits, words * 11);
  if (/^(.)\1+$/.test(pass) || /^(0123|1234|azerty|qwerty|password|motdepasse)/i.test(pass)) bits = Math.min(bits, 10);
  if (bits < 40) return { bits, label: "Faible : ajoutez des mots, une phrase de passe de 4 ou 5 mots est idéale.", color: "#ff6b70", pct: 20 };
  if (bits < 60) return { bits, label: "Moyenne : encore un ou deux mots.", color: "#e8b931", pct: 50 };
  if (bits < 80) return { bits, label: "Bonne.", color: "#5ad681", pct: 78 };
  return { bits, label: "Très bonne.", color: "#5ad681", pct: 100 };
}

function passField(id, label, autocomplete) {
  const input = h("input", { type: "password", id, autocomplete, required: true, spellcheck: "false", maxlength: "1024" });
  const show = h("button", { type: "button", class: "link-btn", "aria-controls": id, "aria-pressed": "false", text: "Afficher",
    on: { click: () => {
      const visible = input.type === "password";
      input.type = visible ? "text" : "password";
      show.textContent = visible ? "Masquer" : "Afficher";
      show.setAttribute("aria-pressed", String(visible));
    } } });
  return { input, el: h("div", { class: "field" }, h("label", { for: id, text: label }), h("div", { class: "pass-wrap" }, input, show)) };
}

let countdown = null;

export function showAuth(status, { onUnlocked, message } = {}) {
  $("#app").hidden = true;
  $("#auth").hidden = false;
  const body = clear($("#auth-body"));
  if (status.exists) renderUnlock(body, status, onUnlocked, message);
  else renderCreate(body, onUnlocked);
}

function renderUnlock(body, status, onUnlocked, message) {
  const pass = passField("pass", "Phrase de passe", "current-password");
  const err = h("p", { class: "error", role: "alert", "aria-live": "assertive" });
  const submit = h("button", { type: "submit", class: "btn btn-primary", style: { width: "100%" }, text: "Déverrouiller" });
  const form = h("form", { novalidate: true }, pass.el, err, submit);
  if (message) err.textContent = message;

  const wait = (seconds) => {
    clearInterval(countdown);
    let left = Math.ceil(seconds);
    submit.disabled = true;
    const tick = () => {
      if (left <= 0) { clearInterval(countdown); submit.disabled = false; err.textContent = ""; return; }
      err.textContent = `Trop d'essais. Nouvel essai possible dans ${left} s.`;
      left--;
    };
    tick();
    countdown = setInterval(tick, 1000);
  };
  if (status.retry_after > 0) wait(status.retry_after);

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!pass.input.value) { err.textContent = "Saisissez la phrase de passe."; pass.input.focus(); return; }
    submit.disabled = true;
    submit.textContent = "Déverrouillage...";
    try {
      const res = await post("/api/unlock", { passphrase: pass.input.value });
      pass.input.value = "";
      setUnlockToken(res.unlock_token);
      onUnlocked();
    } catch (ex) {
      submit.textContent = "Déverrouiller";
      submit.disabled = false;
      pass.input.select();
      if (ex.code === "rate_limited") wait(ex.retryAfter || 5);
      else if (ex.code === "wrong_passphrase") {
        err.textContent = "Phrase de passe incorrecte.";
        if (ex.retryAfter) wait(ex.retryAfter);
      } else err.textContent = authMessage(ex);
    }
  });
  body.append(form);
  if (status.demo) body.append(h("p", { class: "demo-hint", text: "Mode démonstration : données fictives en mémoire, phrase de passe « demo »." }));
  pass.input.focus();
}

function renderCreate(body, onUnlocked) {
  const pass = passField("new-pass", "Nouvelle phrase de passe", "new-password");
  const again = passField("new-pass-2", "Confirmez la phrase de passe", "new-password");
  const meter = h("span");
  const hint = h("p", { class: "faint", id: "pass-hint", style: { fontSize: "13px", margin: "4px 0 10px" }, "aria-live": "polite" });
  pass.input.setAttribute("aria-describedby", "pass-hint");
  const err = h("p", { class: "error", role: "alert" });
  const submit = h("button", { type: "submit", class: "btn btn-primary", style: { width: "100%" }, text: "Créer l'archive" });
  pass.input.addEventListener("input", () => {
    const s = strength(pass.input.value);
    meter.style.width = `${s.pct || 0}%`;
    meter.style.background = s.color;
    hint.textContent = s.label;
  });
  const form = h("form", { novalidate: true },
    h("p", { class: "muted", text: "Aucune archive n'existe encore sur cette machine. Choisissez une phrase de passe : elle chiffre tout, et personne ne peut la récupérer pour vous." }),
    pass.el, h("div", { class: "strength", "aria-hidden": "true" }, meter), hint, again.el, err, submit);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const p = pass.input.value;
    if (p.length < 10) { err.textContent = "Au moins 10 caractères."; return; }
    if (strength(p).bits < 40) { err.textContent = "Phrase de passe trop faible."; return; }
    if (p !== again.input.value) { err.textContent = "Les deux saisies diffèrent."; return; }
    submit.disabled = true;
    try {
      const res = await post("/api/create", { passphrase: p });
      pass.input.value = ""; again.input.value = "";
      setUnlockToken(res.unlock_token);
      renderRecovery(body, res.recovery_key, onUnlocked);
    } catch (ex) {
      submit.disabled = false;
      err.textContent = authMessage(ex);
    }
  });
  body.append(form);
  pass.input.focus();
}

function renderRecovery(body, key, onUnlocked) {
  clear(body);
  const check = h("input", { type: "checkbox", id: "rk-ok" });
  const go = h("button", { class: "btn btn-primary", disabled: true, style: { width: "100%" }, text: "J'ai noté la clé, ouvrir l'archive",
    on: { click: () => { clear(body); onUnlocked(); } } });
  check.addEventListener("change", () => { go.disabled = !check.checked; });
  body.append(
    h("h2", { style: { fontSize: "17px", margin: "0 0 8px" }, text: "Clé de récupération" }),
    h("p", { class: "muted", text: "Elle remplace la phrase de passe si vous l'oubliez. Elle n'est affichée qu'une seule fois, maintenant." }),
    h("div", { class: "recovery-key", tabindex: "0", "aria-label": "Clé de récupération", text: key }),
    h("div", { class: "warning", role: "note" },
      h("strong", { text: "Attention. " }),
      "Recopiez cette clé sur papier et rangez-la loin de cet ordinateur. Si vous perdez à la fois la phrase de passe et la clé de récupération, l'archive est perdue : personne, pas même nous, ne pourra la déchiffrer."),
    h("div", { class: "row", style: { marginBottom: "12px" } }, check, h("label", { for: "rk-ok", text: "J'ai recopié la clé de récupération en lieu sûr." })),
    go);
}
