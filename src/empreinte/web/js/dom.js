// DOM helpers. Text always goes through text nodes; no innerHTML anywhere in this app.

const SVG_NS = "http://www.w3.org/2000/svg";

/** Create an element. attrs: class, text, on: {event: fn}, dataset, any attribute. */
export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  applyAttrs(el, attrs);
  append(el, children);
  return el;
}

/** Create an SVG element with attributes. */
export function s(tag, attrs = {}, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  applyAttrs(el, attrs);
  append(el, children);
  return el;
}

function applyAttrs(el, attrs) {
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") el.setAttribute("class", value);
    else if (key === "text") el.textContent = String(value);
    else if (key === "on") for (const [ev, fn] of Object.entries(value)) el.addEventListener(ev, fn);
    else if (key === "dataset") Object.assign(el.dataset, value);
    else if (key === "style") Object.assign(el.style, value);
    else if (key === "value") el.value = value;
    else if (key === "checked") el.checked = !!value;
    else if (key.startsWith("on")) throw new Error("use the on: {} form for events");
    else el.setAttribute(key, value === true ? "" : String(value));
  }
}

export function append(el, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}

export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

export function $(sel, root = document) { return root.querySelector(sel); }

// ------------------------------------------------------------------- icons
// Simple stroked paths on a 24 by 24 grid.
const ICONS = {
  graph: "M6 6m-2.2 0a2.2 2.2 0 1 0 4.4 0a2.2 2.2 0 1 0-4.4 0M18 7m-2.2 0a2.2 2.2 0 1 0 4.4 0a2.2 2.2 0 1 0-4.4 0M12 18m-2.6 0a2.6 2.6 0 1 0 5.2 0a2.6 2.6 0 1 0-5.2 0M7.4 7.7 10.6 15.8M16.6 8.8 13.4 15.8M8.2 6.3 15.8 6.8",
  reading: "M4 5.5C6.5 4.5 9.5 4.5 12 6c2.5-1.5 5.5-1.5 8-.5V19c-2.5-1-5.5-1-8 .5-2.5-1.5-5.5-1.5-8-.5zM12 6v13.5",
  activity: "M4 4h16v16H4zM4 9h16M9 4v16M14 9v11M4 14.5h16",
  search: "M10.5 10.5m-6 0a6 6 0 1 0 12 0a6 6 0 1 0-12 0M15 15l5 5",
  ledger: "M6 3h12v18H6zM9 7h6M9 11h6M9 15h4",
  licenses: "M7 3h7l4 4v14H7zM14 3v4h4M10 13l2 2 4-4",
  lock: "M6 11h12v9H6zM8.5 11V8a3.5 3.5 0 0 1 7 0v3",
  folder: "M3.5 6.5h6l2 2h9v10h-17z",
  sidebar: "M4 5h16v14H4zM9 5v14",
  collapse: "M7 9l5-5 5 5M7 15l5 5 5-5",
  chevron: "M6 9l6 6 6-6",
  close: "M6 6l12 12M18 6 6 18",
  play: "M8 5v14l11-7z",
  pause: "M8 5v14M16 5v14",
  expand: "M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5",
  gear: "M12 12m-3 0a3 3 0 1 0 6 0a3 3 0 1 0-6 0M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M5.6 18.4l2.1-2.1M16.3 7.7l2.1-2.1",
  reset: "M4 12a8 8 0 1 0 2.3-5.7M4 4v4h4",
  trash: "M5 7h14M10 7V4h4v3M7 7l1 13h8l1-13",
};

export function icon(name, cls = "") {
  return s("svg", { viewBox: "0 0 24 24", "aria-hidden": "true", focusable: "false", class: cls },
    s("path", { d: ICONS[name] || "" }));
}

// ---------------------------------------------------------------- formatting
const dtf = new Intl.DateTimeFormat("fr-FR", { dateStyle: "medium", timeStyle: "short" });
const df = new Intl.DateTimeFormat("fr-FR", { dateStyle: "medium" });
const dfl = new Intl.DateTimeFormat("fr-FR", { day: "numeric", month: "long", year: "numeric" });

export function fmtDateTime(iso) { return iso ? dtf.format(new Date(iso)) : ""; }
export function fmtDate(iso) { return iso ? df.format(new Date(iso)) : ""; }
export function fmtDateLong(d) { return dfl.format(d instanceof Date ? d : new Date(d)); }
export function fmtBytes(n) {
  if (n < 1024) return `${n} o`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1).replace(".", ",")} Ko`;
  return `${(n / 1024 / 1024).toFixed(1).replace(".", ",")} Mo`;
}
export function fmtMoney(amount, currency) {
  try { return new Intl.NumberFormat("fr-FR", { style: "currency", currency }).format(amount); }
  catch { return `${amount} ${currency}`; }
}
export function short(hex, n = 10) {
  if (!hex) return "";
  return hex.length > n + 4 ? `${hex.slice(0, n)}…${hex.slice(-4)}` : hex;
}

/** Append text to el, wrapping case-insensitive matches of any term in <mark>. */
export function highlight(el, text, terms) {
  const words = terms.filter((t) => t.length > 0).map((t) => t.toLowerCase());
  if (!words.length) { el.appendChild(document.createTextNode(text)); return el; }
  const low = text.toLowerCase();
  let i = 0;
  while (i < text.length) {
    let best = -1, len = 0;
    for (const w of words) {
      const at = low.indexOf(w, i);
      if (at >= 0 && (best < 0 || at < best)) { best = at; len = w.length; }
    }
    if (best < 0) { el.appendChild(document.createTextNode(text.slice(i))); break; }
    if (best > i) el.appendChild(document.createTextNode(text.slice(i, best)));
    el.appendChild(h("mark", { text: text.slice(best, best + len) }));
    i = best + len;
  }
  return el;
}

// ------------------------------------------------------------- toast, dialog
let toastTimer = null;
export function toast(message, bad = false) {
  const el = $("#toast");
  el.textContent = message;
  el.classList.toggle("bad", bad);
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, bad ? 6000 : 3500);
}

// The confirmation currently open, if any: cancelDialogs() settles it as cancelled.
let openConfirm = null;

/** Modal confirmation. body: string or Node. Resolves true only on an explicit OK click;
 * Escape, Annuler, any close of the dialog and cancelDialogs() resolve false. */
export function confirmDialog(title, body, { ok = "Confirmer", danger = false } = {}) {
  if (openConfirm) openConfirm(false);
  const dlg = $("#dialog");
  $("#dialog-title").textContent = title;
  const bodyEl = clear($("#dialog-body"));
  append(bodyEl, [typeof body === "string" ? h("p", { text: body }) : body]);
  const okBtn = $("#dialog-ok");
  const cancelBtn = $("#dialog-cancel");
  okBtn.textContent = ok;
  okBtn.className = danger ? "btn btn-danger" : "btn btn-primary";
  return new Promise((resolve) => {
    let settled = false;
    const done = (value) => {
      if (settled) return;
      settled = true;
      openConfirm = null;
      okBtn.removeEventListener("click", onOk);
      cancelBtn.removeEventListener("click", onCancel);
      dlg.removeEventListener("cancel", onCancel);
      dlg.removeEventListener("close", onClose);
      if (dlg.open) dlg.close();
      resolve(value);
    };
    const onOk = () => done(true);
    const onCancel = (e) => { if (e) e.preventDefault(); done(false); };
    // A previous dialog's queued close event may arrive after a new showModal().
    const onClose = () => { if (!dlg.open) done(false); };
    openConfirm = done;
    okBtn.addEventListener("click", onOk);
    cancelBtn.addEventListener("click", onCancel);
    dlg.addEventListener("cancel", onCancel);
    dlg.addEventListener("close", onClose);
    dlg.showModal();
    cancelBtn.focus();
  });
}

/** Settle any open confirmation as cancelled and empty the dialog (called on lock). */
export function cancelDialogs() {
  if (openConfirm) openConfirm(false);
  const dlg = $("#dialog");
  if (dlg.open) dlg.close();
  $("#dialog-title").textContent = "";
  clear($("#dialog-body"));
}

/** Debounce a function. */
export function debounce(fn, ms) {
  let t = null;
  const run = (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
  run.cancel = () => { clearTimeout(t); t = null; };
  return run;
}
