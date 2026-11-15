// Activité: calendar heatmap, hour by weekday matrix, topics over time. Drawn in SVG.
import { h, s, clear } from "../dom.js";
import { get, qs, ended } from "../api.js";

const CAT = ["#8b6cef", "#3e9ae8", "#46a758", "#f5a524", "#e5484d", "#2ec4b6", "#e54d9a", "#c9a227", "#7d7d7d"];
const HEAT = ["#2a2a2a", "#3d3260", "#59439a", "#7a5cd6", "#a882ff", "#d4c2ff"];
const DAYS = ["Lun", "Mar", "Mer", "Jeu", "Ven", "Sam", "Dim"];
const MONTHS = ["janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août", "sept.", "oct.", "nov.", "déc."];

let basis = "claimed";
let topicMode = "groups";
let metric = "docs";

function level(v, max) {
  if (!v) return 0;
  return Math.min(5, 1 + Math.floor((Math.log(v + 1) / Math.log(max + 1)) * 4.999));
}

function tooltip() {
  let tip = document.querySelector(".chart-tip");
  if (!tip) { tip = h("div", { class: "chart-tip", hidden: true }); document.body.appendChild(tip); }
  return tip;
}

function withTip(node, text) {
  node.appendChild(s("title", {}, text));
  node.addEventListener("pointerenter", (e) => { const t = tooltip(); t.textContent = text; t.hidden = false; t.style.left = `${e.clientX + 12}px`; t.style.top = `${e.clientY + 12}px`; });
  node.addEventListener("pointermove", (e) => { const t = tooltip(); t.style.left = `${e.clientX + 12}px`; t.style.top = `${e.clientY + 12}px`; });
  node.addEventListener("pointerleave", () => { tooltip().hidden = true; });
  return node;
}

function dayKey(d) { return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`; }

// Calendar coordinates must not depend on daylight-saving transitions.
export function calendarDayIndex(d) {
  return Math.round((Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()) - Date.UTC(d.getFullYear(), 0, 1)) / 864e5);
}

function heatmap(days) {
  const byDay = new Map(days.map((d) => [d.day, d]));
  const value = (d) => (metric === "words" ? d.words : d.created + d.updated);
  const max = Math.max(1, ...days.map(value));
  const years = [...new Set(days.map((d) => +d.day.slice(0, 4)))].sort();
  const cell = 11, gap = 2, left = 34, top = 18;
  const wrap = h("div", { class: "chart" });
  for (const year of years) {
    const first = new Date(year, 0, 1);
    const offset = (first.getDay() + 6) % 7;
    const width = left + 54 * (cell + gap);
    const svg = s("svg", { width, height: top + 7 * (cell + gap) + 4, role: "img", "aria-label": `Activité ${year}` });
    svg.appendChild(s("text", { x: 0, y: 11, "font-weight": "600" }, String(year)));
    [0, 2, 4].forEach((r) => svg.appendChild(s("text", { x: 0, y: top + r * (cell + gap) + 9 }, DAYS[r])));
    let total = 0;
    for (let d = new Date(first); d.getFullYear() === year; d.setDate(d.getDate() + 1)) {
      const idx = calendarDayIndex(d) + offset;
      const col = Math.floor(idx / 7), row = idx % 7;
      if (d.getDate() === 1) svg.appendChild(s("text", { x: left + col * (cell + gap), y: 11 }, MONTHS[d.getMonth()]));
      const item = byDay.get(dayKey(d));
      const v = item ? value(item) : 0;
      total += item ? item.created + item.updated : 0;
      const rect = s("rect", { x: left + col * (cell + gap), y: top + row * (cell + gap), width: cell, height: cell, rx: 2, fill: HEAT[level(v, max)] });
      const label = d.toLocaleDateString("fr-FR", { weekday: "long", day: "numeric", month: "long", year: "numeric" });
      withTip(rect, item ? `${label} : ${item.created} créé${item.created > 1 ? "s" : ""}, ${item.updated} modifié${item.updated > 1 ? "s" : ""}, ${item.words} mots` : `${label} : rien`);
      svg.appendChild(rect);
    }
    wrap.append(svg, h("div", { class: "faint", style: { fontSize: "12px", margin: "0 0 10px" }, text: `${total} version${total > 1 ? "s" : ""} en ${year}` }));
  }
  const legend = h("div", { class: "legend" }, "Moins ", ...HEAT.map((c) => h("i", { style: { background: c } })), " Plus");
  wrap.appendChild(legend);
  return wrap;
}

function hourMatrix(grid) {
  const cell = 22, gap = 3, left = 36, top = 18;
  const max = Math.max(1, ...grid.flat());
  const svg = s("svg", { width: left + 24 * (cell + gap), height: top + 7 * (cell + gap), role: "img", "aria-label": "Heures par jour de la semaine" });
  for (let hr = 0; hr < 24; hr += 3) svg.appendChild(s("text", { x: left + hr * (cell + gap), y: 11 }, `${hr} h`));
  grid.forEach((row, r) => {
    svg.appendChild(s("text", { x: 0, y: top + r * (cell + gap) + 15 }, DAYS[r]));
    row.forEach((v, c) => {
      const rect = s("rect", { x: left + c * (cell + gap), y: top + r * (cell + gap), width: cell, height: cell, rx: 3, fill: HEAT[level(v, max)] });
      withTip(rect, `${DAYS[r]} ${c} h : ${v} version${v > 1 ? "s" : ""}`);
      svg.appendChild(rect);
    });
  });
  return h("div", { class: "chart" }, svg);
}

function topics(byMonth) {
  const months = Object.keys(byMonth).sort();
  if (!months.length) return h("p", { class: "faint", text: "Pas de données." });
  // Fill missing months so the time axis is regular.
  const all = [];
  const [y0, m0] = months[0].split("-").map(Number);
  const [y1, m1] = months[months.length - 1].split("-").map(Number);
  for (let y = y0, m = m0; y < y1 || (y === y1 && m <= m1); m === 12 ? (y++, m = 1) : m++) all.push(`${y}-${String(m).padStart(2, "0")}`);
  const totals = new Map();
  for (const mo of months) for (const [k, v] of Object.entries(byMonth[mo])) totals.set(k, (totals.get(k) || 0) + v);
  const top = [...totals.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([k]) => k);
  const series = [...top, "Autres"];
  const stack = all.map((mo) => {
    const row = byMonth[mo] || {};
    const vals = top.map((k) => row[k] || 0);
    const other = Object.entries(row).filter(([k]) => !top.includes(k)).reduce((a, [, v]) => a + v, 0);
    return [...vals, other];
  });
  const max = Math.max(1, ...stack.map((r) => r.reduce((a, b) => a + b, 0)));
  const W = Math.max(640, all.length * 18), H = 220, left = 34, bottom = 22, bw = (W - left) / all.length;
  const svg = s("svg", { width: W, height: H + bottom, role: "img", "aria-label": "Sujets par mois" });
  for (let t = 0; t <= 4; t++) {
    const y = H - (H - 10) * t / 4;
    svg.appendChild(s("line", { x1: left, x2: W, y1: y, y2: y, stroke: "#333", "stroke-width": 1 }));
    svg.appendChild(s("text", { x: 0, y: y + 3 }, String(Math.round(max * t / 4))));
  }
  stack.forEach((row, i) => {
    let y = H;
    row.forEach((v, j) => {
      if (!v) return;
      const hgt = (H - 10) * v / max;
      y -= hgt;
      const rect = s("rect", { x: left + i * bw + 1, y, width: Math.max(1, bw - 2), height: hgt, fill: CAT[j % CAT.length] });
      withTip(rect, `${all[i]} : ${series[j]}, ${v} document${v > 1 ? "s" : ""}`);
      svg.appendChild(rect);
    });
    const [yy, mm] = all[i].split("-");
    if (mm === "01" || (i === 0 && +mm < 11)) svg.appendChild(s("text", { x: left + i * bw, y: H + 15 }, mm === "01" ? yy : `${MONTHS[+mm - 1]} ${yy}`));
  });
  const legend = h("div", { class: "legend" }, ...series.map((name, j) => h("span", {}, h("i", { style: { background: CAT[j % CAT.length] } }), topicMode === "tags" && name !== "Autres" ? `#${name}` : name)));
  return h("div", {}, h("div", { class: "chart" }, svg), legend);
}

function seg(options, current, onPick, label) {
  return h("div", { class: "seg", role: "group", "aria-label": label },
    ...options.map(([value, text]) => h("button", { type: "button", "aria-pressed": String(value === current), text,
      on: { click: () => onPick(value) } })));
}

export async function renderActivity(root) {
  clear(root);
  const inner = h("div", { class: "inner" });
  root.appendChild(inner);
  inner.append(h("h1", { text: "Activité" }), h("p", { class: "lead", text: "Quand l'archive a été écrite, jour par jour, heure par heure, et de quoi elle parlait." }));
  const controls = h("div", { class: "row", style: { marginBottom: "6px" } },
    seg([["claimed", "Dates des fichiers (déclarées)"], ["ledger", "Dates du registre"]], basis, (v) => { basis = v; renderActivity(root); }, "Base de temps"),
    seg([["docs", "Versions"], ["words", "Mots"]], metric, (v) => { metric = v; renderActivity(root); }, "Mesure"));
  const note = h("p", { class: "faint", style: { fontSize: "13px" }, text: basis === "claimed"
    ? "Dates lues sur les fichiers importés quand elles existent, sinon date du registre. Les dates de fichier ne sont que déclarées : elles ne prouvent rien."
    : "Dates du registre : le moment où cette archive a enregistré chaque version. Un import récent apparaît donc en un seul jour." });
  inner.append(controls, note);
  const slot = h("div", {}, h("p", { class: "muted", text: "Calcul..." }));
  inner.appendChild(slot);
  let act;
  try { act = await get(`/api/activity${qs({ basis })}`); } catch (err) { if (!ended(err)) clear(slot).appendChild(h("p", { class: "error", text: err.message })); return; }
  clear(slot);
  slot.append(
    h("h2", { text: "Calendrier" }), heatmap(act.days),
    h("h2", { text: "Heures et jours de la semaine" }), hourMatrix(act.hour_weekday),
    h("div", { class: "row", style: { justifyContent: "space-between", marginTop: "26px" } },
      h("h2", { style: { margin: "0" }, text: "Sujets dans le temps" }),
      seg([["groups", "Dossiers"], ["tags", "Étiquettes"]], topicMode, (v) => { topicMode = v; renderActivity(root); }, "Regrouper par")),
    h("p", { class: "faint", style: { fontSize: "13px" }, text: "Documents touchés par mois, empilés par sujet." }),
    topics(topicMode === "groups" ? act.groups_by_month : act.tags_by_month));
}
