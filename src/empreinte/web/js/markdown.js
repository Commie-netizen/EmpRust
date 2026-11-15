// A small Markdown renderer written for hostile input.
//
// parse(text) turns Markdown into a tree of plain objects {t, a, c} and strings, without
// touching the DOM. Raw HTML is never interpreted: it stays text. render(tree) builds
// DOM nodes from that tree through a whitelist of tags, attributes and classes, with
// text set as text nodes. Links are kept only for http, https and mailto; anything
// else (javascript:, data:, vbscript:, file:...) becomes plain text.

const MAX_DEPTH = 12;
const MAX_INPUT = 2_000_000;

export const ALLOWED_TAGS = new Set([
  "h1", "h2", "h3", "h4", "h5", "h6", "p", "em", "strong", "del", "code", "pre", "ul", "ol", "li",
  "blockquote", "table", "thead", "tbody", "tr", "th", "td", "a", "hr", "br", "span", "input",
]);
const ALLOWED_ATTRS = {
  a: new Set(["href", "class", "title", "data-target", "rel", "target"]),
  span: new Set(["class", "title"]),
  code: new Set(["class"]),
  li: new Set(["class"]),
  ol: new Set(["start"]),
  th: new Set(["class"]),
  td: new Set(["class"]),
  input: new Set(["type", "checked", "disabled"]),
};
const ALLOWED_CLASSES = /^(wikilink|embed|md-tag|blocked-link|external|task|image-alt|al-left|al-center|al-right|lang-[a-z0-9_+-]{1,20})$/;

/** True when href is an http(s) or mailto URL once control characters and spaces are removed. */
export function isSafeHref(href) {
  if (typeof href !== "string" || href.length > 2048) return false;
  const squeezed = href.replace(/[\u0000-\u0020\u007f-\u009f\u00ad\u200b-\u200f\u2028\u2029\ufeff]/g, "").toLowerCase();
  return /^(https?:\/\/[^\s]|mailto:[^\s])/.test(squeezed) && href.trim() === href.trim().replace(/[\u0000-\u001f]/g, "");
}

const el = (t, a, c) => ({ t, a: a || {}, c: c || [] });

// ------------------------------------------------------------------- blocks

const RE_FENCE = /^ {0,3}(`{3,}|~{3,})\s*([\w+-]*)[^\n]*$/;
// Only the prefix is matched by a regular expression; the closing hashes are removed by
// stripClosing() in one backward pass (the old lazy pattern was quadratic on "# ####...").
const RE_HEADING = /^ {0,3}(#{1,6})(?:[ \t]+(.*)|[ \t]*)$/;
const RE_HR = /^ {0,3}([-*_])(?:[ \t]*\1){2,}[ \t]*$/;
const RE_QUOTE = /^ {0,3}> ?(.*)$/;
const RE_LIST = /^( *)([-*+]|\d{1,9}[.)])[ \t]+(.*)$/;
const RE_SEP_CELL = /^:?-+:?$/;

/** A table separator row such as "| :-- | --: |", checked cell by cell (linear). */
function isTableSep(line) {
  if (line === undefined || !line.includes("-")) return false;
  let s = line.trim();
  if (s.startsWith("|")) s = s.slice(1);
  if (s.endsWith("|")) s = s.slice(0, -1);
  if (!s) return false;
  return s.split("|").every((cell) => RE_SEP_CELL.test(cell.trim()));
}

const isBlank = (ch) => ch === " " || ch === "\t";

/** Heading text without its optional closing "#" sequence. */
function stripClosing(text) {
  let end = text.length;
  while (end > 0 && isBlank(text[end - 1])) end--;
  let k = end;
  while (k > 0 && text[k - 1] === "#") k--;
  if (k < end && (k === 0 || isBlank(text[k - 1]))) {
    end = k;
    while (end > 0 && isBlank(text[end - 1])) end--;
  }
  return text.slice(0, end);
}

function isBlockStart(line, next) {
  return RE_FENCE.test(line) || RE_HEADING.test(line) || RE_HR.test(line) || RE_QUOTE.test(line) ||
    RE_LIST.test(line) || (line.includes("|") && isTableSep(next));
}

function splitRow(line) {
  let s = line.trim();
  if (s.startsWith("|")) s = s.slice(1);
  if (s.endsWith("|") && !s.endsWith("\\|")) s = s.slice(0, -1);
  const cells = [];
  let cur = "";
  for (let i = 0; i < s.length; i++) {
    if (s[i] === "\\" && s[i + 1] === "|") { cur += "|"; i++; continue; }
    if (s[i] === "|") { cells.push(cur.trim()); cur = ""; continue; }
    cur += s[i];
  }
  cells.push(cur.trim());
  return cells;
}

function parseBlocks(lines, depth) {
  const out = [];
  if (depth > MAX_DEPTH) {
    out.push(el("p", {}, [lines.join("\n")]));
    return out;
  }
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (/^\s*$/.test(line)) { i++; continue; }

    let m = RE_FENCE.exec(line);
    if (m) {
      const fence = m[1];
      const lang = (m[2] || "").toLowerCase();
      const body = [];
      i++;
      while (i < lines.length && !new RegExp(`^ {0,3}${fence[0]}{${fence.length},}\\s*$`).test(lines[i])) body.push(lines[i++]);
      i++;
      const attrs = /^[a-z0-9_+-]{1,20}$/.test(lang) ? { class: `lang-${lang}` } : {};
      out.push(el("pre", {}, [el("code", attrs, [body.join("\n")])]));
      continue;
    }
    m = RE_HEADING.exec(line);
    if (m) {
      out.push(el(`h${m[1].length}`, {}, parseInline(stripClosing(m[2] || ""), depth)));
      i++;
      continue;
    }
    if (RE_HR.test(line)) { out.push(el("hr")); i++; continue; }
    if (RE_QUOTE.test(line)) {
      const inner = [];
      while (i < lines.length && RE_QUOTE.test(lines[i])) inner.push(RE_QUOTE.exec(lines[i++])[1]);
      out.push(el("blockquote", {}, parseBlocks(inner, depth + 1)));
      continue;
    }
    if (line.includes("|") && i + 1 < lines.length && isTableSep(lines[i + 1])) {
      const header = splitRow(line);
      const aligns = splitRow(lines[i + 1]).map((c) => {
        const l = c.startsWith(":"), r = c.endsWith(":");
        return l && r ? "al-center" : r ? "al-right" : l ? "al-left" : null;
      });
      i += 2;
      const rows = [];
      while (i < lines.length && lines[i].includes("|") && !/^\s*$/.test(lines[i])) rows.push(splitRow(lines[i++]));
      const cell = (tag, text, k) => el(tag, aligns[k] ? { class: aligns[k] } : {}, parseInline(text, depth));
      out.push(el("table", {}, [
        el("thead", {}, [el("tr", {}, header.map((c, k) => cell("th", c, k)))]),
        el("tbody", {}, rows.map((r) => el("tr", {}, header.map((_, k) => cell("td", r[k] || "", k))))),
      ]));
      continue;
    }
    m = RE_LIST.exec(line);
    if (m) {
      const baseIndent = m[1].length;
      const ordered = /\d/.test(m[2]);
      const items = [];
      while (i < lines.length) {
        const lm = RE_LIST.exec(lines[i]);
        if (!lm || lm[1].length !== baseIndent || /\d/.test(lm[2]) !== ordered) break;
        const body = [lm[3]];
        i++;
        while (i < lines.length) {
          const next = lines[i];
          if (/^\s*$/.test(next)) {
            if (i + 1 < lines.length && /^\s+\S/.test(lines[i + 1]) && (lines[i + 1].length - lines[i + 1].trimStart().length) > baseIndent) {
              body.push(""); i++; continue;
            }
            break;
          }
          const indent = next.length - next.trimStart().length;
          if (indent > baseIndent) { body.push(next.slice(Math.min(indent, baseIndent + 2))); i++; continue; }
          if (RE_LIST.test(next) || isBlockStart(next, lines[i + 1])) break;
          body.push(next); i++;
        }
        items.push(body);
      }
      const listAttrs = {};
      if (ordered) {
        const start = parseInt(m[2], 10);
        if (start !== 1 && Number.isFinite(start)) listAttrs.start = String(start);
      }
      out.push(el(ordered ? "ol" : "ul", listAttrs, items.map((body) => listItem(body, depth))));
      continue;
    }
    // Paragraph: consecutive lines until a blank line or another block.
    const para = [line];
    i++;
    while (i < lines.length && !/^\s*$/.test(lines[i]) && !isBlockStart(lines[i], lines[i + 1])) para.push(lines[i++]);
    out.push(el("p", {}, parseInline(para.join("\n"), depth)));
  }
  return out;
}

function listItem(body, depth) {
  let first = body[0];
  const task = /^\[([ xX])\][ \t]+/.exec(first);
  const children = [];
  const attrs = {};
  if (task) {
    attrs.class = "task";
    children.push(el("input", { type: "checkbox", disabled: "", ...(task[1] !== " " ? { checked: "" } : {}) }));
    first = first.slice(task[0].length);
  }
  const rest = body.slice(1);
  if (rest.length && rest.some((l) => RE_LIST.test(l) || RE_FENCE.test(l) || RE_QUOTE.test(l))) {
    const split = rest.findIndex((l) => RE_LIST.test(l) || RE_FENCE.test(l) || RE_QUOTE.test(l));
    children.push(...parseInline([first, ...rest.slice(0, split)].join("\n"), depth));
    children.push(...parseBlocks(rest.slice(split), depth + 1));
  } else {
    children.push(...parseInline([first, ...rest].join("\n").trim(), depth));
  }
  return el("li", attrs, children);
}

// ------------------------------------------------------------------- inline
//
// Linear scanning: every delimiter position is found once, in scan(), before the inline
// loop runs; the loop then looks matches up in O(1) or by binary search. Nothing rescans
// the rest of the text per character. A global work budget (set by parse) is a second
// safety net: past it, the remaining text is kept as plain text.

const ESCAPABLE = "\\`*_{}[]()#+-.!|~<>\"'";
const RE_AUTOLINK = /<((?:https?:\/\/|mailto:)[^\s<>]{1,2000})>/iy;
const RE_BARE_URL = /https?:\/\/[^\s<>"')\]]{1,2000}/iy;
const RE_TAG = /#([A-Za-z\u00c0-\u024f][\w\-/\u00c0-\u024f]{0,80})/y;
const EMPHASIS = ["**", "__", "~~", "*", "_"];

let budget = Infinity;

/** First element of a sorted list that is >= value. The scan position only moves
 * forward, so each list keeps a cursor that only moves forward: amortised O(1). */
function nextFrom(cursors, key, list, value) {
  let k = cursors.get(key) || 0;
  while (k < list.length && list[k] < value) k++;
  cursors.set(key, k);
  return k < list.length ? list[k] : -1;
}

/** One pass over the text: matching brackets and parentheses, "]]" and newline
 * look-ahead, backtick runs by length, emphasis closers by delimiter. */
function scan(text) {
  const n = text.length;
  const escaped = new Uint8Array(n + 1);
  const bracketClose = new Int32Array(n).fill(-1);
  const parenClose = new Int32Array(n).fill(-1);
  const brackets = [], parens = [];
  for (let i = 0; i < n; i++) {
    const c = text[i];
    if (c === "\\" && i + 1 < n) { escaped[i + 1] = 1; i++; continue; }
    if (c === "[") brackets.push(i);
    else if (c === "]" && brackets.length) bracketClose[brackets.pop()] = i;
    else if (c === "(") parens.push(i);
    else if (c === ")" && parens.length) parenClose[parens.pop()] = i;
    else if (c === "\n") parens.length = 0;
  }
  const nextDouble = new Int32Array(n + 1).fill(-1);
  const nextNl = new Int32Array(n + 1).fill(-1);
  let nd = -1, nl = -1;
  for (let i = n - 1; i >= 0; i--) {
    if (text[i] === "]" && text[i + 1] === "]") nd = i;
    if (text[i] === "\n") nl = i;
    nextDouble[i] = nd;
    nextNl[i] = nl;
  }
  const runs = new Map(); // backtick run length -> sorted start positions
  for (let i = 0; i < n;) {
    if (text[i] !== "`" || escaped[i]) { i++; continue; }
    let j = i;
    while (text[j] === "`") j++;
    const len = j - i;
    if (!runs.has(len)) runs.set(len, []);
    runs.get(len).push(i);
    i = j;
  }
  const closers = new Map(EMPHASIS.map((d) => [d, []]));
  for (let i = 1; i < n; i++) {
    if (escaped[i] || /\s/.test(text[i - 1])) continue;
    for (const d of EMPHASIS) if (text.startsWith(d, i)) closers.get(d).push(i);
  }
  return { escaped, bracketClose, parenClose, nextDouble, nextNl, runs, closers, cursors: new Map() };
}

function closerAfter(info, delim, start) {
  return nextFrom(info.cursors, delim, info.closers.get(delim), start + 1);
}

function linkNode(label, rawUrl, depth) {
  let url = rawUrl.trim();
  const titleMatch = /^(\S+)\s+"[^"]*"$/.exec(url);
  if (titleMatch) url = titleMatch[1];
  if (url.startsWith("<") && url.endsWith(">")) url = url.slice(1, -1);
  const children = parseInline(label, depth + 1);
  if (isSafeHref(url)) {
    return el("a", { href: url, class: "external", rel: "noopener noreferrer nofollow", target: "_blank", title: url }, children);
  }
  if (!/^[a-z][a-z0-9+.-]*:/i.test(url) && !url.startsWith("//")) {
    let target = url.split(/[?#]/)[0];
    try { target = decodeURIComponent(target); } catch { /* keep raw */ }
    if (target) return el("a", { href: "#", class: "wikilink", "data-target": target, title: target }, children);
  }
  return el("span", { class: "blocked-link", title: "lien non suivi" }, children);
}

export function parseInline(text, depth = 0) {
  const out = [];
  if (depth > MAX_DEPTH || budget <= 0) { out.push(text); return out; }
  const info = scan(text);
  budget -= text.length;
  let buf = "";
  const flush = () => { if (buf) { out.push(buf); buf = ""; } };
  let i = 0;
  while (i < text.length) {
    if (--budget < 0) { buf += text.slice(i); break; }
    const ch = text[i];
    // Backslash escapes and hard breaks.
    if (ch === "\\") {
      if (text[i + 1] === "\n") { flush(); out.push(el("br")); i += 2; continue; }
      if (i + 1 < text.length && ESCAPABLE.includes(text[i + 1])) { buf += text[i + 1]; i += 2; continue; }
    }
    if (ch === "\n") { flush(); out.push(el("br")); i++; continue; }
    // Code span: the next backtick run of the same length.
    if (ch === "`") {
      let n = 1;
      while (text[i + n] === "`") n++;
      const end = nextFrom(info.cursors, `run${n}`, info.runs.get(n) || [], i + n);
      if (end > 0) {
        flush();
        out.push(el("code", {}, [text.slice(i + n, end).replace(/\n/g, " ")]));
        i = end + n;
        continue;
      }
      buf += text.slice(i, i + n); i += n; continue;
    }
    // Wikilinks and embeds.
    if ((ch === "[" && text[i + 1] === "[") || (ch === "!" && text[i + 1] === "[" && text[i + 2] === "[")) {
      const embed = ch === "!";
      const open = i + (embed ? 3 : 2);
      const close = open <= text.length ? info.nextDouble[open] : -1;
      const nl = open <= text.length ? info.nextNl[open] : -1;
      if (close > open && close - open < 400 && (nl < 0 || nl > close)) {
        const inner = text.slice(open, close);
        const bar = inner.indexOf("|");
        const targetPart = bar >= 0 ? inner.slice(0, bar) : inner;
        const target = targetPart.split("#")[0].trim();
        const label = (bar >= 0 ? inner.slice(bar + 1) : targetPart.split("#")[0]).trim() || target;
        flush();
        out.push(el("a", { href: "#", class: embed ? "wikilink embed" : "wikilink", "data-target": target, title: target }, [label]));
        i = close + 2;
        continue;
      }
    }
    // Images: never loaded, shown as their alternative text.
    if (ch === "!" && text[i + 1] === "[") {
      const close = info.bracketClose[i + 1];
      if (close > 0 && text[close + 1] === "(") {
        const end = info.parenClose[close + 1];
        if (end > 0 && end - close < 2100) {
          flush();
          out.push(el("span", { class: "image-alt", title: "image non chargée" }, [`[image : ${text.slice(i + 2, close)}]`]));
          i = end + 1;
          continue;
        }
      }
    }
    // Links.
    if (ch === "[" && !info.escaped[i]) {
      const close = info.bracketClose[i];
      if (close > 0 && text[close + 1] === "(") {
        const end = info.parenClose[close + 1];
        if (end > 0 && end - close < 2100) {
          flush();
          out.push(linkNode(text.slice(i + 1, close), text.slice(close + 2, end), depth));
          i = end + 1;
          continue;
        }
      }
    }
    // Autolinks <https://...>.
    if (ch === "<") {
      RE_AUTOLINK.lastIndex = i;
      const m = RE_AUTOLINK.exec(text);
      if (m) { flush(); out.push(linkNode(m[1], m[1], depth)); i += m[0].length; continue; }
    }
    // Bare URLs.
    if ((ch === "h" || ch === "H") && (i === 0 || /[\s(]/.test(text[i - 1]))) {
      RE_BARE_URL.lastIndex = i;
      const m = RE_BARE_URL.exec(text);
      if (m) {
        const url = m[0].replace(/[.,;:!?]+$/, "");
        flush();
        out.push(linkNode(url, url, depth));
        i += url.length;
        continue;
      }
    }
    // Tags.
    if (ch === "#" && (i === 0 || /[\s(]/.test(text[i - 1]))) {
      RE_TAG.lastIndex = i;
      const m = RE_TAG.exec(text);
      if (m) { flush(); out.push(el("span", { class: "md-tag" }, [m[0]])); i += m[0].length; continue; }
    }
    // Emphasis: the first valid closer after the opener, looked up, never searched.
    const two = text.slice(i, i + 2);
    if ((two === "**" || two === "__" || two === "~~") && !info.escaped[i]) {
      const end = closerAfter(info, two, i + 2);
      if (end > i + 2 && !/\s/.test(text[i + 2])) {
        flush();
        out.push(el(two === "~~" ? "del" : "strong", {}, parseInline(text.slice(i + 2, end), depth + 1)));
        i = end + 2;
        continue;
      }
    }
    if ((ch === "*" || ch === "_") && !info.escaped[i] && text[i + 1] !== ch && i + 1 < text.length && !/\s/.test(text[i + 1])) {
      const wordBefore = ch === "_" && i > 0 && /\w/.test(text[i - 1]);
      const end = wordBefore ? -1 : closerAfter(info, ch, i + 1);
      if (end > i + 1 && !(ch === "_" && /\w/.test(text[end + 1] || ""))) {
        flush();
        out.push(el("em", {}, parseInline(text.slice(i + 1, end), depth + 1)));
        i = end + 1;
        continue;
      }
    }
    buf += ch;
    i++;
  }
  flush();
  return out;
}

/** Markdown text to a tree of {t, a, c} nodes and strings. Pure, no DOM. */
export function parse(text) {
  let src = String(text ?? "");
  if (src.length > MAX_INPUT) src = src.slice(0, MAX_INPUT);
  src = src.replace(/\r\n?/g, "\n").replace(/\t/g, "    ").replace(/\u0000/g, "\ufffd");
  // YAML front matter is hidden from the reading view.
  src = src.replace(/^---\n[\s\S]*?\n---\n/, "");
  budget = 60 * src.length + 100000;
  return parseBlocks(src.split("\n"), 0);
}

// ------------------------------------------------------------------- output

function safeAttrs(tag, attrs) {
  const allowed = ALLOWED_ATTRS[tag] || new Set();
  const outAttrs = {};
  for (const [key, value] of Object.entries(attrs || {})) {
    if (!allowed.has(key) || typeof value !== "string") continue;
    if (key === "href" && !(value === "#" || isSafeHref(value))) continue;
    if (key === "class" && !value.split(" ").every((c) => ALLOWED_CLASSES.test(c))) continue;
    if (key === "type" && value !== "checkbox") continue;
    if (key === "start" && !/^\d{1,9}$/.test(value)) continue;
    if (key === "target" && value !== "_blank") continue;
    outAttrs[key] = value;
  }
  return outAttrs;
}

/** Walk a tree with a builder; used by render (DOM) and by the tests (strings). */
export function build(tree, builder) {
  const visit = (node) => {
    if (typeof node === "string") return builder.text(node);
    if (!node || !ALLOWED_TAGS.has(node.t)) return builder.text("");
    const attrs = safeAttrs(node.t, node.a);
    const children = (node.c || []).map(visit);
    return builder.element(node.t, attrs, children);
  };
  return tree.map(visit);
}

/** Render Markdown into a DocumentFragment.
 * options.resolve(target) -> entry id or null (the server's link_targets map: the browser
 * never resolves a link itself); options.onWikilink(id, event). An unresolved link becomes
 * plain dimmed text, not a link. */
export function render(text, options = {}) {
  const frag = document.createDocumentFragment();
  const builder = {
    text: (t) => document.createTextNode(t),
    element: (tag, attrs, children) => {
      const target = tag === "a" ? attrs["data-target"] : undefined;
      let id = null;
      if (target !== undefined) id = options.resolve ? options.resolve(target) : null;
      const unresolved = target !== undefined && !id;
      const node = document.createElement(unresolved ? "span" : tag);
      for (const [k, v] of Object.entries(attrs)) {
        if (unresolved && (k === "href" || k === "data-target")) continue;
        node.setAttribute(k, v);
      }
      if (unresolved) {
        node.classList.add("unresolved");
        node.setAttribute("title", "absent de l'archive");
      }
      for (const c of children) node.appendChild(c);
      if (id) node.addEventListener("click", (e) => { e.preventDefault(); if (options.onWikilink) options.onWikilink(id, e); });
      return node;
    },
  };
  for (const n of build(parse(text), builder)) frag.appendChild(n);
  return frag;
}

/** Serialise a tree as escaped HTML text (tests only; the app never uses it). */
export function toHTMLString(tree) {
  const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  const builder = {
    text: (t) => esc(t),
    element: (tag, attrs, children) => {
      const a = Object.entries(attrs).map(([k, v]) => ` ${k}="${esc(v)}"`).join("");
      return tag === "br" || tag === "hr" || tag === "input" ? `<${tag}${a}>` : `<${tag}${a}>${children.join("")}</${tag}>`;
    },
  };
  return build(tree, builder).join("");
}
