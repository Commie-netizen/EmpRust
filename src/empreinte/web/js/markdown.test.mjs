// Hostile-input tests of the Markdown renderer, run with node by tests/test_server.py.
// Not served by the server (files ending in .test.mjs are excluded).
import { parse, toHTMLString, isSafeHref, ALLOWED_TAGS } from "./markdown.js";

let failures = 0;
function check(name, cond) {
  if (!cond) { failures++; console.log(`FAIL ${name}`); }
}

function walk(tree, fn) {
  for (const n of tree) {
    if (typeof n === "string") continue;
    fn(n);
    walk(n.c || [], fn);
  }
}

function assertSafe(name, md) {
  const tree = parse(md);
  walk(tree, (n) => {
    check(`${name}: tag ${n.t} allowed`, ALLOWED_TAGS.has(n.t));
    for (const [k, v] of Object.entries(n.a || {})) {
      check(`${name}: no event attribute ${k}`, !/^on/i.test(k));
      if (k === "href") check(`${name}: href safe ${v}`, v === "#" || isSafeHref(v));
    }
  });
  const html = toHTMLString(tree);
  check(`${name}: no script tag`, !/<script/i.test(html));
  check(`${name}: no raw img/svg/iframe`, !/<(img|svg|iframe|object|embed|style|link|meta|form)\b/i.test(html));
  check(`${name}: no javascript href`, !/href="\s*(javascript|data|vbscript|file):/i.test(html));
  check(`${name}: no unescaped event handler`, !/<[^>]*\son\w+=/i.test(html.replace(/="[^"]*"/g, '=""')));
  return html;
}

const hostile = [
  ["script", "<script>alert(1)</script>"],
  ["img onerror", '<img src=x onerror="alert(1)">'],
  ["svg onload", "<svg onload=alert(1)>"],
  ["js link", "[clic](javascript:alert(1))"],
  ["js link mixed case", "[clic](JaVaScRiPt:alert(1))"],
  ["js link entity", "[clic](javascript&#58;alert(1))"],
  ["js link tab", "[clic](java\tscript:alert(1))"],
  ["js link newline", "[clic](java\nscript:alert(1))"],
  ["js link spaces", "[clic](   javascript:alert(1))"],
  ["js link control", "[clic](\u0001javascript:alert(1))"],
  ["data link", "[x](data:text/html;base64,PHNjcmlwdD4=)"],
  ["vbscript", "[x](vbscript:msgbox(1))"],
  ["autolink js", "<javascript:alert(1)>"],
  ["wikilink quote", '[[Index" onmouseover="alert(3)]]'],
  ["wikilink html", "[[<img src=x onerror=alert(1)>]]"],
  ["image js", "![x](javascript:alert(1))"],
  ["nested", "**[a](javascript:1)** *<b onclick=x>*"],
  ["table", "| <svg/onload=alert(1)> | b |\n| --- | --- |\n| [x](javascript:1) | <script>1</script> |"],
  ["code", "```html\n<script>alert(1)</script>\n```"],
  ["code lang", "```\" onload=\"x\n1\n```"],
  ["quote", "> <iframe src=javascript:alert(1)>"],
  ["list", "- [x](javascript:1)\n  - <script>2</script>"],
  ["deep nesting", ">".repeat(500) + " x"],
  ["deep emphasis", "*".repeat(2000) + "x" + "*".repeat(2000)],
  ["brackets", "[".repeat(3000) + "x" + "](".repeat(1000)],
  ["html comment", "<!-- <script>x</script> -->"],
  ["style", "<style>body{display:none}</style>"],
  ["front matter", "---\ntitle: <script>1</script>\n---\ntext"],
];
for (const [name, md] of hostile) assertSafe(name, md);

// The hostile text must survive as visible text.
check("script kept as text", toHTMLString(parse("<script>alert(1)</script>")).includes("&lt;script&gt;alert(1)&lt;/script&gt;"));
check("js link becomes text", !toHTMLString(parse("[clic](javascript:alert(1))")).includes("<a"));

// Features still work.
const ok = toHTMLString(parse([
  "# Titre", "", "Du **gras**, de l'*italique*, du ~~barré~~ et du `code`.", "",
  "- un", "- deux [[Cible|alias]]", "", "1. premier", "2. second", "",
  "> citation", "", "| a | b |", "| :-- | --: |", "| 1 | 2 |", "",
  "[lien](https://exemple.org) <https://exemple.org/x> #étiquette ![[schema.png]] [rel](autre%20note.md)",
  "", "- [x] fait", "- [ ] à faire",
].join("\n")));
check("h1", ok.includes("<h1>Titre</h1>"));
check("strong", ok.includes("<strong>gras</strong>"));
check("em", ok.includes("<em>italique</em>"));
check("del", ok.includes("<del>barré</del>"));
check("code", ok.includes("<code>code</code>"));
check("ul", ok.includes("<ul><li>un</li>"));
check("ol", ok.includes("<ol><li>premier</li>"));
check("wikilink alias", ok.includes('data-target="Cible"') && ok.includes(">alias</a>"));
check("blockquote", ok.includes("<blockquote><p>citation</p></blockquote>"));
check("table", ok.includes("<table><thead><tr><th class=\"al-left\">a</th>"));
check("external link", ok.includes('href="https://exemple.org"'));
check("autolink", ok.includes('href="https://exemple.org/x"'));
check("tag", ok.includes('<span class="md-tag">#étiquette</span>'));
check("embed", ok.includes('class="wikilink embed"'));
check("relative md link", ok.includes('data-target="autre note.md"'));
const heading = toHTMLString(parse("## Titre ##\n# Fin #   \n# C#\n# x ###"));
check("closing hashes stripped", heading.includes("<h2>Titre</h2>") && heading.includes("<h1>Fin</h1>"));
check("hash inside a word kept", heading.includes("<h1>C#</h1>"));
check("wikilink target without heading", toHTMLString(parse("[[Note#Partie|vue]]")).includes('data-target="Note"'));
check("relative link to any file", toHTMLString(parse("[pdf](docs/a%20b.pdf#p2)")).includes('data-target="docs/a b.pdf"'));
check("task", ok.includes('<li class="task"><input type="checkbox" disabled="" checked="">fait'));
check("safe href helper", isSafeHref("https://a.b") && !isSafeHref("javascript:x") && !isSafeHref(" javascript:x") && isSafeHref("mailto:a@b.c"));

// Linear time (review finding 8): 200,000 characters of pathological input each parse
// well under a generous bound; the old parser took seconds on 40,000 characters.
const N = 200000;
const slow = [
  ["unmatched [", "[".repeat(N)],
  ["unmatched [[", "[[".repeat(N / 2)],
  ["unmatched ![[", "![[".repeat(N / 3)],
  ["stars", "*".repeat(N)],
  ["star then space", "*a ".repeat(N / 3)],
  ["underscores", "_a ".repeat(N / 3)],
  ["backticks", "`".repeat(N)],
  ["backtick pairs", "`` ` ".repeat(N / 5)],
  ["open links", "[a](".repeat(N / 4)],
  ["open images", "![a](".repeat(N / 5)],
  ["autolink starts", "<".repeat(N)],
  ["nested quotes", ">".repeat(N) + " x"],
  ["quote lines", "> > > x\n".repeat(N / 8)],
  ["tildes", "~~a ".repeat(N / 4)],
  ["heading of hashes", "# " + "#".repeat(N) + "x"],
  ["heading closing hashes", "# a" + " #".repeat(N / 2)],
  ["table separator spaces", "a | b\n" + " ".repeat(N) + "x"],
  ["list indentation", " ".repeat(N) + "- x"],
  ["thematic break", "- ".repeat(N / 2) + "x"],
  ["fences", "```\n".repeat(N / 4)],
  ["front matter", "---\n" + "a\n".repeat(N / 2)],
];
for (const [name, md] of slow) {
  const t0 = Date.now();
  const tree = parse(md);
  const ms = Date.now() - t0;
  check(`${name}: ${ms} ms`, ms < 1500);
  check(`${name}: text kept`, toHTMLString(tree).length > 0);
}

if (failures) { console.log(`${failures} failure(s)`); process.exit(1); }
console.log("markdown: all checks passed");
