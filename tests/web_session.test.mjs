import assert from "node:assert/strict";

class Element extends EventTarget {
  children = []; open = false; textContent = "";
  get firstChild() { return this.children[0]; }
  appendChild(child) { this.children.push(child); return child; }
  removeChild(child) { this.children.splice(this.children.indexOf(child), 1); }
  setAttribute() {} focus() {}
  showModal() { this.open = true; }
  close() { this.open = false; setImmediate(() => this.dispatchEvent(new Event("close"))); }
}
globalThis.Node = Element;
const elements = new Map();
globalThis.document = {
  querySelector(selector) {
    if (selector.startsWith("meta")) return { getAttribute: () => "page-token" };
    if (!elements.has(selector)) elements.set(selector, new Element());
    return elements.get(selector);
  },
  createElement: () => new Element(),
  createTextNode: (text) => Object.assign(new Element(), { textContent: text }),
};
const tick = () => new Promise(setImmediate);
const api = await import("../src/empreinte/web/js/api.js");
const { confirmDialog, cancelDialogs, debounce } = await import("../src/empreinte/web/js/dom.js");
const { GraphView } = await import("../src/empreinte/web/js/graph.js");
const { calendarDayIndex } = await import("../src/empreinte/web/js/views/activity.js");

// A fetch implementation may deliver a buffered response even after abort.
let release, oldSignal, lockHeaders;
globalThis.fetch = (path, init) => {
  if (path === "/api/lock") {
    lockHeaders = init.headers;
    assert.equal(init.signal.aborted, false);
    return Promise.resolve({ ok: true, json: async () => ({ locked: true }) });
  }
  oldSignal = init.signal;
  return new Promise((resolve) => { release = resolve; });
};
api.setUnlockToken("session-secret");
let painted = false;
const settled = [];
// A request from a locked session settles with "cancelled" (never left pending), and the
// caller's ended(err) check keeps it from touching the page.
const late = api.get("/api/entries/private/text").then(() => { painted = true; }, (e) => { settled.push(e.code); });
await api.lockSession();
assert.equal(api.hasUnlockToken(), false);
assert.equal(oldSignal.aborted, true);
assert.equal(lockHeaders["X-Empreinte-Unlock"], "session-secret");
release({ ok: true, json: async () => ({ text: "private" }) });
await late;
assert.equal(painted, false, "late plaintext must not reach the reader");
assert.deepEqual(settled, ["cancelled"]);
assert.equal(api.ended(new api.ApiError(0, "cancelled", "x")), true);

// Also invalidate while the response body is still being decoded.
let releaseBody;
globalThis.fetch = async () => ({ ok: true, json: () => new Promise((resolve) => { releaseBody = resolve; }) });
api.setUnlockToken("replacement");
const decoding = api.get("/api/graph").then(() => { painted = true; }, (e) => { settled.push(e.code); });
await tick();
api.invalidate();
releaseBody({ nodes: [{ label: "private" }] });
await decoding;
assert.equal(painted, false);
assert.deepEqual(settled, ["cancelled", "cancelled"]);

// A request rejected because the server restarted settles with an error the unlock form
// can show (review defect 7): nothing waits forever.
globalThis.fetch = async () => ({ ok: false, status: 401, json: async () => ({ error: "bad_token", message: "jeton" }) });
await assert.rejects(api.post("/api/unlock", { passphrase: "x" }), (error) => {
  assert.match(api.authMessage(error), /redémarré/);
  return error.code === "bad_token";
});

// An authentication failure on lock must settle so the unlock screen can recover.
globalThis.fetch = async () => ({ ok: false, status: 401, json: async () => ({ error: "bad_token" }) });
await assert.rejects(api.lockSession(), (error) => error.code === "bad_token");

const abandoned = confirmDialog("Delete old note", "private title");
cancelDialogs();
assert.equal(await abandoned, false);
assert.equal(document.querySelector("#dialog-body").children.length, 0);
const replacement = confirmDialog("New action", "new body");
await tick(); // queued close from the previous dialog must not cancel this one
document.querySelector("#dialog-ok").dispatchEvent(new Event("click"));
assert.equal(await replacement, true);
const closed = confirmDialog("Another action", "body");
document.querySelector("#dialog").close();
assert.equal(await closed, false);

const secret = { label: "private title" };
const graph = { byId: new Map([["x", secret]]), neighbors: new Map([[secret, new Set([secret])]]),
  selection: new Set(["x"]), pointer: { node: secret }, canvas: { classList: { remove() {} } },
  sim: { setData(nodes, links) { assert.deepEqual([nodes, links], [[], []]); } }, draw() {} };
GraphView.prototype.clear.call(graph);
assert.equal(graph.neighbors.size, 0);
assert.equal(graph.byId.size, 0);
assert.equal(graph.pointer, null);

process.env.TZ = "Europe/Paris";
for (const [month, day, index] of [[2, 30, 88], [6, 1, 181], [9, 26, 298]]) {
  const date = new Date(2026, month, day);
  assert.equal(calendarDayIndex(date), index);
  assert.equal((calendarDayIndex(date) + 3) % 7, (date.getDay() + 6) % 7);
}
const { GraphPanel } = await import("../src/empreinte/web/js/graph-panel.js");
let restored = false;
const panelLike = { pending: new Set() };
const pendingSearch = GraphPanel.prototype.later.call(panelLike, () => { restored = true; }, 0);
pendingSearch();
GraphPanel.prototype.cancelPending.call(panelLike);  // A3: done on lock, before wiping
await new Promise((resolve) => setTimeout(resolve, 10));
assert.equal(restored, false);
let saved = false;
const save = debounce(() => { saved = true; }, 0);
save(); save.cancel();
await new Promise((resolve) => setTimeout(resolve, 10));
assert.equal(saved, false);
console.log("web session: all checks passed");
