// Closing audit A3 / defect 6: a lock during the page's initialisation stops it.
import assert from "node:assert/strict";

class Element extends EventTarget {
  children = []; textContent = ""; attrs = {}; style = {}; dataset = {}; isConnected = true;
  get firstChild() { return this.children[0]; }
  appendChild(child) { this.children.push(child); return child; }
  removeChild(child) { this.children.splice(this.children.indexOf(child), 1); }
  setAttribute(k, v) { this.attrs[k] = v; }
  text() { return this.textContent + this.children.map((c) => c.text()).join(" "); }
}
globalThis.Node = Element;
globalThis.document = {
  querySelector: () => ({ getAttribute: () => "page-token" }),
  createElement: () => new Element(),
  createTextNode: (text) => Object.assign(new Element(), { textContent: text }),
};
const api = await import("../src/empreinte/web/js/api.js");
const { readPrefs, runInitialisation } = await import("../src/empreinte/web/js/startup.js");

// readPrefs passes a cancellation on instead of answering "no preferences".
const cancelled = new api.ApiError(0, "cancelled", "annulée");
await assert.rejects(readPrefs(async () => { throw cancelled; }), (e) => e === cancelled);
assert.deepEqual(await readPrefs(async () => { throw new api.ApiError(500, "internal", "x"); }), {});
assert.deepEqual(await readPrefs(async () => ({ graph: { a: 1 } })), { graph: { a: 1 } });

// A lock while a step is waiting: the following steps and finish never run.
const done = [];
let finished = false;
const errors = [];
const ok = await runInitialisation([
  async () => { done.push("prefs"); },
  async () => { api.invalidate(); throw cancelled; },  // the owner locks during loadEntries
  async () => { done.push("graph"); },
], () => { finished = true; }, (e) => errors.push(e));
assert.equal(ok, false);
assert.deepEqual(done, ["prefs"]);
assert.equal(finished, false, "no poller or watch footer after a lock");
assert.deepEqual(errors, []);

// A step that resolves although the generation changed meanwhile (a request that
// returned early): stopped as well.
finished = false;
const second = await runInitialisation([
  async () => { api.invalidate(); },
  async () => { done.push("late"); },
], () => { finished = true; }, () => {});
assert.equal(second, false);
assert.equal(finished, false);
assert.ok(!done.includes("late"));

// An ordinary error is reported once; the session is still current, so finish runs.
const reported = [];
finished = false;
const third = await runInitialisation([
  async () => { throw new api.ApiError(500, "internal", "panne"); },
  async () => { done.push("skipped"); },
], () => { finished = true; }, (e) => reported.push(e.message));
assert.equal(third, true);
assert.deepEqual(reported, ["panne"]);
assert.equal(finished, true);
assert.ok(!done.includes("skipped"));

// Review finding 4: the Registre coverage card follows each status answer.
const { showCoverageIn, updateCoverage, resetCoverage } = await import("../src/empreinte/web/js/views/ledger.js");
const slot = new Element();
showCoverageIn(slot);
updateCoverage({ n_records: 3, covered_upto: 2, uncovered: 0, oldest_uncovered_at: null, claimed_upto: -1 });
assert.match(slot.text(), /Tout est couvert/);
updateCoverage({ n_records: 5, covered_upto: 2, uncovered: 2, oldest_uncovered_at: "2026-11-15T10:00:00Z", claimed_upto: -1 });
assert.doesNotMatch(slot.text(), /Tout est couvert/);
assert.match(slot.text(), /2 non couverts/);
resetCoverage();
updateCoverage({ n_records: 5, covered_upto: 4, uncovered: 0, oldest_uncovered_at: null, claimed_upto: -1 });
assert.match(slot.text(), /2 non couverts/, "a card no longer shown is not repainted");
console.log("web init: all checks passed");
