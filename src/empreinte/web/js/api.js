// JSON client of the local server. The page token comes from a meta tag of index.html;
// the unlock token lives only in this module's memory and dies with a reload or a lock.
//
// Session generation: every request remembers the generation it started in. Locking
// (button, idle lock reported by the server, any 401 "locked") calls invalidate(), which
// bumps the generation and aborts every pending fetch. A request that belongs to an
// older generation settles with ApiError code "cancelled"; a 401 "locked" or "bad_token"
// settles with that error after the lock listeners ran. Every caller checks ended(err)
// first in its catch and returns without touching the page: a late answer can never put
// archive data, or an error about it, back into a page that was wiped. Nothing is left
// pending forever, so a form waiting on a request (the unlock form) always recovers.

const pageToken = document.querySelector('meta[name="empreinte-token"]').getAttribute("content");
let unlockToken = null;
let generation = 0;
let controller = new AbortController();
const lockListeners = new Set();

export class ApiError extends Error {
  constructor(status, code, message, retryAfter = null) {
    super(message);
    this.status = status;
    this.code = code;
    this.retryAfter = retryAfter;
  }
}

export function onLocked(fn) { lockListeners.add(fn); }
export function setUnlockToken(token) { unlockToken = token; }
export function hasUnlockToken() { return unlockToken !== null; }
export function currentGeneration() { return generation; }

/** Forget the session: bump the generation, abort pending requests, drop the token. */
export function invalidate() {
  generation += 1;
  unlockToken = null;
  controller.abort();
  controller = new AbortController();
}

const RESTARTED = "Le serveur local a redémarré : rechargez la page.";

function cancelled() { return new ApiError(0, "cancelled", "Requête annulée : la session a été verrouillée."); }

/** True when the error only means the session ended (lock, idle lock, server restart):
 * the caller must stop silently, the lock handling already reset the page. */
export function ended(err) {
  return err instanceof ApiError && (err.code === "cancelled" || err.code === "locked" || err.code === "bad_token");
}

/** A message for the unlock and creation forms. */
export function authMessage(err) {
  if (err instanceof ApiError && err.code === "bad_token") return RESTARTED;
  if (err instanceof ApiError && err.code === "cancelled") return "Requête annulée, réessayez.";
  return err.message;
}

export async function call(method, path, body = undefined, token = unlockToken) {
  const started = generation;
  const headers = { "X-Empreinte-Token": pageToken, Accept: "application/json" };
  if (token) headers["X-Empreinte-Unlock"] = token;
  const init = { method, headers, credentials: "omit", cache: "no-store", redirect: "error",
    referrerPolicy: "no-referrer", signal: controller.signal };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(path, init);
  } catch {
    if (started !== generation) throw cancelled();
    throw new ApiError(0, "network", "Le serveur local ne répond pas.");
  }
  let data = null;
  try { data = await res.json(); } catch { data = null; }
  if (started !== generation) throw cancelled();
  if (!res.ok) {
    const code = (data && data.error) || "http";
    const message = (data && data.message) || `Erreur ${res.status}`;
    const err = new ApiError(res.status, code, message, data && data.retry_after);
    if (res.status === 401 && (code === "locked" || code === "bad_token")) {
      for (const fn of lockListeners) fn(err);
    }
    throw err;
  }
  return data;
}

export const get = (path) => call("GET", path);
export const post = (path, body = {}) => call("POST", path, body);
export const put = (path, body = {}) => call("PUT", path, body);

// Revoke browser work immediately, but authenticate the server lock with the old token.
export function lockSession() {
  const token = unlockToken;
  invalidate();
  return call("POST", "/api/lock", {}, token);
}

/** Build a query string from defined values. */
export function qs(params) {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== "") sp.set(k, String(v));
  const s = sp.toString();
  return s ? `?${s}` : "";
}
