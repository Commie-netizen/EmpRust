// Entering the application after an unlock: a sequence of requests that a lock can
// interrupt at any point. Kept apart from app.js so the rule can be tested on its own:
// once the session generation changes, or a step ends because of a lock, nothing more
// of the sequence runs (no control changed, no poller started, no folder list painted).
import { currentGeneration, ended } from "./api.js";

/** The stored interface preferences. A cancellation (the page was locked while they
 * were read) is passed on so the caller stops; any other failure means "none stored". */
export async function readPrefs(get) {
  try {
    const prefs = await get("/api/prefs");
    return prefs && typeof prefs === "object" ? prefs : {};
  } catch (err) {
    if (ended(err)) throw err;
    return {};
  }
}

/** Run `steps` in order, then `finish` (watch footer, status poller). Stops silently as
 * soon as the session generation differs from the one at the start or a step ended with
 * a lock; returns whether the sequence completed. Any other error goes to `onError`, the
 * remaining steps are skipped and `finish` still runs for the current session. */
export async function runInitialisation(steps, finish, onError) {
  const started = currentGeneration();
  const current = () => currentGeneration() === started;
  for (const step of steps) {
    try {
      await step();
    } catch (err) {
      if (ended(err) || !current()) return false;
      onError(err);
      break;
    }
    if (!current()) return false;
  }
  if (!current()) return false;
  finish();
  return true;
}
