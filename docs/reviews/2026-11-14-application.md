Found 15 actionable defects. The most serious concern is incomplete lock/revocation behavior. I found no demonstrated cross-origin archive-read or stored-XSS exploit.

This was read-only. I ran the supplied Markdown checks and targeted in-memory Node probes; I did not rerun the Python suite.

1. **High — Locking retains the decrypted archive in memory.**  
   **Locations:** `cli.py:125–127`, `server.py:347–357`, `workspace.py:22–28`.  
   `session_for()` retains `state["workspace"]` in its callbacks. Locking clears `App.workspace`, but never clears that reference or the workspace’s full-text index, current texts, historical texts, and mention snippets. After unlocking and locking, a process-memory inspection still exposes the archive indefinitely, until replacement or process exit. This is a live reference, not merely unavoidable garbage-collector residue.  
   **Fix:** Add explicit workspace disposal and session cleanup. Clear plaintext containers and release every session reference on lock.

2. **High — Authentication and session replacement are not atomic with vault operations.**  
   **Locations:** `server.py:583–592`, `server.py:695–712`, `cli.py:125–130`.  
   A request can pass `_check_unlocked()`, pause, then execute after another thread locks and reopens the vault: inside `app.lock`, only `vault is not None` is rechecked, not the token. Thus a revoked token can authorize an operation against the replacement session. Also, `open_vault()` updates the CLI closure’s state outside `app.lock`, while imports/previews may still use it.  
   **Fix:** Check the token/session generation while holding the operation lock. Install callback state atomically with `App` state. Coordinate pending unlocks with explicit locking so an earlier unlock cannot silently reinstall a session after lock completes.

3. **Medium — Pending responses can repopulate the browser after locking.**  
   **Locations:** `web/js/app.js:111–124,185–203`, `web/js/reader.js:66–87`.  
   Start a graph or note request, delay its successful response, then lock. `wipe()` clears the UI but neither increments `graphSeq` nor invalidates reader tokens. The delayed response subsequently restores graph data or decrypted note DOM. Reader tokens only protect against another render, not locking.  
   **Fix:** Introduce a session generation checked after every asynchronous response, invalidate it immediately on lock, and abort pending requests. Clear retained auxiliary state too: `GraphView.clear()` leaves its node-keyed `neighbors` map intact (`graph.js:98`), and the sidebar filter/dialog contents survive wiping.

4. **Medium — An idle lock leaves confirmation handlers armed for a later action.**  
   **Locations:** `web/js/app.js:200–201`, `web/js/dom.js:133–155`.  
   Open “remove note,” let the vault idle-lock, then unlock and confirm a different dialog. Wiping calls `dlg.close()`, but `confirmDialog()` only cleans up on button clicks or `cancel`; programmatic closing does neither. The old confirmation promise can resolve from the new dialog’s OK click, executing the previously abandoned deletion.  
   **Fix:** Resolve confirmations as cancelled on `close` and session invalidation, remove their listeners, and clear dialog contents.

5. **Medium — Every production import reports failure after successfully changing the vault.**  
   **Locations:** `cli.py:76,143`; `importer.py:46–56`.  
   `ImportReport` is a standard dataclass, but both callers invoke `report.model_dump(mode="json")`. A CLI import therefore raises `AttributeError` after committing; browser import returns HTTP 500 after importing and refreshing the workspace. The browser skips its success refresh, leaving users unaware that the operation succeeded. Server tests use a replacement callback returning a dictionary, so they miss this integration defect.  
   **Fix:** Serialize with `dataclasses.asdict()` or make the report a Pydantic model. Exercise the actual `cli.session_for()` import callback in an integration test.

6. **Medium — Unauthenticated connections can exhaust server threads indefinitely.**  
   **Locations:** `server.py:477–483,627,943–945`.  
   Open many connections and send incomplete headers, or send an invalid-token POST with `Content-Length: 100` and withhold the body. `_drain()` blocks before returning the authentication error. There is no socket deadline or connection/thread bound, so even rejected requests can retain threads indefinitely.  
   **Fix:** Apply header/body read deadlines and bounded concurrency. Close rejected requests instead of draining untrusted bodies; close connections on ambiguous framing.

7. **Medium — Any local user can repeatedly lock someone else’s session.**  
   **Locations:** `server.py:400,721–723`.  
   Another local process can GET `/`, extract the page token, forge the accepted Origin header, and POST `/api/lock`. That route deliberately requires no unlock token. Repeating this prevents the legitimate user from working without knowing their passphrase. Browser-origin defenses do not authenticate native local clients.  
   **Fix:** Require the current unlock token to lock an active session. If locked-state idempotence is needed, return success without changing anything when already locked.

8. **Medium — Crafted Markdown freezes the browser through quadratic scanning.**  
   **Locations:** `web/js/markdown.js:211–219,270–304`.  
   A single line containing repeated unmatched `[` characters causes each position to rescan the remaining suffix in `findBracketEnd()`; the wikilink search also repeats. Measured parsing times were approximately **96 ms / 363 ms / 1,526 ms** for **10k / 20k / 40k** characters. The renderer accepts two million characters and runs synchronously, so an imported note can make the interface—including lock controls—unresponsive.  
   **Fix:** Use a linear delimiter parser or precomputed delimiter positions, and enforce a rendering work budget. A length limit alone does not fix quadratic behavior.

9. **Medium — Preview leak checks can accept an entire secret split across keywords.**  
   **Locations:** `previews.py:42–53`.  
   For a lowercase source containing `cobalt velvet falcon meadow copper willow lantern orbit`, a model can return an otherwise generic two-sentence summary and keywords:
   `["cobalt velvet falcon", "meadow copper willow", "lantern orbit"]`.  
   Every keyword has fewer than four words, so all overlap checks are empty; joining the accepted keywords reproduces the eight-word secret. Lowercase personal names also evade the capitalization-only name check. A malicious note can instruct the model to use these forms.  
   **Fix:** Validate the combined disclosure, including cross-field overlap and short distinctive phrases. Treat generated previews as unreviewed drafts requiring approval before public disclosure; these heuristics cannot establish semantic anonymity.

10. **Medium — Demo imports bypass the production importer’s containment protections.**  
    **Locations:** `demo.py:569–580,618–619`.  
    Put `innocent.md` in an import folder as a symlink to a private file outside it. The demo importer follows it through `is_file()`, `stat()`, and `read_bytes()`. The external content becomes accessible in the demo archive, whose default passphrase is publicly known. The pre-read size check is also bypassable by growing/replacing the file.  
    **Fix:** Reuse the hardened importer, including bounded reads and opened-handle verification, or disable real-file imports in demonstration mode.

11. **Medium — Import can archive a torn file under an incorrect source timestamp.**  
    **Locations:** `importer.py:199–217`.  
    The importer captures `fstat()` before reading but never checks the descriptor again afterward. If an editor or other process rewrites the same inode during the read, the imported bytes can combine different file states while retaining the pre-read timestamp. Inode equality only detects replacement, not concurrent modification.  
    **Fix:** Compare descriptor identity, size, and high-resolution modification metadata before and after reading; retry or report unstable files. Use a snapshot or stronger coordination where coherent reads are required.

12. **Medium — Reader wikilinks can open a different document from the graph’s target.**  
    **Locations:** `web/js/state.js:18–38`, `web/js/reader.js:130–135`, `graph.py:59–81`.  
    With `A/Note.md`, `B/Note.md`, and `B/source.md` containing `[[Note]]`, the backend resolves to `B/Note.md`. The browser’s global first-name-wins map resolves to `A/Note.md`; it never receives the source path. I reproduced the browser result. Relative links and Unicode case-folding also differ between implementations.  
    **Fix:** Resolve links centrally with source-path context and return target IDs, or implement identical resolution rules on both sides.

13. **Low — Structured text is searchable but cannot be read.**  
    **Locations:** `web/js/reader.js:125–140`, `parse.py:20–27`.  
    Import JSON, YAML, TOML, XML, or SVG. The workspace recognizes these as text and returns their decoded contents, but the reader only accepts MIME types starting with `text/`; it labels them binary and hides their content. Conversely, plain text and source code are rendered as Markdown, changing their presentation.  
    **Fix:** Share the textual MIME classification. Render Markdown only for Markdown types, and other textual content in escaped preformatted blocks.

14. **Low — Refreshing a historical graph resets the slider without resetting its cutoff.**  
    **Locations:** `web/js/app.js:108,118–124`, `web/js/timeline.js:30–45`.  
    Select an old timeline date, then remove a note. The change handler calls `loadGraph(true)` using the old `untilIso`, then rebuilds the timeline from that filtered graph and moves its slider to “today/all.” The displayed graph remains historical although the control says otherwise.  
    **Fix:** Maintain timeline bounds from the full graph and preserve the selected cutoff, or explicitly clear the cutoff before resetting.

15. **Low — Calendar heatmaps place summer dates in the wrong weekday row.**  
    **Location:** `web/js/views/activity.js:49–52`.  
    The day index divides elapsed local-midnight milliseconds by 24 hours. In Europe/Paris, March 30, 2026 is only 87 days and 23 hours after January 1, so flooring places Monday in Sunday’s row. I reproduced this; July 1 similarly renders as Tuesday instead of Wednesday.  
    **Fix:** Use a calendar-day counter or subtract UTC dates constructed from the local year/month/day components.

Checks that produced no additional finding:

- Default loopback binding, exact Host/port allowlisting, custom page-token headers, Origin checks on mutations, and absent CORS prevent the ordinary hostile-page/DNS-rebinding paths examined. Reading the page token cross-origin was not demonstrated.
- Archive strings reach text nodes or canvas text; Markdown excludes raw HTML/SVG execution, event attributes, and automatically loaded images. The supplied hostile-Markdown checks passed.
- Application-handled responses carry CSP and no-store headers. **This is not universal:** inherited HTTP parser errors and unsupported-method responses bypass `_headers()`.
- Local-model requests pin validated loopback addresses, reject arbitrary DNS names and zone identifiers, disable environment proxies, and refuse redirects.
- The production importer rejects existing symlinks/reparse points, bounds reads, orders files deterministically, and stores its manifest through encrypted auxiliary storage.
- Normal vault operations are serialized; the concurrency finding concerns authentication/session transitions around that serialization.
- A 5,000-node, 10,000-edge simulation remained finite through 100 ticks. Backend timeline filtering follows the stated claimed-date fallback contract, and provenance cards distinguish claimed, locally recorded, and externally anchored dates.