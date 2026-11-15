**The audit is not closed.** Both JavaScript suites pass; I did not rerun the 283 Python tests. Python was unavailable and WSL access was denied. Concurrent watcher edits appeared during inspection; references below reflect the last-read working tree, not a frozen release. No files changed by me.

Paths below are under `src/empreinte/` unless otherwise stated.

**Part 1 — previous findings**

| Item | Status | Evidence / remaining concrete scenario |
|---|---|---|
| N5 | FIXED | `store.py:126,175`; `vault.py:633`: OS-held exclusion and disk-head checks. Independently synced machines still require the documented single-writer workflow. |
| N8 | FIXED | `vault.py:675`; `store.py:219`; `docs/FORMAT.md:265`: directory syncing and prefix-commit semantics agree. |
| N10 | PARTIAL | `vault.py:356,554`: with a lagging catalog and deleted anchors, recovery rewrites `n_anchors` before validation. First opening detects deletion; reopening can forget it and permit writes. |
| N11 | PARTIAL | `tools/verify_bundle.py:703,715`: replace the bundle root with a symlink before opening; the subsequent `realpath(bundle)` follows the replacement, allowing its external files. The root identity is not pinned. |
| N12 | PARTIAL | `vault.py:518,1257`: replace a small header/anchors file with a huge file between `stat()` and `read_bytes()`; the actual read remains unbounded. Proof decoding is now bounded. |
| N15 | FIXED | `docs/FORMAT.md:342`: explicitly specifies the raw head digest, without rehashing. |
| A2 | PARTIAL | `server.py:1008–1009`: manual lock between `do_lock()` returning and the generation snapshot is absorbed; the pending unlock can subsequently install. |
| A3 | PARTIAL | `web/js/app.js:166,208`: debounces are cancelled, but cancelled initialization still changes controls and, with the newly added watcher, can repopulate private folder information after wiping. |
| A6 | FIXED | `server.py:634,701`: socket reads use the remaining absolute deadline, including unfinished header lines. |
| A8 | PARTIAL | `web/js/markdown.js:141`: heading matching is repaired, but wide tables with short rows amplify quadratically; 5,599 input characters produced 640,000 cells in my probe. |
| A9 | PARTIAL | `previews.py:43,78`: a CJK sentence is one token and can be copied whole; splitting `cobalt` into `co-balt` similarly defeats exact-token overlap. Short numeric secrets also escape. |
| A11 | PARTIAL | `importer.py:197–206`: two matching reads improve detection but do not guarantee a snapshot; coordinated rewrites can yield identical mixed bytes on both passes while restoring size/mtime. |
| A12 | FIXED | `web/js/reader.js:132`: the `.md` fallback is gone; unresolved targets cannot open a guessed entry. |
| a | FIXED | `vault.py:964,1072`; `web/js/reader.js:56`: verification and provenance carry per-anchor trust states and select the supporting authenticated anchor. |
| b | FIXED | `web/js/views/ledger.js:41`: choices come from reported capabilities. |
| c | PARTIAL | `server.py:1052`; `web/js/reader.js:221`: historical text receives the latest version’s map; a link present only in v1 becomes “absent” when viewing v1. |
| d | FIXED | `server.py:450,515`: stopped applications reject and dispose pending installations; normal close paths release the vault. |
| e | FIXED | `web/js/graph.js:32,101`: virtual-node behavior uses `node_type`. |
| f | FIXED | `server.py:1273`; `web/js/reader.js:106`: approval compares the exact displayed preview digest. |
| g | PARTIAL | `web/js/reader.js:15` still renders `text/x-markdown`; `web/js/markdown.js:141` still permits table amplification. Group colours, legend, fitting and wording were corrected. |
| h | FIXED | `vault.py:871,1112`; `store.py:126`: auxiliary writes require ownership; anchor completion rechecks ownership and the ledger. |
| j | PARTIAL | `server.py:934`: a 5,000-digit `Content-Length` passes `isdigit()` but raises an uncaught integer-conversion error, producing no structured response. The 417 security-header path is fixed. |
| Previous defect 1 | FIXED | `store.py:126,175`: no unlink-based stale-lock reclamation. |
| Previous defect 2 | FIXED | `server.py:450,515`: shutdown prevents later installation. |
| Previous defect 3 | FIXED | `server.py:1008`: replacement releases the old writer before opening another instance. |
| Previous defect 4 | FIXED | `vault.py:871,695`: readers cannot write auxiliary values or flush replayed catalogs. |
| Previous defect 5 | FIXED | `server.py:1273`: stale approval digests are rejected. |
| Previous defect 6 | FIXED | `previews.py:81`; `server.py:1235`: permutation enumeration is removed; generation runs outside the operation lock. |
| Previous defect 7 | FIXED | `web/js/api.js:72,85`; `web/js/auth.js:77`: cancellation/authentication errors settle and restore the authentication form. |
| Previous defect 8 | FIXED | `pyproject.toml:7`; `docs/FORMAT.md:454`: cryptography minimum is 49. |
| Previous defect 9 | FIXED | `web/js/reader.js:57–62`: trusted attribution comes from the authenticated supporting anchor. |

**Part 2 — defects in the changed paths, ranked**

1. **High — Opening a vault can truncate an unrelated file.** [store.py:126](C:/Users/sawle/OneDrive/Desktop/ChargeGrinder/Empreinte/src/empreinte/store.py:126), `:134`. Make `writer.lock` a symlink to another writable file: acquisition follows it, locks it, then truncates it to informational JSON. **Fix:** reject links/reparse points and validate the opened regular-file handle before modifying it.

2. **High — Successful manual locking can be undone by an already pending unlock.** [server.py:1008](C:/Users/sawle/OneDrive/Desktop/ChargeGrinder/Empreinte/src/empreinte/server.py:1008). Lock in the gap before `seen = app.generation`; installation accepts the newer generation. An unlock queued on `auth_lock` can similarly start after cancellation. **Fix:** register authentication attempts before waiting and atomically coordinate their generation with session replacement.

3. **Medium — Deferred previews overwrite newer state.** [server.py:1239](C:/Users/sawle/OneDrive/Desktop/ChargeGrinder/Empreinte/src/empreinte/server.py:1239). Start generation for v1, import v2, generate/approve v2, then let v1 finish: it overwrites the newer preview and returns `current: true`. **Fix:** compare document commitment and previous preview digest at commit; reject stale jobs and calculate `current` from storage.

4. **Medium — Incorrect authentication now terminates another client’s session.** [server.py:1008](C:/Users/sawle/OneDrive/Desktop/ChargeGrinder/Empreinte/src/empreinte/server.py:1008). A second page submits a wrong passphrase; the existing session is closed before authentication, without its unlock token. **Fix:** authenticate first, then perform an exclusive writer handoff.

5. **Medium — Lock acquisition is not exception-safe.** [store.py:132](C:/Users/sawle/OneDrive/Desktop/ChargeGrinder/Empreinte/src/empreinte/store.py:132). If informational writing/flushing fails after acquiring the OS lock, the handle is neither registered nor explicitly closed. Retaining the exception traceback retains the lock; subsequent opens become read-only. **Fix:** close on every failure until ownership has been transferred to `self._handle`.

6. **Medium — Cancellation continuations still mutate the wiped page.** [app.js:166](C:/Users/sawle/OneDrive/Desktop/ChargeGrinder/Empreinte/src/empreinte/web/js/app.js:166), `:208`. Cancel initialization: `loadPrefs()` swallows cancellation, and `enterApp()` continues after its catch. My extracted-function probes observed control mutations and a recreated poller; current watcher code additionally repaints the previous private folder summary. **Fix:** propagate cancellation and return immediately; guard the whole initialization sequence by generation.

7. **Medium — Valid anchoring eventually makes the archive unreadable for writing.** [vault.py:1121](C:/Users/sawle/OneDrive/Desktop/ChargeGrinder/Empreinte/src/empreinte/vault.py:1121), `:518`. Successful appends can grow `anchors.jsonl` beyond 16 MiB; reopening then refuses to read those valid anchors and enters integrity read-only mode. **Fix:** enforce a compatible write limit or stream bounded individual records.

8. **Medium — The window check rejects ordinary topic summaries.** [previews.py:82](C:/Users/sawle/OneDrive/Desktop/ChargeGrinder/Empreinte/src/empreinte/previews.py:82). A document containing `research research research research` rejects any teaser mentioning “research” once: set membership falsely satisfies all four occurrences. Long repetitive documents amplify this. **Fix:** account for multiplicity/distinctiveness and use script-aware overlap checks; accent folding alone does not solve CJK or inserted punctuation.

9. **Low — Historical links disappear after removing browser fallback.** [reader.js:221](C:/Users/sawle/OneDrive/Desktop/ChargeGrinder/Empreinte/src/empreinte/web/js/reader.js:221). View v1 containing `[[Target]]` after v2 removed that link: the latest map lacks it despite Target existing. **Fix:** return canonical targets for the requested text version.

Direct `Vault.anchor()` interleavings with `put`, `lock`, `close`, and another successful anchor are sound: appends retain the captured ancestor, closure prevents storage, and completions serialize. HTTP anchoring nevertheless retains the server operation lock during networking (`server.py:892`).

The graph performs no per-frame text measurement; fitting still allocates and sorts, but my 2,000-node Node probe averaged **0.13 ms/fit**, not a browser rendering benchmark. Endpoint changes invalidate preview cache entries (`context.py:14`); changed weights at the same endpoint/model still require explicit forcing.

**Part 3**

Fix the destructive lock-file path, session races, recovery evidence loss, and stale preview commits before entrusting important originals.  
Then freeze a revision and exercise crash recovery, Windows/POSIX locking, concurrent operations, and restoration from independent backups.  
The concurrently arriving watcher work needs its own completed audit and test run.