# T1. Corriger l'audit de la tête pensante

Plan approuvé par le propriétaire le 16 novembre 2026. Brief destiné à l'agent qui
exécute (en anglais, comme les autres briefs d'agents du projet).

Read first: CLAUDE.md, docs/CONTEXT.md, docs/THINKING_HEAD.md, then
docs/reviews/2026-11-16-audit-tete-pensante.md: an independent read-only audit of the
head, twelve findings, five high, each with location, scenario and suggested fix, plus
what it found correct (schemas, task binding of results, serialisation of cooperating
writers, rollback, disclosed limits). It was a static read; re-check each location.
Fix all twelve. The two boundaries that matter, what gets executed and what counts as
verified, are weaker than the document says.

## Decisions

Execution authority (findings 1, 2, 3)
- 1: a check names its program by absolute path, never by bare name; the tool refuses a
  relative or bare program. The environment given to a check is built from fixed values,
  not inherited ones: a fixed PATH, HOME and CARGO_HOME pointing where you decide and
  document, nothing else unless the check's entry lists it with its value. Record in each
  result the path and a hash of the executable that ran, and a hash of the execution
  configuration; a change in either makes the result stale.
- 2: no git command that can run configured helpers. Inspect the repository in a way no
  repository configuration can influence: isolate git from system, global and
  repository-level executable settings (no textconv, external diff, fsmonitor, hooks,
  pager, credential or alias expansion), and do not use `git diff` for fingerprinting at
  all (see 4). Any remaining git process runs with the same containment as a check.
- 3: the repository and its allow-list must be explicitly trusted, not discovered. Keep a
  list of trusted repository roots outside any repository (a file in the user's
  configuration directory), filled by an explicit `head trust <path>` that shows what it
  is about to trust; every command refuses to read .agents or run anything in a root that
  is not on it, and says how to trust it. A .git marker is never enough. Refuse .agents,
  .agents/rules or the checks file when any component is a link; open them beneath an
  already opened directory handle without following links where the platform allows; say
  plainly what Windows cannot guarantee.

What counts as verified (findings 4, 5, 10, 11, 12)
- 4: fail closed. If the fingerprint of the inputs cannot be computed completely (git
  missing, failing, timing out, output truncated), nothing is certified: the check may run
  but its result cannot verify a task or support a promotion. The fingerprint covers the
  content of every tracked file and every untracked, non-ignored file, hashed by the tool.
- 5: a result describes exactly the tree that was tested. Run each check against an
  immutable snapshot (copy the fingerprinted files into a private temporary directory, run
  there, bind the result to the snapshot digest). Verification and promotion require the
  working tree to match that digest at the moment of commitment. Build outputs may go to a
  fixed cache directory outside the snapshot; say what that leaves open (a poisoned cache)
  and how you bound it.
- 10: every output that mentions a verification or an evaluation carries its effective
  state: recall and active-rule listings show stale when stale, with the reason.
- 11: ship the two rules as candidates, and add the explicit path by which a rule file
  present in the repository enters the journal (registration as a candidate, then a fresh
  evaluation). Nothing shipped may claim an evaluation the local journal cannot show.
- 12: do not claim what is not enforced. Run checks with no network when the platform
  allows it without privileges (on Linux an unprivileged network namespace), record in each
  result whether isolation was in effect, and let a check declare that it requires
  isolation, in which case its result does not pass without it. Reword the network rule to
  say exactly what is enforced and where.

Process control and durability (findings 6, 7, 8, 9)
- 6: "passed" only if the output was captured completely within its bound and no
  descendant survives. Contain the whole process tree with what the OS enforces (Linux:
  subreaper, or a pid namespace together with the network one); if containment or cleanup
  cannot be confirmed the result is "incomplete", never passed. The timeout test must stop
  accepting zombies. State what Windows would need.
- 7: an ignored line can never become valid later. Before any mutation, a tail without its
  newline is durably set aside in a way replay always honours; replay validates that every
  move's evidence exists, is for the right subject and precedes it.
- 8: rule moves and repair become recoverable transactions: durable intent before touching
  files, complete or undo on next open, directory sync, and never an empty journal when
  evidence of an interrupted repair exists (refuse and explain).
- 9: hold the lock on something a concurrent writer cannot swap unnoticed, re-check its
  identity before committing, document the remaining limit.

## Rules
- Only the head: rust/src/head, rust/tests, the head subcommands of rust/src/main.rs,
  .agents, docs/THINKING_HEAD.md. Smallest possible edit to any shared file, listed in the
  report. harness.rs and conversations.rs untouched; the cloud path of `memory execute` is
  kept by the owner's decision, never called.
- No shell, rules inert unless a human moves them, journal append-only except repair.
- Build and test under WSL: `wsl -e bash -lc "cd /mnt/c/Users/sawle/OneDrive/Desktop/ChargeGrinder/Empreinte/rust && CARGO_TARGET_DIR=/root/empreinte-target cargo test --all-targets --offline --locked"`.
- One test per finding, written to fail on the current code; show the failure first for
  1, 2, 3 and 5. Re-evaluate the two shipped rules under the new rules of the game.
- Update docs/THINKING_HEAD.md so every claim matches the code, with a short trust-model
  section: what the tool assumes about the person, the repository, the machine, and what it
  does not defend against.
- No outside service, no emojis, no em-dashes, rtk prefix on shell commands.

## Done when
All twelve findings fixed with tests, Rust suite green under WSL, THINKING_HEAD.md true,
report written to docs/reviews/ (date-tete-corrections.md): per finding, change and test,
what was seen failing first, what is still not guaranteed on Linux and on Windows, and
whether the tool is fit to receive a planner's proposals as data.
