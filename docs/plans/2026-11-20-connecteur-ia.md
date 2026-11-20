# T2. Connecteur d'IA et tâches planifiées

Demande du propriétaire, 20 novembre 2026 : « ajouter une fonction pour pouvoir connecter
toutes les IA de l'ordinateur et créer des tâches planifiées à partir d'elle ». Brief
destiné à l'agent qui exécute.

## Goal
One place, inside the Empreinte Python package, that (1) knows every AI available on this
machine, (2) can ask any of them to do a task the same way, with safe defaults, and
(3) can turn such a request into a recurring Windows scheduled task, list it, run it now,
and remove it. Command line first: `empreinte ia ...`. A small view in the web interface is
optional and comes last.

## Where
- New subpackage `src/empreinte/aihub/` (standard library only, plus pydantic already in
  use), wired into `src/empreinte/cli.py` as the `ia` command group. Tests in
  `tests/test_aihub.py`. Documentation in `docs/AIHUB.md`, and one line in docs/CONTEXT.md.
- Python, because it must run natively on Windows and drive the Windows Task Scheduler;
  the Rust engine is not validated on Windows. Say in docs/AIHUB.md that a Rust
  counterpart can come later, per the owner's two-engine decision.
- Do not touch the vault engine, the server, the web interface (except the optional view),
  nor anything under rust/.

## 1. Detection: `empreinte ia detecter`
An adapter per AI, each reporting: installed or not, absolute path of the executable or
the local address, version, whether it is signed in (from the tool's own status command,
never by reading token or credential files), cloud or local, and what it can do headless
(read-only mode available, write mode available). Check the real command-line options of
each tool on this machine (`--help`) before relying on them; do not assume flags.
Adapters to cover, as present on this machine:
- Claude Code CLI (`claude`), headless with `-p`.
- Codex CLI (`codex exec`), read-only sandbox `-s read-only`; known limitation here: its
  sandbox cannot run a Python from the user profile; a dedicated interpreter exists in
  C:/Users/sawle/.codex-py (see docs/CONTEXT.md).
- Gemini CLI (`gemini -p`): installed, but refuses individual Google accounts
  (IneligibleTierError); works with a GEMINI_API_KEY set by the owner. Report the state
  honestly, never ask for or store the key.
- Google Antigravity: `agentapi` in C:/Users/sawle/.gemini/antigravity/bin, and the MCP
  bridge in C:/Users/sawle/.gemini/antigravity/scratch/claude-antigravity-mcp. It only works
  from inside Antigravity (ANTIGRAVITY_LS_ADDRESS plus an internal token). Report it as
  "disponible seulement depuis Antigravity"; do not read Antigravity's internal token files.
- Ollama (HTTP 127.0.0.1:11434, list models) and LM Studio (`lms` or its local server),
  loopback only, reusing the loopback rules of src/empreinte/localllm.py.
- Leave room for adding an adapter in a few lines (a registry of adapters).
Detection sends no prompt, makes no paid call, and every probe has a short timeout.
Resolve executables to absolute paths once and store them: later runs use those paths,
never a bare name looked up in PATH (the head audit found PATH hijacking; do not repeat it).

## 2. Asking: `empreinte ia demander <ia> --consigne <fichier> --dossier <dossier>`
- Read-only by default: map to each tool's own read-only or plan mode. Writing is allowed
  only with an explicit `--ecriture`, mapped to the tool's sandboxed write mode. Never use
  any flag that bypasses approvals or sandboxing.
- Timeout, bounded output, exit status. Each run gets a folder outside the repository,
  under %LOCALAPPDATA%\Empreinte\aihub\runs\<date>-<ia>-<id>\, holding the instruction,
  the output, the exit status, the duration and the exact command line (without secrets).
- Protection of the owner's data: refuse a working folder or an instruction file inside
  C:\Users\sawle\Documents\Wiki, inside any Empreinte vault (a folder holding header.json
  and ledger.jsonl), or inside C:\Users\sawle\.empreinte-essai. For a cloud adapter, print
  one line saying which provider the instruction and the folder's files may be sent to.
- Local adapters (Ollama, LM Studio) take the instruction as a prompt over loopback HTTP
  and write the answer to the run folder; they do not get file access.

## 3. Scheduling: `empreinte ia planifier`, `taches`, `lancer`, `supprimer`
- `planifier <nom> --ia <ia> --consigne <fichier> --dossier <dossier>` with one schedule:
  `--toutes-les 3h` (or Nm, Nh) or `--chaque-jour HH:MM`. It shows exactly what will be
  registered and does nothing without `--oui`.
- Register with the Windows Task Scheduler through PowerShell Register-ScheduledTask (not
  schtasks, which breaks nested quotes), in the task folder `\Empreinte\` only, as the
  current user, only when logged on, no stored password, no elevation, MultipleInstances
  IgnoreNew so runs never overlap. The action calls the venv Python by absolute path:
  `C:\Users\sawle\.venvs\empreinte\Scripts\python.exe -m empreinte.cli ia demander ...`.
- Keep each task's definition (JSON) in %LOCALAPPDATA%\Empreinte\aihub\taches\. `taches`
  lists them with next run, last run and last result read back from the scheduler and the
  run folders; `lancer <nom>` runs one now; `supprimer <nom>` removes it. These commands
  only ever touch tasks under `\Empreinte\`.
- Copy the instruction file into the task's folder at creation, so later edits of the
  original do not silently change what a scheduled task sends.

## Tests
- No test calls a real AI, makes a network request or registers a real scheduled task:
  inject the process runner, the HTTP client and the PowerShell runner, and assert on the
  commands and the generated PowerShell script. Fake executables in a temporary folder for
  detection, resolved by absolute path.
- Cover: each adapter detected, absent, signed out; read-only as default mode for each
  adapter; `--ecriture` mapping; refusal of the Wiki, a vault and the trial vault folders;
  timeout and bounded output; the PowerShell script for each schedule form (quoting with
  spaces and accents in paths); `--oui` required; only `\Empreinte\` touched; removal;
  the instruction copied at creation.
- The whole suite stays green: `rtk C:/Users/sawle/.venvs/empreinte/Scripts/python.exe -m pytest -q`.

## Real checks on this machine, at the end
- Run `empreinte ia detecter` for real and put its output in the report.
- Do not register a real scheduled task and do not send any real prompt to a cloud AI.
  One real `demander` to a local model through Ollama is allowed if Ollama is running.

## Rules
French for every user-facing message, no emojis, no em-dashes, rtk prefix on shell
commands, no commit (the queue runner or the owner commits after verification).

## Done when
The three command groups work with tests, the real detection output is in the report,
docs/AIHUB.md explains use, safety defaults and limits, and a report is written to
docs/reviews/<date>-connecteur-ia.md.
