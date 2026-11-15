"""Continuous capture: keep the archive in step with watched folders while unlocked.

A Watcher polls with the standard library only. Each poll is in three phases so that a
server can keep the slow parts outside its operation lock:

    scan()           metadata only (lstat of every visible file, through the importer's
                     scanner, which skips what an import skips); nothing is read;
    read(due)        reads the files that changed and have been quiet long enough,
                     through the importer's stable read (two reads that must agree);
    commit(vault, ready)   one batch of ordinary put() calls, then the saved state.

A file is due when its size and modification time have not changed for `quiet`
seconds (60 by default). A file whose modification time is already older than that
when it is first seen is due at once. A file being written (unstable read, or a
signature that moved between scan and read) waits for the next quiet period. Each
capture is a new version in the ledger, with the file date as claimed time. A deleted
or renamed file removes nothing from the archive: the new name is a new entry.

What is remembered, encrypted inside the vault through aux_put:

    watch/folders.v1               the watched folders (absolute path and logical prefix)
    watch/state.v1/<sha256>        per folder: relative path -> [size, mtime in microseconds]
                                   of what was last captured, so that a restart reads
                                   only what changed while nothing was watching.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from contextlib import nullcontext
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Sequence

from .api import VaultAPI, VaultError
from .importer import SourceFile, TooLarge, _scan, check_prefix, put_source, read_source

FOLDERS_KEY = "watch/folders.v1"
STATE_PREFIX = "watch/state.v1/"
DEFAULT_QUIET = 60.0
DEFAULT_INTERVAL = 3.0
MAX_FOLDERS = 32

Signature = tuple[int, int]  # size in bytes, modification time in microseconds since the epoch


_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _micros(value: datetime) -> int:
    return (value - _EPOCH) // timedelta(microseconds=1)


def signature_of(source: SourceFile) -> Signature:
    return source.size, _micros(source.source_mtime)


def _stat_signature(info: os.stat_result) -> Signature:
    return info.st_size, _micros(datetime.fromtimestamp(info.st_mtime, timezone.utc))


@dataclass(frozen=True)
class WatchedFolder:
    """One watched folder: an absolute path and the logical folder it is filed under."""

    path: str
    prefix: str = ""

    @property
    def key(self) -> str:
        return STATE_PREFIX + hashlib.sha256((self.path + "\0" + self.prefix).encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ remembered folders


def load_folders(vault: VaultAPI) -> list[WatchedFolder]:
    raw = vault.aux_get(FOLDERS_KEY)
    if not raw:
        return []
    try:
        data = json.loads(raw.decode("utf-8"))
        return [WatchedFolder(str(d["path"]), str(d.get("prefix", ""))) for d in data if isinstance(d, dict)]
    except (ValueError, KeyError, TypeError):
        return []


def save_folders(vault: VaultAPI, folders: Sequence[WatchedFolder]) -> None:
    data = [{"path": f.path, "prefix": f.prefix} for f in folders]
    vault.aux_put(FOLDERS_KEY, json.dumps(data, ensure_ascii=False).encode("utf-8"))


def _overlaps(a: Path, b: Path) -> bool:
    return a == b or a.is_relative_to(b) or b.is_relative_to(a)


def add_folder(vault: VaultAPI, path: Path | str, prefix: str = "", *,
               forbidden: Sequence[Path] = ()) -> list[WatchedFolder]:
    """Remember one more folder and return the list. Raises ValueError with a French
    message when the folder is unusable: missing, already watched, overlapping the vault
    (capturing the vault's own files would never stop), or sharing a prefix with another
    watched folder (two files with the same relative path would become versions of one
    entry)."""
    folder = Path(path)
    if not folder.is_absolute():
        raise ValueError("le chemin doit être absolu")
    try:
        folder = folder.resolve(strict=True)
    except OSError:
        raise ValueError("ce dossier n'existe pas") from None
    if not folder.is_dir():
        raise ValueError("ce chemin n'est pas un dossier")
    try:
        prefix = check_prefix(prefix)
    except ValueError:
        raise ValueError("le dossier logique doit être un chemin relatif") from None
    for other in forbidden:
        other = Path(other).resolve()
        if _overlaps(folder, other):
            raise ValueError(f"ce dossier contient l'archive ou ses exports, ou se trouve dedans ({other})")
    folders = load_folders(vault)
    for existing in folders:
        if Path(existing.path) == folder:
            raise ValueError("ce dossier est déjà suivi")
        if existing.prefix == prefix:
            raise ValueError("un autre dossier suivi est déjà rangé sous ce dossier logique : donnez-en un autre")
    if len(folders) >= MAX_FOLDERS:
        raise ValueError(f"au plus {MAX_FOLDERS} dossiers suivis")
    folders.append(WatchedFolder(str(folder), prefix))
    save_folders(vault, folders)
    return folders


def remove_folder(vault: VaultAPI, path: Path | str) -> list[WatchedFolder]:
    """Stop watching a folder. Nothing is removed from the archive."""
    target = str(path)
    try:
        resolved = str(Path(path).resolve())
    except OSError:
        resolved = target
    folders = load_folders(vault)
    kept = [f for f in folders if f.path not in (target, resolved)]
    if len(kept) == len(folders):
        raise ValueError("ce dossier n'est pas suivi")
    save_folders(vault, kept)
    return kept


# ---------------------------------------------------------------------------- watcher


@dataclass
class Capture:
    """One new version recorded by the watcher."""

    folder: str
    path: str  # logical path in the archive
    entry_id: str
    version: int
    at: datetime  # wall clock of the capture, UTC (the ledger time is in the record)


@dataclass
class Due:
    folder: WatchedFolder
    source: SourceFile
    signature: Signature


@dataclass
class Ready:
    folder: WatchedFolder
    source: SourceFile
    signature: Signature
    content: bytes
    info: os.stat_result


@dataclass
class _FolderState:
    known: dict[str, Signature] = field(default_factory=dict)  # last captured
    pending: dict[str, tuple[Signature, float]] = field(default_factory=dict)  # changed: signature, quiet since
    dirty: bool = False  # known differs from what aux holds


class Watcher:
    """Polls watched folders. Thread-safe for one polling thread plus callers changing
    the folder list or reading the summary."""

    def __init__(self, *, quiet: float = DEFAULT_QUIET, interval: float = DEFAULT_INTERVAL,
                 max_bytes: int = 20_000_000, clock: Callable[[], float] = time.time):
        self.quiet = float(quiet)
        self.interval = float(interval)
        self.max_bytes = max_bytes
        self.clock = clock
        self._lock = threading.Lock()
        self._folders: list[WatchedFolder] = []
        self._states: dict[WatchedFolder, _FolderState] = {}
        self.captures = 0
        self.last_capture: datetime | None = None
        self.last_error = ""
        self.errors: dict[str, str] = {}  # folder path -> why it cannot be scanned now

    # ------------------------------------------------------------- folders and state
    def load(self, vault: VaultAPI) -> None:
        """Read the remembered folders and their captured state from the vault."""
        folders = load_folders(vault)
        states = {}
        for folder in folders:
            states[folder] = self._load_state(vault, folder)
        with self._lock:
            self._folders, self._states = folders, states

    def set_folders(self, vault: VaultAPI, folders: Sequence[WatchedFolder]) -> None:
        """Adopt a new folder list (after add_folder or remove_folder), keeping the state
        of the folders that stay."""
        with self._lock:
            kept = {f: s for f, s in self._states.items() if f in folders}
        for folder in folders:
            if folder not in kept:
                kept[folder] = self._load_state(vault, folder)
        with self._lock:
            self._folders, self._states = list(folders), kept
            self.errors = {k: v for k, v in self.errors.items() if any(f.path == k for f in folders)}

    @staticmethod
    def _load_state(vault: VaultAPI, folder: WatchedFolder) -> _FolderState:
        state = _FolderState()
        raw = vault.aux_get(folder.key)
        if raw:
            try:
                data = json.loads(raw.decode("utf-8"))
                state.known = {str(k): (int(v[0]), int(v[1])) for k, v in data.items()}
            except (ValueError, TypeError, IndexError, AttributeError):
                state.known = {}
        return state

    @property
    def folders(self) -> list[WatchedFolder]:
        with self._lock:
            return list(self._folders)

    def summary(self) -> dict:
        with self._lock:
            pending = sum(len(s.pending) for s in self._states.values())
            return {
                "folders": [{"path": f.path, "prefix": f.prefix, "error": self.errors.get(f.path, "")}
                            for f in self._folders],
                "captures": self.captures,
                "last_capture": self.last_capture.isoformat() if self.last_capture else None,
                "pending": pending,
                "quiet": self.quiet,
                "last_error": self.last_error,
            }

    # ----------------------------------------------------------------------- polling
    def scan(self) -> list[Due]:
        """Metadata only. Updates the quiet-period bookkeeping and returns what is due."""
        now = self.clock()
        due: list[Due] = []
        for folder in self.folders:
            with self._lock:
                state = self._states.get(folder)
            if state is None:
                continue
            root = Path(folder.path)
            try:
                found = [s for s in _scan(root) if isinstance(s, SourceFile)]
            except (OSError, ValueError) as exc:
                with self._lock:
                    self.errors[folder.path] = f"dossier illisible : {exc}"[:300]
                continue
            with self._lock:
                self.errors.pop(folder.path, None)
                seen = set()
                for source in found:
                    rel = source.relative_path
                    seen.add(rel)
                    if source.size > self.max_bytes:
                        state.pending.pop(rel, None)
                        continue
                    sig = signature_of(source)
                    if state.known.get(rel) == sig:
                        state.pending.pop(rel, None)
                        continue
                    previous = state.pending.get(rel)
                    if previous is None:
                        age = now - source.source_mtime.timestamp()
                        since = now - self.quiet if age >= self.quiet else now
                        state.pending[rel] = (sig, since)
                    elif previous[0] != sig:
                        state.pending[rel] = (sig, now)  # still being written: the quiet period restarts
                    sig_now, since = state.pending[rel]
                    if now - since >= self.quiet:
                        due.append(Due(folder, source, sig_now))
                # Deleted or renamed: forget it here, the archive keeps every version.
                for rel in [r for r in state.known if r not in seen]:
                    del state.known[rel]
                    state.dirty = True
                for rel in [r for r in state.pending if r not in seen]:
                    del state.pending[rel]
        return due

    def read(self, due: Sequence[Due]) -> list[Ready]:
        """Read what is due. A file that is unstable or changed since the scan stays
        pending for another quiet period."""
        ready: list[Ready] = []
        for item in due:
            root = Path(item.folder.path)
            try:
                content, info = read_source(root, item.source, self.max_bytes)
            except TooLarge:
                self._restart(item)
                continue
            except OSError as exc:
                self._restart(item)
                with self._lock:
                    self.last_error = f"{item.source.relative_path} : {exc}"[:300]
                continue
            if _stat_signature(info) != item.signature:
                self._restart(item)
                continue
            ready.append(Ready(item.folder, item.source, item.signature, content, info))
        return ready

    def _restart(self, item: Due) -> None:
        with self._lock:
            state = self._states.get(item.folder)
            if state is not None and item.source.relative_path in state.pending:
                state.pending[item.source.relative_path] = (item.signature, self.clock())

    def has_work(self, ready: Sequence[Ready]) -> bool:
        with self._lock:
            return bool(ready) or any(s.dirty for s in self._states.values())

    def commit(self, vault: VaultAPI, ready: Sequence[Ready]) -> list[Capture]:
        """Record what was read: one put per file (a new version only if the content
        differs), in one batch, then the captured state. Raises VaultError when the
        vault is locked or read-only; then nothing of this round is marked captured."""
        captures: list[Capture] = []
        captured: list[Ready] = []
        batch = getattr(vault, "batch", None)
        with batch() if callable(batch) else nullcontext():
            for item in ready:
                prefix = item.folder.prefix
                logical = f"{prefix}/{item.source.relative_path}" if prefix else item.source.relative_path
                existing = vault.find(logical)
                before = existing.n_versions if existing else 0
                version = put_source(vault, logical, item.source, item.content, item.info)
                captured.append(item)
                if version.version > before:
                    captures.append(Capture(item.folder.path, logical, version.entry_id, version.version,
                                            datetime.fromtimestamp(self.clock(), timezone.utc)))
        # The batch is durable now: only then is the state saved and the files marked.
        with self._lock:
            for item in captured:
                state = self._states.get(item.folder)
                if state is None:
                    continue
                rel = item.source.relative_path
                state.known[rel] = item.signature
                if state.pending.get(rel, (None,))[0] == item.signature:
                    del state.pending[rel]
                state.dirty = True
            to_save = [(f, dict(s.known)) for f, s in self._states.items() if s.dirty]
        for folder, known in to_save:
            vault.aux_put(folder.key, json.dumps({k: list(v) for k, v in known.items()},
                                                 ensure_ascii=False).encode("utf-8"))
        with self._lock:
            for folder, _ in to_save:
                if folder in self._states:
                    self._states[folder].dirty = False
            if captures:
                self.captures += len(captures)
                self.last_capture = captures[-1].at
        return captures

    def poll(self, vault: VaultAPI) -> list[Capture]:
        """scan, read and commit in one go (the command line)."""
        ready = self.read(self.scan())
        if not self.has_work(ready):
            return []
        return self.commit(vault, ready)


# ------------------------------------------------------------------ background thread


class Stale(Exception):
    """The session the watcher was started for is gone."""


class WatchThread(threading.Thread):
    """Runs a Watcher for one session. `run_locked(fn)` must call fn(vault) inside the
    caller's lock and raise Stale when the session is no longer the one this thread was
    started for. Reading files happens outside that lock; only commit, and `on_capture`
    (for example a workspace refresh), run inside it."""

    def __init__(self, watcher: Watcher, run_locked: Callable[[Callable[[VaultAPI], object]], object],
                 on_capture: Callable[[VaultAPI, list[Capture]], None] | None = None):
        super().__init__(name="empreinte-watch", daemon=True)
        self.watcher = watcher
        self.run_locked = run_locked
        self.on_capture = on_capture
        self.stopped = threading.Event()

    def stop(self) -> None:
        """Ask the thread to end; never blocks (it may be waiting for the caller's lock)."""
        self.stopped.set()

    def run(self) -> None:
        try:
            self.run_locked(self.watcher.load)
        except (Stale, VaultError):
            return
        while not self.stopped.wait(self.watcher.interval):
            try:
                ready = self.watcher.read(self.watcher.scan())
                if self.stopped.is_set():
                    return
                if not self.watcher.has_work(ready):
                    continue
                self.run_locked(lambda vault: self._commit(vault, ready))
            except Stale:
                return
            except VaultError as exc:
                self.watcher.last_error = str(exc)[:300]
            except Exception as exc:  # noqa: BLE001 - the watcher must survive one bad file
                self.watcher.last_error = f"{type(exc).__name__}: {str(exc)[:200]}"

    def _commit(self, vault: VaultAPI, ready: Sequence[Ready]) -> list[Capture]:
        captures = self.watcher.commit(vault, ready)
        if captures and self.on_capture is not None:
            self.on_capture(vault, captures)
        return captures
