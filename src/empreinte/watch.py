"""Continuous capture: keep the archive in step with watched folders while unlocked.

A Watcher polls with the standard library only. Each poll is in three phases so that a
server can keep the slow parts outside its operation lock:

    scan()           metadata only (lstat of every visible file, excluding hidden
                     paths, links, the vault and exports); nothing is read;
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

Logical namespaces are compared case-insensitively on every platform. No two
watches may have equal or nested prefixes, including the empty root prefix.
One batch holds at most 64 files / 32,000,000 bytes; one poll attempts at most
512 files / 128,000,000 bytes. Only one batch's plaintext is retained at a time.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
import time
from contextlib import nullcontext
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Sequence

from .api import VaultAPI, VaultError
from .importer import SourceFile, SkippedFile, TooLarge, _SKIP, _classify, check_prefix, put_source, read_source

FOLDERS_KEY = "watch/folders.v1"
STATE_PREFIX = "watch/state.v1/"
DEFAULT_QUIET = 60.0
DEFAULT_INTERVAL = 3.0
MAX_FOLDERS = 32
MAX_BACKOFF = 3600.0  # an unreadable file is retried at most this far apart (seconds)
MAX_BATCH_BYTES = 32_000_000
MAX_BATCH_FILES = 64
MAX_POLL_BYTES = 128_000_000
MAX_POLL_FILES = 512

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
    disabled_reason: str = field(default="", compare=False)

    @property
    def key(self) -> str:
        return STATE_PREFIX + hashlib.sha256((self.path + "\0" + self.prefix).encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ remembered folders


def _forbidden(vault: VaultAPI, extra: Sequence[Path] = ()) -> tuple[Path, ...]:
    paths = list(extra)
    path = getattr(vault, "path", None)
    if path is not None:
        path = Path(path).resolve()
        paths.extend((path, path.parent / f"{path.name}-licences"))
    return tuple(Path(p).resolve() for p in paths)


def _prefix_overlaps(a: str, b: str) -> bool:
    a, b = a.casefold().strip("/"), b.casefold().strip("/")
    return not a or not b or a == b or a.startswith(b + "/") or b.startswith(a + "/")


def _validated(folders, forbidden):
    out = []
    for f in folders:
        reason = ""
        try:
            if any(_overlaps(Path(f.path).resolve(), p) for p in forbidden):
                reason = "dossier désactivé : contient l'archive ou ses exports, ou se trouve dedans"
            elif any(_prefix_overlaps(f.prefix, other.prefix) for other in out):
                reason = "dossier désactivé : chevauchement de dossier logique (sans distinction de casse)"
        except OSError as exc:
            reason = f"dossier désactivé : {exc}"
        out.append(WatchedFolder(f.path, f.prefix, reason))
    return out


def load_folders(vault: VaultAPI, *, forbidden: Sequence[Path] = ()) -> list[WatchedFolder]:
    raw = vault.aux_get(FOLDERS_KEY)
    if not raw:
        return []
    try:
        data = json.loads(raw.decode("utf-8"))
        return _validated([WatchedFolder(str(d["path"]), str(d.get("prefix", "")))
                           for d in data if isinstance(d, dict)], _forbidden(vault, forbidden))
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
    for other in _forbidden(vault, forbidden):
        other = Path(other).resolve()
        if _overlaps(folder, other):
            raise ValueError(f"ce dossier contient l'archive ou ses exports, ou se trouve dedans ({other})")
    folders = load_folders(vault)
    for existing in folders:
        if Path(existing.path) == folder:
            raise ValueError("ce dossier est déjà suivi")
        if _prefix_overlaps(existing.prefix, prefix):
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
    entry_revision: tuple[str, int] | None
    generation: object


@dataclass
class _FolderState:
    generation: object = field(default_factory=object)
    known: dict[str, Signature] = field(default_factory=dict)  # last captured
    pending: dict[str, tuple[Signature, float]] = field(default_factory=dict)  # changed: signature, quiet since
    dirty: bool = False  # known differs from what aux holds
    # Files that could not be read: failures in a row, retry time, signature then. The
    # wait doubles from one quiet period up to MAX_BACKOFF; a new signature retries at once.
    failures: dict[str, tuple[int, float, Signature]] = field(default_factory=dict)
    skipped: dict[str, str] = field(default_factory=dict)


def _scan(root: Path, forbidden: Sequence[Path] = ()):
    """Scan metadata without descending into excluded directories; report I/O errors."""
    root = root.resolve(strict=True)
    pending = [root]
    while pending:
        folder = pending.pop()
        try:
            if any(folder.resolve().is_relative_to(p) for p in forbidden):
                continue
            if folder.is_symlink() or not folder.resolve().is_relative_to(root):
                raise OSError("directory changed to a link")
            children = sorted(folder.iterdir(), key=lambda p: p.name)
        except OSError as exc:
            yield SkippedFile(folder.relative_to(root).as_posix(), str(exc))
            continue
        for path in children:
            relative = path.relative_to(root).as_posix()
            try:
                info = path.lstat()
                if (path.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x402
                        or path.name.startswith(".") or path.name in _SKIP):
                    continue
                resolved = path.resolve()
                if not resolved.is_relative_to(root) or any(resolved.is_relative_to(p) for p in forbidden):
                    continue
                if stat.S_ISDIR(info.st_mode):
                    pending.append(path)
                elif stat.S_ISREG(info.st_mode):
                    media, kind = _classify(relative)
                    yield SourceFile(path, relative, info.st_size,
                                     datetime.fromtimestamp(info.st_mtime, timezone.utc), media, kind)
            except OSError as exc:
                yield SkippedFile(relative, str(exc))


class Watcher:
    """Polls watched folders. Thread-safe for one polling thread plus callers changing
    the folder list or reading the summary."""

    def __init__(self, *, quiet: float = DEFAULT_QUIET, interval: float = DEFAULT_INTERVAL,
                 max_bytes: int = 20_000_000, clock: Callable[[], float] = time.time,
                 forbidden: Sequence[Path] = ()):
        self.quiet = float(quiet)
        self.interval = float(interval)
        self.max_bytes = max_bytes
        self.clock = clock
        self._lock = threading.RLock()
        self._extra_forbidden = tuple(forbidden)
        self._forbidden = tuple(Path(p).resolve() for p in forbidden)
        self._vault: VaultAPI | None = None
        self.files_waiting = 0
        self._folders: list[WatchedFolder] = []
        self._states: dict[WatchedFolder, _FolderState] = {}
        self.captures = 0
        self.last_capture: datetime | None = None
        self.last_error = ""
        self.errors: dict[str, str] = {}  # folder path -> why it cannot be scanned now

    # ------------------------------------------------------------- folders and state
    def exclude(self, paths: Sequence[Path | None]) -> None:
        """Locations never scanned and never watchable (the vault, its exports), in
        addition to the vault's own path; applied at the next load()."""
        self._extra_forbidden = tuple(p for p in paths if p is not None)

    def load(self, vault: VaultAPI) -> None:
        """Read the remembered folders and their captured state from the vault."""
        self._vault = vault
        self._forbidden = _forbidden(vault, self._extra_forbidden)
        folders = load_folders(vault, forbidden=self._forbidden)
        states = {}
        for folder in folders:
            states[folder] = self._load_state(vault, folder)
        with self._lock:
            self._folders, self._states = folders, states

    def set_folders(self, vault: VaultAPI, folders: Sequence[WatchedFolder]) -> None:
        """Adopt a new folder list (after add_folder or remove_folder), keeping the state
        of the folders that stay."""
        folders = _validated(folders, _forbidden(vault, self._extra_forbidden))
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
                "folders": [{"path": f.path, "prefix": f.prefix,
                             "enabled": not bool(f.disabled_reason),
                             "error": f.disabled_reason or self.errors.get(f.path, "")}
                            for f in self._folders],
                "captures": self.captures,
                "last_capture": self.last_capture.isoformat() if self.last_capture else None,
                "pending": pending,
                "files_waiting": self.files_waiting,
                "skipped": [{"folder": f.path, "path": rel, "reason": reason}
                            for f, s in self._states.items() for rel, reason in s.skipped.items()],
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
            if state is None or folder.disabled_reason:
                continue
            root = Path(folder.path)
            try:
                found = list(_scan(root, self._forbidden))
            except (OSError, ValueError) as exc:
                with self._lock:
                    self.errors[folder.path] = f"dossier illisible : {exc}"[:300]
                continue
            with self._lock:
                self.errors.pop(folder.path, None)
                unreadable = [s for s in found if isinstance(s, SkippedFile)]
                if unreadable:
                    self.errors[folder.path] = "dossier illisible : " + "; ".join(
                        f"{s.path} : {s.reason}" for s in unreadable)[:300]
                def unseen(rel):
                    return rel not in seen and not any(
                        s.path == "." or rel == s.path or rel.startswith(s.path + "/") for s in unreadable)
                seen = set()
                for source in found:
                    if isinstance(source, SkippedFile):
                        continue
                    rel = source.relative_path
                    seen.add(rel)
                    if source.size > min(self.max_bytes, MAX_BATCH_BYTES, MAX_POLL_BYTES):
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
                    failed = state.failures.get(rel)
                    if failed is not None:
                        if failed[2] != sig_now:
                            del state.failures[rel]
                            state.skipped.pop(rel, None)
                            since = now - self.quiet  # changed failed file: retry immediately
                            state.pending[rel] = (sig_now, since)
                        elif now < failed[1]:
                            continue  # unreadable before: wait for its back-off
                        else:
                            since = now - self.quiet  # the retry deadline includes the quiet delay
                    if now - since >= self.quiet:
                        due.append(Due(folder, source, sig_now))
                # Deleted or renamed: forget it here, the archive keeps every version.
                for rel in [r for r in state.known if unseen(r)]:
                    del state.known[rel]
                    state.dirty = True
                for rel in [r for r in state.pending if unseen(r)]:
                    del state.pending[rel]
                for rel in [r for r in state.failures if unseen(r)]:
                    del state.failures[rel]
                    state.skipped.pop(rel, None)
        return due

    def batches(self, due: Sequence[Due]):
        """Metadata-only batches, bounded also by the total work allowed per poll."""
        selected, total = [], 0
        for item in due:
            if len(selected) >= MAX_POLL_FILES or total + item.source.size > MAX_POLL_BYTES:
                break
            selected.append(item)
            total += item.source.size
        with self._lock:
            self.files_waiting = len(due) - len(selected)
        batch, size = [], 0
        for item in selected:
            if batch and (len(batch) >= MAX_BATCH_FILES or size + item.source.size > MAX_BATCH_BYTES):
                yield batch
                batch, size = [], 0
            batch.append(item)
            size += item.source.size
        if batch:
            yield batch

    @staticmethod
    def _logical(item):
        return f"{item.folder.prefix}/{item.source.relative_path}" if item.folder.prefix else item.source.relative_path

    @staticmethod
    def _revision(vault, logical):
        entry = vault.find(logical)
        return (entry.entry_id, entry.n_versions) if entry else None

    def read(self, due: Sequence[Due]) -> list[Ready]:
        """Read what is due. A file that is unstable or changed since the scan stays
        pending for another quiet period."""
        ready: list[Ready] = []
        size = 0
        for item in due:
            if len(ready) >= MAX_BATCH_FILES or size + item.source.size > MAX_BATCH_BYTES:
                break
            with self._lock:
                state = self._states.get(item.folder)
                if state is None or item.folder.disabled_reason:
                    continue
                generation = state.generation
            revision = self._revision(self._vault, self._logical(item))
            root = Path(item.folder.path)
            try:
                content, info = read_source(root, item.source, min(self.max_bytes, MAX_BATCH_BYTES - size))
            except TooLarge:
                self._restart(item)
                continue
            except OSError as exc:
                self._restart(item)
                self._failed(item)
                with self._lock:
                    self.last_error = f"{item.source.relative_path} : {exc}"[:300]
                    state.skipped.setdefault(item.source.relative_path, str(exc)[:300])
                continue
            if _stat_signature(info) != item.signature:
                del content
                self._restart(item)
                continue
            ready.append(Ready(item.folder, item.source, item.signature, content, info, revision, generation))
            size += len(content)
        return ready

    def _failed(self, item: Due) -> None:
        """Back off from a file that cannot be read (locked by another program, no
        permission): the next attempts come after 1, 2, 4... quiet periods."""
        with self._lock:
            state = self._states.get(item.folder)
            if state is None:
                return
            rel = item.source.relative_path
            count = state.failures.get(rel, (0, 0.0, item.signature))[0]
            wait = min(max(self.quiet, 1.0) * (2 ** min(count, 30)), MAX_BACKOFF)
            state.failures[rel] = (count + 1, self.clock() + wait, item.signature)

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
                with self._lock:
                    state = self._states.get(item.folder)
                    current = next((f for f in self._folders if f == item.folder), None)
                    if (state is None or current is None or current.disabled_reason
                            or state.generation is not item.generation
                            or vault is not self._vault):
                        continue
                    try:
                        if _stat_signature(item.source.path.stat()) != item.signature:
                            continue
                    except OSError:
                        continue
                    if self._revision(vault, logical) != item.entry_revision:
                        continue
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
                state.failures.pop(rel, None)
                state.skipped.pop(rel, None)
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
        captures = []
        for due in self.batches(self.scan()):
            ready = self.read(due)
            if self.has_work(ready):
                captures.extend(self.commit(vault, ready))
            del ready  # release plaintext before reading the next batch
        if self.has_work([]):
            self.commit(vault, [])
        return captures


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
                for due in self.watcher.batches(self.watcher.scan()):
                    if self.stopped.is_set():
                        return
                    self.run_locked(lambda vault: None)  # session check before each read
                    ready = self.watcher.read(due)
                    if self.stopped.is_set():
                        return
                    if self.watcher.has_work(ready):
                        self.run_locked(lambda vault: self._commit(vault, ready))
                    del ready
                if self.watcher.has_work([]) and not self.stopped.is_set():
                    self.run_locked(lambda vault: self._commit(vault, []))
            except Stale:
                return
            except VaultError as exc:
                self.watcher.last_error = str(exc)[:300]
            except Exception as exc:  # noqa: BLE001 - the watcher must survive one bad file
                self.watcher.last_error = f"{type(exc).__name__}: {str(exc)[:200]}"
            finally:
                ready = None  # also release a failed batch before another poll reads

    def _commit(self, vault: VaultAPI, ready: Sequence[Ready]) -> list[Capture]:
        if self.stopped.is_set():
            raise Stale()
        captures = self.watcher.commit(vault, ready)
        if captures and self.on_capture is not None:
            self.on_capture(vault, captures)
        return captures
