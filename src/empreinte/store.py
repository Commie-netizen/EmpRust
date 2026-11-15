"""Durable file operations for a vault directory.

A vault is a plain directory that may sit in a OneDrive or Dropbox folder: a sync client
can hold a file open for a moment, so every replace and read retries briefly instead of
failing, and nothing relies on file locking.
"""
from __future__ import annotations

import json
import os
import socket
import stat
import time
from pathlib import Path
from typing import Callable, TypeVar

T = TypeVar("T")

RETRY_DELAYS = (0.05, 0.1, 0.2, 0.4, 0.8, 1.6)  # about 3 s in total


def _retry(action: Callable[[], T]) -> T:
    """Retry an operation that a sync client or antivirus may block for a moment."""
    for delay in RETRY_DELAYS:
        try:
            return action()
        except PermissionError:
            time.sleep(delay)
    return action()


def fsync_dir(path: Path) -> None:
    """Make a rename durable on POSIX. Windows cannot open a directory for fsync; NTFS
    journals the rename itself, so skipping it there is the documented behaviour."""
    if os.name == "nt":
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path: Path, data: bytes, *, durable: bool = True) -> None:
    """Write to a temporary file in the same directory, fsync, then replace the target."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{os.urandom(4).hex()}.tmp")
    try:
        with open(tmp, "wb") as handle:
            handle.write(data)
            handle.flush()
            if durable:
                os.fsync(handle.fileno())
        _retry(lambda: os.replace(tmp, path))
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
    if durable:
        fsync_dir(path.parent)


def atomic_write_text(path: Path, text: str, *, durable: bool = True) -> None:
    atomic_write(path, text.encode("utf-8"), durable=durable)


def fsync_file(path: Path) -> None:
    def action() -> None:
        with open(path, "r+b") as handle:
            os.fsync(handle.fileno())
    _retry(action)


def read_bytes(path: Path) -> bytes:
    return _retry(lambda: Path(path).read_bytes())


def read_bounded(path: Path, limit: int) -> bytes:
    """Read a whole file through one handle, never more than `limit` bytes: a file that
    is larger when it is read (even if it was small when stat() looked) raises TooLarge."""
    def action() -> bytes:
        with open(path, "rb") as handle:
            data = handle.read(limit + 1)
        return data
    data = _retry(action)
    if len(data) > limit:
        raise TooLarge(f"{Path(path).name} is larger than {limit} bytes")
    return data


class TooLarge(ValueError):
    """A file or a record exceeds its bound; nothing beyond the bound was read."""


def iter_bounded_lines(path: Path, limit: int):
    """Yield (line_number, line) for each line of a file, read as a stream from one handle.

    A line longer than `limit` bytes yields (line_number, None) and is skipped without
    being held in memory, so a long file costs one record at a time and one oversized
    record cannot make the reader allocate without bound. The newline is stripped.
    """
    handle = _retry(lambda: open(path, "rb"))
    with handle:
        number = 0
        while True:
            line = handle.readline(limit + 1)
            if not line:
                return
            number += 1
            if len(line) > limit and not line.endswith(b"\n"):
                while True:  # skip the rest of the oversized line in bounded chunks
                    rest = handle.readline(1 << 16)
                    if not rest or rest.endswith(b"\n"):
                        break
                yield number, None
                continue
            yield number, line.rstrip(b"\r\n")


def append_bytes(path: Path, data: bytes) -> None:
    """Append and fsync. The ledger is the only file that grows in place.

    Only opening is retried: once bytes may have been written, a retry could duplicate them.
    """
    handle = _retry(lambda: open(path, "ab"))
    with handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def truncate(path: Path, size: int) -> None:
    def action() -> None:
        with open(path, "r+b") as handle:
            handle.truncate(size)
            handle.flush()
            os.fsync(handle.fileno())
    _retry(action)


class WriterLock:
    """writer.lock: one writer per vault, held by the operating system.

    The writer keeps a handle open on writer.lock and holds an exclusive lock on one
    byte at LOCK_OFFSET (beyond the informational text, so the file stays readable):
    msvcrt.locking on Windows, fcntl.flock elsewhere. The system releases it when the
    handle is closed or the process dies, so a crash never leaves a lock to reclaim and
    nobody ever deletes another owner's lock file. A second handle, even in the same
    process, cannot take it: that instance stays read-only.

    It coordinates processes on one machine only. Two machines syncing the folder each
    see their own local lock; see docs/FORMAT.md for what then happens.
    """

    LOCK_OFFSET = 1 << 20

    def __init__(self, path: Path):
        self.path = Path(path)
        self._handle = None
        self._identity: tuple[int, int] | None = None

    NOT_PLAIN = ("writer.lock is a link or not a plain file; opened read-only "
                 "(replace it by an ordinary file, or delete it, to write again)")

    def acquire(self) -> str | None:
        """Take the lock without waiting. Returns None on success, else why it is held.

        writer.lock must be a plain file with a single name: a symbolic link, a hard link
        to another file, a junction or a directory is refused before anything is written,
        so locking never truncates a file outside the vault. The opened handle is checked
        against the path, and it is closed on every failure until this object owns it.
        """
        if self._handle is not None:
            return None
        if _is_link(self.path) or self.path.is_dir():
            return self.NOT_PLAIN
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = _retry(lambda: os.open(self.path, flags, 0o600))  # never truncates, never deletes
        except OSError:
            if self.path.is_dir() or _is_link(self.path):
                return self.NOT_PLAIN
            raise
        handle = None
        try:
            handle = os.fdopen(fd, "r+b")
            if not _same_plain_file(handle.fileno(), self.path):
                handle.close()
                return self.NOT_PLAIN
            try:
                _lock_byte(handle, self.LOCK_OFFSET)
            except OSError:
                handle.close()
                return "another writer (a process, or another open Vault object) holds this vault; opened read-only"
            info = json.dumps({"pid": os.getpid(), "host": socket.gethostname()}).encode("ascii")
            handle.seek(0)
            handle.truncate()
            handle.write(info + b"\n")  # informational only: the OS lock is the truth
            handle.flush()
            status = os.fstat(handle.fileno())
        except BaseException:
            if handle is not None:
                handle.close()  # closing releases the OS lock
            else:
                os.close(fd)
            raise
        self._handle, self._identity = handle, (status.st_dev, status.st_ino)
        return None

    def held(self) -> bool:
        """True while this object holds the lock on the file that is at the path now."""
        if self._handle is None:
            return False
        try:
            status = os.stat(self.path)
        except OSError:
            return False
        if os.name != "nt" and (status.st_dev, status.st_ino) != self._identity:
            return False  # the file was replaced: the lock we hold protects nothing
        return True

    def release(self) -> None:
        handle, self._handle, self._identity = self._handle, None, None
        if handle is None:
            return
        try:
            _unlock_byte(handle, self.LOCK_OFFSET)
        except OSError:
            pass
        finally:
            handle.close()  # closing releases the lock in any case


_REPARSE_POINT = 0x400  # FILE_ATTRIBUTE_REPARSE_POINT: symbolic links and junctions on Windows


def _is_link(path: Path) -> bool:
    """True when path exists and is a symbolic link, a junction or another reparse point."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)


def _same_plain_file(fd: int, path: Path) -> bool:
    """The open handle is a regular file with one name, and that name is `path` itself."""
    opened = os.fstat(fd)
    if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
        return False
    try:
        here = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(here.st_mode) or getattr(here, "st_file_attributes", 0) & _REPARSE_POINT:
        return False
    return (here.st_dev, here.st_ino) == (opened.st_dev, opened.st_ino)


def _lock_byte(handle, offset: int) -> None:
    if os.name == "nt":
        import msvcrt
        handle.seek(offset)
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)  # raises OSError when held
    else:
        import fcntl
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock_byte(handle, offset: int) -> None:
    if os.name == "nt":
        import msvcrt
        handle.seek(offset)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class BlobStore:
    """Encrypted blobs named by the hex SHA-256 of their ciphertext, under blobs/xx/.

    The name is the ledger's cipher_hash: it is already public and, being a hash of
    ciphertext under a fresh key, it cannot confirm any guess about the plaintext.
    """

    def __init__(self, root: Path):
        self.root = Path(root)

    def path(self, cipher_hash: str) -> Path:
        if len(cipher_hash) != 64 or any(c not in "0123456789abcdef" for c in cipher_hash):
            raise ValueError("cipher hash must be 64 lowercase hex characters")
        return self.root / cipher_hash[:2] / cipher_hash

    def write(self, cipher_hash: str, data: bytes, *, durable: bool = True) -> tuple[Path, list[Path]]:
        """Write one blob. Returns its path and the directories whose entries changed.

        Durable: the file and its directory entries (shard, and the blobs directory when the
        shard is new) are synced before returning. Not durable: the caller passes the
        returned paths to sync() before writing any record that names the blob.
        """
        target = self.path(cipher_hash)
        dirs = [target.parent] + ([self.root] if not target.parent.exists() else [])
        atomic_write(target, data, durable=durable)
        if durable:
            for directory in dirs[1:]:
                fsync_dir(directory)
        return target, dirs

    def sync(self, files: list[Path], dirs: set[Path]) -> None:
        """fsync files, then the directories that received them (POSIX needs both)."""
        for target in files:
            fsync_file(target)
        for directory in sorted(dirs, key=lambda p: len(p.parts), reverse=True):
            fsync_dir(directory)

    def read(self, cipher_hash: str) -> bytes:
        return read_bytes(self.path(cipher_hash))

    def exists(self, cipher_hash: str) -> bool:
        return self.path(cipher_hash).is_file()

    def names(self) -> set[str]:
        if not self.root.is_dir():
            return set()
        return {p.name for p in self.root.glob("??/*") if p.is_file() and not p.name.startswith(".")}
