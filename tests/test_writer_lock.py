"""writer.lock never writes through a link, and never keeps a lock it failed to set up
(closing audit, defects 1 and 5)."""
import os
from pathlib import Path

import pytest

from empreinte import crypto
from empreinte.store import WriterLock
from empreinte.testing import stepping_clock
from empreinte.vault import Vault

PASS = "correct horse battery staple"
VICTIM = b"an unrelated file of the owner\n" * 10


def _make(path: Path) -> Vault:
    v = Vault.create(path, PASS, clock=stepping_clock(), kdf_params=crypto.TEST_KDF)
    v.put("a.md", b"alpha")
    v.lock()
    return v


def _open(path: Path) -> Vault:
    return Vault.open(path, PASS, clock=stepping_clock())


def _replace_with(path: Path, link) -> None:
    lock = path / "writer.lock"
    lock.unlink()
    link(lock)


def test_hard_linked_writer_lock_never_truncates_the_other_file(tmp_path):
    path = tmp_path / "vault"
    _make(path)
    victim = tmp_path / "victim.txt"
    victim.write_bytes(VICTIM)
    _replace_with(path, lambda lock: os.link(victim, lock))
    v = _open(path)
    try:
        assert victim.read_bytes() == VICTIM
        assert any("writer.lock" in n for n in v.notices)
        with pytest.raises(Exception, match="read-only"):
            v.put("b.md", b"b")
    finally:
        v.lock()
    assert victim.read_bytes() == VICTIM


def test_symlinked_writer_lock_never_truncates_the_target(tmp_path):
    path = tmp_path / "vault"
    _make(path)
    victim = tmp_path / "victim.txt"
    victim.write_bytes(VICTIM)
    try:
        _replace_with(path, lambda lock: os.symlink(victim, lock))
    except OSError:
        pytest.skip("this account cannot create symbolic links")
    v = _open(path)
    try:
        assert victim.read_bytes() == VICTIM
        assert any("writer.lock" in n for n in v.notices)
    finally:
        v.lock()
    assert victim.read_bytes() == VICTIM


def test_a_directory_named_writer_lock_is_refused(tmp_path):
    lock = WriterLock(tmp_path / "writer.lock")
    (tmp_path / "writer.lock").mkdir()
    assert lock.acquire() is not None
    assert not lock.held()


def test_a_failure_after_locking_releases_the_lock(tmp_path, monkeypatch):
    first = WriterLock(tmp_path / "writer.lock")

    def failing(*args):
        raise OSError("disk full")

    # Writing the informational text happens after the OS lock is taken.
    monkeypatch.setattr("empreinte.store.socket.gethostname", failing)
    with pytest.raises(OSError, match="disk full") as caught:
        first.acquire()
    monkeypatch.undo()
    assert caught.value is not None  # the traceback is still alive here
    second = WriterLock(tmp_path / "writer.lock")
    assert second.acquire() is None  # the failed attempt kept no OS lock
    second.release()


def test_a_regular_writer_lock_still_works(tmp_path):
    lock = WriterLock(tmp_path / "writer.lock")
    assert lock.acquire() is None and lock.held()
    other = WriterLock(tmp_path / "writer.lock")
    assert other.acquire() is not None
    lock.release()
    assert other.acquire() is None
    other.release()
