"""Continuous capture: the watcher on a real encrypted vault, the command line, the server."""
from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from empreinte import crypto, watch
from empreinte.api import VaultError
from empreinte.cli import BUSY, main, session_for
from empreinte.vault import Vault
from empreinte.watch import Watcher, add_folder, load_folders, remove_folder
from test_server import Harness, ids

PASS = "une phrase de passe de test"


class Clock:
    def __init__(self) -> None:
        self.now = time.time()

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def write(path: Path, text: str, at: float) -> None:
    """Write a file and give it the modification time `at` (the test clock)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    os.utime(path, (at, at))


@pytest.fixture
def vault(tmp_path):
    v = Vault.create(tmp_path / "coffre", PASS, kdf_params=crypto.TEST_KDF)
    yield v
    v.lock()


def watcher_for(vault, folder: Path, clock: Clock, **kw) -> Watcher:
    add_folder(vault, folder, forbidden=(vault.path,))
    w = Watcher(quiet=60, clock=clock, **kw)
    w.load(vault)
    return w


def puts(vault) -> int:
    return sum(1 for r in vault.ledger() if r.kind == "put")


def test_created_modified_twice_then_deleted(vault, tmp_path):
    clock, folder = Clock(), tmp_path / "notes"
    folder.mkdir()
    w = watcher_for(vault, folder, clock)
    write(folder / "a.md", "# A\n\npremier jet", clock.now)
    assert w.poll(vault) == []  # being written: waits for the quiet period
    clock.advance(59)
    assert w.poll(vault) == []
    clock.advance(2)
    [first] = w.poll(vault)
    assert (first.path, first.version) == ("a.md", 1)
    entry = vault.find("a.md")
    assert entry.title == "A" and vault.read(entry.entry_id) == "# A\n\npremier jet".encode()

    clock.advance(5)
    write(folder / "a.md", "# A\n\ndeuxième jet", clock.now)
    assert w.poll(vault) == []
    clock.advance(30)
    write(folder / "a.md", "# A\n\ntroisième jet, plus long", clock.now)  # again within the quiet period
    assert w.poll(vault) == []
    clock.advance(59)
    assert w.poll(vault) == []  # the quiet period restarted at the second change
    clock.advance(2)
    [second] = w.poll(vault)
    assert second.version == 2 and puts(vault) == 2  # one version for two quick changes
    assert vault.read(entry.entry_id) == "# A\n\ntroisième jet, plus long".encode()
    assert vault.versions(entry.entry_id)[-1].source_mtime is not None  # file date as claimed time

    (folder / "a.md").unlink()
    clock.advance(120)
    assert w.poll(vault) == []
    assert vault.find("a.md") is not None and [r.kind for r in vault.ledger()] == ["put", "put"]


def test_burst_of_500_files_then_nothing_is_read_again(vault, tmp_path, monkeypatch):
    clock, folder = Clock(), tmp_path / "rafale"
    for i in range(500):
        write(folder / f"d{i // 50}" / f"n{i:03d}.md", f"note {i}", clock.now - 3600)  # quiet for an hour
    (folder / ".cache").mkdir()
    write(folder / ".cache" / "skip.md", "hidden", clock.now - 3600)  # skipped like the importer skips it
    w = watcher_for(vault, folder, clock)
    started = time.perf_counter()
    captures = w.poll(vault)
    elapsed = time.perf_counter() - started
    assert len(captures) == 500 and puts(vault) == 500 and vault.verify().ok
    assert elapsed < 60
    reads = []
    real = watch.read_source
    monkeypatch.setattr(watch, "read_source", lambda *a: reads.append(a) or real(*a))
    clock.advance(600)
    assert w.poll(vault) == [] and reads == []  # unchanged size and date: no file is opened


def test_a_file_that_keeps_changing_is_captured_once_quiet(vault, tmp_path):
    clock, folder = Clock(), tmp_path / "journal"
    folder.mkdir()
    w = watcher_for(vault, folder, clock)
    for minute in range(10):  # typed into every ten seconds for ten minutes
        for _ in range(6):
            write(folder / "jour.md", f"ligne {clock.now}", clock.now)
            assert w.poll(vault) == []
            clock.advance(10)
    clock.advance(61)
    assert len(w.poll(vault)) == 1 and puts(vault) == 1


def test_an_unstable_read_waits_for_another_quiet_period(vault, tmp_path, monkeypatch):
    clock, folder = Clock(), tmp_path / "n"
    write(folder / "a.md", "x", clock.now - 3600)
    w = watcher_for(vault, folder, clock)

    def unstable(*args):
        raise OSError("unstable during read")
    monkeypatch.setattr(watch, "read_source", unstable)
    assert w.poll(vault) == [] and "unstable" in w.last_error
    monkeypatch.undo()
    clock.advance(30)
    assert w.poll(vault) == []  # the quiet period restarted
    clock.advance(31)
    assert len(w.poll(vault)) == 1


def test_lock_during_a_capture_records_nothing_and_loses_nothing(tmp_path):
    clock, folder = Clock(), tmp_path / "n"
    write(folder / "a.md", "avant le verrouillage", clock.now - 3600)
    v = Vault.create(tmp_path / "coffre", PASS, kdf_params=crypto.TEST_KDF)
    w = watcher_for(v, folder, clock)
    ready = w.read(w.scan())
    assert len(ready) == 1
    v.lock()  # between the read and the commit
    with pytest.raises(VaultError):
        w.commit(v, ready)
    again = Vault.open(tmp_path / "coffre", PASS)
    try:
        assert again.ledger() == []
        w2 = Watcher(quiet=60, clock=clock)
        w2.load(again)  # the state was not marked: the file is captured by the next session
        assert [c.path for c in w2.poll(again)] == ["a.md"]
    finally:
        again.lock()


def test_restart_remembers_folders_and_reads_only_what_changed(tmp_path, monkeypatch):
    clock, folder = Clock(), tmp_path / "n"
    write(folder / "a.md", "a", clock.now - 3600)
    write(folder / "b.md", "b", clock.now - 3600)
    path = tmp_path / "coffre"
    v = Vault.create(path, PASS, kdf_params=crypto.TEST_KDF)
    w = watcher_for(v, folder, clock)
    assert len(w.poll(v)) == 2
    v.lock()
    write(folder / "b.md", "b modifiée pendant la fermeture", clock.now - 1800)
    v = Vault.open(path, PASS)
    try:
        assert [f.path for f in load_folders(v)] == [str(folder.resolve())]
        w = Watcher(quiet=60, clock=clock)
        w.load(v)
        reads = []
        real = watch.read_source
        monkeypatch.setattr(watch, "read_source", lambda root, source, n: reads.append(source.relative_path)
                            or real(root, source, n))
        [capture] = w.poll(v)
        assert capture.path == "b.md" and capture.version == 2 and reads == ["b.md"]
    finally:
        v.lock()


def test_folders_are_stored_encrypted(tmp_path):
    folder = tmp_path / "dossier-tres-prive"
    folder.mkdir()
    path = tmp_path / "coffre"
    v = Vault.create(path, PASS, kdf_params=crypto.TEST_KDF)
    add_folder(v, folder)
    v.lock()
    on_disk = b"".join(p.read_bytes() for p in path.rglob("*") if p.is_file())
    assert b"dossier-tres-prive" not in on_disk


def test_add_folder_refuses_overlaps_duplicates_and_shared_prefixes(vault, tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    with pytest.raises(ValueError, match="absolu"):
        add_folder(vault, "relatif")
    with pytest.raises(ValueError, match="existe pas"):
        add_folder(vault, tmp_path / "absent")
    with pytest.raises(ValueError, match="archive"):
        add_folder(vault, tmp_path, forbidden=(vault.path,))  # would capture the vault itself
    with pytest.raises(ValueError, match="archive"):
        add_folder(vault, vault.path / "blobs", forbidden=(vault.path,))
    add_folder(vault, a)
    with pytest.raises(ValueError, match="déjà suivi"):
        add_folder(vault, a)
    with pytest.raises(ValueError, match="dossier logique"):
        add_folder(vault, b)  # same (empty) prefix: same logical paths
    with pytest.raises(ValueError, match="dossier logique"):
        add_folder(vault, b, "Autre")
    assert remove_folder(vault, a) == []
    with pytest.raises(ValueError):
        remove_folder(vault, a)


def test_prefix_files_captures_under_a_logical_folder(vault, tmp_path):
    clock, folder = Clock(), tmp_path / "code"
    write(folder / "x.py", "print(1)\n", clock.now - 3600)
    add_folder(vault, folder, "Projets/code")
    w = Watcher(quiet=60, clock=clock)
    w.load(vault)
    [capture] = w.poll(vault)
    assert capture.path == "Projets/code/x.py" and vault.find("Projets/code/x.py").kind == "code"


# ------------------------------------------------------------- one writer per vault


def test_second_writer_is_refused_clearly(tmp_path, monkeypatch, capsys):
    path, folder = tmp_path / "coffre", tmp_path / "n"
    folder.mkdir()
    first = Vault.create(path, PASS, kdf_params=crypto.TEST_KDF)  # holds the writer lock
    try:
        monkeypatch.setenv("EMPREINTE_PASSPHRASE", PASS)
        with pytest.raises(SystemExit) as exc:
            main(["watch", str(path), str(folder)])
        assert str(exc.value) == BUSY
        session = session_for(path, kdf_params=crypto.TEST_KDF)
        h = Harness(session, None)
        try:
            status, body = h.unlock(PASS)
            assert status == 409 and "déjà ouverte en écriture" in body["message"]
            assert h.server.app.active is None
        finally:
            h.close()
    finally:
        first.lock()


def test_watch_command_refuses_a_vault_the_server_writes(tmp_path, monkeypatch):
    path, folder = tmp_path / "coffre", tmp_path / "n"
    folder.mkdir()
    Vault.create(path, PASS, kdf_params=crypto.TEST_KDF).lock()
    h = Harness(session_for(path, kdf_params=crypto.TEST_KDF), None)
    try:
        assert h.unlock(PASS)[0] == 200
        monkeypatch.setenv("EMPREINTE_PASSPHRASE", PASS)
        with pytest.raises(SystemExit) as exc:
            main(["watch", str(path), str(folder)])
        assert "déjà ouverte en écriture" in str(exc.value)
    finally:
        h.close()


# --------------------------------------------------------------------------- server


def wait_for(predicate, timeout: float = 10.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return True
        time.sleep(0.05)
    return False


@pytest.fixture
def served(tmp_path):
    path = tmp_path / "coffre"
    Vault.create(path, PASS, kdf_params=crypto.TEST_KDF).lock()
    session = session_for(path, kdf_params=crypto.TEST_KDF)
    session.make_watcher = lambda: Watcher(quiet=0.3, interval=0.05)
    h = Harness(session, None, idle_timeout=600)
    yield h, path
    h.close()


def test_server_watches_remembered_folders_and_stops_on_every_lock(served, tmp_path):
    h, path = served
    folder = tmp_path / "notes"
    folder.mkdir()
    assert h.unlock(PASS)[0] == 200
    status = h.call("GET", "/api/status")[1]
    assert status["features"]["watch"] and status["watch"]["folders"] == []
    code, body, _ = h.call("POST", "/api/watch", {"action": "add", "path": str(folder)})
    assert code == 200 and body["folders"][0]["path"] == str(folder.resolve())
    assert h.call("POST", "/api/watch", {"action": "add", "path": str(path)})[0] == 400  # the vault itself
    (folder / "a.md").write_text("# A\n\ncapturée par le serveur", encoding="utf-8")
    assert wait_for(lambda: "a.md" in ids(h))
    status = h.call("GET", "/api/status")[1]
    assert status["watch"]["captures"] == 1 and status["watch"]["last_capture"]
    graph = h.call("GET", "/api/graph")[1]
    assert [n["path"] for n in graph["nodes"]] == ["a.md"]  # the workspace was refreshed

    # Lock button: the thread ends, nothing is captured into a locked session.
    thread = h.server.app.active.watcher
    assert h.call("POST", "/api/lock", {})[0] == 200
    assert wait_for(lambda: not thread.is_alive())
    (folder / "b.md").write_text("pendant le verrouillage", encoding="utf-8")
    time.sleep(0.6)
    # Unlock again: the remembered folder is watched by a new thread, b.md is captured now.
    assert h.unlock(PASS)[0] == 200
    second = h.server.app.active.watcher
    assert second is not thread and wait_for(lambda: "b.md" in ids(h))

    # Replacement (unlock while unlocked) stops the old thread too.
    assert h.unlock(PASS)[0] == 200
    third = h.server.app.active.watcher
    assert wait_for(lambda: not second.is_alive()) and third.is_alive()
    # Idle lock.
    h.server.app.options.idle_timeout = 0.1
    assert wait_for(lambda: h.server.app.active is None)
    assert wait_for(lambda: not third.is_alive())
    h.server.app.options.idle_timeout = 600
    # Shutdown (the fixture) stops the last one: checked in the next test.


def test_server_shutdown_stops_the_watcher(tmp_path):
    path = tmp_path / "coffre"
    Vault.create(path, PASS, kdf_params=crypto.TEST_KDF).lock()
    session = session_for(path, kdf_params=crypto.TEST_KDF)
    session.make_watcher = lambda: Watcher(quiet=0.3, interval=0.05)
    h = Harness(session, None)
    assert h.unlock(PASS)[0] == 200
    thread = h.server.app.active.watcher
    h.close()
    assert wait_for(lambda: not thread.is_alive())


def test_lock_during_a_server_capture_records_nothing(served, tmp_path):
    h, path = served
    folder = tmp_path / "notes"
    folder.mkdir()
    assert h.unlock(PASS)[0] == 200
    assert h.call("POST", "/api/watch", {"action": "add", "path": str(folder)})[0] == 200
    app = h.server.app
    watcher = app.active.watcher.watcher
    real_read = watcher.read
    locked = []

    def read_then_lock(due):
        ready = real_read(due)
        if ready and not locked:
            locked.append(True)
            app.do_lock()  # the lock lands between the read (outside the lock) and the commit
        return ready
    watcher.read = read_then_lock
    (folder / "a.md").write_text("lue puis verrouillée", encoding="utf-8")
    assert wait_for(lambda: bool(locked))
    time.sleep(0.3)
    v = Vault.open(path, PASS)
    try:
        assert v.ledger() == [] and not v.held_by_another_writer
    finally:
        v.lock()


def test_watch_routes_need_the_feature_and_the_unlock_token(tmp_path):
    from test_server import make_vault, session_for as plain_session
    h = Harness(plain_session(make_vault()), None)  # no make_watcher
    try:
        h.unlock("correct horse battery")
        status = h.call("GET", "/api/status")[1]
        assert status["features"]["watch"] is False and status["watch"] is None
        assert h.call("GET", "/api/watch")[0] == 404
    finally:
        h.close()


# --------------------------------------------------- fix round after the closing audit


def test_an_unreadable_file_is_retried_with_back_off(vault, tmp_path, monkeypatch):  # closing audit
    clock, folder = Clock(), tmp_path / "notes"
    folder.mkdir()
    w = watcher_for(vault, folder, clock)
    write(folder / "verrou.md", "# Verrouillé", clock.now - 3600)
    attempts = []

    def unreadable(root, source, max_bytes):
        attempts.append(clock.now)
        raise PermissionError("accès refusé")

    monkeypatch.setattr(watch, "read_source", unreadable)
    for _ in range(3600):  # one hour of polls, one per second
        w.poll(vault)
        clock.advance(1)
    assert 3 <= len(attempts) <= 12, len(attempts)  # not one read per quiet period forever
    gaps = [b - a for a, b in zip(attempts, attempts[1:])]
    assert gaps == sorted(gaps)  # the wait grows
    assert "verrou.md" in w.summary()["last_error"]
    monkeypatch.undo()
    write(folder / "verrou.md", "# Lisible", clock.now - 120)  # the file changed: no back-off any more
    [capture] = w.poll(vault)
    assert capture.path == "verrou.md"


@pytest.mark.parametrize("batch_files,batch_bytes,poll_files,poll_bytes", [
    (2, 8, 5, 20), (3, 8, 7, 20), (2, 100, 5, 100),
])
def test_review_1_bounded_batches_and_poll(vault, tmp_path, monkeypatch,
                                         batch_files, batch_bytes, poll_files, poll_bytes):
    clock, folder = Clock(), tmp_path / "bounded"
    for i in range(7):
        write(folder / f"{i}.md", "1234", clock.now - 100)
    w = watcher_for(vault, folder, clock)
    monkeypatch.setattr(watch, "MAX_BATCH_FILES", batch_files, raising=False)
    monkeypatch.setattr(watch, "MAX_BATCH_BYTES", batch_bytes, raising=False)
    monkeypatch.setattr(watch, "MAX_POLL_FILES", poll_files, raising=False)
    monkeypatch.setattr(watch, "MAX_POLL_BYTES", poll_bytes, raising=False)
    sizes = []
    original = w.commit
    def commit(v, ready):
        sizes.append((len(ready), sum(len(r.content) for r in ready)))
        return original(v, ready)
    monkeypatch.setattr(w, "commit", commit)
    assert len(w.poll(vault)) == 5
    assert sizes == [(2, 8), (2, 8), (1, 4)]
    assert w.summary()["files_waiting"] == 2
    assert len(w.poll(vault)) == 2


def test_review_2_saved_forbidden_watch_disabled(vault):
    watch.save_folders(vault, [watch.WatchedFolder(str(vault.path))])
    w = Watcher()
    w.load(vault)
    assert w.scan() == []
    assert w.summary()["folders"][0]["enabled"] is False
    assert "archive" in w.summary()["folders"][0]["error"]


@pytest.mark.parametrize("change", ["removed", "source", "entry", "readded"])
def test_review_5_obsolete_ready(vault, tmp_path, change):
    clock, folder = Clock(), tmp_path / "queued"
    write(folder / "a.md", "old", clock.now - 100)
    w = watcher_for(vault, folder, clock)
    ready = w.read(w.scan())
    if change in {"removed", "readded"}:
        w.set_folders(vault, remove_folder(vault, folder))
        if change == "readded":
            w.set_folders(vault, add_folder(vault, folder))
    elif change == "source":
        write(folder / "a.md", "newer source", clock.now)
    else:
        vault.put("a.md", b"manual import")
    assert w.commit(vault, ready) == []
    assert puts(vault) == (1 if change == "entry" else 0)


@pytest.mark.parametrize("a,b", [("", "Work"), ("Work", "work/sub"), ("Work/sub", "WORK"), ("Work", "WORK")])
def test_review_6_prefix_overlap(vault, tmp_path, a, b):
    left, right = tmp_path / "left", tmp_path / "right"
    left.mkdir(); right.mkdir()
    add_folder(vault, left, a)
    with pytest.raises(ValueError, match="dossier logique"):
        add_folder(vault, right, b)


def test_review_10_unreadable_subtree_keeps_state(vault, tmp_path, monkeypatch):
    clock, folder = Clock(), tmp_path / "scan"
    write(folder / "sub" / "a.md", "a", clock.now - 100)
    w = watcher_for(vault, folder, clock)
    w.poll(vault)
    before = dict(w._states[w.folders[0]].known)
    original = Path.iterdir
    def denied(path):
        if path == folder / "sub":
            raise PermissionError("denied subtree")
        return original(path)
    monkeypatch.setattr(Path, "iterdir", denied)
    assert w.poll(vault) == []
    assert "denied subtree" in w.summary()["folders"][0]["error"]
    assert w._states[w.folders[0]].known == before


def test_extra_skipped_once_and_immediate_changed_retry(vault, tmp_path, monkeypatch):
    clock, folder = Clock(), tmp_path / "retry"
    write(folder / "a.md", "a", clock.now - 100)
    w = watcher_for(vault, folder, clock)
    real = watch.read_source
    monkeypatch.setattr(watch, "read_source", lambda *args: (_ for _ in ()).throw(PermissionError("denied")))
    w.poll(vault)
    clock.advance(61)
    w.poll(vault)
    assert len(w.summary()["skipped"]) == 1
    assert "denied" in w.summary()["skipped"][0]["reason"]
    monkeypatch.setattr(watch, "read_source", real)
    write(folder / "a.md", "changed", clock.now)
    assert len(w.poll(vault)) == 1
    assert w.summary()["skipped"] == []


def test_extra_backoff_reaches_ceiling(vault, tmp_path, monkeypatch):
    clock, folder = Clock(), tmp_path / "ceiling"
    write(folder / "a.md", "a", clock.now - 100)
    w = watcher_for(vault, folder, clock)
    attempts = []
    def denied(*args):
        attempts.append(clock.now)
        raise PermissionError("denied")
    monkeypatch.setattr(watch, "MAX_BACKOFF", 120)
    monkeypatch.setattr(watch, "read_source", denied)
    for _ in range(421):
        w.poll(vault)
        clock.advance(1)
    assert [b - a for a, b in zip(attempts, attempts[1:])] == [60, 120, 120, 120]
    assert len(w.summary()["skipped"]) == 1


@pytest.mark.parametrize("end", ["stop", "stale"])
def test_review_1_thread_releases_lock_and_checks_session_between_batches(vault, tmp_path, monkeypatch, end):
    clock, folder = Clock(), tmp_path / "thread"
    for i in range(5):
        write(folder / f"{i}.md", "data", clock.now - 100)
    w = watcher_for(vault, folder, clock)
    w.interval = 0
    monkeypatch.setattr(watch, "MAX_BATCH_FILES", 2)
    committed, reads = [], []
    real_read = w.read
    def read(due):
        reads.append(len(due))
        return real_read(due)
    monkeypatch.setattr(w, "read", read)
    def locked(fn):
        if committed and end == "stale":
            raise watch.Stale()
        return fn(vault)
    def captured(v, captures):
        committed.extend(captures)
        if end == "stop":
            thread.stop()
    thread = watch.WatchThread(w, locked, captured)
    thread.run()
    assert len(committed) == 2 and reads == [2] and puts(vault) == 2


def test_review_2_scanner_never_descends_into_exclusions(tmp_path, monkeypatch):
    clock = Clock()
    for name in ("vault", "exports", "notes"):
        write(tmp_path / name / "a.md", "data", clock.now)
    forbidden = (tmp_path / "vault", tmp_path / "exports")
    original = Path.iterdir
    def checked(path):
        assert path not in forbidden, "scanner descended into an exclusion"
        return original(path)
    monkeypatch.setattr(Path, "iterdir", checked)
    assert [s.relative_path for s in watch._scan(tmp_path, forbidden)] == ["notes/a.md"]


def test_review_2_saved_parent_and_export_are_disabled(vault):
    export = vault.path.parent / f"{vault.path.name}-licences"
    watch.save_folders(vault, [watch.WatchedFolder(str(vault.path.parent), "parent"),
                              watch.WatchedFolder(str(export), "exports")])
    folders = load_folders(vault)
    assert len(folders) == 2 and all(f.disabled_reason for f in folders)


def test_review_10_vanished_root_retains_known(vault, tmp_path):
    clock, folder = Clock(), tmp_path / "vanish"
    write(folder / "a.md", "data", clock.now - 100)
    w = watcher_for(vault, folder, clock)
    w.poll(vault)
    before = dict(w._states[w.folders[0]].known)
    folder.rename(tmp_path / "moved")
    assert w.poll(vault) == []
    assert "illisible" in w.summary()["folders"][0]["error"]
    assert w._states[w.folders[0]].known == before
