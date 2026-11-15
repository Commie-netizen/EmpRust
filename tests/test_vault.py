"""The encrypted vault: the shared contract, then keys, storage, crash recovery and tamper evidence."""
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from empreinte import crypto
from empreinte.api import Corrupted, NotFound, VaultError, WrongPassphrase
from empreinte.testing import stepping_clock
from empreinte.vault import Vault
from vault_contract import *  # noqa: F401,F403

PASS = "correct horse battery staple"
SECRETS = (b"Plan secret", b"confidentiel", b"secret/plan", b"contenu", b"plan.md")


def make(path: Path, **kwargs) -> Vault:
    return Vault.create(path, PASS, clock=stepping_clock(), kdf_params=crypto.TEST_KDF, **kwargs)


def reopen(path: Path) -> Vault:
    return Vault.open(path, PASS, clock=stepping_clock(datetime(2026, 6, 1, tzinfo=timezone.utc)))


def die(v: Vault) -> None:
    """What the operating system does when a process crashes: its lock handle is closed.
    Nothing else is cleaned up (keys, pending state and files stay as they were)."""
    v._writer.release()


CHILD = """
import os, sys
sys.path.insert(0, sys.argv[1])
from empreinte.vault import Vault
v = Vault.open(sys.argv[2], sys.argv[3])
assert not v.notices, v.notices
v.put("child.md", b"written by the child")
print("ready", flush=True)
if sys.argv[4] == "crash":
    os._exit(0)  # no close(), no lock(): like a crash
sys.stdin.readline()  # hold the lock until the parent says so
"""


def child(path: Path, mode: str):
    import subprocess
    import sys
    src = str(Path(__file__).resolve().parents[1] / "src")
    proc = subprocess.Popen([sys.executable, "-c", CHILD, src, str(path), PASS, mode], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, text=True)
    assert proc.stdout.readline().strip() == "ready"
    return proc


@pytest.fixture
def vault(tmp_path):
    return make(tmp_path / "vault")


@pytest.fixture
def filled(tmp_path):
    v = make(tmp_path / "vault")
    v.put("secret/plan.md", "contenu très secret".encode(), title="Plan secret", tags=["confidentiel"])
    v.put("secret/plan.md", b"contenu v2")
    v.put("notes/b.md", b"bravo")
    return v


# ------------------------------------------------------------------ keys


def test_open_with_passphrase_and_wrong_passphrase(filled):
    path = filled.path
    filled.lock()
    with pytest.raises(VaultError):
        filled.read("0" * 32)
    with pytest.raises(WrongPassphrase) as info:
        Vault.open(path, "wrong")
    assert "wrong" not in str(info.value).replace("wrong passphrase", "")
    again = reopen(path)
    assert [m.path for m in again.entries()] == ["notes/b.md", "secret/plan.md"]
    meta = again.find("secret/plan.md")
    assert meta.title == "Plan secret" and meta.tags == [] and meta.n_versions == 2  # tags are replaced by each put
    assert again.read(meta.entry_id, 1) == "contenu très secret".encode()
    assert again.verify().ok


def test_recovery_key_and_change_passphrase(filled):
    path = filled.path
    key = filled.take_recovery_key()
    assert key and filled.recovery_key is None and filled.take_recovery_key() is None
    filled.change_passphrase(PASS, "new passphrase")
    with pytest.raises(WrongPassphrase):
        filled.change_passphrase("not it", "x")
    filled.lock()
    with pytest.raises(WrongPassphrase):
        Vault.open(path, PASS)
    second = Vault.open(path, "new passphrase")
    assert second.verify().ok
    second.lock()
    recovered = Vault.open_with_recovery_key(path, key.lower().replace("-", " "))
    recovered.change_passphrase(None, "third")
    reader = Vault.open(path, "third")  # read-only: `recovered` is the writer
    assert reader.find("notes/b.md") is not None and reader.notices
    reader.lock()
    with pytest.raises(VaultError):
        Vault.open_with_recovery_key(path, key[:3] + ("A" if key[3] != "A" else "B") + key[4:])
    new_key = recovered.rotate_recovery_key()
    with pytest.raises(WrongPassphrase):
        Vault.open_with_recovery_key(path, key)
    assert Vault.open_with_recovery_key(path, new_key).find("notes/b.md") is not None


def test_change_passphrase_requires_old_unless_recovery(filled):
    with pytest.raises(WrongPassphrase):
        filled.change_passphrase(None, "x")


def test_changing_passphrase_does_not_reencrypt(filled):
    before = {p.name: p.read_bytes() for p in (filled.path / "blobs").rglob("*") if p.is_file()}
    catalog = (filled.path / "catalog.bin").read_bytes()
    filled.change_passphrase(PASS, "other")
    after = {p.name: p.read_bytes() for p in (filled.path / "blobs").rglob("*") if p.is_file()}
    assert before == after and (filled.path / "catalog.bin").read_bytes() == catalog


def test_create_refuses_non_empty_directory_and_empty_passphrase(tmp_path):
    (tmp_path / "x").mkdir()
    (tmp_path / "x" / "file").write_text("x", encoding="utf-8")
    with pytest.raises(VaultError):
        make(tmp_path / "x")
    with pytest.raises(VaultError):
        Vault.create(tmp_path / "y", "", kdf_params=crypto.TEST_KDF)
    with pytest.raises(VaultError):
        Vault.open(tmp_path / "nothing", PASS)


# ------------------------------------------------------------------ on disk


def test_nothing_secret_on_disk(filled):
    filled.aux_put("index/confidentiel", b"contenu index")
    names = " ".join(str(p.relative_to(filled.path)) for p in filled.path.rglob("*"))
    for word in ("plan", "secret", "notes", "confidentiel", "index", ".md"):
        assert word not in names
    for file in filled.path.rglob("*"):
        if file.is_file():
            data = file.read_bytes()
            for secret in SECRETS + (b"bravo", "très".encode()):
                assert secret not in data, (file.name, secret)
    header = json.loads((filled.path / "header.json").read_text(encoding="utf-8"))
    assert set(header) == {"format", "format_version", "vault_id", "public_key", "kdf", "master_key_wraps", "identity"}


def test_blob_names_are_cipher_hashes(filled):
    hashes = {r.cipher_hash for r in filled.ledger() if r.cipher_hash}
    on_disk = {p.name for p in (filled.path / "blobs").rglob("*") if p.is_file()}
    assert hashes == on_disk


def test_aux_survives_reopen_and_is_bound_to_its_key(filled):
    filled.aux_put("a", b"one")
    filled.aux_put("b", b"two")
    path = filled.path
    a_file, _ = filled._aux_path("a")
    b_file, _ = filled._aux_path("b")
    assert len([p for p in (path / "aux").rglob("*") if p.is_file()]) == 2
    filled.lock()
    v = reopen(path)
    assert v.aux_get("a") == b"one"
    b_file.write_bytes(a_file.read_bytes())  # a value copied under another key's name
    with pytest.raises(Corrupted):
        v.aux_get("b")


def test_batch_writes_once_and_is_durable(tmp_path):
    v = make(tmp_path / "v")
    writes = []
    original = v._write_catalog
    v._write_catalog = lambda: (writes.append(1), original())
    with v.batch():
        for i in range(200):
            v.put(f"import/{i:04d}.md", f"note {i}".encode())
        assert len(v.entries()) == 200 and v.read(v.find("import/0007.md").entry_id) == b"note 7"
        assert (tmp_path / "v" / "ledger.jsonl").read_bytes() == b""
    assert writes == [1]
    path = v.path
    v.lock()
    again = reopen(path)
    assert len(again.entries()) == 200 and again.verify().ok


def test_lock_inside_a_batch_keeps_what_was_put(tmp_path):
    v = make(tmp_path / "v")
    with v.batch():
        v.put("a.md", b"a")
        v.lock()
    assert reopen(tmp_path / "v").find("a.md") is not None


def test_entries_fast_with_ten_thousand(tmp_path):
    v = make(tmp_path / "v")
    stamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
    from empreinte.vault import _EntryState, _VersionState
    for i in range(10_000):
        eid = f"{i:032x}"
        v._entries[eid] = _EntryState(entry_id=eid, path=f"n/{i:05d}.md", title=str(i), kind="note",
                                      media_type="text/markdown", tags=[],
                                      versions=[_VersionState(1, i, stamp, 1, "0" * 64, "0" * 64, "0" * 64)])
        v._by_path[f"n/{i:05d}.md"] = eid
    v._sorted_cache = None
    v.entries()
    start = time.perf_counter()
    for _ in range(20):
        assert len(v.entries()) == 10_000
        v.entry(f"{1234:032x}")
    assert (time.perf_counter() - start) / 20 < 0.01


def test_locked_vault_refuses_everything(filled):
    filled.lock()
    for call in (lambda: filled.put("x.md", b"x"), filled.ledger, filled.verify, lambda: filled.aux_get("a"),
                 lambda: filled.change_passphrase(PASS, "x")):
        with pytest.raises(VaultError):
            call()
    assert filled.locked and filled._keys is None and filled._signer is None


def test_removed_history_stays_readable(filled):
    meta = filled.find("notes/b.md")
    filled.remove(meta.entry_id)
    assert filled.read(meta.entry_id) == b"bravo"
    with pytest.raises(NotFound):
        filled.remove(meta.entry_id)
    v2 = filled.put("notes/b.md", b"bravo")
    assert v2.entry_id != meta.entry_id and v2.version == 1
    assert filled.verify().ok


def test_naive_clock_is_refused(tmp_path):
    v = Vault.create(tmp_path / "v", PASS, clock=lambda: datetime(2026, 1, 1), kdf_params=crypto.TEST_KDF)
    with pytest.raises(VaultError):
        v.put("a.md", b"a")


# ------------------------------------------------------------------ crash recovery


class Crash(Exception):
    pass


def test_crash_after_blob_before_ledger(filled):
    path = filled.path
    def crash(records):
        raise Crash()
    filled._append_records = crash
    with pytest.raises(Crash):
        filled.put("new.md", b"lost")
    die(filled)  # the process is gone; its stale writer.lock is taken over
    v = reopen(path)
    assert v.find("new.md") is None and len(v.ledger()) == 3
    report = v.verify()
    assert report.ok, report.errors
    v.put("new.md", b"again")
    assert reopen(path).verify().ok


def test_crash_after_ledger_before_catalog(filled):
    path = filled.path
    def crash():
        raise Crash()
    filled._write_catalog = crash
    with pytest.raises(Crash):
        filled.put("new.md", b"kept", title="Kept", tags=["t"])
    with pytest.raises(Crash):
        filled.remove(filled.find("notes/b.md").entry_id)
    die(filled)
    v = reopen(path)
    meta = v.find("new.md")
    assert meta is not None and meta.title == "Kept" and meta.tags == ["t"]
    assert v.read(meta.entry_id) == b"kept" and v.find("notes/b.md") is None
    assert len(v.ledger()) == 5 and v.verify().ok
    assert reopen(path).verify().ok  # the replayed catalog was saved


def test_crash_after_license_record_before_catalog(filled):
    path = filled.path
    filled._write_catalog = lambda: (_ for _ in ()).throw(Crash())
    with pytest.raises(Crash):
        filled.grant("X", [(filled.find("notes/b.md").entry_id, None)], usage="u")
    die(filled)
    v = reopen(path)
    assert len(v.licenses()) == 1 and v.verify().ok


def test_torn_last_line_is_repaired(filled):
    path = filled.path
    filled.lock()
    with open(path / "ledger.jsonl", "ab") as handle:
        handle.write(b'{"seq":3,"kind":"pu')
    v = reopen(path)
    assert len(v.ledger()) == 3 and v.verify().ok and v.notices
    assert (path / "ledger.jsonl").read_bytes().endswith(b"}\n")


def test_lost_catalog_is_rebuilt(filled):
    path = filled.path
    grant = filled.grant("X", [(filled.find("notes/b.md").entry_id, None)], usage="u")
    filled.remove(filled.find("notes/b.md").entry_id)
    filled.lock()
    (path / "catalog.bin").unlink()
    v = reopen(path)
    assert [m.path for m in v.entries()] == ["secret/plan.md"]
    assert v.find("secret/plan.md").title == "Plan secret"
    assert [g.license_id for g in v.licenses()] == [grant.license_id]
    assert v.verify().ok


def test_sync_client_holding_a_file_is_retried(filled, monkeypatch):
    import os as _os
    real = _os.replace
    calls = []
    def flaky(src, dst):
        calls.append(dst)
        if len(calls) < 3:
            raise PermissionError("held by sync client")
        return real(src, dst)
    monkeypatch.setattr("empreinte.store.os.replace", flaky)
    filled.put("x.md", b"x")
    assert len(calls) >= 3 and filled.verify().ok


# ------------------------------------------------------------------ tamper evidence


def _lines(path: Path) -> list[bytes]:
    return (path / "ledger.jsonl").read_bytes().splitlines(keepends=True)


def _write_lines(path: Path, lines: list[bytes]) -> None:
    (path / "ledger.jsonl").write_bytes(b"".join(lines))


def _tampered(filled, change) -> list[str]:
    path = filled.path
    filled.lock()
    change(path)
    report = reopen(path).verify()
    assert not report.ok
    return report.errors


def test_flipped_byte_in_a_blob(filled):
    target = filled.ledger()[1].cipher_hash
    def change(path):
        blob = path / "blobs" / target[:2] / target
        data = bytearray(blob.read_bytes())
        data[60] ^= 1
        blob.write_bytes(bytes(data))
    errors = _tampered(filled, change)
    assert "record 1: blob does not match cipher_hash" in errors


def test_edited_ledger_line(filled):
    def change(path):
        lines = _lines(path)
        lines[1] = lines[1].replace(b'"size":10', b'"size":11')
        _write_lines(path, lines)
    errors = _tampered(filled, change)
    assert "record 1: record_hash does not match its content" in errors


def test_deleted_ledger_line(filled):
    errors = _tampered(filled, lambda p: _write_lines(p, [l for i, l in enumerate(_lines(p)) if i != 1]))
    assert any(e.startswith("record 1: seq is 2") for e in errors)
    assert "record 1: prev_hash does not match record 0" in errors


def test_inserted_ledger_line(filled):
    def change(path):
        lines = _lines(path)
        _write_lines(path, lines[:2] + [lines[1]] + lines[2:])
    errors = _tampered(filled, change)
    assert any(e.startswith("record 2: seq is 1") for e in errors)


def test_reordered_ledger_lines(filled):
    def change(path):
        lines = _lines(path)
        _write_lines(path, [lines[0], lines[2], lines[1]])
    errors = _tampered(filled, change)
    assert any(e.startswith("record 1: seq is 2") for e in errors)


def test_replaced_public_key(filled):
    def change(path):
        header = json.loads((path / "header.json").read_text(encoding="utf-8"))
        header["public_key"] = crypto.public_hex(crypto.new_identity())
        (path / "header.json").write_text(json.dumps(header), encoding="utf-8")
    errors = _tampered(filled, change)
    assert "header: public key does not match the vault identity key" in errors


def test_resigned_chain_with_another_key_is_caught(filled):
    """An attacker who replaces the key and re-signs every record still fails verify()."""
    from empreinte.ledger import make_record, record_to_line
    records = filled.ledger()
    def change(path):
        rogue = crypto.new_identity()
        rogue_hex = crypto.public_hex(rogue)
        prev, out = "0" * 64, []
        for r in records:
            fields = r.model_dump(exclude={"seq", "kind", "prev_hash", "record_hash", "signature", "timestamp"})
            new = make_record(seq=r.seq, kind=r.kind, prev_hash=prev, timestamp=r.timestamp, signer=rogue,
                              public_key_hex=rogue_hex, **fields)
            out.append(record_to_line(new))
            prev = new.record_hash
        _write_lines(path, out)
        header = json.loads((path / "header.json").read_text(encoding="utf-8"))
        header["public_key"] = rogue_hex
        (path / "header.json").write_text(json.dumps(header), encoding="utf-8")
    errors = _tampered(filled, change)
    assert "record 0: signature invalid" in errors and "header: public key does not match the vault identity key" in errors


def test_blob_moved_to_another_entry(filled):
    records = filled.ledger()
    a, b = records[0].cipher_hash, records[2].cipher_hash
    def change(path):
        (path / "blobs" / b[:2] / b).write_bytes((path / "blobs" / a[:2] / a).read_bytes())
    errors = _tampered(filled, change)
    assert "record 2: blob does not match cipher_hash" in errors


def test_blob_moved_with_its_name_is_caught_by_binding(filled):
    """Even if the ledger pointed entry B at entry A's blob, decryption binds the blob to A."""
    records = filled.ledger()
    a, b = records[0], records[2]
    data = (filled.path / "blobs" / a.cipher_hash[:2] / a.cipher_hash).read_bytes()
    with pytest.raises(Corrupted):
        crypto.open_blob(filled._keys.content, data,
                         crypto.blob_binding(filled._vault_id, f"content:{b.entry_id}:{b.version}"),
                         crypto.BLOB_CONTENT)


def test_rollback_is_flagged_by_the_catalog(filled):
    path = filled.path
    last = filled.ledger()[-1].cipher_hash
    def change(path):
        _write_lines(path, _lines(path)[:-1])
        (path / "blobs" / last[:2] / last).unlink()
    errors = _tampered(filled, change)
    assert any(e.startswith("rollback: the catalog recorded 3 records") for e in errors)
    with pytest.raises(Corrupted):
        reopen(path).put("x.md", b"x")


def test_appended_forged_record_is_not_replayed(filled):
    def change(path):
        lines = _lines(path)
        forged = json.loads(lines[-1])
        forged.update(seq=3, prev_hash=forged["record_hash"])
        _write_lines(path, lines + [json.dumps(forged).encode() + b"\n"])
    errors = _tampered(filled, change)
    assert any("not replayed" in e for e in errors)


def test_corrupted_catalog_refuses_to_open(filled):
    path = filled.path
    filled.lock()
    data = bytearray((path / "catalog.bin").read_bytes())
    data[-1] ^= 1
    (path / "catalog.bin").write_bytes(bytes(data))
    with pytest.raises(Corrupted):
        reopen(path)


def test_tampered_kdf_parameters_do_not_open(filled):
    path = filled.path
    filled.lock()
    header = json.loads((path / "header.json").read_text(encoding="utf-8"))
    header["kdf"]["iterations"] = 2
    (path / "header.json").write_text(json.dumps(header), encoding="utf-8")
    with pytest.raises(WrongPassphrase):
        reopen(path)


# ------------------------------------------------------------------ review fixes


def test_one_writer_at_a_time(filled):
    """Finding 5: a second instance opens read-only; the first keeps writing."""
    second = reopen(filled.path)
    assert any("another writer" in n for n in second.notices)
    with pytest.raises(VaultError, match="read-only"):
        second.put("x.md", b"x")
    with pytest.raises(VaultError, match="read-only"):
        second.change_passphrase(PASS, "other")
    filled.put("y.md", b"y")
    second.lock()
    filled.lock()
    third = reopen(filled.path)
    third.put("z.md", b"z")
    assert third.verify().ok and len(third.ledger()) == 5


def test_a_crashed_writer_releases_its_lock(filled):
    """N5: the lock is held by the operating system, so a crash frees it; nobody deletes it."""
    path = filled.path
    filled.lock()
    proc = child(path, "crash")
    proc.wait(timeout=60)
    assert (path / "writer.lock").exists()  # the file stays; only the OS lock was released
    v = reopen(path)
    assert not v.notices
    v.put("after.md", b"after")
    assert v.find("child.md") is not None and v.verify().ok


def test_a_live_writer_in_another_process_makes_us_read_only(filled):
    """N5, defect 4: while another process writes, this instance can write nothing at all."""
    path = filled.path
    filled.lock()
    proc = child(path, "hold")
    try:
        v = reopen(path)
        assert any("another writer" in n for n in v.notices)
        before = {p: p.read_bytes() for p in path.rglob("*") if p.is_file() and p.name != "writer.lock"}
        for write in (lambda: v.put("x.md", b"x"), lambda: v.aux_put("k", b"v"), lambda: v.remove(v.find("child.md").entry_id),
                      lambda: v.change_passphrase(PASS, "other")):
            with pytest.raises(VaultError, match="read-only"):
                write()
        with v.batch():
            pass  # an empty batch flushes nothing
        v.lock()
        after = {p: p.read_bytes() for p in path.rglob("*") if p.is_file() and p.name != "writer.lock"}
        assert after == before
    finally:
        proc.communicate("\n", timeout=60)


def test_only_one_of_two_contenders_becomes_writer(filled):
    """Defect 1: after the writer is gone, two openers cannot both win."""
    path = filled.path
    die(filled)
    a, b = reopen(path), reopen(path)
    writable = [v for v in (a, b) if not v.notices]
    assert len(writable) == 1
    writable[0].put("one.md", b"1")
    other = b if writable[0] is a else a
    with pytest.raises(VaultError, match="read-only"):
        other.put("two.md", b"2")


def test_close_then_reopen_in_the_same_process_writes(filled):
    """Defect 3: a server replacing a session closes the old Vault first."""
    path = filled.path
    stale = reopen(path)  # opened while `filled` still writes: read-only
    assert stale.notices
    stale.close()
    filled.close()
    replacement = reopen(path)
    assert not replacement.notices
    replacement.put("new-session.md", b"ok")
    with pytest.raises(VaultError):
        filled.put("old-session.md", b"no")  # closed: keys gone


def test_reader_never_writes_its_replayed_catalog(filled):
    """Defect 4: a reader that replayed records in memory must not save catalog.bin."""
    path = filled.path
    def crash():
        raise Crash()
    real = filled._write_catalog
    filled._write_catalog = crash
    with pytest.raises(Crash):
        filled.put("late.md", b"late")  # ledger written, catalog not: catalog lags
    filled._write_catalog = real
    catalog = (path / "catalog.bin").read_bytes()
    reader = reopen(path)  # filled still holds the lock
    assert reader.find("late.md") is not None  # replayed in memory
    with reader.batch():
        pass
    reader.lock()
    assert (path / "catalog.bin").read_bytes() == catalog


def test_writes_from_another_copy_are_detected_before_appending(filled, tmp_path):
    """Finding 5: a sync client brings in another machine's records; nothing is forked."""
    import shutil
    fork_path = tmp_path / "fork"
    shutil.copytree(filled.path, fork_path)
    fork = Vault.open(fork_path, PASS)  # a copied lock file is not a held lock
    fork.put("from-the-other-machine.md", b"other")
    fork.lock()
    shutil.copyfile(fork_path / "ledger.jsonl", filled.path / "ledger.jsonl")
    with pytest.raises(Corrupted, match="changed on disk"):
        filled.put("local.md", b"local")
    with pytest.raises(Corrupted):
        filled.put("again.md", b"again")  # now read-only
    lines = (filled.path / "ledger.jsonl").read_bytes().splitlines()
    assert len(lines) == 4  # no forked line was appended


def test_verify_rereads_the_disk(filled):
    """Finding 6: changes made after open are seen by verify(), which also blocks writes."""
    path = filled.path
    lines = (path / "ledger.jsonl").read_bytes().splitlines(keepends=True)
    (path / "ledger.jsonl").write_bytes(b"".join(lines[:-1]))
    errors = filled.verify().errors
    assert any(e.startswith("ledger.jsonl on disk differs from the ledger in memory from record 2") for e in errors)
    assert any(e.startswith("rollback") for e in errors)
    with pytest.raises(Corrupted):
        filled.put("x.md", b"x")


def test_verify_sees_a_changed_header(filled):
    header = json.loads((filled.path / "header.json").read_text(encoding="utf-8"))
    header["public_key"] = crypto.public_hex(crypto.new_identity())
    (filled.path / "header.json").write_text(json.dumps(header), encoding="utf-8")
    errors = filled.verify().errors
    assert "header.json on disk differs from the header this vault opened" in errors
    assert "header: public key does not match the vault identity key" in errors


def test_verify_sees_a_replaced_catalog(filled):
    old = (filled.path / "catalog.bin").read_bytes()
    filled.put("x.md", b"x")
    (filled.path / "catalog.bin").write_bytes(old)
    errors = filled.verify().errors
    assert "catalog.bin on disk differs from the catalog in memory" in errors


def test_append_with_uncertain_outcome_makes_the_object_read_only(filled, monkeypatch):
    """Finding 7: the bytes reached the disk but fsync failed; the seq is never reused."""
    import empreinte.ledger as ledger_module
    real = ledger_module.append_bytes
    def written_then_failed(path, data):
        real(path, data)
        raise OSError("fsync failed")
    monkeypatch.setattr(ledger_module, "append_bytes", written_then_failed)
    with pytest.raises(OSError):
        filled.put("x.md", b"x")
    monkeypatch.setattr(ledger_module, "append_bytes", real)
    with pytest.raises(VaultError, match="uncertain"):
        filled.put("y.md", b"y")
    filled.lock()
    v = reopen(filled.path)
    seqs = [r.seq for r in v.ledger()]
    assert seqs == list(range(len(seqs))) and len(seqs) == 4 and v.verify().ok
    assert v.find("x.md") is not None  # recovered from its self-describing blob


def test_failed_batch_append_does_not_persist_invented_records(filled, monkeypatch):
    """Finding 7: pending records are kept until written; lock() then saves nothing."""
    import empreinte.ledger as ledger_module
    def disk_full(path, data):
        raise OSError("disk full")
    with pytest.raises(OSError):
        with filled.batch():
            filled.put("a1.md", b"1")
            filled.put("a2.md", b"2")
            monkeypatch.setattr(ledger_module, "append_bytes", disk_full)
    monkeypatch.undo()
    filled.lock()
    v = reopen(filled.path)
    assert len(v.ledger()) == 3 and v.find("a1.md") is None and v.verify().ok


def test_batch_blob_directories_are_synced_before_the_ledger(tmp_path, monkeypatch):
    """Finding 8: on POSIX a renamed blob is durable only once its directory is fsynced."""
    import empreinte.ledger as ledger_module
    import empreinte.store as store_module
    events = []
    monkeypatch.setattr(store_module, "fsync_dir", lambda path: events.append(("dir", Path(path))))
    real_append = ledger_module.append_bytes
    monkeypatch.setattr(ledger_module, "append_bytes", lambda path, data: (events.append(("append",)),
                                                                           real_append(path, data)))
    v = make(tmp_path / "v")
    events.clear()
    with v.batch():
        v.put("a.md", b"a")
        v.put("b.md", b"b")
    shards = {(v.path / "blobs" / r.cipher_hash[:2]) for r in v.ledger()}
    append_at = events.index(("append",))
    synced = {e[1] for e in events[:append_at] if e[0] == "dir"}
    assert shards <= synced and (v.path / "blobs") in synced


def test_batch_crash_keeps_a_prefix(tmp_path):
    """Finding 8, documented semantics: complete lines of a torn batch append are kept."""
    v = make(tmp_path / "v")
    with v.batch():
        for name in ("a", "b", "c"):
            v.put(f"{name}.md", name.encode())
    die(v)
    data = (v.path / "ledger.jsonl").read_bytes()
    lines = data.splitlines(keepends=True)
    (v.path / "ledger.jsonl").write_bytes(lines[0] + lines[1] + lines[2][:40])
    (v.path / "catalog.bin").unlink()  # as if the catalog write never happened
    again = reopen(v.path)
    assert [m.path for m in again.entries()] == ["a.md", "b.md"] and again.verify().ok


def test_lock_drops_secrets_even_when_saving_fails(filled):
    """Finding 9."""
    def failing():
        raise OSError("read-only disk")
    with pytest.raises(OSError):
        with filled.batch():
            filled.put("x.md", b"x")
            filled._write_catalog = failing
            filled.lock()
    assert filled._keys is None and filled._master is None and filled._signer is None
    assert filled._entries == {} and not filled._writer.held()
    assert not reopen(filled.path).notices  # the lock was released too


def test_integrity_problem_at_open_blocks_writes(filled):
    """Finding 10: an altered signature in the middle, same count and same head."""
    path = filled.path
    filled.lock()
    lines = (path / "ledger.jsonl").read_bytes().splitlines(keepends=True)
    record = json.loads(lines[0])
    record["signature"] = json.loads(lines[1])["signature"]
    lines[0] = json.dumps(record, separators=(",", ":")).encode() + b"\n"
    (path / "ledger.jsonl").write_bytes(b"".join(lines))
    v = reopen(path)
    with pytest.raises(Corrupted, match="record 0: signature invalid"):
        v.put("x.md", b"x")
    assert "record 0: signature invalid" in v.verify().errors


def test_unreadable_line_blocks_writes(filled):
    path = filled.path
    filled.lock()
    lines = (path / "ledger.jsonl").read_bytes().splitlines(keepends=True)
    (path / "ledger.jsonl").write_bytes(lines[0] + b"not json\n" + b"".join(lines[1:]))
    with pytest.raises(Corrupted):
        reopen(path).put("x.md", b"x")


def test_open_checks_anchor_tokens_and_count_before_writes(filled, tmp_path):
    """N10: a garbage token keeping its head, or a deleted anchor, blocks writes at open."""
    from test_anchor import FakeTSA
    tsa = FakeTSA()
    filled.transport, filled.trust_roots = tsa, [tsa.root]
    filled.anchor()
    path = filled.path
    filled.lock()
    good = (path / "anchors.jsonl").read_text(encoding="utf-8")
    anchor = json.loads(good)
    anchor["proof"] = "AAAA"
    (path / "anchors.jsonl").write_text(json.dumps(anchor) + "\n", encoding="utf-8")
    v = reopen(path)
    with pytest.raises(Corrupted, match="anchor 0"):
        v.put("x.md", b"x")
    v.lock()
    (path / "anchors.jsonl").write_text("", encoding="utf-8")
    v = reopen(path)
    with pytest.raises(Corrupted, match="the catalog knows 1"):
        v.put("x.md", b"x")


def test_oversized_header_and_anchors_are_not_parsed(filled, monkeypatch):
    """N12: unauthenticated files are bounded before parsing."""
    import empreinte.vault as vault_module
    path = filled.path
    filled.lock()
    parsed = []
    real_loads = json.loads
    monkeypatch.setattr(vault_module.json, "loads", lambda data, *a, **k: (parsed.append(len(data)),
                                                                           real_loads(data, *a, **k))[1])
    header = (path / "header.json").read_bytes()
    (path / "header.json").write_bytes(header.rstrip() + b" " * (vault_module.MAX_HEADER_BYTES + 1) + b"\n")
    with pytest.raises(Corrupted, match="larger than"):
        reopen(path)
    assert all(n <= vault_module.MAX_HEADER_BYTES for n in parsed)
    (path / "header.json").write_bytes(header)
    monkeypatch.undo()
    with open(path / "anchors.jsonl", "wb") as handle:
        handle.truncate(vault_module.MAX_ANCHORS_BYTES + 1)
    v = reopen(path)
    with pytest.raises(Corrupted, match="anchors.jsonl is larger"):
        v.put("x.md", b"x")


def test_format_document_states_prefix_commit():
    """N8: FORMAT.md says what the code does for a torn batch."""
    text = (Path(__file__).resolve().parents[1] / "docs" / "FORMAT.md").read_text(encoding="utf-8")
    assert "loses that batch and nothing else" not in text
    assert "prefix" in text and "writer.lock" in text


def test_kdf_parameters_are_bounded_before_derivation(filled, monkeypatch):
    """Finding 12: an attacker-edited header cannot make unlock allocate terabytes."""
    path = filled.path
    filled.lock()
    def never(*args, **kwargs):
        raise AssertionError("Argon2 must not run")
    monkeypatch.setattr(crypto, "Argon2id", never)
    for field, value in (("memory_cost", 2 ** 30), ("iterations", 10 ** 6), ("lanes", 0), ("iterations", True)):
        header = json.loads((path / "header.json").read_text(encoding="utf-8"))
        saved = header["kdf"][field]
        header["kdf"][field] = value
        (path / "header.json").write_text(json.dumps(header), encoding="utf-8")
        with pytest.raises(Corrupted, match="kdf"):
            reopen(path)
        header["kdf"][field] = saved
        (path / "header.json").write_text(json.dumps(header), encoding="utf-8")


def test_unknown_catalog_version_is_refused(filled):
    """Finding 14."""
    data = json.loads(crypto.open_blob(filled._keys.metadata, (filled.path / "catalog.bin").read_bytes(),
                                       crypto.blob_binding(filled._vault_id, "catalog"), crypto.BLOB_CATALOG))
    data["format_version"] = 2
    blob = crypto.seal_blob(filled._keys.metadata, crypto.BLOB_CATALOG, json.dumps(data).encode(),
                            crypto.blob_binding(filled._vault_id, "catalog"))
    path = filled.path
    filled.lock()
    (path / "catalog.bin").write_bytes(blob)
    with pytest.raises(VaultError, match="catalog format version 2"):
        reopen(path)
