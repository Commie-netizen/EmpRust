"""Behaviour every VaultAPI implementation must have.

Not collected on its own (the file name does not start with test_). A test module
defines a `vault` fixture and imports everything from here:

    from vault_contract import *  # noqa: F401,F403

test_contract_inmemory.py does it for InMemoryVault; the encrypted vault's tests must
do the same with a real vault, so both stay interchangeable.
"""
from datetime import datetime, timezone

import pytest

from empreinte.api import NotFound, VaultAPI, VaultError
from empreinte.model import RoyaltyTerms


def test_is_a_vault(vault):
    assert isinstance(vault, VaultAPI)
    assert all(m in ("rfc3161", "opentimestamps") for m in vault.anchor_methods())


def test_put_creates_then_versions_then_is_idempotent(vault):
    v1 = vault.put("notes/idea.md", b"first", tags=["b", "a", "a"], source_mtime=datetime(2021, 5, 1, tzinfo=timezone.utc))
    assert (v1.version, v1.seq) == (1, 0)
    again = vault.put("notes/idea.md", b"first")
    assert again.version == 1 and len(vault.ledger()) == 1
    v2 = vault.put("notes/idea.md", b"second", source_mtime=datetime(2022, 1, 1, tzinfo=timezone.utc))
    assert v2.version == 2 and v2.entry_id == v1.entry_id
    meta = vault.entry(v1.entry_id)
    assert meta.title == "idea" and meta.n_versions == 2 and meta.size == 6
    assert meta.created_at == v1.timestamp and meta.updated_at == v2.timestamp
    assert meta.authored_at.year == 2021 and meta.modified_at.year == 2022
    assert vault.read(v1.entry_id) == b"second" and vault.read(v1.entry_id, 1) == b"first"
    assert [v.version for v in vault.versions(v1.entry_id)] == [1, 2]
    assert vault.find("notes\\idea.md").entry_id == v1.entry_id


def test_entry_ids_do_not_derive_from_content_or_path(vault):
    a = vault.put("a.md", b"same")
    b = vault.put("b.md", b"same")
    assert a.entry_id != b.entry_id and len(a.entry_id) == 32
    assert a.commitment != b.commitment  # salted: equal contents are not linkable from the ledger


def test_entries_sorted_and_removal_keeps_history(vault):
    vault.put("z.md", b"z")
    kept = vault.put("a.md", b"a")
    gone = vault.put("m.md", b"m")
    assert [m.path for m in vault.entries()] == ["a.md", "m.md", "z.md"]
    vault.remove(gone.entry_id)
    assert [m.path for m in vault.entries()] == ["a.md", "z.md"]
    assert vault.find("m.md") is None
    assert [r.kind for r in vault.ledger()] == ["put", "put", "put", "remove"]
    with pytest.raises(NotFound):
        vault.entry(gone.entry_id)
    assert vault.entry(kept.entry_id).path == "a.md"


def test_ledger_is_a_gapless_hash_chain_and_leaks_nothing(vault):
    vault.put("secret/plan.md", "contenu très secret".encode(), title="Plan secret", tags=["confidentiel"])
    vault.put("secret/plan.md", b"v2")
    records = vault.ledger()
    assert [r.seq for r in records] == [0, 1]
    assert records[0].prev_hash == "0" * 64 and records[1].prev_hash == records[0].record_hash
    dumped = " ".join(r.model_dump_json() for r in records)
    for secret in ("plan", "Plan secret", "confidentiel", "secret/"):
        assert secret not in dumped
    report = vault.verify()
    assert report.ok and report.n_records == 2 and report.head_hash == records[-1].record_hash


def test_proof_points_at_the_right_record(vault):
    first = vault.put("a.md", b"a")
    vault.put("b.md", b"b")
    proof = vault.proof(first.entry_id)
    assert proof.record.seq == 0 and proof.n_following == 1 and proof.verified
    assert proof.record.commitment == first.commitment
    with pytest.raises(NotFound):
        vault.proof(first.entry_id, 7)


def test_licensing_and_royalties(vault, tmp_path):
    a = vault.put("a.md", b"alpha", title="Alpha")
    vault.put("a.md", b"alpha 2")
    b = vault.put("b.md", b"beta")
    grant = vault.grant("Editions X", [(a.entry_id, 1), (b.entry_id, None)], usage="anthology",
                        royalty=RoyaltyTerms(model="per_use", amount=0.5))
    assert [(i.version, i.title) for i in grant.items] == [(1, "Alpha"), (1, "b")]
    assert vault.ledger()[grant.seq].kind == "license"
    bundle = vault.export_bundle(grant.license_id, tmp_path)
    disclosed = b"".join(p.read_bytes() for p in sorted(bundle.rglob("*")) if p.is_file())
    assert b"alpha" in disclosed and b"beta" in disclosed and b"alpha 2" not in disclosed
    event = vault.record_royalty(grant.license_id, 12.5, period="2026-Q4")
    assert vault.royalties(grant.license_id) == [event] and vault.ledger()[event.seq].kind == "royalty"
    assert [g.license_id for g in vault.licenses()] == [grant.license_id]
    with pytest.raises(VaultError):
        vault.grant("nobody", [], usage="x")
    with pytest.raises(NotFound):
        vault.record_royalty("missing", 1.0)


def test_aux_store_and_lock(vault):
    assert vault.aux_get("index") is None
    vault.aux_put("index", b"\x00\x01")
    assert vault.aux_get("index") == b"\x00\x01"
    vault.put("a.md", b"a")
    vault.lock()
    with pytest.raises(VaultError):
        vault.entries()
