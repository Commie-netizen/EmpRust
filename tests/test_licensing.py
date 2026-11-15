"""Grants, royalties and the content of a disclosure bundle."""
import hashlib
import json
from datetime import date

import pytest

from empreinte import crypto
from empreinte.api import NotFound
from empreinte.model import LicenseGrant, RoyaltyTerms
from empreinte.testing import stepping_clock
from empreinte.vault import Vault
from test_anchor import FakeTSA


@pytest.fixture
def setup(tmp_path):
    tsa = FakeTSA()
    v = Vault.create(tmp_path / "v", "pw", clock=stepping_clock(), kdf_params=crypto.TEST_KDF, transport=tsa)
    v.trust_roots = [tsa.root]
    a = v.put("public/alpha.md", b"alpha text", title="Alpha")
    v.put("public/alpha.md", b"alpha text, second version")
    hidden = v.put("private/journal.md", b"diary: nobody may read this", title="Journal intime")
    v.anchor()
    b = v.put("public/beta.md", b"beta text", title="Beta")
    grant = v.grant("Editions X", [(a.entry_id, 1), (b.entry_id, None)], usage="anthology",
                    terms="world rights, 5 years", royalty=RoyaltyTerms(model="flat", amount=300.0),
                    valid_until=date(2031, 1, 1))
    v.put("private/journal.md", b"diary: later entry")
    return v, a, b, hidden, grant, tmp_path


def test_grant_record_commits_without_revealing(setup):
    v, a, b, hidden, grant, _ = setup
    record = v.ledger()[grant.seq]
    assert record.kind == "license" and record.entry_id == "" and record.size == 0 and record.version == 0
    dumped = record.model_dump_json()
    for secret in ("Editions", "anthology", "Alpha", grant.license_id):
        assert secret not in dumped
    state = v._licenses[grant.license_id]
    assert record.commitment == hashlib.sha256(bytes.fromhex(state.salt) + state.committed.encode()).hexdigest()
    assert grant.created_at == record.timestamp and [i.version for i in grant.items] == [1, 1]


def test_licenses_and_royalties_persist_encrypted(setup):
    v, a, b, hidden, grant, tmp_path = setup
    event = v.record_royalty(grant.license_id, 300.0, period="2026", note="advance",
                             received_on=date(2026, 3, 2))
    record = v.ledger()[event.seq]
    assert record.kind == "royalty" and record.size == 0 and "advance" not in record.model_dump_json()
    with pytest.raises(NotFound):
        v.record_royalty("0" * 32, 1.0)
    path = v.path
    v.lock()
    for file in path.rglob("*"):
        if file.is_file():
            assert b"Editions" not in file.read_bytes() and b"advance" not in file.read_bytes()
    again = Vault.open(path, "pw")
    assert [g.license_id for g in again.licenses()] == [grant.license_id]
    assert again.licenses()[0].royalty.amount == 300.0
    assert again.royalties(grant.license_id) == [event] and again.royalties("other") == []
    assert again.verify().ok


def test_grant_of_removed_or_unknown_entry_fails(setup):
    v, a, b, hidden, grant, _ = setup
    v.remove(hidden.entry_id)
    with pytest.raises(NotFound):
        v.grant("Y", [(hidden.entry_id, None)], usage="u")
    with pytest.raises(NotFound):
        v.grant("Y", [(a.entry_id, 9)], usage="u")


def test_bundle_discloses_only_the_licensed_versions(setup):
    v, a, b, hidden, grant, tmp_path = setup
    bundle = v.export_bundle(grant.license_id, tmp_path / "out")
    files = sorted(str(p.relative_to(bundle)).replace("\\", "/") for p in bundle.rglob("*") if p.is_file())
    assert files == ["README.txt", "anchors/anchor-2.tst", "grant.json", f"items/01_{a.entry_id}_v1.md",
                     f"items/02_{b.entry_id}_v1.md", "manifest.json", "verify_bundle.py"]
    assert (bundle / f"items/01_{a.entry_id}_v1.md").read_bytes() == b"alpha text"
    everything = b"".join((bundle / f).read_bytes() for f in files if f != "verify_bundle.py")
    for secret in (b"second version", b"diary", b"Journal", b"private/", b"public/", hidden.entry_id.encode(),
                   hidden.commitment.encode()):
        assert secret not in everything
    # Other records appear only as opaque chain values (body digests, an anchored or neighbouring
    # record hash), never with their commitment, blob hash or entry id.
    others = [r for r in v.ledger() if r.seq not in (a.seq, b.seq, grant.seq)]
    for record in others:
        entry_id = "" if record.entry_id in (a.entry_id, b.entry_id) else record.entry_id
        for value in (record.commitment, record.cipher_hash, entry_id):
            if value:
                assert value.encode() not in everything


def test_manifest_structure_and_bundle_hash(setup):
    v, a, b, hidden, grant, tmp_path = setup
    bundle = v.export_bundle(grant.license_id, tmp_path / "out")
    manifest_bytes = (bundle / "manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    records = v.ledger()
    assert manifest["chain"]["from_seq"] == a.seq == 0
    assert len(manifest["chain"]["body_digests"]) == len(records)
    assert manifest["head"] == {"seq": records[-1].seq, "record_hash": records[-1].record_hash,
                                "signature": records[-1].signature}
    assert manifest["public_key"] == v.public_key
    assert [x["anchored_at"] for x in manifest["anchors"]] == ["2026-03-01T12:00:00.500000Z"]
    committed = (bundle / "grant.json").read_bytes()
    assert LicenseGrant.model_validate_json(committed).license_id == grant.license_id
    expected = hashlib.sha256(manifest_bytes).hexdigest()
    assert v.licenses()[0].bundle_hash == expected
    path = v.path
    v.lock()
    again = Vault.open(path, "pw")
    assert again.licenses()[0].bundle_hash == expected and again.verify().ok
    rebundle = again.export_bundle(grant.license_id, tmp_path / "out")  # re-export replaces the old one
    assert rebundle == bundle and (bundle / "manifest.json").exists()


def test_readme_holds_the_openssl_command(setup):
    v, a, b, hidden, grant, tmp_path = setup
    bundle = v.export_bundle(grant.license_id, tmp_path / "out")
    readme = (bundle / "README.txt").read_text(encoding="utf-8")
    head = v.ledger()[2].record_hash
    assert f"openssl ts -verify -digest {head} -token_in -in anchors/anchor-2.tst -CAfile ROOT.pem" in readme
