"""Uncovered records: how many ledger records no proven anchor covers, and since when.
No timestamp authority is contacted: the fake authority of test_anchor answers."""
from __future__ import annotations

from empreinte import crypto
from empreinte.cli import session_for
from empreinte.testing import stepping_clock
from empreinte.vault import Vault
from test_anchor import FakeTSA
from test_server import Harness

PASS = "une phrase de passe de test"


def test_coverage_follows_proven_anchors_only(tmp_path):
    tsa = FakeTSA()
    v = Vault.create(tmp_path / "v", "pw", clock=stepping_clock(), kdf_params=crypto.TEST_KDF, transport=tsa)
    try:
        v.trust_roots = [tsa.root]
        v.put("a.md", b"a")
        v.put("b.md", b"b")
        c = v.coverage()
        assert (c.n_records, c.uncovered, c.covered_upto) == (2, 2, -1)
        assert c.oldest_uncovered_at == v.ledger()[0].timestamp
        v.anchor()  # proven with the fake root
        assert v.coverage().uncovered == 0 and v.coverage().oldest_uncovered_at is None
        later = v.put("c.md", b"c")
        v.put("d.md", b"d")
        c = v.coverage()
        assert (c.uncovered, c.covered_upto, c.oldest_uncovered_at) == (2, 1, later.timestamp)
        # Without a trusted root the same anchor is only claimed: nothing counts as covered.
        v.trust_roots = []
        c = v.coverage()
        assert (c.covered_upto, c.claimed_upto, c.uncovered) == (-1, 1, 4)
    finally:
        v.lock()


def test_status_reports_coverage_only_to_the_unlocked_page(tmp_path):
    path = tmp_path / "coffre"
    v = Vault.create(path, PASS, kdf_params=crypto.TEST_KDF)
    v.put("a.md", b"a")
    v.lock()
    h = Harness(session_for(path, kdf_params=crypto.TEST_KDF), None)
    try:
        assert h.call("GET", "/api/status")[1]["coverage"] is None
        assert h.unlock(PASS)[0] == 200
        coverage = h.call("GET", "/api/status")[1]["coverage"]
        assert coverage["n_records"] == 1 and coverage["uncovered"] == 1 and coverage["oldest_uncovered_at"]
    finally:
        h.close()


# --------------------------------------------------- review of capture and catalogue, finding 3


def test_coverage_cache_follows_the_trust_roots_content_and_the_anchors(tmp_path):
    tsa = FakeTSA()
    v = Vault.create(tmp_path / "v", "pw", clock=stepping_clock(), kdf_params=crypto.TEST_KDF, transport=tsa)
    try:
        v.trust_roots = [tsa.root]
        v.put("a.md", b"a")
        v.anchor()
        assert v.coverage().uncovered == 0
        v.trust_roots.clear()  # emptied in place: same list object
        assert v.coverage().covered_upto == -1, "a root removed in place must not keep proving"
        v.trust_roots.append(tsa.root)
        assert v.coverage().covered_upto == 0
        (v.path / "anchors.jsonl").write_text("", encoding="utf-8")  # the anchors vanish on disk
        report = v.verify()
        assert not report.ok
        c = v.coverage()
        assert c.covered_upto == -1 and c.uncovered == 1, "after a discrepancy nothing is vouched for"
    finally:
        v.lock()
