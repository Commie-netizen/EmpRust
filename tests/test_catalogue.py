"""Public catalogue: export by the real vault, the standalone verifier by subprocess,
tampering, leaks, and matching a later bundle item to its catalogue entry."""
from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
import cryptography
from cryptography.hazmat.primitives.serialization import Encoding

from empreinte import crypto
from empreinte.api import VaultError
from empreinte.catalogue import SIGNATURE_PREFIX, candidates, canonical
from empreinte.model import CatalogueChoice, Preview
from empreinte.testing import stepping_clock
from empreinte.vault import Vault
from test_anchor import FakeTSA

VERIFIER = Path(__file__).resolve().parents[1] / "tools" / "verify_bundle.py"
SECRET_TITLE = "Titre très secret"
SECRET_PATH = "secret/caché.md"
SECRET_TAG = "confidentiel"
SECRET_TEXT = "texte jamais publié nulle part"


@pytest.mark.parametrize("step", ["catalogue.json", "anchor", "README.txt", "copy", "ids", "history", "rename", "rollback"])
def test_review_9_failed_export_leaves_no_publication(tmp_path, monkeypatch, step):
    from empreinte import catalogue
    tsa = FakeTSA()
    v = Vault.create(tmp_path / "v", "pw", kdf_params=crypto.TEST_KDF, transport=tsa)
    v.trust_roots = [tsa.root]
    try:
        item = v.put("a.md", b"a")
        approve(v, item.entry_id, "summary")
        v.anchor()
        out = tmp_path / "out"
        real_write, real_aux = catalogue.atomic_write, v.aux_put
        history_writes = []
        def write(path, data):
            if path.name == step or (step == "anchor" and path.suffix == ".tst"):
                raise OSError("injected write failure")
            return real_write(path, data)
        def aux(key, data):
            if key == catalogue.PUBLISHED_KEY:
                history_writes.append(data)
                if step == "rollback" and len(history_writes) > 1:
                    raise OSError("injected rollback failure")
            if (step == "ids" and key == catalogue.IDS_KEY) or (step == "history" and key == catalogue.PUBLISHED_KEY):
                raise OSError("injected aux failure")
            return real_aux(key, data)
        monkeypatch.setattr(catalogue, "atomic_write", write)
        monkeypatch.setattr(v, "aux_put", aux)
        def fail(*args, **kwargs):
            raise OSError("injected failure")
        if step == "copy":
            monkeypatch.setattr(catalogue.shutil, "copyfile", fail)
        if step in {"rename", "rollback"}:
            monkeypatch.setattr(Path, "rename", fail)
        with pytest.raises(OSError, match="injected"):
            v.export_catalogue([CatalogueChoice(entry_id=item.entry_id)], out)
        assert v.catalogues() == []
        assert not out.exists() or list(out.iterdir()) == []
    finally:
        v.lock()


def test_review_11_wording(world):
    readme = (world["dir"] / "README.txt").read_text(encoding="utf-8")
    ui = (VERIFIER.parents[1] / "src/empreinte/web/js/views/licenses.js").read_text(encoding="utf-8")
    for text in (readme, ui):
        assert "ancre prouvée" in text
        assert "autorité non authentifiée" in text
        assert "Sans ancre" in text
        assert "déclarations du propriétaire" in text
    assert "owner assertions, not verified facts" in readme


def approve(vault, entry_id: str, summary: str, *, approved: bool = True) -> Preview:
    latest = vault.versions(entry_id)[-1]
    preview = Preview(entry_id=entry_id, version=latest.version, summary=summary, keywords=["preuve", "date"],
                      words=42, commitment=latest.commitment, model="test", created_at=datetime.now(timezone.utc),
                      approved=approved)
    vault.aux_put("preview/" + entry_id, preview.model_dump_json().encode("utf-8"))
    return preview


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    root = tmp_path_factory.mktemp("catalogue")
    tsa = FakeTSA()
    v = Vault.create(root / "v", "pw", clock=stepping_clock(), kdf_params=crypto.TEST_KDF, transport=tsa)
    v.trust_roots = [tsa.root]
    a = v.put("Recherche/alpha.md", "# Alpha\n\nUne idée datée.".encode(), title="Alpha public", tags=["idee"])
    hidden = v.put(SECRET_PATH, f"# {SECRET_TITLE}\n\n{SECRET_TEXT} #{SECRET_TAG}".encode(),
                   title=SECRET_TITLE, tags=[SECRET_TAG])
    draft = v.put("brouillon.md", b"# Brouillon\n\npas encore relu")
    v.anchor()
    b = v.put("Recherche/beta.md", b"# Beta\n\nEcrite apres l'ancre.", title="Beta", tags=["tard"])
    approve(v, a.entry_id, "Une note de recherche sur la datation des idées. Elle reste privée.")
    approve(v, b.entry_id, "Une note plus récente sur le même sujet. Aucun ancrage ne la couvre encore.")
    approve(v, hidden.entry_id, "Approuvé mais jamais listé dans ce catalogue. Il ne doit pas fuir.")
    approve(v, draft.entry_id, "Un brouillon d'aperçu que personne n'a relu. Il ne doit pas sortir.", approved=False)
    publication = v.export_catalogue([CatalogueChoice(entry_id=a.entry_id),
                                      CatalogueChoice(entry_id=b.entry_id, show_title=True)], root / "out")
    grant = v.grant("Editions X", [(a.entry_id, None), (b.entry_id, None), (hidden.entry_id, None)],
                    usage="anthologie")
    bundle = v.export_bundle(grant.license_id, root / "bundles")
    (root / "root.pem").write_bytes(tsa.root.public_bytes(Encoding.PEM))
    yield {"vault": v, "root": root, "a": a, "b": b, "hidden": hidden, "draft": draft, "pub": publication,
           "dir": Path(publication.path), "bundle": bundle, "tsa": tsa}
    v.lock()


def run(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    # The managed interpreter supplies dependencies through PYTHONPATH, which -I
    # deliberately ignores. Keep isolation from the repo and explicitly supply only
    # the dependency directory already used by this test process.
    dependencies = str(Path(cryptography.__file__).resolve().parent.parent)
    bootstrap = ("import sys, runpy; sys.path.insert(0, sys.argv.pop(1)); "
                 "sys.argv = sys.argv[1:]; runpy.run_path(sys.argv[0], run_name='__main__')")
    return subprocess.run([sys.executable, "-I", "-c", bootstrap, dependencies, str(VERIFIER), *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", cwd=cwd, timeout=60)


def by_commitment(document: dict, commitment: str) -> dict:
    return next(e for e in document["entries"] if e["commitment"] == commitment)


# ------------------------------------------------------------------------ round trip


def test_round_trip_through_the_standalone_verifier(world):
    directory, root = world["dir"], world["root"]
    result = run("--catalogue", str(directory), "--tsa-ca", str(root / "root.pem"), cwd=root)
    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout
    assert "Catalogue signed by this key: yes" in out and "VERDICT: ALL CHECKS PASSED" in out
    assert "PROVEN FROM 2026-03-01T12:00:00.500000+00:00" in out  # alpha, before the anchor
    assert "NOT YET PROVABLE TO A THIRD PARTY" in out  # beta, after the anchor
    assert '"Beta"' in out and "Alpha public" not in out  # the title only where it was ticked
    # Without the fake root the same token is only a claim (exit 0: a claim is not a failure).
    claimed = run("--catalogue", str(directory / "catalogue.json"), "--json", cwd=root)
    assert claimed.returncode == 0, claimed.stdout + claimed.stderr
    summary = json.loads(claimed.stdout)
    states = sorted(e["timestamp"]["state"] for e in summary["entries"])
    assert states == ["claimed", "none"] and summary["signature"] is True
    assert (directory / "verify_bundle.py").read_bytes() == VERIFIER.read_bytes()
    assert (directory / "README.txt").is_file() and list((directory / "anchors").glob("*.tst"))


def test_publication_is_recorded_and_public_ids_are_stable_and_opaque(world, tmp_path):
    v, a, b = world["vault"], world["a"], world["b"]
    first = world["pub"]
    again = v.export_catalogue([CatalogueChoice(entry_id=a.entry_id)], tmp_path)
    assert [p.catalogue_id for p in v.catalogues()][-2:] == [first.catalogue_id, again.catalogue_id]
    old = {p.entry_id: p.public_id for p in first.entries}
    assert again.entries[0].public_id == old[a.entry_id]  # same (entry, version): same public id
    assert all(p.public_id not in (a.entry_id, b.entry_id) and len(p.public_id) == 32 for p in first.entries)
    shown = {p.entry_id: p.shown for p in first.entries}
    assert shown == {a.entry_id: [], b.entry_id: ["title"]}
    states = {p.entry_id: p.anchor_state for p in first.entries}
    assert states == {a.entry_id: "proven", b.entry_id: "none"}


def test_candidates_say_why_an_entry_cannot_be_listed(world):
    by_id = {c.entry_id: c for c in candidates(world["vault"])}
    assert by_id[world["a"].entry_id].eligible and by_id[world["a"].entry_id].anchored == "proven"
    assert by_id[world["b"].entry_id].anchored == "none"
    draft = by_id[world["draft"].entry_id]
    assert not draft.eligible and "brouillon" in draft.reason


def test_an_unapproved_preview_is_refused_and_nothing_is_written(world, tmp_path):
    v = world["vault"]
    before = len(v.catalogues())
    with pytest.raises(VaultError, match="non approuvé"):
        v.export_catalogue([CatalogueChoice(entry_id=world["a"].entry_id),
                            CatalogueChoice(entry_id=world["draft"].entry_id)], tmp_path / "out")
    assert not (tmp_path / "out").exists() and len(v.catalogues()) == before
    with pytest.raises(VaultError, match="twice"):
        v.export_catalogue([CatalogueChoice(entry_id=world["a"].entry_id)] * 2, tmp_path / "out")
    c = v.put("sans-apercu.md", b"rien")
    with pytest.raises(VaultError, match="aucun aperçu"):
        v.export_catalogue([CatalogueChoice(entry_id=c.entry_id)], tmp_path / "out")


def test_a_preview_of_an_older_version_lists_that_exact_version(tmp_path):
    v = Vault.create(tmp_path / "v", "pw", kdf_params=crypto.TEST_KDF)
    try:
        first = v.put("n.md", b"premiere version")
        approve(v, first.entry_id, "Résumé de la première version. Il a été approuvé.")
        second = v.put("n.md", b"deuxieme version")
        [candidate] = candidates(v)
        assert candidate.eligible and candidate.version == 1 and not candidate.latest
        publication = v.export_catalogue([CatalogueChoice(entry_id=first.entry_id)], tmp_path / "out")
        assert publication.entries[0].commitment == first.commitment != second.commitment
    finally:
        v.lock()


# ---------------------------------------------------------------------------- leaks


def test_nothing_of_an_unlisted_entry_is_in_the_output(world):
    hidden = world["hidden"]
    data = b"".join(p.read_bytes() for p in sorted(world["dir"].rglob("*")) if p.is_file()
                    and p.name != "verify_bundle.py")
    for secret in (SECRET_TITLE, SECRET_PATH, SECRET_TAG, SECRET_TEXT, hidden.entry_id, hidden.commitment,
                   "Approuvé mais jamais listé", "Un brouillon d'aperçu"):
        assert secret.encode("utf-8") not in data, secret
        assert json.dumps(secret).encode("ascii") not in data  # nor in an escaped form
    # The listed entries: no text, and title, path and tags only where ticked.
    for secret in ("Une idée datée", "Ecrite apres l'ancre", "Alpha public", "Recherche/", "idee", "tard"):
        assert secret.encode("utf-8") not in data, secret
    document = json.loads((world["dir"] / "catalogue.json").read_text(encoding="utf-8"))
    for entry in document["entries"]:
        assert set(entry) <= {"public_id", "media_type", "words", "summary", "keywords", "commitment", "record",
                              "proof", "title"}


# ------------------------------------------------------------------------- tampering


def tampered(world, tmp_path, change, *, resign: bool = False) -> subprocess.CompletedProcess:
    target = tmp_path / "copy"
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(world["dir"], target)
    path = target / "catalogue.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    change(document)
    if resign:  # an attacker with the vault key: the per-record checks must still catch it
        document["signature"] = world["vault"]._signer.sign(SIGNATURE_PREFIX + canonical(document)).hex()
    path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
    return run("--catalogue", str(target), "--tsa-ca", str(world["root"] / "root.pem"), cwd=tmp_path)


def _every_field_change(document: dict) -> list[tuple[str, callable]]:
    def setter(path: list, value):
        def change(doc):
            node = doc
            for key in path[:-1]:
                node = node[key]
            node[path[-1]] = value
        return change

    changes = []
    for key, value in document.items():
        if key in ("entries", "anchors"):
            continue
        changes.append((key, setter([key], value + "x" if isinstance(value, str) else value + 1)))
    for i, entry in enumerate(document["entries"]):
        for key, value in entry.items():
            if key == "record":
                for rkey, rvalue in value.items():
                    new = (rvalue + 1) if isinstance(rvalue, int) else (
                        "2020-01-01T00:00:00.000000Z" if rkey == "timestamp" else ("f" * len(rvalue) or "ab"))
                    changes.append((f"entries.{i}.record.{rkey}", setter(["entries", i, "record", rkey], new)))
            elif key == "proof":
                if value is None:
                    changes.append((f"entries.{i}.proof", setter(["entries", i, "proof"],
                                                                 {"anchor": 0, "body_digests": []})))
                else:
                    changes.append((f"entries.{i}.proof.anchor", setter(["entries", i, "proof", "anchor"], 1)))
                    digests = list(value["body_digests"]) + ["11" * 32]
                    changes.append((f"entries.{i}.proof.body_digests", setter(["entries", i, "proof", "body_digests"],
                                                                              digests)))
            elif isinstance(value, list):
                changes.append((f"entries.{i}.{key}", setter(["entries", i, key], value + ["ajout"])))
            elif isinstance(value, int):
                changes.append((f"entries.{i}.{key}", setter(["entries", i, key], value + 1)))
            else:
                changes.append((f"entries.{i}.{key}", setter(["entries", i, key], value[:-1] + (
                    "0" if value[-1] != "0" else "1"))))
        changes.append((f"entries.{i}.+title", setter(["entries", i, "title"], "Titre ajouté")))
    for j, anchor in enumerate(document["anchors"]):
        for key, value in anchor.items():
            new = value + 1 if isinstance(value, int) else (
                "2019-01-01T00:00:00Z" if key == "anchored_at" else value[:-2] + "AA" if key == "proof" else value + "x")
            changes.append((f"anchors.{j}.{key}", setter(["anchors", j, key], new)))
    changes.append(("entries.order", lambda doc: doc["entries"].reverse()))
    changes.append(("entries.drop", lambda doc: doc["entries"].pop()))
    return changes


def test_tampering_with_any_field_fails(world, tmp_path):
    document = json.loads((world["dir"] / "catalogue.json").read_text(encoding="utf-8"))
    changes = _every_field_change(document)
    assert len(changes) > 30
    for name, change in changes:
        if name == "signature":
            continue  # covered below: a changed signature is simply invalid
        result = tampered(world, tmp_path, change)
        assert result.returncode != 0, name
    result = tampered(world, tmp_path, lambda d: d.update(signature="00" * 64))
    assert result.returncode == 1 and "signature by the vault key is invalid" in result.stdout


@pytest.mark.parametrize("name, change, message", [
    ("record time", lambda d: d["entries"][0]["record"].update(timestamp="2020-01-01T00:00:00.000000Z"),
     "signed by this key: NO"),
    ("commitment", lambda d: (d["entries"][0].update(commitment="ab" * 32),
                              d["entries"][0]["record"].update(commitment="ab" * 32)), "signed by this key: NO"),
    ("digest", lambda d: [e for e in d["entries"] if e["proof"]][0]["proof"]["body_digests"].__setitem__(0, "11" * 32),
     "do not lead from this record"),
    ("anchor time", lambda d: d["anchors"][0].update(anchored_at="2019-01-01T00:00:00Z"), "anchored_at differs"),
    ("summary", lambda d: d["entries"][0].update(summary="Un autre résumé, réécrit."), None),
])
def test_resigned_tampering_is_still_caught_per_entry(world, tmp_path, name, change, message):
    result = tampered(world, tmp_path, change, resign=True)
    if message is None:
        # The summary is the owner's own claim, signed by the key: re-signing it is legitimate.
        assert result.returncode == 0, result.stdout
    else:
        assert result.returncode == 1 and message in result.stdout, (name, result.stdout)


# ------------------------------------------------------------------ bundle matching


def test_a_bundle_item_is_matched_to_its_catalogue_entry(world):
    root = world["root"]
    result = run(str(world["bundle"]), "--catalogue", str(world["dir"]), "--tsa-ca", str(root / "root.pem"),
                 cwd=root)
    # One licensed item is not listed: the bundle's items are not all catalogue entries.
    assert result.returncode == 1, result.stdout + result.stderr
    assert "BUNDLE: ALL CHECKS PASSED" in result.stdout and "MATCH: FAILED (2 of 3" in result.stdout
    pub = {p.entry_id: p.public_id for p in world["pub"].entries}
    out = result.stdout
    assert f"same document as catalogue entry {pub[world['a'].entry_id]}" in out
    assert f"same document as catalogue entry {pub[world['b'].entry_id]}" in out
    assert out.count("NOT an entry of this catalogue") == 1  # the licensed but unlisted item
    summary = json.loads(run(str(world["bundle"]), "--catalogue", str(world["dir"]), "--json", cwd=root).stdout)
    assert summary["same_key"] and sorted(m["public_id"] is None for m in summary["matches"]) == [False, False, True]


def test_a_catalogue_from_another_vault_matches_nothing(world, tmp_path):
    other = Vault.create(tmp_path / "autre", "pw", kdf_params=crypto.TEST_KDF)
    try:
        e = other.put("x.md", b"autre")
        approve(other, e.entry_id, "Une note d'une autre archive. Rien de commun.")
        publication = other.export_catalogue([CatalogueChoice(entry_id=e.entry_id)], tmp_path / "out")
    finally:
        other.lock()
    result = run(str(world["bundle"]), "--catalogue", publication.path, cwd=tmp_path)
    assert result.returncode == 1 and "different vault keys" in result.stdout


def test_unreadable_catalogue_exits_2(tmp_path):
    (tmp_path / "catalogue.json").write_text("{}", encoding="utf-8")
    result = run("--catalogue", str(tmp_path), cwd=tmp_path)
    assert result.returncode == 2 and "cannot read the catalogue" in result.stderr


def test_single_json_file_is_the_same_catalogue(world, tmp_path):
    only = tmp_path / "seul.json"
    shutil.copyfile(world["dir"] / "catalogue.json", only)
    result = run("--catalogue", str(only), "--tsa-ca", str(world["root"] / "root.pem"), cwd=tmp_path)
    assert result.returncode == 0 and "PROVEN FROM" in result.stdout


# ------------------------------------------------------------------------- server


def test_server_catalogue_routes(tmp_path):
    from test_server import Harness, make_vault, session_for
    vault = make_vault()
    h = Harness(session_for(vault, export_dir=tmp_path / "exports"), vault)
    try:
        h.unlock("correct horse battery")
        entries = {m.path: m.entry_id for m in vault.entries()}
        idee = entries["Recherche/idee.md"]
        approve(vault, idee, "Une idée sur la datation. Résumé approuvé.")
        approve(vault, entries["seule.md"], "Brouillon. Pas approuvé.", approved=False)
        status, body, _ = h.call("GET", "/api/catalogue")
        assert status == 200
        by_id = {c["entry_id"]: c for c in body["candidates"]}
        assert by_id[idee]["eligible"] and not by_id[entries["seule.md"]]["eligible"]
        assert body["publications"] == []
        items = [{"entry_id": idee, "show_title": True, "show_path": False, "show_tags": False}]
        assert h.call("POST", "/api/catalogue", {"items": items})[0] == 400  # no confirmation
        status, pub, _ = h.call("POST", "/api/catalogue", {"items": items, "confirm": True})
        assert status == 200 and pub["entries"][0]["shown"] == ["title"]
        assert Path(pub["path"]).is_relative_to(tmp_path / "exports")
        bad = [{"entry_id": entries["seule.md"], "show_title": False, "show_path": False, "show_tags": False}]
        status, err, _ = h.call("POST", "/api/catalogue", {"items": bad, "confirm": True})
        assert status == 409 and "non approuvé" in err["message"]
        assert len(h.call("GET", "/api/catalogue")[1]["publications"]) == 1
    finally:
        h.close()


# --------------------------------------------------- fix round after the closing audit


def test_every_tampered_catalogue_exits_1_with_a_reason(world, tmp_path):  # closing audit
    document = json.loads((world["dir"] / "catalogue.json").read_text(encoding="utf-8"))
    changes = _every_field_change(document)
    changes += [("entries.0.record.-seq", lambda d: d["entries"][0]["record"].pop("seq")),
                ("entries.0.-record", lambda d: d["entries"][0].update(record="x")),
                ("-entries", lambda d: d.pop("entries")),
                ("anchors.0.-proof", lambda d: d["anchors"][0].pop("proof")),
                ("public_key", lambda d: d.update(public_key="zz")),
                ("format", lambda d: d.update(format="autre-chose"))]
    for name, change in changes:
        result = tampered(world, tmp_path, change)
        assert result.returncode == 1, (name, result.returncode, result.stdout, result.stderr)
        assert "VERDICT: FAILED" in result.stdout and "problem:" in result.stdout, (name, result.stdout)


def _raw_catalogue(world, tmp_path, text: str) -> subprocess.CompletedProcess:
    target = tmp_path / "raw"
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(world["dir"], target)
    (target / "catalogue.json").write_text(text, encoding="utf-8")
    return run("--catalogue", str(target), "--tsa-ca", str(world["root"] / "root.pem"), cwd=tmp_path)


def test_a_duplicate_key_is_refused_even_when_the_signature_holds(world, tmp_path):  # review finding 7
    text = (world["dir"] / "catalogue.json").read_text(encoding="utf-8")
    document = json.loads(text)
    entry = document["entries"][0]
    # A first "summary" key that a first-value reader would show; Python keeps the last.
    forged = text.replace(json.dumps(entry["summary"], ensure_ascii=False),
                          json.dumps("Résumé inventé par un tiers.", ensure_ascii=False) + ', "summary": '
                          + json.dumps(entry["summary"], ensure_ascii=False), 1)
    assert forged != text
    result = _raw_catalogue(world, tmp_path, forged.replace('"summary": "Résumé inventé', '"summary":"Résumé inventé'))
    assert result.returncode == 1 and "duplicate key" in result.stdout, result.stdout + result.stderr


def test_deep_nesting_is_refused_cleanly(world, tmp_path):  # review finding 7
    result = _raw_catalogue(world, tmp_path, '{"format": "empreinte-catalogue", "x": ' + "[" * 100000 + "]" * 100000 + "}")
    assert result.returncode in (1, 2) and "Traceback" not in result.stderr
    assert "nested" in result.stdout + result.stderr


def test_a_bundle_of_other_documents_does_not_pass_the_catalogue_question(world, tmp_path):  # review finding 8
    v = world["vault"]
    root = world["root"]
    other = v.put("autre/hors-catalogue.md", b"# Hors catalogue\n\nrien a voir")
    grant = v.grant("Editions Y", [(other.entry_id, None)], usage="autre")
    bundle = v.export_bundle(grant.license_id, tmp_path / "bundles")
    alone = run(str(bundle), "--tsa-ca", str(root / "root.pem"), cwd=root)
    assert alone.returncode == 0, alone.stdout  # a valid bundle on its own
    both = run(str(bundle), "--catalogue", str(world["dir"]), "--tsa-ca", str(root / "root.pem"), cwd=root)
    assert both.returncode == 1, both.stdout
    assert "BUNDLE: ALL CHECKS PASSED" in both.stdout and "CATALOGUE: ALL CHECKS PASSED" in both.stdout
    assert "MATCH: FAILED" in both.stdout
    summary = json.loads(run(str(bundle), "--catalogue", str(world["dir"]), "--json", cwd=root).stdout)
    assert summary["ok"] is False and summary["bundle"]["ok"] is True and summary["catalogue"]["ok"] is True
    assert summary["match"]["ok"] is False and summary["match"]["matched"] == 0 and summary["match"]["items"] == 1


def test_a_bundle_of_listed_entries_passes_the_catalogue_question(world, tmp_path):  # review finding 8
    v, a, b, root = world["vault"], world["a"], world["b"], world["root"]
    grant = v.grant("Editions Z", [(a.entry_id, None), (b.entry_id, None)], usage="anthologie")
    bundle = v.export_bundle(grant.license_id, tmp_path / "bundles")
    result = run(str(bundle), "--catalogue", str(world["dir"]), "--tsa-ca", str(root / "root.pem"), cwd=root)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "MATCH: ALL 2 BUNDLE ITEMS ARE ENTRIES OF THIS CATALOGUE" in result.stdout
