"""tools/verify_bundle.py, run as a licensee would: a subprocess on an exported bundle."""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import Encoding

from empreinte import crypto
from empreinte.testing import stepping_clock
from empreinte.vault import Vault
from test_anchor import FakeTSA

VERIFIER = Path(__file__).resolve().parents[1] / "tools" / "verify_bundle.py"


@pytest.fixture(scope="module")
def exported(tmp_path_factory):
    root = tmp_path_factory.mktemp("bundle")
    tsa = FakeTSA()
    v = Vault.create(root / "v", "pw", clock=stepping_clock(), kdf_params=crypto.TEST_KDF, transport=tsa)
    v.trust_roots = [tsa.root]
    a = v.put("a.md", "Première idée".encode(), title="Première")
    v.put("hidden.md", b"never disclosed")
    v.anchor()
    b = v.put("b.md", b"after the anchor", title="Later")
    grant = v.grant("Editions X", [(a.entry_id, None), (b.entry_id, None)], usage="anthology")
    v.put("hidden.md", b"never disclosed either")
    bundle = v.export_bundle(grant.license_id, root / "out")
    (root / "root.pem").write_bytes(tsa.root.public_bytes(Encoding.PEM))
    (root / "other.pem").write_bytes(FakeTSA().root.public_bytes(Encoding.PEM))
    return bundle, root


def run(bundle: Path, *args: str) -> subprocess.CompletedProcess:
    # -I: isolated mode, no user site and no current directory on sys.path; cwd outside the repo.
    return subprocess.run([sys.executable, "-I", str(VERIFIER), str(bundle), *args], capture_output=True,
                          text=True, encoding="utf-8", errors="replace", cwd=bundle.parent, timeout=60)


def copy(exported, name: str) -> Path:
    bundle, root = exported
    target = root / name
    shutil.copytree(bundle, target)
    return target


def edit_manifest(bundle: Path, change) -> None:
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    change(manifest)
    (bundle / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def test_verifier_is_standalone():
    source = VERIFIER.read_text(encoding="utf-8")
    assert "import empreinte" not in source and "from empreinte" not in source


def test_good_bundle_passes(exported):
    bundle, root = exported
    result = run(bundle)
    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout
    assert "VERDICT: ALL CHECKS PASSED" in out
    assert out.count("matches the commitment: yes") == 3 and out.count("chained to the head: yes") == 3
    assert "outside timestamp: CLAIMED ONLY, existence by 2026-03-01T12:00:00.500000+00:00" in out
    assert "outside timestamp: NONE; recorded" in out  # item 2, after the anchor
    assert "outside timestamp: PROVEN" not in out
    assert 'item 1 "Première"' in out  # UTF-8 output even when piped on Windows
    assert (bundle / "verify_bundle.py").read_bytes() == VERIFIER.read_bytes()


def test_trusted_root_option(exported):
    bundle, root = exported
    good = run(bundle, "--tsa-ca", str(root / "root.pem"))
    assert good.returncode == 0 and "outside timestamp: PROVEN" in good.stdout
    assert "CLAIMED ONLY" not in good.stdout
    bad = run(bundle, "--tsa-ca", str(root / "other.pem"))
    # Content integrity still passes, but an unrelated root cannot prove the date.
    assert bad.returncode == 0 and "outside timestamp: CLAIMED ONLY" in bad.stdout
    assert "outside timestamp: PROVEN" not in bad.stdout
    summary = json.loads(run(bundle, "--tsa-ca", str(root / "other.pem"), "--json").stdout)
    timestamps = [item["timestamp"] for item in summary["items"]]
    assert any(stamp["state"] == "claimed" for stamp in timestamps)
    assert all(stamp["proven_before"] is None for stamp in timestamps)


def test_json_output(exported):
    bundle, _ = exported
    summary = json.loads(run(bundle, "--json").stdout)
    assert summary["ok"] and [i["ok"] for i in summary["items"]] == [True, True, True]


def test_changed_plaintext_fails(exported):
    bundle = copy(exported, "plaintext")
    item = next((bundle / "items").iterdir())
    item.write_bytes(item.read_bytes() + b" (edited)")
    result = run(bundle)
    assert result.returncode == 1 and "content matches the commitment: NO" in result.stdout


def test_changed_salt_fails(exported):
    bundle = copy(exported, "salt")
    edit_manifest(bundle, lambda m: m["items"][0].update(salt="00" * 32))
    result = run(bundle)
    assert result.returncode == 1 and "content matches the commitment: NO" in result.stdout


def test_changed_record_fails(exported):
    bundle = copy(exported, "record")
    edit_manifest(bundle, lambda m: m["items"][0]["record"].update(timestamp="2020-01-01T00:00:00.000000Z"))
    result = run(bundle)
    assert result.returncode == 1
    assert "signed by this key: NO" in result.stdout and "chained to the head: NO" in result.stdout


def test_changed_grant_fails(exported):
    bundle = copy(exported, "grant")
    grant = (bundle / "grant.json").read_bytes()
    (bundle / "grant.json").write_bytes(grant.replace(b"anthology", b"any use whatsoever"))
    result = run(bundle)
    assert result.returncode == 1
    assert "grant: FAILED" in result.stdout and "grant signature by the vault key is invalid" in result.stdout


def test_changed_chain_digest_fails(exported):
    bundle = copy(exported, "digest")
    edit_manifest(bundle, lambda m: m["chain"]["body_digests"].__setitem__(1, "11" * 32))
    result = run(bundle)
    assert result.returncode == 1 and "do not lead to the head record hash" in result.stdout


def test_changed_anchor_time_fails(exported):
    bundle = copy(exported, "anchor")
    edit_manifest(bundle, lambda m: m["anchors"][0].update(anchored_at="2019-01-01T00:00:00Z"))
    result = run(bundle)
    assert result.returncode == 1 and "anchored_at differs" in result.stdout


def test_unreadable_bundle_exits_2(tmp_path):
    result = run(tmp_path)
    assert result.returncode == 2 and "cannot read the bundle" in result.stderr


def test_duplicate_item_cannot_replace_missing_granted_item(exported):
    bundle = copy(exported, "duplicate-item")
    edit_manifest(bundle, lambda m: m["items"].__setitem__(1, m["items"][0]))
    result = run(bundle)
    assert result.returncode == 1
    assert "appears twice" in result.stdout
    assert "listed in the grant are not in the bundle" in result.stdout


def test_item_path_cannot_escape_bundle(exported):
    bundle = copy(exported, "outside-item")
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    source = bundle / manifest["items"][0]["file"]
    shutil.copyfile(source, bundle.parent / "outside.txt")
    edit_manifest(bundle, lambda m: m["items"][0].update(file="../outside.txt"))
    result = run(bundle)
    assert result.returncode == 1
    assert "content unreadable" in result.stdout


def _load_verifier():
    import importlib.util
    spec = importlib.util.spec_from_file_location("verify_bundle_under_test", VERIFIER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up there
    spec.loader.exec_module(module)
    return module


def _link_directory(target: Path, link: Path) -> None:
    import os
    if os.name == "nt":
        import _winapi
        _winapi.CreateJunction(str(target), str(link))  # no privilege needed, unlike symlinks
    else:
        os.symlink(target, link, target_is_directory=True)


def test_swap_between_check_and_open_cannot_redirect_the_read(exported, monkeypatch):
    """N11: the items directory is swapped for a link to an outside copy at the moment of
    opening. The read must come from what was opened, and that must be inside the bundle."""
    import os
    bundle = copy(exported, "swap")
    item = sorted((bundle / "items").iterdir())[0]
    outside = bundle.parent / "outside-items"
    outside.mkdir()
    (outside / item.name).write_bytes(item.read_bytes())  # the genuine bytes, outside the bundle
    item.write_bytes(b"not the licensed document")  # what the bundle really holds
    verifier = _load_verifier()
    swapped = []
    real_os_open, real_open = os.open, open

    def swap_once(path):
        if not swapped and "items" in str(path):
            swapped.append(path)
            (bundle / "items").rename(bundle / "items-real")
            _link_directory(outside, bundle / "items")

    def os_open(path, *args, **kwargs):
        swap_once(path)
        return real_os_open(path, *args, **kwargs)

    def builtin_open(path, *args, **kwargs):
        swap_once(path)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(verifier.os, "open", os_open)
    monkeypatch.setattr(verifier, "open", builtin_open, raising=False)
    report = verifier.verify(bundle, [])
    monkeypatch.undo()
    assert swapped
    first = report["items"][0]
    assert not report["ok"] and not first.content_ok
    assert any("outside the bundle" in p or "cannot be opened" in p for p in first.problems)


def test_bundle_files_must_be_regular_files_inside(exported):
    verifier = _load_verifier()
    bundle, _ = exported
    for name in ("../manifest.json", "items", "C:/Windows/win.ini", "/etc/passwd", "items\\x"):
        with pytest.raises(verifier.BundleError):
            verifier.read_bundle_file(bundle, name, 1 << 20)
    with pytest.raises(verifier.BundleError, match="larger"):
        verifier.read_bundle_file(bundle, "manifest.json", 10)


def test_oversized_anchor_proof_is_not_decoded(exported):
    bundle = copy(exported, "bigproof")
    edit_manifest(bundle, lambda m: m["anchors"][0].update(proof="A" * (2 << 20)))
    result = run(bundle)
    assert result.returncode == 1 and ("malformed" in result.stdout or "too large" in result.stdout)
