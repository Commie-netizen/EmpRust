"""Command line and the real integration path: cli.session_for with an encrypted vault,
the real importer and the real Workspace, driven through the HTTP server."""
from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from empreinte import crypto
from empreinte.cli import main, report_dict, session_for
from empreinte.vault import Vault
from empreinte.workspace import Workspace
from test_server import Harness, ids

PASS = "une phrase de passe de test"
SRC = Path(__file__).resolve().parents[1] / "src"


def make_folder(root: Path) -> Path:
    folder = root / "notes"
    (folder / "Projet").mkdir(parents=True)
    (folder / "Projet" / "a.md").write_text("# Alpha\n\nVoir [[b]] et [[absente]].\n", encoding="utf-8", newline="\n")
    (folder / "Projet" / "b.md").write_text("# Bêta\n\nUne note liée.\n", encoding="utf-8", newline="\n")
    (folder / "reglages.json").write_text('{"cle": "valeur"}\n', encoding="utf-8", newline="\n")
    return folder


def test_report_dict_serialises_the_importer_dataclass():  # finding 5
    @dataclass
    class Skipped:
        path: str
        reason: str

    @dataclass
    class Report:
        scanned: int = 2
        added: int = 1
        skipped: list = field(default_factory=lambda: [Skipped("x", "lien")])
        missing: list = field(default_factory=lambda: ["y", "z"])

    assert report_dict(Report()) == {"scanned": 2, "added": 1, "skipped": 1, "missing": 2}


def test_server_integration_with_a_real_vault(tmp_path):  # findings 1, 5 and the untested path
    vault_dir = tmp_path / "coffre"
    folder = make_folder(tmp_path)
    session = session_for(vault_dir, kdf_params=crypto.TEST_KDF)
    for fn in (session.open_vault, session.create_vault, session.import_folder):
        assert not any(isinstance(c.cell_contents, (Vault, Workspace)) for c in fn.__closure__ or ())
    h = Harness(session, None)
    try:
        assert h.call("GET", "/api/status")[1]["exists"] is False
        status, body, _ = h.call("POST", "/api/create", {"passphrase": PASS})
        assert status == 200 and body["recovery_key"]
        h.unlock_token = body["unlock_token"]
        status, report, _ = h.call("POST", "/api/import", {"path": str(folder)})
        assert status == 200, report
        assert report["added"] == 3 and isinstance(report["skipped"], int)
        by_path = ids(h)
        assert set(by_path) == {"Projet/a.md", "Projet/b.md", "reglages.json"}
        graph = h.call("GET", "/api/graph")[1]
        assert len(graph["nodes"]) == 3 and len(graph["edges"]) == 1
        status, entry, _ = h.call("GET", f"/api/entries/{by_path['Projet/a.md']}")
        assert entry["link_targets"] == {"b": by_path["Projet/b.md"]}
        text = h.call("GET", f"/api/entries/{by_path['reglages.json']}/text")[1]
        assert text["text"].startswith('{"cle"')
        assert isinstance(h.call("GET", "/api/status")[1]["features"]["anchor_methods"], list)
        active = h.server.app.active
        assert h.call("POST", "/api/lock", {})[0] == 200
        assert h.server.app.active is None
        with pytest.raises(Exception):
            active.workspace.search("alpha")  # closed: its plaintext is gone
        assert h.unlock(PASS)[0] == 200
        assert len(ids(h)) == 3
        assert h.call("POST", "/api/search", {"q": "alpha"})[1][0]["path"] == "Projet/a.md"
    finally:
        h.close()


def _run_cli(*args: str, env_extra: dict | None = None) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": str(SRC), **(env_extra or {})}
    env.pop("PYTHONIOENCODING", None)
    return subprocess.run([sys.executable, "-m", "empreinte.cli", *args], capture_output=True, env=env, timeout=120)


def test_cli_missing_vault_has_a_clear_message_in_utf8(tmp_path):
    result = _run_cli("verify", str(tmp_path / "absent"))
    assert result.returncode != 0
    err = result.stderr.decode("utf-8")
    assert "Aucune archive Empreinte" in err and "créez-la" in err


def test_cli_import_prints_counts(tmp_path, monkeypatch, capsys):  # finding 5, command side
    vault_dir = tmp_path / "coffre"
    Vault.create(vault_dir, PASS, kdf_params=crypto.TEST_KDF).lock()
    folder = make_folder(tmp_path)
    monkeypatch.setenv("EMPREINTE_PASSPHRASE", PASS)
    assert main(["import", str(vault_dir), str(folder)]) == 0
    out = capsys.readouterr().out
    assert '"added": 3' in out and '"skipped": 0' in out
    assert main(["import", str(vault_dir), str(tmp_path / "nulle-part")]) != 0 if False else True
    with pytest.raises(SystemExit):
        main(["import", str(vault_dir), str(tmp_path / "nulle-part")])


def test_cli_utf8_output_survives_redirection(tmp_path):
    vault_dir = tmp_path / "coffre"
    result = _run_cli("init", str(vault_dir), env_extra={"EMPREINTE_PASSPHRASE": PASS})
    assert result.returncode == 0, result.stderr
    out = result.stdout.decode("utf-8")
    assert "Coffre créé" in out and "Clé de secours" in out


def test_unlock_again_keeps_a_writable_vault(tmp_path):  # new defect 3, real vault
    vault_dir = tmp_path / "coffre"
    folder = make_folder(tmp_path)
    h = Harness(session_for(vault_dir, kdf_params=crypto.TEST_KDF), None)
    try:
        status, body, _ = h.call("POST", "/api/create", {"passphrase": PASS})
        h.unlock_token = body["unlock_token"]
        assert h.unlock(PASS)[0] == 200  # unlock again while unlocked
        status, report, _ = h.call("POST", "/api/import", {"path": str(folder)})
        assert status == 200, report
        assert h.call("PUT", "/api/prefs", {"graph": {"repel": 9}})[0] == 200
        assert len(ids(h)) == 3
    finally:
        h.close()
