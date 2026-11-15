"""Tests of the local HTTP server over real HTTP, with InMemoryVault and the stub workspace."""
from __future__ import annotations

import http.client
import json
import re
import shutil
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from empreinte.api import Corrupted, WrongPassphrase
from empreinte.demo import StubWorkspace, build_demo, make_preview
from empreinte.server import ServerOptions, Session, serve
from empreinte.testing import InMemoryVault, stepping_clock

PASS = "correct horse battery"
WEB = Path(__file__).resolve().parents[1] / "src" / "empreinte" / "web"


class ReopenableVault(InMemoryVault):
    def reopen(self) -> None:
        self._locked = False


def make_vault() -> ReopenableVault:
    vault = ReopenableVault(clock=stepping_clock())
    old = datetime(2021, 3, 4, 10, 0, tzinfo=timezone.utc)
    vault.put("Recherche/idee.md", b"# Idee\n\nUne idee sur l'horodatage. Voir [[Plan]] et [[Absente]]. #preuve",
              tags=["idee"], source_mtime=old)
    vault.put("Projets/Plan.md", b"# Plan\n\nLe plan mentionne l'horodatage et [[idee]].")
    vault.put("Recherche/idee.md", b"# Idee\n\nUne idee sur l'horodatage, reprise. Voir [[Plan]]. #preuve", tags=["idee"])
    vault.put("seule.md", b"Note isolee sans lien.")
    vault.put("Pieces/schema.png", b"\x89PNG....", kind="file", media_type="image/png")
    return vault


class Harness:
    """A running server plus an HTTP client that sets every header explicitly."""

    def __init__(self, session: Session, vault: ReopenableVault | None, **opts):
        self.vault = vault
        options = ServerOptions(log=opts.pop("log", False), **opts)
        self.server = serve(session, options=options)
        self.port = self.server.port
        self.host = f"127.0.0.1:{self.port}"
        self.origin = f"http://{self.host}"
        self.unlock_token: str | None = None
        status, _, body = self.raw("GET", "/", token=False)
        assert status == 200
        self.token = re.search(rb'name="empreinte-token" content="([^"]+)"', body).group(1).decode()

    def raw(self, method: str, path: str, *, body: bytes | None = None, headers: dict | None = None,
            token: bool = True, unlock: bool = True, origin: bool = True, ctype: str | None = "application/json"):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Host": self.host}
        if token and getattr(self, "token", None):
            h["X-Empreinte-Token"] = self.token
        if unlock and self.unlock_token:
            h["X-Empreinte-Unlock"] = self.unlock_token
        if origin and method in ("POST", "PUT", "DELETE"):
            h["Origin"] = self.origin
        if body is not None and ctype:
            h["Content-Type"] = ctype
        h.update(headers or {})
        h = {k: v for k, v in h.items() if v is not None}
        conn.request(method, path, body=body, headers=h)
        res = conn.getresponse()
        data = res.read()
        conn.close()
        return res.status, {k.lower(): v for k, v in res.getheaders()}, data

    def call(self, method: str, path: str, payload=None, **kw):
        body = None if payload is None and method == "GET" else json.dumps(payload or {}).encode()
        status, headers, data = self.raw(method, path, body=body, **kw)
        parsed = json.loads(data) if data and headers.get("content-type", "").startswith("application/json") else data
        return status, parsed, headers

    def unlock(self, passphrase: str = PASS):
        status, body, _ = self.call("POST", "/api/unlock", {"passphrase": passphrase})
        if status == 200:
            self.unlock_token = body["unlock_token"]
        return status, body

    def close(self):
        self.server.shutdown()


def session_and_state(vault, *, exists=True, with_extras=True, export_dir: Path | None = None):
    # The test keeps the vault (it is reopened) and records every workspace handed out, to
    # check that the server closes them; the callables themselves receive vault and workspace.
    state = {"vault": vault, "pass": PASS, "workspaces": []}

    def new_ws(v):
        ws = StubWorkspace(v)
        state["workspaces"].append(ws)
        return ws

    def open_vault(passphrase):
        if passphrase != state["pass"] or state["vault"] is None:
            raise WrongPassphrase("non")
        state["vault"].reopen()
        return state["vault"], new_ws(state["vault"])

    def check_passphrase(passphrase):
        if passphrase != state["pass"] or state["vault"] is None:
            raise WrongPassphrase("non")

    def create_vault(passphrase):
        state["vault"] = make_vault()
        state["pass"] = passphrase
        return state["vault"], new_ws(state["vault"]), "RECO-VERY-KEY0"

    def import_folder(v, ws, path):
        v.put("Importe/nouveau.md", b"# Nouveau\n\nimporte")
        return {"added": 1}

    def previews(v, ws, ids):
        return [make_preview(v, i) for i in ids]

    return Session(open_vault=open_vault, create_vault=create_vault, check_passphrase=check_passphrase,
                   exists=lambda: state["vault"] is not None if not exists else True,
                   import_folder=import_folder if with_extras else None,
                   make_previews=previews if with_extras else None,
                   export_dir=export_dir if with_extras else None,
                   ), state


def session_for(vault, **kw) -> Session:
    return session_and_state(vault, **kw)[0]


@pytest.fixture
def srv(tmp_path):
    vault = make_vault()
    h = Harness(session_for(vault, export_dir=tmp_path / "exports"), vault, free_attempts=2, base_delay=0.4,
                max_delay=2.0, max_body=50_000)
    yield h
    h.close()


@pytest.fixture
def open_srv(srv):
    assert srv.unlock()[0] == 200
    return srv


def ids(h: Harness) -> dict[str, str]:
    _, entries, _ = h.call("GET", "/api/entries")
    return {e["path"]: e["entry_id"] for e in entries}


# ------------------------------------------------------------------ static files


def test_index_carries_token_and_security_headers(srv):
    status, headers, body = srv.raw("GET", "/", token=False)
    assert status == 200 and b"__EMPREINTE_PAGE_TOKEN__" not in body
    assert len(srv.token) >= 32
    csp = headers["content-security-policy"]
    assert "script-src 'self'" in csp and "default-src 'none'" in csp and "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp and "http" not in csp
    assert headers["cache-control"] == "no-store"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert not any(k.startswith("access-control") for k in headers)
    assert "set-cookie" not in headers


def test_static_files_and_types(srv):
    status, headers, body = srv.raw("GET", "/js/app.js", token=False)
    assert status == 200 and headers["content-type"].startswith("text/javascript")
    status, headers, _ = srv.raw("GET", "/style.css", token=False)
    assert status == 200 and headers["content-type"].startswith("text/css")


def test_index_has_no_inline_script_or_remote_resource():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    assert re.search(r"<script(?![^>]*\bsrc=)", html) is None
    assert re.search(r"\son\w+\s*=", html) is None
    for path in WEB.rglob("*"):
        if path.suffix in (".html", ".css", ".js"):
            text = path.read_text(encoding="utf-8")
            assert re.search(r"""(src|href)\s*=\s*["']?(https?:)?//""", text) is None, path
            assert re.search(r"""url\(\s*["']?(https?:)?//|@import""", text) is None, path
            assert re.search(r"""(from\s+|import\(\s*|fetch\(\s*)["'`](https?:)?//""", text) is None, path
            assert ".innerHTML" not in text and "insertAdjacentHTML" not in text and "document.write" not in text, path
            assert "\u2014" not in text, path


@pytest.mark.parametrize("path", [
    "/../server.py", "/%2e%2e/server.py", "/js/../../server.py", "/..%2fserver.py", "/%2e%2e%2fapi.py",
    "/js/markdown.test.mjs", "/C:/Windows/win.ini", "//etc/passwd", "/web/index.html", "/js/%2e%2e/%2e%2e/demo.py",
])
def test_path_traversal_is_impossible(srv, path):
    status, _, body = srv.raw("GET", path, token=False)
    assert status == 404
    assert b"import" not in body


# --------------------------------------------------------------- host, origin, token


@pytest.mark.parametrize("host", ["evil.example", "127.0.0.1", "127.0.0.1:1", "localhost.evil.example:{port}", ""])
def test_bad_host_is_refused(srv, host):
    status, body, _ = srv.call("GET", "/api/status", headers={"Host": host.format(port=srv.port)})
    assert status == 403 and body["error"] == "bad_host"
    status, _, _ = srv.raw("GET", "/", headers={"Host": host.format(port=srv.port)}, token=False)
    assert status == 403


def test_loopback_names_are_accepted(srv):
    for host in (f"localhost:{srv.port}", f"127.0.0.1:{srv.port}", f"[::1]:{srv.port}"):
        assert srv.call("GET", "/api/status", headers={"Host": host})[0] == 200


def test_token_is_required_on_every_api_call(srv):
    assert srv.call("GET", "/api/status", token=False)[1]["error"] == "bad_token"
    status, body, _ = srv.call("GET", "/api/status", headers={"X-Empreinte-Token": "x" * 43})
    assert status == 401 and body["error"] == "bad_token"
    status, body, _ = srv.call("POST", "/api/unlock", {"passphrase": PASS}, token=False)
    assert status == 401 and body["error"] == "bad_token"
    assert srv.call("GET", "/api/nope", token=False)[0] == 401


def test_origin_is_checked_on_state_changing_requests(srv):
    status, body, _ = srv.call("POST", "/api/unlock", {"passphrase": PASS}, origin=False)
    assert status == 403 and body["error"] == "bad_origin"
    for origin in ("http://evil.example", "null", f"http://127.0.0.1:{srv.port + 1}", f"https://127.0.0.1:{srv.port}"):
        status, body, _ = srv.call("POST", "/api/unlock", {"passphrase": PASS}, headers={"Origin": origin})
        assert status == 403 and body["error"] == "bad_origin", origin
    status, body, _ = srv.call("GET", "/api/status", headers={"Sec-Fetch-Site": "cross-site"})
    assert status == 403 and body["error"] == "cross_site"
    assert srv.call("GET", "/api/status", headers={"Sec-Fetch-Site": "same-origin"})[0] == 200
    assert srv.unlock()[0] == 200


def test_no_cors_and_options_refused(srv):
    status, headers, _ = srv.raw("OPTIONS", "/api/unlock", headers={"Origin": "http://evil.example",
                                                                      "Access-Control-Request-Method": "POST"})
    assert status == 405
    assert not any(k.startswith("access-control") for k in headers)


def test_status_without_unlock(srv):
    status, body, headers = srv.call("GET", "/api/status")
    assert status == 200
    assert body["exists"] is True and body["unlocked"] is False
    assert body["features"] == {"import": True, "previews": True, "export": True, "watch": False,
                                "anchor_methods": []}
    assert headers["cache-control"] == "no-store"


# ---------------------------------------------------------------- bodies and input


def test_body_must_be_json_and_small(srv):
    status, body, _ = srv.call("POST", "/api/unlock", headers={"Content-Type": "text/plain"})
    assert status == 415
    # Oversized: answered 413 from the headers alone, without reading the body.
    sock = socket.create_connection(("127.0.0.1", srv.port), timeout=5)
    sock.sendall((f"POST /api/unlock HTTP/1.1\r\nHost: {srv.host}\r\nX-Empreinte-Token: {srv.token}\r\n"
                  f"Origin: {srv.origin}\r\nContent-Type: application/json\r\nContent-Length: 60000\r\n\r\n").encode())
    reply = sock.recv(4096)
    sock.close()
    assert reply.startswith(b"HTTP/1.1 413") and b"Connection: close" in reply
    status, _, data = srv.raw("POST", "/api/unlock", body=b"{not json")
    assert status == 400 and json.loads(data)["error"] == "invalid"
    status, _, data = srv.raw("POST", "/api/unlock", body=b"[1, 2]")
    assert status == 400
    status, _, data = srv.raw("POST", "/api/unlock", body=b'{"passphrase": 12}')
    assert status == 400


def test_missing_content_length_and_chunked(srv):
    for extra in (b"", b"Transfer-Encoding: chunked\r\n"):
        sock = socket.create_connection(("127.0.0.1", srv.port), timeout=5)
        request = (f"POST /api/lock HTTP/1.1\r\nHost: {srv.host}\r\nX-Empreinte-Token: {srv.token}\r\n"
                   f"Origin: {srv.origin}\r\nContent-Type: application/json\r\n").encode() + extra + b"\r\n"
        if extra:
            request += b"2\r\n{}\r\n0\r\n\r\n"
        sock.sendall(request)
        reply = sock.recv(4096)
        sock.close()
        assert reply.startswith(b"HTTP/1.1 411"), reply[:40]


def test_unknown_route_and_wrong_method(srv):
    assert srv.call("GET", "/api/nothing")[1]["error"] == "no_route"
    assert srv.call("GET", "/api/unlock")[0] == 405
    assert srv.call("DELETE", "/api/entries", {})[0] == 405


# ------------------------------------------------------ passphrase and rate limit


def test_wrong_passphrase_then_rate_limit(srv):
    status, body = srv.unlock("wrong")
    assert status == 401 and body["error"] == "wrong_passphrase"
    status, body = srv.unlock("wrong again")
    assert status == 401
    status, body, headers = srv.call("POST", "/api/unlock", {"passphrase": PASS})
    assert status == 429 and body["error"] == "rate_limited" and int(headers["retry-after"]) >= 1
    assert srv.call("GET", "/api/status")[1]["retry_after"] > 0
    time.sleep(0.45)
    status, body = srv.unlock("wrong a third time")
    assert status == 401
    status, body, _ = srv.call("POST", "/api/unlock", {"passphrase": PASS})
    assert status == 429  # the delay doubled
    time.sleep(0.85)
    status, _ = srv.unlock(PASS)
    assert status == 200
    assert srv.server.app.limiter.failures == 0


def test_passphrase_never_in_logs_or_urls(tmp_path, capsys):
    vault = make_vault()
    h = Harness(session_for(vault), vault, log=True)
    try:
        h.unlock("a secret passphrase that fails")
        h.unlock()
        h.call("GET", "/api/graph?until=2099-01-01T00:00:00&tags=1")
        h.call("POST", "/api/search", {"q": "horodatage"})
    finally:
        h.close()
    err = capsys.readouterr().err
    assert "POST /api/unlock 401" in err and "GET /api/graph 200" in err
    assert "secret" not in err and "2099" not in err and "horodatage" not in err and h.token not in err


# --------------------------------------------------------------- locked access


def test_data_routes_need_the_unlock_token(srv):
    for path in ("/api/entries", "/api/graph", "/api/ledger", "/api/licenses", "/api/prefs", "/api/activity"):
        status, body, _ = srv.call("GET", path)
        assert status == 401 and body["error"] == "locked", path
    srv.unlock()
    assert srv.call("GET", "/api/entries")[0] == 200
    status, body, _ = srv.call("GET", "/api/entries", headers={"X-Empreinte-Unlock": "forged"})
    assert status == 401 and body["error"] == "locked"


def test_lock_now_forgets_keys_and_token(open_srv):
    stale = open_srv.unlock_token
    assert open_srv.call("GET", "/api/status")[1]["unlocked"] is True
    assert open_srv.call("POST", "/api/lock", {})[1] == {"locked": True}
    assert open_srv.vault._locked is True
    status, body, _ = open_srv.call("GET", "/api/entries", headers={"X-Empreinte-Unlock": stale})
    assert status == 401 and body["error"] == "locked"
    assert open_srv.call("GET", "/api/status")[1]["unlocked"] is False
    open_srv.unlock()
    assert open_srv.unlock_token != stale


def test_idle_lock(tmp_path):
    vault = make_vault()
    h = Harness(session_for(vault), vault, idle_timeout=0.5)
    try:
        assert h.unlock()[0] == 200
        assert h.call("GET", "/api/entries")[0] == 200
        for _ in range(6):  # status polls must not keep the vault open
            time.sleep(0.2)
            h.call("GET", "/api/status")
        assert vault._locked is True
        status, body, _ = h.call("GET", "/api/entries")
        assert status == 401 and body["error"] == "locked"
        assert h.call("GET", "/api/status")[1]["unlocked"] is False
    finally:
        h.close()


def test_activity_keeps_the_vault_open(tmp_path):
    vault = make_vault()
    h = Harness(session_for(vault), vault, idle_timeout=0.6)
    try:
        h.unlock()
        for _ in range(6):
            time.sleep(0.2)
            assert h.call("GET", "/api/entries")[0] == 200
        assert vault._locked is False
    finally:
        h.close()


def test_create_flow(tmp_path):
    session = session_for(None, exists=False)
    h = Harness(session, None)
    try:
        assert h.call("GET", "/api/status")[1]["exists"] is False
        status, body, _ = h.call("POST", "/api/create", {"passphrase": "court"})
        assert status == 400
        status, body, _ = h.call("POST", "/api/create", {"passphrase": "une phrase de passe longue"})
        assert status == 200 and body["recovery_key"] == "RECO-VERY-KEY0"
        h.unlock_token = body["unlock_token"]
        assert h.call("GET", "/api/entries")[0] == 200
        status, body, _ = h.call("POST", "/api/create", {"passphrase": "une autre phrase longue"})
        assert status == 409 and body["error"] == "exists"
    finally:
        h.close()


def test_refuses_non_loopback_host():
    session = session_for(make_vault())
    with pytest.raises(ValueError):
        serve(session, host="0.0.0.0")
    with pytest.raises(ValueError):
        serve(session, host="192.168.1.10")


# --------------------------------------------------------------------- entries


def test_entries_entry_text_versions_proof(open_srv):
    by_path = ids(open_srv)
    idee, plan = by_path["Recherche/idee.md"], by_path["Projets/Plan.md"]
    status, body, _ = open_srv.call("GET", f"/api/entries/{idee}")
    assert status == 200 and body["meta"]["n_versions"] == 2 and body["outlinks"] == [plan]
    assert body["backlinks"] == [plan] and "preuve" in body["parsed"]["tags"]
    status, body, _ = open_srv.call("GET", f"/api/entries/{idee}/text")
    assert body["version"] == 2 and "reprise" in body["text"]
    status, body, _ = open_srv.call("GET", f"/api/entries/{idee}/text?version=1")
    assert body["version"] == 1 and "reprise" not in body["text"]
    assert open_srv.call("GET", f"/api/entries/{idee}/text?version=9")[0] == 404
    assert open_srv.call("GET", f"/api/entries/{idee}/text?version=abc")[0] == 400
    assert open_srv.call("GET", f"/api/entries/{idee}/text?version=0")[0] == 400
    status, versions, _ = open_srv.call("GET", f"/api/entries/{idee}/versions")
    assert [v["version"] for v in versions] == [1, 2] and versions[0]["source_mtime"].startswith("2021")
    status, proof, _ = open_srv.call("GET", f"/api/entries/{idee}/proof?version=1")
    assert status == 200 and proof["record"]["version"] == 1 and proof["verified"] is True
    assert "content" not in json.dumps(proof["record"])


@pytest.mark.parametrize("bad", ["zzz", "0" * 31, "G" * 32, "%2e%2e", "a" * 33])
def test_malformed_ids_are_404(open_srv, bad):
    status, body, _ = open_srv.call("GET", f"/api/entries/{bad}")
    assert status == 404 and body["error"] in ("not_found", "no_route")


def test_unknown_ids_are_404(open_srv):
    unknown = "f" * 32
    for path in (f"/api/entries/{unknown}", f"/api/entries/{unknown}/text", f"/api/entries/{unknown}/versions",
                 f"/api/entries/{unknown}/proof"):
        status, body, _ = open_srv.call("GET", path)
        assert status == 404 and body["error"] == "not_found", path
    assert open_srv.call("POST", f"/api/entries/{unknown}/remove", {"confirm": True})[0] == 404
    assert open_srv.call("POST", "/api/licenses/nope/export", {})[0] == 404
    assert open_srv.call("POST", "/api/licenses/bad%20id!/export", {})[0] in (400, 404)
    assert open_srv.call("GET", "/api/royalties?license_id=nope")[1] == []
    assert open_srv.call("POST", "/api/royalties", {"license_id": "nope", "amount": 5})[0] == 404


def test_remove_needs_confirmation(open_srv):
    seule = ids(open_srv)["seule.md"]
    assert open_srv.call("POST", f"/api/entries/{seule}/remove", {})[0] == 400
    status, body, _ = open_srv.call("POST", f"/api/entries/{seule}/remove", {"confirm": True})
    assert status == 200 and body == {"removed": seule}
    assert "seule.md" not in ids(open_srv)
    assert open_srv.call("GET", "/api/ledger?limit=1")[1]["records"][0]["kind"] == "remove"


# ------------------------------------------------------------------ derived data


def test_graph_until_and_tags(open_srv):
    status, g, _ = open_srv.call("GET", "/api/graph")
    assert status == 200 and len(g["nodes"]) == 4 and g["unresolved"] == 0
    assert {(e["kind"]) for e in g["edges"]} == {"link"}
    status, g, _ = open_srv.call("GET", "/api/graph?tags=1")
    assert any(n["id"] == "tag:preuve" for n in g["nodes"]) and any(e["kind"] == "tag" for e in g["edges"])
    status, g, _ = open_srv.call("GET", "/api/graph?until=2022-01-01T00:00:00Z")
    assert [n["path"] for n in g["nodes"]] == ["Recherche/idee.md"]  # claimed date 2021
    assert open_srv.call("GET", "/api/graph?until=hier")[0] == 400
    assert open_srv.call("GET", "/api/graph?tags=maybe")[0] == 400


def test_search_and_mentions(open_srv):
    status, hits, _ = open_srv.call("POST", "/api/search", {"q": "horodatage"})
    assert status == 200 and {h["path"] for h in hits} == {"Recherche/idee.md", "Projets/Plan.md"}
    assert open_srv.call("POST", "/api/search", {"q": ""})[0] == 400
    assert open_srv.call("POST", "/api/search", {"q": "x" * 301})[0] == 400
    assert open_srv.call("POST", "/api/search", {"q": "a", "limit": 0})[0] == 400
    assert open_srv.call("POST", "/api/search", {"q": "a", "limit": True})[0] == 400
    status, mentions, _ = open_srv.call("POST", "/api/mentions", {"term": "horodatage"})
    assert status == 200 and len(mentions) == 3
    stamps = [m["timestamp"] for m in mentions]
    assert stamps == sorted(stamps)
    assert open_srv.call("POST", "/api/mentions", {})[0] == 400


def test_activity_both_bases(open_srv):
    status, claimed, _ = open_srv.call("GET", "/api/activity")
    assert status == 200 and claimed["basis"] == "claimed" and claimed["days"][0]["day"].startswith("2021")
    status, ledger, _ = open_srv.call("GET", "/api/activity?basis=ledger")
    assert ledger["basis"] == "ledger" and ledger["days"][0]["day"].startswith("2026")
    assert len(ledger["hour_weekday"]) == 7 and len(ledger["hour_weekday"][0]) == 24
    assert open_srv.call("GET", "/api/activity?basis=other")[0] == 400


# ------------------------------------------------------------------------ ledger


def test_ledger_paging_verify_anchors(open_srv):
    status, page, _ = open_srv.call("GET", "/api/ledger?offset=1&limit=2&order=asc")
    assert status == 200 and page["total"] == 5 and [r["seq"] for r in page["records"]] == [1, 2]
    status, page, _ = open_srv.call("GET", "/api/ledger?limit=2")
    assert [r["seq"] for r in page["records"]] == [4, 3]
    for bad in ("limit=0", "limit=501", "offset=-1", "order=up", "limit=1e3"):
        assert open_srv.call("GET", f"/api/ledger?{bad}")[0] == 400, bad
    status, report, _ = open_srv.call("POST", "/api/verify", {})
    assert status == 200 and report["ok"] is True and report["n_records"] == 5
    assert open_srv.call("GET", "/api/anchors")[1] == []
    status, body, _ = open_srv.call("POST", "/api/anchor", {"method": "rfc3161"})
    assert status == 400  # confirmation is required
    assert open_srv.call("POST", "/api/anchor", {"method": "carrier-pigeon", "confirm": True})[0] == 400
    # InMemoryVault implements no anchoring method: every method is refused before the vault is called.
    status, body, _ = open_srv.call("POST", "/api/anchor", {"method": "rfc3161", "confirm": True})
    assert status == 400 and "disponible" in body["message"]


def test_demo_vault_anchor_and_proof():
    vault = build_demo()
    proofs = [vault.proof(e.entry_id) for e in vault.entries()[:40]]
    assert any(p.proven_before for p in proofs) and vault.anchors()
    assert len(vault.entries()) > 300 and len(vault.licenses()) == 2


# --------------------------------------------------------------------- licensing


def test_license_grant_export_royalties(open_srv, tmp_path):
    by_path = ids(open_srv)
    idee, plan = by_path["Recherche/idee.md"], by_path["Projets/Plan.md"]
    payload = {"licensee": "Editions Test", "usage": "publication", "terms": "six mois",
               "items": [{"entry_id": idee, "version": 1}, {"entry_id": plan, "version": None}],
               "royalty": {"model": "flat", "amount": 100, "currency": "EUR", "note": ""}, "valid_until": "2027-01-31"}
    status, grant, _ = open_srv.call("POST", "/api/licenses", payload)
    assert status == 200 and [i["version"] for i in grant["items"]] == [1, 1] and grant["valid_until"] == "2027-01-31"
    lid = grant["license_id"]
    assert [g["license_id"] for g in open_srv.call("GET", "/api/licenses")[1]] == [lid]
    for field, value in (("items", []), ("items", [{"entry_id": "nope"}]), ("licensee", ""), ("valid_until", "31/01/2027"),
                         ("royalty", {"model": "gift"}), ("royalty", {"model": "flat", "amount": -1}),
                         ("royalty", {"model": "flat", "amount": 1, "currency": "euro"}),
                         ("royalty", {"model": "revenue_share", "amount": 150}),
                         ("royalty", {"model": "flat", "amount": float("inf")})):
        bad = dict(payload, **{field: value})
        status, body, _ = open_srv.call("POST", "/api/licenses", bad) if value != float("inf") else (None, None, None)
        if status is None:
            raw = json.dumps(bad).replace("Infinity", "1e999").encode()
            status, _, _ = open_srv.raw("POST", "/api/licenses", body=raw)
        assert status == 400, (field, value)
    unknown = dict(payload, items=[{"entry_id": "a" * 32, "version": None}])
    assert open_srv.call("POST", "/api/licenses", unknown)[0] == 404
    status, exported, _ = open_srv.call("POST", f"/api/licenses/{lid}/export", {})
    assert status == 200 and Path(exported["path"]).is_dir() and len(exported["bundle_hash"]) == 64
    status, event, _ = open_srv.call("POST", "/api/royalties", {"license_id": lid, "amount": 50.5, "currency": "EUR",
                                                                "received_on": "2026-10-01", "period": "2026-T4"})
    assert status == 200 and event["amount"] == 50.5 and event["received_on"] == "2026-10-01"
    assert open_srv.call("POST", "/api/royalties", {"license_id": lid, "amount": 0})[0] == 400
    assert open_srv.call("POST", "/api/royalties", {"license_id": lid, "amount": "5"})[0] == 400
    assert open_srv.call("POST", "/api/royalties", {"license_id": lid, "amount": 5, "currency": "eu"})[0] == 400
    assert len(open_srv.call("GET", f"/api/royalties?license_id={lid}")[1]) == 1
    assert len(open_srv.call("GET", "/api/royalties")[1]) == 1


# -------------------------------------------------------------- optional actions


def test_previews_import_prefs(open_srv, tmp_path):
    idee = ids(open_srv)["Recherche/idee.md"]
    status, previews, _ = open_srv.call("POST", "/api/previews", {"entry_ids": [idee]})
    assert status == 200 and previews[0]["entry_id"] == idee and previews[0]["version"] == 2
    assert open_srv.call("POST", "/api/previews", {"entry_ids": []})[0] == 400
    assert open_srv.call("POST", "/api/previews", {"entry_ids": ["x"]})[0] == 400
    assert open_srv.call("POST", "/api/previews", {"entry_ids": ["b" * 32]})[0] == 404
    assert open_srv.call("POST", "/api/import", {"path": "relative/dir"})[0] == 400
    assert open_srv.call("POST", "/api/import", {"path": str(tmp_path / "missing")})[0] == 400
    status, body, _ = open_srv.call("POST", "/api/import", {"path": str(tmp_path)})
    assert status == 200 and body == {"added": 1}
    assert "Importe/nouveau.md" in ids(open_srv)
    assert len(open_srv.call("GET", "/api/graph")[1]["nodes"]) == 5  # workspace refreshed
    assert open_srv.call("GET", "/api/prefs")[1] == {}
    assert open_srv.call("PUT", "/api/prefs", {"graph": {"repel": 12}})[1] == {"saved": True}
    assert open_srv.call("GET", "/api/prefs")[1] == {"graph": {"repel": 12}}
    assert open_srv.vault.aux_get("ui.prefs.v1") is not None
    status, _, _ = open_srv.call("PUT", "/api/prefs", {"big": "x" * 70_000})
    assert status == 413


def test_features_off(tmp_path):
    vault = make_vault()
    h = Harness(session_for(vault, with_extras=False), vault)
    try:
        assert h.call("GET", "/api/status")[1]["features"] == {"import": False, "previews": False, "export": False,
                                                                "watch": False, "anchor_methods": []}
        h.unlock()
        idee = ids(h)["Recherche/idee.md"]
        assert h.call("POST", "/api/previews", {"entry_ids": [idee]})[1]["error"] == "feature_off"
        assert h.call("POST", "/api/import", {"path": str(tmp_path)})[1]["error"] == "feature_off"
        grant = vault.grant("x", [(idee, None)], usage="u")
        assert h.call("POST", f"/api/licenses/{grant.license_id}/export", {})[1]["error"] == "feature_off"
    finally:
        h.close()


# ------------------------------------------------------------------ error mapping


def test_errors_are_mapped_without_leaking(open_srv, monkeypatch):
    idee = ids(open_srv)["Recherche/idee.md"]
    ws = open_srv.server.app.active.workspace

    def boom(*a, **k):
        raise RuntimeError("plaintext secret in the message")

    monkeypatch.setattr(ws, "search", boom)
    status, body, _ = open_srv.call("POST", "/api/search", {"q": "x"})
    assert status == 500 and body["error"] == "internal" and "secret" not in json.dumps(body)

    def corrupted(*a, **k):
        raise Corrupted("blob 3 failed")

    monkeypatch.setattr(open_srv.vault, "versions", corrupted)
    status, body, _ = open_srv.call("GET", f"/api/entries/{idee}/versions")
    assert status == 500 and body["error"] == "corrupted"


# ------------------------------------------------------------------ the renderer


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_markdown_renderer_against_hostile_input():
    result = subprocess.run(["node", str(WEB / "js" / "markdown.test.mjs")], capture_output=True, text=True,
                            timeout=60, encoding="utf-8")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "all checks passed" in result.stdout


def test_demo_session_serves(tmp_path):
    from empreinte.demo import demo_session

    session = demo_session()
    h = Harness(session, None)
    try:
        assert h.unlock("demo")[0] == 200
        status, g, _ = h.call("GET", "/api/graph")
        assert status == 200 and len(g["nodes"]) > 300 and len(g["edges"]) > 300
        assert len(h.call("GET", "/api/licenses")[1]) == 2
        assert h.call("GET", "/api/status")[1]["features"]["anchor_methods"] == ["rfc3161"]
        assert h.call("GET", "/api/status")[1]["features"]["import"] is False  # finding 10: no real files
        status, a, _ = h.call("POST", "/api/anchor", {"method": "rfc3161", "confirm": True})
        assert status == 200 and "aucune autorité" in a["authority"]
        assert h.call("POST", "/api/anchor", {"method": "opentimestamps", "confirm": True})[0] == 400
    finally:
        h.close()
        shutil.rmtree(session.export_dir, ignore_errors=True)


# --------------------------------------------- fix round after the 2026-11-14 review


def test_lock_closes_the_workspace_and_drops_the_session():  # finding 1
    vault = make_vault()
    session, state = session_and_state(vault)
    h = Harness(session, vault)
    try:
        h.unlock()
        first = state["workspaces"][-1]
        h.unlock()  # replacing a session closes the previous workspace
        assert first._closed and first._text == {} and first._meta == {}
        second = state["workspaces"][-1]
        assert not second._closed
        assert h.call("POST", "/api/lock", {})[0] == 200
        assert second._closed and second._text == {} and second._parsed == {}
        assert h.server.app.active is None and vault._locked
        for fn in (session.import_folder, session.make_previews):
            assert not any(isinstance(c.cell_contents, (InMemoryVault, StubWorkspace)) for c in fn.__closure__ or ())
    finally:
        h.close()


def test_idle_lock_closes_the_workspace():  # finding 1
    vault = make_vault()
    session, state = session_and_state(vault)
    h = Harness(session, vault, idle_timeout=0.3)
    try:
        h.unlock()
        time.sleep(0.9)
        assert state["workspaces"][-1]._closed and h.server.app.active is None
    finally:
        h.close()


def test_request_authorised_before_a_lock_cannot_run_on_the_next_session(open_srv):  # finding 2
    seule = ids(open_srv)["seule.md"]
    stale = open_srv.unlock_token
    body = b'{"confirm": true}'
    sock = socket.create_connection(("127.0.0.1", open_srv.port), timeout=5)
    sock.sendall((f"POST /api/entries/{seule}/remove HTTP/1.1\r\nHost: {open_srv.host}\r\n"
                  f"X-Empreinte-Token: {open_srv.token}\r\nX-Empreinte-Unlock: {stale}\r\n"
                  f"Origin: {open_srv.origin}\r\nContent-Type: application/json\r\n"
                  f"Content-Length: {len(body)}\r\n\r\n").encode() + body[:1])
    time.sleep(0.2)  # the server is now waiting for the rest of the body
    assert open_srv.call("POST", "/api/lock", {})[0] == 200
    assert open_srv.unlock()[0] == 200 and open_srv.unlock_token != stale
    sock.sendall(body[1:])
    reply = _read_all(sock)
    assert reply.startswith(b"HTTP/1.1 401") and b'"locked"' in reply
    assert "seule.md" in ids(open_srv)


def test_unlock_finishing_after_a_lock_installs_nothing():  # finding 2
    import threading

    vault = make_vault()
    session, state = session_and_state(vault)
    original = session.open_vault
    gate, entered, slow = threading.Event(), threading.Event(), {"on": False}

    def slow_open(passphrase):
        if slow["on"]:
            entered.set()
            gate.wait(5)
        return original(passphrase)

    session.open_vault = slow_open
    h = Harness(session, vault)
    try:
        h.unlock()
        token_a = h.unlock_token
        slow["on"] = True
        result = {}
        worker = threading.Thread(target=lambda: result.update(
            r=h.call("POST", "/api/unlock", {"passphrase": PASS}, unlock=False)))
        worker.start()
        assert entered.wait(5)
        status, _, _ = h.call("POST", "/api/lock", {}, headers={"X-Empreinte-Unlock": token_a})
        assert status == 200
        gate.set()
        worker.join(5)
        status, body, _ = result["r"]
        assert status == 409 and body["error"] == "locked_meanwhile"
        assert h.server.app.active is None
        assert state["workspaces"][-1]._closed  # the late session was closed, not installed
    finally:
        gate.set()
        h.close()


def test_lock_needs_the_unlock_token_when_open(open_srv):  # finding 7
    status, body, _ = open_srv.call("POST", "/api/lock", {}, unlock=False)
    assert status == 401
    status, body, _ = open_srv.call("POST", "/api/lock", {}, headers={"X-Empreinte-Unlock": "forged"})
    assert status == 401
    assert open_srv.call("GET", "/api/status")[1]["unlocked"] is True
    assert open_srv.call("POST", "/api/lock", {})[1] == {"locked": True}
    assert open_srv.call("POST", "/api/lock", {}, unlock=False)[1] == {"locked": True}  # already locked: no-op


def _read_all(sock) -> bytes:
    """Everything the server sends until it closes the connection."""
    data = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except OSError:
            break
        if not chunk:
            break
        data += chunk
    sock.close()
    return data


def _dos_harness(**opts) -> Harness:
    vault = make_vault()
    return Harness(session_for(vault), vault, **opts)


def test_slow_headers_are_cut_off():  # finding 6
    h = _dos_harness(socket_timeout=0.3, header_deadline=0.6)
    try:
        sock = socket.create_connection(("127.0.0.1", h.port), timeout=3)
        sock.sendall(f"GET / HTTP/1.1\r\nHost: {h.host}\r\n".encode())
        started = time.monotonic()
        closed = False
        while time.monotonic() - started < 3 and not closed:
            try:
                sock.sendall(b"X-Slow: 1\r\n")
                time.sleep(0.1)
                sock.setblocking(False)
                try:
                    closed = sock.recv(1) == b""
                except BlockingIOError:
                    pass
                finally:
                    sock.setblocking(True)
            except OSError:
                closed = True
        sock.close()
        assert closed and time.monotonic() - started < 2
    finally:
        h.close()


def test_rejected_request_is_answered_without_reading_its_body():  # finding 6
    h = _dos_harness(socket_timeout=5)
    try:
        sock = socket.create_connection(("127.0.0.1", h.port), timeout=3)
        sock.sendall((f"POST /api/lock HTTP/1.1\r\nHost: {h.host}\r\nX-Empreinte-Token: wrong\r\n"
                      f"Origin: {h.origin}\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n").encode())
        started = time.monotonic()
        reply = _read_all(sock)  # returns because the server closes the connection
        assert reply.startswith(b"HTTP/1.1 401") and b"Connection: close" in reply and b"bad_token" in reply
        assert time.monotonic() - started < 1
    finally:
        h.close()


def test_connections_are_capped():  # finding 6
    h = _dos_harness(socket_timeout=5, header_deadline=5, max_connections=2)
    try:
        idle = [socket.create_connection(("127.0.0.1", h.port), timeout=3) for _ in range(2)]
        time.sleep(0.2)
        extra = socket.create_connection(("127.0.0.1", h.port), timeout=3)
        reply = extra.recv(4096)
        extra.close()
        assert reply.startswith(b"HTTP/1.1 503") and b"Content-Security-Policy" in reply
        for sock in idle:
            sock.close()
        time.sleep(0.3)
        assert h.call("GET", "/api/status")[0] == 200
    finally:
        h.close()


@pytest.mark.parametrize("raw", [b"BOGUS\r\n\r\n", b"TRACE / HTTP/1.1\r\nHost: x\r\n\r\n",
                                 b"GET /" + b"a" * 70000 + b" HTTP/1.1\r\n\r\n"])
def test_http_server_errors_carry_security_headers(srv, raw):
    sock = socket.create_connection(("127.0.0.1", srv.port), timeout=5)
    try:
        sock.sendall(raw)
    except OSError:
        pass
    reply = b""
    while b"\r\n\r\n" not in reply:
        try:
            chunk = sock.recv(4096)
        except OSError:
            break
        if not chunk:
            break
        reply += chunk
    sock.close()
    head = reply.split(b"\r\n\r\n")[0]
    assert re.match(rb"HTTP/1\.[01] (400|414|501)", head), head[:40]
    for name in (b"Content-Security-Policy", b"Cache-Control: no-store", b"X-Content-Type-Options: nosniff",
                 b"X-Frame-Options: DENY", b"Referrer-Policy: no-referrer"):
        assert name in head


def test_entry_returns_link_targets_resolved_near_the_source():  # finding 12 (server side)
    vault = ReopenableVault(clock=stepping_clock())
    vault.put("A/Note.md", b"# Note A")
    vault.put("B/Note.md", b"# Note B")
    vault.put("B/source.md", b"Voir [[Note]] et [[Absente]].")
    h = Harness(session_for(vault), vault)
    try:
        h.unlock()
        by_path = ids(h)
        status, body, _ = h.call("GET", f"/api/entries/{by_path['B/source.md']}")
        assert status == 200 and body["link_targets"] == {"Note": by_path["B/Note.md"]}
    finally:
        h.close()


def test_graph_nodes_carry_node_type(open_srv):
    nodes = open_srv.call("GET", "/api/graph?tags=1")[1]["nodes"]
    assert {n["node_type"] for n in nodes if n["id"].startswith("tag:")} == {"tag"}
    assert {n["node_type"] for n in nodes if not n["id"].startswith("tag:")} == {"entry"}


def test_preview_is_a_draft_until_approved(open_srv):
    idee = ids(open_srv)["Recherche/idee.md"]
    assert open_srv.call("GET", f"/api/previews/{idee}")[0] == 404
    status, made, _ = open_srv.call("POST", "/api/previews", {"entry_ids": [idee]})
    assert status == 200 and made[0]["approved"] is False
    status, stored, _ = open_srv.call("GET", f"/api/previews/{idee}")
    assert status == 200 and stored["approved"] is False and stored["current"] is True
    assert made[0]["digest"] == stored["digest"] and len(stored["digest"]) == 64
    assert open_srv.call("POST", f"/api/previews/{idee}/approve", {})[0] == 400  # digest required
    status, body, _ = open_srv.call("POST", f"/api/previews/{idee}/approve", {"digest": "0" * 64})
    assert status == 409 and body["error"] == "changed"
    status, approved, _ = open_srv.call("POST", f"/api/previews/{idee}/approve", {"digest": stored["digest"]})
    assert status == 200 and approved["approved"] is True and approved["digest"] != stored["digest"]
    assert open_srv.call("GET", f"/api/previews/{idee}")[1]["approved"] is True
    open_srv.vault.put("Recherche/idee.md", b"# Idee\n\nune troisieme version")
    assert open_srv.call("GET", f"/api/previews/{idee}")[1]["current"] is False
    regenerated = open_srv.call("POST", "/api/previews", {"entry_ids": [idee]})[1][0]
    status, body, _ = open_srv.call("POST", f"/api/previews/{idee}/approve", {"digest": approved["digest"]})
    assert status == 409 and body["error"] == "changed"  # the displayed preview was replaced: refused
    assert open_srv.call("POST", f"/api/previews/{idee}/approve", {"digest": regenerated["digest"]})[0] == 200
    open_srv.vault.put("Recherche/idee.md", b"# Idee\n\nune quatrieme version")
    current = open_srv.call("GET", f"/api/previews/{idee}")[1]
    status, body, _ = open_srv.call("POST", f"/api/previews/{idee}/approve", {"digest": current["digest"]})
    assert status == 409 and body["error"] == "stale"
    assert open_srv.call("POST", "/api/previews/" + "c" * 32 + "/approve", {"digest": "0" * 64})[0] == 404
    assert open_srv.call("GET", "/api/previews/nope")[0] == 404


def test_demo_proofs_have_three_states():
    vault = build_demo()
    proofs = [vault.proof(e.entry_id) for e in vault.entries()]
    assert any(p.proven_before for p in proofs)
    assert any(p.claimed_before and not p.proven_before and p.anchor_errors for p in proofs)
    assert any(not p.anchors and not p.proven_before and not p.claimed_before for p in proofs)


# --------------------------------------------------- fix round after the 2026-11-15 audit


def _gated_session(vault):
    """A session whose open_vault can be held at a gate, to test pending unlocks."""
    import threading

    session, state = session_and_state(vault)
    original = session.open_vault
    ctl = {"gate": threading.Event(), "entered": threading.Event(), "on": False}

    def slow_open(passphrase):
        if ctl["on"]:
            ctl["entered"].set()
            ctl["gate"].wait(5)
        return original(passphrase)

    session.open_vault = slow_open
    return session, state, ctl


def _unlock_in_background(h: Harness) -> tuple:
    import threading

    result: dict = {}
    worker = threading.Thread(target=lambda: result.update(
        r=h.call("POST", "/api/unlock", {"passphrase": PASS}, unlock=False)))
    worker.start()
    return worker, result


def test_first_unlock_pending_during_a_lock_installs_nothing():  # A2, d
    vault = make_vault()
    session, state, ctl = _gated_session(vault)
    h = Harness(session, vault)
    try:
        ctl["on"] = True
        worker, result = _unlock_in_background(h)
        assert ctl["entered"].wait(5)
        assert h.call("POST", "/api/lock", {}, unlock=False)[1] == {"locked": True}  # nothing open yet
        ctl["gate"].set()
        worker.join(5)
        status, body, _ = result["r"]
        assert status == 409 and body["error"] == "locked_meanwhile"
        assert h.server.app.active is None and state["workspaces"][-1]._closed and vault._locked
    finally:
        ctl["gate"].set()
        h.close()


def test_unlock_pending_during_shutdown_is_disposed():  # new defect 2
    import threading

    vault = make_vault()
    session, state, ctl = _gated_session(vault)
    h = Harness(session, vault)
    ctl["on"] = True
    worker, result = _unlock_in_background(h)
    assert ctl["entered"].wait(5)
    stopper = threading.Thread(target=h.server.shutdown)
    stopper.start()
    time.sleep(0.2)
    ctl["gate"].set()
    worker.join(5)
    stopper.join(5)
    assert h.server.app.active is None and h.server.app.stopped
    assert state["workspaces"][-1]._closed and vault._locked


def test_unlock_while_unlocked_closes_the_current_vault_before_opening():  # new defect 3
    events: list[str] = []

    class Recording(ReopenableVault):
        def lock(self):
            events.append("lock")
            super().lock()

        def close(self):
            events.append("close")

    vault = Recording(clock=stepping_clock())
    vault.put("a.md", b"# A")
    session, state = session_and_state(vault)
    original = session.open_vault

    def open_vault(passphrase):
        events.append("open")
        return original(passphrase)

    session.open_vault = open_vault
    h = Harness(session, vault)
    try:
        h.unlock()
        events.clear()
        h.unlock()
        assert events[:3] == ["lock", "close", "open"]
        assert h.call("GET", "/api/entries")[0] == 200
    finally:
        h.close()


def test_trickled_header_line_cannot_extend_the_deadline():  # A6
    h = _dos_harness(socket_timeout=0.4, header_deadline=0.6)
    try:
        sock = socket.create_connection(("127.0.0.1", h.port), timeout=3)
        sock.sendall(f"GET / HTTP/1.1\r\nHost: {h.host}\r\nX-Slow: ".encode())
        started = time.monotonic()
        closed = False
        while time.monotonic() - started < 3 and not closed:
            try:
                sock.sendall(b"a")  # never a newline: one unfinished header line
                time.sleep(0.1)
                sock.setblocking(False)
                try:
                    closed = sock.recv(1) == b""
                except BlockingIOError:
                    pass
                finally:
                    sock.setblocking(True)
            except OSError:
                closed = True
        sock.close()
        assert closed and time.monotonic() - started < 1.5
    finally:
        h.close()


def test_expect_continue_is_refused_with_security_headers(srv):  # j
    sock = socket.create_connection(("127.0.0.1", srv.port), timeout=5)
    sock.sendall((f"POST /api/unlock HTTP/1.1\r\nHost: {srv.host}\r\nX-Empreinte-Token: {srv.token}\r\n"
                  f"Origin: {srv.origin}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n"
                  f"Expect: 100-continue\r\n\r\n").encode())
    reply = _read_all(sock)
    head = reply.split(b"\r\n\r\n")[0]
    assert head.startswith(b"HTTP/1.1 417") and b"100 Continue" not in reply
    assert b"Content-Security-Policy" in head and b"Cache-Control: no-store" in head


def test_preview_generation_does_not_hold_the_session_lock():  # new defect 6
    import threading

    vault = make_vault()
    session, state = session_and_state(vault)
    gate, entered = threading.Event(), threading.Event()
    original = session.make_previews

    def slow(v, ws, ids_):
        result = original(v, ws, ids_)  # stores through the guarded vault: recorded, not written
        entered.set()
        gate.wait(5)
        return result

    session.make_previews = slow
    h = Harness(session, vault)
    try:
        h.unlock()
        idee = ids(h)["Recherche/idee.md"]
        result: dict = {}
        worker = threading.Thread(target=lambda: result.update(r=h.call("POST", "/api/previews", {"entry_ids": [idee]})))
        worker.start()
        assert entered.wait(5)
        started = time.monotonic()
        assert h.call("GET", "/api/entries")[0] == 200  # not blocked by the generation
        assert h.call("POST", "/api/lock", {})[0] == 200
        assert time.monotonic() - started < 1
        gate.set()
        worker.join(5)
        status, body, _ = result["r"]
        assert status == 409 and body["error"] == "locked_meanwhile"
        vault.reopen()
        assert vault.aux_get("preview/" + idee) is None  # nothing stored after the lock
    finally:
        gate.set()
        h.close()


def test_proof_and_verify_pass_anchor_status_through():  # a, new defect 9
    from empreinte.demo import demo_session

    session = demo_session()
    h = Harness(session, None)
    try:
        h.unlock("demo")
        report = h.call("POST", "/api/verify", {})[1]
        assert "anchor_status" in report
        entry = next(iter(ids(h).values()))
        assert "anchor_status" in h.call("GET", f"/api/entries/{entry}/proof")[1]
    finally:
        h.close()
        shutil.rmtree(session.export_dir, ignore_errors=True)


# --------------------------------------------------- fix round after the closing audit


def test_a_lock_is_not_undone_by_an_unlock_waiting_for_its_turn():  # closing audit, defect 2
    import threading

    vault = make_vault()
    h = Harness(session_for(vault), vault)
    try:
        h.unlock()
        token_a = h.unlock_token
        app = h.server.app
        app.auth_lock.acquire()  # another passphrase attempt is being checked
        try:
            worker, result = _unlock_in_background(h)
            time.sleep(0.3)  # the new attempt has arrived and waits for its turn
            assert h.call("POST", "/api/lock", {}, headers={"X-Empreinte-Unlock": token_a})[0] == 200
        finally:
            app.auth_lock.release()
        worker.join(5)
        status, body, _ = result["r"]
        assert status == 409 and body["error"] == "locked_meanwhile"
        assert app.active is None  # the owner's lock stands
        assert h.call("GET", "/api/status")[1]["unlocked"] is False
    finally:
        h.close()


def test_a_wrong_passphrase_does_not_close_the_open_session():  # closing audit, defect 4
    vault = make_vault()
    h = Harness(session_for(vault), vault)
    try:
        h.unlock()
        token_a = h.unlock_token
        status, body, _ = h.call("POST", "/api/unlock", {"passphrase": "wrong one"}, unlock=False)
        assert status == 401 and body["error"] == "wrong_passphrase"
        status, _, _ = h.call("GET", "/api/entries", headers={"X-Empreinte-Unlock": token_a})
        assert status == 200
        assert h.server.app.active is not None and h.server.app.active.token == token_a
    finally:
        h.close()


def test_second_unlock_of_a_real_vault_authenticates_then_hands_over_the_writer(tmp_path):
    from empreinte import crypto
    from empreinte.cli import session_for as real_session

    session = real_session(tmp_path / "coffre", kdf_params=crypto.TEST_KDF)
    h = Harness(session, None)
    try:
        status, body, _ = h.call("POST", "/api/create", {"passphrase": "une phrase assez longue"})
        assert status == 200
        first = body["unlock_token"]
        status, _, _ = h.call("POST", "/api/unlock", {"passphrase": "pas la bonne phrase"}, unlock=False)
        assert status == 401
        assert h.call("GET", "/api/entries", headers={"X-Empreinte-Unlock": first})[0] == 200
        assert h.unlock("une phrase assez longue")[0] == 200 and h.unlock_token != first
        assert not getattr(h.server.app.active.vault, "held_by_another_writer")  # the writer moved over
        assert h.call("GET", "/api/entries", headers={"X-Empreinte-Unlock": first})[0] == 401
    finally:
        h.close()


def test_a_preview_of_an_older_version_is_refused_at_commit():  # closing audit, defect 3
    import threading

    vault = make_vault()
    session, state = session_and_state(vault)
    gate, entered, slow = threading.Event(), threading.Event(), {"on": True}
    original = session.make_previews

    def held(v, ws, ids_):
        result = original(v, ws, ids_)  # generated for the version current now (v1 below)
        if slow["on"]:
            slow["on"] = False
            entered.set()
            gate.wait(5)
        return result

    session.make_previews = held
    h = Harness(session, vault)
    try:
        h.unlock()
        plan = ids(h)["Projets/Plan.md"]
        result: dict = {}
        worker = threading.Thread(target=lambda: result.update(r=h.call("POST", "/api/previews", {"entry_ids": [plan]})))
        worker.start()
        assert entered.wait(5)
        vault.put("Projets/Plan.md", b"# Plan\n\nUne nouvelle version du plan, sur un autre sujet.")
        status, newer, _ = h.call("POST", "/api/previews", {"entry_ids": [plan]})
        assert status == 200 and newer[0]["version"] == 2
        assert h.call("POST", f"/api/previews/{plan}/approve", {"digest": newer[0]["digest"]})[0] == 200
        gate.set()
        worker.join(5)
        status, body, _ = result["r"]
        assert status == 409 and body["error"] == "stale"
        stored = h.call("GET", f"/api/previews/{plan}")[1]
        assert stored["version"] == 2 and stored["approved"] and stored["current"]
    finally:
        gate.set()
        h.close()


def test_anchoring_does_not_hold_the_operation_lock():  # closing audit, server.py anchor call
    import threading

    gate, entered = threading.Event(), threading.Event()

    class SlowAnchor(ReopenableVault):
        def anchor_methods(self):
            return ["rfc3161"]

        def anchor(self, method="rfc3161"):
            entered.set()
            gate.wait(5)  # the authority is slow to answer
            if self._locked:
                raise VaultError("the vault was locked during the timestamp request; the anchor is not stored")
            raise VaultError("refusé par le test")

    from empreinte.api import VaultError

    vault = SlowAnchor(clock=stepping_clock())
    vault.put("a.md", b"# A")
    h = Harness(session_for(vault), vault)
    try:
        h.unlock()
        result: dict = {}
        worker = threading.Thread(target=lambda: result.update(
            r=h.call("POST", "/api/anchor", {"method": "rfc3161", "confirm": True})))
        worker.start()
        assert entered.wait(5)
        started = time.monotonic()
        assert h.call("GET", "/api/entries")[0] == 200
        assert h.call("POST", "/api/lock", {})[0] == 200
        assert time.monotonic() - started < 1
        gate.set()
        worker.join(5)
        status, body, _ = result["r"]
        assert status == 409 and "locked" in body["message"]
    finally:
        gate.set()
        h.close()


@pytest.mark.parametrize("length", ["9" * 5000, "²", "12 3", "-1", "+5"])
def test_an_absurd_content_length_gets_a_structured_400(srv, length):  # j
    sock = socket.create_connection(("127.0.0.1", srv.port), timeout=5)
    sock.sendall((f"POST /api/unlock HTTP/1.1\r\nHost: {srv.host}\r\nX-Empreinte-Token: {srv.token}\r\n"
                  f"Origin: {srv.origin}\r\nContent-Type: application/json\r\nContent-Length: {length}\r\n\r\n"
                  ).encode("utf-8"))
    reply = _read_all(sock)
    head, _, body = reply.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 400"), reply[:200]
    assert json.loads(body)["error"] == "invalid"


def test_historical_text_comes_with_its_own_link_targets(open_srv):  # closing audit c, defect 9
    vault = open_srv.vault
    target = vault.find("Projets/Plan.md").entry_id
    note = vault.put("Historique.md", b"Voir [[Plan]].")
    vault.put("Historique.md", b"Le lien a disparu.")
    open_srv.server.app.active.workspace.refresh()
    first = open_srv.call("GET", f"/api/entries/{note.entry_id}/text?version=1")[1]
    latest = open_srv.call("GET", f"/api/entries/{note.entry_id}/text")[1]
    assert first["link_targets"] == {"Plan": target}
    assert latest["link_targets"] == {}
