import json
import socket

import httpx
import pytest

from empreinte.localllm import LLMError, LocalLLMClient, complete_json, strip_reasoning
from empreinte.previews import _Teaser, _validate, load_preview, make_preview, make_previews
from empreinte.testing import InMemoryVault, stepping_clock
from empreinte.workspace import Workspace


SAFE = {"summary": "An exploration of creative habits considers recurring obstacles. Practical reflections address sustainable routines.",
        "keywords": ["creativity", "practice", "reflection"]}


def client_for(replies):
    calls = []

    def respond(request):
        calls.append(request)
        reply = replies[min(len(calls) - 1, len(replies) - 1)]
        return httpx.Response(200, json={"choices": [{"message": {"content": reply}}]})

    return LocalLLMClient(transport=httpx.MockTransport(respond), sleep=lambda _: None), calls


def test_preview_round_trip_and_json_candidates():
    vault = InMemoryVault(clock=stepping_clock())
    v = vault.put("a.md", b"Alice writes privately about painting every morning.")
    workspace = Workspace(vault)
    client, calls = client_for(['<think>{"summary":"leak"}</think> {"wrong":1}\n```json\n' + json.dumps(SAFE) + '\n```'])
    with client:
        preview = make_preview(client, vault, workspace, v.entry_id)
        assert load_preview(vault, v.entry_id) == preview
        assert preview.approved is False
        assert json.loads(vault.aux_get("preview/" + v.entry_id))["approved"] is False
        assert preview.commitment == v.commitment and preview.version == 1
        assert len(calls) == 1
        assert len(make_previews(client, vault, workspace)) == 1
    vault.put("a.md", b"new content")
    assert load_preview(vault, v.entry_id) is None


@pytest.mark.parametrize("unsafe,document", [
    ({"summary": "one two three four five six seven eight. A generic second sentence.", "keywords": ["a", "b", "c"]},
     "one two three four five six seven eight nine ten"),
    ({"summary": "Alice studies recurring patterns in routine. Broader themes concern motivation.", "keywords": ["a", "b", "c"]},
     "Alice has a private diary."),
    ({"summary": "one two three four. five six seven eight.", "keywords": ["a", "b", "c"]},
     "one two three four different five six seven eight"),
])
def test_reject_and_reask_once(unsafe, document):
    vault = InMemoryVault(clock=stepping_clock())
    v = vault.put("a.md", document.encode())
    workspace = Workspace(vault)
    client, calls = client_for([json.dumps(unsafe), json.dumps(SAFE)])
    with client:
        assert make_preview(client, vault, workspace, v.entry_id).summary == SAFE["summary"]
    assert len(calls) == 2
    client, calls = client_for([json.dumps(unsafe)])
    with client, pytest.raises(LLMError, match="two attempts"):
        make_preview(client, vault, workspace, v.entry_id, force=True)
    assert len(calls) == 2


def test_pii_scrubbing_bounds_and_no_storage_on_failure():
    vault = InMemoryVault(clock=stepping_clock())
    v = vault.put("a.md", b"private diary")
    reply = dict(SAFE, keywords=["creativity", "practice", "a@example.org"])
    client, _ = client_for([json.dumps(reply)])
    with client:
        preview = make_preview(client, vault, Workspace(vault), v.entry_id)
        assert "[EMAIL]" in preview.keywords
    vault.aux_put("preview/" + v.entry_id, b"invalid")
    assert load_preview(vault, v.entry_id) is None
    client, calls = client_for([json.dumps(dict(SAFE, summary="Only one sentence."))])
    with client, pytest.raises(LLMError):
        make_preview(client, vault, Workspace(vault), v.entry_id)
    assert len(calls) == 2


def test_loopback_restriction_redirects_and_retries(monkeypatch):
    vault = InMemoryVault(clock=stepping_clock())
    vault.put("a.md", b"private")
    for url in ["https://example.com/v1", "http://192.168.1.1/v1", "http://127.0.0.1@evil.com/v1",
                "file:///tmp/model", "http://[::ffff:192.168.1.1]/v1"]:
        with pytest.raises(ValueError):
            LocalLLMClient(url)
    calls = []

    def redirect(request):
        calls.append(request)
        return httpx.Response(302, headers={"location": "https://example.com"})

    with LocalLLMClient(transport=httpx.MockTransport(redirect)) as client:
        with pytest.raises(LLMError, match="302"):
            client.complete([])
    assert len(calls) == 1
    calls.clear()

    def retry(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(503)
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(SAFE)}}]})

    with LocalLLMClient(transport=httpx.MockTransport(retry), sleep=lambda _: None) as client:
        assert complete_json(client, [], _Teaser).summary == SAFE["summary"]
    assert len(calls) == 2
    assert strip_reasoning("<think>secret") == ""
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 80))])
    with pytest.raises(ValueError, match="non-loopback"):
        LocalLLMClient("http://localhost/v1")


@pytest.mark.parametrize("keywords,document", [
    (["cobalt velvet falcon", "meadow copper willow", "lantern orbit"],
     "cobalt velvet falcon meadow copper willow lantern orbit"),
    (["unusual private phrase here", "practice", "reflection"], "unrelated source"),
    (["velvet falcon", "practice", "reflection"], "a velvet falcon appears"),
    (["alice", "practice", "reflection"], "we met Alice yesterday."),
    (["Alice", "practice", "reflection"], "we met Alice yesterday."),
    # The revealing order differs from the returned order; each keyword is one word.
    (["cobalt", "falcon", "velvet", "copper", "meadow"], "cobalt velvet falcon meadow copper"),
    (["cobalt", "velvet", "falcon", "meadow"], "cobalt velvet falcon meadow"),
    (["meadow", "falcon", "cobalt", "velvet"], "the cobalt and velvet le falcon et meadow"),
])
def test_combined_disclosure_rejected(keywords, document):
    with pytest.raises(ValueError):
        _validate(_Teaser(**dict(SAFE, keywords=keywords)), document)


def test_five_word_run_across_summary_keyword_boundary():
    teaser = _Teaser(summary="General ideas concern cobalt velvet falcon. Meadow copper.",
                     keywords=["willow", "lantern", "orbit"])
    with pytest.raises(ValueError, match="copies"):
        _validate(teaser, "falcon meadow copper willow lantern orbit")


def test_abstract_long_teaser_has_bounded_checks(monkeypatch):
    import empreinte.previews as previews

    original = previews._grams
    work = 0

    def counted(words, size):
        nonlocal work
        work += len(words)
        assert work < 100_000, "disclosure checks must not enumerate keyword orders"
        return original(words, size)

    monkeypatch.setattr(previews, "_grams", counted)
    document = "cobalt velvet falcon meadow " * 2000
    teaser = _Teaser(**dict(SAFE, keywords=["creativity", "practice", "reflection", "ideas",
                                          "habits", "motivation", "learning", "growth"]))
    assert _validate(teaser, document) == (teaser.summary, teaser.keywords)
