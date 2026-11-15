import json

from empreinte.context import CONTEXT_BYTES, compact_context, preview_cache_policy
from empreinte.previews import make_preview
from empreinte.testing import InMemoryVault, stepping_clock
from empreinte.workspace import Workspace
from test_previews import SAFE, client_for


def test_compaction_removes_metadata_and_repeated_paragraphs():
    text = "---\nprivate: hidden-metadata\n---\n\n# Topic\n\nRepeated paragraph.\n\nRepeated paragraph."
    context = compact_context(text, "text/markdown")
    assert "hidden-metadata" not in context.text
    assert context.text.count("Repeated paragraph.") == 1
    assert context.sent_bytes < context.source_bytes
    assert not context.partial


def test_budget_is_utf8_safe_and_samples_three_regions():
    document = "BEGIN " + "é中🌍" * 20_000 + " END"
    context = compact_context(document, "text/plain")
    assert context.sent_bytes <= CONTEXT_BYTES
    assert context.sent_bytes == len(context.text.encode("utf-8"))
    assert context.partial
    assert context.text.startswith("BEGIN ") and context.text.endswith(" END")
    assert context.text.count("passage omis") == 2
    assert "\ufffd" not in context.text
    assert compact_context(document, "text/plain") == context


def test_preview_cache_and_invalidation():
    vault = InMemoryVault(clock=stepping_clock())
    entry = vault.put("a.md", b"private diary")
    workspace = Workspace(vault)
    client, calls = client_for([json.dumps(SAFE)])
    with client:
        first = make_preview(client, vault, workspace, entry.entry_id)
        assert make_preview(client, vault, workspace, entry.entry_id) == first
        assert len(calls) == 1
        assert first.context_policy == preview_cache_policy(client.base_url)
        first.approved = True
        vault.aux_put("preview/" + entry.entry_id, first.model_dump_json().encode())
        assert make_preview(client, vault, workspace, entry.entry_id).approved
        assert len(calls) == 1
        client.model = "other-local-model"
        make_preview(client, vault, workspace, entry.entry_id)
        assert len(calls) == 2
        vault.put("a.md", b"changed diary")
        make_preview(client, vault, workspace, entry.entry_id)
        assert len(calls) == 3
        make_preview(client, vault, workspace, entry.entry_id, force=True)
        assert len(calls) == 4
        old = make_preview(client, vault, workspace, entry.entry_id)
        old.context_policy = "obsolete"
        vault.aux_put("preview/" + entry.entry_id, old.model_dump_json().encode())
        assert not make_preview(client, vault, workspace, entry.entry_id).approved
        assert len(calls) == 5


def test_long_preview_payload_is_bounded_and_checks_omitted_text():
    vault = InMemoryVault(clock=stepping_clock())
    # Alice is well outside the beginning/middle/end sample.
    document = "quiet words " * 2000 + "Alice " + "quiet words " * 12000
    entry = vault.put("long.txt", document.encode())
    unsafe = dict(SAFE, summary="Alice considers creative habits and recurring obstacles. Practical reflections address routines.")
    client, calls = client_for([json.dumps(unsafe), json.dumps(SAFE)])
    with client:
        preview = make_preview(client, vault, Workspace(vault), entry.entry_id)
    assert len(calls) == 2  # Full original still rejects the omitted personal name.
    payload = json.loads(calls[0].content)
    assert "Alice" not in payload["messages"][1]["content"]
    assert len(payload["messages"][1]["content"].encode()) < CONTEXT_BYTES + 150
    assert payload["max_tokens"] == 512
    assert preview.source_partial and not preview.approved
    assert preview.context_bytes <= CONTEXT_BYTES


def test_preview_cache_distinguishes_endpoints_and_force():
    vault = InMemoryVault(clock=stepping_clock())
    entry = vault.put("a.md", b"private diary")
    workspace = Workspace(vault)
    client, calls = client_for([json.dumps(SAFE)])
    with client:
        make_preview(client, vault, workspace, entry.entry_id)
        client.base_url = "http://127.0.0.1:12345/v1"
        second = make_preview(client, vault, workspace, entry.entry_id)
        assert len(calls) == 2
        assert str(calls[-1].url).startswith(client.base_url)
        assert make_preview(client, vault, workspace, entry.entry_id) == second
        assert len(calls) == 2
        make_preview(client, vault, workspace, entry.entry_id, force=True)
        assert len(calls) == 3
