from datetime import timezone

import pytest

from empreinte.api import VaultError, WorkspaceAPI
from empreinte.testing import InMemoryVault, stepping_clock
from empreinte.workspace import Workspace


class CountingVault(InMemoryVault):
    def __init__(self):
        super().__init__(clock=stepping_clock())
        self.reads = 0

    def read(self, entry_id, version=None):
        self.reads += 1
        return super().read(entry_id, version)


def test_incremental_refresh_and_binary_graph():
    vault = CountingVault()
    a = vault.put("a.md", b"\xef\xbb\xbf# A\n[[b]] ![[pic.png]] cafe")
    b = vault.put("b.md", b"# B")
    pic = vault.put("pic.png", b"\x89PNG", kind="file", media_type="image/png")
    vault.put("unused.png", b"\x89PNG", kind="file", media_type="image/png")
    workspace = Workspace(vault, tz=timezone.utc)
    assert isinstance(workspace, WorkspaceAPI)
    assert vault.reads == 2
    workspace.refresh()
    assert vault.reads == 2
    assert workspace.parsed(a.entry_id).title == "A"
    assert workspace.outlinks(a.entry_id) == sorted([b.entry_id, pic.entry_id])
    assert workspace.backlinks(b.entry_id) == [a.entry_id]
    assert len(workspace.graph().nodes) == 3
    assert workspace.text(pic.entry_id) == ""
    assert all(hit.entry_id != pic.entry_id for hit in workspace.search("pic"))
    vault.put("b.md", b"changed")
    workspace.refresh()
    assert vault.reads == 3
    vault.remove(b.entry_id)
    workspace.refresh()
    assert not workspace.search("changed")
    assert workspace.graph().unresolved == 1
    vault.lock()
    with pytest.raises(VaultError):
        workspace.search("cafe")


def test_mentions_lazy_bounded_and_activity():
    vault = CountingVault()
    v = vault.put("a.md", "café, not cafeteria".encode())
    for i in range(1, 12):
        vault.put("a.md", f"café revision {i}".encode())
    workspace = Workspace(vault, tz=timezone.utc)
    assert vault.reads == 1
    mentions = workspace.mentions("CAFE")
    assert [m.version for m in mentions] == list(range(1, 13))
    assert [m.timestamp for m in mentions] == sorted(m.timestamp for m in mentions)
    reads = vault.reads
    assert workspace.mentions("CAFE") == mentions and vault.reads == reads
    assert len(workspace._old) <= 8
    assert not workspace.mentions("caf")
    assert len(workspace.mentions("cafeteria")) == 1
    assert workspace.mentions("cafe", limit=1)[0].version == 1
    assert workspace.activity("ledger").days[0].updated == 11
    assert workspace.text(v.entry_id, 1).startswith("café")


def test_close_clears_plaintext_and_rejects_every_call():
    vault = CountingVault()
    v = vault.put("secret.md", b"old secret")
    vault.put("secret.md", b"new secret")
    workspace = Workspace(vault)
    workspace.mentions("secret")
    workspace.search("sec")
    containers = [workspace._entries, workspace._parsed, workspace._texts, workspace._old,
                  workspace._words, workspace._mention_cache, workspace._index.documents,
                  workspace._index.postings, workspace._index.term_positions, workspace._index._vocabulary]
    workspace.close()
    assert all(not container for container in containers)
    for call in [workspace.close, workspace.refresh, workspace.graph, workspace.activity,
                 lambda: workspace.parsed(v.entry_id), lambda: workspace.text(v.entry_id),
                 lambda: workspace.link_targets(v.entry_id), lambda: workspace.outlinks(v.entry_id),
                 lambda: workspace.backlinks(v.entry_id), lambda: workspace.search("secret"),
                 lambda: workspace.mentions("secret")]:
        with pytest.raises(VaultError, match="^workspace is closed$"):
            call()


def test_reader_and_graph_share_resolution():
    vault = CountingVault()
    vault.put("A/Note.md", b"a")
    target = vault.put("B/Note.md", b"b")
    source = vault.put("B/source.md", b"[[Note]] ![[../A/Note.md]] [[missing]]")
    workspace = Workspace(vault)
    assert workspace.link_targets(source.entry_id) == {
        "Note": target.entry_id, "../A/Note.md": vault.find("A/Note.md").entry_id}
    assert any(e.source == source.entry_id and e.target == target.entry_id and e.kind == "link"
               for e in workspace.graph().edges)


def test_search_body_snippets_and_metadata():
    vault = CountingVault()
    v = vault.put("a.md", b'---\ntitle: Specialtitle\naliases: [Alternate name]\ntags: [specialtag]\nprivate: hiddenyaml\n---\n**Visible** [label](target.md) and [[Target|display]] _words_.')
    workspace = Workspace(vault)
    for query in ["Specialtitle", '"Alternate name"', "specialtag", "Visible", "display"]:
        hit = workspace.search(query)[0]
        assert hit.entry_id == v.entry_id
        assert hit.snippet == "Visible label and display words."
    assert not workspace.search("hiddenyaml")


def test_markdown_extension_is_not_an_md_alias():
    vault = CountingVault()
    note = vault.put("Note.markdown", b"note")
    source = vault.put("source.md", b"[[Note]] [[Note.md]]")
    workspace = Workspace(vault)
    assert workspace.link_targets(source.entry_id) == {"Note": note.entry_id}
    graph = workspace.graph()
    assert graph.unresolved == 1
    assert [(e.source, e.target) for e in graph.edges] == [(source.entry_id, note.entry_id)]
