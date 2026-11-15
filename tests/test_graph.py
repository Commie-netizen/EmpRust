from datetime import timedelta
from time import perf_counter

from empreinte.graph import build_graph, resolve_link
from empreinte.model import ParsedDoc
from empreinte.testing import InMemoryVault, stepping_clock


def test_resolution_and_graph():
    vault = InMemoryVault(clock=stepping_clock())
    a = vault.put("folder/a.md", b"a")
    b = vault.put("folder/b.md", b"b", tags=["topic"])
    c = vault.put("other/b.md", b"c")
    asset = vault.put("image.png", b"png", media_type="image/png", kind="file")
    paths = [e.path for e in vault.entries()]
    assert resolve_link("B", "folder/a.md", paths) == "folder/b.md"
    assert resolve_link("../image.png", "folder/a.md", paths) == "image.png"
    assert resolve_link("other/B.md", "folder/a.md", paths) == "other/b.md"
    assert resolve_link("missing", "folder/a.md", paths) is None
    parsed = {a.entry_id: ParsedDoc(title="a", links=["b", "b", "a", "missing"], embeds=["image.png"])}
    graph = build_graph(vault.entries(), parsed, tags_as_nodes=True)
    assert graph.unresolved == 1
    assert len(graph.edges) == 3
    assert next(n for n in graph.nodes if n.id == a.entry_id).degree == 2
    assert next(n for n in graph.nodes if n.id == b.entry_id).degree == 2
    assert any(n.id == "tag:topic" for n in graph.nodes)
    assert all(n.node_type == ("tag" if n.id == "tag:topic" else "entry") for n in graph.nodes)
    past = build_graph(vault.entries(), parsed, until=a.timestamp)
    assert len(past.nodes) == 1 and not past.edges and past.unresolved == 1
    assert c.entry_id != asset.entry_id


def test_closeness_and_claimed_time():
    vault = InMemoryVault(clock=stepping_clock())
    date = stepping_clock()()
    vault.put("a/deep/n.md", b"n", source_mtime=date - timedelta(days=10))
    paths = ["x/n.md", "a/n.md", "a/deep/n.md", "z/image.pdf"]
    assert resolve_link("n", "a/deep/source.md", paths) == "a/deep/n.md"
    assert resolve_link("image.pdf", "a/source.md", paths) == "z/image.pdf"
    assert resolve_link("n", "a/deep/more/source.md", paths) == "a/deep/n.md"
    assert resolve_link("n", "new/source.md", ["z/n.md", "b/n.md"]) == "b/n.md"
    assert len(build_graph(vault.entries(), {}, until=date - timedelta(days=1)).nodes) == 1


def test_graph_scale():
    vault = InMemoryVault(clock=stepping_clock())
    seed = vault.put("seed.md", b"seed")
    template = vault.entry(seed.entry_id)
    entries = [template.model_copy(update={"entry_id": f"id{i:05}", "path": f"g/n{i:05}.md"}) for i in range(10_000)]
    parsed = {e.entry_id: ParsedDoc(title=e.title, links=[f"n{(i + j + 1) % 10000:05}" for j in range(5)]) for i, e in enumerate(entries)}
    start = perf_counter()
    graph = build_graph(entries, parsed)
    elapsed = perf_counter() - start
    assert len(graph.nodes) == 10_000 and len(graph.edges) == 50_000
    assert graph.unresolved == 0
    assert elapsed < 1.0, f"graph took {elapsed:.3f}s"


def test_common_folder_groups():
    for paths, expected in [
        (["root.md", "wiki/index.md", "wiki/sources/a.md", "wiki/conversations/b.md", "wiki/meta/c.md"],
         ["", "", "sources", "conversations", "meta"]),
        (["a/one.md", "b/two.md", "root.md"], ["a", "b", ""]),
    ]:
        vault = InMemoryVault(clock=stepping_clock())
        for path in paths:
            vault.put(path, b"text")
        graph = build_graph(vault.entries(), {})
        assert {n.path: n.group for n in graph.nodes} == dict(zip(paths, expected))
        assert build_graph(list(reversed(vault.entries())), {}) == graph
