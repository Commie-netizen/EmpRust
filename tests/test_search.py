from time import perf_counter

from empreinte.search import SearchIndex
from empreinte.testing import InMemoryVault, stepping_clock


def test_unicode_phrases_prefix_and_ranking():
    vault = InMemoryVault(clock=stepping_clock())
    index = SearchIndex()
    for path, title, text in [("a.md", "Café garden", "A quiet cafe garden has green leaves. 中文研究"),
                              ("b.md", "Other", "cafe and a very distant garden. green light"),
                              ("c.md", "Unrelated", "nothing here")]:
        v = vault.put(path, text.encode(), title=title)
        index.add(v.entry_id, title, path, text, v.timestamp)
    assert index.search("CAFE gar", 10)[0].path == "a.md"
    assert [h.path for h in index.search('"cafe garden"', 10)] == ["a.md"]
    assert [h.path for h in index.search('"cafe garden" distant', 10)] == ["a.md"]
    assert len(index.search("cafe nonexistent", 10)) == 2
    assert index.search("中文研究", 10)[0].path == "a.md"
    assert index.search("no such word", 10) == []
    assert index.search("", 10) == []
    assert index.search("cafe", 0) == []
    assert "cafe" in index.term_positions[vault.find("a.md").entry_id]


def test_replacement_removal_snippet():
    vault = InMemoryVault(clock=stepping_clock())
    index = SearchIndex()
    v = vault.put("a.md", b"old")
    index.add(v.entry_id, "Title", "a.md", "old", v.timestamp)
    text = "padding " * 100 + "specialneedle " + "suffix " * 100
    index.add(v.entry_id, "Title", "a.md", text, v.timestamp)
    assert not index.search("old", 10)
    hit = index.search("specialneedle", 1)[0]
    assert "specialneedle" in hit.snippet and len(hit.snippet) <= 160
    index.remove(v.entry_id)
    assert not index.search("special", 10)


def test_search_scale():
    vault = InMemoryVault(clock=stepping_clock())
    v = vault.put("seed.md", b"seed")
    index = SearchIndex()
    start = perf_counter()
    for i in range(10_000):
        index.add(str(i), f"Document {i}", f"g/n{i}.md", f"common research token{i} evidence", v.timestamp)
    assert perf_counter() - start < 5
    start = perf_counter()
    assert index.search("token9999", 10)[0].entry_id == "9999"
    assert len(index.search("research", 30)) == 30
    assert perf_counter() - start < 1


def test_alias_receives_title_boost():
    index = SearchIndex()
    now = stepping_clock()()
    index.add("alias", "Other", "a.md", "ordinary text", now, aliases=("Special phrase",))
    index.add("title", "Other Special phrase", "b.md", "ordinary text", now)
    index.add("body", "Other", "c.md", "Special phrase", now)
    hits = {h.entry_id: h for h in index.search('"Special phrase"')}
    assert hits["alias"].score == hits["title"].score
    assert hits["alias"].score > hits["body"].score
