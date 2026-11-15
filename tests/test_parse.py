from empreinte.parse import parse_document
from empreinte.testing import InMemoryVault, stepping_clock


def test_obsidian_syntax():
    vault = InMemoryVault(clock=stepping_clock())
    content = '''---
title: "My title"
tags: [one, two]
aliases:
  - Other name
---
# Heading
## Smaller
[[Target|alias]] [[Folder/Note#Heading]] [[Block#^abc]] ![[image.png]]
[local](a%20b.md) [spaces](<folder/a b.md>) [web](https://x.com) [mail](mailto:x@y.org) [anchor](#here)
#inline #nested/tag #123 #abc-2 `#hidden [[No]]` `` ` #alsohidden ``
```md
# Ignored
[[Missing]] #no
```
'''
    version = vault.put("file.md", content.encode())
    doc = parse_document(vault.read(version.entry_id).decode(), path="file.md")
    assert doc.title == "My title"
    assert doc.aliases == ["Other name"]
    assert doc.headings == ["Heading", "Smaller"]
    assert doc.tags == ["one", "two", "inline", "nested/tag", "abc-2"]
    assert doc.links == ["Target", "Folder/Note", "Block", "a b.md", "folder/a b.md"]
    assert doc.embeds == ["image.png"]


def test_fallbacks_malformed_frontmatter_and_cjk():
    vault = InMemoryVault(clock=stepping_clock())
    v = vault.put("note.md", "---\nnot: [yaml\n---\n# First\nhello 中文\n~~~\nhidden words\n~~~".encode())
    doc = parse_document(vault.read(v.entry_id).decode(), path="note.md")
    assert doc.title == "First"
    assert doc.words == 4
    assert parse_document("---\nbroken", path="a.md").title == "a"
    assert parse_document("# Heading [[X]] 中文", path="a.txt", media_type="text/plain").links == []
    assert parse_document("plain 中文", path="a.txt", media_type="text/plain").words == 3
    assert parse_document("---\ntags:\n  - alpha\n  - beta\n---\n# H", path="a.md").tags == ["alpha", "beta"]
    assert parse_document("---\ntags: alpha, beta gamma\n---\nx", path="a.md").tags == ["alpha", "beta", "gamma"]


def test_unclosed_code_and_link_tags():
    vault = InMemoryVault(clock=stepping_clock())
    v = vault.put("a.md", b'[label #no](target.md) [[X|#no]] #yes\n```\n#hidden [[No]]')
    doc = parse_document(vault.read(v.entry_id).decode(), path="a.md")
    assert doc.tags == ["yes"]
    assert doc.links == ["target.md", "X"]


def test_inline_aliases_preserve_phrases():
    doc = parse_document('---\naliases: ["Other name", Second]\n---\nbody', path="a.md")
    assert doc.aliases == ["Other name", "Second"]
