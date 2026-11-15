"""Unlocked, incremental projections of a vault."""
from __future__ import annotations

import re
from collections import OrderedDict
from datetime import datetime, tzinfo
from typing import Literal

from .activity import compute_activity
from .api import VaultAPI, VaultError
from .graph import build_graph, _Resolver
from .model import Activity, EntryMeta, Graph, Mention, ParsedDoc, SearchHit
from .parse import _CJK, is_text, parse_document, plain_body
from .search import SearchIndex, fold, snippet


class Workspace:
    """Keep current text indexed and at most eight historical texts decrypted."""

    def __init__(self, vault: VaultAPI, *, tz: tzinfo | None = None) -> None:
        self.vault, self.tz = vault, tz
        self._closed = False
        self._entries: dict[str, EntryMeta] = {}
        self._parsed: dict[str, ParsedDoc] = {}
        self._texts: dict[str, str] = {}
        self._old: OrderedDict[tuple[str, int], str] = OrderedDict()
        self._words: dict[tuple[str, int], int] = {}
        self._mention_cache: dict[tuple[str, int, str], str | None] = {}
        self._index = SearchIndex()
        self.refresh()

    def _ensure_open(self) -> None:
        if self._closed:
            raise VaultError("workspace is closed")

    def close(self) -> None:
        """Release all plaintext projections and permanently close the workspace."""
        self._ensure_open()
        self._closed = True
        for container in (self._entries, self._parsed, self._texts, self._old,
                          self._words, self._mention_cache):
            container.clear()
        self._index.clear()

    def link_targets(self, entry_id: str) -> dict[str, str]:
        """Use the same source-aware resolution as the graph."""
        self._ensure_open()
        self.vault.entry(entry_id)
        entry, doc = self._entries[entry_id], self._parsed[entry_id]
        by_path = {e.path: e.entry_id for e in self._entries.values()}
        resolver = _Resolver(by_path)
        return {target: by_path[path] for target in (*doc.links, *doc.embeds)
                if (path := resolver.resolve(target, entry.path)) is not None}

    def refresh(self) -> None:
        """Read and index only new versions, and discard removed entries."""
        self._ensure_open()
        entries = {e.entry_id: e for e in self.vault.entries()}
        for entry_id in self._entries.keys() - entries.keys():
            self._index.remove(entry_id)
            self._parsed.pop(entry_id, None)
            self._texts.pop(entry_id, None)
        self._old = OrderedDict((k, v) for k, v in self._old.items() if k[0] in entries)
        self._words = {k: v for k, v in self._words.items() if k[0] in entries}
        self._mention_cache = {k: v for k, v in self._mention_cache.items() if k[0] in entries}
        for entry_id, e in entries.items():
            old = self._entries.get(entry_id)
            if old and old.n_versions == e.n_versions:
                continue
            text = self.vault.read(entry_id).decode("utf-8-sig", errors="replace") if is_text(e.media_type) else ""
            self._texts[entry_id] = text
            doc = parse_document(text, path=e.path, media_type=e.media_type)
            self._parsed[entry_id] = doc
            self._words[(entry_id, e.n_versions)] = doc.words
            self._index.remove(entry_id)
            if is_text(e.media_type):
                self._index.add(entry_id, doc.title, e.path, plain_body(text, e.media_type), e.updated_at,
                                aliases=tuple(doc.aliases), tags=tuple(sorted(set(e.tags) | set(doc.tags))))
        self._entries = entries

    def parsed(self, entry_id: str) -> ParsedDoc:
        """Return parsed metadata for the current version."""
        self._ensure_open()
        self.vault.entry(entry_id)
        return self._parsed[entry_id].model_copy(deep=True)

    def text(self, entry_id: str, version: int | None = None) -> str:
        """Decode text, caching a bounded number of historical versions."""
        self._ensure_open()
        e = self.vault.entry(entry_id)
        if not is_text(e.media_type):
            return ""
        current = self._entries.get(entry_id)
        if current and current.n_versions == e.n_versions and (version is None or version == e.n_versions):
            return self._texts[entry_id]
        number = e.n_versions if version is None else version
        key = (entry_id, number)
        if key not in self._old:
            text = self.vault.read(entry_id, number).decode("utf-8-sig", errors="replace")
            self._words[key] = parse_document(text, path=e.path, media_type=e.media_type).words
            self._old[key] = text
        self._old.move_to_end(key)
        while len(self._old) > 8:
            self._old.popitem(last=False)
        return self._old[key]

    def graph(self, *, until: datetime | None = None, tags_as_nodes: bool = False) -> Graph:
        """Show all text entries and only referenced binary attachments."""
        self._ensure_open()
        self.vault.entries()  # Also enforce the vault's locked-state guard.
        graph = build_graph(list(self._entries.values()), self._parsed, until=until, tags_as_nodes=tags_as_nodes)
        referenced = {edge.target for edge in graph.edges if edge.kind in {"link", "embed"}}
        keep = {n.id for n in graph.nodes if n.id.startswith("tag:") or
                is_text(self._entries[n.id].media_type) or n.id in referenced}
        graph.nodes = [n for n in graph.nodes if n.id in keep]
        graph.edges = [e for e in graph.edges if e.source in keep and e.target in keep]
        for node in graph.nodes:
            node.degree = 0
        nodes = {n.id: n for n in graph.nodes}
        for edge in graph.edges:
            nodes[edge.source].degree += 1
            nodes[edge.target].degree += 1
        return graph

    def outlinks(self, entry_id: str) -> list[str]:
        """Return unique resolved outgoing entry ids, including embeds."""
        self._ensure_open()
        self.vault.entry(entry_id)
        return sorted({e.target for e in self.graph().edges if e.source == entry_id})

    def backlinks(self, entry_id: str) -> list[str]:
        """Return unique incoming entry ids, including embeds."""
        self._ensure_open()
        self.vault.entry(entry_id)
        return sorted({e.source for e in self.graph().edges if e.target == entry_id})

    def search(self, query: str, limit: int = 30) -> list[SearchHit]:
        """Search the current text versions."""
        self._ensure_open()
        self.vault.entries()
        return self._index.search(query, limit)

    def mentions(self, term: str, limit: int = 50) -> list[Mention]:
        """Find historical occurrences; cache snippets, never all old texts."""
        self._ensure_open()
        self.vault.entries()
        needle = fold(term.strip())
        if not needle or limit <= 0:
            return []
        boundary = not re.search(rf"[{_CJK}]", needle)
        pattern = re.compile((r"(?<!\w)" if boundary else "") + re.escape(needle) + (r"(?!\w)" if boundary else ""))
        versions = [(v.timestamp, e.path, v.version, e, v) for e in self._entries.values()
                    if is_text(e.media_type) for v in self.vault.versions(e.entry_id)]
        result = []
        for _, _, _, entry, version in sorted(versions, key=lambda row: row[:3]):
            key = (entry.entry_id, version.version, needle)
            if key not in self._mention_cache:
                text = self.text(entry.entry_id, version.version)
                # Map folded offsets back to original text (casefold can expand).
                folded, offsets = [], []
                for i, char in enumerate(text):
                    value = fold(char)
                    folded.append(value)
                    offsets.extend([i] * len(value))
                match = pattern.search("".join(folded))
                self._mention_cache[key] = snippet(text, offsets[match.start()]) if match else None
            excerpt = self._mention_cache[key]
            if excerpt is not None:
                result.append(Mention(entry_id=entry.entry_id, version=version.version,
                    title=entry.title, path=entry.path, timestamp=version.timestamp,
                    authored_at=version.source_mtime, snippet=excerpt))
                if len(result) >= limit:
                    break
        return result

    def activity(self, basis: Literal["claimed", "ledger"] = "claimed") -> Activity:
        """Lazily read historical word counts for activity."""
        self._ensure_open()
        self.vault.entries()
        versions = {e.entry_id: self.vault.versions(e.entry_id) for e in self._entries.values()}
        for entry_id, history in versions.items():
            for version in history:
                if (entry_id, version.version) not in self._words:
                    self.text(entry_id, version.version)
        return compute_activity(list(self._entries.values()), versions, self._words, basis=basis, tz=self.tz)
