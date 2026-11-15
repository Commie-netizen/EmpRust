"""Indexed path resolution and deterministic navigation graphs."""
from __future__ import annotations

import posixpath
from collections.abc import Collection, Mapping, Sequence
from datetime import datetime

from .model import EntryMeta, Graph, GraphEdge, GraphNode, ParsedDoc


def _normal(path: str) -> str:
    return posixpath.normpath(path.replace("\\", "/")).lstrip("/").casefold()


class _PathTree:
    """Closest basename candidates, indexed by their folder prefixes."""

    def __init__(self) -> None:
        self.children: dict[str, _PathTree] = {}
        self.best: tuple[int, str, str] | None = None

    def add(self, path: str) -> None:
        normalized = _normal(path)
        folders = normalized.split("/")[:-1]
        candidate = (len(folders), normalized, path)
        node = self
        if node.best is None or candidate < node.best:
            node.best = candidate
        for folder in folders:
            node = node.children.setdefault(folder, _PathTree())
            if node.best is None or candidate < node.best:
                node.best = candidate

    def candidates(self, folder: str) -> list[str]:
        node = self
        result = [node.best[2]] if node.best else []
        for part in folder.split("/") if folder else []:
            child = node.children.get(part)
            if child is None:
                break
            node = child
            if node.best:
                result.append(node.best[2])
        return result


class _Resolver:
    def __init__(self, paths: Collection[str]):
        self.exact: dict[str, str] = {}
        self.bases: dict[str, _PathTree] = {}
        self.cache: dict[tuple[str, str], str | None] = {}
        for path in sorted(paths):
            key = _normal(path)
            self.exact.setdefault(key, path)
            self.bases.setdefault(posixpath.basename(key), _PathTree()).add(path)
            if key.endswith((".md", ".markdown")):
                self.bases.setdefault(posixpath.splitext(posixpath.basename(key))[0], _PathTree()).add(path)

    def resolve(self, target: str, source_path: str) -> str | None:
        target = _normal(target.split("#", 1)[0])
        folder = posixpath.dirname(_normal(source_path))
        cache_key = (target, folder)
        if cache_key in self.cache:
            return self.cache[cache_key]
        suffixes = ("", ".md", ".markdown") if not posixpath.splitext(target)[1] else ("",)
        for base in (target, _normal(posixpath.join(folder, target))):
            for suffix in suffixes:
                if base + suffix in self.exact:
                    result = self.exact[base + suffix]
                    self.cache[cache_key] = result
                    return result
        tree = self.bases.get(posixpath.basename(target))
        candidates = tree.candidates(folder) if tree else []

        def distance(path: str) -> tuple[int, int, str, str]:
            parent = posixpath.dirname(_normal(path))
            relative = posixpath.relpath(parent or ".", folder or ".")
            return (0 if parent == folder else 1,
                    0 if relative == "." else len(relative.split("/")), _normal(path), path)

        result = min(candidates, key=distance) if candidates else None
        self.cache[cache_key] = result
        return result


def resolve_link(target: str, source_path: str, paths: Collection[str]) -> str | None:
    """Resolve an Obsidian target, breaking equal distances lexically."""
    return _Resolver(paths).resolve(target, source_path)


def entry_groups(entries: Sequence[EntryMeta]) -> dict[str, str]:
    """Strip common folders, ignoring entries at the vault root when finding them."""
    folders = [e.path.replace("\\", "/").split("/")[:-1] for e in entries]
    nested = [parts for parts in folders if parts]
    common = 0
    if nested:
        for parts in zip(*nested):
            if len(set(parts)) != 1:
                break
            common += 1
    return {e.entry_id: parts[common] if len(parts) > common else ""
            for e, parts in zip(entries, folders)}


def build_graph(entries: Sequence[EntryMeta], parsed: Mapping[str, ParsedDoc], *,
                until: datetime | None = None, tags_as_nodes: bool = False) -> Graph:
    """Build links using one path index; timeline filtering retains only live endpoints."""
    resolver = _Resolver([e.path for e in entries])
    by_path = {e.path: e.entry_id for e in entries}
    groups = entry_groups(entries)
    kept = [e for e in entries if until is None or (e.authored_at or e.created_at) <= until]
    nodes: dict[str, GraphNode] = {}
    edges: set[tuple[str, str, str]] = set()
    unresolved = 0
    for e in kept:
        doc = parsed.get(e.entry_id)
        nodes[e.entry_id] = GraphNode(id=e.entry_id, label=doc.title if doc else e.title,
            path=e.path, group=groups[e.entry_id], kind=e.kind,
            tags=sorted(set(e.tags) | set(doc.tags if doc else [])), words=doc.words if doc else 0,
            created_at=e.created_at, updated_at=e.updated_at, authored_at=e.authored_at)
    for e in kept:
        doc = parsed.get(e.entry_id)
        if doc:
            for kind, targets in (("link", doc.links), ("embed", doc.embeds)):
                for target in targets:
                    path = resolver.resolve(target, e.path)
                    if path is None:
                        unresolved += 1
                    elif by_path[path] in nodes and by_path[path] != e.entry_id:
                        edges.add((e.entry_id, by_path[path], kind))
        if tags_as_nodes:
            for tag in nodes[e.entry_id].tags:
                key = "tag:" + tag
                if key not in nodes:
                    nodes[key] = GraphNode(id=key, node_type="tag", label="#" + tag, path=key, group="#",
                        kind="note", created_at=e.created_at, updated_at=e.updated_at)
                else:
                    nodes[key].created_at = min(nodes[key].created_at, e.created_at)
                    nodes[key].updated_at = max(nodes[key].updated_at, e.updated_at)
                edges.add((e.entry_id, key, "tag"))
    ordered_edges = []
    for source, target, kind in sorted(edges):
        nodes[source].degree += 1
        nodes[target].degree += 1
        ordered_edges.append(GraphEdge(source=source, target=target, kind=kind))
    return Graph(nodes=sorted(nodes.values(), key=lambda n: (n.path, n.id)),
                 edges=ordered_edges, unresolved=unresolved)
