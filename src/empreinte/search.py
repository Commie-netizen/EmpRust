"""Unicode inverted index with positional matching and BM25 ranking."""
from __future__ import annotations

import bisect
import math
import re
import unicodedata
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime

from .model import SearchHit
from .parse import _CJK

_TOKENS = re.compile(rf"[{_CJK}]+|[^\W_{_CJK}]+", re.UNICODE)
_HAN = re.compile(rf"^[{_CJK}]")


def fold(text: str) -> str:
    """Fold accents and case without transliterating other scripts."""
    return "".join(c for c in unicodedata.normalize("NFKD", text.casefold()) if not unicodedata.combining(c))


def tokenize(text: str) -> list[tuple[str, int]]:
    """Return folded tokens with offsets in the original string."""
    result: list[tuple[str, int]] = []
    for match in _TOKENS.finditer(text):
        word = match[0]
        if _HAN.match(word):
            result.extend((word[i:i + 2], match.start() + i) for i in range(max(1, len(word) - 1)))
        else:
            result.append((fold(word), match.start()))
    return result


def snippet(text: str, position: int = 0, size: int = 160) -> str:
    """Return a plain text window without HTML highlighting."""
    start = max(0, min(position - size // 3, len(text) - size))
    return " ".join(text[start:start + size].split())


@dataclass
class _Document:
    title: str
    aliases: tuple[str, ...]
    path: str
    text: str
    updated_at: datetime
    counts: Counter[str]
    title_terms: set[str]
    path_terms: set[str]
    length: int


class SearchIndex:
    """Mutable in-memory index; offsets remain available for snippet callers."""

    def __init__(self) -> None:
        self.documents: dict[str, _Document] = {}
        self.postings: dict[str, set[str]] = defaultdict(set)
        self.term_positions: dict[str, dict[str, list[int]]] = {}
        self._vocabulary: list[str] | None = None
        self._total_length = 0

    def clear(self) -> None:
        """Release all indexed plaintext, including cached vocabulary."""
        self.documents.clear()
        self.postings.clear()
        self.term_positions.clear()
        if self._vocabulary is not None:
            self._vocabulary.clear()
        self._vocabulary = None
        self._total_length = 0

    def remove(self, entry_id: str) -> None:
        """Remove an entry if indexed."""
        doc = self.documents.pop(entry_id, None)
        if doc is None:
            return
        for term in doc.counts:
            self.postings[term].discard(entry_id)
            if not self.postings[term]:
                del self.postings[term]
        self._total_length -= doc.length
        self.term_positions.pop(entry_id, None)
        self._vocabulary = None

    def add(self, entry_id: str, title: str, path: str, text: str, updated_at: datetime,
            *, aliases: tuple[str, ...] = (), tags: tuple[str, ...] = ()) -> None:
        """Insert or replace one document and its positions."""
        self.remove(entry_id)
        positions: dict[str, list[int]] = defaultdict(list)
        for term, position in tokenize(text):
            positions[term].append(position)
        title_terms = {t for t, _ in tokenize(" ".join((title, *aliases)))}
        path_terms = {t for t, _ in tokenize(path)}
        counts = Counter({term: len(offsets) for term, offsets in positions.items()})
        for term in title_terms | path_terms | {t for t, _ in tokenize(" ".join(tags))}:
            counts[term] += 1
        length = max(1, sum(counts.values()))
        self.documents[entry_id] = _Document(title, aliases, path, text, updated_at, counts, title_terms, path_terms, length)
        self.term_positions[entry_id] = dict(positions)
        self._total_length += length
        for term in counts:
            self.postings[term].add(entry_id)
        self._vocabulary = None

    def _expand(self, term: str) -> list[str]:
        if self._vocabulary is None:
            self._vocabulary = sorted(self.postings)
        start = bisect.bisect_left(self._vocabulary, term)
        end = bisect.bisect_left(self._vocabulary, term + chr(0x10ffff))
        return self._vocabulary[start:end]

    def search(self, query: str, limit: int = 30) -> list[SearchHit]:
        """Require all terms, fall back to any term, and preserve quoted phrases."""
        if limit <= 0:
            return []
        pieces = list(re.finditer(r'"([^"]+)"|(\S+)', query))
        groups: list[set[str]] = []
        terms: set[str] = set()
        phrases: list[str] = []
        for i, piece in enumerate(pieces):
            words = tokenize(piece[1] or piece[2])
            if piece[1]:
                phrases.append(fold(piece[1]))
            for j, (term, _) in enumerate(words):
                expanded = self._expand(term) if not piece[1] and i == len(pieces) - 1 and j == len(words) - 1 else [term]
                terms.update(expanded)
                group: set[str] = set()
                for token in expanded:
                    group.update(self.postings.get(token, ()))
                groups.append(group)
        if not groups:
            return []
        candidates = set.intersection(*groups)
        def matches_phrases(entry_id: str) -> bool:
            if not phrases:
                return True
            doc = self.documents[entry_id]
            fields = [fold(s) for s in (doc.title, *doc.aliases, doc.path, doc.text)]
            return all(any(re.search(r"(?<!\w)" + re.escape(p) + r"(?!\w)", f) for f in fields) for p in phrases)

        candidates = {entry_id for entry_id in candidates if matches_phrases(entry_id)}
        if not candidates:
            candidates = {entry_id for entry_id in set.union(*groups) if matches_phrases(entry_id)}
        ranked: list[tuple[float, str, str, int]] = []
        average = self._total_length / max(1, len(self.documents))
        for entry_id in candidates:
            doc = self.documents[entry_id]
            score = 0.0
            best_weight, best_position = -1.0, 0
            for term in sorted(terms & doc.counts.keys()):
                frequency = doc.counts[term]
                idf = math.log(1 + (len(self.documents) - len(self.postings[term]) + 0.5) / (len(self.postings[term]) + 0.5))
                weight = idf * frequency * 2.2 / (frequency + 1.2 * (0.25 + 0.75 * doc.length / average))
                score += weight + idf * (2 * (term in doc.title_terms) + (term in doc.path_terms))
                offsets = self.term_positions[entry_id].get(term)
                if offsets and weight > best_weight:
                    best_weight, best_position = weight, offsets[0]
            ranked.append((-score, doc.path, entry_id, best_position))
        hits = []
        for negative_score, _, entry_id, position in sorted(ranked)[:limit]:
            doc = self.documents[entry_id]
            hits.append(SearchHit(entry_id=entry_id, title=doc.title, path=doc.path,
                snippet=snippet(doc.text, position), score=-negative_score, updated_at=doc.updated_at))
        return hits
