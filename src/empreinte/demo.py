"""Demo data and a stub WorkspaceAPI, so the interface can be seen without a real vault.

`StubWorkspace` is a small, unoptimised WorkspaceAPI over any VaultAPI, written for the
server's tests and the demo; the real one is workspace.Workspace. `DemoVault` is an
InMemoryVault that can be reopened after a lock and that fakes outside anchors locally
(clearly labelled: no authority is ever contacted). `demo_session()` builds the Session
used by `python -m empreinte.server --demo`.

The demo never reads real files: folder import is disabled in demo mode, because the
demo passphrase is public. Its in-memory vault keeps its (fictitious) content while
locked so it can be reopened; the stub workspace drops its copy on close().
"""
from __future__ import annotations

import base64
import hashlib
import random
import re
import secrets
import tempfile
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Literal

from .api import NotFound, VaultAPI, VaultError, WrongPassphrase
from .model import (
    Activity,
    ActivityDay,
    Anchor,
    AnchorStatus,
    Graph,
    GraphEdge,
    GraphNode,
    Mention,
    ParsedDoc,
    Preview,
    ProvenanceProof,
    RoyaltyTerms,
    SearchHit,
    VerifyReport,
)
from .testing import InMemoryVault

UTC = timezone.utc
TAG_RE = re.compile(r"(?<![\w#/&])#([A-Za-zÀ-ÿ][\w\-/À-ÿ]*)")
WIKILINK_RE = re.compile(r"(!?)\[\[([^\]|#\n]+)(?:#[^\]|\n]*)?(?:\|[^\]\n]*)?\]\]")
MDLINK_RE = re.compile(r"(?<!!)\[[^\]\n]*\]\(([^)\s]+\.md)\)")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$", re.M)
WORD_RE = re.compile(r"\w+", re.U)


# ------------------------------------------------------------------- stub workspace


TEXT_TYPES = {"application/json", "application/xml", "application/javascript", "application/x-python",
              "application/sql", "application/x-sh", "application/toml", "application/yaml",
              "application/x-yaml", "image/svg+xml"}


def _is_text(media_type: str) -> bool:
    """Same rule as parse.is_text (textual MIME types, structured text included)."""
    media = media_type.lower().split(";", 1)[0].strip()
    return media.startswith("text/") or media.endswith(("+json", "+xml")) or media in TEXT_TYPES


def parse_text(text: str, fallback_title: str, meta_tags: list[str]) -> ParsedDoc:
    """Title, tags, links, embeds, headings and word count of one Markdown text."""
    headings = [m.group(2).strip() for m in HEADING_RE.finditer(text)]
    first_h1 = next((m.group(2).strip() for m in HEADING_RE.finditer(text) if m.group(1) == "#"), None)
    tags = set(meta_tags)
    for m in TAG_RE.finditer(text):
        tags.add(m.group(1))
    links, embeds = [], []
    for m in WIKILINK_RE.finditer(text):
        (embeds if m.group(1) else links).append(m.group(2).strip())
    links += [m.group(1) for m in MDLINK_RE.finditer(text)]
    return ParsedDoc(title=first_h1 or fallback_title, tags=sorted(tags), links=links, embeds=embeds,
                     headings=headings, words=len(WORD_RE.findall(text)))


def _snippet(text: str, needle: str, width: int = 160) -> str:
    flat = re.sub(r"\s+", " ", text).strip()
    pos = flat.lower().find(needle.lower()) if needle else -1
    if pos < 0:
        return flat[:width]
    start = max(0, pos - width // 3)
    piece = flat[start:start + width]
    return ("..." if start else "") + piece + ("..." if start + width < len(flat) else "")


class StubWorkspace:
    """A WorkspaceAPI written for tests and the demo. Everything is recomputed on refresh."""

    def __init__(self, vault: VaultAPI):
        self.vault = vault
        self._closed = False
        self.refresh()

    def _check(self) -> None:
        if self._closed:
            raise VaultError("workspace closed")

    def close(self) -> None:
        """Drop every plaintext held here; later calls raise VaultError."""
        self._closed = True
        for name in ("_meta", "_text", "_parsed", "_out", "_back", "_targets"):
            value = getattr(self, name, None)
            if hasattr(value, "clear"):
                value.clear()
        self._edges = []

    def _resolve(self, raw: str, source_path: str, names: dict[str, list[str]]) -> str | None:
        """Target entry of a raw link: exact path first, then the candidate nearest the source."""
        key = raw.lower().strip().replace("\\", "/").strip("/")
        if key.endswith(".md"):
            key = key[:-3]
        candidates = names.get(key) or names.get(key.split("/")[-1]) or []
        if not candidates:
            return None
        folder = source_path.lower().rsplit("/", 1)[0] if "/" in source_path else ""

        def rank(entry_id: str) -> tuple[int, int, str]:
            path = self._meta[entry_id].path.lower()
            same = (path.rsplit("/", 1)[0] if "/" in path else "") == folder
            return (0 if same else 1, path.count("/"), path)

        return min(candidates, key=rank)

    def refresh(self) -> None:
        self._check()
        self._meta = {m.entry_id: m for m in self.vault.entries()}
        self._text: dict[str, str] = {}
        self._parsed: dict[str, ParsedDoc] = {}
        for entry_id, meta in self._meta.items():
            text = self.vault.read(entry_id).decode("utf-8", "replace") if _is_text(meta.media_type) else ""
            self._text[entry_id] = text
            self._parsed[entry_id] = parse_text(text, meta.title, meta.tags)
        names: dict[str, list[str]] = defaultdict(list)
        for entry_id, meta in self._meta.items():
            path = meta.path.lower()
            stem = path.rsplit("/", 1)[-1]
            keys = {path, path.rsplit(".", 1)[0], stem, stem.rsplit(".", 1)[0], meta.title.lower()}
            for key in keys:
                names[key].append(entry_id)
        self._out: dict[str, list[str]] = {}
        self._back: dict[str, list[str]] = defaultdict(list)
        self._targets: dict[str, dict[str, str]] = {}
        self._edges: list[GraphEdge] = []
        self._unresolved = 0
        for entry_id, parsed in self._parsed.items():
            outs: list[str] = []
            targets_map: dict[str, str] = {}
            for kind, targets in (("link", parsed.links), ("embed", parsed.embeds)):
                for raw in targets:
                    target = self._resolve(raw, self._meta[entry_id].path, names)
                    if target is None:
                        self._unresolved += 1
                        continue
                    targets_map[raw] = target
                    if target == entry_id or target in outs:
                        continue
                    outs.append(target)
                    self._back[target].append(entry_id)
                    self._edges.append(GraphEdge(source=entry_id, target=target, kind=kind))  # type: ignore[arg-type]
            self._out[entry_id] = outs
            self._targets[entry_id] = targets_map

    def _known(self, entry_id: str) -> None:
        self._check()
        if entry_id not in self._meta:
            raise NotFound(entry_id)

    def link_targets(self, entry_id: str) -> dict[str, str]:
        self._known(entry_id)
        return dict(self._targets.get(entry_id, {}))

    def parsed(self, entry_id: str) -> ParsedDoc:
        self._known(entry_id)
        return self._parsed[entry_id]

    def text(self, entry_id: str, version: int | None = None) -> str:
        self._known(entry_id)
        if not _is_text(self._meta[entry_id].media_type):
            return ""
        if version is None:
            return self._text[entry_id]
        return self.vault.read(entry_id, version).decode("utf-8", "replace")

    def graph(self, *, until: datetime | None = None, tags_as_nodes: bool = False) -> Graph:
        self._check()
        kept = {}
        for entry_id, meta in self._meta.items():
            when = meta.authored_at or meta.created_at
            if until is None or when <= until:
                kept[entry_id] = meta
        edges = [e for e in self._edges if e.source in kept and e.target in kept]
        tag_nodes: dict[str, GraphNode] = {}
        if tags_as_nodes:
            for entry_id, meta in kept.items():
                for tag in self._parsed[entry_id].tags:
                    node_id = f"tag:{tag}"
                    when = meta.authored_at or meta.created_at
                    current = tag_nodes.get(node_id)
                    if current is None or when < (current.authored_at or current.created_at):
                        tag_nodes[node_id] = GraphNode(id=node_id, label=f"#{tag}", path="", group="#",
                                                       node_type="tag",
                                                       tags=[tag], created_at=meta.created_at,
                                                       updated_at=meta.updated_at, authored_at=meta.authored_at)
                    edges.append(GraphEdge(source=entry_id, target=node_id, kind="tag"))
        degree: Counter[str] = Counter()
        for e in edges:
            degree[e.source] += 1
            degree[e.target] += 1
        nodes = []
        for entry_id, meta in kept.items():
            parts = meta.path.split("/")
            nodes.append(GraphNode(id=entry_id, label=meta.title, path=meta.path,
                                   group=parts[0] if len(parts) > 1 else "", kind=meta.kind,
                                   tags=self._parsed[entry_id].tags, degree=degree[entry_id],
                                   words=self._parsed[entry_id].words, created_at=meta.created_at,
                                   updated_at=meta.updated_at, authored_at=meta.authored_at))
        for node in tag_nodes.values():
            node.degree = degree[node.id]
            nodes.append(node)
        return Graph(nodes=nodes, edges=edges, unresolved=self._unresolved)

    def outlinks(self, entry_id: str) -> list[str]:
        self._known(entry_id)
        return list(self._out.get(entry_id, []))

    def backlinks(self, entry_id: str) -> list[str]:
        self._known(entry_id)
        return list(self._back.get(entry_id, []))

    def search(self, query: str, limit: int = 30) -> list[SearchHit]:
        self._check()
        terms = [t for t in WORD_RE.findall(query.lower()) if t]
        if not terms:
            return []
        hits = []
        for entry_id, text in self._text.items():
            meta = self._meta[entry_id]
            low = text.lower()
            title = meta.title.lower()
            if not all(t in low or t in title for t in terms):
                continue
            score = sum(low.count(t) + 5 * title.count(t) for t in terms)
            hits.append(SearchHit(entry_id=entry_id, title=meta.title, path=meta.path,
                                  snippet=_snippet(text, terms[0]), score=float(score), updated_at=meta.updated_at))
        hits.sort(key=lambda h: -h.score)
        return hits[:limit]

    def mentions(self, term: str, limit: int = 50) -> list[Mention]:
        self._check()
        needle = term.lower().strip()
        if not needle:
            return []
        found = []
        for entry_id, meta in self._meta.items():
            if not _is_text(meta.media_type):
                continue
            for v in self.vault.versions(entry_id):
                text = self.vault.read(entry_id, v.version).decode("utf-8", "replace")
                if needle in text.lower():
                    found.append(Mention(entry_id=entry_id, version=v.version, title=meta.title, path=meta.path,
                                         timestamp=v.timestamp, authored_at=v.source_mtime,
                                         snippet=_snippet(text, needle)))
        found.sort(key=lambda m: m.timestamp)
        return found[:limit]

    def activity(self, basis: Literal["claimed", "ledger"] = "claimed") -> Activity:
        self._check()
        days: dict[date, ActivityDay] = {}
        grid = [[0] * 24 for _ in range(7)]
        groups: dict[str, Counter[str]] = defaultdict(Counter)
        tags: dict[str, Counter[str]] = defaultdict(Counter)
        for entry_id, meta in self._meta.items():
            parts = meta.path.split("/")
            group = parts[0] if len(parts) > 1 else ""
            previous_words = 0
            touched_months: set[str] = set()
            for v in self.vault.versions(entry_id):
                when = v.source_mtime if basis == "claimed" and v.source_mtime else v.timestamp
                local = when.astimezone()
                day = local.date()
                item = days.setdefault(day, ActivityDay(day=day))
                if v.version == 1:
                    item.created += 1
                else:
                    item.updated += 1
                words = 0
                if _is_text(meta.media_type):
                    words = len(WORD_RE.findall(self.vault.read(entry_id, v.version).decode("utf-8", "replace")))
                item.words += max(0, words - previous_words)
                previous_words = words
                grid[local.weekday()][local.hour] += 1
                touched_months.add(local.strftime("%Y-%m"))
            for month in touched_months:
                groups[month][group or "(racine)"] += 1
                for tag in self._parsed[entry_id].tags:
                    tags[month][tag] += 1
        return Activity(basis=basis, days=[days[d] for d in sorted(days)], hour_weekday=grid,
                        groups_by_month={m: dict(c) for m, c in sorted(groups.items())},
                        tags_by_month={m: dict(c) for m, c in sorted(tags.items())})


# ----------------------------------------------------------------------- demo vault


class DemoVault(InMemoryVault):
    """InMemoryVault with a settable clock, reopening, and local fake anchors."""

    DEMO_AUTHORITY = "démonstration locale (aucune autorité contactée)"

    def __init__(self) -> None:
        self.now: datetime | None = None
        super().__init__(clock=lambda: self.now or datetime.now(UTC))
        self._anchors: list[Anchor] = []
        self._trusted: set[int] = set()  # indexes of anchors treated as authenticated

    def reopen(self) -> None:
        self._locked = False

    def anchor_methods(self) -> list[str]:
        return ["rfc3161"]

    def add_demo_anchor(self, anchored_at: datetime, *, trusted: bool = False) -> Anchor:
        head = self._ledger[-1]
        anchor = Anchor(seq_upto=head.seq, head_hash=head.record_hash, method="rfc3161",
                        authority=self.DEMO_AUTHORITY, anchored_at=anchored_at,
                        proof=base64.b64encode(b"jeton de demonstration, sans valeur").decode())
        if trusted:
            self._trusted.add(len(self._anchors))
        self._anchors.append(anchor)
        return anchor

    def anchors(self) -> list[Anchor]:
        self._check()
        return list(self._anchors)

    def anchor(self, method: Literal["rfc3161", "opentimestamps"] = "rfc3161") -> Anchor:
        self._check()
        if not self._ledger:
            raise VaultError("le registre est vide")
        if method not in self.anchor_methods():
            raise VaultError(f"méthode non disponible : {method}")
        return self.add_demo_anchor(datetime.now(UTC))

    def anchor_status(self, anchors: list[tuple[int, Anchor]] | None = None) -> list[AnchorStatus]:
        """Demo trust states: the first stored anchor plays an authenticated authority,
        the others an authority that could not be authenticated."""
        items = anchors if anchors is not None else list(enumerate(self._anchors))
        return [AnchorStatus(seq_upto=a.seq_upto, authority=a.authority, anchored_at=a.anchored_at,
                             state="proven" if i in self._trusted else "claimed",
                             signer="CN=Autorité de démonstration" if i in self._trusted else "",
                             error="" if i in self._trusted else "autorité non authentifiée (jeton de démonstration)")
                for i, a in items]

    def verify(self) -> VerifyReport:
        report = super().verify()
        report.anchors_checked = len(self._anchors)
        report.anchor_status = self.anchor_status()
        return report

    def proof(self, entry_id: str, version: int | None = None) -> ProvenanceProof:
        proof = super().proof(entry_id, version)
        covering = [(i, a) for i, a in enumerate(self._anchors) if a.seq_upto >= proof.record.seq]
        proof.anchors = [a for _, a in covering]
        proven = [a.anchored_at for i, a in covering if i in self._trusted and a.anchored_at]
        claimed = [a.anchored_at for i, a in covering if i not in self._trusted and a.anchored_at]
        proof.proven_before = min(proven) if proven else None
        proof.claimed_before = min(claimed) if claimed else None
        proof.anchor_status = self.anchor_status(covering)
        proof.anchor_errors = [
            f"ancre jusqu'à la séquence {a.seq_upto} : autorité non authentifiée (jeton de démonstration)"
            for i, a in covering if i not in self._trusted]
        return proof


# ------------------------------------------------------------------------ demo data

FOLDERS = ["Journal", "Recherche", "Projets", "Brouillons", "Code", "Lectures", "Pièces jointes"]
NOUNS = ["Mémoire", "Archive", "Trace", "Signature", "Récit", "Méthode", "Carnet", "Index", "Lien", "Version",
         "Source", "Rythme", "Atelier", "Question", "Preuve", "Empreinte", "Chaîne", "Graphe", "Licence", "Corpus"]
ADJECTIVES = ["vivante", "partagée", "lente", "ouverte", "fragile", "durable", "locale", "collective", "privée",
              "numérique", "datée", "chiffrée"]
CONCEPTS = ["Horodatage", "Chaîne de hachage", "Preuve d'antériorité", "Chiffrement local", "Graphe de connaissances",
            "Écriture quotidienne", "Licence de données", "Droit d'auteur", "Modèles de langage", "Jardin numérique",
            "Zettelkasten", "Revue hebdomadaire", "Lecture lente", "Attention", "Habitudes", "Typographie",
            "Cartographie", "Autorité d'horodatage", "Merkle", "Signature Ed25519", "Redevances", "Consentement",
            "Données personnelles", "Provenance", "Versionnage", "Oubli", "Mémoire de travail", "Prise de notes"]
TAGS = ["idée", "lecture", "projet", "question", "méthode", "à-relire", "citation", "code", "journal", "preuve",
        "licence", "brouillon"]
SENTENCES = [
    "Je reprends l'idée de {a} sous un autre angle, en partant de {b}.",
    "Ce qui compte ici, c'est la date à laquelle la note a existé, pas celle du fichier.",
    "Une question reste ouverte : comment relier {a} et {b} sans tout réécrire ?",
    "Premier essai de formulation, à reprendre demain avec un exemple concret.",
    "La lecture du jour confirme l'intuition notée dans {a}.",
    "Il faudrait mesurer le temps passé sur {b} avant de conclure.",
    "Trois pistes : simplifier, dater, partager seulement ce qui doit l'être.",
    "Le lien avec {a} est plus fort que prévu ; voir aussi {b}.",
    "Note rapide après la réunion : garder une trace écrite de chaque décision.",
    "En relisant, je remarque que {a} revient souvent sans être défini.",
]


def _title_pool(rng: random.Random, n: int) -> list[str]:
    pool = [f"{noun} {adj}" for noun in NOUNS for adj in ADJECTIVES]
    rng.shuffle(pool)
    return pool[:n]


def _paragraph(rng: random.Random, links: list[str]) -> str:
    out = []
    for _ in range(rng.randint(2, 4)):
        a = f"[[{rng.choice(links)}]]" if links else "cette idée"
        b = f"[[{rng.choice(links)}]]" if links else "la précédente"
        out.append(rng.choice(SENTENCES).format(a=a, b=b))
    return " ".join(out)


HOSTILE_NOTE = """# Collage depuis le web

Texte copié d'une page, avec du contenu hostile qui doit rester inerte :

<script>alert('xss')</script>

<img src=x onerror="alert(1)">

[un lien piégé](javascript:alert(1)) et [un autre](JaVaScRiPt:alert(2)) et [data](data:text/html,<b>x</b>)

[[Index" onmouseover="alert(3)]]

`<b>code</b>` et **gras <i>pas italique</i>**

| colonne | valeur |
| --- | --- |
| <svg onload=alert(4)> | [lien](https://exemple.org) |
"""


def build_demo(vault: DemoVault | None = None, seed: int = 7) -> DemoVault:
    """Fill a DemoVault with about 340 notes over three years, versions, two licenses."""
    rng = random.Random(seed)
    vault = vault or DemoVault()
    start = datetime(2023, 11, 15, 9, 0, tzinfo=UTC)
    end = datetime(2026, 11, 10, 18, 0, tzinfo=UTC)
    import_day = datetime(2025, 3, 1, 10, 0, tzinfo=UTC)
    span = (end - start).total_seconds()

    def at(fraction: float) -> datetime:
        moment = start + timedelta(seconds=span * fraction)
        hour = rng.choice([7, 8, 9, 10, 11, 14, 15, 16, 17, 21, 22, 23])
        return moment.replace(hour=hour, minute=rng.randint(0, 59))

    docs: list[dict] = []  # path, title, kind, tags, media_type, authored, body builder

    def add(path: str, title: str, authored: datetime, *, kind: str = "note", tags: list[str] | None = None,
            media_type: str = "text/markdown", body: str | None = None, links: list[str] | None = None) -> None:
        if any(d["path"] == path for d in docs):
            return
        docs.append({"path": path, "title": title, "kind": kind, "tags": tags or [], "media_type": media_type,
                     "authored": authored, "body": body, "links": links or []})

    concepts = CONCEPTS[:]
    concept_titles = concepts + _title_pool(rng, 34)
    projects = {"Projets/Empreinte": "Empreinte", "Projets/Recueil": "Recueil d'essais",
                "Projets/Atlas": "Atlas des lectures", "Projets/Atelier": "Atelier d'écriture"}
    project_notes: dict[str, list[str]] = {}
    for folder, name in projects.items():
        titles = [f"{name} : {t}" for t in ("plan", "journal de bord", "questions", "décisions", "calendrier",
                                             "références", "risques", "idées en vrac", "bilan", "suite")]
        project_notes[folder] = titles
    # Long titles (60 to 90 characters), as in real reading notes.
    suffixes = ["notes prises pendant la relecture du chapitre sur la mémoire datée",
                "ce que le livre dit de la preuve et de la date des écrits personnels",
                "résumé, citations choisies et questions ouvertes pour la suite",
                "relecture lente, avec les passages à reprendre dans un essai"]
    reading_titles = [f"Lecture : {t}, {suffixes[i % len(suffixes)]}"[:90]
                      for i, t in enumerate(_title_pool(random.Random(seed + 1), 40))]
    attachments = [f"schema-{i:02d}.png" for i in range(1, 8)] + ["contrat-type.pdf", "releve-2024.pdf",
                                                                    "carte.png"]

    add("Index.md", "Index", start, tags=["index"],
        body="# Index\n\nPoint d'entrée de l'archive. Les grandes notes de concept :\n\n" +
             "\n".join(f"- [[{t}]]" for t in concept_titles) +
             "\n\nLes projets :\n\n" + "\n".join(f"- [[{titles[0]}]]" for titles in project_notes.values()) +
             "\n\nLectures :\n\n" + "\n".join(f"- [[{t}]]" for t in reading_titles) +
             "\n\nVoir aussi [[Méthode de travail]] et [[Lecture lente]].\n")
    add("Méthode de travail.md", "Méthode de travail", at(0.01), tags=["méthode"],
        body="# Méthode de travail\n\n1. Écrire chaque jour dans le **journal**.\n2. Relier chaque idée à un "
             "concept : [[Zettelkasten]], [[Prise de notes]].\n3. Relire le dimanche ([[Revue hebdomadaire]]).\n\n"
             "> Une note qui n'est reliée à rien est une note perdue.\n\n- [ ] trier les brouillons\n- [x] dater "
             "les imports\n")
    for i, title in enumerate(concept_titles):
        sub = "Recherche/Concepts" if i < len(concepts) else "Recherche/Notes"
        add(f"{sub}/{title}.md", title, at(rng.random() * 0.9), tags=rng.sample(TAGS[:6], rng.randint(0, 2)),
            links=rng.sample(concept_titles, 1 if rng.random() < 0.7 else 2))
    for folder, titles in project_notes.items():
        base = rng.random() * 0.6 + 0.2
        for j, title in enumerate(titles):
            add(f"{folder}/{title}.md", title, at(min(0.99, base + j * 0.02)), tags=["projet"],
                links=([rng.choice(concept_titles)] if j == 0 else [titles[0]] + ([titles[1]] if rng.random() < 0.3 else [])))
    for i, title in enumerate(reading_titles):
        add(f"Lectures/{title}.md", title, at(rng.random()), tags=["lecture"] + (["citation"] if i % 3 == 0 else []),
            links=[concept_titles[rng.randint(0, 11)]])
    all_project_notes = [t for ts in project_notes.values() for t in ts]
    for year in (2023, 2024, 2025, 2026):
        add(f"Journal/{year}/Journal {year}.md", f"Journal {year}", max(start, datetime(year, 1, 1, 9, 0, tzinfo=UTC)),
            kind="log", tags=["journal"], links=["Index"])
    for k in range(150):
        when = at(k / 150 + rng.random() * 0.004)
        day = when.date().isoformat()
        extra = [rng.choice(all_project_notes)] if rng.random() < 0.2 else []
        add(f"Journal/{when.year}/{day}.md", f"Journal du {day}", when, kind="log", tags=["journal"],
            links=([f"Journal {when.year}"] if rng.random() < 0.85 else []) + extra)
    for i in range(24):
        title = f"Brouillon {i + 1:02d} : {rng.choice(NOUNS).lower()}"
        add(f"Brouillons/{title}.md", title, at(rng.random()), kind="draft", tags=["brouillon"],
            links=[rng.choice(concept_titles)] if i % 2 else [])
    add("Brouillons/Collage depuis le web.md", "Collage depuis le web", at(0.97), kind="draft", body=HOSTILE_NOTE)
    for i, name in enumerate(["chaine.py", "horodatage.py", "graphe.js", "import.sh", "licence.py", "verif.py",
                              "notes.sql", "export.py", "rendu.css", "cles.py", "index.py"]):
        lang = {"py": "python", "js": "javascript", "sh": "bash", "sql": "sql", "css": "css"}[name.rsplit(".", 1)[1]]
        body = (f"# {name}\n\nExtrait de code lié à [[{rng.choice(concepts)}]].\n\n```{lang}\n"
                f"def etape_{i}(donnees):\n    # calcule une empreinte\n    return hash(donnees)\n```\n")
        add(f"Code/{name}.md", name, at(rng.random() * 0.8 + 0.2), kind="code", tags=["code"], body=body)
    add("Code/reglages.json", "reglages.json", at(0.6), kind="code", tags=["code"], media_type="application/json",
        body='{\n  "archive": "Empreinte",\n  "verrouillage_minutes": 15,\n  "ancrage": ["rfc3161"],\n'
             '  "note": "<script>alert(1)</script> reste du texte"\n}\n')
    add("Code/import.yaml", "import.yaml", at(0.7), kind="code", tags=["code"], media_type="application/yaml",
        body="dossiers:\n  - Journal\n  - Recherche\nexclure:\n  - '*.tmp'\n# commentaire : *pas* du Markdown\n")
    for name in attachments:
        add(f"Pièces jointes/{name}", name, at(rng.random()), kind="file",
            media_type="image/png" if name.endswith(".png") else "application/pdf")
    for i in range(6):
        add(f"Isolées/Note isolée {i + 1}.md", f"Note isolée {i + 1}", at(rng.random()), tags=[])

    # Some notes embed attachments.
    for doc in rng.sample([d for d in docs if d["kind"] == "note" and d["body"] is None], 14):
        doc["links"] = doc["links"] + [f"!{rng.choice(attachments)}"]

    ops: list[tuple[datetime, Callable[[], None]]] = []

    def text_for(doc: dict, extra: str = "") -> bytes:
        if doc["body"] is not None:
            return (doc["body"] + extra).encode("utf-8")
        if doc["media_type"] != "text/markdown":
            return hashlib.sha256(doc["path"].encode()).digest() * 40
        links = [link for link in doc["links"] if not link.startswith("!")]
        embeds = [link[1:] for link in doc["links"] if link.startswith("!")]
        parts = [f"# {doc['title']}", "", _paragraph(rng, links)]
        if links:
            parts += ["", "Voir aussi : " + ", ".join(f"[[{link}]]" for link in links)]
        if doc["tags"]:
            parts += ["", " ".join(f"#{t}" for t in doc["tags"])]
        if doc["kind"] == "log":
            parts += ["", "## Fait aujourd'hui", "", "- relu une note ancienne", "- écrit *une page*",
                      f"- avancé sur {('[[' + links[0] + ']]') if links else 'le plan'}"]
        if rng.random() < 0.08:
            parts += ["", "| Étape | Durée |", "| --- | --- |", "| lecture | 40 min |", "| écriture | 1 h |"]
        if rng.random() < 0.15:
            parts += ["", "> Ce que l'on note avec sa date devient une preuve."]
        for embed in embeds:
            parts += ["", f"![[{embed}]]"]
        return ("\n".join(parts) + extra + "\n").encode("utf-8")

    for doc in docs:
        authored: datetime = doc["authored"]
        imported = authored < import_day
        ledger_time = import_day + timedelta(seconds=len(ops)) if imported else authored + timedelta(minutes=3)
        source_mtime = authored if imported or doc["kind"] in ("file", "code") else None
        content = text_for(doc)

        def put(doc=doc, content=content, source_mtime=source_mtime) -> None:
            vault.put(doc["path"], content, title=doc["title"], kind=doc["kind"], tags=doc["tags"],
                      media_type=doc["media_type"], source_mtime=source_mtime)

        ops.append((ledger_time, put))
        if doc["media_type"] == "text/markdown" and doc["kind"] != "log" and rng.random() < 0.12:
            later = max(ledger_time, authored) + timedelta(days=rng.randint(3, 200), hours=rng.randint(0, 8))
            if later < end:
                v2 = text_for(doc, "\n\n## Ajout\n\nReprise de la note : une précision sur la date et la source.")

                def put2(doc=doc, v2=v2, later=later) -> None:
                    vault.put(doc["path"], v2, title=doc["title"], kind=doc["kind"], tags=doc["tags"],
                              media_type=doc["media_type"], source_mtime=None if later >= import_day else later)

                ops.append((later, put2))
                if rng.random() < 0.4:
                    later3 = later + timedelta(days=rng.randint(2, 60))
                    if later3 < end:
                        v3 = v2 + "\n\nTroisième passage, plus court.".encode("utf-8")

                        def put3(doc=doc, v3=v3) -> None:
                            vault.put(doc["path"], v3, title=doc["title"], kind=doc["kind"], tags=doc["tags"],
                                      media_type=doc["media_type"])

                        ops.append((later3, put3))

    ops.append((datetime(2025, 6, 2, 12, 0, tzinfo=UTC), lambda: vault.add_demo_anchor(vault.now, trusted=True)))
    ops.append((datetime(2026, 2, 3, 12, 0, tzinfo=UTC), lambda: vault.add_demo_anchor(vault.now)))

    def licenses() -> None:
        by_path = {m.path: m.entry_id for m in vault.entries()}
        first = [by_path[d["path"]] for d in docs if d["path"].startswith("Recherche/Concepts/") and d["path"] in by_path][:12]
        second = [by_path[d["path"]] for d in docs if d["path"].startswith("Lectures/") and d["path"] in by_path][:20]
        g1 = vault.grant("Atelier Lumen (éditeur)", [(e, None) for e in first],
                         usage="publication d'un recueil imprimé de douze notes de recherche",
                         terms="Exclusivité de six mois en langue française.",
                         royalty=RoyaltyTerms(model="flat", amount=1200.0, currency="EUR", note="versé en deux fois"),
                         valid_until=date(2027, 12, 31))
        g2 = vault.grant("Laboratoire Corpus Ouvert", [(e, None) for e in second],
                         usage="entraînement d'un modèle de langage nommé, sans redistribution du texte",
                         terms="Suppression du corpus à la fin de la licence.",
                         royalty=RoyaltyTerms(model="revenue_share", amount=3.5, currency="USD"),
                         valid_until=date(2026, 12, 31))
        vault.now = datetime(2026, 9, 20, 10, 0, tzinfo=UTC)
        vault.record_royalty(g1.license_id, 600.0, currency="EUR", received_on=date(2026, 9, 20), period="2026-T3",
                             note="premier versement")
        vault.now = datetime(2026, 10, 15, 10, 0, tzinfo=UTC)
        vault.record_royalty(g2.license_id, 240.5, currency="USD", received_on=date(2026, 10, 15), period="2026-T3")
        vault.now = datetime(2026, 11, 5, 10, 0, tzinfo=UTC)
        vault.record_royalty(g1.license_id, 600.0, currency="EUR", received_on=date(2026, 11, 5), period="2026-T4",
                             note="solde")

    ops.append((datetime(2026, 9, 1, 10, 0, tzinfo=UTC), licenses))
    ops.sort(key=lambda item: item[0])
    for when, op in ops:
        vault.now = max(vault.now or when, when)
        op()
    vault.now = None
    return vault


# --------------------------------------------------------------------- demo actions


STOPWORDS = {"cette", "comme", "aussi", "avant", "après", "notes", "toute", "entre", "votre", "leurs", "autre",
             "faudrait", "reste", "comment", "partant", "relier"}


def make_preview(vault: VaultAPI, entry_id: str) -> Preview:
    """A teaser built without any model: first sentences and frequent words."""
    meta = vault.entry(entry_id)
    latest = vault.versions(entry_id)[-1]
    text = vault.read(entry_id).decode("utf-8", "replace") if _is_text(meta.media_type) else ""
    plain = re.sub(r"\[\[([^\]|]+)(\|[^\]]*)?\]\]", r"\1", text)
    plain = re.sub(r"[#>*`|_\-\[\]()!]", " ", plain)
    plain = re.sub(r"\s+", " ", plain).strip()
    sentences = re.split(r"(?<=[.!?])\s+", plain)
    summary = " ".join(sentences[:2])[:280] or "Document sans texte."
    words = [w.lower() for w in WORD_RE.findall(plain) if len(w) >= 5 and w.lower() not in STOPWORDS]
    keywords = [w for w, _ in Counter(words).most_common(6)]
    preview = Preview(entry_id=entry_id, version=latest.version, summary=summary, keywords=keywords,
                      words=len(WORD_RE.findall(plain)), commitment=latest.commitment,
                      model="démonstration (aucun modèle)", created_at=datetime.now(UTC))
    vault.aux_put("preview/" + entry_id, preview.model_dump_json().encode("utf-8"))
    return preview


def demo_session(*, fresh: bool = False):
    """The Session of the demo. Passphrase "demo"; `fresh` starts without an archive."""
    from .server import Session

    state: dict = {"vault": None, "passphrase": "demo"}
    export_dir = Path(tempfile.mkdtemp(prefix="empreinte-demo-export-"))

    if not fresh:
        state["vault"] = build_demo()

    def exists() -> bool:
        return state["vault"] is not None

    def open_vault(passphrase: str):
        if state["vault"] is None or not secrets.compare_digest(passphrase.encode(), state["passphrase"].encode()):
            raise WrongPassphrase("phrase de passe incorrecte")
        state["vault"].reopen()
        return state["vault"], StubWorkspace(state["vault"])

    def create_vault(passphrase: str):
        if state["vault"] is not None:
            raise VaultError("une archive existe déjà")
        state["passphrase"] = passphrase
        state["vault"] = build_demo()
        key = "-".join(secrets.token_hex(2).upper() for _ in range(8))
        return state["vault"], StubWorkspace(state["vault"]), key

    def make_previews(vault: VaultAPI, workspace, entry_ids: list[str]) -> list[Preview]:
        return [make_preview(vault, e) for e in entry_ids]

    # No import_folder: the demo passphrase is public, so the demo never reads real files.
    return Session(open_vault=open_vault, create_vault=create_vault, exists=exists, import_folder=None,
                   make_previews=make_previews, export_dir=export_dir, demo=True)
