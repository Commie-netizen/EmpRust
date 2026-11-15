"""The two interfaces everything else is written against.

    VaultAPI      encrypted storage, ledger, licensing   (implemented by vault.Vault)
    WorkspaceAPI  everything derived from plaintext while unlocked: parsing, graph,
                  search, activity                       (implemented by workspace.Workspace)

The HTTP server and the command line only ever call these two. `testing.InMemoryVault`
implements VaultAPI without any cryptography, for tests of the other layers.
"""
from __future__ import annotations

from datetime import date, datetime
from pathlib import Path
from typing import Literal, Protocol, Sequence, runtime_checkable

from .model import (
    Activity,
    Anchor,
    CatalogueChoice,
    CataloguePublication,
    Coverage,
    EntryKind,
    EntryMeta,
    Graph,
    LedgerRecord,
    LicenseGrant,
    Mention,
    ParsedDoc,
    ProvenanceProof,
    RoyaltyEvent,
    RoyaltyTerms,
    SearchHit,
    VerifyReport,
    Version,
)


class VaultError(Exception):
    """Base class of every error the vault raises on purpose."""


class WrongPassphrase(VaultError):
    pass


class NotFound(VaultError):
    pass


class Corrupted(VaultError):
    """A blob, the ledger or the header failed an integrity check."""


@runtime_checkable
class VaultAPI(Protocol):
    # ------------------------------------------------------------------ entries
    def put(
        self,
        path: str,
        content: bytes,
        *,
        title: str | None = None,
        kind: EntryKind = "note",
        tags: Sequence[str] = (),
        media_type: str = "text/markdown",
        source_mtime: datetime | None = None,
    ) -> Version:
        """Record `content` at logical `path`.

        New path: creates the entry at version 1. Existing path with different content:
        appends a new version. Existing path with identical content: changes nothing and
        returns the latest Version (so an import can be re-run). `title` None keeps the
        previous title, or for a new entry takes the last path segment without its
        extension; kind, tags and media_type are replaced by the values given. Each new
        version appends exactly one ledger record of kind "put".
        """
        ...

    def entries(self) -> list[EntryMeta]:
        """Live entries (removed ones excluded), sorted by path."""
        ...

    def entry(self, entry_id: str) -> EntryMeta:
        """Raises NotFound."""
        ...

    def find(self, path: str) -> EntryMeta | None: ...

    def read(self, entry_id: str, version: int | None = None) -> bytes:
        """Plaintext of a version (latest by default). Raises NotFound, Corrupted."""
        ...

    def versions(self, entry_id: str) -> list[Version]:
        """Ascending."""
        ...

    def remove(self, entry_id: str) -> None:
        """Hide an entry. Its history stays in the ledger; a "remove" record is appended."""
        ...

    # ------------------------------------------------------------------- ledger
    def ledger(self) -> list[LedgerRecord]: ...

    def verify(self) -> VerifyReport:
        """Re-check the whole chain, the signatures, the stored blobs and the anchors."""
        ...

    def proof(self, entry_id: str, version: int | None = None) -> ProvenanceProof: ...

    def anchors(self) -> list[Anchor]: ...

    def anchor_methods(self) -> list[str]:
        """Anchoring methods this vault really implements, e.g. ["rfc3161"]. The interface
        offers only these."""
        ...

    def anchor(self, method: Literal["rfc3161", "opentimestamps"] = "rfc3161") -> Anchor:
        """Ask an outside authority to timestamp the current chain head.

        The only network call of the vault. It sends the 32-byte head hash and nothing
        else. Never called implicitly: only on an explicit user action.
        """
        ...

    # ---------------------------------------------------------------- licensing
    def grant(
        self,
        licensee: str,
        items: Sequence[tuple[str, int | None]],  # (entry_id, version or None for latest)
        *,
        usage: str,
        terms: str = "",
        royalty: RoyaltyTerms | None = None,
        valid_until: date | None = None,
    ) -> LicenseGrant: ...

    def export_bundle(self, license_id: str, out_dir: Path) -> Path:
        """Write the disclosure bundle for one grant and return its directory.

        The bundle holds the plaintext of the licensed versions only, the grant, and for
        each item what a third party needs to check its date without the vault.
        """
        ...

    def licenses(self) -> list[LicenseGrant]: ...

    def record_royalty(
        self, license_id: str, amount: float, *, currency: str = "EUR", received_on: date | None = None,
        period: str = "", note: str = "",
    ) -> RoyaltyEvent: ...

    def royalties(self, license_id: str | None = None) -> list[RoyaltyEvent]: ...

    # ------------------------------------------------------- public catalogue
    def export_catalogue(self, items: Sequence[CatalogueChoice], out_dir: Path) -> CataloguePublication:
        """Write a public catalogue of the chosen entries under out_dir and return the
        private record of what was published.

        Each entry must have a stored preview with approved True whose commitment is one
        of its recorded versions (that exact version is listed); otherwise VaultError and
        nothing is written. The catalogue holds no content: the approved summary and
        keywords, word count, media type, the version's ledger record and, when an anchor
        that is not invalid covers it, the chain digests up to that anchor and its token;
        title, path and tags only when chosen. Signed by the vault identity when the vault
        has one. Format: docs/FORMAT.md section 15.
        """
        ...

    def catalogues(self) -> list[CataloguePublication]:
        """What was published, oldest first."""
        ...

    def coverage(self) -> Coverage:
        """How many ledger records no proven anchor covers yet, and since when."""
        ...

    # ---------------------------------------------------- encrypted side storage
    def aux_get(self, key: str) -> bytes | None:
        """Small encrypted key-value store for derived data (index cache, previews)."""
        ...

    def aux_put(self, key: str, value: bytes) -> None: ...

    def lock(self) -> None:
        """Forget the keys. Every later call raises VaultError."""
        ...


@runtime_checkable
class WorkspaceAPI(Protocol):
    vault: VaultAPI

    def refresh(self) -> None:
        """Re-read the vault after entries changed."""
        ...

    def parsed(self, entry_id: str) -> ParsedDoc: ...

    def text(self, entry_id: str, version: int | None = None) -> str:
        """Decoded text of a text entry; "" for binary media types."""
        ...

    def graph(self, *, until: datetime | None = None, tags_as_nodes: bool = False) -> Graph:
        """Entries as nodes, resolved links as edges.

        `until` keeps only the nodes that existed at that time, by claimed time when the
        entry has one, else ledger time: it drives the timeline slider.
        """
        ...

    def close(self) -> None:
        """Drop every piece of plaintext held in memory (texts, index, caches). Called when
        the vault locks. Every later call raises VaultError."""
        ...

    def link_targets(self, entry_id: str) -> dict[str, str]:
        """Raw link and embed targets of this entry that resolve, mapped to the entry_id
        they resolve to. The one place links are resolved: the interface uses this map and
        never resolves a link itself."""
        ...

    def outlinks(self, entry_id: str) -> list[str]: ...

    def backlinks(self, entry_id: str) -> list[str]: ...

    def search(self, query: str, limit: int = 30) -> list[SearchHit]: ...

    def mentions(self, term: str, limit: int = 50) -> list[Mention]:
        """Every version in which `term` appears, oldest first by ledger time."""
        ...

    def activity(self, basis: Literal["claimed", "ledger"] = "claimed") -> Activity: ...
