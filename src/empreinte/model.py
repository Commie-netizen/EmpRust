"""Shared data contract. Three people build against this file in parallel:
do not rename or retype a field without telling the integrator.

Two kinds of time appear everywhere, and they must never be confused:

* ledger time (`created_at`, `updated_at`, `LedgerRecord.timestamp`): when the vault
  recorded a version. It is what the hash chain orders, and what an external anchor
  can prove to a third party.
* claimed time (`authored_at`, `modified_at`): the file date of an imported document.
  It is useful to navigate the past (timeline, activity), but it is only a claim: a
  note written in 2021 and imported today is provable from today, not from 2021.

What is secret and what is not:

* Plaintext, titles, paths, tags and every model below except LedgerRecord and Anchor
  exist only encrypted on disk and in memory while the vault is unlocked.
* LedgerRecord and Anchor are designed to be shown to anyone: they hold opaque ids,
  hashes, sizes and times, never content or names. Coverage holds only counts and times.
* A public catalogue (catalogue.py, docs/FORMAT.md section 15) is written from approved
  previews and ledger records only; CatalogueCandidate and CataloguePublication are the
  owner's private view of it and stay encrypted like everything else.
"""
from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

EntryKind = Literal["note", "draft", "log", "code", "file"]
RecordKind = Literal["put", "remove", "license", "royalty"]
EdgeKind = Literal["link", "embed", "tag"]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------------------------- entries


class EntryMeta(_Model):
    """One document of the archive, at its latest version."""

    entry_id: str  # 32 hex chars, random, never derived from content or path
    path: str  # logical path with forward slashes, unique among live entries
    title: str
    kind: EntryKind = "note"
    media_type: str = "text/markdown"
    tags: list[str] = Field(default_factory=list)  # without the leading '#'
    n_versions: int = 1
    size: int = 0  # bytes of the latest plaintext
    created_at: datetime  # ledger time of version 1, UTC
    updated_at: datetime  # ledger time of the latest version, UTC
    authored_at: datetime | None = None  # claimed: earliest source file date
    modified_at: datetime | None = None  # claimed: latest source file date


class Version(_Model):
    entry_id: str
    version: int  # 1-based
    seq: int  # LedgerRecord.seq that recorded it
    timestamp: datetime  # ledger time, UTC
    size: int
    commitment: str  # hex, same as the ledger record
    source_mtime: datetime | None = None  # claimed


# ---------------------------------------------------------------------------- ledger


class LedgerRecord(_Model):
    """One line of the append-only hash chain. Public-safe by construction."""

    seq: int  # 0-based, gapless
    kind: RecordKind
    entry_id: str = ""  # opaque; "" for records that are not about one entry
    version: int = 0
    commitment: str = ""  # hex SHA-256(salt || plaintext); the salt stays in the vault
    cipher_hash: str = ""  # hex SHA-256 of the encrypted blob as stored
    size: int = 0  # plaintext bytes
    timestamp: datetime  # ledger time, UTC, from the local clock
    prev_hash: str  # record_hash of seq - 1, or 64 zeros for seq 0
    # hex SHA-256(prev_hash || SHA-256(canonical body)); the body also binds the vault's
    # public key. Exact encoding in docs/FORMAT.md. The two-level form lets a license
    # bundle prove a chain by disclosing only 32-byte digests of the records in between.
    record_hash: str
    signature: str = ""  # hex Ed25519 signature of record_hash by the vault identity


class Anchor(_Model):
    """Proof by an outside authority that the chain head existed at a given time."""

    seq_upto: int  # the anchor covers records 0..seq_upto
    head_hash: str  # record_hash of seq_upto, the only thing ever sent out
    method: Literal["rfc3161", "opentimestamps"]
    authority: str  # URL or name of the timestamp authority
    anchored_at: datetime | None = None  # time asserted by the authority, UTC
    proof: str  # base64 of the authority's token


class AnchorStatus(_Model):
    """One anchor as re-checked just now. The interface names an authority as
    authenticated only from an entry whose state is "proven"."""

    seq_upto: int
    authority: str
    anchored_at: datetime | None = None
    # proven: token valid and its signer chains to a trusted root.
    # claimed: token internally valid, authority not authenticated.
    # invalid: the token fails; `error` says why.
    state: Literal["proven", "claimed", "invalid"]
    signer: str = ""  # subject of the signing certificate, when readable
    error: str = ""


class VerifyReport(_Model):
    ok: bool
    n_records: int
    head_hash: str
    signatures_checked: int = 0
    blobs_checked: int = 0
    anchors_checked: int = 0
    anchor_status: list[AnchorStatus] = Field(default_factory=list)  # one per stored anchor
    errors: list[str] = Field(default_factory=list)  # human readable, empty when ok


class ProvenanceProof(_Model):
    """Everything needed to show when one version was recorded."""

    record: LedgerRecord
    public_key: str  # hex Ed25519 public key of the vault identity
    head_hash: str
    n_following: int  # records chained after this one
    anchors: list[Anchor] = Field(default_factory=list)  # anchors with seq_upto >= record.seq
    # Earliest time asserted by an anchor whose token was re-checked just now AND whose
    # signer chains to a trusted root. An anchor that fails either test never sets it.
    proven_before: datetime | None = None
    # Earliest time asserted by a token that is internally valid but whose authority could
    # not be authenticated (no trusted root). Shown as a claim by an unverified authority.
    claimed_before: datetime | None = None
    anchor_errors: list[str] = Field(default_factory=list)  # why an anchor was not used
    # One entry per anchor covering this record, so the interface can name the authority
    # that really supports proven_before instead of guessing from the anchor list.
    anchor_status: list[AnchorStatus] = Field(default_factory=list)
    verified: bool = False  # chain from this record to the head re-checked just now (not a full verify())


# ------------------------------------------------------------------ parsing and graph


class ParsedDoc(_Model):
    """What the parser reads in one document's text."""

    title: str
    tags: list[str] = Field(default_factory=list)
    links: list[str] = Field(default_factory=list)  # raw targets of [[wikilinks]] and [text](relative.md)
    embeds: list[str] = Field(default_factory=list)  # raw targets of ![[embeds]]
    aliases: list[str] = Field(default_factory=list)  # front matter aliases: searchable, not link targets
    headings: list[str] = Field(default_factory=list)
    words: int = 0


class GraphNode(_Model):
    id: str  # entry_id, or "tag:<name>" for a tag node
    node_type: Literal["entry", "tag"] = "entry"
    label: str  # title
    path: str
    # First path segment once the folders shared by every entry are stripped, so that a
    # vault imported under one root folder still splits into meaningful groups. "" at the
    # top, "#" for tag nodes.
    group: str
    kind: EntryKind = "note"
    tags: list[str] = Field(default_factory=list)
    degree: int = 0
    words: int = 0
    created_at: datetime  # ledger time
    updated_at: datetime
    authored_at: datetime | None = None  # claimed; the timeline falls back to created_at


class GraphEdge(_Model):
    source: str  # entry_id
    target: str  # entry_id
    kind: EdgeKind = "link"


class Graph(_Model):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    unresolved: int = 0  # links whose target is not in the archive


class ActivityDay(_Model):
    day: date
    created: int = 0  # documents first seen that day
    updated: int = 0  # later versions recorded that day
    words: int = 0  # words written that day (new documents plus growth)


class Activity(_Model):
    """Longitudinal view. `basis` says which time was used."""

    basis: Literal["claimed", "ledger"]
    days: list[ActivityDay] = Field(default_factory=list)  # ascending, days without activity omitted
    hour_weekday: list[list[int]] = Field(default_factory=list)  # 7 rows (Monday first) x 24 hours, local time
    groups_by_month: dict[str, dict[str, int]] = Field(default_factory=dict)  # "YYYY-MM" -> group -> documents touched
    tags_by_month: dict[str, dict[str, int]] = Field(default_factory=dict)  # "YYYY-MM" -> tag -> documents touched


class SearchHit(_Model):
    entry_id: str
    title: str
    path: str
    snippet: str  # plain text, about 160 chars around the match
    score: float
    updated_at: datetime


class Mention(_Model):
    """One version in which a term appears: answers "when did this idea first show up"."""

    entry_id: str
    version: int
    title: str
    path: str
    timestamp: datetime  # ledger time of that version: the provable date
    authored_at: datetime | None = None  # claimed date of that version
    snippet: str


# ------------------------------------------------------------------------- licensing


class RoyaltyTerms(_Model):
    model: Literal["flat", "per_use", "revenue_share", "none"] = "none"
    amount: float = 0.0  # flat fee, price per use, or percentage for revenue_share
    currency: str = "EUR"
    note: str = ""


class LicenseItem(_Model):
    entry_id: str
    version: int
    title: str  # disclosed to the licensee
    commitment: str


class LicenseGrant(_Model):
    license_id: str
    licensee: str
    items: list[LicenseItem]
    usage: str  # what the licensee may do, e.g. "training of one named model"
    terms: str  # free text
    royalty: RoyaltyTerms = Field(default_factory=RoyaltyTerms)
    created_at: datetime
    valid_until: date | None = None
    seq: int  # ledger record of kind "license"
    bundle_hash: str = ""  # hex SHA-256 of the exported bundle manifest, once exported


class RoyaltyEvent(_Model):
    license_id: str
    received_on: date
    amount: float
    currency: str = "EUR"
    period: str = ""  # e.g. "2026-Q4"
    note: str = ""
    seq: int  # ledger record of kind "royalty"


class Coverage(_Model):
    """How much of the ledger a third party can date: records 0..covered_upto are covered
    by an anchor whose authority was authenticated just now ("proven")."""

    n_records: int
    covered_upto: int = -1  # last seq covered by a proven anchor; -1 when none is
    uncovered: int = 0  # records after covered_upto: their date rests on the local clock only
    oldest_uncovered_at: datetime | None = None  # ledger time of record covered_upto + 1
    claimed_upto: int = -1  # last seq covered by an anchor that is only "claimed"


# ------------------------------------------------------------------- public catalogue


class CatalogueChoice(_Model):
    """One entry the owner lists in a public catalogue. Only the approved preview, sizes
    and the proof are published; title, path and tags only when ticked here."""

    entry_id: str
    show_title: bool = False
    show_path: bool = False
    show_tags: bool = False


class CatalogueCandidate(_Model):
    """Whether an entry can be listed (owner's interface only, never published)."""

    entry_id: str
    eligible: bool
    reason: str = ""  # why not, in French, when not eligible
    version: int = 0  # the version its approved preview describes
    latest: bool = True  # that version is the entry's latest
    summary: str = ""
    keywords: list[str] = Field(default_factory=list)
    words: int = 0
    anchored: Literal["proven", "claimed", "none"] = "none"  # best anchor covering that version now


class PublishedEntry(_Model):
    public_id: str  # 32 hex, random, stable for one (entry, version) across catalogues
    entry_id: str
    version: int
    commitment: str
    shown: list[Literal["title", "path", "tags"]] = Field(default_factory=list)
    anchor_state: Literal["proven", "claimed", "none"] = "none"  # as assessed at export time
    anchored_at: datetime | None = None  # time asserted by that anchor


class CataloguePublication(_Model):
    """The owner's private record of one exported catalogue (kept encrypted)."""

    catalogue_id: str  # 32 hex, random
    exported_at: datetime
    path: str  # directory written
    catalogue_hash: str  # hex SHA-256 of catalogue.json as written
    entries: list[PublishedEntry] = Field(default_factory=list)


class Preview(_Model):
    """A teaser that can be shown to a prospective licensee without revealing the document.
    Written by a local model, then scrubbed of personal data. Stored encrypted until published."""

    entry_id: str
    version: int
    summary: str
    keywords: list[str] = Field(default_factory=list)
    words: int = 0
    commitment: str  # ties the teaser to one exact version
    model: str
    created_at: datetime
    # A generated teaser is a draft. Automatic leak checks cannot guarantee that it reveals
    # nothing: the owner must read it and approve it before it is shown to anyone.
    approved: bool = False
    context_policy: str = ""
    source_partial: bool = False
    context_bytes: int = 0
