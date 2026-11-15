"""Public catalogue: what the owner hands to a prospective licensee, without any content.

A catalogue lists, for each entry the owner chose: an opaque public id, the approved
preview (summary and keywords), the word count and media type, the commitment of the
exact version, its ledger record and, when an anchor covers it, the body digests that
chain the record to that anchor plus the anchor token. Anyone can then check, with the
standalone tools/verify_bundle.py and without the vault, that "this exact document,
which I have not seen, existed no later than this date" and that the vault key signed
the list. Title, path and tags appear only when the owner ticks them per entry.

What it cannot hide, and why (docs/FORMAT.md section 15 has the full note):

* the ledger record is disclosed because the date proof needs it: its canonical body
  holds the entry id, version number, exact size, ledger time and seq. The public id
  therefore does not hide which vault entry is listed from someone who also holds the
  ledger; it is a stable handle, not a mask;
* the chain from the record to its anchor discloses one 32-byte body digest per record
  in between: their number, not their content.

The builder is shared by vault.Vault (signed, real chain proofs) and
testing.InMemoryVault (unsigned, no anchors), so the selection and leak rules are the
same for both.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Callable, Literal, Sequence

from pydantic import ValidationError

from .api import VaultAPI, VaultError
from .ledger import format_time, record_to_dict
from .model import (
    Anchor,
    CatalogueCandidate,
    CatalogueChoice,
    CataloguePublication,
    Coverage,
    LedgerRecord,
    Preview,
    PublishedEntry,
    Version,
)
from .store import atomic_write

CATALOGUE_FORMAT = "empreinte-catalogue"
CATALOGUE_VERSION = 1
SIGNATURE_PREFIX = b"empreinte/v1/catalogue\x00"
PREVIEW_KEY = "preview/"  # same key as previews.make_preview and the server
IDS_KEY = "catalogue/ids.v1"  # {"<entry_id>:<version>": public_id}
PUBLISHED_KEY = "catalogue/published.v1"  # [CataloguePublication]
MAX_ENTRIES = 10_000
STATEMENT = (
    "This catalogue proves only that each listed document, identified by its commitment, was recorded "
    "in the ledger of the vault whose public key is given, and, for an entry with an anchor, that it "
    "existed no later than the time asserted by that timestamp authority. It shows none of the documents. "
    "It proves nothing about their quality or originality, nor about who wrote them beyond control of "
    "that key."
)

State = Literal["proven", "claimed", "none"]


@dataclass(frozen=True)
class AssessedAnchor:
    """An anchor that is not invalid, with its state as re-checked by the vault."""

    anchor: Anchor
    state: Literal["proven", "claimed"]
    time: datetime


# ------------------------------------------------------------------- eligibility


def approved_version(vault: VaultAPI, entry_id: str) -> tuple[Preview, Version] | str:
    """The approved preview of an entry and the version it describes, or why there is none
    (French, for the interface)."""
    raw = vault.aux_get(PREVIEW_KEY + entry_id)
    if raw is None:
        return "aucun aperçu : générez-en un puis approuvez-le"
    try:
        preview = Preview.model_validate_json(raw)
    except ValidationError:
        return "aperçu illisible : régénérez-le"
    if preview.entry_id != entry_id:
        return "aperçu illisible : régénérez-le"
    if not preview.approved:
        return "aperçu non approuvé (brouillon) : relisez-le et approuvez-le"
    for version in vault.versions(entry_id):
        if version.version == preview.version and version.commitment == preview.commitment:
            return preview, version
    return "l'aperçu ne correspond à aucune version enregistrée : régénérez-le"


def state_for(seq: int, coverage: Coverage) -> State:
    if seq <= coverage.covered_upto:
        return "proven"
    if seq <= coverage.claimed_upto:
        return "claimed"
    return "none"


def candidates(vault: VaultAPI) -> list[CatalogueCandidate]:
    """Every live entry, with whether it can be listed and why not."""
    coverage = vault.coverage()
    out = []
    for meta in vault.entries():
        found = approved_version(vault, meta.entry_id)
        if isinstance(found, str):
            out.append(CatalogueCandidate(entry_id=meta.entry_id, eligible=False, reason=found))
            continue
        preview, version = found
        out.append(CatalogueCandidate(
            entry_id=meta.entry_id, eligible=True, version=version.version,
            latest=version.version == meta.n_versions, summary=preview.summary, keywords=list(preview.keywords),
            words=preview.words, anchored=state_for(version.seq, coverage)))
    return out


def coverage_of(records: Sequence[LedgerRecord], anchors: Sequence[AssessedAnchor]) -> Coverage:
    proven = [a.anchor.seq_upto for a in anchors if a.state == "proven"]
    claimed = [a.anchor.seq_upto for a in anchors if a.state == "claimed"]
    covered = max(proven, default=-1)
    uncovered = max(0, len(records) - 1 - covered)
    return Coverage(n_records=len(records), covered_upto=covered, uncovered=uncovered,
                    oldest_uncovered_at=records[covered + 1].timestamp if uncovered else None,
                    claimed_upto=max(claimed, default=-1))


# ------------------------------------------------------------------- publications


def publications(vault: VaultAPI) -> list[CataloguePublication]:
    raw = vault.aux_get(PUBLISHED_KEY)
    if not raw:
        return []
    try:
        return [CataloguePublication.model_validate(p) for p in json.loads(raw.decode("utf-8"))]
    except (ValueError, ValidationError, TypeError):
        return []


def _public_ids(vault: VaultAPI) -> dict[str, str]:
    raw = vault.aux_get(IDS_KEY)
    if not raw:
        return {}
    try:
        data = json.loads(raw.decode("utf-8"))
        return {str(k): str(v) for k, v in data.items()}
    except (ValueError, AttributeError):
        return {}


def canonical(document: dict) -> bytes:
    """Canonical JSON (docs/FORMAT.md section 1), UTF-8, of the catalogue without its signature."""
    body = {k: v for k, v in document.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ------------------------------------------------------------------------- export


def export(vault: VaultAPI, choices: Sequence[CatalogueChoice], out_dir: Path, *, public_key: str,
           records: Sequence[LedgerRecord], anchors: Sequence[AssessedAnchor],
           sign: Callable[[bytes], str] | None, digests: Callable[[int, int], list[str]] | None,
           ) -> CataloguePublication:
    """Build, sign and write a catalogue; remember it. See the module docstring.

    `digests(first, last)` returns the hex body digests of records first..last (both
    included); it is needed only when an anchor covers an entry.
    """
    choices = list(choices)
    if not choices:
        raise VaultError("a catalogue needs at least one entry")
    if len(choices) > MAX_ENTRIES:
        raise VaultError(f"at most {MAX_ENTRIES} entries in one catalogue")
    if len({c.entry_id for c in choices}) != len(choices):
        raise VaultError("an entry is listed twice")
    ids = _public_ids(vault)
    ids_changed = False
    entries: list[dict] = []
    published: list[PublishedEntry] = []
    used: dict[int, int] = {}  # index in `anchors` -> index in the catalogue
    for choice in choices:
        meta = vault.entry(choice.entry_id)  # NotFound for a removed or unknown entry
        found = approved_version(vault, choice.entry_id)
        if isinstance(found, str):
            raise VaultError(f"{choice.entry_id}: {found}")
        preview, version = found
        record = records[version.seq]
        if (record.kind, record.entry_id, record.version, record.commitment) != (
                "put", choice.entry_id, version.version, version.commitment):
            raise VaultError(f"{choice.entry_id}: the ledger record does not match the version")
        key = f"{choice.entry_id}:{version.version}"
        public_id = ids.get(key)
        if public_id is None:
            public_id = ids[key] = secrets.token_hex(16)
            ids_changed = True
        entry: dict = {
            "public_id": public_id,
            "media_type": meta.media_type,
            "words": preview.words,
            "summary": preview.summary,
            "keywords": list(preview.keywords),
            "commitment": version.commitment,
            "record": record_to_dict(record),
            "proof": None,
        }
        shown: list[str] = []
        if choice.show_title:
            entry["title"] = meta.title
            shown.append("title")
        if choice.show_path:
            entry["path"] = meta.path
            shown.append("path")
        if choice.show_tags:
            entry["tags"] = list(meta.tags)
            shown.append("tags")
        best = _best_anchor(anchors, record.seq)
        state: State = "none"
        anchored_at = None
        if best is not None and digests is not None:
            index, chosen = best
            if index not in used:
                used[index] = len(used)
            entry["proof"] = {"anchor": used[index],
                              "body_digests": digests(record.seq + 1, chosen.anchor.seq_upto)}
            state, anchored_at = chosen.state, chosen.time
        entries.append(entry)
        published.append(PublishedEntry(public_id=public_id, entry_id=choice.entry_id, version=version.version,
                                        commitment=version.commitment, shown=shown, anchor_state=state,
                                        anchored_at=anchored_at))
    # Sorted by the random public id: the order says nothing about the owner's choice.
    entries.sort(key=lambda e: e["public_id"])
    published.sort(key=lambda p: p.public_id)
    anchor_list = [None] * len(used)
    for index, position in used.items():
        a = anchors[index].anchor
        anchor_list[position] = dict(a.model_dump(mode="json"), file=f"anchors/anchor-{a.seq_upto}.tst")
    catalogue_id = secrets.token_hex(16)
    exported_at = datetime.now(timezone.utc)
    document = {
        "format": CATALOGUE_FORMAT,
        "format_version": CATALOGUE_VERSION,
        "catalogue_id": catalogue_id,
        "public_key": public_key,
        "exported_at": format_time(exported_at),
        "statement": STATEMENT,
        "entries": entries,
        "anchors": anchor_list,
    }
    document["signature"] = sign(SIGNATURE_PREFIX + canonical(document)) if sign is not None else ""
    data = (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8")

    target = Path(out_dir) / f"catalogue-{catalogue_id}"
    target.mkdir(parents=True, exist_ok=False)
    atomic_write(target / "catalogue.json", data)
    for item in anchor_list:
        atomic_write(target / PurePosixPath(item["file"]), base64.b64decode(item["proof"]))
    atomic_write(target / "README.txt", _readme(document).encode("utf-8"))
    verifier = Path(__file__).resolve().parents[2] / "tools" / "verify_bundle.py"
    if verifier.is_file():
        shutil.copyfile(verifier, target / "verify_bundle.py")

    publication = CataloguePublication(catalogue_id=catalogue_id, exported_at=exported_at, path=str(target),
                                       catalogue_hash=hashlib.sha256(data).hexdigest(), entries=published)
    if ids_changed:
        vault.aux_put(IDS_KEY, json.dumps(ids).encode("utf-8"))
    history = publications(vault) + [publication]
    vault.aux_put(PUBLISHED_KEY, json.dumps([p.model_dump(mode="json") for p in history],
                                            ensure_ascii=False).encode("utf-8"))
    return publication


def _best_anchor(anchors: Sequence[AssessedAnchor], seq: int) -> tuple[int, AssessedAnchor] | None:
    """The earliest proven anchor covering seq, else the earliest claimed one."""
    covering = [(i, a) for i, a in enumerate(anchors) if a.anchor.seq_upto >= seq]
    for wanted in ("proven", "claimed"):
        matching = [(i, a) for i, a in covering if a.state == wanted]
        if matching:
            return min(matching, key=lambda item: (item[1].time, item[1].anchor.seq_upto))
    return None


def _readme(document: dict) -> str:
    lines = [
        "Empreinte public catalogue",
        "",
        f"Catalogue {document['catalogue_id']}, vault public key (Ed25519) {document['public_key'] or '(none)'}.",
        f"{len(document['entries'])} entries. No document is included: only approved summaries and proofs.",
        "",
        document["statement"],
        "",
        "Check it (needs Python 3.11+ and the 'cryptography' package):",
        "",
        "    python verify_bundle.py --catalogue .",
        "",
        "Prefer your own copy of verify_bundle.py over the one shipped here, and compare the",
        "public key above with one the author published elsewhere.",
        "",
        "After a license, check that a bundle item is the same document as a catalogue entry:",
        "",
        "    python verify_bundle.py BUNDLE_DIR --catalogue catalogue.json",
        "",
        "What the dates mean, per entry, as verify_bundle.py reports them:",
        "  NOT YET PROVABLE  no outside timestamp covers the entry: its ledger time is the author's",
        "                    clock only;",
        "  CLAIMED ONLY      a valid timestamp token covers it, but its authority could not be",
        "                    authenticated: anyone could have made it;",
        "  PROVEN FROM       the token's signer has a valid certificate path to a trusted root at the",
        "                    asserted time: the document existed by then (revocation is not checked).",
        "",
    ]
    for anchor in document["anchors"]:
        lines += [f"Anchor of record {anchor['seq_upto']}, asserted {anchor['anchored_at']} by a token naming "
                  f"{anchor['authority']}:",
                  f"    openssl ts -verify -digest {anchor['head_hash']} -token_in -in {anchor['file']} "
                  "-CAfile ROOT.pem [-untrusted INTERMEDIATE.pem]", ""]
    return "\n".join(lines)
