"""InMemoryVault: a VaultAPI without cryptography, for tests of the other layers.

It keeps the observable behaviour of the real vault (versions, idempotent put, hash
chain shape, removal, licensing bookkeeping) so that the importer, the workspace and
the server can be built and tested before the encrypted vault exists. Nothing here is
secure and nothing is written to disk, except export_bundle.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Literal, Sequence

from .api import NotFound, VaultError
from .model import (
    Anchor,
    EntryKind,
    EntryMeta,
    LedgerRecord,
    LicenseGrant,
    LicenseItem,
    ProvenanceProof,
    RoyaltyEvent,
    RoyaltyTerms,
    VerifyReport,
    Version,
)

ZERO_HASH = "0" * 64


def stepping_clock(start: datetime | None = None, step: timedelta = timedelta(minutes=1)) -> Callable[[], datetime]:
    """A deterministic clock: each call returns `step` later than the previous one."""
    current = start or datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)

    def now() -> datetime:
        nonlocal current
        value = current
        current = current + step
        return value

    return now


def record_hash(fields: dict) -> str:
    """Hash of a record's fields (everything except record_hash and signature)."""
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class InMemoryVault:
    def __init__(self, clock: Callable[[], datetime] | None = None):
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._meta: dict[str, EntryMeta] = {}
        self._by_path: dict[str, str] = {}
        self._versions: dict[str, list[Version]] = {}
        self._content: dict[tuple[str, int], bytes] = {}
        self._ledger: list[LedgerRecord] = []
        self._licenses: list[LicenseGrant] = []
        self._royalties: list[RoyaltyEvent] = []
        self._aux: dict[str, bytes] = {}
        self._locked = False

    # ---------------------------------------------------------------- internals
    def _check(self) -> None:
        if self._locked:
            raise VaultError("vault is locked")

    def _append(self, kind: str, *, entry_id: str = "", version: int = 0, commitment: str = "",
                cipher_hash: str = "", size: int = 0) -> LedgerRecord:
        fields = {
            "seq": len(self._ledger),
            "kind": kind,
            "entry_id": entry_id,
            "version": version,
            "commitment": commitment,
            "cipher_hash": cipher_hash,
            "size": size,
            "timestamp": self._clock().isoformat(),
            "prev_hash": self._ledger[-1].record_hash if self._ledger else ZERO_HASH,
        }
        record = LedgerRecord(**fields, record_hash=record_hash(fields))
        self._ledger.append(record)
        return record

    # ------------------------------------------------------------------ entries
    def put(self, path: str, content: bytes, *, title: str | None = None, kind: EntryKind = "note",
            tags: Sequence[str] = (), media_type: str = "text/markdown",
            source_mtime: datetime | None = None) -> Version:
        self._check()
        path = path.replace("\\", "/").strip("/")
        entry_id = self._by_path.get(path)
        if entry_id is not None:
            latest = self._versions[entry_id][-1]
            if self._content[(entry_id, latest.version)] == content:
                return latest
        else:
            entry_id = secrets.token_hex(16)
        number = len(self._versions.get(entry_id, [])) + 1
        commitment = hashlib.sha256(b"salt:" + entry_id.encode() + content).hexdigest()
        record = self._append("put", entry_id=entry_id, version=number, commitment=commitment,
                              cipher_hash=hashlib.sha256(content).hexdigest(), size=len(content))
        version = Version(entry_id=entry_id, version=number, seq=record.seq, timestamp=record.timestamp,
                          size=len(content), commitment=commitment, source_mtime=source_mtime)
        self._versions.setdefault(entry_id, []).append(version)
        self._content[(entry_id, number)] = content
        self._by_path[path] = entry_id
        claimed = [v.source_mtime for v in self._versions[entry_id] if v.source_mtime is not None]
        previous = self._meta.get(entry_id)
        self._meta[entry_id] = EntryMeta(
            entry_id=entry_id,
            path=path,
            title=title or (previous.title if previous else Path(path).stem),
            kind=kind,
            media_type=media_type,
            tags=sorted(set(tags)),
            n_versions=number,
            size=len(content),
            created_at=previous.created_at if previous else record.timestamp,
            updated_at=record.timestamp,
            authored_at=min(claimed) if claimed else None,
            modified_at=max(claimed) if claimed else None,
        )
        return version

    def entries(self) -> list[EntryMeta]:
        self._check()
        return sorted(self._meta.values(), key=lambda m: m.path)

    def entry(self, entry_id: str) -> EntryMeta:
        self._check()
        try:
            return self._meta[entry_id]
        except KeyError:
            raise NotFound(entry_id) from None

    def find(self, path: str) -> EntryMeta | None:
        self._check()
        entry_id = self._by_path.get(path.replace("\\", "/").strip("/"))
        return self._meta.get(entry_id) if entry_id else None

    def read(self, entry_id: str, version: int | None = None) -> bytes:
        self._check()
        versions = self._versions.get(entry_id)
        if not versions:
            raise NotFound(entry_id)
        number = versions[-1].version if version is None else version
        try:
            return self._content[(entry_id, number)]
        except KeyError:
            raise NotFound(f"{entry_id} v{number}") from None

    def versions(self, entry_id: str) -> list[Version]:
        self._check()
        if entry_id not in self._versions:
            raise NotFound(entry_id)
        return list(self._versions[entry_id])

    def remove(self, entry_id: str) -> None:
        meta = self.entry(entry_id)
        self._append("remove", entry_id=entry_id, version=meta.n_versions)
        del self._meta[entry_id]
        del self._by_path[meta.path]

    # ------------------------------------------------------------------- ledger
    def ledger(self) -> list[LedgerRecord]:
        self._check()
        return list(self._ledger)

    def verify(self) -> VerifyReport:
        self._check()
        errors = []
        previous = ZERO_HASH
        for i, record in enumerate(self._ledger):
            fields = record.model_dump(mode="json", exclude={"record_hash", "signature"})
            fields["timestamp"] = record.timestamp.isoformat()
            if record.seq != i:
                errors.append(f"record {i}: wrong seq {record.seq}")
            if record.prev_hash != previous:
                errors.append(f"record {i}: broken chain")
            if record_hash(fields) != record.record_hash:
                errors.append(f"record {i}: hash mismatch")
            previous = record.record_hash
        return VerifyReport(ok=not errors, n_records=len(self._ledger), head_hash=previous, errors=errors)

    def proof(self, entry_id: str, version: int | None = None) -> ProvenanceProof:
        versions = self.versions(entry_id)
        chosen = versions[-1] if version is None else next((v for v in versions if v.version == version), None)
        if chosen is None:
            raise NotFound(f"{entry_id} v{version}")
        record = self._ledger[chosen.seq]
        return ProvenanceProof(
            record=record,
            public_key="",
            head_hash=self._ledger[-1].record_hash,
            n_following=len(self._ledger) - 1 - record.seq,
            verified=self.verify().ok,
        )

    def anchors(self) -> list[Anchor]:
        self._check()
        return []

    def anchor_methods(self) -> list[str]:
        return []

    def anchor(self, method: Literal["rfc3161", "opentimestamps"] = "rfc3161") -> Anchor:
        raise VaultError("InMemoryVault never calls the network")

    # ---------------------------------------------------------------- licensing
    def grant(self, licensee: str, items: Sequence[tuple[str, int | None]], *, usage: str, terms: str = "",
              royalty: RoyaltyTerms | None = None, valid_until: date | None = None) -> LicenseGrant:
        self._check()
        if not items:
            raise VaultError("a license needs at least one item")
        licensed = []
        for entry_id, number in items:
            meta = self.entry(entry_id)
            versions = self._versions[entry_id]
            chosen = versions[-1] if number is None else next((v for v in versions if v.version == number), None)
            if chosen is None:
                raise NotFound(f"{entry_id} v{number}")
            licensed.append(LicenseItem(entry_id=entry_id, version=chosen.version, title=meta.title,
                                        commitment=chosen.commitment))
        record = self._append("license")
        grant = LicenseGrant(license_id=secrets.token_hex(8), licensee=licensee, items=licensed, usage=usage,
                             terms=terms, royalty=royalty or RoyaltyTerms(), created_at=record.timestamp,
                             valid_until=valid_until, seq=record.seq)
        self._licenses.append(grant)
        return grant

    def _license(self, license_id: str) -> LicenseGrant:
        for grant in self._licenses:
            if grant.license_id == license_id:
                return grant
        raise NotFound(license_id)

    def export_bundle(self, license_id: str, out_dir: Path) -> Path:
        self._check()
        grant = self._license(license_id)
        bundle = Path(out_dir) / f"license-{license_id}"
        (bundle / "items").mkdir(parents=True, exist_ok=True)
        for item in grant.items:
            (bundle / "items" / f"{item.entry_id}-v{item.version}").write_bytes(self._content[(item.entry_id, item.version)])
        manifest = grant.model_dump_json(indent=2)
        (bundle / "license.json").write_text(manifest, encoding="utf-8", newline="\n")
        grant.bundle_hash = hashlib.sha256(manifest.encode("utf-8")).hexdigest()
        return bundle

    def licenses(self) -> list[LicenseGrant]:
        self._check()
        return list(self._licenses)

    def record_royalty(self, license_id: str, amount: float, *, currency: str = "EUR",
                       received_on: date | None = None, period: str = "", note: str = "") -> RoyaltyEvent:
        self._license(license_id)
        record = self._append("royalty")
        event = RoyaltyEvent(license_id=license_id, received_on=received_on or record.timestamp.date(),
                             amount=amount, currency=currency, period=period, note=note, seq=record.seq)
        self._royalties.append(event)
        return event

    def royalties(self, license_id: str | None = None) -> list[RoyaltyEvent]:
        self._check()
        return [e for e in self._royalties if license_id is None or e.license_id == license_id]

    # ---------------------------------------------------- encrypted side storage
    def aux_get(self, key: str) -> bytes | None:
        self._check()
        return self._aux.get(key)

    def aux_put(self, key: str, value: bytes) -> None:
        self._check()
        self._aux[key] = value

    def lock(self) -> None:
        self._locked = True
