"""The encrypted vault: VaultAPI on a plain directory. Format in docs/FORMAT.md.

Write order of one put(), chosen so that open() can recover from a crash between any
two steps without losing or inventing a record:

    1. blob    blobs/xx/<cipher_hash>        atomic (temp, fsync, replace)
    2. ledger  ledger.jsonl                   one line appended, fsync
    3. catalog catalog.bin                    atomic (temp, fsync, replace)

Crash after 1: an orphan blob, no record; nothing is lost because put() never returned.
Crash after 2: the ledger has records the catalog lacks. Every blob is self-describing
(it holds the encrypted path, title, tags and salt), so open() replays those records
from their blobs after checking their chain and signature.
A torn last ledger line (crash inside 2) is completed or cut off by Ledger.load().
"""
from __future__ import annotations

import functools
import json
import secrets
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Callable, Iterator, Literal, Sequence

from cryptography import x509
from cryptography.exceptions import InvalidTag

from . import crypto
from .anchor import DEFAULT_TSA_URL, MAX_PROOF_CHARS, TokenAssessment, Transport, assess_anchor, request_anchor
from .api import Corrupted, NotFound, VaultError, WrongPassphrase
from .crypto import KdfParams
from .ledger import (
    ZERO_HASH,
    Ledger,
    chain_digests,
    check_chain,
    compute_record_hash,
    format_time,
    make_record,
    parse_time,
)
from .model import (
    Anchor,
    AnchorStatus,
    CatalogueChoice,
    CataloguePublication,
    Coverage,
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
from .store import BlobStore, WriterLock, append_bytes, atomic_write, atomic_write_text, read_bytes

HEADER = "header.json"
LEDGER = "ledger.jsonl"
CATALOG = "catalog.bin"
ANCHORS = "anchors.jsonl"
WRITER_LOCK = "writer.lock"
MAX_HEADER_BYTES = 64 << 10
MAX_ANCHORS_BYTES = 16 << 20
BLOBS = "blobs"
AUX = "aux"
VAULT_FORMAT = "empreinte-vault"


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return parse_time(format_time(value))


def _time_or_none(text: str | None) -> datetime | None:
    return parse_time(text) if text else None


@dataclass
class _VersionState:
    version: int
    seq: int
    timestamp: datetime
    size: int
    commitment: str
    salt: str
    cipher_hash: str
    source_mtime: datetime | None = None

    def to_dict(self) -> dict:
        return {"version": self.version, "seq": self.seq, "timestamp": format_time(self.timestamp), "size": self.size,
                "commitment": self.commitment, "salt": self.salt, "cipher_hash": self.cipher_hash,
                "source_mtime": format_time(self.source_mtime) if self.source_mtime else None}

    @classmethod
    def from_dict(cls, d: dict) -> "_VersionState":
        return cls(version=d["version"], seq=d["seq"], timestamp=parse_time(d["timestamp"]), size=d["size"],
                   commitment=d["commitment"], salt=d["salt"], cipher_hash=d["cipher_hash"],
                   source_mtime=_time_or_none(d.get("source_mtime")))


@dataclass
class _EntryState:
    entry_id: str
    path: str
    title: str
    kind: str
    media_type: str
    tags: list[str]
    removed: bool = False
    versions: list[_VersionState] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"entry_id": self.entry_id, "path": self.path, "title": self.title, "kind": self.kind,
                "media_type": self.media_type, "tags": self.tags, "removed": self.removed,
                "versions": [v.to_dict() for v in self.versions]}

    @classmethod
    def from_dict(cls, d: dict) -> "_EntryState":
        return cls(entry_id=d["entry_id"], path=d["path"], title=d["title"], kind=d["kind"],
                   media_type=d["media_type"], tags=list(d["tags"]), removed=d["removed"],
                   versions=[_VersionState.from_dict(v) for v in d["versions"]])


@dataclass
class _Committed:
    """A license grant or royalty event: exact committed bytes, their salt and blob."""

    seq: int
    committed: str  # UTF-8 JSON text whose bytes are committed in the ledger
    salt: str
    cipher_hash: str
    bundle_hash: str = ""

    def to_dict(self) -> dict:
        return {"seq": self.seq, "committed": self.committed, "salt": self.salt, "cipher_hash": self.cipher_hash,
                "bundle_hash": self.bundle_hash}

    @classmethod
    def from_dict(cls, d: dict) -> "_Committed":
        return cls(seq=d["seq"], committed=d["committed"], salt=d["salt"], cipher_hash=d["cipher_hash"],
                   bundle_hash=d.get("bundle_hash", ""))


def canonical_json(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _locked(method):
    """Serialize public calls (the HTTP server may call from several threads) and refuse when locked."""
    @functools.wraps(method)
    def wrapper(self: "Vault", *args, **kwargs):
        with self._lock:
            if self._keys is None:
                raise VaultError("vault is locked")
            return method(self, *args, **kwargs)
    return wrapper


class Vault:
    """An unlocked vault. Build it with Vault.create, Vault.open or Vault.open_with_recovery_key."""

    def __init__(self, path: Path, header: dict, master_key: bytes, *, clock: Callable[[], datetime] | None,
                 via_recovery: bool, tsa_url: str | None = None, transport: Transport | None = None):
        self.path = Path(path)
        self._lock = threading.RLock()
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._header = header
        self._vault_id = bytes.fromhex(header["vault_id"])
        self._via_recovery = via_recovery
        self.tsa_url = tsa_url or DEFAULT_TSA_URL
        self.transport = transport  # None: real HTTP, used only by an explicit anchor() call
        # None: the public roots of the installed certifi; a list overrides them.
        self.trust_roots: list[x509.Certificate] | None = None
        # anchor() refuses a token whose authority cannot be authenticated, unless this is False.
        self.require_trusted_anchor = True
        self.recovery_key: str | None = None
        self._blobs = BlobStore(self.path / BLOBS)
        self._ledger = Ledger(self.path / LEDGER)
        self._batch_depth = 0
        self._pending_blobs: list[Path] = []
        self._pending_dirs: set[Path] = set()
        self._pending_records: list[LedgerRecord] = []
        self._catalog_dirty = False
        self._problems: list[str] = []  # integrity failures: the vault is read-only while any is listed
        self._readonly: str | None = None  # another reason not to write (lock held elsewhere, uncertain append)
        self.notices: list[str] = []  # repairs done at open (not integrity failures)
        self._writer = WriterLock(self.path / WRITER_LOCK)
        held_elsewhere = self._writer.acquire()
        self.held_by_another_writer = bool(held_elsewhere)  # read-only because another writer has the lock
        if held_elsewhere:
            self._readonly = held_elsewhere
            self.notices.append(held_elsewhere)
        try:
            self._unlock(master_key)
        except BaseException:
            self._writer.release()
            raise

    # ================================================================ construction

    @classmethod
    def create(cls, path: Path, passphrase: str, *, clock: Callable[[], datetime] | None = None,
               kdf_params: KdfParams | None = None, tsa_url: str | None = None,
               transport: Transport | None = None) -> "Vault":
        """Create a new vault directory and return it unlocked.

        The one-time recovery key is in `vault.recovery_key` (also returned by
        take_recovery_key()); it is never stored and cannot be shown again.
        """
        path = Path(path)
        crypto.normalize_passphrase(passphrase)
        if path.exists() and any(path.iterdir()):
            raise VaultError("target directory is not empty")
        params = kdf_params or crypto.DEFAULT_KDF
        params.validate()
        vault_id = crypto.random_bytes(16)
        master = crypto.random_bytes(crypto.KEY_LEN)
        recovery = crypto.random_bytes(crypto.KEY_LEN)
        identity = crypto.new_identity()
        keys = crypto.derive_subkeys(master, vault_id)
        header = {"format": VAULT_FORMAT, "format_version": crypto.FORMAT_VERSION, "vault_id": vault_id.hex(),
                  "public_key": crypto.public_hex(identity)}
        header["kdf"], header["master_key_wraps"] = {}, {}
        _set_passphrase(header, master, passphrase, params)
        header["master_key_wraps"]["recovery"] = crypto.wrap(
            crypto.recovery_kek(recovery, vault_id), master, crypto.wrap_aad("recovery", vault_id))
        header["identity"] = crypto.wrap(keys.identity, crypto.private_raw(identity),
                                         crypto.wrap_aad("identity", vault_id))
        path.mkdir(parents=True, exist_ok=True)
        (path / BLOBS).mkdir(exist_ok=True)
        (path / AUX).mkdir(exist_ok=True)
        (path / LEDGER).touch()
        (path / ANCHORS).touch()
        # The catalog first, the header last: a directory without header.json is not a vault yet.
        catalog = {"format_version": crypto.FORMAT_VERSION, "n_records": 0, "head_hash": ZERO_HASH,
                   "public_key": header["public_key"], "entries": [], "licenses": [], "royalties": [],
                   "n_anchors": 0}
        blob = crypto.seal_blob(keys.metadata, crypto.BLOB_CATALOG, canonical_json(catalog).encode("utf-8"),
                                crypto.blob_binding(vault_id, "catalog"))
        atomic_write(path / CATALOG, blob)
        atomic_write_text(path / HEADER, json.dumps(header, indent=2, sort_keys=True) + "\n")
        vault = cls(path, header, master, clock=clock, via_recovery=False, tsa_url=tsa_url, transport=transport)
        vault.recovery_key = crypto.encode_recovery_key(recovery)
        return vault

    @classmethod
    def open(cls, path: Path, passphrase: str, *, clock: Callable[[], datetime] | None = None,
             tsa_url: str | None = None, transport: Transport | None = None) -> "Vault":
        """Raises WrongPassphrase, or Corrupted when the header or catalog is unreadable.

        The vault is opened for writing when no other process or open Vault object holds
        its writer lock; otherwise it opens read-only, says so in `notices`, and can never
        write. To replace a session in the same process, close() the old one first.
        """
        header = _read_header(Path(path))
        vault_id = bytes.fromhex(header["vault_id"])
        params = KdfParams.from_dict(header["kdf"])  # range-checked before any derivation
        try:
            salt = bytes.fromhex(header["kdf"]["salt"])
            kek = crypto.derive_passphrase_key(passphrase, salt, params)
            master = crypto.unwrap(kek, header["master_key_wraps"]["passphrase"],
                                   crypto.wrap_aad("passphrase", vault_id, _kdf_aad(header["kdf"])))
        except InvalidTag:
            raise WrongPassphrase("wrong passphrase") from None
        except (KeyError, ValueError, TypeError):
            raise Corrupted("header: malformed passphrase wrap") from None
        return cls(path, header, master, clock=clock, via_recovery=False, tsa_url=tsa_url, transport=transport)

    @classmethod
    def open_with_recovery_key(cls, path: Path, recovery_key: str, *, clock: Callable[[], datetime] | None = None,
                               tsa_url: str | None = None, transport: Transport | None = None) -> "Vault":
        """Unlock with the recovery key; then change_passphrase(None, new) sets a new passphrase."""
        header = _read_header(Path(path))
        vault_id = bytes.fromhex(header["vault_id"])
        raw = crypto.decode_recovery_key(recovery_key)
        try:
            master = crypto.unwrap(crypto.recovery_kek(raw, vault_id), header["master_key_wraps"]["recovery"],
                                   crypto.wrap_aad("recovery", vault_id))
        except InvalidTag:
            raise WrongPassphrase("recovery key does not open this vault") from None
        except (KeyError, ValueError, TypeError):
            raise Corrupted("header: malformed recovery wrap") from None
        return cls(path, header, master, clock=clock, via_recovery=True, tsa_url=tsa_url, transport=transport)

    def take_recovery_key(self) -> str | None:
        """Return the recovery key shown once after create() or rotate_recovery_key(), then forget it."""
        key, self.recovery_key = self.recovery_key, None
        return key

    @_locked
    def change_passphrase(self, old: str | None, new: str, *, kdf_params: KdfParams | None = None) -> None:
        """Rewrap the master key under `new`. Nothing is re-encrypted.

        `old` may be None only when the vault was opened with the recovery key.
        The KDF parameters stay as they are unless `kdf_params` is given.
        """
        crypto.normalize_passphrase(new)
        self._require_writer()
        header = json.loads(json.dumps(self._header))
        if old is None:
            if not self._via_recovery:
                raise WrongPassphrase("the current passphrase is required")
        else:
            try:
                kek = crypto.derive_passphrase_key(old, bytes.fromhex(header["kdf"]["salt"]),
                                                   KdfParams.from_dict(header["kdf"]))
                crypto.unwrap(kek, header["master_key_wraps"]["passphrase"],
                              crypto.wrap_aad("passphrase", self._vault_id, _kdf_aad(header["kdf"])))
            except InvalidTag:
                raise WrongPassphrase("wrong passphrase") from None
        params = kdf_params or KdfParams.from_dict(header["kdf"])
        params.validate()
        _set_passphrase(header, self._master, new, params)
        atomic_write_text(self.path / HEADER, json.dumps(header, indent=2, sort_keys=True) + "\n")
        self._header = header

    @_locked
    def rotate_recovery_key(self) -> str:
        """Replace the recovery wrap; the old recovery key stops working. Returns the new key once."""
        self._require_writer()
        recovery = crypto.random_bytes(crypto.KEY_LEN)
        header = json.loads(json.dumps(self._header))
        header["master_key_wraps"]["recovery"] = crypto.wrap(
            crypto.recovery_kek(recovery, self._vault_id), self._master, crypto.wrap_aad("recovery", self._vault_id))
        atomic_write_text(self.path / HEADER, json.dumps(header, indent=2, sort_keys=True) + "\n")
        self._header = header
        return crypto.encode_recovery_key(recovery)

    # ================================================================ unlock / lock

    def _unlock(self, master: bytes) -> None:
        self._master = master
        self._keys = crypto.derive_subkeys(master, self._vault_id)
        try:
            raw = crypto.unwrap(self._keys.identity, self._header["identity"],
                                crypto.wrap_aad("identity", self._vault_id))
        except (InvalidTag, KeyError):
            self._drop_keys()
            raise Corrupted("header: identity key cannot be decrypted") from None
        self._signer = crypto.identity_from_raw(raw)
        self._public = self._signer.public_key()
        self._public_hex = crypto.public_hex(self._public)
        self._reset_state()
        writer = self._writer.held()
        self._ledger.load(repair_tail=writer)  # only the writer may repair the file
        if self._ledger.repaired_tail:
            self.notices.append("torn last ledger line repaired (crash during an append)")
        self._load_catalog()
        self._load_anchors()
        self._recover()
        self._check_at_open()

    def _check_at_open(self) -> None:
        """Everything that can be checked without reading every blob: the whole chain and
        its signatures, unreadable lines, the header key, the catalog against the ledger,
        and where anchors point. Any problem makes the vault read-only."""
        records = self._ledger.records
        problems = list(self._ledger.problems)
        if self._ledger.torn_tail:
            problems.append("ledger: incomplete last line (a crash during an append, not repaired)")
        if self._header.get("public_key") != self._public_hex:
            problems.append("header: public key does not match the vault identity key")
        problems += check_chain(records, self._public, self._public_hex)[0]
        if not any(p.startswith(("rollback", "catalog head", "ledger records after", "record ")) for p in self._problems):
            problems += self._check_catalog(records)
        problems += self._anchor_positions(self._anchors, records)
        if self._catalog_anchors > len(self._anchors):
            problems.append(f"anchors: the catalog knows {self._catalog_anchors}, "
                            f"anchors.jsonl has {len(self._anchors)}")
        for index, anchor in enumerate(self._anchors):
            problems += [f"anchor {index}: {e}" for e in assess_anchor(anchor, self.trust_roots).errors]
        self._add_problems(problems)

    def _add_problems(self, problems: list[str]) -> None:
        for problem in problems:
            if problem not in self._problems:
                self._problems.append(problem)

    @staticmethod
    def _anchor_positions(anchors: list[Anchor], records: list[LedgerRecord]) -> list[str]:
        return [f"anchor {i}: head hash is not record {a.seq_upto} of this ledger" for i, a in enumerate(anchors)
                if not 0 <= a.seq_upto < len(records) or records[a.seq_upto].record_hash != a.head_hash]

    def _drop_keys(self) -> None:
        # Python cannot wipe immutable bytes; dropping every reference is the best available.
        self._master = None
        self._keys = None
        self._signer = None

    def _reset_state(self) -> None:
        self._entries: dict[str, _EntryState] = {}
        self._by_path: dict[str, str] = {}
        self._licenses: dict[str, _Committed] = {}
        self._license_order: list[str] = []
        self._royalties: list[_Committed] = []
        self._anchors: list[Anchor] = []
        self._catalog_n = 0
        self._catalog_head = ZERO_HASH
        self._catalog_anchors = 0
        self._meta_cache: dict[str, EntryMeta] = {}
        self._sorted_cache: list[EntryMeta] | None = None

    def lock(self) -> None:
        """Forget the keys and every decrypted value. Later calls raise VaultError."""
        with self._lock:
            try:
                if self._keys is not None and self._can_write() and (
                        self._pending_records or self._pending_blobs or self._catalog_dirty):
                    self._flush()  # lock() inside a batch must not lose the puts that already returned
            finally:
                # Always, even when saving failed: the error is re-raised after the secrets are gone.
                self._drop_keys()
                self.recovery_key = None
                self._reset_state()
                self._ledger.records = []
                self._pending_records, self._pending_blobs, self._pending_dirs = [], [], set()
                self._writer.release()

    def close(self) -> None:
        """End this session: save what is pending, forget the keys, release the writer lock.

        Same as lock(). A server replacing a session must close() the old Vault before
        opening the new one, or the new one is read-only (the lock is still held).
        """
        self.lock()

    @property
    def locked(self) -> bool:
        return self._keys is None

    @property
    def public_key(self) -> str:
        return self._public_hex

    @property
    def vault_id(self) -> str:
        return self._vault_id.hex()

    # ================================================================ catalog

    def _catalog_dict(self) -> dict:
        return {
            "format_version": crypto.FORMAT_VERSION,
            "n_records": len(self._ledger.records),
            "head_hash": self._ledger.head_hash,
            "public_key": self._public_hex,
            "entries": [e.to_dict() for e in self._entries.values()],
            "licenses": [self._licenses[i].to_dict() for i in self._license_order],
            "royalties": [r.to_dict() for r in self._royalties],
            "n_anchors": len(self._anchors),
        }

    def _write_catalog(self) -> None:
        if self._readonly is not None or not self._writer.held():
            raise VaultError("read-only: catalog.bin is written only by the writer")
        data = canonical_json(self._catalog_dict()).encode("utf-8")
        blob = crypto.seal_blob(self._keys.metadata, crypto.BLOB_CATALOG, data,
                                crypto.blob_binding(self._vault_id, "catalog"))
        atomic_write(self.path / CATALOG, blob)
        self._catalog_dirty = False

    def _save_catalog(self) -> None:
        self._catalog_dirty = True
        if self._batch_depth == 0 and self._can_write():  # only the writer touches catalog.bin
            self._write_catalog()

    def _load_catalog(self) -> None:
        catalog_path = self.path / CATALOG
        if not catalog_path.exists():
            # Lost catalog: rebuild everything from the ledger and the self-describing blobs.
            self.notices.append("catalog.bin was missing and has been rebuilt from the ledger")
            return
        data = crypto.open_blob(self._keys.metadata, read_bytes(catalog_path),
                                crypto.blob_binding(self._vault_id, "catalog"), crypto.BLOB_CATALOG, "catalog")
        try:
            catalog = json.loads(data)
        except ValueError:
            raise Corrupted("catalog: decrypted but malformed") from None
        if not isinstance(catalog, dict) or catalog.get("format_version") != crypto.FORMAT_VERSION:
            version = catalog.get("format_version") if isinstance(catalog, dict) else None
            raise VaultError(f"catalog format version {version!r} is not supported by this reader")
        try:
            for item in catalog["entries"]:
                entry = _EntryState.from_dict(item)
                self._entries[entry.entry_id] = entry
                if not entry.removed:
                    self._by_path[entry.path] = entry.entry_id
            for item in catalog["licenses"]:
                state = _Committed.from_dict(item)
                grant = LicenseGrant.model_validate_json(state.committed)
                self._licenses[grant.license_id] = state
                self._license_order.append(grant.license_id)
            self._royalties = [_Committed.from_dict(item) for item in catalog["royalties"]]
            self._catalog_n = catalog["n_records"]
            self._catalog_head = catalog["head_hash"]
            self._catalog_anchors = catalog["n_anchors"]
            if catalog["public_key"] != self._public_hex:
                self._problems.append("catalog: identity key differs from the vault key")
        except (KeyError, TypeError, ValueError):
            raise Corrupted("catalog: decrypted but malformed") from None

    def _load_anchors(self) -> None:
        self._anchors, problems = self._read_anchors()
        self._add_problems(problems)

    def _read_anchors(self) -> tuple[list[Anchor], list[str]]:
        anchors_path = self.path / ANCHORS
        anchors: list[Anchor] = []
        problems: list[str] = []
        if not anchors_path.exists():
            return anchors, ["anchors.jsonl is missing"] if self._catalog_anchors else []
        if anchors_path.stat().st_size > MAX_ANCHORS_BYTES:
            return anchors, [f"anchors.jsonl is larger than {MAX_ANCHORS_BYTES} bytes; not read"]
        for number, line in enumerate(read_bytes(anchors_path).splitlines()):
            if not line.strip():
                continue
            try:
                anchors.append(Anchor.model_validate_json(line))
            except ValueError:
                problems.append(f"anchors line {number + 1}: unreadable")
        return anchors, problems

    def _recover(self) -> None:
        """Bring the catalog up to the ledger after a crash, or flag a rollback."""
        records = self._ledger.records
        n = self._catalog_n
        if len(records) < n:
            self._problems.append(
                f"rollback: the catalog recorded {n} records ending in {self._catalog_head[:16]}, "
                f"the ledger has only {len(records)}")
            return
        if n and records[n - 1].record_hash != self._catalog_head:
            self._problems.append(f"catalog head hash does not match ledger record {n - 1}")
            return
        if len(records) == n:
            return
        errors, _ = check_chain(records, self._public, self._public_hex, start=n)
        if errors:
            self._problems.append("ledger records after the catalog do not verify; not replayed: " + errors[0])
            return
        for record in records[n:]:
            try:
                self._replay(record)
            except (Corrupted, KeyError, ValueError, OSError) as exc:
                self._problems.append(f"record {record.seq}: cannot be replayed ({_short(exc)})")
                return
        if self._writer.held():
            self._write_catalog()
        else:
            self._catalog_dirty = True  # replayed in memory only: this object is not the writer

    def _replay(self, record: LedgerRecord) -> None:
        if record.kind == "put":
            payload = self._read_blob(record.cipher_hash, self._keys.content, crypto.BLOB_CONTENT,
                                      f"content:{record.entry_id}:{record.version}")
            meta_raw, body = crypto.unpack_payload(payload)
            meta = json.loads(meta_raw)
            if crypto.commitment(bytes.fromhex(meta["salt"]), body) != record.commitment or len(body) != record.size:
                raise Corrupted("blob does not match the commitment")
            self._apply_put(record, meta)
        elif record.kind == "remove":
            self._apply_remove(record.entry_id)
        else:
            blob_type = crypto.BLOB_GRANT if record.kind == "license" else crypto.BLOB_ROYALTY
            payload = self._read_blob(record.cipher_hash, self._keys.license, blob_type, f"{record.kind}:{record.seq}")
            meta_raw, body = crypto.unpack_payload(payload)
            salt = json.loads(meta_raw)["salt"]
            if crypto.commitment(bytes.fromhex(salt), body) != record.commitment:
                raise Corrupted("blob does not match the commitment")
            state = _Committed(seq=record.seq, committed=body.decode("utf-8"), salt=salt,
                               cipher_hash=record.cipher_hash)
            if record.kind == "license":
                grant = LicenseGrant.model_validate_json(state.committed)
                self._licenses[grant.license_id] = state
                self._license_order.append(grant.license_id)
            else:
                self._royalties.append(state)

    def _read_blob(self, cipher_hash: str, key: bytes, blob_type: int, label: str) -> bytes:
        data = self._blobs.read(cipher_hash)
        if crypto.sha256(data).hex() != cipher_hash:
            raise Corrupted("blob does not match its cipher_hash")
        return crypto.open_blob(key, data, crypto.blob_binding(self._vault_id, label), blob_type, label)

    # ================================================================ write path

    def _can_write(self) -> bool:
        return not self._problems and self._readonly is None and self._writer.held()

    def _require_writer(self) -> None:
        if self._readonly is not None:
            raise VaultError(f"read-only: {self._readonly}")
        if not self._writer.held():
            self._readonly = "the writer lock was lost (another process took it over); reopen the vault"
            raise VaultError(f"read-only: {self._readonly}")

    def _require_writable(self) -> None:
        """Refuse ledger writes on a vault with an integrity problem or without the writer lock."""
        if self._problems:
            raise Corrupted(f"read-only: integrity problem ({self._problems[0]}); see verify()")
        self._require_writer()

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise VaultError("clock must return a timezone-aware datetime")
        return parse_time(format_time(value))

    def _new_record(self, kind: str, **fields) -> LedgerRecord:
        return make_record(seq=len(self._ledger.records), kind=kind, prev_hash=self._ledger.head_hash,
                           timestamp=fields.pop("timestamp", None) or self._now(), signer=self._signer,
                           public_key_hex=self._public_hex, **fields)

    def _store_blob(self, cipher_hash: str, data: bytes) -> None:
        durable = self._batch_depth == 0
        target, dirs = self._blobs.write(cipher_hash, data, durable=durable)
        if not durable:
            self._pending_blobs.append(target)
            self._pending_dirs.update(dirs)

    def _append_records(self, records: list[LedgerRecord]) -> None:
        if self._batch_depth:
            self._pending_records.extend(records)
        else:
            self._append_ledger(records)

    def _append_ledger(self, records: list[LedgerRecord]) -> None:
        """The only path to the ledger file: re-check ownership and the head on disk first."""
        self._require_writer()
        mismatch = self._ledger.disk_mismatch(records[0].prev_hash)
        if mismatch:
            self._add_problems([mismatch])
            raise Corrupted(f"read-only: {mismatch}")
        try:
            self._ledger.append(records)
        except BaseException:
            # Some or all bytes may be on disk: never retry blindly, never reuse these seqs.
            self._readonly = "a ledger append failed with an uncertain outcome; reopen the vault to reconcile"
            raise

    def _commit(self, record: LedgerRecord, blob: tuple[str, bytes] | None) -> None:
        """Blob, then ledger, then catalog (see the module docstring)."""
        if blob is not None:
            self._store_blob(*blob)
        self._append_records([record])
        self._ledger.records.append(record)

    @contextmanager
    def batch(self) -> Iterator["Vault"]:
        """Many put() calls, one durable flush at the end.

        Inside the batch, blobs are written without fsync and records are held in
        memory; on exit (also after an exception: it is not a rollback) the blobs and their
        directories are fsynced, then the records appended in one write, then the catalog
        written once. Crash semantics are prefix-commit: a crash before the append loses
        the batch; a crash during it keeps the records whose lines are complete, in order.
        """
        with self._lock:
            if self._keys is None:
                raise VaultError("vault is locked")
            self._batch_depth += 1
            try:
                yield self
            finally:
                self._batch_depth -= 1
                if self._batch_depth == 0 and self._keys is not None:
                    self._flush()

    def _flush(self) -> None:
        """End of a batch: blobs and their directories durable, then the records, then the catalog.

        The pending lists are cleared only after success. A failure leaves the object
        read-only: memory then holds records that may not be on disk.
        """
        try:
            if self._pending_blobs:
                self._blobs.sync(self._pending_blobs, self._pending_dirs)
        except BaseException:
            self._readonly = "batch blobs could not be made durable; nothing was recorded; reopen the vault"
            raise
        if self._pending_records:
            try:
                self._append_ledger(self._pending_records)
            except BaseException:
                if self._readonly is None:
                    self._readonly = "the batch could not be recorded; reopen the vault"
                raise
        self._pending_records, self._pending_blobs, self._pending_dirs = [], [], set()
        if self._catalog_dirty and self._can_write():  # a reader's replayed catalog is never written
            self._write_catalog()

    def _apply_put(self, record: LedgerRecord, meta: dict) -> _VersionState:
        state = _VersionState(version=record.version, seq=record.seq, timestamp=record.timestamp, size=record.size,
                              commitment=record.commitment, salt=meta["salt"], cipher_hash=record.cipher_hash,
                              source_mtime=_time_or_none(meta.get("source_mtime")))
        entry = self._entries.get(record.entry_id)
        if entry is None:
            entry = _EntryState(entry_id=record.entry_id, path=meta["path"], title=meta["title"], kind=meta["kind"],
                                media_type=meta["media_type"], tags=list(meta["tags"]))
            self._entries[record.entry_id] = entry
        if len(entry.versions) + 1 != record.version:
            raise Corrupted(f"entry {record.entry_id}: version {record.version} out of order")
        entry.title, entry.kind, entry.media_type = meta["title"], meta["kind"], meta["media_type"]
        entry.tags = list(meta["tags"])
        if entry.path != meta["path"]:
            self._by_path.pop(entry.path, None)
            entry.path = meta["path"]
        entry.versions.append(state)
        if not entry.removed:
            self._by_path[entry.path] = entry.entry_id
        self._invalidate(record.entry_id)
        return state

    def _apply_remove(self, entry_id: str) -> None:
        entry = self._entries[entry_id]
        entry.removed = True
        if self._by_path.get(entry.path) == entry_id:
            del self._by_path[entry.path]
        self._invalidate(entry_id)

    def _invalidate(self, entry_id: str) -> None:
        self._meta_cache.pop(entry_id, None)
        self._sorted_cache = None

    # ================================================================ entries

    @staticmethod
    def _normalize(path: str) -> str:
        return str(path).replace("\\", "/").strip("/")

    @_locked
    def put(self, path: str, content: bytes, *, title: str | None = None, kind: EntryKind = "note",
            tags: Sequence[str] = (), media_type: str = "text/markdown",
            source_mtime: datetime | None = None) -> Version:
        self._require_writable()
        path = self._normalize(path)
        if not path:
            raise VaultError("path must not be empty")
        content = bytes(content)
        entry_id = self._by_path.get(path)
        previous = self._entries.get(entry_id) if entry_id else None
        if previous is not None:
            latest = previous.versions[-1]
            if crypto.commitment(bytes.fromhex(latest.salt), content) == latest.commitment:
                return self._version(previous, latest)
        else:
            entry_id = secrets.token_hex(16)
        number = len(previous.versions) + 1 if previous else 1
        salt = crypto.random_bytes(32)
        meta = {
            "path": path,
            "title": title if title is not None else (previous.title if previous else PurePosixPath(path).stem),
            "kind": kind,
            "media_type": media_type,
            "tags": sorted(set(tags)),
            "source_mtime": format_time(_utc(source_mtime)) if source_mtime else None,
            "salt": salt.hex(),
        }
        payload = crypto.pack_payload(canonical_json(meta).encode("utf-8"), content)
        blob = crypto.seal_blob(self._keys.content, crypto.BLOB_CONTENT, payload,
                                crypto.blob_binding(self._vault_id, f"content:{entry_id}:{number}"))
        cipher_hash = crypto.sha256(blob).hex()
        record = self._new_record("put", entry_id=entry_id, version=number,
                                  commitment=crypto.commitment(salt, content), cipher_hash=cipher_hash,
                                  size=len(content))
        self._commit(record, (cipher_hash, blob))
        state = self._apply_put(record, meta)
        self._save_catalog()
        return self._version(self._entries[entry_id], state)

    def _version(self, entry: _EntryState, state: _VersionState) -> Version:
        return Version(entry_id=entry.entry_id, version=state.version, seq=state.seq, timestamp=state.timestamp,
                       size=state.size, commitment=state.commitment, source_mtime=state.source_mtime)

    def _meta(self, entry: _EntryState) -> EntryMeta:
        cached = self._meta_cache.get(entry.entry_id)
        if cached is None:
            claimed = [v.source_mtime for v in entry.versions if v.source_mtime is not None]
            cached = EntryMeta(entry_id=entry.entry_id, path=entry.path, title=entry.title, kind=entry.kind,
                               media_type=entry.media_type, tags=list(entry.tags), n_versions=len(entry.versions),
                               size=entry.versions[-1].size, created_at=entry.versions[0].timestamp,
                               updated_at=entry.versions[-1].timestamp,
                               authored_at=min(claimed) if claimed else None,
                               modified_at=max(claimed) if claimed else None)
            self._meta_cache[entry.entry_id] = cached
        return cached

    @_locked
    def entries(self) -> list[EntryMeta]:
        if self._sorted_cache is None:
            live = [self._entries[eid] for eid in self._by_path.values()]
            self._sorted_cache = sorted((self._meta(e) for e in live), key=lambda m: m.path)
        return list(self._sorted_cache)

    @_locked
    def entry(self, entry_id: str) -> EntryMeta:
        entry = self._entries.get(entry_id)
        if entry is None or entry.removed:
            raise NotFound(entry_id)
        return self._meta(entry)

    @_locked
    def find(self, path: str) -> EntryMeta | None:
        entry_id = self._by_path.get(self._normalize(path))
        return self._meta(self._entries[entry_id]) if entry_id else None

    def _state(self, entry_id: str, version: int | None) -> tuple[_EntryState, _VersionState]:
        """Any recorded version, removed entries included: their history stays readable."""
        entry = self._entries.get(entry_id)
        if entry is None:
            raise NotFound(entry_id)
        if version is None:
            return entry, entry.versions[-1]
        if not 1 <= version <= len(entry.versions):
            raise NotFound(f"{entry_id} v{version}")
        return entry, entry.versions[version - 1]

    @_locked
    def read(self, entry_id: str, version: int | None = None) -> bytes:
        entry, state = self._state(entry_id, version)
        try:
            payload = self._read_blob(state.cipher_hash, self._keys.content, crypto.BLOB_CONTENT,
                                      f"content:{entry_id}:{state.version}")
        except FileNotFoundError:
            raise Corrupted(f"blob of {entry_id} v{state.version} is missing") from None
        _, body = crypto.unpack_payload(payload)
        if crypto.commitment(bytes.fromhex(state.salt), body) != state.commitment:
            raise Corrupted(f"{entry_id} v{state.version}: content does not match its commitment")
        return body

    @_locked
    def versions(self, entry_id: str) -> list[Version]:
        entry = self._entries.get(entry_id)
        if entry is None:
            raise NotFound(entry_id)
        return [self._version(entry, v) for v in entry.versions]

    @_locked
    def remove(self, entry_id: str) -> None:
        self._require_writable()
        entry = self._entries.get(entry_id)
        if entry is None or entry.removed:
            raise NotFound(entry_id)
        record = self._new_record("remove", entry_id=entry_id, version=len(entry.versions))
        self._commit(record, None)
        self._apply_remove(entry_id)
        self._save_catalog()

    # ================================================================ aux

    def _aux_path(self, key: str) -> tuple[Path, str]:
        name = crypto.name_mac(self._keys.aux_name, key)
        return self.path / AUX / name[:2] / name, name

    @_locked
    def aux_get(self, key: str) -> bytes | None:
        target, name = self._aux_path(key)
        if not target.exists():
            return None
        return crypto.open_blob(self._keys.aux, read_bytes(target), crypto.blob_binding(self._vault_id, f"aux:{name}"),
                                crypto.BLOB_AUX, "aux value")

    @_locked
    def aux_put(self, key: str, value: bytes) -> None:
        self._require_writable()
        target, name = self._aux_path(key)
        atomic_write(target, crypto.seal_blob(self._keys.aux, crypto.BLOB_AUX, bytes(value),
                                              crypto.blob_binding(self._vault_id, f"aux:{name}")))

    # ================================================================ ledger

    @_locked
    def ledger(self) -> list[LedgerRecord]:
        return list(self._ledger.records)

    @_locked
    def anchors(self) -> list[Anchor]:
        return list(self._anchors)

    @_locked
    def verify(self) -> VerifyReport:
        """Re-read header, ledger, catalog and anchors from disk and check them; repair nothing.

        What is on disk is compared with what this object holds, then checked on its own.
        Any error makes the vault read-only. An anchor whose authority cannot be
        authenticated is not an error (see anchor_states()); an invalid one is.
        """
        if self._batch_depth:
            raise VaultError("cannot verify inside a batch: its records are not on disk yet")
        errors: list[str] = list(self._problems)
        found: list[str] = []
        # header
        try:
            if (self.path / HEADER).stat().st_size > MAX_HEADER_BYTES:
                raise ValueError("header too large")
            disk_header = json.loads(read_bytes(self.path / HEADER))
            if disk_header != self._header:
                found.append("header.json on disk differs from the header this vault opened")
            if disk_header.get("public_key") != self._public_hex:
                found.append("header: public key does not match the vault identity key")
        except (OSError, ValueError, AttributeError):
            found.append("header.json is missing or unreadable")
        # ledger, as it is on disk now
        disk = Ledger(self.path / LEDGER)
        disk.load(repair_tail=False)
        records = disk.records
        found += disk.problems
        if disk.torn_tail:
            found.append("ledger: incomplete last line")
        memory = self._ledger.records
        if len(records) != len(memory) or any(a != b for a, b in zip(records, memory)):
            index = next((i for i, (a, b) in enumerate(zip(records, memory)) if a != b), min(len(records), len(memory)))
            found.append(f"ledger.jsonl on disk differs from the ledger in memory from record {index} "
                         f"({len(records)} records on disk, {len(memory)} in memory)")
        chain_errors, signatures = check_chain(records, self._public, self._public_hex)
        found += chain_errors
        blobs = 0
        for record in records:
            if not record.cipher_hash:
                continue
            blobs += 1
            label, key, blob_type = self._blob_place(record)
            try:
                data = self._blobs.read(record.cipher_hash)
            except FileNotFoundError:
                found.append(f"record {record.seq}: blob missing")
                continue
            if crypto.sha256(data).hex() != record.cipher_hash:
                found.append(f"record {record.seq}: blob does not match cipher_hash")
                continue
            try:
                crypto.open_blob(key, data, crypto.blob_binding(self._vault_id, label), blob_type, label)
            except Corrupted:
                found.append(f"record {record.seq}: blob does not decrypt as {record.kind} of this place")
        # catalog: the file against memory, then memory against the disk ledger
        found += self._check_catalog_file(records)
        found += self._check_catalog(records)
        # anchors, as on disk
        anchors, anchor_problems = self._read_anchors()
        found += anchor_problems
        if anchors != self._anchors:
            found.append("anchors.jsonl on disk differs from the anchors in memory")
        if self._catalog_anchors > len(anchors):
            found.append(f"anchors: the catalog knows {self._catalog_anchors}, anchors.jsonl has {len(anchors)}")
        found += self._anchor_positions(anchors, records)
        statuses = []
        for index, anchor in enumerate(anchors):
            status = self._anchor_status(anchor, records)
            statuses.append(status)
            if status.state == "invalid":
                found.append(f"anchor {index}: {status.error}")
        for problem in found:
            if problem not in errors:
                errors.append(problem)
        self._add_problems(found)
        head = records[-1].record_hash if records else ZERO_HASH
        return VerifyReport(ok=not errors, n_records=len(records), head_hash=head, signatures_checked=signatures,
                            blobs_checked=blobs, anchors_checked=len(anchors), anchor_status=statuses,
                            errors=errors)

    def _check_catalog_file(self, records: list[LedgerRecord]) -> list[str]:
        try:
            data = crypto.open_blob(self._keys.metadata, read_bytes(self.path / CATALOG),
                                    crypto.blob_binding(self._vault_id, "catalog"), crypto.BLOB_CATALOG, "catalog")
            catalog = json.loads(data)
        except FileNotFoundError:
            return ["catalog.bin is missing"]
        except (Corrupted, ValueError):
            return ["catalog.bin does not decrypt or parse"]
        problems = []
        n = catalog.get("n_records", 0)
        if n > len(records):
            problems.append(f"rollback: the catalog recorded {n} records ending in {str(catalog.get('head_hash'))[:16]}, "
                            f"the ledger has only {len(records)}")
        elif n and records[n - 1].record_hash != catalog.get("head_hash"):
            problems.append(f"catalog head hash does not match ledger record {n - 1}")
        if not self._catalog_dirty and catalog != json.loads(canonical_json(self._catalog_dict())):
            problems.append("catalog.bin on disk differs from the catalog in memory")
        return problems

    def _blob_place(self, record: LedgerRecord) -> tuple[str, bytes, int]:
        if record.kind == "put":
            return f"content:{record.entry_id}:{record.version}", self._keys.content, crypto.BLOB_CONTENT
        if record.kind == "license":
            return f"license:{record.seq}", self._keys.license, crypto.BLOB_GRANT
        return f"royalty:{record.seq}", self._keys.license, crypto.BLOB_ROYALTY

    def _check_catalog(self, records: list[LedgerRecord]) -> list[str]:
        errors: list[str] = []
        known: set[int] = set()
        for entry in self._entries.values():
            for state in entry.versions:
                known.add(state.seq)
                record = records[state.seq] if state.seq < len(records) else None
                if (record is None or record.kind != "put" or record.entry_id != entry.entry_id
                        or record.version != state.version or record.commitment != state.commitment
                        or record.cipher_hash != state.cipher_hash or record.size != state.size
                        or record.timestamp != state.timestamp):
                    errors.append(f"catalog: entry {entry.entry_id} v{state.version} does not match ledger "
                                  f"record {state.seq}")
        for state in list(self._licenses.values()) + self._royalties:
            known.add(state.seq)
            record = records[state.seq] if state.seq < len(records) else None
            if record is None or record.commitment != crypto.commitment(bytes.fromhex(state.salt),
                                                                       state.committed.encode("utf-8")):
                errors.append(f"catalog: license or royalty at record {state.seq} does not match the ledger")
        removed: set[str] = set()
        for record in records:
            if record.kind == "remove":
                removed.add(record.entry_id)
                entry = self._entries.get(record.entry_id)
                if entry is None or not entry.removed:
                    errors.append(f"record {record.seq}: removal not reflected in the catalog")
            elif record.seq not in known:
                errors.append(f"record {record.seq}: not in the catalog")
        for entry in self._entries.values():
            if entry.removed and entry.entry_id not in removed:
                errors.append(f"catalog: entry {entry.entry_id} is removed but the ledger has no removal")
        return errors

    def _anchor_status(self, anchor: Anchor, records: list[LedgerRecord]) -> AnchorStatus:
        """One anchor re-checked now, as the contract's AnchorStatus. A time is given only
        for a valid token; "proven" only when its signer chains to a trusted root."""
        if not 0 <= anchor.seq_upto < len(records) or records[anchor.seq_upto].record_hash != anchor.head_hash:
            return AnchorStatus(seq_upto=anchor.seq_upto, authority=anchor.authority, state="invalid",
                                error=f"head hash is not record {anchor.seq_upto} of this ledger")
        check: TokenAssessment = assess_anchor(anchor, self.trust_roots)
        if check.state == "invalid":
            return AnchorStatus(seq_upto=anchor.seq_upto, authority=anchor.authority, state="invalid",
                                signer=check.signer, error="; ".join(check.errors))
        return AnchorStatus(seq_upto=anchor.seq_upto, authority=anchor.authority, anchored_at=check.time,
                            state=check.state, signer=check.signer, error=check.trust_error)

    @_locked
    def proof(self, entry_id: str, version: int | None = None) -> ProvenanceProof:
        """Where one version stands, with every covering anchor re-checked in this call.

        anchor_status: one entry per anchor with seq_upto >= the record. proven_before is
        the earliest anchored_at among "proven" entries, claimed_before among "claimed"
        ones; an "invalid" entry sets neither and is also named in anchor_errors.
        `anchors` lists the covering anchors that are not invalid.
        """
        _, state = self._state(entry_id, version)
        records = self._ledger.records
        record = records[state.seq]
        errors, _ = check_chain(records, self._public, self._public_hex, start=state.seq)
        verified = not errors and compute_record_hash(record, self._public_hex) == record.record_hash
        usable: list[Anchor] = []
        statuses: list[AnchorStatus] = []
        anchor_errors: list[str] = []
        for index, anchor in enumerate(self._anchors):
            if anchor.seq_upto < record.seq:
                continue
            status = self._anchor_status(anchor, records)
            statuses.append(status)
            if status.state == "invalid":
                anchor_errors.append(f"anchor {index}: {status.error}")
            else:
                usable.append(anchor)
        proven = [s.anchored_at for s in statuses if s.state == "proven" and s.anchored_at]
        claimed = [s.anchored_at for s in statuses if s.state == "claimed" and s.anchored_at]
        return ProvenanceProof(record=record, public_key=self._public_hex, head_hash=records[-1].record_hash,
                               n_following=len(records) - 1 - record.seq, anchors=usable,
                               proven_before=min(proven) if proven else None,
                               claimed_before=min(claimed) if claimed else None,
                               anchor_errors=anchor_errors, anchor_status=statuses, verified=verified)

    def anchor_methods(self) -> list[str]:
        """Only what really works: RFC 3161. OpenTimestamps is not implemented."""
        return ["rfc3161"]

    @_locked
    def anchor_states(self) -> list[AnchorStatus]:
        """Each stored anchor re-checked now (the same list as verify().anchor_status)."""
        return [self._anchor_status(a, self._ledger.records) for a in self._anchors]

    def anchor(self, method: Literal["rfc3161", "opentimestamps"] = "rfc3161") -> Anchor:
        """Timestamp the head at self.tsa_url through self.transport (HTTP when None).

        Sends the 32-byte head hash only. Never called implicitly. Refuses a token whose
        authority cannot be authenticated against the trust roots (certifi by default)
        unless require_trusted_anchor is False. The network call runs without the vault
        lock; ownership, integrity and the head on disk are checked again after it.
        """
        if method == "opentimestamps":
            raise VaultError("opentimestamps anchoring is not implemented")
        if method != "rfc3161":
            raise VaultError(f"unknown anchoring method {method!r}")
        with self._lock:
            if self._keys is None:
                raise VaultError("vault is locked")
            if self._batch_depth:
                raise VaultError("cannot anchor inside a batch")
            self._require_writable()
            records = self._ledger.records
            if not records:
                raise VaultError("nothing to anchor: the ledger is empty")
            seq, head = len(records) - 1, records[-1].record_hash
            url, transport, roots, strict = self.tsa_url, self.transport, self.trust_roots, self.require_trusted_anchor
        anchor = request_anchor(head, seq, url=url, transport=transport, trust_roots=roots, require_trusted=strict)
        with self._lock:
            if self._keys is None:
                raise VaultError("the vault was locked during the timestamp request; the anchor is not stored")
            if self._batch_depth:
                raise VaultError("a batch started during the timestamp request; the anchor is not stored")
            self._require_writable()
            records = self._ledger.records
            if seq >= len(records) or records[seq].record_hash != head:
                raise Corrupted("the ledger changed under the timestamp request; the anchor is not stored")
            mismatch = self._ledger.disk_mismatch(self._ledger.head_hash)
            if mismatch:
                self._add_problems([mismatch])
                raise Corrupted(f"read-only: {mismatch}")
            line = anchor.model_dump_json() + "\n"
            append_bytes(self.path / ANCHORS, line.encode("utf-8"))
            self._anchors.append(anchor)
            self._catalog_anchors = len(self._anchors)
            self._save_catalog()
            return anchor

    # ================================================================ licensing

    def _commit_document(self, kind: str, build: Callable[[int, datetime], dict]) -> tuple[_Committed, LedgerRecord]:
        """Record a license grant or royalty event: commit to its exact bytes, store it encrypted."""
        seq = len(self._ledger.records)
        timestamp = self._now()
        committed = canonical_json(build(seq, timestamp))
        body = committed.encode("utf-8")
        salt = crypto.random_bytes(32)
        payload = crypto.pack_payload(canonical_json({"salt": salt.hex()}).encode("utf-8"), body)
        blob_type = crypto.BLOB_GRANT if kind == "license" else crypto.BLOB_ROYALTY
        blob = crypto.seal_blob(self._keys.license, blob_type, payload,
                                crypto.blob_binding(self._vault_id, f"{kind}:{seq}"))
        cipher_hash = crypto.sha256(blob).hex()
        # size 0: the length of a grant would say something about its terms.
        record = self._new_record(kind, commitment=crypto.commitment(salt, body), cipher_hash=cipher_hash,
                                  timestamp=timestamp)
        self._commit(record, (cipher_hash, blob))
        return _Committed(seq=seq, committed=committed, salt=salt.hex(), cipher_hash=cipher_hash), record

    @_locked
    def grant(self, licensee: str, items: Sequence[tuple[str, int | None]], *, usage: str, terms: str = "",
              royalty: RoyaltyTerms | None = None, valid_until: date | None = None) -> LicenseGrant:
        self._require_writable()
        if not items:
            raise VaultError("a license needs at least one item")
        licensed = []
        for entry_id, number in items:
            meta = self.entry(entry_id)
            _, state = self._state(entry_id, number)
            if any(i.entry_id == entry_id and i.version == state.version for i in licensed):
                raise VaultError(f"duplicate item {entry_id} v{state.version} in the grant")
            licensed.append(LicenseItem(entry_id=entry_id, version=state.version, title=meta.title,
                                        commitment=state.commitment))
        license_id = secrets.token_hex(16)

        def build(seq: int, timestamp: datetime) -> dict:
            grant = LicenseGrant(license_id=license_id, licensee=licensee, items=licensed, usage=usage, terms=terms,
                                 royalty=royalty or RoyaltyTerms(), created_at=timestamp, valid_until=valid_until,
                                 seq=seq, bundle_hash="")
            return grant.model_dump(mode="json")

        state, _ = self._commit_document("license", build)
        self._licenses[license_id] = state
        self._license_order.append(license_id)
        self._save_catalog()
        return self._grant(license_id)

    def _grant(self, license_id: str) -> LicenseGrant:
        state = self._licenses.get(license_id)
        if state is None:
            raise NotFound(license_id)
        grant = LicenseGrant.model_validate_json(state.committed)
        grant.bundle_hash = state.bundle_hash
        return grant

    @_locked
    def licenses(self) -> list[LicenseGrant]:
        return [self._grant(i) for i in self._license_order]

    @_locked
    def record_royalty(self, license_id: str, amount: float, *, currency: str = "EUR",
                       received_on: date | None = None, period: str = "", note: str = "") -> RoyaltyEvent:
        self._require_writable()
        if license_id not in self._licenses:
            raise NotFound(license_id)

        def build(seq: int, timestamp: datetime) -> dict:
            event = RoyaltyEvent(license_id=license_id, received_on=received_on or timestamp.date(), amount=amount,
                                 currency=currency, period=period, note=note, seq=seq)
            return event.model_dump(mode="json")

        state, _ = self._commit_document("royalty", build)
        self._royalties.append(state)
        self._save_catalog()
        return RoyaltyEvent.model_validate_json(state.committed)

    @_locked
    def royalties(self, license_id: str | None = None) -> list[RoyaltyEvent]:
        events = [RoyaltyEvent.model_validate_json(s.committed) for s in self._royalties]
        return [e for e in events if license_id is None or e.license_id == license_id]

    @_locked
    def export_bundle(self, license_id: str, out_dir: Path) -> Path:
        """Write the disclosure bundle of one grant (see licensing.py) and set its bundle_hash."""
        from .licensing import BundleItem, write_bundle
        if self._batch_depth:
            raise VaultError("cannot export inside a batch")
        state = self._licenses.get(license_id)
        if state is None:
            raise NotFound(license_id)
        grant = LicenseGrant.model_validate_json(state.committed)
        items = []
        for item in grant.items:
            entry, version = self._state(item.entry_id, item.version)
            items.append(BundleItem(item=item, media_type=entry.media_type, salt=version.salt,
                                    plaintext=self.read(item.entry_id, item.version),
                                    record=self._ledger.records[version.seq]))
        records = self._ledger.records
        bundle, manifest_hash = write_bundle(
            out_dir=Path(out_dir), license_id=license_id, committed=state.committed.encode("utf-8"),
            grant_salt=state.salt, license_record=records[state.seq], items=items, records=records,
            public_key_hex=self._public_hex, signer=self._signer,
            anchors=[a for a in self._anchors if assess_anchor(a, self.trust_roots).state != "invalid"])
        state.bundle_hash = manifest_hash
        self._save_catalog()
        return bundle

    # ================================================================ catalogue and coverage

    def _assessed_anchors(self) -> list:
        """Anchors that are not invalid, re-checked once per (anchor count, trust roots)."""
        from .catalogue import AssessedAnchor
        # Records are append-only, so an anchor's state can change only with the trust roots.
        key = (len(self._anchors), id(self.trust_roots))
        cached = getattr(self, "_assessed_cache", None)
        if cached is not None and cached[0] == key:
            return cached[1]
        out = []
        for anchor in self._anchors:
            status = self._anchor_status(anchor, self._ledger.records)
            if status.state != "invalid" and status.anchored_at is not None:
                out.append(AssessedAnchor(anchor, status.state, status.anchored_at))
        self._assessed_cache = (key, out)
        return out

    @_locked
    def coverage(self) -> Coverage:
        from .catalogue import coverage_of
        return coverage_of(self._ledger.records, self._assessed_anchors())

    @_locked
    def export_catalogue(self, items: Sequence[CatalogueChoice], out_dir: Path) -> CataloguePublication:
        """Write a public catalogue (see catalogue.py) signed by the vault identity."""
        from . import catalogue
        self._require_writable()  # it records what was published (aux values)
        if self._batch_depth:
            raise VaultError("cannot export inside a batch")
        records = self._ledger.records
        signer = self._signer

        def digests(first: int, last: int) -> list[str]:
            return chain_digests(records[:last + 1], self._public_hex, first)

        return catalogue.export(self, items, Path(out_dir), public_key=self._public_hex, records=records,
                                anchors=self._assessed_anchors(), sign=lambda m: signer.sign(m).hex(),
                                digests=digests)

    @_locked
    def catalogues(self) -> list[CataloguePublication]:
        from .catalogue import publications
        return publications(self)


# ==================================================================== helpers


def _kdf_aad(kdf: dict) -> bytes:
    return json.dumps(kdf, sort_keys=True, separators=(",", ":")).encode("ascii")


def _set_passphrase(header: dict, master: bytes, passphrase: str, params: KdfParams) -> None:
    vault_id = bytes.fromhex(header["vault_id"])
    salt = crypto.random_bytes(16)
    kdf = dict(params.to_dict(), salt=salt.hex())
    kek = crypto.derive_passphrase_key(passphrase, salt, params)
    header["kdf"] = kdf
    header["master_key_wraps"]["passphrase"] = crypto.wrap(kek, master,
                                                           crypto.wrap_aad("passphrase", vault_id, _kdf_aad(kdf)))


def _read_header(path: Path) -> dict:
    target = path / HEADER
    if not target.exists():
        raise VaultError("no vault in this directory (header.json missing)")
    if target.stat().st_size > MAX_HEADER_BYTES:
        raise Corrupted(f"header: larger than {MAX_HEADER_BYTES} bytes")
    try:
        header = json.loads(read_bytes(target))
        if header["format"] != VAULT_FORMAT:
            raise Corrupted("header: not an Empreinte vault")
        if header["format_version"] != crypto.FORMAT_VERSION:
            raise VaultError(f"unsupported vault format version {header['format_version']}")
        if len(bytes.fromhex(header["vault_id"])) != 16:
            raise ValueError
        header["kdf"]["salt"], header["master_key_wraps"]["passphrase"], header["identity"]  # noqa: B018
    except (KeyError, TypeError, ValueError):
        raise Corrupted("header: malformed") from None
    return header


def _short(exc: Exception) -> str:
    return (str(exc).splitlines() or [type(exc).__name__])[0][:120]

