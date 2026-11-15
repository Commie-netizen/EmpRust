"""The append-only, signed hash chain (ledger.jsonl). Specified in docs/FORMAT.md.

    body_digest = SHA-256(canonical body)
    record_hash = SHA-256(prev_hash || body_digest)            (raw 32-byte values)
    signature   = Ed25519(b"empreinte/v1/record\\x00" || record_hash)

The two-level form lets a bundle prove that a record is chained to the head by giving
only the 32-byte body digests of the records in between.

Ledger time is the local clock of the machine that wrote the record: on its own the
ledger proves order, not absolute time. Absolute time comes only from anchors.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .model import LedgerRecord
from .store import append_bytes, read_bytes, truncate

ZERO_HASH = "0" * 64
LEDGER_FORMAT = 1
RECORD_SIGNATURE_PREFIX = b"empreinte/v1/record\x00"
KINDS = ("put", "remove", "license", "royalty")
LINE_FIELDS = ("seq", "kind", "entry_id", "version", "commitment", "cipher_hash", "size", "timestamp",
               "prev_hash", "record_hash", "signature")

_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX32 = re.compile(r"[0-9a-f]{32}")
_HEX128 = re.compile(r"[0-9a-f]{128}")
_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z")


# ------------------------------------------------------------------------- time


def format_time(value: datetime) -> str:
    """Canonical ledger time: UTC, microseconds, 'Z', e.g. 2026-01-01T09:00:00.000000Z."""
    if value.tzinfo is None:
        raise ValueError("ledger times must be timezone-aware")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_time(text: str) -> datetime:
    if not isinstance(text, str) or not _TIME.fullmatch(text):
        raise ValueError(f"not a canonical ledger time: {text!r}")
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


# --------------------------------------------------------------------- encoding


def canonical_body(record: LedgerRecord, public_key_hex: str) -> bytes:
    """The exact bytes hashed into body_digest. Every value is ASCII by construction."""
    body = {
        "cipher_hash": record.cipher_hash,
        "commitment": record.commitment,
        "entry_id": record.entry_id,
        "format": LEDGER_FORMAT,
        "key": public_key_hex,
        "kind": record.kind,
        "seq": record.seq,
        "size": record.size,
        "timestamp": format_time(record.timestamp),
        "version": record.version,
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def body_digest(record: LedgerRecord, public_key_hex: str) -> bytes:
    return hashlib.sha256(canonical_body(record, public_key_hex)).digest()


def chain_hash(prev_hash_hex: str, digest: bytes) -> str:
    return hashlib.sha256(bytes.fromhex(prev_hash_hex) + digest).hexdigest()


def compute_record_hash(record: LedgerRecord, public_key_hex: str) -> str:
    return chain_hash(record.prev_hash, body_digest(record, public_key_hex))


def signature_message(record_hash_hex: str) -> bytes:
    return RECORD_SIGNATURE_PREFIX + bytes.fromhex(record_hash_hex)


def make_record(*, seq: int, kind: str, prev_hash: str, timestamp: datetime, signer: Ed25519PrivateKey,
                public_key_hex: str, entry_id: str = "", version: int = 0, commitment: str = "",
                cipher_hash: str = "", size: int = 0) -> LedgerRecord:
    """Build, hash and sign the next record."""
    draft = LedgerRecord(seq=seq, kind=kind, entry_id=entry_id, version=version, commitment=commitment,
                         cipher_hash=cipher_hash, size=size,
                         timestamp=parse_time(format_time(timestamp)), prev_hash=prev_hash, record_hash=ZERO_HASH)
    _check_fields(draft)
    record_hash = compute_record_hash(draft, public_key_hex)
    signature = signer.sign(signature_message(record_hash)).hex()
    return draft.model_copy(update={"record_hash": record_hash, "signature": signature})


def record_to_line(record: LedgerRecord) -> bytes:
    data = {
        "seq": record.seq, "kind": record.kind, "entry_id": record.entry_id, "version": record.version,
        "commitment": record.commitment, "cipher_hash": record.cipher_hash, "size": record.size,
        "timestamp": format_time(record.timestamp), "prev_hash": record.prev_hash,
        "record_hash": record.record_hash, "signature": record.signature,
    }
    return json.dumps(data, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"


def record_to_dict(record: LedgerRecord) -> dict:
    """The public JSON form of a record (as in a ledger line)."""
    return json.loads(record_to_line(record))


def record_from_dict(data: dict) -> LedgerRecord:
    """Strict parse: wrong types, unknown fields or non-canonical values raise ValueError."""
    if not isinstance(data, dict) or set(data) != set(LINE_FIELDS):
        raise ValueError("wrong set of fields")
    for name in ("seq", "version", "size"):
        if type(data[name]) is not int or data[name] < 0:
            raise ValueError(f"{name} must be a non-negative integer")
    record = LedgerRecord(seq=data["seq"], kind=data["kind"], entry_id=data["entry_id"], version=data["version"],
                          commitment=data["commitment"], cipher_hash=data["cipher_hash"], size=data["size"],
                          timestamp=parse_time(data["timestamp"]), prev_hash=data["prev_hash"],
                          record_hash=data["record_hash"], signature=data["signature"])
    _check_fields(record)
    if not _HEX64.fullmatch(record.record_hash) or not _HEX128.fullmatch(record.signature):
        raise ValueError("record_hash or signature malformed")
    return record


def _check_fields(record: LedgerRecord) -> None:
    if record.kind not in KINDS:
        raise ValueError("unknown kind")
    if record.entry_id and not _HEX32.fullmatch(record.entry_id):
        raise ValueError("entry_id must be 32 lowercase hex characters or empty")
    for name in ("commitment", "cipher_hash"):
        value = getattr(record, name)
        if value and not _HEX64.fullmatch(value):
            raise ValueError(f"{name} must be 64 lowercase hex characters or empty")
    if not _HEX64.fullmatch(record.prev_hash):
        raise ValueError("prev_hash malformed")


# ---------------------------------------------------------------- verification


def verify_signature(record: LedgerRecord, public_key: Ed25519PublicKey) -> bool:
    try:
        public_key.verify(bytes.fromhex(record.signature), signature_message(record.record_hash))
        return True
    except (InvalidSignature, ValueError):
        return False


def check_chain(records: Sequence[LedgerRecord], public_key: Ed25519PublicKey, public_key_hex: str,
                start: int = 0) -> tuple[list[str], int]:
    """Errors in records[start:], and the number of signatures checked."""
    errors: list[str] = []
    checked = 0
    previous = records[start - 1].record_hash if start > 0 else ZERO_HASH
    for index in range(start, len(records)):
        record = records[index]
        if record.seq != index:
            errors.append(f"record {index}: seq is {record.seq}, expected {index} (line deleted, inserted or moved)")
        if record.prev_hash != previous:
            errors.append(f"record {index}: prev_hash does not match record {index - 1}")
        if compute_record_hash(record, public_key_hex) != record.record_hash:
            errors.append(f"record {index}: record_hash does not match its content")
        checked += 1
        if not verify_signature(record, public_key):
            errors.append(f"record {index}: signature invalid")
        previous = record.record_hash
    return errors, checked


def chain_digests(records: Sequence[LedgerRecord], public_key_hex: str, start: int) -> list[str]:
    """Hex body digests of records[start:], for a chain proof."""
    return [body_digest(r, public_key_hex).hex() for r in records[start:]]


# ------------------------------------------------------------------------- file


class Ledger:
    """ledger.jsonl: one JSON object per line, appended and fsynced, never rewritten."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.records: list[LedgerRecord] = []
        self.problems: list[str] = []
        self.repaired_tail = False
        self.torn_tail = False  # a last line without newline was found (and not repaired)
        self.size = 0  # bytes of the file as this object last read or wrote it

    def load(self, *, repair_tail: bool = True) -> None:
        """Read every line. Unreadable lines are reported, not fatal, so verify() can name them.

        A last line without its newline is the trace of a crash during append: the put()
        that wrote it never returned. With repair_tail it is completed if it parses, else
        cut off; without, it is reported in `torn_tail` and ignored.
        """
        self.records, self.problems, self.repaired_tail, self.torn_tail = [], [], False, False
        if not self.path.exists():
            self.size = 0
            return
        data = read_bytes(self.path)
        if data and not data.endswith(b"\n"):
            cut = data.rfind(b"\n") + 1
            try:
                record_from_dict(json.loads(data[cut:]))
                fixed = True
            except (ValueError, TypeError):
                fixed = False
            if repair_tail:
                if fixed:
                    append_bytes(self.path, b"\n")
                    data += b"\n"
                else:
                    truncate(self.path, cut)
                    data = data[:cut]
                self.repaired_tail = True
            else:
                self.torn_tail = True
                data = data[:cut]
        self.size = len(data) if repair_tail or not self.torn_tail else self.path.stat().st_size
        for number, line in enumerate(data.split(b"\n")[:-1] if data else []):
            try:
                self.records.append(record_from_dict(json.loads(line)))
            except (ValueError, TypeError) as exc:
                self.problems.append(f"ledger line {number + 1}: unreadable ({_reason(exc)})")

    def disk_mismatch(self, expected_head: str) -> str | None:
        """Why the file on disk does not end with `expected_head` as this object left it, or None.

        Checked before every append: another writer, a sync client bringing in another
        machine's lines, or an edit would otherwise be silently forked.
        """
        try:
            size = self.path.stat().st_size
        except FileNotFoundError:
            return "ledger.jsonl has disappeared"
        if size != self.size:
            return f"ledger.jsonl changed on disk since it was read ({self.size} bytes known, {size} found)"
        if expected_head == ZERO_HASH:
            return None if size == 0 else "ledger.jsonl is not empty although this vault knows no record"
        with open(self.path, "rb") as handle:
            handle.seek(max(0, size - 4096))
            tail = handle.read()
        last = tail.rstrip(b"\n").rsplit(b"\n", 1)[-1]
        try:
            if record_from_dict(json.loads(last)).record_hash == expected_head:
                return None
        except (ValueError, TypeError):
            pass
        return "the last line of ledger.jsonl is not the head this vault knows"

    def append(self, records: Iterable[LedgerRecord]) -> None:
        """Append and fsync. On any exception the outcome is uncertain (bytes may be on disk)."""
        data = b"".join(record_to_line(r) for r in records)
        if data:
            append_bytes(self.path, data)
            self.size += len(data)

    @property
    def head_hash(self) -> str:
        return self.records[-1].record_hash if self.records else ZERO_HASH


def _reason(exc: Exception) -> str:
    text = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
    return text[:120]
