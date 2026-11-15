"""The ledger encoding, re-derived here from docs/FORMAT.md rather than from the module."""
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from empreinte import ledger as L
from empreinte.model import LedgerRecord

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
KEY_HEX = KEY.public_key().public_bytes_raw().hex()
T0 = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)


def chain(n: int) -> list[LedgerRecord]:
    records, prev = [], L.ZERO_HASH
    for i in range(n):
        record = L.make_record(seq=i, kind="put", prev_hash=prev, timestamp=T0 + timedelta(minutes=i), signer=KEY,
                               public_key_hex=KEY_HEX, entry_id=f"{i:032x}", version=1,
                               commitment=hashlib.sha256(b"c%d" % i).hexdigest(),
                               cipher_hash=hashlib.sha256(b"b%d" % i).hexdigest(), size=i)
        records.append(record)
        prev = record.record_hash
    return records


def test_record_hash_follows_the_documented_encoding():
    record = chain(1)[0]
    canonical = (
        '{"cipher_hash":"%s","commitment":"%s","entry_id":"%s","format":1,"key":"%s","kind":"put","seq":0,'
        '"size":0,"timestamp":"2026-01-01T09:00:00.000000Z","version":1}'
        % (record.cipher_hash, record.commitment, record.entry_id, KEY_HEX)).encode("ascii")
    assert L.canonical_body(record, KEY_HEX) == canonical
    digest = hashlib.sha256(canonical).digest()
    expected = hashlib.sha256(bytes(32) + digest).hexdigest()
    assert record.record_hash == expected and record.prev_hash == "0" * 64
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(KEY_HEX)).verify(
        bytes.fromhex(record.signature), b"empreinte/v1/record\x00" + bytes.fromhex(expected))


def test_key_is_bound_into_every_record_hash():
    record = chain(1)[0]
    other = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    assert L.compute_record_hash(record, other) != record.record_hash


def test_line_round_trip_and_strict_parsing():
    record = chain(2)[1]
    line = L.record_to_line(record)
    assert line.endswith(b"\n") and b"\n" not in line[:-1]
    assert L.record_from_dict(json.loads(line)) == record
    data = json.loads(line)
    for change in ({"extra": 1}, {"seq": 1.0}, {"seq": True}, {"size": -1}, {"entry_id": "A" * 32},
                   {"commitment": "ab"}, {"timestamp": "2026-01-01T09:01:00Z"}, {"kind": "edit"}):
        with pytest.raises(ValueError):
            L.record_from_dict({**data, **change})


def test_time_format_is_strict_and_utc():
    paris = timezone(timedelta(hours=1))
    assert L.format_time(datetime(2026, 1, 1, 10, 0, tzinfo=paris)) == "2026-01-01T09:00:00.000000Z"
    assert L.parse_time("2026-01-01T09:00:00.123456Z") == T0.replace(microsecond=123456)
    with pytest.raises(ValueError):
        L.format_time(datetime(2026, 1, 1))
    with pytest.raises(ValueError):
        L.parse_time("2026-01-01 09:00:00")


def test_check_chain_names_each_problem():
    pub = KEY.public_key()
    records = chain(4)
    assert L.check_chain(records, pub, KEY_HEX) == ([], 4)
    edited = records[2].model_copy(update={"size": 99})
    errors, _ = L.check_chain(records[:2] + [edited] + records[3:], pub, KEY_HEX)
    assert errors == ["record 2: record_hash does not match its content"]
    bad_sig = records[1].model_copy(update={"signature": records[0].signature})
    assert L.check_chain([records[0], bad_sig] + records[2:], pub, KEY_HEX)[0] == ["record 1: signature invalid"]
    other = Ed25519PrivateKey.generate().public_key()
    assert len(L.check_chain(records, other, KEY_HEX)[0]) == 4


def test_chain_proof_with_body_digests_only():
    """From record 1, the body digests alone lead to the head: the two-level form at work."""
    records = chain(6)
    digests = L.chain_digests(records, KEY_HEX, 2)
    current = records[1].record_hash
    for digest in digests:
        current = hashlib.sha256(bytes.fromhex(current) + bytes.fromhex(digest)).hexdigest()
    assert current == records[-1].record_hash


def test_ledger_file_load_reports_unreadable_lines_and_repairs_tail(tmp_path):
    path = tmp_path / "ledger.jsonl"
    records = chain(3)
    ledger = L.Ledger(path)
    ledger.append(records)
    data = path.read_bytes()
    lines = data.splitlines(keepends=True)
    path.write_bytes(lines[0] + b"garbage\n" + lines[2])
    ledger.load()
    assert [r.seq for r in ledger.records] == [0, 2] and ledger.problems[0].startswith("ledger line 2: unreadable")
    path.write_bytes(lines[0] + lines[1] + lines[2][:-1])  # complete record, missing newline
    ledger.load()
    assert len(ledger.records) == 3 and ledger.repaired_tail and path.read_bytes() == data
    path.write_bytes(lines[0] + lines[1][:30])
    ledger.load()
    assert len(ledger.records) == 1 and path.read_bytes() == lines[0]
