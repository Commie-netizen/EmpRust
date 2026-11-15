"""Primitives: known answers from the RFCs, blob sealing, binding, wrapping, recovery keys."""
import json

import pytest
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from empreinte import crypto
from empreinte.api import Corrupted, VaultError
from empreinte.vault import Vault


def test_default_kdf_is_strong():
    params = crypto.DEFAULT_KDF
    assert params.name == "argon2id"
    assert params.memory_cost >= 65536 and params.iterations >= 3 and params.lanes >= 1  # >= RFC 9106 option 2


def test_create_uses_the_default_kdf_unless_told(tmp_path, monkeypatch):
    seen = []
    real = crypto.derive_passphrase_key
    def spy(passphrase, salt, params):
        seen.append(params)
        return real(passphrase, salt, crypto.TEST_KDF)  # same code path, cheap work
    monkeypatch.setattr(crypto, "derive_passphrase_key", spy)
    Vault.create(tmp_path / "v", "pw")
    header = json.loads((tmp_path / "v" / "header.json").read_text(encoding="utf-8"))
    assert seen == [crypto.DEFAULT_KDF]
    assert {k: header["kdf"][k] for k in ("name", "iterations", "lanes", "memory_cost")} == crypto.DEFAULT_KDF.to_dict()
    assert len(bytes.fromhex(header["kdf"]["salt"])) == 16


def test_argon2id_rfc9106_vector():
    """RFC 9106 section 5.3: confirms memory_cost is in KiB and the primitive is Argon2id v1.3."""
    kdf = Argon2id(salt=b"\x02" * 16, length=32, iterations=3, lanes=4, memory_cost=32, ad=b"\x04" * 12,
                   secret=b"\x03" * 8)
    assert kdf.derive(b"\x01" * 32).hex() == "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"


def test_hkdf_rfc5869_case_1():
    okm = crypto.hkdf(b"\x0b" * 22, bytes(range(0xF0, 0xFA)), salt=bytes(range(13)), length=42)
    assert okm.hex() == ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                         "34007208d5b887185865")


def test_passphrase_is_nfc_normalized():
    salt = b"s" * 16
    composed = crypto.derive_passphrase_key("café", salt, crypto.TEST_KDF)
    decomposed = crypto.derive_passphrase_key("café", salt, crypto.TEST_KDF)
    assert composed == decomposed != crypto.derive_passphrase_key("cafe", salt, crypto.TEST_KDF)
    with pytest.raises(VaultError):
        crypto.normalize_passphrase("")


def test_subkeys_are_distinct_and_vault_specific():
    master = b"m" * 32
    keys = crypto.derive_subkeys(master, b"a" * 16)
    values = [keys.content, keys.metadata, keys.aux, keys.aux_name, keys.identity, keys.license]
    assert len(set(values)) == 6 and master not in values
    assert crypto.derive_subkeys(master, b"b" * 16).content != keys.content


def test_seal_and_open_blob():
    key = b"k" * 32
    binding = crypto.blob_binding(b"v" * 16, "content:" + "0" * 32 + ":1")
    blob = crypto.seal_blob(key, crypto.BLOB_CONTENT, b"secret text", binding)
    assert blob[:4] == b"EMPB" and blob[4] == 1 and blob[5] == crypto.BLOB_CONTENT
    assert len(blob) == crypto.BLOB_HEADER_LEN + len(b"secret text") + 16
    assert b"secret" not in blob
    assert crypto.open_blob(key, blob, binding, crypto.BLOB_CONTENT) == b"secret text"


def test_blob_is_bound_to_its_place_and_type():
    key = b"k" * 32
    place = crypto.blob_binding(b"v" * 16, "content:" + "a" * 32 + ":1")
    blob = crypto.seal_blob(key, crypto.BLOB_CONTENT, b"x", place)
    for other in ("content:" + "a" * 32 + ":2", "content:" + "b" * 32 + ":1"):
        with pytest.raises(Corrupted):
            crypto.open_blob(key, blob, crypto.blob_binding(b"v" * 16, other), crypto.BLOB_CONTENT)
    with pytest.raises(Corrupted):
        crypto.open_blob(key, blob, crypto.blob_binding(b"w" * 16, "content:" + "a" * 32 + ":1"), crypto.BLOB_CONTENT)
    with pytest.raises(Corrupted):
        crypto.open_blob(key, blob, place, crypto.BLOB_AUX)
    retyped = blob[:5] + bytes([crypto.BLOB_AUX]) + blob[6:]
    with pytest.raises(Corrupted):
        crypto.open_blob(key, retyped, place, crypto.BLOB_AUX)
    for position in (10, 45, len(blob) - 1):
        flipped = bytearray(blob)
        flipped[position] ^= 0x80
        with pytest.raises(Corrupted):
            crypto.open_blob(key, bytes(flipped), place, crypto.BLOB_CONTENT)


def test_every_blob_has_its_own_salt_and_nonce():
    key = b"k" * 32
    blobs = [crypto.seal_blob(key, crypto.BLOB_CONTENT, b"same", b"same") for _ in range(2000)]
    salts = {b[6:38] for b in blobs}
    nonces = {b[38:50] for b in blobs}
    assert len(salts) == len(nonces) == len({b[50:] for b in blobs}) == 2000


def test_wrap_unwrap_and_aad():
    kek, secret = b"k" * 32, b"s" * 32
    wrapped = crypto.wrap(kek, secret, b"aad")
    assert crypto.unwrap(kek, wrapped, b"aad") == secret
    with pytest.raises(crypto.InvalidTag):
        crypto.unwrap(kek, wrapped, b"other")
    with pytest.raises(crypto.InvalidTag):
        crypto.unwrap(b"x" * 32, wrapped, b"aad")


def test_recovery_key_encoding_and_checksum():
    raw = bytes(range(32))
    text = crypto.encode_recovery_key(raw)
    assert all(len(group) == 5 for group in text.split("-")[:-1]) and text.isupper()
    assert crypto.decode_recovery_key(text) == raw
    assert crypto.decode_recovery_key(text.lower().replace("-", " ")) == raw
    typo = text[:7] + ("A" if text[7] != "A" else "B") + text[8:]
    with pytest.raises(VaultError):
        crypto.decode_recovery_key(typo)
    with pytest.raises(VaultError):
        crypto.decode_recovery_key("not a key")


def test_commitment_is_salted_sha256():
    import hashlib
    salt = b"\x01" * 32
    assert crypto.commitment(salt, b"text") == hashlib.sha256(salt + b"text").hexdigest()
    assert crypto.commitment(b"\x02" * 32, b"text") != crypto.commitment(salt, b"text")


def test_payload_packing():
    packed = crypto.pack_payload(b'{"a":1}', b"body")
    assert crypto.unpack_payload(packed) == (b'{"a":1}', b"body")
    with pytest.raises(Corrupted):
        crypto.unpack_payload(packed[:5])
