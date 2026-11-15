"""Cryptographic primitives of the vault format, version 1.

Everything here uses the `cryptography` package and the standard library only:
Argon2id (passphrase), HKDF-SHA256 (subkeys and per-blob keys), AES-256-GCM
(authenticated encryption), Ed25519 (identity), SHA-256 (hashes, commitments).
The byte layouts are specified in docs/FORMAT.md.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import unicodedata
from dataclasses import asdict, dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .api import Corrupted, VaultError

FORMAT_VERSION = 1
KEY_LEN = 32
NONCE_LEN = 12
SALT_LEN = 32
BLOB_MAGIC = b"EMPB"
BLOB_HEADER_LEN = 4 + 1 + 1 + SALT_LEN + NONCE_LEN  # 50

# Blob types (one byte in the blob header, also part of the associated data).
BLOB_CONTENT = 1
BLOB_CATALOG = 2
BLOB_AUX = 3
BLOB_GRANT = 4
BLOB_ROYALTY = 5
BLOB_TYPES = {BLOB_CONTENT, BLOB_CATALOG, BLOB_AUX, BLOB_GRANT, BLOB_ROYALTY}

# Purpose labels of the HKDF subkeys derived from the master key.
SUBKEY_LABELS = ("content", "metadata", "aux", "aux-name", "identity", "license")


def random_bytes(n: int) -> bytes:
    return os.urandom(n)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# --------------------------------------------------------------------------- KDF


@dataclass(frozen=True)
class KdfParams:
    """Argon2id parameters. memory_cost is in KiB, as in RFC 9106."""

    name: str = "argon2id"
    iterations: int = 3
    lanes: int = 4
    memory_cost: int = 262144  # 256 MiB

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "KdfParams":
        """Parse and range-check, before any derivation: the header is not authenticated
        yet, so huge values would exhaust memory or time before the wrap could fail."""
        try:
            fields = {k: data[k] for k in ("name", "iterations", "lanes", "memory_cost")}
        except (KeyError, TypeError):
            raise Corrupted("header: invalid kdf parameters") from None
        params = cls(**fields)
        params.validate()
        return params

    def validate(self) -> None:
        if self.name != "argon2id":
            raise Corrupted(f"header: unsupported kdf {str(self.name)[:20]!r}")
        for name, low, high in (("iterations", *KDF_ITERATIONS), ("lanes", *KDF_LANES),
                                ("memory_cost", *KDF_MEMORY_KIB)):
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise Corrupted(f"header: kdf {name} outside the supported range {low}..{high}")
        if self.memory_cost < 8 * self.lanes:
            raise Corrupted("header: kdf memory_cost below 8 KiB per lane (RFC 9106)")


# Supported ranges, checked before any derivation (RFC 9106 option 1 uses 2 GiB, t=1).
KDF_ITERATIONS = (1, 16)
KDF_LANES = (1, 16)
KDF_MEMORY_KIB = (8, 2 * 1024 * 1024)
KDF_SALT_BYTES = (16, 64)


# RFC 9106 section 4 second recommended option is t=3, p=4, m=64 MiB; we use 4x the memory.
DEFAULT_KDF = KdfParams()
# Cheap parameters for tests only. Never use them for a real vault.
TEST_KDF = KdfParams(iterations=1, lanes=1, memory_cost=8)


def normalize_passphrase(passphrase: str) -> bytes:
    """NFC then UTF-8, so the same passphrase typed on two systems gives the same bytes."""
    if not isinstance(passphrase, str) or not passphrase:
        raise VaultError("passphrase must be a non-empty string")
    return unicodedata.normalize("NFC", passphrase).encode("utf-8")


def derive_passphrase_key(passphrase: str, salt: bytes, params: KdfParams) -> bytes:
    params.validate()
    if not KDF_SALT_BYTES[0] <= len(salt) <= KDF_SALT_BYTES[1]:
        raise Corrupted("header: kdf salt length outside the supported range")
    kdf = Argon2id(salt=salt, length=KEY_LEN, iterations=params.iterations, lanes=params.lanes,
                   memory_cost=params.memory_cost)
    return kdf.derive(normalize_passphrase(passphrase))


def hkdf(key: bytes, info: bytes, salt: bytes | None = None, length: int = KEY_LEN) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(key)


@dataclass
class Subkeys:
    content: bytes
    metadata: bytes
    aux: bytes
    aux_name: bytes
    identity: bytes
    license: bytes


def derive_subkeys(master_key: bytes, vault_id: bytes) -> Subkeys:
    """Purpose-separated keys: a leak or misuse of one never exposes another."""
    keys = {label: hkdf(master_key, b"empreinte/v1/subkey/" + label.encode("ascii"), salt=vault_id)
            for label in SUBKEY_LABELS}
    return Subkeys(content=keys["content"], metadata=keys["metadata"], aux=keys["aux"],
                   aux_name=keys["aux-name"], identity=keys["identity"], license=keys["license"])


# ------------------------------------------------------------------- key wrapping


def wrap(kek: bytes, secret: bytes, aad: bytes) -> dict:
    """AES-256-GCM with a random nonce. Used a handful of times per key, so a random nonce is safe."""
    nonce = random_bytes(NONCE_LEN)
    return {"alg": "AES-256-GCM", "nonce": nonce.hex(), "ciphertext": AESGCM(kek).encrypt(nonce, secret, aad).hex()}


def unwrap(kek: bytes, wrapped: dict, aad: bytes) -> bytes:
    """Raises InvalidTag (caller decides whether that means wrong passphrase or corruption)."""
    if wrapped.get("alg") != "AES-256-GCM":
        raise Corrupted("header: unsupported wrap algorithm")
    try:
        nonce = bytes.fromhex(wrapped["nonce"])
        ciphertext = bytes.fromhex(wrapped["ciphertext"])
    except (KeyError, TypeError, ValueError):
        raise Corrupted("header: malformed wrapped key") from None
    return AESGCM(kek).decrypt(nonce, ciphertext, aad)


def wrap_aad(purpose: str, vault_id: bytes, extra: bytes = b"") -> bytes:
    return b"empreinte/v1/wrap/" + purpose.encode("ascii") + b"\x00" + vault_id + extra


# ------------------------------------------------------------------------- blobs


def blob_binding(vault_id: bytes, label: str) -> bytes:
    """Where a blob belongs: the vault and a label such as 'content:<entry_id>:<version>'."""
    return vault_id + label.encode("ascii")


def seal_blob(subkey: bytes, blob_type: int, plaintext: bytes, binding: bytes) -> bytes:
    """Encrypt one blob.

    Each blob gets its own key, HKDF(subkey, salt=32 random bytes), and a random nonce.
    Nonce reuse would need two equal 256-bit salts, so it cannot happen in practice
    however many blobs are written.
    """
    if blob_type not in BLOB_TYPES:
        raise ValueError("unknown blob type")
    salt = random_bytes(SALT_LEN)
    nonce = random_bytes(NONCE_LEN)
    header = BLOB_MAGIC + bytes([FORMAT_VERSION, blob_type]) + salt + nonce
    key = hkdf(subkey, b"empreinte/v1/blob-key", salt=salt)
    aad = b"empreinte/v1/blob\x00" + header + binding
    return header + AESGCM(key).encrypt(nonce, plaintext, aad)


def open_blob(subkey: bytes, data: bytes, binding: bytes, blob_type: int, what: str = "blob") -> bytes:
    """Decrypt one blob. Raises Corrupted if it was altered or belongs elsewhere."""
    if len(data) < BLOB_HEADER_LEN + 16 or data[:4] != BLOB_MAGIC:
        raise Corrupted(f"{what}: not an Empreinte blob")
    if data[4] != FORMAT_VERSION:
        raise Corrupted(f"{what}: unsupported blob format version {data[4]}")
    if data[5] != blob_type:
        raise Corrupted(f"{what}: wrong blob type {data[5]}, expected {blob_type}")
    header = data[:BLOB_HEADER_LEN]
    salt = header[6:6 + SALT_LEN]
    nonce = header[6 + SALT_LEN:]
    key = hkdf(subkey, b"empreinte/v1/blob-key", salt=salt)
    aad = b"empreinte/v1/blob\x00" + header + binding
    try:
        return AESGCM(key).decrypt(nonce, data[BLOB_HEADER_LEN:], aad)
    except InvalidTag:
        raise Corrupted(f"{what}: authentication failed (altered, or moved from another place)") from None


def pack_payload(meta: bytes, body: bytes) -> bytes:
    """Plaintext of an entry blob: u32 big-endian length of meta, meta, body."""
    return struct.pack(">I", len(meta)) + meta + body


def unpack_payload(payload: bytes, what: str = "blob") -> tuple[bytes, bytes]:
    if len(payload) < 4:
        raise Corrupted(f"{what}: truncated payload")
    (n,) = struct.unpack(">I", payload[:4])
    if 4 + n > len(payload):
        raise Corrupted(f"{what}: truncated payload")
    return payload[4:4 + n], payload[4 + n:]


# ---------------------------------------------------------------- commitments


def commitment(salt: bytes, plaintext: bytes) -> str:
    """Hex SHA-256(salt || plaintext). The 32-byte random salt stops plaintext guessing."""
    return hashlib.sha256(salt + plaintext).hexdigest()


def name_mac(key: bytes, name: str) -> str:
    """Opaque file name for an aux key: HMAC-SHA256, so it reveals nothing about the name."""
    return hmac.new(key, name.encode("utf-8"), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------- identity


def new_identity() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def identity_from_raw(raw: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(raw)


def private_raw(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes_raw()


def public_hex(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    public = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return public.public_bytes_raw().hex()


def public_from_hex(value: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(value))


# ---------------------------------------------------------------- recovery key


def encode_recovery_key(key: bytes) -> str:
    """Base32 of key || first 2 bytes of SHA-256(key), in groups of 5, for a human to write down."""
    text = base64.b32encode(key + sha256(key)[:2]).decode("ascii").rstrip("=")
    return "-".join(text[i:i + 5] for i in range(0, len(text), 5))


def decode_recovery_key(text: str) -> bytes:
    """Raises VaultError on a malformed key or a typo caught by the checksum."""
    cleaned = "".join(ch for ch in str(text).upper() if ch.isalnum())
    cleaned += "=" * (-len(cleaned) % 8)
    try:
        raw = base64.b32decode(cleaned)
    except (ValueError, base64.binascii.Error):
        raise VaultError("recovery key is malformed") from None
    if len(raw) != KEY_LEN + 2 or sha256(raw[:KEY_LEN])[:2] != raw[KEY_LEN:]:
        raise VaultError("recovery key is malformed or mistyped")
    return raw[:KEY_LEN]


def recovery_kek(recovery_key: bytes, vault_id: bytes) -> bytes:
    # The recovery key is 256 random bits, so HKDF is enough: no stretching needed.
    return hkdf(recovery_key, b"empreinte/v1/recovery-wrap", salt=vault_id)
