#!/usr/bin/env python3
"""Standalone verifier of an Empreinte disclosure bundle.

Requirements: Python 3.11 or later and cryptography 49.0 or later (`pip install
"cryptography>=49"`); `certifi` is used when installed. Imports nothing from Empreinte.
An older cryptography is refused with a clear message (exit status 2): 45 added the
certificate path validation used here, 49 fixed a path-building denial of service.

    python verify_bundle.py BUNDLE_DIR [--tsa-ca ROOT.pem ...] [--json]

For the grant and for each licensed item it checks, from the bundle alone:
  * the content matches the commitment in the ledger record: SHA-256(salt || content);
  * the record is signed by the vault key given in the bundle (Ed25519);
  * the record is chained to the head of the ledger through the disclosed body digests,
    and the head is signed by the same key;
  * the bundle holds exactly the items listed in the signed grant, each once;
  * the outside timestamp, in one of three states:
      none      no anchor covers the record: the only date is the author's clock;
      claimed   a valid RFC 3161 token covers it, but its authority could not be
                authenticated (no trust root, or no valid certificate path): a claim;
      proven    a valid token whose signer has a valid certificate path to a trusted
                root at the asserted time: existence by that time is proven.
Trust roots: --tsa-ca when given, else the certifi bundle when certifi is installed, else
none (every timestamp is then at most "claimed").

Exit status 0 when every check passes (a "claimed" or "none" timestamp is not a failure,
it is reported as such), 1 when a check fails, 2 when the bundle cannot be read.

Safety: every file named by the manifest must be a plain relative path; it is opened
first, then the opened handle itself is checked (a regular file, whose real path is inside
the bundle), and read through that handle only, so swapping a file or directory for a
link between check and read cannot redirect it. Sizes are bounded (manifest 64 MiB, grant 1 MiB,
each item 1 GiB, hashed in chunks; at most 100000 items; tokens 256 KiB).

The token-checking section below is a verbatim copy of empreinte/anchor.py (the test
suite checks that they are identical). Format: docs/FORMAT.md of Empreinte.
"""
from __future__ import annotations

import argparse
import base64
import functools
import hashlib
import json
import os
import re
import stat
import sys
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Callable, Literal, Sequence

MIN_CRYPTOGRAPHY = (49, 0)
try:
    import cryptography
    _version = tuple(int(x) for x in cryptography.__version__.split(".")[:2] if x.isdigit())
except ImportError:
    _version = None
if _version is None or _version < MIN_CRYPTOGRAPHY:
    found = "not installed" if _version is None else f"version {cryptography.__version__} found"
    sys.stderr.write(f"verify_bundle.py needs the Python package cryptography >= 49.0 ({found}).\n"
                     'Install it with:  python -m pip install "cryptography>=49"\n')
    sys.exit(2)

from cryptography import x509  # noqa: E402 (after the version check, on purpose)
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.verification import Criticality, ExtensionPolicy, PolicyBuilder, Store, VerificationError

ZERO_HASH = "0" * 64
RECORD_PREFIX = b"empreinte/v1/record\x00"
GRANT_PREFIX = b"empreinte/v1/grant\x00"
LINE_FIELDS = ("seq", "kind", "entry_id", "version", "commitment", "cipher_hash", "size", "timestamp",
               "prev_hash", "record_hash", "signature")
_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z")
_HEX = re.compile(r"[0-9a-f]*")

MAX_MANIFEST_BYTES = 64 << 20
MAX_GRANT_BYTES = 1 << 20
MAX_ITEM_BYTES = 1 << 30
MAX_ITEMS = 100_000
MAX_RESPONSE_BYTES = 1 << 20
MAX_TOKEN_BYTES = 256 << 10
MAX_PROOF_CHARS = 4 * ((MAX_TOKEN_BYTES + 2) // 3)
MAX_CERTIFICATES = 16
MAX_CHAIN_DEPTH = 8
TokenState = Literal["proven", "claimed", "invalid"]


class AnchorError(Exception):
    pass


class BundleError(Exception):
    pass


# =============================================================================== DER
# Minimal DER (X.690) reader and writer: definite lengths, single-byte tags.

class DerError(ValueError):
    pass


@dataclass(frozen=True)
class Node:
    data: bytes
    tag: int
    start: int  # first byte of the tag
    body: int  # first byte of the contents
    end: int  # one past the last byte

    @property
    def raw(self) -> bytes:
        return self.data[self.start:self.end]

    @property
    def content(self) -> bytes:
        return self.data[self.body:self.end]

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)

    def children(self) -> list["Node"]:
        if not self.constructed:
            raise DerError("primitive value has no children")
        items, pos = [], self.body
        while pos < self.end:
            child = parse(self.data, pos, self.end)
            items.append(child)
            pos = child.end
        return items


def parse(data: bytes, pos: int = 0, limit: int | None = None) -> Node:
    limit = len(data) if limit is None else limit
    if pos + 2 > limit:
        raise DerError("truncated")
    tag = data[pos]
    if tag & 0x1F == 0x1F:
        raise DerError("multi-byte tags are not supported")
    first = data[pos + 1]
    body = pos + 2
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise DerError("indefinite length (BER) is not DER")
    else:
        count = first & 0x7F
        if count > 4 or body + count > limit:
            raise DerError("bad length")
        length = int.from_bytes(data[body:body + count], "big")
        body += count
    end = body + length
    if end > limit:
        raise DerError("truncated")
    return Node(data, tag, pos, body, end)


def parse_one(data: bytes) -> Node:
    node = parse(data)
    if node.end != len(data):
        raise DerError("trailing bytes")
    return node


def read_int(node: Node) -> int:
    if node.tag != 0x02:
        raise DerError("expected INTEGER")
    return int.from_bytes(node.content, "big", signed=True)


def read_oid(node: Node) -> str:
    if node.tag != 0x06:
        raise DerError("expected OBJECT IDENTIFIER")
    parts, value = [], 0
    for byte in node.content:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    if not parts:
        raise DerError("empty OID")
    first = parts[0]
    head = [0, first] if first < 40 else [1, first - 40] if first < 80 else [2, first - 80]
    return ".".join(str(p) for p in head + parts[1:])


def read_time(node: Node) -> datetime:
    """GeneralizedTime YYYYMMDDHHMMSS[.f*]Z (RFC 3161 requires UTC with 'Z')."""
    if node.tag != 0x18:
        raise DerError("expected GeneralizedTime")
    text = node.content.decode("ascii")
    if not text.endswith("Z") or len(text) < 15:
        raise DerError("genTime must be UTC")
    base = datetime.strptime(text[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    frac = text[14:-1]
    if frac:
        if not frac.startswith(".") or not frac[1:].isdigit():
            raise DerError("bad fraction in genTime")
        base = base.replace(microsecond=int((frac[1:] + "000000")[:6]))
    return base


def tlv(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + content


def enc_int(value: int) -> bytes:
    raw = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big", signed=True)
    return tlv(0x02, raw)


def enc_oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    values = [parts[0] * 40 + parts[1]] + parts[2:]
    out = bytearray()
    for value in values:
        chunk = [value & 0x7F]
        value >>= 7
        while value:
            chunk.append(0x80 | (value & 0x7F))
            value >>= 7
        out.extend(reversed(chunk))
    return tlv(0x06, bytes(out))


def enc_seq(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def enc_set(*items: bytes) -> bytes:
    return tlv(0x31, b"".join(sorted(items)))  # DER SET OF: sorted encodings


def enc_octets(value: bytes) -> bytes:
    return tlv(0x04, value)


def enc_bool(value: bool) -> bytes:
    return tlv(0x01, b"\xff" if value else b"\x00")


def enc_null() -> bytes:
    return b"\x05\x00"


def enc_gentime(value: datetime) -> bytes:
    value = value.astimezone(timezone.utc)
    text = value.strftime("%Y%m%d%H%M%S")
    if value.microsecond:
        text += "." + f"{value.microsecond:06d}".rstrip("0")
    return tlv(0x18, (text + "Z").encode("ascii"))


def explicit(number: int, content: bytes) -> bytes:
    return tlv(0xA0 | number, content)


# ====================================================================== RFC 3161

OID_SHA1 = "1.3.14.3.2.26"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SHA384 = "2.16.840.1.101.3.4.2.2"
OID_SHA512 = "2.16.840.1.101.3.4.2.3"
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_CERT = "1.2.840.113549.1.9.16.2.12"
OID_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47"
OID_RSA = "1.2.840.113549.1.1.1"
OID_RSA_PSS = "1.2.840.113549.1.1.10"
OID_MGF1 = "1.2.840.113549.1.1.8"
OID_ED25519 = "1.3.101.112"

# SHA-1 is refused for signatures and digests (collisions are practical); it is only used
# to identify a certificate in an ESS signing-certificate v1 attribute.
HASHES: dict[str, Callable[[], hashes.HashAlgorithm]] = {
    OID_SHA256: hashes.SHA256, OID_SHA384: hashes.SHA384, OID_SHA512: hashes.SHA512,
}
HASHLIB_NAMES = {OID_SHA1: "sha1", OID_SHA256: "sha256", OID_SHA384: "sha384", OID_SHA512: "sha512"}
RSA_PKCS1 = {"1.2.840.113549.1.1.11": OID_SHA256, "1.2.840.113549.1.1.12": OID_SHA384,
             "1.2.840.113549.1.1.13": OID_SHA512}
ECDSA = {"1.2.840.10045.4.3.2": OID_SHA256, "1.2.840.10045.4.3.3": OID_SHA384, "1.2.840.10045.4.3.4": OID_SHA512}

PKI_STATUS = {0: "granted", 1: "grantedWithMods", 2: "rejection", 3: "waiting", 4: "revocationWarning",
              5: "revocationNotification"}


def build_request(digest: bytes, nonce: int) -> bytes:
    """DER TimeStampReq: version 1, imprint (SHA-256, `digest` as is), nonce, certReq TRUE.

    The AlgorithmIdentifier carries NULL parameters, as `openssl ts -query` sends it.
    """
    if len(digest) != 32:
        raise ValueError("a SHA-256 digest is 32 bytes")
    imprint = enc_seq(enc_seq(enc_oid(OID_SHA256), enc_null()), enc_octets(digest))
    return enc_seq(enc_int(1), imprint, enc_int(nonce), enc_bool(True))


@dataclass
class TokenCheck:
    """Result of check_token. `errors` empty means the token is internally valid."""

    gen_time: datetime | None = None
    imprint: bytes = b""
    imprint_alg: str = ""
    nonce: int | None = None
    serial: int | None = None
    policy: str = ""
    signer: str = ""  # subject of the signer certificate
    signature_valid: bool = False
    chain_trusted: bool | None = None  # None: no trust root available at all
    trust_error: str = ""  # why the signer could not be authenticated
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    @property
    def state(self) -> TokenState:
        if self.errors:
            return "invalid"
        return "proven" if self.chain_trusted else "claimed"


@functools.lru_cache(maxsize=1)
def default_trust_roots() -> tuple[x509.Certificate, ...]:
    """The public CA bundle of the installed `certifi`, or () when it is not installed."""
    try:
        import certifi
    except ImportError:
        return ()
    with open(certifi.where(), "rb") as handle:
        data = handle.read()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # a few old roots have non-positive serial numbers
        return tuple(x509.load_pem_x509_certificates(data))


def _resolve_roots(trust_roots: Sequence[x509.Certificate] | None) -> list[x509.Certificate]:
    return list(default_trust_roots() if trust_roots is None else trust_roots)


def extract_token(response: bytes) -> bytes:
    """TimeStampResp -> DER TimeStampToken. Raises AnchorError if the authority refused."""
    if len(response) > MAX_RESPONSE_BYTES:
        raise AnchorError("timestamp response is too large")
    try:
        resp = parse_one(response)
        parts = resp.children()
        status_info = parts[0].children()
        status = read_int(status_info[0])
    except (DerError, IndexError, ValueError):
        raise AnchorError("timestamp response is not a valid TimeStampResp") from None
    if status not in (0, 1):
        text = ""
        if len(status_info) > 1 and status_info[1].tag == 0x30:
            try:
                text = "; ".join(c.content.decode("utf-8", "replace") for c in status_info[1].children())[:200]
            except DerError:
                text = ""
        raise AnchorError(f"timestamp authority answered {PKI_STATUS.get(status, status)}" + (f": {text}" if text else ""))
    if len(parts) < 2:
        raise AnchorError("timestamp response is granted but holds no token")
    return parts[1].raw


def check_token(token: bytes, expected_digest: bytes, *, nonce: int | None = None,
                trust_roots: Sequence[x509.Certificate] | None = None) -> TokenCheck:
    """Check that a DER TimeStampToken covers `expected_digest`. Never raises on bad input.

    `trust_roots` None means the default roots (certifi); an empty list means none.
    """
    result = TokenCheck()
    if len(token) > MAX_TOKEN_BYTES:
        result.errors.append("token is too large")
        return result
    try:
        _check_token(token, expected_digest, nonce, _resolve_roots(trust_roots), result)
    except (DerError, IndexError, ValueError, UnicodeDecodeError) as exc:
        result.errors.append(f"token is malformed ({str(exc)[:80] or type(exc).__name__})")
    return result


def _check_token(token: bytes, expected: bytes, nonce: int | None, roots: list[x509.Certificate],
                 result: TokenCheck) -> None:
    content_info = parse_one(token).children()
    if read_oid(content_info[0]) != OID_SIGNED_DATA or content_info[1].tag != 0xA0:
        raise DerError("not a CMS SignedData")
    signed_data = content_info[1].children()[0].children()
    encap = signed_data[2].children()
    if read_oid(encap[0]) != OID_TST_INFO:
        raise DerError("SignedData does not hold a TSTInfo")
    e_content = encap[1].children()[0]
    if e_content.tag != 0x04:
        raise DerError("eContent is not an OCTET STRING")
    tst_der = e_content.content

    tst = parse_one(tst_der).children()
    result.policy = read_oid(tst[1])
    imprint = tst[2].children()
    result.imprint_alg = read_oid(imprint[0].children()[0])
    result.imprint = imprint[1].content
    result.serial = read_int(tst[3])
    result.gen_time = read_time(tst[4])
    for item in tst[5:]:
        if item.tag == 0x02:
            result.nonce = read_int(item)
    if result.imprint_alg != OID_SHA256 or result.imprint != expected:
        result.errors.append("token does not cover this hash (messageImprint differs)")
    if nonce is not None and result.nonce != nonce:
        result.errors.append("token nonce does not match the request")

    certs: list[x509.Certificate] = []
    signer_infos = None
    for item in signed_data[3:]:
        if item.tag == 0xA0:
            raw_certs = [c for c in item.children() if c.tag == 0x30]
            if len(raw_certs) > MAX_CERTIFICATES:
                raise DerError("too many certificates")
            certs = [x509.load_der_x509_certificate(c.raw) for c in raw_certs]
        elif item.tag == 0x31:
            signer_infos = item.children()
    if not signer_infos or len(signer_infos) != 1:
        result.errors.append("token must have exactly one signer")
        return
    info = signer_infos[0].children()
    digest_oid = read_oid(info[2].children()[0])
    position = 3
    signed_attrs = None
    if info[position].tag == 0xA0:
        signed_attrs = info[position]
        position += 1
    sig_alg = info[position].children()
    signature = info[position + 1].content
    if signed_attrs is None:
        result.errors.append("signer has no signed attributes")
        return
    if digest_oid not in HASHES:
        result.errors.append(f"unsupported digest algorithm {digest_oid}")
        return

    signer = _find_signer(info[1], certs)
    if signer is None:
        result.errors.append("signer certificate not included in the token")
        return
    result.signer = signer.subject.rfc4514_string()

    attrs: dict[str, Node] = {}
    for attr in signed_attrs.children():
        parts = attr.children()
        attrs[read_oid(parts[0])] = parts[1].children()[0]
    if OID_CONTENT_TYPE not in attrs or read_oid(attrs[OID_CONTENT_TYPE]) != OID_TST_INFO:
        result.errors.append("content-type attribute is not id-ct-TSTInfo")
    tst_hash = hashlib.new(HASHLIB_NAMES[digest_oid], tst_der).digest()
    if OID_MESSAGE_DIGEST not in attrs or attrs[OID_MESSAGE_DIGEST].content != tst_hash:
        result.errors.append("messageDigest attribute does not match the TSTInfo")
    if not _ess_matches(attrs, signer):
        result.errors.append("signing-certificate attribute does not name the signer certificate")

    to_verify = b"\x31" + signed_attrs.raw[1:]  # signature covers the attributes as a SET OF
    try:
        verify_cms_signature(signer.public_key(), sig_alg, digest_oid, signature, to_verify)
        result.signature_valid = True
    except (InvalidSignature, ValueError, TypeError, KeyError, IndexError) as exc:
        result.errors.append(f"authority signature invalid ({str(exc)[:80] or type(exc).__name__})")

    _check_tsa_certificate(signer, result)
    if result.errors:
        return
    if not roots:
        result.chain_trusted = None
        result.trust_error = "no trusted root available (install certifi or give trust roots)"
        return
    problem = validate_path(signer, certs, roots, result.gen_time)
    result.chain_trusted = problem is None
    result.trust_error = problem or ""


def _find_signer(sid: Node, certs: list[x509.Certificate]) -> x509.Certificate | None:
    if sid.tag == 0x30:  # IssuerAndSerialNumber
        issuer_der, serial = sid.children()[0].raw, read_int(sid.children()[1])
        for cert in certs:
            if cert.serial_number == serial and cert.issuer.public_bytes() == issuer_der:
                return cert
    elif sid.tag == 0x80:  # [0] SubjectKeyIdentifier
        for cert in certs:
            try:
                ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
            except x509.ExtensionNotFound:
                continue
            if ski == sid.content:
                return cert
    return None


def _ess_matches(attrs: dict[str, Node], cert: x509.Certificate) -> bool:
    der = cert.public_bytes(Encoding.DER)
    if OID_SIGNING_CERT_V2 in attrs:
        first = attrs[OID_SIGNING_CERT_V2].children()[0].children()[0].children()
        alg = OID_SHA256
        if first[0].tag == 0x30:
            alg = read_oid(first[0].children()[0])
            first = first[1:]
        if alg not in HASHES:
            return False
        return first[0].content == hashlib.new(HASHLIB_NAMES[alg], der).digest()
    if OID_SIGNING_CERT in attrs:
        first = attrs[OID_SIGNING_CERT].children()[0].children()[0].children()
        return first[0].content == hashlib.sha1(der).digest()
    return False


def pss_parameters(params: Node | None) -> tuple[str, str, int]:
    """RSASSA-PSS-params (RFC 4055): (hash OID, MGF1 hash OID, salt length).

    Absent fields take the RFC defaults (SHA-1, MGF1-SHA-1, 20, trailer 1); SHA-1 is then
    refused like everywhere else. Unknown fields, another MGF or another trailer raise.
    """
    hash_oid, mgf_hash, salt, trailer = OID_SHA1, OID_SHA1, 20, 1
    if params is not None and params.tag != 0x05:
        for item in params.children():
            inner = item.children()[0]
            if item.tag == 0xA0:
                hash_oid = read_oid(inner.children()[0])
            elif item.tag == 0xA1:
                parts = inner.children()
                if read_oid(parts[0]) != OID_MGF1:
                    raise ValueError("RSA-PSS mask generation other than MGF1")
                mgf_hash = read_oid(parts[1].children()[0])
            elif item.tag == 0xA2:
                salt = read_int(inner)
            elif item.tag == 0xA3:
                trailer = read_int(inner)
            else:
                raise ValueError("unknown RSA-PSS parameter")
    if trailer != 1:
        raise ValueError("RSA-PSS trailer field must be 1")
    if hash_oid not in HASHES or mgf_hash not in HASHES:
        raise ValueError("RSA-PSS with an unsupported or SHA-1 hash")
    if not 0 <= salt <= 1024:
        raise ValueError("RSA-PSS salt length out of range")
    return hash_oid, mgf_hash, salt


def verify_cms_signature(key, sig_alg: list[Node], digest_oid: str, signature: bytes, data: bytes) -> None:
    """Verify a SignerInfo signature with the algorithm and parameters it declares."""
    sig_oid = read_oid(sig_alg[0])
    params = sig_alg[1] if len(sig_alg) > 1 else None
    if isinstance(key, rsa.RSAPublicKey):
        if sig_oid == OID_RSA or sig_oid in RSA_PKCS1:
            key.verify(signature, data, padding.PKCS1v15(), HASHES[RSA_PKCS1.get(sig_oid, digest_oid)]())
            return
        if sig_oid == OID_RSA_PSS:
            hash_oid, mgf_hash, salt = pss_parameters(params)
            key.verify(signature, data, padding.PSS(mgf=padding.MGF1(HASHES[mgf_hash]()), salt_length=salt),
                       HASHES[hash_oid]())
            return
    if isinstance(key, ec.EllipticCurvePublicKey) and sig_oid in ECDSA:
        key.verify(signature, data, ec.ECDSA(HASHES[ECDSA[sig_oid]]()))
        return
    if isinstance(key, ed25519.Ed25519PublicKey) and sig_oid == OID_ED25519:
        key.verify(signature, data)
        return
    raise ValueError(f"unsupported signature algorithm {sig_oid}")


def _check_tsa_certificate(cert: x509.Certificate, result: TokenCheck) -> None:
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        if not eku.critical or list(eku.value) != [ExtendedKeyUsageOID.TIME_STAMPING]:
            result.errors.append("signer certificate is not a TSA certificate (EKU must be critical timeStamping only)")
    except x509.ExtensionNotFound:
        result.errors.append("signer certificate has no extended key usage timeStamping")
    if result.gen_time and not (cert.not_valid_before_utc <= result.gen_time <= cert.not_valid_after_utc):
        result.errors.append("genTime is outside the validity of the signer certificate")


def _ee_eku(policy, cert, eku) -> None:
    if list(eku) != [ExtendedKeyUsageOID.TIME_STAMPING]:
        raise ValueError("TSA certificate EKU must be timeStamping only")


def _ca_eku(policy, cert, eku) -> None:
    if eku is not None and ExtendedKeyUsageOID.TIME_STAMPING not in eku \
            and ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE not in eku:
        raise ValueError("issuer EKU does not allow timeStamping")


def validate_path(signer: x509.Certificate, pool: Sequence[x509.Certificate], roots: Sequence[x509.Certificate],
                  when: datetime) -> str | None:
    """Certificate path validation by cryptography.x509.verification. None when valid."""
    ca_policy = ExtensionPolicy.webpki_defaults_ca().may_be_present(
        x509.ExtendedKeyUsage, Criticality.AGNOSTIC, _ca_eku)
    ee_policy = (ExtensionPolicy.webpki_defaults_ee()
                 .require_present(x509.ExtendedKeyUsage, Criticality.CRITICAL, _ee_eku)
                 .may_be_present(x509.SubjectAlternativeName, Criticality.AGNOSTIC, None))
    try:
        verifier = (PolicyBuilder().store(Store(list(roots))).time(when).max_chain_depth(MAX_CHAIN_DEPTH)
                    .extension_policies(ca_policy=ca_policy, ee_policy=ee_policy).build_client_verifier())
        verifier.verify(signer, [c for c in pool if c != signer])
    except (VerificationError, ValueError, TypeError) as exc:
        return f"certificate path not valid ({str(exc).split(' (encountered')[0][:160]})"
    return None


# ======================================================================== ledger


def canonical_body(record: dict, key_hex: str) -> bytes:
    """Same bytes as empreinte.ledger.canonical_body (docs/FORMAT.md, "Ledger")."""
    if not isinstance(record, dict) or set(record) != set(LINE_FIELDS):
        raise BundleError("record has the wrong set of fields")
    for name in ("seq", "version", "size"):
        if type(record[name]) is not int or record[name] < 0:
            raise BundleError(f"record field {name} is not a non-negative integer")
    for name in ("entry_id", "commitment", "cipher_hash", "kind", "prev_hash", "record_hash", "signature"):
        if not isinstance(record[name], str) or not record[name].isascii():
            raise BundleError(f"record field {name} is not ASCII text")
    if not isinstance(record["timestamp"], str) or not _TIME.fullmatch(record["timestamp"]):
        raise BundleError("record timestamp is not canonical")
    body = {"cipher_hash": record["cipher_hash"], "commitment": record["commitment"], "entry_id": record["entry_id"],
            "format": 1, "key": key_hex, "kind": record["kind"], "seq": record["seq"], "size": record["size"],
            "timestamp": record["timestamp"], "version": record["version"]}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def hexbytes(value: object, length: int, what: str) -> bytes:
    if not isinstance(value, str) or len(value) != 2 * length or not _HEX.fullmatch(value):
        raise BundleError(f"{what} is not {length} bytes of lowercase hex")
    return bytes.fromhex(value)


def signed(key: ed25519.Ed25519PublicKey, signature_hex: str, message: bytes) -> bool:
    try:
        key.verify(hexbytes(signature_hex, 64, "signature"), message)
        return True
    except (InvalidSignature, BundleError):
        return False


# ========================================================================= files


def _handle_path(fd: int) -> str | None:
    """Real path of an open file, from the handle itself (not from a name looked up again)."""
    if os.name == "nt":
        import ctypes
        import msvcrt
        from ctypes import wintypes
        buffer = ctypes.create_unicode_buffer(32768)
        n = ctypes.windll.kernel32.GetFinalPathNameByHandleW(wintypes.HANDLE(msvcrt.get_osfhandle(fd)),
                                                             buffer, 32768, 0)
        if not 0 < n < 32768:
            return None
        path = buffer.value
        if path.startswith("\\\\?\\UNC\\"):
            return "\\\\" + path[8:]
        return path[4:] if path.startswith("\\\\?\\") else path
    for link in (f"/proc/self/fd/{fd}", f"/dev/fd/{fd}"):
        try:
            target = os.readlink(link)
        except OSError:
            continue
        if target.startswith("/"):
            return target
    if sys.platform == "darwin":
        import fcntl
        raw = fcntl.fcntl(fd, 50, b"\0" * 1024)  # F_GETPATH
        return raw.split(b"\0", 1)[0].decode("utf-8", "surrogateescape") or None
    return None


def open_bundle_file(bundle: Path, name: object, limit: int):
    """Open `name` inside the bundle and return the file object, checked after opening.

    The name must be plain and relative; the opened handle must be a regular file of at
    most `limit` bytes whose real path is inside the bundle directory. Reading happens
    through this handle only.
    """
    if not isinstance(name, str) or not name or "\\" in name or "\x00" in name:
        raise BundleError(f"file name {str(name)[:80]!r} is not a plain relative path")
    posix, windows = PurePosixPath(name), PureWindowsPath(name)
    if not posix.parts or posix.is_absolute() or windows.is_absolute() or windows.drive or ".." in posix.parts:
        raise BundleError(f"file name {name[:80]!r} leaves the bundle")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(bundle / posix, flags)
    except OSError:
        raise BundleError(f"{name[:80]} is missing or cannot be opened (links are refused)") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise BundleError(f"{name[:80]} is not a regular file")
        if info.st_size > limit:
            raise BundleError(f"{name[:80]} is larger than {limit} bytes")
        real = _handle_path(fd)
        if real is None:
            raise BundleError(f"{name[:80]}: cannot tell where the opened file is; refused")
        root = os.path.normcase(os.path.realpath(bundle))
        if not os.path.normcase(real).startswith(root.rstrip(os.sep) + os.sep):
            raise BundleError(f"{name[:80]} resolves outside the bundle")
        if os.name != "nt" and hasattr(os, "O_NONBLOCK"):
            os.set_blocking(fd, True)
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def read_bundle_file(bundle: Path, name: object, limit: int) -> bytes:
    with open_bundle_file(bundle, name, limit) as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise BundleError(f"{str(name)[:80]} is larger than {limit} bytes")
    return data


def salted_hash(salt: bytes, bundle: Path, name: object, limit: int) -> str:
    digest = hashlib.sha256(salt)
    total = 0
    with open_bundle_file(bundle, name, limit) as handle:
        while chunk := handle.read(1 << 20):
            total += len(chunk)
            if total > limit:
                raise BundleError(f"{str(name)[:80]} is larger than {limit} bytes")
            digest.update(chunk)
    return digest.hexdigest()


# ========================================================================= bundle


@dataclass
class Verdict:
    name: str
    seq: int = -1
    content_ok: bool = False
    signed_ok: bool = False
    chained_ok: bool = False
    listed_ok: bool = True
    ledger_time: str = ""
    timestamp: str = "none"  # "none", "claimed" or "proven"
    proven_before: datetime | None = None
    proven_by: str = ""
    claimed_before: datetime | None = None
    claimed_by: str = ""
    claim_reason: str = ""
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.content_ok and self.signed_ok and self.chained_ok and self.listed_ok and not self.problems


def verify(bundle: Path, roots: list[x509.Certificate]) -> dict:
    """Check a bundle; return a report dict (see main() for how it is printed)."""
    manifest = json.loads(read_bundle_file(bundle, "manifest.json", MAX_MANIFEST_BYTES))
    if not isinstance(manifest, dict) or manifest.get("format") != "empreinte-bundle" \
            or manifest.get("format_version") != 1:
        raise BundleError("not an Empreinte bundle of format version 1")
    key_hex = manifest["public_key"]
    key = ed25519.Ed25519PublicKey.from_public_bytes(hexbytes(key_hex, 32, "public key"))
    general: list[str] = []

    # Chain: h[s] for s in from_seq..head.
    chain = manifest["chain"]
    first = chain["from_seq"]
    if type(first) is not int or first < 0:
        raise BundleError("chain.from_seq is not a non-negative integer")
    digests = [hexbytes(d, 32, "body digest") for d in chain["body_digests"]]
    hashes_by_seq: dict[int, str] = {first - 1: chain["prev_hash"]}
    current = hexbytes(chain["prev_hash"], 32, "chain prev_hash")
    for offset, digest in enumerate(digests):
        current = hashlib.sha256(current + digest).digest()
        hashes_by_seq[first + offset] = current.hex()
    head = manifest["head"]
    last = first + len(digests) - 1
    head_ok = head.get("seq") == last and hashes_by_seq.get(last) == head.get("record_hash")
    if not head_ok:
        general.append("the disclosed digests do not lead to the head record hash")
    if not signed(key, head.get("signature"), RECORD_PREFIX + hexbytes(head.get("record_hash"), 32, "head hash")):
        head_ok = False
        general.append("the head record is not signed by this key")

    # Anchors: which records they cover, and in which state.
    anchors = []
    for index, anchor in enumerate(manifest.get("anchors", [])):
        seq = anchor["seq_upto"]
        problems = []
        if type(seq) is not int or seq < first or hashes_by_seq.get(seq) != anchor["head_hash"]:
            problems.append("its head hash is not on the disclosed chain")
        try:
            proof = anchor["proof"]
            if not isinstance(proof, str) or len(proof) > MAX_PROOF_CHARS:
                raise ValueError("proof too large")
            token = base64.b64decode(proof, validate=True)
        except (ValueError, TypeError):
            token = b""
        check = check_token(token, hexbytes(anchor["head_hash"], 32, "anchor hash"), trust_roots=roots)
        problems += check.errors
        if check.gen_time and anchor.get("anchored_at") and \
                datetime.fromisoformat(str(anchor["anchored_at"]).replace("Z", "+00:00")) != check.gen_time:
            problems.append("anchored_at differs from the time in the token")
        state = "invalid" if problems else check.state
        anchors.append({"index": index, "seq_upto": seq, "authority": str(anchor.get("authority", ""))[:200],
                        "gen_time": check.gen_time, "signer": check.signer, "state": state,
                        "trust_error": check.trust_error, "problems": problems})
        for problem in problems:
            general.append(f"anchor {index} (record {seq}): {problem}")

    def check_record(verdict: Verdict, record: dict, kind: str) -> None:
        try:
            body = canonical_body(record, key_hex)
            prev = hexbytes(record["prev_hash"], 32, "prev_hash")
        except BundleError as exc:
            verdict.problems.append(str(exc))
            return
        seq = record["seq"]
        verdict.seq = seq
        verdict.ledger_time = record["timestamp"]
        if record["kind"] != kind:
            verdict.problems.append(f"record {seq} is of kind {record['kind']}, expected {kind}")
        digest = hashlib.sha256(body).digest()
        offset = seq - first
        record_hash = hashlib.sha256(prev + digest).hexdigest()
        verdict.chained_ok = (head_ok and 0 <= offset < len(digests) and digests[offset] == digest
                              and hashes_by_seq.get(seq - 1) == record["prev_hash"]
                              and hashes_by_seq.get(seq) == record_hash == record["record_hash"])
        verdict.signed_ok = record_hash == record["record_hash"] and signed(
            key, record["signature"], RECORD_PREFIX + bytes.fromhex(record_hash))
        if not verdict.chained_ok:
            return
        covering = [a for a in anchors if isinstance(a["seq_upto"], int) and a["seq_upto"] >= seq
                    and a["state"] != "invalid" and a["gen_time"]]
        proven = [a for a in covering if a["state"] == "proven"]
        claimed = [a for a in covering if a["state"] == "claimed"]
        if proven:
            best = min(proven, key=lambda a: a["gen_time"])
            verdict.timestamp, verdict.proven_before, verdict.proven_by = "proven", best["gen_time"], best["signer"]
        if claimed:
            best = min(claimed, key=lambda a: a["gen_time"])
            verdict.claimed_before, verdict.claimed_by = best["gen_time"], best["authority"]
            verdict.claim_reason = best["trust_error"]
            if not proven:
                verdict.timestamp = "claimed"

    # Grant.
    grant_info = manifest["grant"]
    grant_bytes = read_bundle_file(bundle, grant_info["file"], MAX_GRANT_BYTES)
    grant_verdict = Verdict(name="grant")
    grant_record = grant_info["record"]
    check_record(grant_verdict, grant_record, "license")
    salt = hexbytes(grant_info["salt"], 32, "grant salt")
    grant_verdict.content_ok = hashlib.sha256(salt + grant_bytes).hexdigest() == grant_record.get("commitment")
    if not signed(key, grant_info["signature"], GRANT_PREFIX + grant_bytes):
        grant_verdict.problems.append("grant signature by the vault key is invalid")
    try:
        grant = json.loads(grant_bytes)
        if not isinstance(grant, dict):
            raise ValueError
    except ValueError:
        grant = {}
        grant_verdict.problems.append("grant.json is not a JSON object")
    if grant.get("license_id") != manifest.get("license_id") or grant.get("seq") != grant_record.get("seq"):
        grant_verdict.problems.append("grant does not match the manifest (license id or record)")
    granted = [(i.get("entry_id"), i.get("version"), i.get("commitment")) for i in grant.get("items", [])
               if isinstance(i, dict)]
    if len(set(granted)) != len(granted):
        general.append("the grant lists an item twice")

    # Items: exactly the granted set, each once.
    items = manifest["items"]
    if not isinstance(items, list) or len(items) > MAX_ITEMS:
        raise BundleError("manifest items is not a list of a reasonable size")
    item_verdicts = []
    disclosed = []
    for number, item in enumerate(items, start=1):
        verdict = Verdict(name=f'item {number} "{str(item.get("title", ""))[:120]}" '
                               f'({str(item.get("entry_id"))[:32]} v{item.get("version")})')
        record = item["record"]
        check_record(verdict, record, "put")
        try:
            verdict.content_ok = salted_hash(hexbytes(item["salt"], 32, "salt"), bundle, item["file"],
                                             MAX_ITEM_BYTES) == record.get("commitment")
        except (OSError, BundleError) as exc:
            verdict.problems.append(f"content unreadable ({exc})")
        if (record.get("entry_id"), record.get("version")) != (item["entry_id"], item["version"]):
            verdict.problems.append("record is about another entry or version")
        identity = (item["entry_id"], item["version"], record.get("commitment"))
        if identity in disclosed:
            verdict.problems.append("this item appears twice in the bundle")
        disclosed.append(identity)
        verdict.listed_ok = identity in granted
        item_verdicts.append(verdict)
    missing = set(granted) - set(disclosed)
    if missing:
        general.append(f"{len(missing)} item(s) listed in the grant are not in the bundle")

    ok = not general and grant_verdict.ok and all(v.ok for v in item_verdicts)
    return {"ok": ok, "manifest": manifest, "grant": grant, "grant_verdict": grant_verdict, "items": item_verdicts,
            "anchors": anchors, "general": general, "head": head, "roots": len(roots)}


def _yes(value: bool) -> str:
    return "yes" if value else "NO"


def _describe(verdict: Verdict, lines: list[str], what: str) -> None:
    lines.append(f"{verdict.name}: {'OK' if verdict.ok else 'FAILED'}")
    lines.append(f"  {what} matches the commitment: {_yes(verdict.content_ok)}")
    lines.append(f"  record {verdict.seq} signed by this key: {_yes(verdict.signed_ok)}")
    lines.append(f"  chained to the head: {_yes(verdict.chained_ok)}")
    if not verdict.listed_ok:
        lines.append("  listed in the grant: NO")
    if verdict.timestamp == "proven":
        lines.append(f"  outside timestamp: PROVEN, existed by {verdict.proven_before.isoformat()} "
                     f"(authenticated authority: {verdict.proven_by})")
    if verdict.claimed_before and (verdict.timestamp == "claimed" or verdict.claimed_before < verdict.proven_before):
        lines.append(f"  outside timestamp: CLAIMED ONLY, existence by {verdict.claimed_before.isoformat()} is "
                     f"asserted by an authority that could not be authenticated ({verdict.claim_reason}); "
                     f"it names itself {verdict.claimed_by}")
    if verdict.timestamp == "none":
        lines.append(f"  outside timestamp: NONE; recorded {verdict.ledger_time} by the author's own clock "
                     "(proves order, not date)")
    for problem in verdict.problems:
        lines.append(f"  problem: {problem}")


def render(report: dict) -> str:
    grant = report["grant"]
    roots = report["roots"]
    lines = ["Empreinte bundle verification", "",
             f"License {report['manifest'].get('license_id')} to {str(grant.get('licensee', '?'))[:200]}",
             f"Usage: {str(grant.get('usage', '?'))[:500]}",
             f"Vault key (Ed25519): {report['manifest']['public_key']}",
             f"Head: record {report['head'].get('seq')}, {report['head'].get('record_hash')}",
             f"Timestamp trust roots: {roots} certificate(s)" if roots else
             "Timestamp trust roots: none (give --tsa-ca or install certifi); timestamps can only be claims", ""]
    _describe(report["grant_verdict"], lines, "grant")
    for verdict in report["items"]:
        _describe(verdict, lines, "content")
    for problem in report["general"]:
        lines.append(f"problem: {problem}")
    lines += ["", "VERDICT: " + ("ALL CHECKS PASSED" if report["ok"] else "FAILED")]
    return "\n".join(lines) + "\n"


def _summary(verdict: Verdict) -> dict:
    def iso(value):
        return value.isoformat() if value else None
    return {"name": verdict.name, "ok": verdict.ok, "content": verdict.content_ok, "signed": verdict.signed_ok,
            "chained": verdict.chained_ok, "listed": verdict.listed_ok,
            "timestamp": {"state": verdict.timestamp, "proven_before": iso(verdict.proven_before),
                          "proven_by": verdict.proven_by or None, "claimed_before": iso(verdict.claimed_before),
                          "claimed_by": verdict.claimed_by or None, "claim_reason": verdict.claim_reason or None,
                          "ledger_time": verdict.ledger_time},
            "problems": verdict.problems}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify an Empreinte disclosure bundle.")
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--tsa-ca", action="append", default=[], type=Path,
                        help="PEM file of a trusted timestamp authority root (repeatable); replaces certifi")
    parser.add_argument("--json", action="store_true", help="print a JSON summary")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # titles are Unicode, whatever the code page
    try:
        if args.tsa_ca:
            roots = [cert for path in args.tsa_ca for cert in x509.load_pem_x509_certificates(path.read_bytes())]
        else:
            roots = list(default_trust_roots())
        report = verify(args.bundle, roots)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, BundleError) as exc:
        print(f"cannot read the bundle: {exc}", file=sys.stderr)
        return 2
    if args.json:
        summary = {"ok": report["ok"], "trust_roots": report["roots"], "general": report["general"],
                   "items": [_summary(v) for v in [report["grant_verdict"]] + report["items"]],
                   "anchors": [{"index": a["index"], "seq_upto": a["seq_upto"], "state": a["state"],
                                "time": a["gen_time"].isoformat() if a["gen_time"] else None,
                                "signer": a["signer"], "trust_error": a["trust_error"] or None,
                                "problems": a["problems"]} for a in report["anchors"]]}
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    else:
        sys.stdout.write(render(report))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
