"""External anchoring of the chain head by RFC 3161 trusted timestamping.

What is sent out: a TimeStampReq whose messageImprint has hashAlgorithm SHA-256 and
hashedMessage = the 32 raw bytes of the head record_hash (not hashed again: the
record_hash is already SHA-256(prev_hash || body_digest)), a random nonce and certReq
TRUE. A third party can check the token with `openssl ts -verify -digest <head_hash>`.

A token ends in one of three states, kept distinct everywhere:
  * "invalid": it does not prove anything (see the checks below); never used;
  * "claimed": internally valid, but its signer could not be authenticated (no trust root
    given or found, or the certificate path is not valid): a date claimed by an
    unauthenticated party;
  * "proven": internally valid AND the signer certificate has a valid path to a trusted
    root at genTime: the date is asserted by an authenticated authority.

Who checks what:
  * by this module (hand-written, the `cryptography` package has no CMS verifier): DER
    parsing; response status; SignedData holding a TSTInfo; imprint algorithm SHA-256 and
    hashedMessage equal to our head hash; nonce; content-type and messageDigest signed
    attributes; the signature over the signed attributes with the embedded signer
    certificate's key (RSA PKCS#1 v1.5, RSA-PSS with its encoded parameters enforced,
    ECDSA, Ed25519; SHA-1 refused); the ESS signing-certificate attribute naming that
    certificate; the signer certificate's extended key usage (critical, timeStamping
    only, RFC 3161 section 2.3) and validity at genTime;
  * by `cryptography.x509.verification` (PolicyBuilder, client verifier, time = genTime):
    path building to the trust store, every certificate signature, validity periods,
    BasicConstraints cA on issuers, keyUsage keyCertSign on issuers, path length
    constraints, name constraints, rejection of unknown critical extensions, and the web
    PKI defaults for algorithms and key sizes. Two web PKI rules are adjusted here, through
    its ExtensionPolicy API: a TSA certificate needs no subjectAltName, and the extended
    key usage rule is "critical, timeStamping only" for the signer and "absent, or
    containing timeStamping or anyExtendedKeyUsage" for issuers.
  * not checked by anyone: revocation (OCSP, CRL) and certificate policies.

Default trust roots: the public CA bundle of the installed `certifi` package (DigiCert
Trusted Root G4, root of the default authority, is in it). `trust_roots` overrides it.

The transport is injectable. The default one makes an HTTP POST: it is never called
unless the user explicitly asks for an anchor.
"""
from __future__ import annotations

import base64
import functools
import hashlib
import secrets
import urllib.request
import warnings

import cryptography

# x509.verification.ExtensionPolicy arrived in 45; 49 also fixes the duplicate-certificate
# path-building denial of service (GHSA-jwv3-5hgf-82ww). pyproject.toml requires >= 49.
MIN_CRYPTOGRAPHY = (49, 0)
if tuple(int(x) for x in cryptography.__version__.split(".")[:2] if x.isdigit()) < MIN_CRYPTOGRAPHY:
    raise ImportError(f"empreinte needs cryptography >= 49.0, found {cryptography.__version__}")
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Literal, Sequence

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.verification import Criticality, ExtensionPolicy, PolicyBuilder, Store, VerificationError

from .api import VaultError
from .model import Anchor

# The default authority. Documented by DigiCert as its RFC 3161 timestamping URL (plain
# HTTP; the token is signed, and only a hash is sent). Its chain goes up to
# "DigiCert Trusted Root G4". Untested live: no request has ever been sent from here.
DEFAULT_TSA_URL = "http://timestamp.digicert.com"
DIGICERT_ROOT_NAME = "DigiCert Trusted Root G4"

MAX_RESPONSE_BYTES = 1 << 20  # a TimeStampResp with a full chain is a few KiB
MAX_TOKEN_BYTES = 256 << 10
MAX_PROOF_CHARS = 4 * ((MAX_TOKEN_BYTES + 2) // 3)  # base64 of the largest accepted token
MAX_CERTIFICATES = 16
MAX_CHAIN_DEPTH = 8

Transport = Callable[[str, bytes], bytes]
TokenState = Literal["proven", "claimed", "invalid"]


class AnchorError(VaultError):
    """The authority refused, or its token does not prove what it should."""


def http_transport(url: str, body: bytes, timeout: float = 30.0) -> bytes:
    """POST a DER TimeStampReq (RFC 3161 section 3.4). This is the only network code."""
    request = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/timestamp-query",
        "Accept": "application/timestamp-reply",
    })
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 (explicit user action)
        data = response.read(MAX_RESPONSE_BYTES + 1)
    if len(data) > MAX_RESPONSE_BYTES:
        raise AnchorError("timestamp response is too large")
    return data


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


# ===================================================================== vault side


@dataclass
class TokenAssessment:
    """What one stored anchor proves, re-checked now."""

    state: TokenState
    time: datetime | None  # the authority's genTime (None when invalid)
    signer: str = ""
    trust_error: str = ""
    errors: list[str] = field(default_factory=list)


def request_anchor(head_hash: str, seq_upto: int, *, url: str = DEFAULT_TSA_URL, transport: Transport | None = None,
                   trust_roots: Sequence[x509.Certificate] | None = None, require_trusted: bool = True) -> Anchor:
    """Timestamp `head_hash` at `url`.

    Raises AnchorError if the token is invalid, or (by default) if its authority cannot be
    authenticated: an HTTP intermediary could otherwise invent both certificate and date.
    """
    digest = bytes.fromhex(head_hash)
    nonce = secrets.randbits(63) | 1  # positive, never zero
    send = transport or http_transport
    response = send(url, build_request(digest, nonce))
    token = extract_token(response)
    check = check_token(token, digest, nonce=nonce, trust_roots=trust_roots)
    if not check.ok:
        raise AnchorError("timestamp token rejected: " + "; ".join(check.errors))
    if require_trusted and not check.chain_trusted:
        raise AnchorError("timestamp authority could not be authenticated: " + check.trust_error)
    return Anchor(seq_upto=seq_upto, head_hash=head_hash, method="rfc3161", authority=url,
                  anchored_at=check.gen_time, proof=base64.b64encode(token).decode("ascii"))


def assess_anchor(anchor: Anchor, trust_roots: Sequence[x509.Certificate] | None = None) -> TokenAssessment:
    """Re-check a stored anchor: proven, claimed (unauthenticated authority) or invalid."""
    if anchor.method != "rfc3161":
        return TokenAssessment("invalid", None, errors=[f"method {anchor.method} cannot be checked"])
    if len(anchor.proof) > MAX_PROOF_CHARS:
        return TokenAssessment("invalid", None, errors=["proof is larger than any accepted token; not decoded"])
    try:
        token = base64.b64decode(anchor.proof, validate=True)
        digest = bytes.fromhex(anchor.head_hash)
    except ValueError:
        return TokenAssessment("invalid", None, errors=["proof or head hash is not decodable"])
    check = check_token(token, digest, trust_roots=trust_roots)
    errors = list(check.errors)
    if check.gen_time is not None and anchor.anchored_at != check.gen_time:
        errors.append("anchored_at differs from the time in the token")
    if errors:
        return TokenAssessment("invalid", None, signer=check.signer, errors=errors)
    return TokenAssessment(check.state, check.gen_time, signer=check.signer, trust_error=check.trust_error)


def check_anchor(anchor: Anchor, trust_roots: Sequence[x509.Certificate] | None = None) -> list[str]:
    """Errors that make an anchor invalid (empty for a proven or claimed anchor)."""
    return assess_anchor(anchor, trust_roots).errors
