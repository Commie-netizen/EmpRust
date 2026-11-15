"""RFC 3161 anchoring. No test makes a network request.

Two kinds of tokens are used:
* FakeTSA builds TimeStampResp structures with `cryptography` (ECDSA P-256 keys);
* OPENSSL_RESPONSE is a real RFC 3161 response produced offline by OpenSSL 3.5.9
  (`openssl ts -query -digest ... -sha256 -cert`, then `openssl ts -reply` with a
  throwaway RSA-2048 CA and TSA certificate whose EKU is critical timeStamping, and
  ess_cert_id_alg = sha256). `openssl ts -verify -digest OPENSSL_DIGEST -in resp.tsr
  -CAfile ca.pem` printed "Verification: OK" for it. It checks the parser against an
  independent implementation, with RSA PKCS#1 v1.5 and two embedded certificates.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from empreinte import anchor as A
from empreinte import crypto
from empreinte.api import Corrupted as Corrupted_
from empreinte.api import VaultError
from empreinte.testing import stepping_clock
from empreinte.vault import Vault

OPENSSL_DIGEST = bytes.fromhex("5f2b51ca2fdc5baa31ec02e002f69aec382bfb4b0b0f0e56bbbe0d6e0d2b7f1c")
OPENSSL_QUERY = bytes.fromhex(  # `openssl ts -query -digest 00..01 -sha256 -cert`, nonce a8a4cba721a600bd
    "30440201013031300d0609608648016503040201050004200000000000000000000000000000000000000000000000000000000000"
    "000001020900a8a4cba721a600bd0101ff")
OPENSSL_RESPONSE = base64.b64decode(
    "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")
OPENSSL_CA = b"""-----BEGIN CERTIFICATE-----
MIIDDjCCAfagAwIBAgIUDt9JT3eim5osoiLJZPcSaBWdLWkwDQYJKoZIhvcNAQEL
BQAwHjEcMBoGA1UEAwwTRW1wcmVpbnRlIFRlc3QgUm9vdDAgFw0yNjExMTQxMzQ1
MzJaGA8yMTI2MTAyMTEzNDUzMlowHjEcMBoGA1UEAwwTRW1wcmVpbnRlIFRlc3Qg
Um9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALrNN5c2Owp6U5HC
rKjjcK8E2HcRILGeTZl70wU2dZ7OxoZsS7pylDItWNyQxhLoFyiVHWlX9w8G+gzb
AvsiqKwyQA94W4piOY4/RPQD8gyGB5PLRlf9JZPtIiwy0Qv9lic5pdQAqZfNxlAF
u0hOEToXc3sKPsuDy8RluzcvdKcyyloZ14tdDWNdjch0ydnnDIAj/cFIm5StfBTJ
CZRfO7oPp4zPAtY52ulSVYZakjMZlibBKQ1yI6hI4AGkQR0JBcLgPvhEuSzhBfes
mHBaVoBBE2/cC78gPdX0X6duzpaUSBKUsWVtDDGDAmzUoK/y7UHS56WWiEI8e/02
QY6W4skCAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw
HQYDVR0OBBYEFGoqRY5NHkYNpzF5+RaLTdi75TSGMA0GCSqGSIb3DQEBCwUAA4IB
AQBI6xToK7D/W8r9UmFecGKYtKs88CiAL2Itr2vAAH/zRg6aNELOaiyNUJ2mPR+G
j8t163bHPFi/lGcmBfiNBxn+T1HofFHN/J9Z3491pj0DAMEHJDFOqewKUxB7iftK
u8EKzqDPPjLV8LJqV9U3arCLrfk4l2LjfmidXtptywzxGA4N9+vV0QKDMul80y/5
4597wcrbuSdsB2jg9aPZD7GZXZZIG7hTOLgeOmz1xE43IgJGz0CAaZYRwO2aaPtc
bwkmon+aIIVA+B18EeR8j8GkO9ONNNBeB+FhrjP7lwvKaOiqzTBi76G60z/HMHcy
pmWToRrt81JHFyCLuTdl+BK6
-----END CERTIFICATE-----
"""
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
OPENSSL_PSS_CMS = base64.b64decode(  # see the module docstring: CMS RSA-PSS (SHA-256, MGF1-SHA-384, salt 32)
    "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")

CA_USAGE = x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                         data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                         encipher_only=False, decipher_only=False)
EE_USAGE = x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                         data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                         encipher_only=False, decipher_only=False)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject: str, key, issuer: str, issuer_key, *, ca: bool, eku: bool = True, usage=None,
          path_length: int | None = None, not_before: datetime | None = None) -> x509.Certificate:
    start = not_before or datetime(2020, 1, 1, tzinfo=timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(_name(issuer))
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(start).not_valid_after(start + timedelta(days=3650))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length if ca else None), critical=True)
               .add_extension(usage or (CA_USAGE if ca else EE_USAGE), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    if subject != issuer:
        builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                                        critical=False)
    if not ca and eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
    return builder.sign(issuer_key, hashes.SHA256())


class FakeTSA:
    """A transport answering like an RFC 3161 authority, with knobs to misbehave.

    chain: "direct" (root -> TSA), "ee-issuer" (root -> an end-entity certificate that
    illegitimately issues the TSA certificate, finding 1), "no-certsign" (an issuing CA
    without keyCertSign), "pathlen" (a CA with pathLen 0 above another CA).
    pss: sign with RSA-PSS; `declared_salt` lets the token declare another salt length.
    """

    def __init__(self, when: datetime = datetime(2026, 3, 1, 12, 0, 0, 500000, tzinfo=timezone.utc), *,
                 eku: bool = True, chain: str = "direct", pss: bool = False, salt: int = 32,
                 declared_salt: int | None = None, mgf_hash: str = A.OID_SHA256):
        self.when = when
        self.pss, self.salt, self.mgf_hash = pss, salt, mgf_hash
        self.declared_salt = salt if declared_salt is None else declared_salt
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.root = _cert("Fake Root", self.root_key, "Fake Root", self.root_key, ca=True)
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048) if pss \
            else ec.generate_private_key(ec.SECP256R1())
        self.intermediates: list[x509.Certificate] = []
        if chain == "direct":
            self.cert = _cert("Fake TSA", self.key, "Fake Root", self.root_key, ca=False, eku=eku)
        else:
            mid_key = ec.generate_private_key(ec.SECP256R1())
            if chain == "ee-issuer":
                mid = _cert("Some End Entity", mid_key, "Fake Root", self.root_key, ca=False, eku=True)
            elif chain == "no-certsign":
                mid = _cert("Some End Entity", mid_key, "Fake Root", self.root_key, ca=True, usage=EE_USAGE)
            else:  # pathlen
                top_key = mid_key
                top = _cert("Top CA", top_key, "Fake Root", self.root_key, ca=True, path_length=0)
                mid_key = ec.generate_private_key(ec.SECP256R1())
                mid = _cert("Some End Entity", mid_key, "Top CA", top_key, ca=True)
                self.intermediates.append(top)
            self.intermediates.insert(0, mid)
            self.cert = _cert("Fake TSA", self.key, "Some End Entity", mid_key, ca=False, eku=eku)
        self.requests: list[bytes] = []
        self.stamp_other_digest = False
        self.wrong_nonce = False
        self.status = 0
        self.break_signature = False

    def __call__(self, url: str, body: bytes) -> bytes:
        self.requests.append(body)
        req = A.parse_one(body).children()
        digest = req[1].children()[1].content
        nonce = A.read_int(req[2])
        if self.status:
            status = A.enc_seq(A.enc_int(self.status), A.enc_seq(A.tlv(0x0C, b"request refused")))
            return A.enc_seq(status)
        if self.stamp_other_digest:
            digest = hashlib.sha256(digest).digest()
        return A.enc_seq(A.enc_seq(A.enc_int(0)), self.token(digest, nonce + 1 if self.wrong_nonce else nonce))

    def _sign(self, data: bytes) -> tuple[bytes, bytes]:
        if not self.pss:
            return self.key.sign(data, ec.ECDSA(hashes.SHA256())), A.enc_seq(A.enc_oid(OID_ECDSA_SHA256))
        mgf = {A.OID_SHA256: hashes.SHA256, A.OID_SHA384: hashes.SHA384}[self.mgf_hash]
        signature = self.key.sign(data, padding.PSS(mgf=padding.MGF1(mgf()), salt_length=self.salt), hashes.SHA256())
        params = A.enc_seq(
            A.explicit(0, A.enc_seq(A.enc_oid(A.OID_SHA256), A.enc_null())),
            A.explicit(1, A.enc_seq(A.enc_oid(A.OID_MGF1), A.enc_seq(A.enc_oid(self.mgf_hash), A.enc_null()))),
            A.explicit(2, A.enc_int(self.declared_salt)))
        return signature, A.enc_seq(A.enc_oid(A.OID_RSA_PSS), params)

    def token(self, digest: bytes, nonce: int | None) -> bytes:
        tst = A.enc_seq(A.enc_int(1), A.enc_oid("1.2.3.4.1"),
                        A.enc_seq(A.enc_seq(A.enc_oid(A.OID_SHA256), A.enc_null()), A.enc_octets(digest)),
                        A.enc_int(42), A.enc_gentime(self.when), *([A.enc_int(nonce)] if nonce is not None else []))
        cert_der = self.cert.public_bytes(Encoding.DER)
        attrs = A.enc_set(
            A.enc_seq(A.enc_oid(A.OID_CONTENT_TYPE), A.enc_set(A.enc_oid(A.OID_TST_INFO))),
            A.enc_seq(A.enc_oid(A.OID_MESSAGE_DIGEST), A.enc_set(A.enc_octets(hashlib.sha256(tst).digest()))),
            A.enc_seq(A.enc_oid(A.OID_SIGNING_CERT_V2),
                      A.enc_set(A.enc_seq(A.enc_seq(A.enc_seq(A.enc_octets(hashlib.sha256(cert_der).digest())))))),
        )
        signature, sig_alg = self._sign(attrs + (b"x" if self.break_signature else b""))
        signer_info = A.enc_seq(
            A.enc_int(1),
            A.enc_seq(self.cert.issuer.public_bytes(), A.enc_int(self.cert.serial_number)),
            A.enc_seq(A.enc_oid(A.OID_SHA256), A.enc_null()),
            b"\xa0" + attrs[1:],
            sig_alg,
            A.enc_octets(signature),
        )
        certs = b"".join(c.public_bytes(Encoding.DER) for c in [self.cert] + self.intermediates)
        signed_data = A.enc_seq(
            A.enc_int(3), A.enc_set(A.enc_seq(A.enc_oid(A.OID_SHA256), A.enc_null())),
            A.enc_seq(A.enc_oid(A.OID_TST_INFO), A.explicit(0, A.enc_octets(tst))),
            A.tlv(0xA0, certs), A.enc_set(signer_info))
        return A.enc_seq(A.enc_oid(A.OID_SIGNED_DATA), A.explicit(0, signed_data))


@pytest.fixture
def tsa():
    return FakeTSA()


@pytest.fixture
def vault(tmp_path, tsa):
    v = Vault.create(tmp_path / "v", "pw", clock=stepping_clock(), kdf_params=crypto.TEST_KDF, transport=tsa,
                     tsa_url="https://tsa.example/tsr")
    v.trust_roots = [tsa.root]
    v.put("a.md", b"alpha")
    v.put("b.md", b"beta")
    return v


def reopen(path, tsa=None):
    # The fake authority is also the transport: a reopened vault must never fall back to HTTP.
    v = Vault.open(path, "pw", transport=tsa, tsa_url="https://tsa.example/tsr" if tsa is not None else None)
    if tsa is not None:
        v.trust_roots = [tsa.root]
    return v


# ------------------------------------------------------------------ wire format


def test_request_matches_openssl_query_byte_for_byte():
    assert A.build_request(bytes(31) + b"\x01", 0xA8A4CBA721A600BD) == OPENSSL_QUERY


def test_der_round_trips():
    assert A.read_oid(A.parse_one(A.enc_oid("1.2.840.113549.1.9.16.1.4"))) == "1.2.840.113549.1.9.16.1.4"
    for n in (0, 1, 127, 128, 255, 256, 2 ** 63 - 1, -1, -129):
        assert A.read_int(A.parse_one(A.enc_int(n))) == n
    long = A.enc_octets(bytes(300))
    assert A.parse_one(long).content == bytes(300)
    when = datetime(2026, 3, 1, 12, 0, 0, 250000, tzinfo=timezone.utc)
    assert A.read_time(A.parse_one(A.enc_gentime(when))) == when
    with pytest.raises(A.DerError):
        A.parse_one(b"\x30\x80\x00\x00")  # BER indefinite length
    with pytest.raises(A.DerError):
        A.parse_one(b"\x04\x05abc")


# ------------------------------------------------------------------ OpenSSL token


def test_openssl_token_verifies_including_the_chain():
    token = A.extract_token(OPENSSL_RESPONSE)
    root = x509.load_pem_x509_certificate(OPENSSL_CA)
    check = A.check_token(token, OPENSSL_DIGEST, trust_roots=[root])
    assert check.ok, check.errors
    assert check.gen_time == datetime(2026, 11, 14, 13, 45, 32, tzinfo=timezone.utc)
    assert check.nonce == 0xBBA369B4FC1479D0 and check.serial == 2 and check.policy == "1.2.3.4.1"
    assert check.signature_valid and check.chain_trusted and "Empreinte Test TSA" in check.signer


def test_openssl_token_rejects_other_digest_and_other_root():
    token = A.extract_token(OPENSSL_RESPONSE)
    assert "token does not cover this hash (messageImprint differs)" in A.check_token(token, bytes(32)).errors
    other_root = FakeTSA().root
    check = A.check_token(token, OPENSSL_DIGEST, trust_roots=[other_root])
    # A wrong root is not a broken token: it is an unauthenticated claim (finding 2).
    assert check.ok and check.chain_trusted is False and check.state == "claimed" and check.trust_error
    assert A.check_token(token, OPENSSL_DIGEST, nonce=1).errors == ["token nonce does not match the request"]


def test_openssl_token_with_altered_tstinfo_fails():
    token = bytearray(A.extract_token(OPENSSL_RESPONSE))
    index = token.find(OPENSSL_DIGEST)
    token[index + 40] ^= 1  # inside TSTInfo, after the imprint: serial or genTime
    errors = A.check_token(bytes(token), OPENSSL_DIGEST).errors
    assert errors and any("messageDigest" in e or "malformed" in e for e in errors)


# ------------------------------------------------------------------ trust (findings 1, 2, 13)


def test_three_states_of_a_token():
    tsa = FakeTSA()
    token = tsa.token(OPENSSL_DIGEST, None)
    assert A.check_token(token, OPENSSL_DIGEST, trust_roots=[tsa.root]).state == "proven"
    unauthenticated = A.check_token(token, OPENSSL_DIGEST, trust_roots=[])
    assert unauthenticated.state == "claimed" and unauthenticated.chain_trusted is None
    assert A.check_token(token, bytes(32), trust_roots=[tsa.root]).state == "invalid"


def test_default_roots_come_from_certifi_and_do_not_trust_a_self_made_authority():
    roots = A.default_trust_roots()
    assert len(roots) > 50 and any(A.DIGICERT_ROOT_NAME in r.subject.rfc4514_string() for r in roots)
    tsa = FakeTSA()
    check = A.check_token(tsa.token(OPENSSL_DIGEST, None), OPENSSL_DIGEST)  # defaults
    assert check.ok and check.state == "claimed"


@pytest.mark.parametrize("chain, reason", [
    ("ee-issuer", "basicConstraints.cA"),
    ("no-certsign", "keyCertSign"),
    ("pathlen", "path length"),
])
def test_misissued_chains_are_not_trusted(chain, reason):
    """Finding 1: an end-entity certificate, a CA without keyCertSign, or a path length
    violation cannot vouch for a TSA certificate, even under the right root."""
    tsa = FakeTSA(chain=chain)
    check = A.check_token(tsa.token(OPENSSL_DIGEST, None), OPENSSL_DIGEST, trust_roots=[tsa.root])
    assert check.ok and check.chain_trusted is False and check.state == "claimed"
    assert reason in check.trust_error
    with pytest.raises(A.AnchorError, match="could not be authenticated"):
        A.request_anchor("ab" * 32, 0, transport=tsa, trust_roots=[tsa.root])


def test_unknown_critical_extension_and_non_critical_eku_are_refused():
    tsa = FakeTSA()
    unknown = x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.99999.1"), b"\x05\x00")
    cert = (x509.CertificateBuilder().subject_name(_name("Fake TSA")).issuer_name(_name("Fake Root"))
            .public_key(tsa.key.public_key()).serial_number(7)
            .not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2030, 1, 1, tzinfo=timezone.utc))
            .add_extension(EE_USAGE, critical=True)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(tsa.root_key.public_key()), False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
            .add_extension(unknown, critical=True).sign(tsa.root_key, hashes.SHA256()))
    tsa.cert = cert
    check = A.check_token(tsa.token(OPENSSL_DIGEST, None), OPENSSL_DIGEST, trust_roots=[tsa.root])
    assert check.state == "claimed" and "critical" in check.trust_error


def test_anchor_refuses_an_unauthenticated_authority_by_default(tmp_path):
    """Finding 2: an HTTP intermediary answering with its own certificate gets nowhere."""
    attacker = FakeTSA()
    v = Vault.create(tmp_path / "v", "pw", kdf_params=crypto.TEST_KDF, transport=attacker)
    v.put("a.md", b"a")
    with pytest.raises(A.AnchorError, match="could not be authenticated"):
        v.anchor()  # default roots: certifi
    assert v.anchors() == []
    v.require_trusted_anchor = False  # explicit opt-in: stored, but only ever a claim
    v.anchor()
    proof = v.proof(v.find("a.md").entry_id)
    assert proof.proven_before is None and proof.claimed_before == attacker.when and proof.anchor_errors == []
    assert v.verify().ok  # a claim is not an integrity error
    assert [s.state for s in v.anchor_states()] == ["claimed"]
    assert [s.state for s in v.verify().anchor_status] == ["claimed"]


def test_rsa_pss_parameters_are_enforced():
    """Finding 13: the declared PSS parameters are the ones checked."""
    good = FakeTSA(pss=True, salt=32, mgf_hash=A.OID_SHA384)
    assert A.check_token(good.token(OPENSSL_DIGEST, None), OPENSSL_DIGEST, trust_roots=[good.root]).ok
    lying = FakeTSA(pss=True, salt=32, declared_salt=20)
    errors = A.check_token(lying.token(OPENSSL_DIGEST, None), OPENSSL_DIGEST, trust_roots=[lying.root]).errors
    assert any("authority signature invalid" in e for e in errors)
    with pytest.raises(ValueError, match="trailer"):
        A.pss_parameters(A.parse_one(A.enc_seq(A.explicit(3, A.enc_int(2)))))
    with pytest.raises(ValueError, match="SHA-1"):
        A.pss_parameters(None)  # the RFC 4055 defaults are SHA-1


def test_openssl_rsa_pss_signature_verifies():
    """Independent PSS fixture: CMS produced by `openssl cms -sign -keyopt rsa_padding_mode:pss
    -keyopt rsa_pss_saltlen:32 -keyopt rsa_mgf1_md:sha384 -md sha256` over a TSTInfo, with the
    throwaway TSA key of OPENSSL_RESPONSE. OpenSSL adds no ESS attribute, so only that is missing."""
    signed_data = A.parse_one(OPENSSL_PSS_CMS).children()[1].children()[0].children()
    info = signed_data[-1].children()[0].children()
    cert = x509.load_der_x509_certificate(signed_data[3].children()[0].raw)
    sig_alg = info[4].children()
    assert A.pss_parameters(sig_alg[1]) == (A.OID_SHA256, A.OID_SHA384, 32)
    A.verify_cms_signature(cert.public_key(), sig_alg, A.OID_SHA256, info[5].content, b"\x31" + info[3].raw[1:])
    check = A.check_token(OPENSSL_PSS_CMS, OPENSSL_DIGEST, trust_roots=[x509.load_pem_x509_certificate(OPENSSL_CA)])
    assert check.signature_valid
    assert check.errors == ["signing-certificate attribute does not name the signer certificate"]


def test_sha1_signatures_are_refused():
    with pytest.raises(ValueError):
        A.verify_cms_signature(None, [A.parse_one(A.enc_oid("1.2.840.113549.1.1.5"))], A.OID_SHA1, b"", b"")


def test_oversized_inputs_are_refused():
    with pytest.raises(A.AnchorError, match="too large"):
        A.extract_token(bytes(A.MAX_RESPONSE_BYTES + 1))
    assert A.check_token(bytes(A.MAX_TOKEN_BYTES + 1), bytes(32)).errors == ["token is too large"]


# ------------------------------------------------------------------ fake authority


def test_request_anchor_round_trip(tsa):
    head = hashlib.sha256(b"head").hexdigest()
    anchor = A.request_anchor(head, 7, url="https://tsa.example/tsr", transport=tsa, trust_roots=[tsa.root])
    assert anchor.seq_upto == 7 and anchor.head_hash == head and anchor.anchored_at == tsa.when
    assert anchor.method == "rfc3161" and anchor.authority == "https://tsa.example/tsr"
    assert A.check_anchor(anchor, [tsa.root]) == [] and A.assess_anchor(anchor, [tsa.root]).state == "proven"
    sent = A.parse_one(tsa.requests[0]).children()
    # Finding 15: hashedMessage is the head hash itself, not a hash of it.
    assert sent[1].children()[1].content == bytes.fromhex(head)
    assert len(tsa.requests[0]) < 80


@pytest.mark.parametrize("knob, message", [
    ("stamp_other_digest", "messageImprint differs"),
    ("wrong_nonce", "nonce does not match"),
    ("break_signature", "authority signature invalid"),
])
def test_bad_tokens_are_refused(tsa, knob, message):
    setattr(tsa, knob, True)
    with pytest.raises(A.AnchorError, match=message):
        A.request_anchor("ab" * 32, 0, transport=tsa, trust_roots=[tsa.root])


def test_refusal_status_is_reported(tsa):
    tsa.status = 2
    with pytest.raises(A.AnchorError, match="rejection: request refused"):
        A.request_anchor("ab" * 32, 0, transport=tsa)
    with pytest.raises(A.AnchorError, match="not a valid TimeStampResp"):
        A.request_anchor("ab" * 32, 0, transport=lambda url, body: b"<html>")


def test_certificate_without_timestamping_eku_is_refused():
    tsa = FakeTSA(eku=False)
    with pytest.raises(A.AnchorError, match="extended key usage"):
        A.request_anchor("ab" * 32, 0, transport=tsa, trust_roots=[tsa.root])


def test_anchored_at_must_match_the_token(tsa):
    anchor = A.request_anchor("ab" * 32, 0, transport=tsa, trust_roots=[tsa.root])
    forged = anchor.model_copy(update={"anchored_at": datetime(2020, 1, 1, tzinfo=timezone.utc)})
    assert A.check_anchor(forged, [tsa.root]) == ["anchored_at differs from the time in the token"]
    moved = anchor.model_copy(update={"head_hash": "cd" * 32})
    assert any("messageImprint" in e for e in A.check_anchor(moved, [tsa.root]))


# ------------------------------------------------------------------ vault


def test_vault_anchor_verify_and_proof(vault, tsa):
    assert vault.anchor_methods() == ["rfc3161"]
    anchor = vault.anchor()
    assert anchor.seq_upto == 1 and anchor.head_hash == vault.ledger()[-1].record_hash
    vault.put("c.md", b"gamma")
    report = vault.verify()
    assert report.ok and report.anchors_checked == 1
    first = vault.find("a.md").entry_id
    proof = vault.proof(first)
    assert proof.anchors == [anchor] and proof.proven_before == tsa.when and proof.verified
    assert proof.claimed_before is None and proof.anchor_errors == []
    late = vault.proof(vault.find("c.md").entry_id)
    assert late.anchors == [] and late.proven_before is None and late.claimed_before is None
    path = vault.path
    vault.lock()
    again = reopen(path, tsa)
    assert again.anchors() == [anchor] and again.verify().ok
    again.trust_roots = []  # same token, no root: a claim, never a proof
    proof = again.proof(first)
    assert proof.proven_before is None and proof.claimed_before == tsa.when


def test_proof_never_returns_a_forged_date(vault, tsa):
    """Finding 3: proof() re-checks every token before using its time."""
    vault.anchor()
    path = vault.path
    vault.lock()
    line = (path / "anchors.jsonl").read_text(encoding="utf-8")
    forged = line.replace("2026-03-01T12:00:00.500000Z", "2000-01-01T00:00:00Z")
    assert forged != line
    garbage = json.loads(line)
    garbage["proof"] = base64.b64encode(b"garbage").decode()
    garbage["anchored_at"] = "1999-01-01T00:00:00Z"
    (path / "anchors.jsonl").write_text(forged + json.dumps(garbage) + "\n", encoding="utf-8")
    v = reopen(path, tsa)
    proof = v.proof(v.find("a.md").entry_id)
    assert proof.proven_before is None and proof.claimed_before is None and proof.anchors == []
    assert any("anchored_at differs" in e for e in proof.anchor_errors)
    assert any("malformed" in e for e in proof.anchor_errors)
    assert not v.verify().ok


def test_vault_detects_tampered_or_deleted_anchor(vault, tsa):
    vault.anchor()
    path = vault.path
    vault.lock()
    line = (path / "anchors.jsonl").read_text(encoding="utf-8")
    (path / "anchors.jsonl").write_text(line.replace('"seq_upto":1', '"seq_upto":0'), encoding="utf-8")
    v = reopen(path, tsa)
    errors = v.verify().errors
    v.lock()
    assert any(e.startswith("anchor 0: head hash is not record 0") for e in errors)
    (path / "anchors.jsonl").write_text("", encoding="utf-8")
    errors = reopen(path, tsa).verify().errors
    assert "anchors: the catalog knows 1, anchors.jsonl has 0" in errors


def test_verify_sees_anchors_deleted_after_open(vault, tsa):
    """Finding 6 for anchors: verify() re-reads anchors.jsonl."""
    vault.anchor()
    (vault.path / "anchors.jsonl").write_text("", encoding="utf-8")
    errors = vault.verify().errors
    assert "anchors.jsonl on disk differs from the anchors in memory" in errors


def test_opentimestamps_is_not_implemented_and_empty_ledger_refused(tmp_path, tsa):
    v = Vault.create(tmp_path / "e", "pw", kdf_params=crypto.TEST_KDF, transport=tsa)
    v.trust_roots = [tsa.root]
    with pytest.raises(VaultError, match="empty"):
        v.anchor()
    v.put("a.md", b"a")
    with pytest.raises(VaultError, match="not implemented"):
        v.anchor("opentimestamps")
    assert tsa.requests == [] and "opentimestamps" not in v.anchor_methods()


def test_nothing_reaches_the_network_without_an_explicit_anchor(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("network used")
    monkeypatch.setattr(A, "http_transport", forbidden)
    monkeypatch.setattr(A.urllib.request, "urlopen", forbidden)
    v = Vault.create(tmp_path / "n", "pw", kdf_params=crypto.TEST_KDF)
    meta = v.put("a.md", b"a")
    grant = v.grant("L", [(meta.entry_id, None)], usage="u")
    v.export_bundle(grant.license_id, tmp_path / "out")
    assert v.verify().ok and v.proof(meta.entry_id).verified
    assert A.DEFAULT_TSA_URL == "http://timestamp.digicert.com"


def test_http_transport_bounds_the_response(monkeypatch):
    class Response:
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            return False
        def read(self, n=-1):
            return bytes(min(n, A.MAX_RESPONSE_BYTES + 10))
    monkeypatch.setattr(A.urllib.request, "urlopen", lambda request, timeout: Response())
    with pytest.raises(A.AnchorError, match="too large"):
        A.http_transport("http://tsa.invalid", b"")


def test_verifier_embeds_the_same_token_checks():
    """tools/verify_bundle.py carries a verbatim copy of the token-checking section."""
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    anchor = (root / "src/empreinte/anchor.py").read_text(encoding="utf-8")
    verifier = (root / "tools/verify_bundle.py").read_text(encoding="utf-8")
    begin, end = "# " + "=" * 79 + " DER\n", "# " + "=" * 69 + " vault side\n"
    section = anchor[anchor.index(begin):anchor.index(end)]
    assert len(section) > 5000 and section in verifier


# ------------------------------------------------------------------ audit round


def test_proof_and_verify_give_one_status_per_anchor(tmp_path):
    """a, defect 9: an earlier claimed anchor and a later proven one stay distinct; the
    proven date comes from the proven entry, which also names its authority."""
    attacker = FakeTSA(when=datetime(2026, 2, 1, tzinfo=timezone.utc))
    trusted = FakeTSA(when=datetime(2026, 3, 1, tzinfo=timezone.utc))
    v = Vault.create(tmp_path / "v", "pw", kdf_params=crypto.TEST_KDF, transport=attacker,
                     tsa_url="http://unauthenticated.example/tsr")
    v.trust_roots = [trusted.root]
    meta = v.put("a.md", b"a")
    v.require_trusted_anchor = False
    v.anchor()
    v.require_trusted_anchor = True
    v.transport, v.tsa_url = trusted, "https://trusted.example/tsr"
    v.anchor()
    proof = v.proof(meta.entry_id)
    assert [(s.state, s.authority) for s in proof.anchor_status] == [
        ("claimed", "http://unauthenticated.example/tsr"), ("proven", "https://trusted.example/tsr")]
    assert proof.proven_before == trusted.when and proof.claimed_before == attacker.when
    proven = [s for s in proof.anchor_status if s.state == "proven"]
    assert proven[0].anchored_at == proof.proven_before and proven[0].signer == "CN=Fake TSA"
    assert proof.anchor_status[0].error  # why it is only a claim
    report = v.verify()
    assert report.ok and [s.state for s in report.anchor_status] == ["claimed", "proven"]


def test_invalid_anchor_status_carries_no_time(vault, tsa):
    vault.anchor()
    vault.trust_roots = [tsa.root]
    vault._anchors[0] = vault._anchors[0].model_copy(update={"anchored_at": datetime(2000, 1, 1, tzinfo=timezone.utc)})
    status = vault.proof(vault.find("a.md").entry_id).anchor_status[0]
    assert status.state == "invalid" and status.anchored_at is None and "anchored_at differs" in status.error


def test_stored_proof_size_is_checked_before_decoding(vault, monkeypatch):
    """N12: an enormous stored proof is refused without being decoded."""
    anchor = A.Anchor(seq_upto=0, head_hash="ab" * 32, method="rfc3161", authority="x",
                      proof="A" * (A.MAX_PROOF_CHARS + 4))
    def no_decode(*args, **kwargs):
        raise AssertionError("decoded")
    monkeypatch.setattr(A.base64, "b64decode", no_decode)
    status = A.assess_anchor(anchor, [])
    assert status.state == "invalid" and "larger" in status.errors[0]


def test_network_call_runs_without_the_vault_lock(vault, tsa):
    """h: other threads keep working while the authority answers."""
    import threading
    done = []
    def slow(url, body):
        worker = threading.Thread(target=lambda: done.append(len(vault.entries())))
        worker.start()
        worker.join(timeout=5)
        return tsa(url, body)
    vault.transport = slow
    vault.anchor()
    assert done == [2]


def test_anchor_rechecks_the_disk_after_the_network_call(vault, tsa):
    """h: another writer's line arriving during the request stops the anchor append."""
    def meanwhile(url, body):
        with open(vault.path / "ledger.jsonl", "ab") as handle:
            handle.write(b"{}\n")  # whatever another writer or a sync client brought in
        return tsa(url, body)
    vault.transport = meanwhile
    with pytest.raises(Corrupted_, match="changed on disk"):
        vault.anchor()
    assert (vault.path / "anchors.jsonl").read_bytes() == b"" and vault.anchors() == []


def test_anchor_is_not_stored_when_the_lock_was_lost_meanwhile(vault, tsa):
    def meanwhile(url, body):
        vault._writer.release()  # as if the session were closed by another thread
        return tsa(url, body)
    vault.transport = meanwhile
    with pytest.raises(VaultError, match="read-only"):
        vault.anchor()
    assert (vault.path / "anchors.jsonl").read_bytes() == b""


def test_format_document_states_the_raw_imprint():
    """N15: hashedMessage is the 32 raw bytes of the head hash, not a second hash."""
    from pathlib import Path
    text = (Path(__file__).resolve().parents[1] / "docs" / "FORMAT.md").read_text(encoding="utf-8")
    assert "imprint is SHA-256 of our head hash" not in text
    assert "hashedMessage = the 32 raw bytes of head_hash" in text


def test_old_cryptography_is_refused_with_a_clear_message(tmp_path):
    """Defect 8: the package and the standalone verifier both name the minimum version."""
    import os
    import subprocess
    import sys
    from pathlib import Path
    fake = tmp_path / "fake" / "cryptography"
    fake.mkdir(parents=True)
    (fake / "__init__.py").write_text('__version__ = "44.0.3"\n', encoding="utf-8")
    root = Path(__file__).resolve().parents[1]
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(tmp_path / "fake"), str(root / "src")]))
    verifier = subprocess.run([sys.executable, str(root / "tools" / "verify_bundle.py"), str(tmp_path)],
                              capture_output=True, text=True, env=env, cwd=tmp_path, timeout=60)
    assert verifier.returncode == 2 and "cryptography >= 49.0" in verifier.stderr
    assert "Traceback" not in verifier.stderr
    package = subprocess.run([sys.executable, "-c", "import empreinte.anchor"], capture_output=True, text=True,
                             env=env, cwd=tmp_path, timeout=60)
    assert package.returncode != 0 and "needs cryptography >= 49.0, found 44.0.3" in package.stderr


# --------------------------------------------------- fix round after the closing audit


def test_recovery_never_forgets_deleted_anchors(vault, tsa):  # N10
    """A lagging catalog is replayed at open; that must not rewrite the anchor count
    before the anchors were checked, or a second opening forgets the deletion."""
    vault.anchor()
    path = vault.path
    lagging = (path / "catalog.bin").read_bytes()  # records 0..1, one anchor
    vault.put("c.md", b"gamma")
    vault.lock()
    (path / "catalog.bin").write_bytes(lagging)  # as after a crash before the catalog write
    (path / "anchors.jsonl").write_text("", encoding="utf-8")  # and the anchor deleted
    for _ in range(2):
        v = reopen(path, tsa)
        try:
            assert "anchors: the catalog knows 1, anchors.jsonl has 0" in v.verify().errors
            with pytest.raises(VaultError, match="read-only"):
                v.put("d.md", b"delta")
        finally:
            v.lock()


def test_anchors_beyond_the_old_size_limit_stay_readable_and_writable(vault, tsa, monkeypatch):  # defect 7
    import empreinte.vault as V

    for _ in range(3):
        vault.anchor()
    path = vault.path
    vault.lock()
    size = (path / "anchors.jsonl").stat().st_size
    monkeypatch.setattr(V, "MAX_ANCHORS_BYTES", size // 2)  # the file is now "long"
    v = reopen(path, tsa)
    try:
        assert len(v.anchors()) == 3 and v.verify().ok, v.verify().errors
        v.put("d.md", b"delta")
        v.anchor()
        assert len(v.anchors()) == 4
    finally:
        v.lock()


def test_one_oversized_anchor_record_is_refused_without_reading_it(vault, tsa, monkeypatch):  # defect 7, N12
    import empreinte.vault as V

    vault.anchor()
    path = vault.path
    vault.lock()
    first = (path / "anchors.jsonl").stat().st_size
    with open(path / "anchors.jsonl", "ab") as handle:
        handle.write(b'{"x":"' + b"A" * (first * 4) + b'"}\n')
    monkeypatch.setattr(V, "MAX_ANCHOR_RECORD_BYTES", first + 100)
    v = reopen(path, tsa)
    try:
        assert len(v.anchors()) == 1
        assert any("anchors line 2" in e for e in v.verify().errors)
    finally:
        v.lock()
