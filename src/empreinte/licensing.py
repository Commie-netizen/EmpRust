"""Disclosure bundles: what a licensee receives and can check without the vault.

A bundle directory holds:

    manifest.json        everything needed to check the items (format in docs/FORMAT.md)
    grant.json           the exact committed bytes of the grant
    items/NN_<entry_id>_v<version>.<ext>   the licensed plaintexts, nothing else
    anchors/anchor-<seq_upto>.tst          DER timestamp tokens, for openssl
    README.txt           how to verify, with the openssl commands
    verify_bundle.py     a copy of the standalone verifier, when available

About the other records of the vault, the bundle reveals only their 32-byte body digests
(and the head's record hash and signature): not their kind, size, time or entry id.
"""
from __future__ import annotations

import base64
import hashlib
import json
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .anchor import DIGICERT_ROOT_NAME
from .api import VaultError
from .ledger import chain_digests, format_time, record_to_dict
from .model import Anchor, LedgerRecord, LicenseItem
from .store import atomic_write

BUNDLE_FORMAT = "empreinte-bundle"
BUNDLE_VERSION = 1
GRANT_SIGNATURE_PREFIX = b"empreinte/v1/grant\x00"
EXTENSIONS = {"text/markdown": ".md", "text/plain": ".txt", "text/html": ".html", "application/pdf": ".pdf",
              "application/json": ".json"}


@dataclass
class BundleItem:
    item: LicenseItem
    media_type: str
    salt: str
    plaintext: bytes
    record: LedgerRecord


def grant_signature(signer: Ed25519PrivateKey, committed: bytes) -> str:
    return signer.sign(GRANT_SIGNATURE_PREFIX + committed).hex()


def write_bundle(*, out_dir: Path, license_id: str, committed: bytes, grant_salt: str, license_record: LedgerRecord,
                 items: Sequence[BundleItem], records: Sequence[LedgerRecord], public_key_hex: str,
                 signer: Ed25519PrivateKey, anchors: Sequence[Anchor]) -> tuple[Path, str]:
    """Write the bundle; return its directory and the hex SHA-256 of manifest.json."""
    bundle = Path(out_dir) / f"license-{license_id}"
    if bundle.exists():
        if not (bundle / "manifest.json").exists():
            raise VaultError("bundle directory exists and is not an Empreinte bundle")
        shutil.rmtree(bundle)
    (bundle / "items").mkdir(parents=True)
    head = records[-1]
    first = min([license_record.seq] + [i.record.seq for i in items])
    manifest_items = []
    for number, entry in enumerate(items, start=1):
        ext = EXTENSIONS.get(entry.media_type, ".bin")
        name = f"items/{number:02d}_{entry.item.entry_id}_v{entry.item.version}{ext}"
        atomic_write(bundle / PurePosixPath(name), entry.plaintext)
        manifest_items.append({
            "file": name,
            "entry_id": entry.item.entry_id,
            "version": entry.item.version,
            "title": entry.item.title,
            "media_type": entry.media_type,
            "salt": entry.salt,
            "record": record_to_dict(entry.record),
        })
    atomic_write(bundle / "grant.json", committed)
    manifest_anchors = []
    covering = [a for a in anchors if first <= a.seq_upto <= head.seq
                and records[a.seq_upto].record_hash == a.head_hash]
    if covering:
        (bundle / "anchors").mkdir()
    for anchor in covering:
        name = f"anchors/anchor-{anchor.seq_upto}.tst"
        atomic_write(bundle / PurePosixPath(name), base64.b64decode(anchor.proof))
        manifest_anchors.append(dict(anchor.model_dump(mode="json"), file=name))
    manifest = {
        "format": BUNDLE_FORMAT,
        "format_version": BUNDLE_VERSION,
        "license_id": license_id,
        "public_key": public_key_hex,
        "exported_at": format_time(datetime.now(timezone.utc)),
        "grant": {
            "file": "grant.json",
            "salt": grant_salt,
            "signature": grant_signature(signer, committed),
            "record": record_to_dict(license_record),
        },
        "items": manifest_items,
        "chain": {
            "from_seq": first,
            "prev_hash": records[first].prev_hash,
            "body_digests": chain_digests(records, public_key_hex, first),
        },
        "head": {"seq": head.seq, "record_hash": head.record_hash, "signature": head.signature},
        "anchors": manifest_anchors,
    }
    manifest_bytes = (json.dumps(manifest, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    atomic_write(bundle / "manifest.json", manifest_bytes)
    atomic_write(bundle / "README.txt", _readme(manifest).encode("utf-8"))
    verifier = Path(__file__).resolve().parents[2] / "tools" / "verify_bundle.py"
    if verifier.is_file():
        shutil.copyfile(verifier, bundle / "verify_bundle.py")
    return bundle, hashlib.sha256(manifest_bytes).hexdigest()


def _readme(manifest: dict) -> str:
    lines = [
        "Empreinte disclosure bundle",
        "",
        f"License {manifest['license_id']}, vault public key (Ed25519) {manifest['public_key']}.",
        "",
        "1. Check everything (needs Python 3.11+ and the 'cryptography' package):",
        "",
        "       python verify_bundle.py .",
        "",
        "   Prefer your own copy of verify_bundle.py over the one shipped here.",
        "   Compare the public key above with one the author published elsewhere.",
        "",
        "2. Check the outside timestamps independently with OpenSSL. Each token covers the",
        "   head hash given below; verify_bundle.py checks that the items are chained to it.",
        f"   You need the root certificate of the authority (for the default authority: {DIGICERT_ROOT_NAME},",
        "   downloadable from the authority's site) and, if the token does not embed it, its",
        "   intermediate certificate (-untrusted).",
        "",
    ]
    if not manifest["anchors"]:
        lines.append("   This bundle has no outside timestamp: the dates are the author's clock only.")
    for anchor in manifest["anchors"]:
        lines += [
            f"   Anchor of record {anchor['seq_upto']}: a token that names itself {anchor['authority']} and asserts",
            f"   {anchor['anchored_at']}. Until its certificate path to a root you trust is checked, this is",
            "   only a claim:",
            "",
            f"       openssl ts -verify -digest {anchor['head_hash']} -token_in -in {anchor['file']} "
            "-CAfile ROOT.pem [-untrusted INTERMEDIATE.pem]",
            "",
        ]
    lines += [
        "What the dates mean, as verify_bundle.py reports them:",
        "  NONE         no anchor covers the record: its ledger time is the author's local clock and",
        "               proves only order;",
        "  CLAIMED ONLY a valid timestamp token covers it, but its authority could not be authenticated",
        "               (no trusted root, or no valid certificate path): anyone could have made it;",
        "  PROVEN       the token's signer has a valid certificate path to a trusted root at the asserted",
        "               time: the record existed by then (revocation is not checked).",
        "",
    ]
    return "\n".join(lines)
