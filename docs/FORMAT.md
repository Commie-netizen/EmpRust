# Empreinte vault format, version 1

This document specifies the on-disk format of an Empreinte vault, its ledger, its
external anchors, its disclosure bundles and its public catalogues, precisely enough to
write a reader or a verifier in another language. The reference implementation is
`src/empreinte/crypto.py`, `store.py`, `ledger.py`, `vault.py`, `anchor.py`,
`licensing.py`, `catalogue.py` and the standalone `tools/verify_bundle.py`.

## 1. Conventions

* `||` is byte concatenation. `0x00` is one zero byte.
* "hex" is lowercase hexadecimal without prefix. `hex32` is 32 bytes as 64 hex characters.
* "canonical JSON" is JSON with object keys sorted by code point, no whitespace
  (separators `,` and `:`), encoded in UTF-8. Python: `json.dumps(obj, sort_keys=True,
  separators=(",", ":"), ensure_ascii=False).encode("utf-8")`. Where a section says
  "ASCII canonical JSON", every value is ASCII and `ensure_ascii=True` gives the same bytes.
* Ledger time is written `YYYY-MM-DDTHH:MM:SS.ffffffZ`: UTC, always six fractional
  digits, a literal `Z` (for example `2026-01-01T09:00:00.000000Z`). Readers must reject
  any other form in the ledger.
* All text files are UTF-8 with `\n` line ends.

Primitives (all standard, all from the `cryptography` package):

| Primitive | Parameters | Protects |
|---|---|---|
| Argon2id (RFC 9106, v1.3) | 32-byte output, 16-byte random salt, default t=3, p=4, m=262144 KiB (256 MiB) | turns the passphrase into the key that wraps the master key |
| AES-256-GCM | 96-bit random nonce, 128-bit tag | wraps of the master key and of the identity key |
| HKDF-SHA256 (RFC 5869) | salt and info as below, 32-byte output | subkeys per purpose, per-blob keys, recovery key wrap key |
| AES-256-GCM, per-blob key | key = HKDF(subkey, 32-byte random salt), 96-bit random nonce, associated data binding the blob to its place | every blob: contents, catalog, aux values, grants, royalties |
| HMAC-SHA256 | aux-name subkey | opaque file names of aux values |
| SHA-256 | | commitments, cipher hashes, the hash chain |
| Ed25519 (RFC 8032) | one key pair per vault | signature of every ledger record and of every grant |
| RFC 3161 time-stamp token | SHA-256 imprint of the head record hash | outside proof of time |

The installed `cryptography` provides Argon2id, so scrypt is not used.

## 2. Directory layout

```
VAULT/
  header.json         public: format, vault id, public key, KDF parameters, wrapped keys
  ledger.jsonl        public: the signed hash chain, one JSON object per line
  anchors.jsonl       public: RFC 3161 anchors, one JSON object per line
  catalog.bin         encrypted blob (type 2): the index of everything
  blobs/xx/<hex32>    encrypted blobs, named by SHA-256 of the blob bytes (the ledger's
                      cipher_hash); xx is the first two hex characters
  aux/xx/<hex32>      encrypted aux values, named by HMAC-SHA256 of the aux key
  writer.lock         the single-writer lock (section 9); its text is informational only
```

A vault is a plain directory: it can be copied, synced or backed up as is. Files
starting with `.` and ending in `.tmp` are interrupted temporary files and can be
deleted. A blob file that no ledger record names is an orphan left by a crash (section
9) and can be ignored or deleted.

File names reveal nothing: blob names are hashes of ciphertext under a fresh key (they
cannot confirm a guess about the plaintext, and they repeat the public `cipher_hash`),
aux names are keyed MACs.

## 3. header.json

A JSON object (written with indentation; parse it as JSON, not by bytes):

```
{
  "format": "empreinte-vault",
  "format_version": 1,
  "vault_id": hex16,                  random, 16 bytes
  "public_key": hex32,                Ed25519 public key of the vault identity
  "kdf": {"name": "argon2id", "iterations": int, "lanes": int,
          "memory_cost": int,         KiB
          "salt": hex16},
  "master_key_wraps": {"passphrase": WRAP, "recovery": WRAP},
  "identity": WRAP
}
WRAP = {"alg": "AES-256-GCM", "nonce": hex12, "ciphertext": hex (ciphertext || 16-byte tag)}
```

The KDF salt is necessarily public. All other salts (commitment salts, blob salts are
inside the blob) are encrypted or random.

The header is not authenticated before unlocking, so a reader bounds it before use:
at most 64 KiB, and the KDF parameters must lie in the supported ranges before any
derivation runs: `iterations` 1 to 16, `lanes` 1 to 16, `memory_cost` 8 KiB per lane up
to 2 GiB (2097152 KiB), salt 16 to 64 bytes. Values outside are refused as corruption.

Old headers: changing the passphrase rewraps the same master key. Anyone who kept a copy
of an earlier header.json and knows the earlier passphrase (or recovery key) can still
unwrap the master key and read the vault. A passphrase change protects against future
guesses at the new passphrase, not against a leaked old passphrase together with an old
header. Re-encrypting under a new master key is not implemented.

## 4. Key hierarchy

```
passphrase --NFC, UTF-8--> Argon2id(salt=kdf.salt, t, p, m) = PK (32 bytes)
recovery key (32 random bytes) --HKDF--> RK
                          PK, RK each wrap the MASTER KEY (32 random bytes)
MASTER --HKDF--> content, metadata, aux, aux-name, identity, license subkeys
identity subkey wraps the Ed25519 private key (32-byte seed)
```

* `MASTER` is 32 random bytes, generated once. Changing the passphrase rewraps it;
  nothing else is re-encrypted.
* Passphrase wrap: AES-256-GCM, key `PK`, associated data
  `"empreinte/v1/wrap/passphrase" || 0x00 || vault_id(16 raw bytes) || KDFJSON`, where
  KDFJSON is the ASCII canonical JSON of the `kdf` object (keys `iterations`, `lanes`,
  `memory_cost`, `name`, `salt`). Changing any KDF parameter in the header makes the
  unwrap fail (reported as a wrong passphrase: the two cannot be told apart).
* Recovery wrap: key `RK = HKDF-SHA256(IKM=recovery key, salt=vault_id, info="empreinte/v1/recovery-wrap")`,
  associated data `"empreinte/v1/wrap/recovery" || 0x00 || vault_id`.
* Subkeys: `HKDF-SHA256(IKM=MASTER, salt=vault_id, info="empreinte/v1/subkey/" || LABEL, L=32)`
  with LABEL one of `content`, `metadata`, `aux`, `aux-name`, `identity`, `license`.
* Identity wrap: key = identity subkey, associated data
  `"empreinte/v1/wrap/identity" || 0x00 || vault_id`, plaintext = Ed25519 private key
  (32-byte seed, RFC 8032). The public key derived from it must equal `header.public_key`.
* Recovery key text: `BASE32(key || SHA-256(key)[0:2])` (RFC 4648 alphabet, no
  padding, 55 characters) split in groups of 5 joined by `-`. Readers ignore case,
  spaces and dashes, and reject a wrong checksum. It is shown once at creation and never
  stored.

## 5. Blobs

```
offset  size  field
0       4     magic "EMPB"
4       1     format version = 1
5       1     blob type: 1 content, 2 catalog, 3 aux, 4 grant, 5 royalty
6       32    salt (random)
38      12    nonce (random)
50      n+16  AES-256-GCM ciphertext || tag
```

* Key: `HKDF-SHA256(IKM=SUBKEY, salt=blob salt, info="empreinte/v1/blob-key", L=32)`
  where SUBKEY is the content subkey for type 1, metadata for 2, aux for 3, license for
  4 and 5. Every blob has its own key, so a nonce can only repeat if two random 256-bit
  salts collide: nonce reuse is not a practical concern however many blobs are written.
* Associated data: `"empreinte/v1/blob" || 0x00 || bytes 0..49 of the blob || vault_id || LABEL`
  where LABEL (ASCII) names the blob's place:

| Type | LABEL |
|---|---|
| content | `content:<entry_id>:<version in decimal>` |
| catalog | `catalog` |
| aux | `aux:<file name, hex32>` |
| grant | `license:<ledger seq in decimal>` |
| royalty | `royalty:<ledger seq in decimal>` |

  A blob copied to another entry, version, record or vault, or with its header edited,
  fails authentication.
* Content, grant and royalty plaintext ("payload"): `u32 big-endian length of META || META || BODY`.
  * Content: META is canonical JSON `{"kind", "media_type", "path", "salt": hex32,
    "source_mtime": ledger time or null, "tags": sorted unique list, "title"}` and BODY
    is the document. Every content blob is self-describing, which is what lets a lost
    catalog be rebuilt and a crash be recovered (section 9).
  * Grant and royalty: META is `{"salt": hex32}`, BODY is the committed JSON (section 8).
* Catalog and aux plaintext: the bytes themselves (no META).

## 6. catalog.bin

A blob of type 2, LABEL `catalog`. Plaintext: canonical JSON

```
{
  "format_version": 1,
  "n_records": int,            number of ledger records the catalog reflects
  "head_hash": hex32,          record_hash of record n_records - 1 (64 zeros if none)
  "public_key": hex32,
  "n_anchors": int,
  "entries": [{"entry_id", "path", "title", "kind", "media_type", "tags", "removed": bool,
               "versions": [{"version", "seq", "timestamp", "size", "commitment",
                             "salt": hex32, "cipher_hash", "source_mtime"}]}],
  "licenses": [{"seq", "committed": text, "salt", "cipher_hash", "bundle_hash"}],
  "royalties": [{"seq", "committed": text, "salt", "cipher_hash", "bundle_hash": ""}]
}
```

The catalog is kept decrypted in memory while the vault is unlocked; it is a cache that
can be rebuilt entirely from the ledger and the blobs, except `bundle_hash`, `n_anchors`
and the rollback information (`n_records`, `head_hash`).

## 7. aux/

`name = hex(HMAC-SHA256(aux-name subkey, UTF-8 key))`, file `aux/<name[0:2]>/<name>`,
a blob of type 3 with LABEL `aux:<name>`. Aux values are derived data (index caches,
previews, watched folders and their capture state, catalogue public ids and the record of
published catalogues) and are not in the ledger.

## 8. Ledger (ledger.jsonl)

One JSON object per line, appended and fsynced, never rewritten. Fields:

| Field | Type | Rule |
|---|---|---|
| seq | int | 0-based, gapless: line N holds seq N |
| kind | text | `put`, `remove`, `license`, `royalty` |
| entry_id | text | 32 hex (random, never derived from content or path), or "" |
| version | int | 1-based for put, latest version for remove, 0 otherwise |
| commitment | text | hex32 or "" |
| cipher_hash | text | hex32 SHA-256 of the blob as stored, or "" |
| size | int | plaintext bytes for put; 0 otherwise |
| timestamp | text | ledger time (section 1) |
| prev_hash | text | record_hash of seq - 1, 64 zeros for seq 0 |
| record_hash | text | see below |
| signature | text | 64 bytes hex |

Per kind: `put` has entry_id, version, commitment, cipher_hash, size. `remove` has
entry_id and version, the rest empty or zero. `license` and `royalty` have commitment
and cipher_hash (of the encrypted grant or royalty blob), entry_id "" and size 0, so
that the record says nothing about the grant's length or subject.

**Commitment** = `hex(SHA-256(salt || plaintext))`, salt 32 random bytes per version, kept
encrypted (in the blob META and the catalog) and disclosed only in a license bundle.
Without the salt nobody can confirm a guessed plaintext from the public ledger, and two
equal documents have unrelated commitments. For `license` and `royalty` the plaintext is
the committed JSON: the canonical JSON (section 1) of the LicenseGrant (with
`bundle_hash` "") or RoyaltyEvent, exactly as stored in the catalog field `committed`.

**Canonical body.** The ASCII canonical JSON of exactly these ten keys:

```
{"cipher_hash","commitment","entry_id","format":1,"key":<vault public key hex>,"kind",
 "seq","size","timestamp","version"}
```

for example

```
{"cipher_hash":"…","commitment":"…","entry_id":"…","format":1,"key":"…","kind":"put","seq":0,"size":5,"timestamp":"2026-01-01T09:00:00.000000Z","version":1}
```

`key` is not stored in the line: it is the vault public key, bound into every hash so
that replacing the key changes every record hash and breaks every anchor.

**Hashes.**

```
body_digest = SHA-256(canonical body)                       32 bytes
record_hash = SHA-256(prev_hash(32 raw bytes) || body_digest)
signature   = Ed25519-Sign(identity, "empreinte/v1/record" || 0x00 || record_hash(32 raw bytes))
```

The two-level form lets a bundle prove that a record is chained to the head, or to an
anchored record, by disclosing only the 32-byte `body_digest` of each record in between:
not their kind, size, time or entry id.

**Honesty about time.** `timestamp` is the clock of the machine that wrote the record.
It is not checked for monotonicity. On its own the ledger proves the order of records,
not their absolute time. Absolute time comes only from anchors (section 10). The
"claimed" dates of imported files (`source_mtime`, `authored_at`) are stored encrypted
and are never evidence.

## 9. Write order and crash recovery

One `put()` performs, in this order:

1. write the blob: temporary file in the same directory, fsync, atomic replace
   (`blobs/xx/<cipher_hash>`);
2. append the ledger line and fsync;
3. write `catalog.bin` atomically (temporary file, fsync, replace).

`remove()` skips step 1; `grant()` and `record_royalty()` follow 1 to 3 with their blob.
On POSIX the directory that receives a new blob (and `blobs/` when the shard directory
is new) is fsynced before the record that names the blob is appended.

`batch()` writes the blobs of many puts without fsync; at the end it fsyncs those files
and their directories, then appends all their lines in one write and one fsync, then
writes the catalog once. Its crash semantics are **prefix-commit**: a crash before the
append keeps nothing of the batch; a crash during the append keeps, in order, every
record whose line is complete (each is a valid signed record with its blob durable) and
cuts the torn last line. A batch is not a rollback transaction either: an exception
raised inside `with vault.batch():` still commits the puts that already returned.

`open()` recovers:

* crash after 1: the blob is an orphan, no record refers to it; nothing was promised.
* crash during 2: a last line without `\n` is completed if it parses as a record, else
  cut off. Its signature and chain are then checked like any other line.
* crash after 2: the ledger has more records than `catalog.n_records`. If record
  `n_records - 1` has the `head_hash` stored in the catalog, the extra records are
  checked (chain and signatures) and replayed from their self-describing blobs, whose
  cipher hash, authentication and commitment must all match; the catalog is then
  written. Records that fail these checks are not replayed and verify() reports them.
* missing catalog: everything is rebuilt from the ledger and blobs (the bundle hashes and
  the anchor count are lost; rollback detection restarts from that point).

Every replace and read retries for about 3 seconds when the file is held by another
process (a sync client or an antivirus). On Windows the directory itself cannot be
fsynced; NTFS journals the rename.

**One writer.** A Vault object writes only while it holds the writer lock: an open
handle on `writer.lock` with an exclusive operating-system lock on one byte at offset
2^20 (`msvcrt.locking` on Windows, `fcntl.flock` elsewhere). The system releases it when
the handle closes or the process dies, so a crash leaves nothing to reclaim, and the
file is never deleted. A vault opened while another process, or another open Vault
object of the same process, holds the lock is read-only: `notices` says so, and every
write (ledger, catalog, blobs, aux values, anchors, passphrase and recovery wraps, and
the flush at the end of a batch, even an empty one) is refused. To replace a session in
one process, `close()` the old Vault (same as `lock()`: it saves what is pending, drops
the keys and releases the lock), then open the new one.

Before every append the writer also re-reads the end of `ledger.jsonl`: its size and
its last record must be what this object left. Anything else (another writer, an edit,
a sync client bringing in lines) makes the vault read-only with `Corrupted`. `anchor()`
runs its network request without the vault lock and checks ownership, integrity and the
on-disk head again before appending the anchor. An append that raises after it may have
written bytes (fsync failure, disk full) makes the object read-only until reopened: its
sequence numbers are never reused, and open() reconciles what reached the disk.

**Two machines.** The lock is local. Two machines syncing the folder (OneDrive, Dropbox)
each take their own lock and can both append record N+1. The sync client then keeps one
`ledger.jsonl` and usually saves the other as a conflict copy, which the vault ignores.
On the machine whose history lost: the next append is refused ("ledger.jsonl changed on
disk"), and verify() reports "ledger.jsonl on disk differs from the ledger in memory from
record N+1", and after reopening the catalog checks name the records the catalog knows
but the ledger lacks ("rollback: the catalog recorded ..." or "catalog head hash does
not match ledger record ..."). Nothing is merged automatically. Use one writing machine
at a time and let the folder finish syncing before writing on another.

**Read-only after a problem.** open() checks, before allowing any write: every line
parses, the whole chain and every signature, the header key, the catalog against the
ledger, where anchors point, every anchor token, and that anchors.jsonl holds as many
anchors as the catalog recorded. Any problem found there or later by verify() makes the
vault read-only (`Corrupted`) for the life of the object.

## 10. Anchors (anchors.jsonl)

One JSON object per line (the `Anchor` model): `seq_upto`, `head_hash` (record_hash of
`seq_upto`), `method` (`rfc3161`), `authority` (URL), `anchored_at` (time asserted by
the authority, ISO 8601 UTC), `proof` (base64 of the DER TimeStampToken, a CMS
ContentInfo). A reader bounds the file (16 MiB) and each proof (the base64 of a token of
at most 256 KiB) before decoding.

Request (RFC 3161 section 2.4.1), DER, POSTed with `Content-Type:
application/timestamp-query`:

```
TimeStampReq ::= SEQUENCE { version 1, messageImprint SEQUENCE {
    SEQUENCE { id-sha256 2.16.840.1.101.3.4.2.1, NULL }, OCTET STRING head_hash(32 raw bytes) },
  nonce INTEGER (random 63 bits), certReq TRUE }
```

That is: hashAlgorithm = id-sha256 and hashedMessage = the 32 raw bytes of head_hash,
taken as they are and not hashed again. This is byte-for-byte what `openssl ts -query
-digest <head_hash> -sha256 -cert` sends. Only the head hash leaves the machine. Because
`head_hash = SHA-256(prev_hash || body_digest)` already, the token is an ordinary RFC 3161
timestamp of those 64 bytes.

The default authority is `http://timestamp.digicert.com` (DigiCert's documented RFC 3161
URL; its tokens chain to "DigiCert Trusted Root G4"). Plain HTTP is acceptable because
the token is signed and only a hash is sent.

A token is in one of three states, kept distinct everywhere (ProvenanceProof and
VerifyReport `anchor_status`, the bundle README, the verifier's text and JSON):

* **invalid**: one of the token checks below fails. It proves nothing and gives no time.
* **claimed**: the token is internally valid, but its signer could not be authenticated
  (no trust root, or no valid certificate path). The date is a claim by an
  unauthenticated party: an HTTP intermediary could have made the certificate and the
  token. `claimed_before` is the earliest such date.
* **proven**: valid, and the signer certificate has a valid path to a trusted root at
  genTime. `proven_before` is the earliest such date; only a proven entry names an
  authority as authenticated.

Trust roots default to the public CA bundle of the installed `certifi` package (which
holds DigiCert Trusted Root G4); `Vault.trust_roots` and `--tsa-ca` replace it. By
default `anchor()` refuses to store a token that is not proven.

Token checks, written in `anchor.py` (copied verbatim into `verify_bundle.py`, as
`cryptography` has no CMS verifier): status granted; SignedData holding a TSTInfo;
imprint algorithm SHA-256 and hashedMessage equal to the raw head hash; the nonce (at
request time); the `messageDigest` signed attribute equals the hash of the TSTInfo; the
content-type attribute is id-ct-TSTInfo; the signature over the DER SET OF signed
attributes with the key of the signer certificate embedded in the token (RSA PKCS#1
v1.5, RSA-PSS with its RSASSA-PSS-params enforced: hash, MGF1 hash, salt length, trailer
field 1; ECDSA; Ed25519; SHA-1 is refused); the ESS signing-certificate attribute (v1 or
v2) names that certificate; that certificate carries the critical extended key usage
timeStamping only and is valid at genTime; `anchored_at` equals genTime.

Certificate path, by `cryptography.x509.verification` (49.0 or later), at genTime: path
building to the trust store, every signature, validity periods, cA and keyCertSign on
issuers, path length, name constraints, unknown critical extensions, web PKI algorithm
and key-size rules; adjusted for timestamping: no subjectAltName needed, signer EKU
critical timeStamping only, issuer EKU absent or allowing timeStamping. Not checked by
anyone: revocation (OCSP, CRL) and certificate policies. A third party who wants an
independent PKI check runs, with the authority's root:

```
openssl ts -verify -digest <head_hash> -token_in -in anchor-<seq>.tst -CAfile ROOT.pem [-untrusted INTERMEDIATE.pem]
```

An anchor of record S proves that records 0..S existed, with their exact contents, by
`anchored_at`. It says nothing about records after S.

OpenTimestamps is not implemented (`anchor("opentimestamps")` raises VaultError).

## 11. Disclosure bundle

`export_bundle()` writes `license-<license_id>/`:

```
manifest.json      UTF-8 JSON, below
grant.json         the committed bytes of the grant (section 8)
items/NN_<entry_id>_v<version>.<ext>   plaintext of each licensed version
anchors/anchor-<seq_upto>.tst          DER tokens of the anchors that cover an item
README.txt         instructions and the openssl commands
verify_bundle.py   copy of the verifier, when available
```

```
manifest = {
  "format": "empreinte-bundle", "format_version": 1,
  "license_id", "public_key": hex32, "exported_at": ledger time,
  "grant": {"file": "grant.json", "salt": hex32,
            "signature": hex64 = Ed25519("empreinte/v1/grant" || 0x00 || grant.json bytes),
            "record": the license ledger record, as a ledger line object},
  "items": [{"file", "entry_id", "version", "title", "media_type", "salt": hex32,
             "record": the put ledger record}],
  "chain": {"from_seq": F, "prev_hash": prev_hash of record F,
            "body_digests": [hex32 body_digest of records F, F+1, ..., head]},
  "head": {"seq", "record_hash", "signature"},
  "anchors": [Anchor objects with seq_upto >= F, plus "file"]
}
LicenseGrant.bundle_hash = hex(SHA-256(manifest.json bytes))
```

`F` is the smallest seq among the items and the license record. Records that are not
disclosed appear only as their body digest (and, for an anchored or neighbouring record,
its record hash): nothing about any other entry.

Verification algorithm (what `tools/verify_bundle.py` does):

1. `h[F-1] = chain.prev_hash`; for each digest `d[s]`, `h[s] = SHA-256(h[s-1] || d[s])`.
   The last value must equal `head.record_hash`, and `head.signature` must verify on it.
2. For each disclosed record r (the license record and each item): recompute its
   canonical body with the bundle's public key; `SHA-256(body) == d[r.seq]`,
   `r.prev_hash == h[r.seq-1]`, `SHA-256(r.prev_hash || SHA-256(body)) == r.record_hash == h[r.seq]`,
   and `r.signature` verifies.
3. Grant: `SHA-256(salt || grant.json) == license record commitment`, the grant signature
   verifies, its `license_id` and `seq` match.
4. Each item: `SHA-256(salt || plaintext) == record commitment`, the record is a `put` of
   that entry and version, and `(entry_id, version, commitment)` is listed in the grant.
5. Each anchor: `h[seq_upto] == head_hash` and the token checks of section 10. An item
   at seq s is covered by every anchor with `seq_upto >= s` that is not invalid; the
   earliest `anchored_at` of a proven one is the date by which it provably existed, the
   earliest of a claimed one is only a claim. Without an anchor the only date is the
   author's clock.
6. Files: every name in the manifest must be a plain relative path without `..`. The
   verifier opens it first, then checks the opened handle (a regular file, whose real
   path, read from the handle, is inside the bundle) and reads through that handle only.
   Limits: manifest 64 MiB, grant 1 MiB, each item 1 GiB (hashed in chunks), 100000 items,
   each proof 256 KiB once decoded. The bundle must hold exactly the granted items, each
   once.

`verify_bundle.py` needs Python 3.11+ and cryptography 49.0 or later; an older version is
refused with a message and exit status 2.

The licensee must obtain the vault public key from the author by another channel (a
published fingerprint) to know whose key it is; the bundle proves consistency with that
key, not identity.

## 12. What verify() checks

`Vault.verify()` (unlocked) reports, each with a specific message:

* every ledger line parses (`ledger line N: unreadable`);
* seq gapless, prev_hash chain, record_hash recomputed, Ed25519 signature with the
  identity key decrypted from the vault (`record N: signature invalid`);
* header public key equals the identity key (`header: public key does not match ...`);
* every blob named by a record exists, hashes to its cipher_hash and authenticates as
  the blob of that place (`record N: blob does not match cipher_hash`);
* the catalog against the ledger, both ways (every version, removal, license and
  royalty matches its record; every record is in the catalog);
* rollback: ledger shorter than the catalog's `n_records`, or a different `head_hash`;
* anchors: each covers a record of this ledger, its token checks pass, and none of the
  anchors the catalog counted is missing; `anchor_status` gives each anchor's state
  (proven, claimed, invalid). Only invalid ones are errors: a claim is reported, not
  failed.
* that what is on disk now (header, ledger, catalog, anchors) is what this object
  holds: verify() re-reads every file and repairs nothing.

Tamper cases covered by tests: a flipped byte in a blob; an edited, deleted, inserted or
reordered ledger line; a replaced public key (also with the whole chain re-signed by the
new key); a blob moved to another entry; the last lines removed together with their
blobs; a forged appended line; an edited or deleted anchor.

What it cannot detect:

* **A complete rewrite.** An attacker who can replace the whole directory with an older
  consistent copy (ledger, blobs and catalog together) produces a vault that verifies.
  Only an external anchor protects against an attacker who can rewrite everything: an
  anchored head that is no longer in the ledger, or a ledger that no longer matches it,
  exposes the change to anyone holding the anchor.
* Removing the last records together with their blobs and replacing catalog.bin by an
  older copy of it.
* Wrong ledger times: the local clock is trusted for order only.
* Deleted orphan blobs, deleted aux values (aux is a cache, not evidence).
* Which of two diverged histories is right (section 9, "Two machines").

## 13. Threat model

An attacker who obtains the vault directory (a stolen laptop, a cloud sync account)
learns: the number of records and their kinds, sizes of plaintexts (exactly, in the
ledger) and of blobs, ledger times, which records are versions of the same entry, which
entries were removed, how many licenses and royalty payments exist and when, the public
key, the KDF parameters, and the total size of the catalog and of aux values.

They cannot learn, without the passphrase or the recovery key: any content, title, path,
tag, claimed date, licensee, terms or amount; whether a guessed document is in the vault
(commitments are salted, file names are opaque); and they cannot add, alter, reorder or
move records or blobs without verify() reporting it (except the full rewrite above).

The passphrase is the weak point of an offline attack: Argon2id with 256 MiB and t=3
slows each guess, it does not save a weak passphrase. Out of scope: malware or a person
with access to the machine while the vault is unlocked (keys and plaintext are in
memory; Python cannot guarantee that freed memory is wiped, lock() only drops the
references), a compromised `cryptography` package, side channels, and the honesty of the
timestamp authority.

## 14. Versioning

`header.format_version`, the blob format byte, the ledger body `format` field, the
catalog `format_version`, the bundle `format_version` and the public catalogue
`format_version` (section 15) are all 1. A reader must refuse a version it does not know
rather than guess. A future version will add a new value and keep reading version 1.

## 15. Public catalogue

A catalogue is what the owner hands to a prospective licensee before any license: a
signed list of entries with their approved previews and date proofs, without any
content. It is not to be confused with `catalog.bin` (section 6), the vault's private
index. `export_catalogue()` writes `catalogue-<catalogue_id>/`:

```
catalogue.json     UTF-8 JSON, below; on its own it is the whole catalogue
anchors/anchor-<seq_upto>.tst   DER tokens of the anchors it uses, for openssl
README.txt         what it proves and how to check it
verify_bundle.py   copy of the verifier, when available
```

```
catalogue = {
  "format": "empreinte-catalogue", "format_version": 1,
  "catalogue_id": hex16 (random),
  "public_key": hex32 (vault identity),
  "exported_at": ledger time (the author's clock),
  "statement": text (what a catalogue proves and does not prove),
  "entries": [ENTRY, ...]   sorted by public_id,
  "anchors": [ANCHOR, ...],
  "signature": hex64 = Ed25519("empreinte/v1/catalogue" || 0x00 || C)
}
C = canonical JSON (section 1, ensure_ascii false, UTF-8) of the catalogue object without
    its "signature" key
ENTRY = {
  "public_id": hex16,
  "media_type": text, "words": int (word count from the preview),
  "summary": text, "keywords": [text],          the approved preview, as approved
  "commitment": hex32,                          of the exact version listed
  "record": the put ledger record of that version, as a ledger line object (section 8),
  "proof": null | {"anchor": index into "anchors",
                   "body_digests": [hex32 body_digest of records seq+1 .. anchor.seq_upto]},
  "title": text, "path": text, "tags": [text]   each present only when the owner chose it
}
ANCHOR = the Anchor object (section 10) plus "file"
```

Only an entry whose stored preview has `approved` true, and whose preview commitment is
one of the entry's recorded versions, can be listed; that version is the one listed
(an approved preview of an older version lists the older version). A draft is refused
and nothing is written. Each entry's anchor is the earliest proven anchor covering its
record, else the earliest claimed one; an invalid anchor is never used. Without one,
`proof` is null.

Canonical JSON for the signature: object keys sorted by code point, separators `,` and
`:`, non-ASCII characters written as UTF-8 (not escaped), strings escaped as Python's
`json.dumps` does (`\"`, `\\`, `\n`, `\r`, `\t`, `\b`, `\f`, other control characters as
`\u00XX` with lowercase hex). Only integers, strings, lists, objects and null occur.

**public_id.** 16 random bytes drawn the first time an (entry, version) is published, kept
encrypted (aux `catalogue/ids.v1`) and reused by every later catalogue, so a licensee can
name an entry across catalogues. It is a stable handle, not a mask: the disclosed ledger
record carries the vault's entry id, because the record's canonical body includes it and
the date proof needs that body. Choosing an unlinkable id per catalogue would therefore
hide nothing. Hiding the entry id would need a different ledger body (for example a
commitment to the entry id), that is a new ledger format; it was not done.

Verification algorithm (`verify_bundle.py --catalogue PATH`, PATH a catalogue directory
or its `catalogue.json`):

1. The exact set of top-level keys, entry keys (the optional three aside) and anchor keys.
   Limits: 64 MiB, 100000 entries, 100000 anchors.
2. `signature` verifies with `public_key` over `"empreinte/v1/catalogue" || 0x00 || C`.
   Any change to any field, the order of entries included, breaks it.
3. Each anchor: the token checks of section 10 against its own `head_hash`, and
   `anchored_at` equal to genTime; its state is invalid, claimed or proven.
4. Each entry: the record's canonical body is recomputed with `public_key`;
   `record_hash == SHA-256(prev_hash || SHA-256(body))`, the record signature verifies,
   `kind` is `put` and `record.commitment == commitment`. Public ids and commitments are
   unique. With a proof: `h = record_hash`, then `h = SHA-256(h || d)` for each digest;
   `h` must equal the anchor's `head_hash` and `anchor.seq_upto == record.seq + number of
   digests`. The entry is then proven from the anchor's genTime (proven anchor), claimed
   by an unauthenticated authority (claimed), or failed (invalid). Without a proof it is
   reported as not yet provable to a third party: its only date is the author's clock.
5. With a bundle too (`verify_bundle.py BUNDLE --catalogue PATH`): both are verified,
   both must carry the same public key, and each verified bundle item is matched to the
   verified catalogue entry with the same commitment and the same record (seq and
   record hash). That is what makes the catalogue a promise that can be checked: the
   licensed document is the one the catalogue dated.

What a catalogue proves: that the vault key signed this list, and that each listed
document, identified by its commitment, was recorded in that vault's ledger and, with a
proven anchor, existed no later than the authority's time. It proves nothing about the
quality or originality of a document, nor who wrote it beyond control of the key. The
summary is the owner's own statement: re-signing a changed summary with the vault key
produces a valid catalogue.

**What a catalogue reveals (threat note).** The catalogue is public. Per listed entry:
the approved summary and keywords (written by a local model, scrubbed, then read and
approved by the owner: the only text, and the owner's responsibility), the media type,
the word count, and through the record the exact plaintext size, the version number (so
how many earlier versions exist), the ledger time and seq of that version, the entry id
and the cipher hash. Through the seq and the digests: how many records precede the
listed one and how many lie between it and its anchor, so a rough rate of writing. Through
the anchors: the ledger length and the authority's time at each anchor used. Anyone who
also holds the vault's `ledger.jsonl` (a thief of the directory, a sync provider) can use
the entry id to find every version of a listed entry, their sizes and times, and whether
it was removed. About an entry that is not listed, nothing but 32-byte digests appears:
a body digest when its record lies between a listed record and its anchor, or its
record hash as the `prev_hash` of a listed record; not its kind, size, time, id, title,
path, tags or text. Two catalogues share the public id of an entry listed in both. The
title, path and tags of a listed entry appear only when the owner ticks them. The owner's
private record of each publication (aux `catalogue/published.v1`) stays encrypted.

## 16. Watched folders

`empreinte watch` and the server's continuous capture remember the watched folders and,
per folder, the size and modification time of every file last captured, in aux values
(`watch/folders.v1`, `watch/state.v1/<sha256 of path and prefix>`), encrypted like every
aux value. A capture is an ordinary `put()` (section 9): a watched folder adds nothing to
the public files beyond the ledger records of the versions it captures. Only the writer
captures (section 9, "One writer"): a second process that finds the writer lock held
refuses to start watching instead of opening read-only.
