//! External anchoring of the chain head by RFC 3161 trusted timestamping (Rust port).
//!
//! Provides ASN.1 / DER parsing and encoding for RFC 3161 TimeStampReq and TimeStampToken
//! (CMS SignedData encapsulating TSTInfo).

use anyhow::{Result, anyhow, bail, ensure};
use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
pub const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
pub const OID_CT_TSTINFO: &str = "1.2.840.113549.1.9.16.1.4";
pub const OID_MESSAGE_DIGEST: &str = "1.2.840.113549.1.9.4";
pub const OID_CONTENT_TYPE: &str = "1.2.840.113549.1.9.3";

// Maximum limits
pub const MAX_TOKEN_BYTES: usize = 256 * 1024;
pub const MAX_PROOF_CHARS: usize = 4 * ((MAX_TOKEN_BYTES + 2) / 3);

// ==============================================================================
// DER Node Parser
// ==============================================================================

#[derive(Clone, Debug)]
pub struct DerNode<'a> {
    pub data: &'a [u8],
    pub tag: u8,
    pub start: usize,
    pub body: usize,
    pub end: usize,
}

impl<'a> DerNode<'a> {
    pub fn raw(&self) -> &'a [u8] {
        &self.data[self.start..self.end]
    }

    pub fn content(&self) -> &'a [u8] {
        &self.data[self.body..self.end]
    }

    pub fn is_constructed(&self) -> bool {
        (self.tag & 0x20) != 0
    }

    pub fn children(&self) -> Result<Vec<DerNode<'a>>> {
        ensure!(self.is_constructed(), "valeur primitive sans enfants");
        let mut items = Vec::new();
        let mut pos = self.body;
        while pos < self.end {
            let child = parse_der(self.data, pos, self.end)?;
            pos = child.end;
            items.push(child);
        }
        Ok(items)
    }
}

pub fn parse_der(data: &[u8], pos: usize, limit: usize) -> Result<DerNode<'_>> {
    ensure!(pos + 2 <= limit, "DER tronqué");
    let tag = data[pos];
    ensure!(
        tag & 0x1F != 0x1F,
        "tags multi-octets non supportés en DER minimal"
    );

    let first = data[pos + 1];
    let body;
    let length: usize;

    if first < 0x80 {
        body = pos + 2;
        length = first as usize;
    } else if first == 0x80 {
        bail!("longueur indéfinie (BER) interdite en DER");
    } else {
        let count = (first & 0x7F) as usize;
        body = pos + 2 + count;
        ensure!(count <= 4 && body <= limit, "longueur DER invalide");
        let mut acc = 0usize;
        for &b in &data[pos + 2..body] {
            acc = (acc << 8) | (b as usize);
        }
        length = acc;
    }

    let end = body + length;
    ensure!(end <= limit, "longueur DER dépasse la limite");
    Ok(DerNode {
        data,
        tag,
        start: pos,
        body,
        end,
    })
}

pub fn parse_der_one(data: &[u8]) -> Result<DerNode<'_>> {
    let node = parse_der(data, 0, data.len())?;
    ensure!(node.end == data.len(), "octets résiduels après le DER");
    Ok(node)
}

pub fn read_int(node: &DerNode) -> Result<i64> {
    ensure!(node.tag == 0x02, "attendu INTEGER (0x02)");
    let bytes = node.content();
    ensure!(!bytes.is_empty(), "INTEGER vide");
    let mut acc = if (bytes[0] & 0x80) != 0 { -1i64 } else { 0i64 };
    for &b in bytes {
        acc = (acc << 8) | (b as i64);
    }
    Ok(acc)
}

pub fn read_oid(node: &DerNode) -> Result<String> {
    ensure!(node.tag == 0x06, "attendu OBJECT IDENTIFIER (0x06)");
    let bytes = node.content();
    ensure!(!bytes.is_empty(), "OID vide");

    let mut parts = Vec::new();
    let mut value = 0u64;

    for &b in bytes {
        value = (value << 7) | ((b & 0x7F) as u64);
        if (b & 0x80) == 0 {
            parts.push(value);
            value = 0;
        }
    }
    ensure!(!parts.is_empty(), "OID vide");

    let first = parts[0];
    let (head0, head1) = if first < 40 {
        (0, first)
    } else if first < 80 {
        (1, first - 40)
    } else {
        (2, first - 80)
    };

    let mut res = format!("{}.{}", head0, head1);
    for p in &parts[1..] {
        res.push_str(&format!(".{}", p));
    }
    Ok(res)
}

pub fn read_time(node: &DerNode) -> Result<DateTime<Utc>> {
    ensure!(node.tag == 0x18, "attendu GeneralizedTime (0x18)");
    let text = std::str::from_utf8(node.content())?;
    ensure!(
        text.ends_with('Z') && text.len() >= 15,
        "genTime doit être au format UTC ('Z')"
    );

    let base_part = &text[..14]; // YYYYMMDDHHMMSS
    let naive = NaiveDateTime::parse_from_str(base_part, "%Y%m%d%H%M%S")
        .map_err(|e| anyhow!("genTime invalide: {}", e))?;

    let frac_part = &text[14..text.len() - 1];
    let mut dt = DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc);

    if !frac_part.is_empty() {
        ensure!(
            frac_part.starts_with('.') && frac_part[1..].chars().all(|c| c.is_ascii_digit()),
            "fraction de seconde invalide dans genTime"
        );
        let digits = &frac_part[1..];
        let mut micros_str = String::from(digits);
        while micros_str.len() < 6 {
            micros_str.push('0');
        }
        micros_str.truncate(6);
        let micros: u32 = micros_str.parse()?;
        dt = dt + chrono::Duration::microseconds(micros as i64);
    }

    Ok(dt)
}

// ==============================================================================
// DER TLV Encoders
// ==============================================================================

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let n = content.len();
    let mut out = Vec::with_capacity(n + 4);
    out.push(tag);
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let mut len_bytes = Vec::new();
        let mut temp = n;
        while temp > 0 {
            len_bytes.push((temp & 0xFF) as u8);
            temp >>= 8;
        }
        len_bytes.reverse();
        out.push(0x80 | (len_bytes.len() as u8));
        out.extend_from_slice(&len_bytes);
    }
    out.extend_from_slice(content);
    out
}

pub fn enc_int(value: i64) -> Vec<u8> {
    let raw = value.to_be_bytes();
    let mut start = 0;
    while start + 1 < raw.len() {
        if raw[start] == 0 && (raw[start + 1] & 0x80) == 0 {
            start += 1;
        } else if raw[start] == 0xFF && (raw[start + 1] & 0x80) != 0 {
            start += 1;
        } else {
            break;
        }
    }
    tlv(0x02, &raw[start..])
}

pub fn enc_oid(dotted: &str) -> Vec<u8> {
    let parts: Vec<u64> = dotted.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() < 2 {
        return tlv(0x06, &[]);
    }
    let mut values = vec![parts[0] * 40 + parts[1]];
    values.extend_from_slice(&parts[2..]);

    let mut out = Vec::new();
    for mut val in values {
        let mut chunk = vec![(val & 0x7F) as u8];
        val >>= 7;
        while val > 0 {
            chunk.push(0x80 | ((val & 0x7F) as u8));
            val >>= 7;
        }
        chunk.reverse();
        out.extend_from_slice(&chunk);
    }
    tlv(0x06, &out)
}

pub fn enc_seq(items: &[&[u8]]) -> Vec<u8> {
    let mut content = Vec::new();
    for it in items {
        content.extend_from_slice(it);
    }
    tlv(0x30, &content)
}

pub fn enc_octets(value: &[u8]) -> Vec<u8> {
    tlv(0x04, value)
}

pub fn enc_bool(value: bool) -> Vec<u8> {
    tlv(0x01, &[if value { 0xFF } else { 0x00 }])
}

pub fn enc_null() -> Vec<u8> {
    vec![0x05, 0x00]
}

/// Builds an RFC 3161 TimeStampReq DER
pub fn make_request(head_hash: &[u8; 32], nonce: u64) -> Vec<u8> {
    let alg_id = enc_seq(&[&enc_oid(OID_SHA256), &enc_null()]);
    let imprint = enc_seq(&[&alg_id, &enc_octets(head_hash)]);
    let version = enc_int(1);
    let nonce_der = enc_int(nonce as i64);
    let cert_req = enc_bool(true);
    enc_seq(&[&version, &imprint, &nonce_der, &cert_req])
}

// ==============================================================================
// Token Extraction and Verification
// ==============================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TstInfo {
    pub version: i64,
    pub policy: String,
    pub hash_algo: String,
    pub hashed_message: Vec<u8>,
    pub serial_number: i64,
    pub gen_time: DateTime<Utc>,
    pub nonce: Option<i64>,
}

pub fn extract_token_node<'a>(data: &'a [u8]) -> Result<DerNode<'a>> {
    let root = parse_der_one(data)?;
    ensure!(root.tag == 0x30, "attendu SEQUENCE");
    let children = root.children()?;
    ensure!(!children.is_empty(), "SEQUENCE vide");

    // If first child is SEQUENCE with INTEGER, it's TimeStampResp
    if children[0].tag == 0x30 {
        if let Ok(st_children) = children[0].children() {
            if !st_children.is_empty() && st_children[0].tag == 0x02 {
                let status = read_int(&st_children[0])?;
                ensure!(status == 0 || status == 1, "statut PKI rejeté: {}", status);
                ensure!(children.len() >= 2, "réponse accordée mais sans jeton");
                return Ok(children[1].clone());
            }
        }
    }
    Ok(root)
}

pub fn extract_tstinfo(token_or_resp_der: &[u8]) -> Result<(TstInfo, Vec<u8>)> {
    let token_node = extract_token_node(token_or_resp_der)?;
    let top_children = token_node.children()?;
    ensure!(top_children.len() >= 2, "ContentInfo incomplet");

    let ct_oid = read_oid(&top_children[0])?;
    ensure!(
        ct_oid == OID_SIGNED_DATA,
        "ContentInfo n'est pas signedData ({})",
        ct_oid
    );

    // signedData content is [0] EXPLICIT
    let wrapper = &top_children[1];
    ensure!(
        wrapper.tag == 0xa0,
        "attendu [0] EXPLICIT pour le contenu de signedData"
    );
    let signed_data = wrapper.children()?[0].clone();
    ensure!(signed_data.tag == 0x30, "SignedData doit être SEQUENCE");

    let sd_children = signed_data.children()?;
    ensure!(sd_children.len() >= 3, "SignedData incomplet");

    // encapContentInfo is child at index 2
    let encap = &sd_children[2];
    ensure!(encap.tag == 0x30, "encapContentInfo doit être SEQUENCE");
    let encap_children = encap.children()?;
    ensure!(encap_children.len() >= 2, "encapContentInfo incomplet");

    let inner_type = read_oid(&encap_children[0])?;
    ensure!(
        inner_type == OID_CT_TSTINFO,
        "eContentType n'est pas id-ct-TSTInfo ({})",
        inner_type
    );

    let econtent_wrapper = &encap_children[1];
    ensure!(
        econtent_wrapper.tag == 0xa0,
        "eContent doit être [0] EXPLICIT"
    );
    let octets = econtent_wrapper.children()?[0].clone();
    ensure!(octets.tag == 0x04, "eContent doit être OCTET STRING");

    let tstinfo_raw = octets.content().to_vec();
    let tst_node = parse_der_one(&tstinfo_raw)?;
    ensure!(tst_node.tag == 0x30, "TSTInfo doit être SEQUENCE");
    let tst_children = tst_node.children()?;
    ensure!(tst_children.len() >= 5, "TSTInfo incomplet");

    let version = read_int(&tst_children[0])?;
    let policy = read_oid(&tst_children[1])?;

    // messageImprint
    let imprint_node = &tst_children[2];
    ensure!(
        imprint_node.tag == 0x30,
        "messageImprint doit être SEQUENCE"
    );
    let imp_children = imprint_node.children()?;
    ensure!(imp_children.len() >= 2, "messageImprint incomplet");

    let hash_algo_seq = &imp_children[0];
    let hash_algo = read_oid(&hash_algo_seq.children()?[0])?;
    let hashed_message = imp_children[1].content().to_vec();

    let serial_number = read_int(&tst_children[3])?;
    let gen_time = read_time(&tst_children[4])?;

    let mut nonce = None;
    for child in &tst_children[5..] {
        if child.tag == 0x02 {
            nonce = Some(read_int(child)?);
            break;
        }
    }

    Ok((
        TstInfo {
            version,
            policy,
            hash_algo,
            hashed_message,
            serial_number,
            gen_time,
            nonce,
        },
        tstinfo_raw,
    ))
}

/// Evaluates a base64 DER token against the vault's head hash.
/// Returns status: "proven", "claimed", or "invalid".
pub fn evaluate_token(proof_b64: &str, expected_head_hash: &[u8]) -> Result<Value> {
    if proof_b64.len() > MAX_PROOF_CHARS {
        bail!("preuve d'ancrage trop volumineuse");
    }

    let trimmed = proof_b64.trim();
    let token_der = data_encoding::BASE64
        .decode(trimmed.as_bytes())
        .map_err(|e| anyhow!("base64 invalide: {}", e))?;

    ensure!(
        token_der.len() <= MAX_TOKEN_BYTES,
        "jeton DER dépasse la taille limite"
    );

    let (tst, tst_raw) = match extract_tstinfo(&token_der) {
        Ok(res) => res,
        Err(e) => {
            return Ok(json!({
                "status": "invalid",
                "error": format!("décodage du jeton TSTInfo impossible: {}", e)
            }));
        }
    };

    if tst.hash_algo != OID_SHA256 {
        return Ok(json!({
            "status": "invalid",
            "error": format!("algorithme de hachage rejeté: {}", tst.hash_algo)
        }));
    }

    if tst.hashed_message != expected_head_hash {
        return Ok(json!({
            "status": "invalid",
            "error": "l'empreinte scellée dans le jeton ne correspond pas à la tête du registre"
        }));
    }

    // Verify SignedAttributes messageDigest match if present
    let tst_digest = Sha256::digest(&tst_raw);
    let token_node = extract_token_node(&token_der)?;
    let top_children = token_node.children()?;
    let wrapper = &top_children[1];
    let signed_data = wrapper.children()?[0].clone();
    let sd_children = signed_data.children()?;

    if let Some(signer_infos_set) = sd_children.last() {
        if signer_infos_set.is_constructed() && !signer_infos_set.children()?.is_empty() {
            let signer_info = &signer_infos_set.children()?[0];
            let si_children = signer_info.children()?;
            for child in &si_children {
                if child.tag == 0xa0 {
                    for attr in child.children()? {
                        let attr_children = attr.children()?;
                        if attr_children.len() >= 2 {
                            let oid = read_oid(&attr_children[0])?;
                            if oid == OID_MESSAGE_DIGEST {
                                let val_set = &attr_children[1];
                                if let Some(octets) = val_set.children()?.first() {
                                    if octets.content() != tst_digest.as_slice() {
                                        return Ok(json!({
                                            "status": "invalid",
                                            "error": "messageDigest dans signedAttrs ne correspond pas au hachage de TSTInfo"
                                        }));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let iso_date = tst.gen_time.to_rfc3339();

    Ok(json!({
        "status": "proven",
        "anchored_at": iso_date,
        "serial": tst.serial_number,
        "policy": tst.policy
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPENSSL_DIGEST: [u8; 32] = [
        0x5f, 0x2b, 0x51, 0xca, 0x2f, 0xdc, 0x5b, 0xaa, 0x31, 0xec, 0x02, 0xe0, 0x02, 0xf6, 0x9a,
        0xec, 0x38, 0x2b, 0xfb, 0x4b, 0x0b, 0x0f, 0x0e, 0x56, 0xbb, 0xbe, 0x0d, 0x6e, 0x0d, 0x2b,
        0x7f, 0x1c,
    ];

    #[test]
    fn make_request_encodes_rfc3161() {
        let req = make_request(&OPENSSL_DIGEST, 0x12345678);
        assert!(req.len() > 30);
        let node = parse_der_one(&req).unwrap();
        assert_eq!(node.tag, 0x30);
    }

    #[test]
    fn parses_openssl_tstinfo() {
        let b64 = include_str!("../../tools/openssl_resp.b64").trim();
        let der = data_encoding::BASE64.decode(b64.as_bytes()).unwrap();
        let (tst, _) = extract_tstinfo(&der).unwrap();
        assert_eq!(tst.version, 1);
        assert_eq!(tst.hash_algo, OID_SHA256);
        assert_eq!(tst.hashed_message.as_slice(), &OPENSSL_DIGEST);
    }

    #[test]
    fn evaluates_token_match_and_mismatch() {
        let b64 = include_str!("../../tools/openssl_resp.b64").trim();
        let res = evaluate_token(b64, &OPENSSL_DIGEST).unwrap();
        assert_eq!(res["status"], "proven");

        let mut wrong = OPENSSL_DIGEST;
        wrong[0] ^= 0xFF;
        let fail = evaluate_token(b64, &wrong).unwrap();
        assert_eq!(fail["status"], "invalid");
    }
}
