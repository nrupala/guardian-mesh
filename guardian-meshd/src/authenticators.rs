// authenticators.rs — Boundary authenticators: SPIFFE SVID + OpenPGP second-factor framework
// WO-14 v0.12.0
//
// Honesty boundary:
// - v1 verifies SVID leaf structure and possession of its key. It does NOT verify a chain
//   to a SPIFFE trust bundle and does NOT terminate mTLS transport.
// - v1 OpenPGP supports Ed25519 keys and SHA-256/SHA-512 signature digests only.
//   Any other algorithm is refused with a message naming it.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256, Sha512};
use sha1::Sha1;

/// Authentication methods supported by Guardian Mesh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    MlDsa65,
    HmacSession,
    SpiffeX509,
    OpenPgp,
}

impl AuthMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthMethod::MlDsa65 => "ML_DSA_65",
            AuthMethod::HmacSession => "HMAC_SESSION",
            AuthMethod::SpiffeX509 => "SPIFFE_X509",
            AuthMethod::OpenPgp => "OPENPGP",
        }
    }

    pub fn factor_type(&self) -> &'static str {
        match self {
            AuthMethod::MlDsa65 => "possession",
            AuthMethod::HmacSession => "possession",
            AuthMethod::SpiffeX509 => "workload-attestation",
            AuthMethod::OpenPgp => "possession",
        }
    }

    pub fn assurance(&self) -> &'static str {
        match self {
            AuthMethod::MlDsa65 => "high",
            AuthMethod::HmacSession => "medium",
            AuthMethod::SpiffeX509 => "high",
            AuthMethod::OpenPgp => "high",
        }
    }
}

/// Parsed SPIFFE SVID information.
#[derive(Debug)]
pub struct SvidInfo {
    pub spiffe_id: String,
    pub public_key: [u8; 32],
    pub not_before: u64,
    pub not_after: u64,
    pub serial_hex: String,
}

/// Parsed OpenPGP public key.
#[derive(Debug)]
pub struct PgpKey {
    pub fingerprint: String,
    pub public_key: [u8; 32],
    pub created: u32,
}

// ============================================================================
// SVID parsing (DER walker)
// ============================================================================

/// Parse a SPIFFE SVID from DER-encoded X.509 certificate.
/// v1: validates leaf structure, Ed25519 SPKI, SAN SPIFFE ID, validity window.
/// Does NOT verify CA signature chain.
pub fn parse_svid(der: &[u8], now_secs: u64) -> Result<SvidInfo, String> {
    let mut cursor = 0;

    // Certificate SEQUENCE
    let (cert_end, _) = read_sequence(der, &mut cursor)?;

    // TBSCertificate SEQUENCE
    let tbs_start = cursor;
    let (tbs_end, _) = read_sequence(der, &mut cursor)?;

    // Optional [0] version (default v1 = 0, but SPIFFE uses v3 = 2)
    let mut serial_start = cursor;
    if cursor < tbs_end && der[cursor] == 0xA0 {
        let _ = skip_constructed(der, &mut cursor)?;
        serial_start = cursor;
    }

    // Serial INTEGER
    let serial_bytes = read_integer(der, &mut cursor)?;
    let serial_hex = hex_encode(serial_bytes);

    // Signature algorithm SEQUENCE
    skip_sequence(der, &mut cursor)?;

    // Issuer SEQUENCE
    skip_sequence(der, &mut cursor)?;

    // Validity SEQUENCE
    let (val_end, _) = read_sequence(der, &mut cursor)?;
    let not_before = read_time(der, &mut cursor)?;
    if cursor >= val_end {
        return Err("missing notAfter in validity".into());
    }
    let not_after = read_time(der, &mut cursor)?;

    if now_secs < not_before {
        return Err("SVID not yet valid".into());
    }
    if now_secs > not_after {
        return Err("SVID expired".into());
    }

    // Subject SEQUENCE
    skip_sequence(der, &mut cursor)?;

    // SubjectPublicKeyInfo SEQUENCE
    let (spki_end, _) = read_sequence(der, &mut cursor)?;
    let spki_alg_start = cursor;
    let (alg_end, _) = read_sequence(der, &mut cursor)?;

    // Algorithm OID: must be Ed25519 1.3.101.112 → DER 06 03 2B 65 70
    let oid_tag = der.get(cursor).ok_or("truncated SPKI algorithm")?;
    if *oid_tag != 0x06 {
        return Err("missing OID in SPKI algorithm".into());
    }
    cursor += 1;
    let oid_len = read_length(der, &mut cursor)?;
    let oid_bytes = der
        .get(cursor..cursor + oid_len)
        .ok_or("truncated OID")?;
    if oid_bytes != [0x2B, 0x65, 0x70] {
        return Err("unsupported SVID public key algorithm (v1 supports Ed25519 only)".into());
    }
    cursor += oid_len;

    // BIT STRING
    if cursor >= spki_end {
        return Err("missing BIT STRING in SPKI".into());
    }
    let bs_tag = der[cursor];
    if bs_tag != 0x03 {
        return Err("expected BIT STRING in SPKI".into());
    }
    cursor += 1;
    let bs_len = read_length(der, &mut cursor)?;
    let bs_start = cursor;
    let unused_bits = *der.get(cursor).ok_or("truncated BIT STRING")?;
    cursor += 1;
    if unused_bits != 0 {
        return Err("BIT STRING unused bits must be 0".into());
    }
    let key_bytes = der
        .get(cursor..cursor + 32)
        .ok_or("BIT STRING does not contain 32-byte Ed25519 key")?;
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(key_bytes);
    cursor = bs_start + bs_len;

    // Extensions: scan for SAN [3]
    let mut spiffe_id = None;
    while cursor < tbs_end {
        let tag = der[cursor];
        if tag == 0xA3 {
            // [3] extensions
            cursor += 1;
            let ext_outer_len = read_length(der, &mut cursor)?;
            let ext_outer_end = cursor + ext_outer_len;

            // SEQUENCE of extensions
            let (ext_seq_end, _) = read_sequence(der, &mut cursor)?;

            while cursor < ext_seq_end {
                let (one_ext_end, _) = read_sequence(der, &mut cursor)?;
                let ext_oid_tag = der.get(cursor).ok_or("truncated extension OID")?;
                if *ext_oid_tag != 0x06 {
                    cursor = one_ext_end;
                    continue;
                }
                cursor += 1;
                let ext_oid_len = read_length(der, &mut cursor)?;
                let ext_oid = der
                    .get(cursor..cursor + ext_oid_len)
                    .ok_or("truncated extension OID")?;
                cursor += ext_oid_len;

                // SAN OID 2.5.29.17 → 55 1D 11
                if ext_oid == [0x55, 0x1D, 0x11] {
                    // Optional critical BOOL
                    if cursor < one_ext_end && der[cursor] == 0x01 {
                        cursor += 1;
                        let _ = read_length(der, &mut cursor)?;
                        cursor += 1; // skip bool value
                    }
                    // OCTET STRING wrapping GeneralNames
                    if cursor >= one_ext_end || der[cursor] != 0x04 {
                        return Err("malformed SAN extension".into());
                    }
                    cursor += 1;
                    let octet_len = read_length(der, &mut cursor)?;
                    let octet_start = cursor;

                    // GeneralNames SEQUENCE
                    let (gn_end, _) = read_sequence(der, &mut cursor)?;
                    while cursor < gn_end {
                        let name_tag = der[cursor];
                        cursor += 1;
                        let name_len = read_length(der, &mut cursor)?;
                        if name_tag == 0x86 {
                            // uniformResourceIdentifier
                            let uri_bytes = der
                                .get(cursor..cursor + name_len)
                                .ok_or("truncated URI SAN")?;
                            let uri = std::str::from_utf8(uri_bytes)
                                .map_err(|_| "non-UTF8 URI SAN")?
                                .to_string();
                            spiffe_id = Some(uri);
                            break;
                        }
                        cursor += name_len;
                    }
                    cursor = one_ext_end;
                    break;
                }
                cursor = one_ext_end;
            }
            cursor = ext_outer_end;
            break;
        } else {
            cursor += 1;
        }
    }

    let spiffe_id = spiffe_id.ok_or("missing SPIFFE ID in SAN extension")?;

    Ok(SvidInfo {
        spiffe_id,
        public_key,
        not_before,
        not_after,
        serial_hex,
    })
}

/// Construct canonical SPIFFE binding string.
pub fn canonical_spiffe_string(spiffe_id: &str, ml_dsa_key_sha256_hex: &str) -> String {
    format!(
        "guardian-mesh-spiffe-v1\nspiffe_id={}\nml_dsa_key_sha256={}\n",
        spiffe_id, ml_dsa_key_sha256_hex
    )
}

/// Verify SPIFFE possession: signature by SVID Ed25519 key over canonical string.
pub fn verify_spiffe_possession(
    info: &SvidInfo,
    canonical: &str,
    signature: &[u8],
) -> Result<(), String> {
    if signature.len() != 64 {
        return Err(format!(
            "SPIFFE possession signature must be exactly 64 bytes, got {}",
            signature.len()
        ));
    }

    let vk = VerifyingKey::from_bytes(&info.public_key)
        .map_err(|e| format!("invalid Ed25519 public key: {}", e))?;
    let sig = Signature::from_bytes(
        signature
            .try_into()
            .map_err(|_| "signature length mismatch")?,
    );

    vk.verify(canonical.as_bytes(), &sig)
        .map_err(|_| "SPIFFE possession signature verification failed".to_string())
}

/// Extract trust domain from SPIFFE ID.
pub fn spiffe_trust_domain(spiffe_id: &str) -> Result<String, String> {
    if !spiffe_id.starts_with("spiffe://") {
        return Err(format!("invalid SPIFFE ID: {}", spiffe_id));
    }
    let after_scheme = &spiffe_id[9..];
    let slash_pos = after_scheme.find('/').unwrap_or(after_scheme.len());
    let domain = &after_scheme[..slash_pos];
    if domain.is_empty() {
        return Err("SPIFFE ID trust domain is empty".into());
    }
    Ok(domain.to_string())
}

// ============================================================================
// OpenPGP parsing (Ed25519 only, v4 keys)
// ============================================================================

/// Parse OpenPGP public key from ASCII-armored data.
/// v1: Ed25519 only. Fingerprint is the RFC 4880 v4 fingerprint (SHA-1).
pub fn parse_pgp_public_key(armored: &str) -> Result<PgpKey, String> {
    let data = dearmor(armored, "PUBLIC KEY BLOCK")?;
    let mut packets = PacketIter::new(&data);

    while let Some((tag, body)) = packets.next()? {
        if tag == 6 {
            // Public-Key packet
            return parse_public_key_packet(body);
        }
    }

    Err("no public key packet found".into())
}

/// Verify detached OpenPGP signature.
pub fn verify_pgp_detached(key: &PgpKey, armored_sig: &str, data: &[u8]) -> Result<(), String> {
    let sig_data = dearmor(armored_sig, "SIGNATURE")?;
    let mut packets = PacketIter::new(&sig_data);

    while let Some((tag, body)) = packets.next()? {
        if tag == 2 {
            // Signature packet
            return verify_signature_packet(key, body, data);
        }
    }

    Err("no signature packet found".into())
}

/// Dearmor PGP ASCII-armored data.
pub fn dearmor(armored: &str, expected_label: &str) -> Result<Vec<u8>, String> {
    let begin_marker = format!("-----BEGIN PGP {}-----", expected_label);
    let end_marker = format!("-----END PGP {}-----", expected_label);

    let begin_pos = armored
        .find(&begin_marker)
        .ok_or("armor begin marker not found")?;
    let end_pos = armored
        .find(&end_marker)
        .ok_or("armor end marker not found")?;

    let body = &armored[begin_pos + begin_marker.len()..end_pos];
    let mut base64_data = String::new();

    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('=') || trimmed.contains(": ") {
            continue;
        }
        base64_data.push_str(trimmed);
    }

    base64_decode(&base64_data)
}

// ============================================================================
// OpenPGP internals
// ============================================================================

fn parse_public_key_packet(body: &[u8]) -> Result<PgpKey, String> {
    let mut pos = 0;

    let version = read_u8(body, &mut pos)?;
    if version != 4 {
        return Err(format!("unsupported PGP key version: {}", version));
    }

    let created = read_u32_be(body, &mut pos)?;

    let algo = read_u8(body, &mut pos)?;
    if algo != 22 {
        return Err(format!(
            "unsupported PGP key algorithm: {} (v1 supports EdDSA/22 only)",
            algo
        ));
    }

    // Curve OID length-prefixed
    let oid_len = read_u8(body, &mut pos)? as usize;
    let oid_bytes = body
        .get(pos..pos + oid_len)
        .ok_or("truncated curve OID")?;
    // Ed25519 OID 1.3.6.1.4.1.11591.15.1 → 2B 06 01 04 01 DA 47 0F 01
    if oid_bytes != [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01] {
        return Err("unsupported curve (v1 supports Ed25519 only)".into());
    }
    pos += oid_len;

    // Point MPI
    let bit_len = read_u16_be(body, &mut pos)? as usize;
    let byte_len = (bit_len + 7) / 8;
    let mpi_bytes = body.get(pos..pos + byte_len).ok_or("truncated MPI")?;
    if mpi_bytes.len() != 33 || mpi_bytes[0] != 0x40 {
        return Err("malformed Ed25519 point MPI".into());
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&mpi_bytes[1..33]);
    pos += byte_len;

    // Fingerprint: RFC 4880 v4 — SHA-1 over 0x99 || u16be(body len) || body.
    let mut fp_input = Vec::with_capacity(body.len() + 3);
    fp_input.push(0x99);
    fp_input.extend_from_slice(&(body.len() as u16).to_be_bytes());
    fp_input.extend_from_slice(body);
    let digest = <Sha1 as sha1::Digest>::digest(&fp_input);
    let fingerprint = hex_encode(&digest[..]);

    Ok(PgpKey {
        fingerprint,
        public_key,
        created,
    })
}

fn verify_signature_packet(key: &PgpKey, body: &[u8], data: &[u8]) -> Result<(), String> {
    let mut pos = 0;

    let version = read_u8(body, &mut pos)?;
    if version != 4 {
        return Err(format!("unsupported signature version: {}", version));
    }

    let sig_type = read_u8(body, &mut pos)?;
    if sig_type != 0x00 {
        return Err(format!(
            "unsupported signature type: 0x{:02x} (expected 0x00)",
            sig_type
        ));
    }

    let pubkey_algo = read_u8(body, &mut pos)?;
    if pubkey_algo != 22 {
        return Err(format!(
            "unsupported signature algorithm: {} (expected EdDSA/22)",
            pubkey_algo
        ));
    }

    let hash_algo = read_u8(body, &mut pos)?;
    let hash_fn: fn(&[u8]) -> Vec<u8> = match hash_algo {
        8 => |d| Sha256::digest(d).to_vec(),
        10 => |d| Sha512::digest(d).to_vec(),
        _ => {
            return Err(format!(
                "unsupported hash algorithm: {} (v1 supports SHA-256/8 or SHA-512/10 only)",
                hash_algo
            ))
        }
    };

    let hashed_len = read_u16_be(body, &mut pos)? as usize;
    let hashed_start = pos;
    let hashed_subpkts = body
        .get(pos..pos + hashed_len)
        .ok_or("truncated hashed subpackets")?;
    pos += hashed_len;

    let unhashed_len = read_u16_be(body, &mut pos)? as usize;
    pos += unhashed_len;

    let left_2 = body.get(pos..pos + 2).ok_or("missing left-2 hash bytes")?;
    pos += 2;

    // R point MPI
    let r_bit_len = read_u16_be(body, &mut pos)? as usize;
    let r_byte_len = (r_bit_len + 7) / 8;
    let r_mpi = body.get(pos..pos + r_byte_len).ok_or("truncated R MPI")?;
    // OpenPGP EdDSA signature R is the 32-byte compressed point as a bare
    // MPI (GnuPG emits 255 bits = 32 bytes, no 0x40 prefix — that prefix is
    // the EC point format used in KEY packets). Accept both encodings.
    let mut r_bytes = [0u8; 32];
    if r_mpi.len() == 33 && r_mpi[0] == 0x40 {
        r_bytes.copy_from_slice(&r_mpi[1..33]);
    } else if r_mpi.len() <= 32 {
        // Bare MPI: leading zero bytes are stripped by MPI encoding, so a
        // point whose first byte(s) are zero arrives shorter — left-pad.
        r_bytes[32 - r_mpi.len()..].copy_from_slice(r_mpi);
    } else {
        return Err("malformed R point MPI".into());
    }
    pos += r_byte_len;

    // S MPI (big-endian integer → last 32 bytes)
    let s_bit_len = read_u16_be(body, &mut pos)? as usize;
    let s_byte_len = (s_bit_len + 7) / 8;
    let s_mpi = body.get(pos..pos + s_byte_len).ok_or("truncated S MPI")?;
    let mut s_bytes = [0u8; 32];
    if s_mpi.len() <= 32 {
        s_bytes[32 - s_mpi.len()..].copy_from_slice(s_mpi);
    } else {
        s_bytes.copy_from_slice(&s_mpi[s_mpi.len() - 32..]);
    }
    pos += s_byte_len;

    // Build signature R||S
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&r_bytes);
    sig_bytes[32..].copy_from_slice(&s_bytes);

    // Trailer: version..hashed_subpkts_end, then 0x04 0xFF || u32be(trailer_len)
    let trailer_body = &body[..hashed_start + hashed_len];
    let trailer_len = trailer_body.len() as u32;
    let mut trailer_suffix = vec![0x04, 0xFF];
    trailer_suffix.extend_from_slice(&trailer_len.to_be_bytes());

    // Full hashed message: data || trailer_body || trailer_suffix
    let mut hashed_message = Vec::new();
    hashed_message.extend_from_slice(data);
    hashed_message.extend_from_slice(trailer_body);
    hashed_message.extend_from_slice(&trailer_suffix);

    let digest = hash_fn(&hashed_message);

    // Check left-2
    if digest[0..2] != *left_2 {
        return Err("signature left-2 hash bytes mismatch".into());
    }

    // OpenPGP EdDSA quirk (RFC 4880bis §12.8): Ed25519 signs the DIGEST
    // bytes, not the original message — the digest computed above is the
    // exact input to the Ed25519 verification.
    let vk = VerifyingKey::from_bytes(&key.public_key)
        .map_err(|e| format!("invalid Ed25519 public key: {}", e))?;
    let sig = Signature::from_bytes(&sig_bytes);

    vk.verify(&digest, &sig)
        .map_err(|_| "OpenPGP signature verification failed".to_string())
}

struct PacketIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> PacketIter<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn next(&mut self) -> Result<Option<(u8, &'a [u8])>, String> {
        if self.pos >= self.data.len() {
            return Ok(None);
        }

        let header = self.data[self.pos];
        self.pos += 1;

        if (header & 0x80) == 0 {
            return Err("invalid packet header".into());
        }

        let (tag, length) = if (header & 0x40) == 0 {
            // Old format
            let tag = (header >> 2) & 0x0F;
            let len_type = header & 0x03;
            let length = match len_type {
                0 => {
                    let l = *self.data.get(self.pos).ok_or("truncated old-format length")? as usize;
                    self.pos += 1;
                    l
                }
                1 => {
                    let l = u16::from_be_bytes(
                        self.data
                            .get(self.pos..self.pos + 2)
                            .ok_or("truncated old-format length")?
                            .try_into()
                            .unwrap(),
                    ) as usize;
                    self.pos += 2;
                    l
                }
                2 => {
                    let l = u32::from_be_bytes(
                        self.data
                            .get(self.pos..self.pos + 4)
                            .ok_or("truncated old-format length")?
                            .try_into()
                            .unwrap(),
                    ) as usize;
                    self.pos += 4;
                    l
                }
                _ => return Err("unsupported old-format length type".into()),
            };
            (tag, length)
        } else {
            // New format
            let tag = header & 0x3F;
            let first = *self.data.get(self.pos).ok_or("truncated new-format length")?;
            self.pos += 1;
            let length = if first < 192 {
                first as usize
            } else if first < 224 {
                let second = *self
                    .data
                    .get(self.pos)
                    .ok_or("truncated new-format two-byte length")?;
                self.pos += 1;
                ((first as usize - 192) << 8) + second as usize + 192
            } else if first == 255 {
                let l = u32::from_be_bytes(
                    self.data
                        .get(self.pos..self.pos + 4)
                        .ok_or("truncated new-format four-byte length")?
                        .try_into()
                        .unwrap(),
                ) as usize;
                self.pos += 4;
                l
            } else {
                return Err("unsupported partial-length packet".into());
            };
            (tag, length)
        };

        let body = self
            .data
            .get(self.pos..self.pos + length)
            .ok_or("truncated packet body")?;
        self.pos += length;

        Ok(Some((tag, body)))
    }
}

// ============================================================================
// DER parsing helpers
// ============================================================================

fn read_sequence(data: &[u8], cursor: &mut usize) -> Result<(usize, usize), String> {
    let tag = *data.get(*cursor).ok_or("truncated sequence tag")?;
    if tag != 0x30 {
        return Err(format!("expected SEQUENCE tag 0x30, got 0x{:02x}", tag));
    }
    *cursor += 1;
    let length = read_length(data, cursor)?;
    let end = *cursor + length;
    Ok((end, length))
}

fn skip_sequence(data: &[u8], cursor: &mut usize) -> Result<(), String> {
    let (end, _) = read_sequence(data, cursor)?;
    *cursor = end;
    Ok(())
}

fn skip_constructed(data: &[u8], cursor: &mut usize) -> Result<(), String> {
    let tag = *data.get(*cursor).ok_or("truncated constructed tag")?;
    *cursor += 1;
    let length = read_length(data, cursor)?;
    *cursor += length;
    Ok(())
}

fn read_integer<'a>(data: &'a [u8], cursor: &mut usize) -> Result<&'a [u8], String> {
    let tag = *data.get(*cursor).ok_or("truncated integer tag")?;
    if tag != 0x02 {
        return Err("expected INTEGER tag 0x02".into());
    }
    *cursor += 1;
    let length = read_length(data, cursor)?;
    let int_bytes = data.get(*cursor..*cursor + length).ok_or("truncated integer")?;
    *cursor += length;
    Ok(int_bytes)
}

fn read_length(data: &[u8], cursor: &mut usize) -> Result<usize, String> {
    let first = *data.get(*cursor).ok_or("truncated length byte")?;
    *cursor += 1;
    if (first & 0x80) == 0 {
        Ok(first as usize)
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes == 1 {
            let l = *data.get(*cursor).ok_or("truncated long-form length")?;
            *cursor += 1;
            Ok(l as usize)
        } else if num_bytes == 2 {
            let bytes = data.get(*cursor..*cursor + 2).ok_or("truncated long-form length")?;
            *cursor += 2;
            Ok(u16::from_be_bytes([bytes[0], bytes[1]]) as usize)
        } else {
            Err(format!("unsupported length encoding: {} bytes", num_bytes))
        }
    }
}

fn read_time(data: &[u8], cursor: &mut usize) -> Result<u64, String> {
    let tag = *data.get(*cursor).ok_or("truncated time tag")?;
    *cursor += 1;
    let length = read_length(data, cursor)?;
    let time_bytes = data.get(*cursor..*cursor + length).ok_or("truncated time")?;
    *cursor += length;

    let time_str = std::str::from_utf8(time_bytes).map_err(|_| "non-UTF8 time")?;

    if tag == 0x17 {
        // UTCTime YYMMDDhhmmssZ
        if time_str.len() != 13 || !time_str.ends_with('Z') {
            return Err("malformed UTCTime".into());
        }
        let yy: u32 = time_str[0..2].parse().map_err(|_| "invalid UTCTime year")?;
        let year = if yy <= 49 { 2000 + yy } else { 1900 + yy };
        let month: u32 = time_str[2..4].parse().map_err(|_| "invalid UTCTime month")?;
        let day: u32 = time_str[4..6].parse().map_err(|_| "invalid UTCTime day")?;
        let hour: u32 = time_str[6..8].parse().map_err(|_| "invalid UTCTime hour")?;
        let minute: u32 = time_str[8..10].parse().map_err(|_| "invalid UTCTime minute")?;
        let second: u32 = time_str[10..12].parse().map_err(|_| "invalid UTCTime second")?;

        Ok(civil_to_unix(year, month, day, hour, minute, second))
    } else if tag == 0x18 {
        // GeneralizedTime YYYYMMDDhhmmssZ
        if time_str.len() != 15 || !time_str.ends_with('Z') {
            return Err("malformed GeneralizedTime".into());
        }
        let year: u32 = time_str[0..4].parse().map_err(|_| "invalid GeneralizedTime year")?;
        let month: u32 = time_str[4..6].parse().map_err(|_| "invalid GeneralizedTime month")?;
        let day: u32 = time_str[6..8].parse().map_err(|_| "invalid GeneralizedTime day")?;
        let hour: u32 = time_str[8..10].parse().map_err(|_| "invalid GeneralizedTime hour")?;
        let minute: u32 = time_str[10..12].parse().map_err(|_| "invalid GeneralizedTime minute")?;
        let second: u32 = time_str[12..14].parse().map_err(|_| "invalid GeneralizedTime second")?;

        Ok(civil_to_unix(year, month, day, hour, minute, second))
    } else {
        Err(format!("unsupported time tag: 0x{:02x}", tag))
    }
}

fn civil_to_unix(year: u32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> u64 {
    // Days from civil (Howard Hinnant's algorithm, public domain formula).
    let y = if month <= 2 { year as i64 - 1 } else { year as i64 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = if month > 2 { month as i64 - 3 } else { month as i64 + 9 }; // [0, 11]
    let doy = (153 * mp + 2) / 5 + day as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days = era * 146097 + doe - 719468;
    (days * 86400 + hour as i64 * 3600 + minute as i64 * 60 + second as i64) as u64
}

// ============================================================================
// OpenPGP byte helpers
// ============================================================================

fn read_u8(data: &[u8], pos: &mut usize) -> Result<u8, String> {
    let val = *data.get(*pos).ok_or("truncated u8")?;
    *pos += 1;
    Ok(val)
}

fn read_u16_be(data: &[u8], pos: &mut usize) -> Result<u16, String> {
    let bytes = data.get(*pos..*pos + 2).ok_or("truncated u16")?;
    *pos += 2;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32_be(data: &[u8], pos: &mut usize) -> Result<u32, String> {
    let bytes = data.get(*pos..*pos + 4).ok_or("truncated u32")?;
    *pos += 4;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}

fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut decode_table = [255u8; 256];
    for (i, &c) in ALPHABET.iter().enumerate() {
        decode_table[c as usize] = i as u8;
    }
    decode_table[b'=' as usize] = 254;

    let cleaned: Vec<u8> = s
        .bytes()
        .filter(|&b| !b.is_ascii_whitespace())
        .collect();
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0;

    for &byte in &cleaned {
        let val = decode_table[byte as usize];
        if val == 255 {
            return Err(format!("invalid base64 character: {}", byte as char));
        }
        if val == 254 {
            break; // padding
        }
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Ok(out)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, Signer};

    const FIXTURE_PUB: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/pgp_admin_pub.asc"));
    const FIXTURE_SIG: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/pgp_admin_sig.asc"));
    const FIXTURE_MSG: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/pgp_admin_message.txt"));

    fn build_test_svid(
        spiffe_id: &str,
        signing_key: &SigningKey,
        not_before: u64,
        not_after: u64,
    ) -> Vec<u8> {
        let vk = signing_key.verifying_key();
        let vk_bytes = vk.to_bytes();

        // Serial
        let serial = vec![0x01, 0x23, 0x45, 0x67, 0x89];

        // Signature algorithm placeholder (OID sha256WithRSAEncryption, irrelevant for v1)
        let sig_alg_oid = vec![0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
        let sig_alg_seq = encode_seq(&[&sig_alg_oid, &[0x05, 0x00]]);

        // Issuer: CN=Test CA
        let issuer = encode_seq(&[&encode_set(&[&encode_seq(&[
            &[0x06, 0x03, 0x55, 0x04, 0x03],
            &encode_utf8_string("Test CA"),
        ])])]);

        // Subject: CN=Test Workload
        let subject = encode_seq(&[&encode_set(&[&encode_seq(&[
            &[0x06, 0x03, 0x55, 0x04, 0x03],
            &encode_utf8_string("Test Workload"),
        ])])]);

        // Validity
        let validity = encode_seq(&[
            &encode_utctime(not_before),
            &encode_utctime(not_after),
        ]);

        // SubjectPublicKeyInfo
        let ed25519_oid = vec![0x06, 0x03, 0x2B, 0x65, 0x70];
        let spki_alg = encode_seq(&[&ed25519_oid]);
        let mut bit_string = vec![0x03, 33, 0x00]; // BIT STRING, 33 bytes (0 unused + 32 key)
        bit_string.extend_from_slice(&vk_bytes);
        let spki = encode_seq(&[&spki_alg, &bit_string]);

        // Extensions: SAN
        let san_oid = vec![0x06, 0x03, 0x55, 0x1D, 0x11];
        let mut san_value = vec![0x86]; // context tag [6]
        san_value.push(spiffe_id.len() as u8);
        san_value.extend_from_slice(spiffe_id.as_bytes());
        let general_names = encode_seq(&[&san_value]);
        let san_ext_value = encode_octet_string(&general_names);
        let san_ext = encode_seq(&[&san_oid, &san_ext_value]);
        let extensions_seq = encode_seq(&[&san_ext]);
        let mut extensions = vec![0xA3]; // context [3]
        extensions.push(extensions_seq.len() as u8);
        extensions.extend_from_slice(&extensions_seq);

        // TBSCertificate
        let version = vec![0xA0, 0x03, 0x02, 0x01, 0x02]; // [0] explicit, INTEGER 2 (v3)
        let serial_int = encode_integer(&serial);

        let tbs = encode_seq(&[
            &version,
            &serial_int,
            &sig_alg_seq,
            &issuer,
            &validity,
            &subject,
            &spki,
            &extensions,
        ]);

        // Certificate signature (dummy bytes for v1 — not verified)
        let cert_sig = vec![0x03, 0x42, 0x00]; // BIT STRING with 65 dummy bytes
        let cert_sig_full = [&cert_sig[..], &[0u8; 64][..]].concat();

        // Certificate
        encode_seq(&[&tbs, &sig_alg_seq, &cert_sig_full])
    }

    fn encode_seq(parts: &[&[u8]]) -> Vec<u8> {
        let total: usize = parts.iter().map(|p| p.len()).sum();
        let mut out = vec![0x30];
        out.extend_from_slice(&encode_length(total));
        for p in parts {
            out.extend_from_slice(p);
        }
        out
    }

    fn encode_set(parts: &[&[u8]]) -> Vec<u8> {
        let total: usize = parts.iter().map(|p| p.len()).sum();
        let mut out = vec![0x31];
        out.extend_from_slice(&encode_length(total));
        for p in parts {
            out.extend_from_slice(p);
        }
        out
    }

    fn encode_integer(bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![0x02];
        out.extend_from_slice(&encode_length(bytes.len()));
        out.extend_from_slice(bytes);
        out
    }

    fn encode_utf8_string(s: &str) -> Vec<u8> {
        let mut out = vec![0x0C];
        out.extend_from_slice(&encode_length(s.len()));
        out.extend_from_slice(s.as_bytes());
        out
    }

    fn encode_octet_string(bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![0x04];
        out.extend_from_slice(&encode_length(bytes.len()));
        out.extend_from_slice(bytes);
        out
    }

    fn encode_utctime(unix_secs: u64) -> Vec<u8> {
        // Civil from days (Howard Hinnant's algorithm, inverse of civil_to_unix).
        let days = (unix_secs / 86400) as i64;
        let secs_today = (unix_secs % 86400) as u32;
        let hour = secs_today / 3600;
        let minute = (secs_today % 3600) / 60;
        let second = secs_today % 60;
        let z = days + 719468;
        let era = if z >= 0 { z } else { z - 146096 } / 146097;
        let doe = z - era * 146097; // [0, 146096]
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
        let mut year = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
        let mp = (5 * doy + 2) / 153; // [0, 11]
        let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
        let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
        if month <= 2 { year += 1; }
        let yy = (year % 100) as u32;
        let time_str = format!("{:02}{:02}{:02}{:02}{:02}{:02}Z", yy, month, day, hour, minute, second);
        let mut out = vec![0x17];
        out.extend_from_slice(&encode_length(time_str.len()));
        out.extend_from_slice(time_str.as_bytes());
        out
    }

    fn encode_length(len: usize) -> Vec<u8> {
        if len < 128 {
            vec![len as u8]
        } else if len < 256 {
            vec![0x81, len as u8]
        } else {
            vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
        }
    }

    #[test]
    fn test_svid_parse_valid() {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let now = 1700000000;
        let not_before = now - 3600;
        let not_after = now + 3600;
        let svid = build_test_svid("spiffe://cluster.local/workload", &sk, not_before, not_after);

        let info = parse_svid(&svid, now).unwrap();
        assert_eq!(info.spiffe_id, "spiffe://cluster.local/workload");
        assert_eq!(info.public_key, sk.verifying_key().to_bytes());
        assert_eq!(info.not_before, not_before);
        assert_eq!(info.not_after, not_after);
        assert_eq!(info.serial_hex, "0123456789");
    }

    #[test]
    fn test_svid_expired() {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let now = 1700000000;
        let svid = build_test_svid("spiffe://test/w", &sk, now - 7200, now - 3600);
        let err = parse_svid(&svid, now).unwrap_err();
        assert!(err.contains("expired"));
    }

    #[test]
    fn test_svid_not_yet_valid() {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let now = 1700000000;
        let svid = build_test_svid("spiffe://test/w", &sk, now + 3600, now + 7200);
        let err = parse_svid(&svid, now).unwrap_err();
        assert!(err.contains("not yet valid"));
    }

    #[test]
    fn test_svid_san_id_extraction() {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let now = 1700000000;
        let svid = build_test_svid("spiffe://example.com/svc", &sk, now - 10, now + 10);
        let info = parse_svid(&svid, now).unwrap();
        assert_eq!(info.spiffe_id, "spiffe://example.com/svc");

        // Mismatch caught by caller, but parsing should succeed
        let claimed = "spiffe://other.com/svc";
        assert_ne!(info.spiffe_id, claimed);
    }

    #[test]
    fn test_svid_non_ed25519_refused() {
        let now = 1700000000;
        let mut svid = build_test_svid("spiffe://test/w", &SigningKey::from_bytes(&[0x42; 32]), now - 10, now + 10);
        // Patch the Ed25519 SPKI OID (06 03 2B 65 70) — same length, different algorithm.
        let pos = svid.windows(5).position(|w| w == [0x06, 0x03, 0x2B, 0x65, 0x70]).expect("OID present in test SVID");
        svid[pos + 4] = 0x71;
        let err = parse_svid(&svid, now).unwrap_err();
        assert!(err.contains("unsupported SVID public key algorithm"), "got: {}", err);
    }

    #[test]
    fn test_spiffe_possession_valid() {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let now = 1700000000;
        let svid = build_test_svid("spiffe://test/w", &sk, now - 10, now + 10);
        let info = parse_svid(&svid, now).unwrap();

        let canonical = canonical_spiffe_string(&info.spiffe_id, "ABCD1234");
        let sig = sk.sign(canonical.as_bytes());

        verify_spiffe_possession(&info, &canonical, &sig.to_bytes()).unwrap();
    }

    #[test]
    fn test_spiffe_possession_tampered() {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let now = 1700000000;
        let svid = build_test_svid("spiffe://test/w", &sk, now - 10, now + 10);
        let info = parse_svid(&svid, now).unwrap();

        let canonical = canonical_spiffe_string(&info.spiffe_id, "ABCD1234");
        let mut sig_bytes = sk.sign(canonical.as_bytes()).to_bytes();
        sig_bytes[0] ^= 0x01;

        let err = verify_spiffe_possession(&info, &canonical, &sig_bytes).unwrap_err();
        assert!(err.contains("verification failed"));
    }

    #[test]
    fn test_spiffe_possession_wrong_message() {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let now = 1700000000;
        let svid = build_test_svid("spiffe://test/w", &sk, now - 10, now + 10);
        let info = parse_svid(&svid, now).unwrap();

        let canonical = canonical_spiffe_string(&info.spiffe_id, "ABCD1234");
        let wrong_canonical = canonical_spiffe_string(&info.spiffe_id, "DEADBEEF");
        let sig = sk.sign(wrong_canonical.as_bytes());

        let err = verify_spiffe_possession(&info, &canonical, &sig.to_bytes()).unwrap_err();
        assert!(err.contains("verification failed"));
    }

    #[test]
    fn test_spiffe_trust_domain_valid() {
        let domain = spiffe_trust_domain("spiffe://cluster.local/ns/default/sa/web").unwrap();
        assert_eq!(domain, "cluster.local");

        let domain2 = spiffe_trust_domain("spiffe://example.com/service").unwrap();
        assert_eq!(domain2, "example.com");
    }

    #[test]
    fn test_spiffe_trust_domain_invalid() {
        let err = spiffe_trust_domain("spiffe://").unwrap_err();
        assert!(err.contains("empty"));

        let err2 = spiffe_trust_domain("http://example.com").unwrap_err();
        assert!(err2.contains("invalid SPIFFE ID"));
    }

    #[test]
    fn test_pgp_fixture_parse() {
        let key = parse_pgp_public_key(FIXTURE_PUB).unwrap();
        // Real GnuPG 2.4.4 fixture key: RFC 4880 v4 fingerprint must match exactly.
        assert_eq!(key.fingerprint, "51680CA8C8B8713930FEA6D9C92DE79CBCE9D55F");
    }

    #[test]
    fn test_pgp_fixture_verify() {
        let key = parse_pgp_public_key(FIXTURE_PUB).unwrap();
        verify_pgp_detached(&key, FIXTURE_SIG, FIXTURE_MSG).unwrap();
    }

    #[test]
    fn test_pgp_tamper_message() {
        let key = parse_pgp_public_key(FIXTURE_PUB).unwrap();
        let mut tampered = FIXTURE_MSG.to_vec();
        tampered[0] ^= 0x01;
        let err = verify_pgp_detached(&key, FIXTURE_SIG, &tampered).unwrap_err();
        assert!(err.contains("verification failed") || err.contains("left-2"));
    }

    #[test]
    fn test_pgp_tamper_signature() {
        let key = parse_pgp_public_key(FIXTURE_PUB).unwrap();
        // Flip one base64 character inside the signature body (after the
        // header blank line), keeping the armor structure intact.
        let mut bytes = FIXTURE_SIG.as_bytes().to_vec();
        // The CRC24 line starts with "\n="; flip the last base64 body
        // character just before it (inside the S MPI of the signature).
        let crc_line = FIXTURE_SIG.rfind("\n=").unwrap();
        let mut i = crc_line - 1;
        while !(bytes[i] as char).is_ascii_alphanumeric() { i -= 1; }
        bytes[i] = if bytes[i] == b'A' { b'B' } else { b'A' };
        let tampered_sig = String::from_utf8(bytes).unwrap();
        let err = verify_pgp_detached(&key, &tampered_sig, FIXTURE_MSG).unwrap_err();
        assert!(err.contains("verification failed") || err.contains("left-2") || err.contains("malformed") || err.contains("unsupported"), "got: {}", err);
    }

    #[test]
    fn test_dearmor_reject_wrong_label() {
        let err = dearmor(FIXTURE_PUB, "WRONG LABEL").unwrap_err();
        assert!(err.contains("not found"));
    }

    #[test]
    fn test_dearmor_garbage() {
        let err = dearmor("garbage input", "PUBLIC KEY BLOCK").unwrap_err();
        assert!(err.contains("not found"));
    }
}
