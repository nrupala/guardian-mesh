// Copyright (c) 2026 Nrupal Akolkar
// SPDX-License-Identifier: Apache-2.0

use crate::sealed_envelope::{SealedEnvelope, compute_fingerprint, verifying_key_from_bytes};
use ml_dsa::{MlDsa65, SigningKey, Keypair};
use sha2::{Sha256, Digest};
use std::sync::OnceLock;

/// Build commit the daemon binary was built from.
pub fn build_commit() -> &'static str {
    env!("GM_GIT_COMMIT")
}

/// Daemon crate version (e.g., "0.13.0").
pub fn build_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// SOURCE_DATE_EPOCH value the binary was built with.
pub fn source_date_epoch() -> &'static str {
    env!("GM_SOURCE_DATE_EPOCH")
}

/// SHA-256 of the running executable's bytes (lowercase hex).
/// Cached on first call. Returns empty string if the executable cannot be read.
pub fn running_binary_sha256() -> String {
    static CACHED: OnceLock<String> = OnceLock::new();
    CACHED.get_or_init(|| {
        std::env::current_exe()
            .ok()
            .and_then(|path| std::fs::read(path).ok())
            .map(|bytes| {
                let hash = Sha256::digest(&bytes);
                hex::encode(hash)
            })
            .unwrap_or_default()
    }).clone()
}

/// Provenance statement for a build, following in-toto / SLSA structure.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProvenanceStatement {
    pub statement_type: String,
    pub subject_name: String,
    pub subject_sha256: String,
    pub predicate_type: String,
    pub build_type: String,
    pub builder_id: String,
    pub invocation_id: String,
    pub git_commit: String,
    pub version: String,
    pub target_triple: String,
    pub toolchain: String,
    pub source_date_epoch: u64,
    pub cargo_lock_sha256: String,
    pub build_command: String,
}

impl ProvenanceStatement {
    /// Canonical JSON serialization (fields in declaration order).
    pub fn canonical_json(&self) -> Vec<u8> {
        // serde_json with structs preserves field order by default when not using maps
        serde_json::to_vec(self).expect("ProvenanceStatement serialization cannot fail")
    }
}

/// A signed attestation package: statement + signature + metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AttestationPackage {
    pub statement: ProvenanceStatement,
    pub fingerprint: String,
    pub signer_fingerprint: String,
    pub verifying_key_hex: String,
    pub envelope_b64: String,
}

impl AttestationPackage {
    /// Build an attestation package by signing the statement.
    pub fn build(
        statement: ProvenanceStatement,
        signing_key: &SigningKey<MlDsa65>,
    ) -> Self {
        let canonical = statement.canonical_json();
        let fingerprint = hex::encode(Sha256::digest(&canonical));

        let envelope = SealedEnvelope::new(
            canonical.clone(),
            b"guardian-mesh/provenance/v1".to_vec(),
            signing_key,
        );
        let envelope_bytes = envelope.to_bytes();
        let envelope_b64 = base64_encode(&envelope_bytes);

        let vk = signing_key.verifying_key();
        let signer_fingerprint = compute_fingerprint(&vk);
        let vk_encoded = vk.encode();
        let vk_bytes: &[u8] = vk_encoded.as_ref();
        let verifying_key_hex = hex::encode(vk_bytes);

        Self {
            statement,
            fingerprint,
            signer_fingerprint,
            verifying_key_hex,
            envelope_b64,
        }
    }
}

/// Verify an attestation package against the actual binary bytes.
/// Fails closed: any mismatch or invalid signature returns Err with a named check.
pub fn verify_package(pkg: &AttestationPackage, binary_bytes: &[u8]) -> Result<(), String> {
    // 1. Verify subject_sha256 matches binary_bytes
    let binary_digest = hex::encode(Sha256::digest(binary_bytes));
    if binary_digest != pkg.statement.subject_sha256 {
        return Err(format!("subject digest mismatch: expected {}, computed {}", 
            pkg.statement.subject_sha256, binary_digest));
    }

    // 2. Verify fingerprint matches canonical_json(statement)
    let canonical = pkg.statement.canonical_json();
    let computed_fingerprint = hex::encode(Sha256::digest(&canonical));
    if computed_fingerprint != pkg.fingerprint {
        return Err(format!("fingerprint mismatch: expected {}, computed {}", 
            pkg.fingerprint, computed_fingerprint));
    }

    // 3. Decode envelope and verify signature
    let envelope_bytes = base64_decode(&pkg.envelope_b64)
        .map_err(|e| format!("envelope base64 decode failed: {}", e))?;
    let vk_bytes = hex::decode(&pkg.verifying_key_hex)
        .map_err(|e| format!("verifying_key_hex decode failed: {}", e))?;
    let vk = verifying_key_from_bytes(&vk_bytes)
        .map_err(|e| format!("verifying key parse failed: {}", e))?;

    // Parse envelope from bytes (reconstruct manually since SealedEnvelope::to_bytes is a custom format)
    let envelope = parse_sealed_envelope(&envelope_bytes)
        .map_err(|e| format!("envelope parse failed: {}", e))?;
    
    envelope.verify(&vk)
        .map_err(|e| format!("signature verification failed: {}", e))?;

    // 4. Check envelope payload equals canonical_json(statement)
    if envelope.payload != canonical {
        return Err("envelope payload does not match statement canonical JSON".to_string());
    }

    // 5. Check signer_fingerprint matches parsed vk
    let vk_fingerprint = compute_fingerprint(&vk);
    if vk_fingerprint != pkg.signer_fingerprint {
        return Err(format!("signer fingerprint mismatch: expected {}, computed {}", 
            pkg.signer_fingerprint, vk_fingerprint));
    }

    Ok(())
}

/// Parse a SealedEnvelope from its byte representation (inverse of to_bytes).
fn parse_sealed_envelope(bytes: &[u8]) -> Result<SealedEnvelope, String> {
    let mut offset = 0;

    // payload length (4 bytes)
    if bytes.len() < offset + 4 {
        return Err("envelope too short for payload length".to_string());
    }
    let payload_len = u32::from_le_bytes([bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3]]) as usize;
    offset += 4;

    // payload
    if bytes.len() < offset + payload_len {
        return Err("envelope too short for payload".to_string());
    }
    let payload = bytes[offset..offset+payload_len].to_vec();
    offset += payload_len;

    // payload_type length (4 bytes)
    if bytes.len() < offset + 4 {
        return Err("envelope too short for payload_type length".to_string());
    }
    let payload_type_len = u32::from_le_bytes([bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3]]) as usize;
    offset += 4;

    // payload_type
    if bytes.len() < offset + payload_type_len {
        return Err("envelope too short for payload_type".to_string());
    }
    let payload_type = bytes[offset..offset+payload_type_len].to_vec();
    offset += payload_type_len;

    // crc32c (4 bytes)
    if bytes.len() < offset + 4 {
        return Err("envelope too short for crc32c".to_string());
    }
    let crc32c_digest = u32::from_le_bytes([bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3]]);
    offset += 4;

    // ML-DSA-65 signature: the rest minus timestamp (8 bytes) and nonce (32 bytes)
    // SealedEnvelope::to_bytes writes: payload_len + payload + payload_type_len + payload_type + crc32c + signature + timestamp + nonce
    // We've read up to crc32c, so remaining = signature + timestamp + nonce
    // Therefore signature_len = remaining - 8 - 32
    const TIMESTAMP_LEN: usize = 8;
    const NONCE_LEN: usize = 32;
    let remaining = bytes.len() - offset;
    if remaining < TIMESTAMP_LEN + NONCE_LEN {
        return Err("envelope too short for signature + timestamp + nonce".to_string());
    }
    let signature_len = remaining - TIMESTAMP_LEN - NONCE_LEN;
    let ml_dsa_65_signature = bytes[offset..offset+signature_len].to_vec();
    offset += signature_len;

    // timestamp (8 bytes)
    if bytes.len() < offset + 8 {
        return Err("envelope too short for timestamp".to_string());
    }
    let timestamp = u64::from_le_bytes([
        bytes[offset], bytes[offset+1], bytes[offset+2], bytes[offset+3],
        bytes[offset+4], bytes[offset+5], bytes[offset+6], bytes[offset+7],
    ]);
    offset += 8;

    // nonce (32 bytes)
    if bytes.len() < offset + 32 {
        return Err("envelope too short for nonce".to_string());
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&bytes[offset..offset+32]);

    Ok(SealedEnvelope {
        payload,
        payload_type,
        crc32c_digest,
        ml_dsa_65_signature,
        timestamp,
        nonce,
    })
}

/// Simple base64 encoder (no new dependencies).
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    let mut i = 0;
    while i < input.len() {
        let b1 = input[i];
        let b2 = input.get(i + 1).copied();
        let b3 = input.get(i + 2).copied();

        let c1 = (b1 >> 2) as usize;
        let c2 = (((b1 & 0x03) << 4) | b2.map(|b| b >> 4).unwrap_or(0)) as usize;
        let c3 = b2.map(|b| (((b & 0x0f) << 2) | b3.map(|x| x >> 6).unwrap_or(0)) as usize);
        let c4 = b3.map(|b| (b & 0x3f) as usize);

        result.push(ALPHABET[c1] as char);
        result.push(ALPHABET[c2] as char);
        result.push(c3.map(|c| ALPHABET[c] as char).unwrap_or('='));
        result.push(c4.map(|c| ALPHABET[c] as char).unwrap_or('='));

        i += 3;
    }
    result
}

/// Simple base64 decoder (no new dependencies).
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    let input = input.trim_end_matches('=');
    let mut result = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;

    for ch in input.chars() {
        let val = match ch {
            'A'..='Z' => (ch as u32) - ('A' as u32),
            'a'..='z' => (ch as u32) - ('a' as u32) + 26,
            '0'..='9' => (ch as u32) - ('0' as u32) + 52,
            '+' => 62,
            '/' => 63,
            _ => return Err(format!("invalid base64 character: {}", ch)),
        };
        buffer = (buffer << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sealed_envelope::generate_keypair;

    #[test]
    fn build_identity_functions_exist() {
        let commit = build_commit();
        assert!(!commit.is_empty());
        let version = build_version();
        assert!(!version.is_empty());
        let epoch = source_date_epoch();
        assert!(!epoch.is_empty());
    }

    #[test]
    fn running_binary_sha256_is_64_hex_chars() {
        let digest = running_binary_sha256();
        // In test binary it should succeed and be 64 lowercase hex chars
        if !digest.is_empty() {
            assert_eq!(digest.len(), 64);
            assert!(digest.chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
        }
    }

    #[test]
    fn canonical_json_is_byte_stable() {
        let stmt = ProvenanceStatement {
            statement_type: "https://in-toto.io/Statement/v1".to_string(),
            subject_name: "guardian-meshd".to_string(),
            subject_sha256: "abc123".to_string(),
            predicate_type: "https://slsa.dev/provenance/v1".to_string(),
            build_type: "https://guardian-mesh.aimlds.org/build/cargo/v1".to_string(),
            builder_id: "guardian-mesh release pipeline".to_string(),
            invocation_id: "run-001".to_string(),
            git_commit: "abcdef1234".to_string(),
            version: "0.13.0".to_string(),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            toolchain: "rustc 1.75.0".to_string(),
            source_date_epoch: 1700000000,
            cargo_lock_sha256: "def456".to_string(),
            build_command: "cargo build --release".to_string(),
        };
        let json1 = stmt.canonical_json();
        let json2 = stmt.canonical_json();
        assert_eq!(json1, json2);
    }

    #[test]
    fn package_builds_and_verifies() {
        let (sk, _vk) = generate_keypair();
        let binary = b"fake binary content for testing";
        let binary_digest = hex::encode(Sha256::digest(binary.as_ref()));

        let stmt = ProvenanceStatement {
            statement_type: "https://in-toto.io/Statement/v1".to_string(),
            subject_name: "guardian-meshd".to_string(),
            subject_sha256: binary_digest,
            predicate_type: "https://slsa.dev/provenance/v1".to_string(),
            build_type: "https://guardian-mesh.aimlds.org/build/cargo/v1".to_string(),
            builder_id: "guardian-mesh release pipeline".to_string(),
            invocation_id: "test-001".to_string(),
            git_commit: "abc123".to_string(),
            version: "0.13.0".to_string(),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            toolchain: "rustc 1.75.0".to_string(),
            source_date_epoch: 1700000000,
            cargo_lock_sha256: "deadbeef".to_string(),
            build_command: "cargo build --release".to_string(),
        };

        let pkg = AttestationPackage::build(stmt, &sk);
        let result = verify_package(&pkg, binary);
        assert!(result.is_ok(), "verification failed: {:?}", result.err());
    }

    #[test]
    fn package_rejects_tampered_binary() {
        let (sk, _vk) = generate_keypair();
        let binary = b"original binary";
        let binary_digest = hex::encode(Sha256::digest(binary.as_ref()));

        let stmt = ProvenanceStatement {
            statement_type: "https://in-toto.io/Statement/v1".to_string(),
            subject_name: "guardian-meshd".to_string(),
            subject_sha256: binary_digest,
            predicate_type: "https://slsa.dev/provenance/v1".to_string(),
            build_type: "https://guardian-mesh.aimlds.org/build/cargo/v1".to_string(),
            builder_id: "guardian-mesh release pipeline".to_string(),
            invocation_id: "test-002".to_string(),
            git_commit: "abc123".to_string(),
            version: "0.13.0".to_string(),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            toolchain: "rustc 1.75.0".to_string(),
            source_date_epoch: 1700000000,
            cargo_lock_sha256: "deadbeef".to_string(),
            build_command: "cargo build --release".to_string(),
        };

        let pkg = AttestationPackage::build(stmt, &sk);
        
        // Verify with tampered binary
        let tampered = b"tampered binary";
        let result = verify_package(&pkg, tampered);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("subject digest"));
    }

    #[test]
    fn package_rejects_tampered_statement() {
        let (sk, _vk) = generate_keypair();
        let binary = b"original binary";
        let binary_digest = hex::encode(Sha256::digest(binary.as_ref()));

        let stmt = ProvenanceStatement {
            statement_type: "https://in-toto.io/Statement/v1".to_string(),
            subject_name: "guardian-meshd".to_string(),
            subject_sha256: binary_digest,
            predicate_type: "https://slsa.dev/provenance/v1".to_string(),
            build_type: "https://guardian-mesh.aimlds.org/build/cargo/v1".to_string(),
            builder_id: "guardian-mesh release pipeline".to_string(),
            invocation_id: "test-003".to_string(),
            git_commit: "abc123".to_string(),
            version: "0.13.0".to_string(),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            toolchain: "rustc 1.75.0".to_string(),
            source_date_epoch: 1700000000,
            cargo_lock_sha256: "deadbeef".to_string(),
            build_command: "cargo build --release".to_string(),
        };

        let mut pkg = AttestationPackage::build(stmt, &sk);
        
        // Tamper the statement version
        pkg.statement.version = "9.9.9".to_string();

        let result = verify_package(&pkg, binary);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("fingerprint"));
    }

    #[test]
    fn package_rejects_wrong_signature_key() {
        let (sk1, _vk1) = generate_keypair();
        let (sk2, vk2) = generate_keypair();
        
        let binary = b"original binary";
        let binary_digest = hex::encode(Sha256::digest(binary.as_ref()));

        let stmt = ProvenanceStatement {
            statement_type: "https://in-toto.io/Statement/v1".to_string(),
            subject_name: "guardian-meshd".to_string(),
            subject_sha256: binary_digest,
            predicate_type: "https://slsa.dev/provenance/v1".to_string(),
            build_type: "https://guardian-mesh.aimlds.org/build/cargo/v1".to_string(),
            builder_id: "guardian-mesh release pipeline".to_string(),
            invocation_id: "test-004".to_string(),
            git_commit: "abc123".to_string(),
            version: "0.13.0".to_string(),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            toolchain: "rustc 1.75.0".to_string(),
            source_date_epoch: 1700000000,
            cargo_lock_sha256: "deadbeef".to_string(),
            build_command: "cargo build --release".to_string(),
        };

        let mut pkg = AttestationPackage::build(stmt.clone(), &sk1);
        
        // Replace verifying key with a different key
        let vk2_encoded = vk2.encode();
        let vk2_bytes: &[u8] = vk2_encoded.as_ref();
        pkg.verifying_key_hex = hex::encode(vk2_bytes);
        pkg.signer_fingerprint = compute_fingerprint(&vk2);

        let result = verify_package(&pkg, binary);
        assert!(result.is_err());
        // Should fail at signature verification
    }

    #[test]
    fn base64_roundtrip() {
        let data = b"hello world test data 12345";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(data.as_ref(), decoded.as_slice());
    }
}
